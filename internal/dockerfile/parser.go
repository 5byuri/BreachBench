package dockerfile

import (
	"encoding/json"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"unicode"
)

// Instruction represents a single parsed Dockerfile instruction.
type Instruction struct {
	Command  string            `json:"command"`
	Flags    map[string]string `json:"flags,omitempty"`
	RawArgs  string            `json:"rawArgs"`
	Args     []string          `json:"args,omitempty"`
	ExecForm bool              `json:"execForm,omitempty"`
	Heredocs []string          `json:"heredocs,omitempty"`
	Line     int               `json:"line"`
}

// Stage represents a single FROM stage in a Dockerfile.
type Stage struct {
	Index        int           `json:"index"`
	Name         string        `json:"name,omitempty"`
	RawFrom      string        `json:"rawFrom"`
	Platform     string        `json:"platform,omitempty"`
	Line         int           `json:"line"`
	Instructions []Instruction `json:"instructions"`
}

// ParsedDockerfile holds the global ARGs and ordered build stages.
type ParsedDockerfile struct {
	Escape     rune          `json:"-"`
	Syntax     string        `json:"syntax,omitempty"`
	GlobalArgs []Instruction `json:"globalArgs,omitempty"`
	Stages     []Stage       `json:"stages"`
}

// Parse parses a Dockerfile or Containerfile into global ARGs and stages.
// It supports # escape= and # syntax= parser directives, line continuations
// with interleaved comments, JSON exec-form arrays, and BuildKit heredocs.
func Parse(content string) (*ParsedDockerfile, error) {
	content = strings.ReplaceAll(content, "\r\n", "\n")
	rawLines := strings.Split(content, "\n")

	df := &ParsedDockerfile{Escape: '\\'}
	lineIdx := 0
	directivesAllowed := true

	for lineIdx < len(rawLines) {
		trimmed := strings.TrimSpace(rawLines[lineIdx])
		if trimmed == "" {
			lineIdx++
			continue
		}
		if strings.HasPrefix(trimmed, "#") {
			if directivesAllowed {
				key, val, ok := parseDirective(trimmed)
				if ok {
					switch key {
					case "escape":
						if val == "`" || val == `\` {
							df.Escape = rune(val[0])
							lineIdx++
							continue
						}
						directivesAllowed = false
					case "syntax":
						df.Syntax = val
						lineIdx++
						continue
					default:
						directivesAllowed = false
					}
				} else {
					directivesAllowed = false
				}
			}
			lineIdx++
			continue
		}
		break
	}

	var currentStage *Stage
	for lineIdx < len(rawLines) {
		trimmed := strings.TrimSpace(rawLines[lineIdx])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			lineIdx++
			continue
		}

		startLine := lineIdx + 1
		logical, nextIdx := readLogicalLine(rawLines, lineIdx, df.Escape)
		lineIdx = nextIdx

		inst, heredocMarkers, err := parseInstruction(logical, startLine, df.Escape)
		if err != nil {
			return nil, err
		}

		for _, marker := range heredocMarkers {
			var body []string
			for lineIdx < len(rawLines) {
				hline := rawLines[lineIdx]
				lineIdx++
				check := hline
				if marker.stripTabs {
					check = strings.TrimLeft(check, "\t")
				}
				if strings.TrimSpace(check) == marker.delimiter {
					break
				}
				body = append(body, hline)
			}
			inst.Heredocs = append(inst.Heredocs, strings.Join(body, "\n"))
		}

		if inst.Command == "FROM" {
			st, err := buildStageFromInstruction(len(df.Stages), inst)
			if err != nil {
				return nil, err
			}
			df.Stages = append(df.Stages, st)
			currentStage = &df.Stages[len(df.Stages)-1]
			continue
		}

		if currentStage == nil {
			if inst.Command == "ARG" {
				df.GlobalArgs = append(df.GlobalArgs, inst)
				continue
			}
			return nil, fmt.Errorf("line %d: instruction %s before first FROM", inst.Line, inst.Command)
		}

		currentStage.Instructions = append(currentStage.Instructions, inst)
	}

	if len(df.Stages) == 0 {
		return nil, fmt.Errorf("dockerfile contains no FROM instructions")
	}
	return df, nil
}

func parseDirective(commentLine string) (string, string, bool) {
	body := strings.TrimSpace(strings.TrimPrefix(commentLine, "#"))
	eq := strings.IndexByte(body, '=')
	if eq <= 0 {
		return "", "", false
	}
	key := strings.ToLower(strings.TrimSpace(body[:eq]))
	val := strings.TrimSpace(body[eq+1:])
	if key == "" || val == "" || strings.ContainsAny(key, " \t") {
		return "", "", false
	}
	return key, val, true
}

func readLogicalLine(lines []string, start int, escape rune) (string, int) {
	var b strings.Builder
	i := start
	for i < len(lines) {
		line := lines[i]
		trimmed := strings.TrimSpace(line)
		if b.Len() > 0 && strings.HasPrefix(trimmed, "#") {
			// Comment lines inside a backslash-continued instruction are skipped.
			i++
			continue
		}
		cont, prefix := hasLineContinuation(line, escape)
		if cont {
			b.WriteString(prefix)
			b.WriteByte(' ')
			i++
			// Skip any trailing comment/empty lines if continuation continues
			for i < len(lines) && strings.HasPrefix(strings.TrimSpace(lines[i]), "#") {
				i++
			}
			continue
		}
		b.WriteString(line)
		i++
		break
	}
	return strings.TrimSpace(b.String()), i
}

func hasLineContinuation(line string, escape rune) (bool, string) {
	trimmedRight := strings.TrimRightFunc(line, unicode.IsSpace)
	if trimmedRight == "" {
		return false, line
	}
	runes := []rune(trimmedRight)
	if runes[len(runes)-1] != escape {
		return false, line
	}
	// Count consecutive trailing escape characters; odd count means escaped newline.
	count := 0
	for j := len(runes) - 1; j >= 0 && runes[j] == escape; j-- {
		count++
	}
	if count%2 == 1 {
		return true, string(runes[:len(runes)-1])
	}
	return false, line
}

type heredocMarker struct {
	delimiter string
	stripTabs bool
}

func parseInstruction(logical string, lineNum int, escape rune) (Instruction, []heredocMarker, error) {
	trimmed := strings.TrimSpace(logical)
	cmdEnd := strings.IndexFunc(trimmed, unicode.IsSpace)
	if cmdEnd < 0 {
		return Instruction{
			Command: strings.ToUpper(trimmed),
			Line:    lineNum,
		}, nil, nil
	}
	cmd := strings.ToUpper(trimmed[:cmdEnd])
	rest := strings.TrimSpace(trimmed[cmdEnd:])

	// Handle ONBUILD by unwrapping or keeping its payload
	flags := map[string]string{}
	for strings.HasPrefix(rest, "--") {
		spaceIdx := indexUnquotedSpace(rest, escape)
		var token string
		if spaceIdx < 0 {
			token = rest
			rest = ""
		} else {
			token = rest[:spaceIdx]
			rest = strings.TrimSpace(rest[spaceIdx:])
		}
		flagBody := strings.TrimPrefix(token, "--")
		if eq := strings.IndexByte(flagBody, '='); eq >= 0 {
			flags[flagBody[:eq]] = unquoteToken(flagBody[eq+1:], escape)
		} else {
			flags[flagBody] = "true"
		}
	}

	inst := Instruction{
		Command: cmd,
		Flags:   flags,
		RawArgs: rest,
		Line:    lineNum,
	}

	// Check for JSON exec form in ENTRYPOINT, CMD, RUN, SHELL, VOLUME
	if slices.Contains([]string{"ENTRYPOINT", "CMD", "RUN", "SHELL", "VOLUME", "COPY", "ADD"}, cmd) &&
		strings.HasPrefix(rest, "[") && strings.HasSuffix(rest, "]") {
		var arr []string
		if err := json.Unmarshal([]byte(rest), &arr); err == nil {
			inst.ExecForm = true
			inst.Args = arr
			return inst, nil, nil
		}
	}

	var markers []heredocMarker
	if cmd == "RUN" || cmd == "COPY" || cmd == "ADD" {
		markers = detectHeredocs(rest)
	}

	inst.Args = splitWords(rest, escape)
	return inst, markers, nil
}

func indexUnquotedSpace(s string, escape rune) int {
	inSingle, inDouble, escaped := false, false, false
	for i, r := range s {
		if escaped {
			escaped = false
			continue
		}
		if r == escape && !inSingle {
			escaped = true
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if !inSingle && !inDouble && unicode.IsSpace(r) {
			return i
		}
	}
	return -1
}

func unquoteToken(s string, escape rune) string {
	if len(s) >= 2 && ((s[0] == '"' && s[len(s)-1] == '"') || (s[0] == '\'' && s[len(s)-1] == '\'')) {
		return s[1 : len(s)-1]
	}
	return s
}

func splitWords(s string, escape rune) []string {
	var words []string
	var cur strings.Builder
	inSingle, inDouble, escaped, hasToken := false, false, false, false

	for _, r := range s {
		if escaped {
			cur.WriteRune(r)
			escaped = false
			hasToken = true
			continue
		}
		if r == escape && !inSingle {
			escaped = true
			hasToken = true
			continue
		}
		if r == '\'' && !inDouble {
			inSingle = !inSingle
			hasToken = true
			continue
		}
		if r == '"' && !inSingle {
			inDouble = !inDouble
			hasToken = true
			continue
		}
		if !inSingle && !inDouble && unicode.IsSpace(r) {
			if hasToken {
				words = append(words, cur.String())
				cur.Reset()
				hasToken = false
			}
			continue
		}
		cur.WriteRune(r)
		hasToken = true
	}
	if hasToken {
		words = append(words, cur.String())
	}
	return words
}

func detectHeredocs(s string) []heredocMarker {
	var markers []heredocMarker
	inSingle, inDouble := false, false
	for i := 0; i < len(s)-1; i++ {
		c := s[i]
		if c == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if c == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}
		if inSingle || inDouble {
			continue
		}
		if c == '<' && s[i+1] == '<' {
			if i+2 < len(s) && s[i+2] == '<' {
				// <<< here-string, not heredoc
				i += 2
				continue
			}
			j := i + 2
			stripTabs := false
			if j < len(s) && s[j] == '-' {
				stripTabs = true
				j++
			}
			for j < len(s) && (s[j] == ' ' || s[j] == '\t') {
				j++
			}
			start := j
			for j < len(s) && !unicode.IsSpace(rune(s[j])) && s[j] != ';' && s[j] != '&' && s[j] != '|' {
				j++
			}
			token := strings.Trim(s[start:j], `"'`)
			if token != "" && isValidHeredocDelimiter(token) {
				markers = append(markers, heredocMarker{delimiter: token, stripTabs: stripTabs})
			}
			i = j - 1
		}
	}
	return markers
}

func isValidHeredocDelimiter(token string) bool {
	for _, r := range token {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' && r != '.' {
			return false
		}
	}
	return true
}

func buildStageFromInstruction(index int, inst Instruction) (Stage, error) {
	if len(inst.Args) == 0 {
		return Stage{}, fmt.Errorf("line %d: FROM requires a base image or stage reference", inst.Line)
	}
	st := Stage{
		Index:    index,
		RawFrom:  inst.Args[0],
		Platform: inst.Flags["platform"],
		Line:     inst.Line,
	}
	if len(inst.Args) >= 3 && strings.EqualFold(inst.Args[1], "AS") {
		st.Name = inst.Args[2]
	} else if len(inst.Args) != 1 {
		return Stage{}, fmt.Errorf("line %d: invalid FROM arguments %v", inst.Line, inst.Args)
	}
	return st, nil
}

// ParseKeyValues parses ARG or ENV instructions into key-value pairs.
// If an ARG has no '=', hasValue is false.
type KeyValue struct {
	Key      string
	Value    string
	HasValue bool
}

func parseArgInstruction(inst Instruction) []KeyValue {
	var out []KeyValue
	for _, tok := range inst.Args {
		if eq := strings.IndexByte(tok, '='); eq >= 0 {
			out = append(out, KeyValue{Key: tok[:eq], Value: tok[eq+1:], HasValue: true})
		} else if tok != "" {
			out = append(out, KeyValue{Key: tok, HasValue: false})
		}
	}
	return out
}

func parseEnvInstruction(inst Instruction, escape rune) []KeyValue {
	raw := strings.TrimSpace(inst.RawArgs)
	if raw == "" {
		return nil
	}
	// Check whether the first token contains '='. If not, legacy form: ENV KEY VALUE...
	firstSpace := indexUnquotedSpace(raw, escape)
	firstToken := raw
	if firstSpace >= 0 {
		firstToken = raw[:firstSpace]
	}
	if !strings.Contains(firstToken, "=") {
		val := ""
		if firstSpace >= 0 {
			val = unquoteToken(strings.TrimSpace(raw[firstSpace:]), escape)
		}
		return []KeyValue{{Key: firstToken, Value: val, HasValue: true}}
	}

	var out []KeyValue
	for _, tok := range inst.Args {
		if eq := strings.IndexByte(tok, '='); eq >= 0 {
			out = append(out, KeyValue{Key: tok[:eq], Value: tok[eq+1:], HasValue: true})
		}
	}
	return out
}

// expandVariables expands $VAR and ${VAR} expressions using the provided scope.
// It returns the expanded string and any variable names that were referenced
// without a defined value or fallback default.
func expandVariables(input string, scope map[string]string) (string, []string) {
	var b strings.Builder
	var unresolved []string
	addUnresolved := func(name string) {
		if name != "" && !slices.Contains(unresolved, name) {
			unresolved = append(unresolved, name)
		}
	}

	for i := 0; i < len(input); i++ {
		if input[i] == '\\' && i+1 < len(input) && input[i+1] == '$' {
			b.WriteByte('$')
			i++
			continue
		}
		if input[i] != '$' || i+1 >= len(input) {
			b.WriteByte(input[i])
			continue
		}
		if input[i+1] == '{' {
			end := strings.IndexByte(input[i+2:], '}')
			if end < 0 {
				b.WriteByte(input[i])
				continue
			}
			expr := input[i+2 : i+2+end]
			i += 2 + end
			val, missing := resolveBraceExpr(expr, scope)
			if missing != "" {
				addUnresolved(missing)
			}
			b.WriteString(val)
			continue
		}
		// $VAR form
		j := i + 1
		for j < len(input) && (unicode.IsLetter(rune(input[j])) || unicode.IsDigit(rune(input[j])) || input[j] == '_') {
			j++
		}
		if j == i+1 {
			b.WriteByte(input[i])
			continue
		}
		name := input[i+1 : j]
		i = j - 1
		if val, ok := scope[name]; ok {
			b.WriteString(val)
		} else {
			addUnresolved(name)
		}
	}
	return b.String(), unresolved
}

func resolveBraceExpr(expr string, scope map[string]string) (string, string) {
	for _, op := range []string{":-", ":+", "-", "+"} {
		if idx := strings.Index(expr, op); idx > 0 {
			name := expr[:idx]
			word := expr[idx+len(op):]
			val, ok := scope[name]
			switch op {
			case ":-":
				if !ok || val == "" {
					expanded, _ := expandVariables(word, scope)
					return expanded, ""
				}
				return val, ""
			case "-":
				if !ok {
					expanded, _ := expandVariables(word, scope)
					return expanded, ""
				}
				return val, ""
			case ":+":
				if ok && val != "" {
					expanded, _ := expandVariables(word, scope)
					return expanded, ""
				}
				return "", ""
			case "+":
				if ok {
					expanded, _ := expandVariables(word, scope)
					return expanded, ""
				}
				return "", ""
			}
		}
	}
	if val, ok := scope[expr]; ok {
		return val, ""
	}
	return "", expr
}

func resolveStageIndex(stages []Stage, ref string) (int, bool) {
	if ref == "" {
		return -1, false
	}
	for i, st := range stages {
		if st.Name != "" && strings.EqualFold(st.Name, ref) {
			return i, true
		}
	}
	if idx, err := strconv.Atoi(ref); err == nil && idx >= 0 && idx < len(stages) {
		return idx, true
	}
	return -1, false
}
