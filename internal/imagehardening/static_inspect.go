package imagehardening

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type staticImageAnalysis struct {
	SourceID         string   `json:"source_id"`
	Architecture     string   `json:"architecture"`
	User             string   `json:"user"`
	UserChanged      bool     `json:"user_changed"`
	PresentTools     []string `json:"present_tools"`
	EligibleRemovals []string `json:"eligible_removals"`
	ShellRequired    bool     `json:"shell_required"`
	DeclaredVolumes  []string `json:"declared_volumes"`
	ExposedPorts     []string `json:"exposed_ports"`
	Unknowns         []string `json:"unknowns"`
}

// A stopped container is only a filesystem-export handle. No image process,
// build step, host extraction, or command from its configuration is executed.
func inspectStaticImage(ctx context.Context, source, artifacts string, policy genericRuntimePolicy) (staticImageAnalysis, error) {
	if err := toolImageReference(source); err != nil {
		return staticImageAnalysis{}, err
	}
	metadata, err := inspectLocalMetadata(ctx, source)
	if err != nil {
		return staticImageAnalysis{}, err
	}
	marker := make([]byte, 12)
	if _, err := rand.Read(marker); err != nil {
		return staticImageAnalysis{}, err
	}
	name := "hardening-static-inspect-" + hex.EncodeToString(marker)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = boundedToolCapture(cleanup, "docker", "rm", "-fv", "--", name)
	}()
	if _, err := boundedToolCapture(ctx, "docker", "create", "--pull=never", "--name", name, "--label=breachbench.static-inspect=true", "--network=none", "--entrypoint=/.breachbench-not-executed", metadata.ID); err != nil {
		return staticImageAnalysis{}, errors.New("cannot create stopped image-export handle")
	}
	exportContext, cancel := context.WithCancel(ctx)
	defer cancel()
	command := exec.CommandContext(exportContext, "docker", "container", "export", "--", name)
	command.Env = slimEnvironment(os.Environ())
	command.Stderr = io.Discard
	stream, err := command.StdoutPipe()
	if err != nil {
		return staticImageAnalysis{}, errors.New("cannot open static filesystem export")
	}
	if err := command.Start(); err != nil {
		return staticImageAnalysis{}, errors.New("cannot start static filesystem export")
	}
	analysis, inspectErr := analyzeStaticRootfs(ctx, metadata, stream, policy)
	if inspectErr != nil {
		cancel()
	}
	_ = stream.Close()
	exportErr := command.Wait()
	if inspectErr != nil {
		return staticImageAnalysis{}, inspectErr
	}
	if exportErr != nil {
		return staticImageAnalysis{}, errors.New("static filesystem export failed")
	}
	return analysis, nil
}

type staticEntry struct {
	kind   byte
	link   string
	prefix []byte
	body   []byte
}

type staticContextReader struct {
	ctx context.Context
	io.Reader
}

func (r staticContextReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.Reader.Read(p)
}

// Only account files, known tools, startup directories, and writable-path
// ancestors are retained in memory; unrelated application files are skipped.
func analyzeStaticRootfs(ctx context.Context, metadata localImageMetadata, input io.Reader, policy genericRuntimePolicy) (staticImageAnalysis, error) {
	result := staticImageAnalysis{SourceID: metadata.ID, Architecture: metadata.Architecture, PresentTools: []string{}, EligibleRemovals: []string{}, DeclaredVolumes: []string{}, ExposedPorts: []string{}, Unknowns: []string{
		"Static inspection does not establish application compatibility or discover dynamic tool, write, credential, or network requirements",
		"Primary UID:GID is resolved statically; supplementary group membership and runtime access are not verified",
	}}
	checkPolicy := policy
	if checkPolicy.User == "" {
		checkPolicy.User = "65532:65532"
	}
	if checkPolicy.Network == "" {
		checkPolicy.Network = "none"
	}
	if err := validateGenericPolicy(checkPolicy); err != nil {
		return result, err
	}
	if !slimImageID(metadata.ID) || metadata.OS != "linux" || len(metadata.Architecture) > 32 || metadata.Architecture == "" || strings.ContainsFunc(metadata.Architecture, func(r rune) bool { return !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' && r != '-' }) {
		return result, errors.New("invalid Linux image identity or architecture")
	}
	var volumes, ports map[string]json.RawMessage
	if json.Unmarshal(metadata.Config["Volumes"], &volumes) != nil && len(metadata.Config["Volumes"]) != 0 {
		return result, errors.New("invalid declared image volumes")
	}
	if json.Unmarshal(metadata.Config["ExposedPorts"], &ports) != nil && len(metadata.Config["ExposedPorts"]) != 0 {
		return result, errors.New("invalid exposed image ports")
	}
	if len(volumes) > 64 || len(ports) > 256 {
		return result, errors.New("too many declared image volumes or ports")
	}
	for volume := range volumes {
		if !staticAbsolutePath(volume) {
			return result, errors.New("invalid declared image volume path")
		}
		result.DeclaredVolumes = append(result.DeclaredVolumes, volume)
	}
	for port := range ports {
		parts := strings.Split(port, "/")
		if len(parts) != 2 || (parts[1] != "tcp" && parts[1] != "udp" && parts[1] != "sctp") {
			return result, errors.New("invalid exposed image port")
		}
		value, ok := staticID(parts[0])
		if !ok || value == 0 || value > 65535 {
			return result, errors.New("invalid exposed image port")
		}
		result.ExposedPorts = append(result.ExposedPorts, port)
	}
	sort.Strings(result.DeclaredVolumes)
	sort.Strings(result.ExposedPorts)
	writable := append([]string{"/tmp"}, policy.WritablePaths...)
	tracked := map[string]bool{}
	track := func(value string) {
		for value != "/" {
			tracked[value] = true
			value = path.Dir(value)
		}
	}
	for _, value := range append(append(append([]string{}, removableTools...), writable...), "/etc/passwd", "/etc/group") {
		track(value)
	}
	startup, directories, err := staticStartupPaths(metadata)
	if err != nil {
		return result, err
	}
	for _, candidates := range startup {
		for _, value := range candidates {
			track(value)
		}
	}
	entries := map[string]staticEntry{}
	reader := tar.NewReader(staticContextReader{ctx, input})
	prefixBytes := 0
	for count := 0; ; count++ {
		if count > 2_000_000 {
			return result, errors.New("exported archive has too many entries")
		}
		header, err := reader.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return result, errors.New("cannot read exported filesystem archive")
		}
		name, err := staticArchivePath(header.Name)
		if err != nil {
			return result, err
		}
		if name == "/" && header.Typeflag != tar.TypeDir {
			return result, errors.New("exported archive root must be a directory")
		}
		entry := staticEntry{kind: header.Typeflag, link: header.Linkname}
		if entry.kind == tar.TypeSymlink || entry.kind == tar.TypeLink {
			if _, err := staticLinkPath(name, entry); err != nil {
				return result, err
			}
		}
		if !tracked[name] && !directories[path.Dir(name)] {
			continue
		}
		if _, duplicate := entries[name]; duplicate || len(entries) >= 20_000 {
			return result, errors.New("duplicate or excessive inspected archive entries")
		}
		if entry.kind == tar.TypeReg || entry.kind == tar.TypeRegA {
			if name == "/etc/passwd" || name == "/etc/group" {
				if header.Size > 1024*1024 {
					return result, errors.New("image account database exceeds the 1 MiB static-inspection limit")
				}
				entry.body, err = io.ReadAll(reader)
			} else {
				entry.prefix, err = io.ReadAll(io.LimitReader(reader, 512))
				prefixBytes += len(entry.prefix)
			}
			if err != nil || prefixBytes > 8*1024*1024 {
				return result, errors.New("cannot read bounded static-inspection data")
			}
		}
		entries[name] = entry
	}
	for _, value := range writable {
		for current := value; current != "/"; current = path.Dir(current) {
			if entry, ok := entries[current]; ok && entry.kind != tar.TypeDir {
				return result, fmt.Errorf("writable path %q or an ancestor is an alias or non-directory; declare a literal directory instead", value)
			}
		}
	}
	var declaredUser string
	if raw := metadata.Config["User"]; len(raw) != 0 && json.Unmarshal(raw, &declaredUser) != nil {
		return result, errors.New("invalid image user configuration")
	}
	resolved, resolveErr := resolveStaticUser(declaredUser, entries["/etc/passwd"].body, entries["/etc/group"].body)
	if policy.User != "" {
		parts := strings.Split(policy.User, ":")
		uid, validUID := staticID(parts[0])
		gid, validGID := staticID(parts[1])
		if !validUID || !validGID || uid == 0 {
			return result, errors.New("policy.user must contain a positive numeric UID and a numeric GID")
		}
		result.User = fmt.Sprintf("%d:%d", uid, gid)
		result.UserChanged = resolveErr != nil || resolved != result.User
		if resolveErr != nil {
			result.Unknowns = append(result.Unknowns, "Original image user could not be resolved; the explicitly supplied numeric runtime user is used")
		}
	} else if resolveErr != nil {
		return result, resolveErr
	} else if strings.HasPrefix(resolved, "0:") {
		result.User, result.UserChanged = "65532:65532", true
	} else {
		result.User = resolved
	}
	result.ShellRequired = shellRequired(metadata)
	requiredTools := map[string]bool{}
	for _, key := range []string{"Entrypoint", "Cmd"} {
		var argv []string
		_ = json.Unmarshal(metadata.Config[key], &argv)
		for _, argument := range argv {
			for _, word := range strings.Fields(argument) {
				word = strings.Trim(word, "\"'")
				result.ShellRequired = result.ShellRequired || isShellTool(word)
				for _, tool := range removableTools {
					if path.Base(tool) == path.Base(word) {
						requiredTools[tool] = true
					}
				}
			}
		}
	}
	opaqueStartup := false
	for _, candidates := range startup {
		found := false
		for _, candidate := range candidates {
			resolvedPath, entry, ok := resolveStaticEntry(candidate, entries, requiredTools)
			if !ok {
				continue
			}
			found = true
			if path.Base(resolvedPath) == "env" {
				opaqueStartup, result.ShellRequired = true, true
			}
			if isShellTool(resolvedPath) {
				result.ShellRequired = true
			}
			if bytes.HasPrefix(entry.prefix, []byte("#!")) {
				first, _, _ := bytes.Cut(entry.prefix, []byte{'\n'})
				words := strings.Fields(strings.TrimPrefix(string(first), "#!"))
				if len(words) > 0 && staticAbsolutePath(words[0]) {
					requiredTools[words[0]] = true
					interpreter, _, inspected := resolveStaticEntry(words[0], entries, requiredTools)
					opaqueStartup = opaqueStartup || !inspected || path.Base(words[0]) == "env"
					if isShellTool(interpreter) || path.Base(words[0]) == "env" {
						result.ShellRequired = true
					}
				} else {
					opaqueStartup, result.ShellRequired = true, true
				}
				for _, word := range words {
					word = strings.Trim(word, "\"'")
					if isShellTool(word) {
						result.ShellRequired = true
					}
					for _, tool := range removableTools {
						if path.Base(tool) == path.Base(word) {
							requiredTools[tool] = true
						}
					}
				}
			} else if !bytes.HasPrefix(entry.prefix, []byte{0x7f, 'E', 'L', 'F'}) {
				opaqueStartup = true
				result.ShellRequired = true
				result.Unknowns = append(result.Unknowns, "A startup executable has an unknown format; shells are conservatively retained")
			}
			break
		}
		if !found {
			opaqueStartup = true
			result.ShellRequired = true
			result.Unknowns = append(result.Unknowns, "A startup executable or alias could not be inspected; shells are conservatively retained")
		}
	}
	if opaqueStartup {
		result.Unknowns = append(result.Unknowns, "A startup dependency or launcher is opaque; all fixed tool entrypoints are conservatively retained")
	}
	allowed := map[string]bool{}
	for _, value := range defaultToolRemovals(metadata) {
		allowed[value] = true
	}
	for _, value := range removableTools {
		entry, present := entries[value]
		if !present || (entry.kind != tar.TypeReg && entry.kind != tar.TypeRegA && entry.kind != tar.TypeSymlink && entry.kind != tar.TypeLink) {
			continue
		}
		result.PresentTools = append(result.PresentTools, value)
		if !opaqueStartup && allowed[value] && !requiredTools[value] && !(result.ShellRequired && isShellTool(value)) {
			result.EligibleRemovals = append(result.EligibleRemovals, value)
		}
	}
	return result, nil
}

func staticAbsolutePath(value string) bool {
	return value != "" && len(value) <= 4096 && path.IsAbs(value) && path.Clean(value) == value && !strings.ContainsRune(value, '\\') && !strings.ContainsFunc(value, unicode.IsControl)
}

func staticArchivePath(raw string) (string, error) {
	if len(raw) > 4096 || path.IsAbs(raw) || strings.ContainsRune(raw, '\\') || strings.ContainsFunc(raw, unicode.IsControl) {
		return "", errors.New("unsafe exported archive path")
	}
	for _, part := range strings.Split(raw, "/") {
		if part == ".." {
			return "", errors.New("unsafe exported archive traversal")
		}
	}
	return path.Clean("/" + raw), nil
}

func staticLinkPath(name string, entry staticEntry) (string, error) {
	if entry.link == "" || len(entry.link) > 4096 || strings.ContainsRune(entry.link, '\\') || strings.ContainsFunc(entry.link, unicode.IsControl) {
		return "", errors.New("unsafe inspected archive link")
	}
	base := path.Dir(name)
	if entry.kind == tar.TypeLink || path.IsAbs(entry.link) {
		base = "/"
	}
	parts := strings.FieldsFunc(strings.TrimPrefix(base, "/"), func(r rune) bool { return r == '/' })
	for _, part := range strings.Split(entry.link, "/") {
		switch part {
		case "", ".":
		case "..":
			if len(parts) == 0 {
				return "", errors.New("inspected archive link escapes its image root")
			}
			parts = parts[:len(parts)-1]
		default:
			parts = append(parts, part)
		}
	}
	return "/" + strings.Join(parts, "/"), nil
}

func resolveStaticEntry(value string, entries map[string]staticEntry, required map[string]bool) (string, staticEntry, bool) {
	for depth := 0; depth < 40; depth++ {
		parts := strings.Split(strings.TrimPrefix(value, "/"), "/")
		redirected := false
		for index := range parts {
			current := "/" + strings.Join(parts[:index+1], "/")
			entry, ok := entries[current]
			if !ok {
				continue
			}
			if entry.kind == tar.TypeSymlink || entry.kind == tar.TypeLink {
				required[current] = true
				target, err := staticLinkPath(current, entry)
				if err != nil {
					return "", staticEntry{}, false
				}
				value = path.Join(target, path.Join(parts[index+1:]...))
				redirected = true
				break
			}
			if index == len(parts)-1 {
				required[current] = true
				return current, entry, entry.kind == tar.TypeReg || entry.kind == tar.TypeRegA
			}
			if entry.kind != tar.TypeDir {
				return "", staticEntry{}, false
			}
		}
		if !redirected {
			return "", staticEntry{}, false
		}
	}
	return "", staticEntry{}, false
}

func staticStartupPaths(metadata localImageMetadata) ([][]string, map[string]bool, error) {
	working := "/"
	if raw := metadata.Config["WorkingDir"]; len(raw) != 0 {
		if json.Unmarshal(raw, &working) != nil {
			return nil, nil, errors.New("invalid image working directory")
		}
		if working == "" {
			working = "/"
		}
	}
	if !staticAbsolutePath(working) {
		return nil, nil, errors.New("invalid image working directory")
	}
	search := "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	var environment []string
	if raw := metadata.Config["Env"]; len(raw) != 0 && json.Unmarshal(raw, &environment) != nil {
		return nil, nil, errors.New("invalid image environment schema")
	}
	for _, variable := range environment {
		if strings.HasPrefix(variable, "PATH=") {
			search = strings.TrimPrefix(variable, "PATH=")
		}
	}
	paths := strings.Split(search, ":")
	if len(paths) > 32 {
		return nil, nil, errors.New("image executable search path exceeds static-inspection limits")
	}
	var result [][]string
	directories := map[string]bool{}
	for _, key := range []string{"Entrypoint", "Cmd"} {
		var argv []string
		if raw := metadata.Config[key]; len(raw) != 0 && json.Unmarshal(raw, &argv) != nil {
			return nil, nil, errors.New("invalid image startup configuration")
		}
		if len(argv) == 0 {
			continue
		}
		executable := argv[0]
		if executable == "" || len(executable) > 4096 || strings.ContainsFunc(executable, unicode.IsControl) {
			return nil, nil, errors.New("invalid image startup executable")
		}
		candidates := []string{}
		if strings.Contains(executable, "/") {
			value := executable
			if !path.IsAbs(value) {
				value = path.Join(working, value)
			}
			if !staticAbsolutePath(value) {
				return nil, nil, errors.New("invalid image startup executable path")
			}
			candidates = append(candidates, value)
		} else {
			for _, directory := range paths {
				if !path.IsAbs(directory) {
					directory = path.Join(working, directory)
				}
				if !staticAbsolutePath(directory) {
					return nil, nil, errors.New("invalid image executable search directory")
				}
				candidates = append(candidates, path.Join(directory, executable))
			}
		}
		for _, candidate := range candidates {
			directories[path.Dir(candidate)] = true
		}
		result = append(result, candidates)
		break // Cmd supplies arguments, not another executable, when Entrypoint exists.
	}
	return result, directories, nil
}

func staticID(value string) (uint64, bool) {
	if value == "" || strings.Trim(value, "0123456789") != "" {
		return 0, false
	}
	number, err := strconv.ParseUint(value, 10, 32)
	return number, err == nil
}

func resolveStaticUser(declared string, passwd, group []byte) (string, error) {
	failure := errors.New("cannot statically resolve the image user; supply a --policy JSON with an explicit numeric non-root user (policy.user)")
	parts := strings.Split(declared, ":")
	if len(parts) > 2 || len(declared) > 256 || strings.ContainsFunc(declared, unicode.IsControl) {
		return "", failure
	}
	if parts[0] == "" {
		return "0:0", nil
	}
	uid, numeric := staticID(parts[0])
	if numeric && uid == 0 {
		return "0:0", nil
	}
	gid := uint64(0)
	matches := 0
	for _, line := range strings.Split(string(passwd), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 4 || strings.HasPrefix(line, "#") {
			continue
		}
		entryUID, validUID := staticID(fields[2])
		matched := fields[0] == parts[0]
		if numeric {
			matched = validUID && entryUID == uid
		}
		if !matched {
			continue
		}
		entryGID, validGID := staticID(fields[3])
		if !validUID || !validGID {
			return "", failure
		}
		uid, gid, matches = entryUID, entryGID, matches+1
	}
	if parts[0] == "root" && matches == 0 {
		return "0:0", nil
	}
	if (!numeric && matches != 1) || matches > 1 {
		return "", failure
	}
	if len(parts) == 2 && parts[1] != "" {
		if number, ok := staticID(parts[1]); ok {
			gid = number
		} else {
			matches = 0
			for _, line := range strings.Split(string(group), "\n") {
				fields := strings.Split(line, ":")
				if len(fields) < 3 || fields[0] != parts[1] {
					continue
				}
				number, valid := staticID(fields[2])
				if !valid {
					return "", failure
				}
				gid, matches = number, matches+1
			}
			if matches != 1 {
				return "", failure
			}
		}
	}
	return fmt.Sprintf("%d:%d", uid, gid), nil
}
