package dockerfile

import (
	"encoding/json"
	"fmt"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

// TraceOptions configures target stage and build argument resolution.
type TraceOptions struct {
	Target    string            `json:"target,omitempty"`
	BuildArgs map[string]string `json:"buildArgs,omitempty"`
}

// CommandSpec represents a resolved ENTRYPOINT or CMD declaration.
type CommandSpec struct {
	Instruction            string   `json:"instruction,omitempty"`
	ExecForm               bool     `json:"execForm"`
	Command                []string `json:"command,omitempty"`
	Raw                    string   `json:"raw,omitempty"`
	StageName              string   `json:"stageName,omitempty"`
	StageIndex             int      `json:"stageIndex"`
	Line                   int      `json:"line,omitempty"`
	InheritedFromStage     bool     `json:"inheritedFromStage,omitempty"`
	InheritedFromBaseImage bool     `json:"inheritedFromBaseImage,omitempty"`
}

// ArtifactTrace records a file or directory copied via COPY --from or RUN --mount=from=.
type ArtifactTrace struct {
	FromRef            string   `json:"fromRef,omitempty"`
	FromStageIndex     int      `json:"fromStageIndex"`
	FromStageName      string   `json:"fromStageName,omitempty"`
	FromStageBaseImage string   `json:"fromStageBaseImage,omitempty"`
	FromStageToolchain string   `json:"fromStageToolchain,omitempty"`
	Sources            []string `json:"sources"`
	Destination        string   `json:"destination"`
	Line               int      `json:"line"`
}

// ExecutableTrace describes the startup executable and how it entered the runtime stage.
type ExecutableTrace struct {
	Executable        string   `json:"executable,omitempty"`
	ResolvedPath      string   `json:"resolvedPath,omitempty"`
	ApplicationTarget string   `json:"applicationTarget,omitempty"`
	OriginType        string   `json:"originType"` // copied-from-stage, copied-from-image, built-in-runtime-chain, copied-from-context, base-image, unknown
	OriginSummary     string   `json:"originSummary"`
	SourceStageName   string   `json:"sourceStageName,omitempty"`
	SourceStageIndex  int      `json:"sourceStageIndex"`
	SourceStageBase   string   `json:"sourceStageBase,omitempty"`
	SourceToolchain   string   `json:"sourceToolchain,omitempty"`
	CopySourcePath    string   `json:"copySourcePath,omitempty"`
	CopyDestPath      string   `json:"copyDestPath,omitempty"`
	BuildCommands     []string `json:"buildCommands,omitempty"`
	Line              int      `json:"line,omitempty"`
}

// Finding represents a specific hardening defect or anti-pattern in a Dockerfile.
type Finding struct {
	Code     string `json:"code"`
	Severity string `json:"severity"` // high, medium, low
	Points   int    `json:"points"`
	Message  string `json:"message"`
	Line     int    `json:"line,omitempty"`
}

// HardeningAssessment is the separate assessment of whether the deployed stage meets hardening requirements.
type HardeningAssessment struct {
	Classification      string    `json:"classification"` // hardened, partially-hardened, unhardened, terrible
	UnhardenedScore     int       `json:"unhardenedScore"`
	MinimalBase         bool      `json:"minimalBase"`
	BaseCategory        string    `json:"baseCategory"` // minimal, distroless, scratch, alpine, distro-slim, full-distro, language-runtime, build-sdk, unknown
	DigestPinned        bool      `json:"digestPinned"`
	FloatingTag         bool      `json:"floatingTag"`
	RunsAsRoot          bool      `json:"runsAsRoot"`
	NumericNonRootUser  bool      `json:"numericNonRootUser"`
	EffectiveUser       string    `json:"effectiveUser,omitempty"`
	ExecFormStartup     bool      `json:"execFormStartup"`
	NoRuntimeBuildTools bool      `json:"noRuntimeBuildTools"`
	RuntimeToolsUsed    []string  `json:"runtimeToolsUsed,omitempty"`
	Findings            []Finding `json:"findings,omitempty"`
}

// StageSummary gives a concise overview of each stage in the Dockerfile.
type StageSummary struct {
	Index         int      `json:"index"`
	Name          string   `json:"name,omitempty"`
	RawFrom       string   `json:"rawFrom"`
	ResolvedFrom  string   `json:"resolvedFrom"`
	BaseImage     string   `json:"baseImage"`
	Toolchain     string   `json:"toolchain,omitempty"`
	IsBuildStage  bool     `json:"isBuildStage"`
	BuildCommands []string `json:"buildCommands,omitempty"`
}

// TraceReport is the complete stage trace and hardening assessment for a Dockerfile.
type TraceReport struct {
	TargetStageName    string              `json:"targetStageName,omitempty"`
	TargetStageIndex   int                 `json:"targetStageIndex"`
	StageCount         int                 `json:"stageCount"`
	Stages             []StageSummary      `json:"stages"`
	FromChain          []string            `json:"fromChain"`
	FromStageIndices   []int               `json:"fromStageIndices"`
	RuntimeBase        string              `json:"runtimeBase"`
	UnresolvedArgs     []string            `json:"unresolvedArgs,omitempty"`
	EffectiveWorkdir   string              `json:"effectiveWorkdir"`
	EffectiveUser      string              `json:"effectiveUser,omitempty"`
	ExposedPorts       []int               `json:"exposedPorts,omitempty"`
	Entrypoint         *CommandSpec        `json:"entrypoint,omitempty"`
	Cmd                *CommandSpec        `json:"cmd,omitempty"`
	StartupDeclaration string              `json:"startupDeclaration"`
	EffectiveCommand   []string            `json:"effectiveCommand,omitempty"`
	ExecutableTrace    ExecutableTrace     `json:"executableTrace"`
	CopiedArtifacts    []ArtifactTrace     `json:"copiedArtifacts,omitempty"`
	SingleStage        bool                `json:"singleStage"`
	InheritsBuildStage bool                `json:"inheritsBuildStage"`
	UsesMultiStageCopy bool                `json:"usesMultiStageCopy"`
	RunsInBuildEnv     bool                `json:"runsInBuildEnv"`
	MultiStagePattern  string              `json:"multiStagePattern"` // single-stage, multi-stage-inherited-build, multi-stage-copied-artifacts, multi-stage-unlinked
	DetectedRuntime    string              `json:"detectedRuntime"`   // go, node, next, php, python, rust, java, ruby, c/cpp, dotnet, other
	HardenCompatible   bool                `json:"hardenCompatible"`
	Hardening          HardeningAssessment `json:"hardening"`
}

type copyEvent struct {
	inst      Instruction
	stageIdx  int
	stageName string
	workdir   string
	fromRef   string
	sources   []string
	dest      string
	absDest   string
	destIsDir bool
}

type runEvent struct {
	inst      Instruction
	stageIdx  int
	stageName string
	workdir   string
	command   string
}

var defaultPlatformArgs = map[string]string{
	"TARGETPLATFORM": "linux/amd64",
	"TARGETOS":       "linux",
	"TARGETARCH":     "amd64",
	"BUILDPLATFORM":  "linux/amd64",
	"BUILDOS":        "linux",
	"BUILDARCH":      "amd64",
}

// Analyze parses a Dockerfile, traces the deployed runtime stage back to its FROM image,
// resolves ENTRYPOINT/CMD, traces the executable's source across COPY --from,
// and performs a separate hardening assessment.
func Analyze(content string, opts TraceOptions) (*TraceReport, error) {
	df, err := Parse(content)
	if err != nil {
		return nil, err
	}
	return TraceParsed(df, opts)
}

// TraceParsed performs stage tracing and hardening analysis on an already-parsed Dockerfile.
func TraceParsed(df *ParsedDockerfile, opts TraceOptions) (*TraceReport, error) {
	if df == nil || len(df.Stages) == 0 {
		return nil, fmt.Errorf("empty parsed dockerfile")
	}

	globalScope := map[string]string{}
	for k, v := range defaultPlatformArgs {
		globalScope[k] = v
	}
	globalDefined := map[string]bool{}
	for _, inst := range df.GlobalArgs {
		for _, kv := range parseArgInstruction(inst) {
			if val, ok := opts.BuildArgs[kv.Key]; ok {
				globalScope[kv.Key] = val
				globalDefined[kv.Key] = true
			} else if kv.HasValue {
				expanded, _ := expandVariables(kv.Value, globalScope)
				globalScope[kv.Key] = expanded
				globalDefined[kv.Key] = true
			}
		}
	}
	for k, v := range opts.BuildArgs {
		globalScope[k] = v
		globalDefined[k] = true
	}

	resolvedFrom := make([]string, len(df.Stages))
	var unresolvedArgs []string
	addUnresolved := func(names []string) {
		for _, n := range names {
			if n != "" && !slices.Contains(unresolvedArgs, n) {
				unresolvedArgs = append(unresolvedArgs, n)
			}
		}
	}

	for i, st := range df.Stages {
		exp, missing := expandVariables(st.RawFrom, globalScope)
		addUnresolved(missing)
		if strings.TrimSpace(exp) == "" {
			exp = strings.TrimSpace(st.RawFrom)
		}
		resolvedFrom[i] = exp
	}

	followFromChain := func(startIdx int) ([]int, string, error) {
		var chain []int
		visited := map[int]bool{}
		curr := startIdx
		for {
			if visited[curr] {
				return nil, "", fmt.Errorf("circular FROM stage reference involving stage %d", curr)
			}
			visited[curr] = true
			chain = append(chain, curr)

			ref := resolvedFrom[curr]
			parentIdx := -1
			for j := curr - 1; j >= 0; j-- {
				if df.Stages[j].Name != "" && strings.EqualFold(df.Stages[j].Name, ref) {
					parentIdx = j
					break
				}
			}
			if parentIdx < 0 {
				return chain, ref, nil
			}
			curr = parentIdx
		}
	}

	stageSummaries := make([]StageSummary, len(df.Stages))
	for i, st := range df.Stages {
		_, extBase, err := followFromChain(i)
		if err != nil {
			return nil, err
		}
		buildCmds := detectStageBuildCommands(st)
		toolchain := classifyToolchain(extBase, buildCmds, st)
		isBuild := len(buildCmds) > 0 || isBuildBaseImage(extBase) || isBuilderStageName(st.Name)
		stageSummaries[i] = StageSummary{
			Index:         i,
			Name:          st.Name,
			RawFrom:       st.RawFrom,
			ResolvedFrom:  resolvedFrom[i],
			BaseImage:     extBase,
			Toolchain:     toolchain,
			IsBuildStage:  isBuild,
			BuildCommands: buildCmds,
		}
	}

	// Step 1: Identify the stage being deployed (--target or last stage by default)
	targetIdx := len(df.Stages) - 1
	if strings.TrimSpace(opts.Target) != "" {
		idx, ok := resolveStageIndex(df.Stages, strings.TrimSpace(opts.Target))
		if !ok {
			return nil, fmt.Errorf("target stage %q not found in Dockerfile", opts.Target)
		}
		targetIdx = idx
	}

	// Step 2: Follow its FROM chain
	chainDesc, externalBase, err := followFromChain(targetIdx)
	if err != nil {
		return nil, err
	}
	var fromChainLabels []string
	for _, idx := range chainDesc {
		label := df.Stages[idx].Name
		if label == "" {
			label = fmt.Sprintf("stage-%d", idx)
		}
		fromChainLabels = append(fromChainLabels, label)
	}
	fromChainLabels = append(fromChainLabels, externalBase)

	chainAsc := slices.Clone(chainDesc)
	slices.Reverse(chainAsc)

	// Step 3: Resolve ENTRYPOINT, CMD, WORKDIR, USER, ENV, EXPOSE, and COPY/RUN history across the FROM chain
	var entrypointSpec *CommandSpec
	var cmdSpec *CommandSpec
	effectiveWorkdir := "/"
	effectiveUser := ""
	var exposedPorts []int
	var copyEvents []copyEvent
	var runEvents []runEvent
	var copiedArtifacts []ArtifactTrace

	chainEnv := map[string]string{}

	for _, stIdx := range chainAsc {
		st := df.Stages[stIdx]
		stageScope := map[string]string{}
		for k, v := range defaultPlatformArgs {
			stageScope[k] = v
		}
		for k, v := range chainEnv {
			stageScope[k] = v
		}

		for _, inst := range st.Instructions {
			switch inst.Command {
			case "ARG":
				for _, kv := range parseArgInstruction(inst) {
					if val, ok := opts.BuildArgs[kv.Key]; ok {
						stageScope[kv.Key] = val
					} else if kv.HasValue {
						exp, missing := expandVariables(kv.Value, stageScope)
						addUnresolved(missing)
						stageScope[kv.Key] = exp
					} else if globalDefined[kv.Key] {
						stageScope[kv.Key] = globalScope[kv.Key]
					}
				}
			case "ENV":
				for _, kv := range parseEnvInstruction(inst, df.Escape) {
					exp, missing := expandVariables(kv.Value, stageScope)
					addUnresolved(missing)
					stageScope[kv.Key] = exp
					chainEnv[kv.Key] = exp
				}
			case "WORKDIR":
				if len(inst.Args) > 0 {
					wd, missing := expandVariables(inst.Args[0], stageScope)
					addUnresolved(missing)
					if strings.HasPrefix(wd, "/") {
						effectiveWorkdir = path.Clean(wd)
					} else {
						effectiveWorkdir = path.Clean(path.Join(effectiveWorkdir, wd))
					}
				}
			case "USER":
				if len(inst.Args) > 0 {
					u, missing := expandVariables(inst.Args[0], stageScope)
					addUnresolved(missing)
					effectiveUser = u
				}
			case "EXPOSE":
				for _, a := range inst.Args {
					exp, _ := expandVariables(a, stageScope)
					portStr := strings.Split(exp, "/")[0]
					if p, err := strconv.Atoi(portStr); err == nil && p > 0 && !slices.Contains(exposedPorts, p) {
						exposedPorts = append(exposedPorts, p)
					}
				}
			case "ENTRYPOINT":
				spec := buildCommandSpec("ENTRYPOINT", inst, st, stIdx != targetIdx, stageScope)
				entrypointSpec = &spec
				// In Docker, setting ENTRYPOINT resets any prior CMD to empty.
				cmdSpec = nil
			case "CMD":
				spec := buildCommandSpec("CMD", inst, st, stIdx != targetIdx, stageScope)
				cmdSpec = &spec
			case "COPY", "ADD":
				if len(inst.Args) >= 2 {
					var srcs []string
					for _, rawSrc := range inst.Args[:len(inst.Args)-1] {
						s, _ := expandVariables(rawSrc, stageScope)
						srcs = append(srcs, s)
					}
					rawDest := inst.Args[len(inst.Args)-1]
					dest, _ := expandVariables(rawDest, stageScope)
					absDest, isDir := resolveCopyDest(effectiveWorkdir, dest, len(srcs))
					fromRef := ""
					if f, ok := inst.Flags["from"]; ok {
						fromRef, _ = expandVariables(f, stageScope)
					}
					ev := copyEvent{
						inst:      inst,
						stageIdx:  stIdx,
						stageName: st.Name,
						workdir:   effectiveWorkdir,
						fromRef:   fromRef,
						sources:   srcs,
						dest:      dest,
						absDest:   absDest,
						destIsDir: isDir,
					}
					copyEvents = append(copyEvents, ev)
					if fromRef != "" {
						art := resolveArtifactTrace(df, stageSummaries, stIdx, fromRef, srcs, absDest, inst.Line)
						copiedArtifacts = append(copiedArtifacts, art)
					}
				}
			case "RUN":
				cmdText := inst.RawArgs
				if len(inst.Heredocs) > 0 {
					cmdText += "\n" + strings.Join(inst.Heredocs, "\n")
				}
				runEvents = append(runEvents, runEvent{
					inst:      inst,
					stageIdx:  stIdx,
					stageName: st.Name,
					workdir:   effectiveWorkdir,
					command:   cmdText,
				})
				if mountSpec, ok := inst.Flags["mount"]; ok && strings.Contains(mountSpec, "from=") {
					if fromStage := extractMountOption(mountSpec, "from"); fromStage != "" {
						fromStage, _ = expandVariables(fromStage, stageScope)
						src := extractMountOption(mountSpec, "source")
						if src == "" {
							src = extractMountOption(mountSpec, "src")
						}
						target := extractMountOption(mountSpec, "target")
						if target == "" {
							target = extractMountOption(mountSpec, "dst")
						}
						art := resolveArtifactTrace(df, stageSummaries, stIdx, fromStage, []string{src}, target, inst.Line)
						copiedArtifacts = append(copiedArtifacts, art)
					}
				}
			}
		}
	}

	startupDecl, effectiveCmd := formatStartupDeclaration(entrypointSpec, cmdSpec, externalBase)
	if entrypointSpec == nil && cmdSpec == nil && !strings.EqualFold(externalBase, "scratch") {
		cmdSpec = &CommandSpec{
			Instruction:            "CMD",
			StageIndex:             targetIdx,
			InheritedFromBaseImage: true,
			Raw:                    fmt.Sprintf("inherited from base image %s", externalBase),
		}
	}

	// Step 4: Trace the executable's source
	execTrace := traceExecutableSource(df, stageSummaries, targetIdx, effectiveWorkdir, effectiveCmd, copyEvents, runEvents, copiedArtifacts, externalBase)

	singleStage := len(df.Stages) == 1
	inheritsBuildStage := false
	if len(chainDesc) > 1 {
		for _, ancIdx := range chainDesc[1:] {
			if stageSummaries[ancIdx].IsBuildStage {
				inheritsBuildStage = true
				break
			}
		}
	}
	usesMultiStageCopy := !singleStage && !inheritsBuildStage && len(copiedArtifacts) > 0

	targetBuildCmds := detectChainBuildCommands(df, chainAsc)
	runsInBuildEnv := inheritsBuildStage || isBuildBaseImage(externalBase) || len(targetBuildCmds) > 0

	multiStagePattern := "single-stage"
	if !singleStage {
		if inheritsBuildStage {
			multiStagePattern = "multi-stage-inherited-build"
		} else if usesMultiStageCopy {
			multiStagePattern = "multi-stage-copied-artifacts"
		} else {
			multiStagePattern = "multi-stage-unlinked"
		}
	}

	detectedRuntime := detectApplicationRuntime(df, stageSummaries, effectiveCmd, execTrace)
	hardenCompatible := slices.Contains([]string{"go", "node", "next", "php"}, detectedRuntime)

	report := &TraceReport{
		TargetStageName:    df.Stages[targetIdx].Name,
		TargetStageIndex:   targetIdx,
		StageCount:         len(df.Stages),
		Stages:             stageSummaries,
		FromChain:          fromChainLabels,
		FromStageIndices:   chainDesc,
		RuntimeBase:        externalBase,
		UnresolvedArgs:     unresolvedArgs,
		EffectiveWorkdir:   effectiveWorkdir,
		EffectiveUser:      effectiveUser,
		ExposedPorts:       exposedPorts,
		Entrypoint:         entrypointSpec,
		Cmd:                cmdSpec,
		StartupDeclaration: startupDecl,
		EffectiveCommand:   effectiveCmd,
		ExecutableTrace:    execTrace,
		CopiedArtifacts:    copiedArtifacts,
		SingleStage:        singleStage,
		InheritsBuildStage: inheritsBuildStage,
		UsesMultiStageCopy: usesMultiStageCopy,
		RunsInBuildEnv:     runsInBuildEnv,
		MultiStagePattern:  multiStagePattern,
		DetectedRuntime:    detectedRuntime,
		HardenCompatible:   hardenCompatible,
	}

	report.Hardening = assessHardening(df, report, chainAsc, runEvents)
	return report, nil
}

func resolveArtifactTrace(df *ParsedDockerfile, summaries []StageSummary, currentStageIdx int, fromRef string, srcs []string, dest string, line int) ArtifactTrace {
	art := ArtifactTrace{
		FromRef:        fromRef,
		FromStageIndex: -1,
		Sources:        srcs,
		Destination:    dest,
		Line:           line,
	}
	if originIdx, ok := resolveStageIndex(df.Stages[:currentStageIdx], fromRef); ok {
		// Follow transitive COPY --from if originIdx itself only copied from an earlier build stage
		rootOriginIdx := resolveTransitiveCopyStage(df, summaries, originIdx, srcs)
		art.FromStageIndex = rootOriginIdx
		art.FromStageName = df.Stages[rootOriginIdx].Name
		art.FromStageBaseImage = summaries[rootOriginIdx].BaseImage
		art.FromStageToolchain = summaries[rootOriginIdx].Toolchain
	}
	return art
}

func resolveTransitiveCopyStage(df *ParsedDockerfile, summaries []StageSummary, stageIdx int, srcs []string) int {
	curr := stageIdx
	currentSrcs := slices.Clone(srcs)
	visited := map[int]bool{}
	for !visited[curr] {
		visited[curr] = true
		if len(summaries[curr].BuildCommands) > 0 || isBuildBaseImage(summaries[curr].BaseImage) {
			return curr
		}
		st := df.Stages[curr]
		wd := "/"
		advanced := false
		for _, inst := range st.Instructions {
			if inst.Command == "WORKDIR" && len(inst.Args) > 0 {
				if strings.HasPrefix(inst.Args[0], "/") {
					wd = path.Clean(inst.Args[0])
				} else {
					wd = path.Clean(path.Join(wd, inst.Args[0]))
				}
			}
			if (inst.Command == "COPY" || inst.Command == "ADD") && inst.Flags["from"] != "" && len(inst.Args) >= 2 {
				fromRef := inst.Flags["from"]
				instSrcs := inst.Args[:len(inst.Args)-1]
				dest, isDir := resolveCopyDest(wd, inst.Args[len(inst.Args)-1], len(instSrcs))
				for _, s := range currentSrcs {
					absSrc := s
					if !strings.HasPrefix(absSrc, "/") {
						absSrc = path.Clean(path.Join(wd, absSrc))
					}
					if matchesCopyDestination(absSrc, instSrcs, dest, isDir) {
						if prevIdx, ok := resolveStageIndex(df.Stages[:curr], fromRef); ok {
							curr = prevIdx
							currentSrcs = instSrcs
							advanced = true
							break
						}
					}
				}
			}
			if advanced {
				break
			}
		}
		if !advanced {
			break
		}
	}
	return curr
}

func buildCommandSpec(kind string, inst Instruction, st Stage, inherited bool, scope map[string]string) CommandSpec {
	var args []string
	for _, a := range inst.Args {
		exp, _ := expandVariables(a, scope)
		args = append(args, exp)
	}
	raw := inst.RawArgs
	if inst.ExecForm {
		b, _ := json.Marshal(args)
		raw = fmt.Sprintf("%s %s", kind, string(b))
	} else {
		expRaw, _ := expandVariables(inst.RawArgs, scope)
		raw = fmt.Sprintf("%s %s", kind, expRaw)
	}
	return CommandSpec{
		Instruction:        kind,
		ExecForm:           inst.ExecForm,
		Command:            args,
		Raw:                raw,
		StageName:          st.Name,
		StageIndex:         st.Index,
		Line:               inst.Line,
		InheritedFromStage: inherited,
	}
}

func formatStartupDeclaration(ep, cmd *CommandSpec, externalBase string) (string, []string) {
	if ep == nil && cmd == nil {
		if strings.EqualFold(externalBase, "scratch") {
			return "none (scratch)", nil
		}
		return fmt.Sprintf("Inherited from base image (%s)", externalBase), nil
	}
	if ep != nil && cmd == nil {
		return ep.Raw, ep.Command
	}
	if ep == nil && cmd != nil {
		return cmd.Raw, cmd.Command
	}
	combined := append(slices.Clone(ep.Command), cmd.Command...)
	return ep.Raw + " + " + cmd.Raw, combined
}

func resolveCopyDest(workdir, dest string, numSrcs int) (string, bool) {
	isDir := strings.HasSuffix(dest, "/") || dest == "." || dest == "./" || dest == ".." || numSrcs > 1
	var abs string
	if strings.HasPrefix(dest, "/") {
		abs = path.Clean(dest)
	} else {
		abs = path.Clean(path.Join(workdir, dest))
	}
	if abs == "/" {
		isDir = true
	}
	return abs, isDir
}

func extractMountOption(mountSpec, key string) string {
	for _, part := range strings.Split(mountSpec, ",") {
		if strings.HasPrefix(part, key+"=") {
			return strings.TrimPrefix(part, key+"=")
		}
	}
	return ""
}

var knownInterpreters = []string{
	"node", "nodejs", "npm", "npx", "yarn", "pnpm", "bun", "deno", "ts-node", "tsx",
	"python", "python3", "uvicorn", "gunicorn", "flask", "celery", "poetry", "uv",
	"php", "php-fpm", "ruby", "bundle", "rails", "puma",
	"java", "dotnet", "sh", "bash", "dash", "ash", "zsh",
}

func isInterpreterBinary(bin string) bool {
	base := strings.ToLower(path.Base(bin))
	return slices.Contains(knownInterpreters, base)
}

func extractApplicationTarget(workdir string, cmd []string) string {
	if len(cmd) < 2 {
		return ""
	}
	for _, arg := range cmd[1:] {
		if strings.HasPrefix(arg, "-") || arg == "-c" || arg == "-m" || arg == "-jar" || arg == "run" || arg == "start" || arg == "serve" {
			continue
		}
		// Look for file-like or path-like target
		if strings.Contains(arg, "/") || strings.HasSuffix(arg, ".js") || strings.HasSuffix(arg, ".mjs") ||
			strings.HasSuffix(arg, ".cjs") || strings.HasSuffix(arg, ".ts") || strings.HasSuffix(arg, ".py") ||
			strings.HasSuffix(arg, ".php") || strings.HasSuffix(arg, ".jar") || strings.HasSuffix(arg, ".rb") ||
			strings.HasSuffix(arg, ".dll") || strings.HasSuffix(arg, ".sh") {
			if strings.HasPrefix(arg, "/") {
				return path.Clean(arg)
			}
			return path.Clean(path.Join(workdir, arg))
		}
	}
	return ""
}

func traceExecutableSource(
	df *ParsedDockerfile,
	summaries []StageSummary,
	targetIdx int,
	workdir string,
	effectiveCmd []string,
	copyEvents []copyEvent,
	runEvents []runEvent,
	copiedArtifacts []ArtifactTrace,
	externalBase string,
) ExecutableTrace {
	if len(effectiveCmd) == 0 {
		// No explicit ENTRYPOINT/CMD in Dockerfile stages; check if any artifacts were copied via COPY --from
		if len(copiedArtifacts) > 0 {
			lastArt := copiedArtifacts[len(copiedArtifacts)-1]
			if lastArt.FromStageIndex >= 0 {
				tc := formatToolchainLabel(lastArt.FromStageToolchain)
				return ExecutableTrace{
					Executable:       "inherited from base image",
					ResolvedPath:     lastArt.Destination,
					OriginType:       "copied-from-stage",
					OriginSummary:    fmt.Sprintf("Copied from the %s build stage", tc),
					SourceStageName:  lastArt.FromStageName,
					SourceStageIndex: lastArt.FromStageIndex,
					SourceStageBase:  lastArt.FromStageBaseImage,
					SourceToolchain:  lastArt.FromStageToolchain,
					CopySourcePath:   strings.Join(lastArt.Sources, ", "),
					CopyDestPath:     lastArt.Destination,
					BuildCommands:    summaries[lastArt.FromStageIndex].BuildCommands,
					Line:             lastArt.Line,
				}
			}
		}
		return ExecutableTrace{
			OriginType:    "base-image",
			OriginSummary: fmt.Sprintf("Provided by runtime base image (%s)", externalBase),
		}
	}

	rawExec := effectiveCmd[0]
	resolvedExec := rawExec
	if strings.HasPrefix(rawExec, "./") || (!strings.HasPrefix(rawExec, "/") && strings.Contains(rawExec, "/")) {
		resolvedExec = path.Clean(path.Join(workdir, rawExec))
	} else if !strings.HasPrefix(rawExec, "/") && !isInterpreterBinary(rawExec) {
		resolvedExec = path.Clean(path.Join(workdir, rawExec))
	}
	appTarget := ""
	if isInterpreterBinary(rawExec) {
		appTarget = extractApplicationTarget(workdir, effectiveCmd)
	}

	// Search copyEvents in reverse chronological order for resolvedExec (or rawExec), and if not found, appTarget
	candidates := []string{resolvedExec}
	if !strings.HasPrefix(rawExec, "/") {
		absInWorkdir := path.Clean(path.Join(workdir, rawExec))
		if !slices.Contains(candidates, absInWorkdir) {
			candidates = append(candidates, absInWorkdir)
		}
	}
	if appTarget != "" && !slices.Contains(candidates, appTarget) {
		candidates = append(candidates, appTarget)
	}

	for _, cand := range candidates {
		for i := len(copyEvents) - 1; i >= 0; i-- {
			ev := copyEvents[i]
			if matchesCopyDestination(cand, ev.sources, ev.absDest, ev.destIsDir) {
				if ev.fromRef != "" {
					if originIdx, ok := resolveStageIndex(df.Stages[:ev.stageIdx], ev.fromRef); ok {
						rootIdx := resolveTransitiveCopyStage(df, summaries, originIdx, ev.sources)
						originSum := summaries[rootIdx]
						tc := formatToolchainLabel(originSum.Toolchain)
						return ExecutableTrace{
							Executable:        rawExec,
							ResolvedPath:      resolvedExec,
							ApplicationTarget: appTarget,
							OriginType:        "copied-from-stage",
							OriginSummary:     fmt.Sprintf("Copied from the %s build stage", tc),
							SourceStageName:   originSum.Name,
							SourceStageIndex:  rootIdx,
							SourceStageBase:   originSum.BaseImage,
							SourceToolchain:   originSum.Toolchain,
							CopySourcePath:    strings.Join(ev.sources, ", "),
							CopyDestPath:      ev.absDest,
							BuildCommands:     originSum.BuildCommands,
							Line:              ev.inst.Line,
						}
					}
					return ExecutableTrace{
						Executable:        rawExec,
						ResolvedPath:      resolvedExec,
						ApplicationTarget: appTarget,
						OriginType:        "copied-from-image",
						OriginSummary:     fmt.Sprintf("Copied from external image %s", ev.fromRef),
						SourceStageIndex:  -1,
						SourceStageBase:   ev.fromRef,
						CopySourcePath:    strings.Join(ev.sources, ", "),
						CopyDestPath:      ev.absDest,
						Line:              ev.inst.Line,
					}
				}
				// Copied from build context, but check if a later RUN command in the runtime chain built the executable!
				if builtTrace, ok := checkBuiltInRuntimeChain(rawExec, resolvedExec, appTarget, targetIdx, summaries, runEvents, ev.inst.Line); ok {
					return builtTrace
				}
				return ExecutableTrace{
					Executable:        rawExec,
					ResolvedPath:      resolvedExec,
					ApplicationTarget: appTarget,
					OriginType:        "copied-from-context",
					OriginSummary:     "Copied from build context into runtime stage",
					SourceStageName:   ev.stageName,
					SourceStageIndex:  ev.stageIdx,
					CopySourcePath:    strings.Join(ev.sources, ", "),
					CopyDestPath:      ev.absDest,
					Line:              ev.inst.Line,
				}
			}
		}
	}

	// Check if built in the runtime stage's own FROM chain via RUN
	if builtTrace, ok := checkBuiltInRuntimeChain(rawExec, resolvedExec, appTarget, targetIdx, summaries, runEvents, 0); ok {
		return builtTrace
	}

	// Fallback: if there is a COPY --from=<stage> in the target stage and the executable wasn't matched by exact path
	if len(copiedArtifacts) > 0 {
		for i := len(copiedArtifacts) - 1; i >= 0; i-- {
			art := copiedArtifacts[i]
			if art.FromStageIndex >= 0 {
				tc := formatToolchainLabel(art.FromStageToolchain)
				return ExecutableTrace{
					Executable:        rawExec,
					ResolvedPath:      resolvedExec,
					ApplicationTarget: appTarget,
					OriginType:        "copied-from-stage",
					OriginSummary:     fmt.Sprintf("Copied from the %s build stage", tc),
					SourceStageName:   art.FromStageName,
					SourceStageIndex:  art.FromStageIndex,
					SourceStageBase:   art.FromStageBaseImage,
					SourceToolchain:   art.FromStageToolchain,
					CopySourcePath:    strings.Join(art.Sources, ", "),
					CopyDestPath:      art.Destination,
					BuildCommands:     summaries[art.FromStageIndex].BuildCommands,
					Line:              art.Line,
				}
			}
		}
	}

	return ExecutableTrace{
		Executable:        rawExec,
		ResolvedPath:      resolvedExec,
		ApplicationTarget: appTarget,
		OriginType:        "base-image",
		OriginSummary:     fmt.Sprintf("Provided by runtime base image (%s)", externalBase),
		SourceStageIndex:  -1,
	}
}

func checkBuiltInRuntimeChain(rawExec, resolvedExec, appTarget string, targetIdx int, summaries []StageSummary, runEvents []runEvent, afterLine int) (ExecutableTrace, bool) {
	baseExec := path.Base(resolvedExec)
	for i := len(runEvents) - 1; i >= 0; i-- {
		re := runEvents[i]
		if re.inst.Line <= afterLine {
			continue
		}
		if strings.Contains(re.command, resolvedExec) ||
			(baseExec != "" && baseExec != "." && baseExec != "/" && !isInterpreterBinary(baseExec) && strings.Contains(re.command, baseExec)) ||
			isBuildCommandText(re.command) {
			sum := summaries[re.stageIdx]
			tc := formatToolchainLabel(sum.Toolchain)
			summaryText := fmt.Sprintf("Built directly in runtime stage (%s)", tc)
			if re.stageIdx != targetIdx {
				stageLabel := re.stageName
				if stageLabel == "" {
					stageLabel = fmt.Sprintf("stage-%d", re.stageIdx)
				}
				summaryText = fmt.Sprintf("Inherited from %s build stage (%s)", tc, stageLabel)
			}
			return ExecutableTrace{
				Executable:        rawExec,
				ResolvedPath:      resolvedExec,
				ApplicationTarget: appTarget,
				OriginType:        "built-in-runtime-chain",
				OriginSummary:     summaryText,
				SourceStageName:   re.stageName,
				SourceStageIndex:  re.stageIdx,
				SourceStageBase:   sum.BaseImage,
				SourceToolchain:   sum.Toolchain,
				BuildCommands:     []string{strings.TrimSpace(re.command)},
				Line:              re.inst.Line,
			}, true
		}
	}
	return ExecutableTrace{}, false
}

func matchesCopyDestination(targetPath string, sources []string, absDest string, destIsDir bool) bool {
	if !strings.HasPrefix(targetPath, "/") {
		return false
	}
	targetClean := path.Clean(targetPath)
	if targetClean == absDest {
		return true
	}
	if strings.HasPrefix(targetClean, absDest+"/") {
		return true
	}
	if destIsDir {
		targetBase := path.Base(targetClean)
		for _, s := range sources {
			srcClean := path.Clean(s)
			if path.Join(absDest, path.Base(srcClean)) == targetClean {
				return true
			}
			if srcClean == "." || srcClean == "./" || strings.HasSuffix(s, "/") || strings.Contains(s, "*") {
				if path.Dir(targetClean) == absDest || strings.HasPrefix(targetClean, absDest+"/") {
					return true
				}
			}
			if path.Base(srcClean) == targetBase && path.Dir(targetClean) == absDest {
				return true
			}
		}
	}
	return false
}

var buildCommandPatterns = []*regexp.Regexp{
	regexp.MustCompile(`\bgo\s+(build|install)\b`),
	regexp.MustCompile(`\bcargo\s+(build|install)\b`),
	regexp.MustCompile(`\b(npm|yarn|pnpm|bun)\s+(install|ci|run\s+build|build)\b`),
	regexp.MustCompile(`\bnext\s+build\b`),
	regexp.MustCompile(`\bcomposer\s+install\b`),
	regexp.MustCompile(`\b(pip|pip3|poetry|uv)\s+(install|sync|build)\b`),
	regexp.MustCompile(`\b(mvn|mvnw|gradle|gradlew)\b`),
	regexp.MustCompile(`\bdotnet\s+(publish|build|restore)\b`),
	regexp.MustCompile(`\b(gcc|g\+\+|clang|make|cmake|ninja|meson)\b`),
	regexp.MustCompile(`\bdocker-php-ext-install\b`),
	regexp.MustCompile(`\bbundle\s+install\b`),
}

func isBuildCommandText(cmd string) bool {
	for _, re := range buildCommandPatterns {
		if re.MatchString(cmd) {
			return true
		}
	}
	return false
}

func detectStageBuildCommands(st Stage) []string {
	var cmds []string
	for _, inst := range st.Instructions {
		if inst.Command == "RUN" {
			text := inst.RawArgs
			if len(inst.Heredocs) > 0 {
				text += "\n" + strings.Join(inst.Heredocs, "\n")
			}
			if isBuildCommandText(text) {
				cmds = append(cmds, strings.TrimSpace(inst.RawArgs))
			}
		}
	}
	return cmds
}

func detectChainBuildCommands(df *ParsedDockerfile, chainAsc []int) []string {
	var cmds []string
	for _, idx := range chainAsc {
		cmds = append(cmds, detectStageBuildCommands(df.Stages[idx])...)
	}
	return cmds
}

func isBuilderStageName(name string) bool {
	n := strings.ToLower(strings.TrimSpace(name))
	return n == "build" || n == "builder" || strings.HasSuffix(n, "-build") || strings.HasSuffix(n, "-builder") || strings.HasPrefix(n, "build-") || strings.HasPrefix(n, "builder-")
}

func normalizeImageName(image string) string {
	img := strings.ToLower(strings.TrimSpace(image))
	if at := strings.IndexByte(img, '@'); at >= 0 {
		img = img[:at]
	}
	if colon := strings.LastIndexByte(img, ':'); colon > strings.LastIndexByte(img, '/') {
		img = img[:colon]
	}
	return img
}

func isBuildBaseImage(image string) bool {
	cat := classifyBaseImageCategory(image)
	return cat == "build-sdk"
}

func classifyBaseImageCategory(image string) string {
	raw := strings.ToLower(strings.TrimSpace(image))
	if raw == "scratch" {
		return "scratch"
	}
	if strings.Contains(raw, "$") {
		return "unresolved-build-arg"
	}
	name := normalizeImageName(raw)
	base := path.Base(name)

	if strings.Contains(name, "distroless") {
		return "distroless"
	}
	if strings.Contains(name, "zendis/static") || strings.Contains(name, "chainguard/static") ||
		strings.Contains(name, "wolfi-base") || (strings.Contains(raw, "static") && strings.Contains(raw, "minimal")) {
		return "minimal"
	}
	// Build SDK / compiler images
	sdkPrefixes := []string{
		"golang", "rust", "maven", "gradle", "gcc", "clang", "llvm", "cmake",
		"composer", "goreleaser", "tonistiigi/xx",
	}
	for _, p := range sdkPrefixes {
		if base == p || strings.HasPrefix(base, p+"-") {
			return "build-sdk"
		}
	}
	if strings.Contains(name, "dotnet/sdk") || strings.Contains(raw, "-sdk") || strings.Contains(raw, "buildpack-deps") {
		return "build-sdk"
	}
	// Language runtime images
	langPrefixes := []string{
		"node", "python", "php", "ruby", "openjdk", "eclipse-temurin", "amazoncorretto", "bellsoft/liberica",
		"bun", "deno", "elixir", "erlang", "julia", "perl", "r-base",
	}
	for _, p := range langPrefixes {
		if base == p || strings.HasPrefix(base, p+"-") {
			return "language-runtime"
		}
	}
	if strings.Contains(name, "dotnet/aspnet") || strings.Contains(name, "dotnet/runtime") {
		return "language-runtime"
	}
	if base == "alpine" || strings.HasSuffix(raw, "-alpine") || strings.Contains(raw, ":alpine") {
		return "alpine"
	}
	if strings.HasSuffix(raw, "-slim") || strings.Contains(raw, "-slim-") {
		return "distro-slim"
	}
	fullDistros := []string{
		"ubuntu", "debian", "centos", "fedora", "rockylinux", "almalinux",
		"amazonlinux", "oraclelinux", "archlinux", "kali", "opensuse", "busybox",
	}
	for _, d := range fullDistros {
		if base == d || strings.Contains(name, "/"+d) {
			return "full-distro"
		}
	}
	return "unknown"
}

func classifyToolchain(baseImage string, buildCmds []string, st Stage) string {
	lowerBase := strings.ToLower(baseImage)
	joinedCmds := strings.ToLower(strings.Join(buildCmds, " "))
	for _, inst := range st.Instructions {
		joinedCmds += " " + strings.ToLower(inst.RawArgs)
	}

	switch {
	case strings.Contains(lowerBase, "golang") || strings.Contains(joinedCmds, "go build") || strings.Contains(joinedCmds, "go install") || strings.Contains(joinedCmds, "go.mod"):
		return "go"
	case strings.Contains(joinedCmds, "next build") || strings.Contains(joinedCmds, ".next/standalone"):
		return "next"
	case strings.Contains(lowerBase, "node") || strings.Contains(lowerBase, "bun") || strings.Contains(lowerBase, "deno") ||
		strings.Contains(joinedCmds, "npm ") || strings.Contains(joinedCmds, "yarn ") || strings.Contains(joinedCmds, "pnpm ") || strings.Contains(joinedCmds, "package.json"):
		return "node"
	case strings.Contains(lowerBase, "php") || strings.Contains(lowerBase, "composer") || strings.Contains(joinedCmds, "composer ") || strings.Contains(joinedCmds, "php-fpm"):
		return "php"
	case strings.Contains(lowerBase, "python") || strings.Contains(joinedCmds, "pip ") || strings.Contains(joinedCmds, "pip3 ") ||
		strings.Contains(joinedCmds, "poetry ") || strings.Contains(joinedCmds, "requirements.txt") || strings.Contains(joinedCmds, "pyproject.toml"):
		return "python"
	case strings.Contains(lowerBase, "rust") || strings.Contains(joinedCmds, "cargo "):
		return "rust"
	case strings.Contains(lowerBase, "maven") || strings.Contains(lowerBase, "gradle") || strings.Contains(lowerBase, "openjdk") ||
		strings.Contains(lowerBase, "temurin") || strings.Contains(joinedCmds, "mvn ") || strings.Contains(joinedCmds, "gradle"):
		return "java"
	case strings.Contains(lowerBase, "dotnet") || strings.Contains(joinedCmds, "dotnet "):
		return "dotnet"
	case strings.Contains(lowerBase, "ruby") || strings.Contains(joinedCmds, "bundle install") || strings.Contains(joinedCmds, "gem install"):
		return "ruby"
	case strings.Contains(lowerBase, "gcc") || strings.Contains(lowerBase, "clang") || strings.Contains(joinedCmds, "cmake") || strings.Contains(joinedCmds, "gcc ") || strings.Contains(joinedCmds, "g++ "):
		return "c/cpp"
	default:
		return "other"
	}
}

func formatToolchainLabel(tc string) string {
	switch tc {
	case "go":
		return "Go"
	case "node":
		return "Node.js"
	case "next":
		return "Next.js"
	case "php":
		return "PHP"
	case "python":
		return "Python"
	case "rust":
		return "Rust"
	case "java":
		return "Java"
	case "dotnet":
		return ".NET"
	case "ruby":
		return "Ruby"
	case "c/cpp":
		return "C/C++"
	default:
		return "application"
	}
}

func detectApplicationRuntime(df *ParsedDockerfile, summaries []StageSummary, effectiveCmd []string, execTrace ExecutableTrace) string {
	if execTrace.SourceToolchain != "" && execTrace.SourceToolchain != "other" {
		// Check if any stage detected next
		for _, s := range summaries {
			if s.Toolchain == "next" {
				return "next"
			}
		}
		return execTrace.SourceToolchain
	}
	for _, s := range summaries {
		if s.Toolchain == "next" {
			return "next"
		}
	}
	for i := len(summaries) - 1; i >= 0; i-- {
		if summaries[i].Toolchain != "" && summaries[i].Toolchain != "other" {
			return summaries[i].Toolchain
		}
	}
	cmdStr := strings.ToLower(strings.Join(effectiveCmd, " "))
	switch {
	case strings.Contains(cmdStr, "node") || strings.Contains(cmdStr, "npm"):
		return "node"
	case strings.Contains(cmdStr, "python") || strings.Contains(cmdStr, "uvicorn") || strings.Contains(cmdStr, "gunicorn"):
		return "python"
	case strings.Contains(cmdStr, "php"):
		return "php"
	case strings.Contains(cmdStr, "java") || strings.Contains(cmdStr, ".jar"):
		return "java"
	case strings.Contains(cmdStr, "ruby") || strings.Contains(cmdStr, "rails") || strings.Contains(cmdStr, "puma"):
		return "ruby"
	}
	return "other"
}

var runtimeToolRegexes = []struct {
	name string
	re   *regexp.Regexp
}{
	{"apt-get/apt", regexp.MustCompile(`\b(apt-get|apt)\s+(install|update|upgrade)\b`)},
	{"apk", regexp.MustCompile(`\bapk\s+(add|update)\b`)},
	{"yum/dnf", regexp.MustCompile(`\b(yum|dnf|microdnf)\s+install\b`)},
	{"pip", regexp.MustCompile(`\b(pip|pip3)\s+install\b`)},
	{"npm/yarn/pnpm", regexp.MustCompile(`\b(npm|yarn|pnpm)\s+(install|ci|add|global)\b`)},
	{"composer", regexp.MustCompile(`\bcomposer\s+install\b`)},
	{"go-toolchain", regexp.MustCompile(`\bgo\s+(build|install|get|mod)\b`)},
	{"cargo", regexp.MustCompile(`\bcargo\s+(build|install)\b`)},
	{"compiler/make", regexp.MustCompile(`\b(gcc|g\+\+|clang|make|cmake|build-essential)\b`)},
	{"curl", regexp.MustCompile(`\bcurl\b`)},
	{"wget", regexp.MustCompile(`\bwget\b`)},
	{"git", regexp.MustCompile(`\bgit\s+(clone|pull|checkout)\b`)},
	{"sudo", regexp.MustCompile(`\bsudo\b`)},
}

var (
	pipeToShellRE = regexp.MustCompile(`(curl|wget)\b[^|\n]*\|\s*(sudo\s+)?(sh|bash|zsh|dash)\b`)
	chmod777RE    = regexp.MustCompile(`\bchmod\s+(-R\s+)?(0?777|[ugo]*\+s|[2467][0-7]{3})\b`)
	numericUserRE = regexp.MustCompile(`^[0-9]+(:[0-9]+)?$`)
	secretKeyRE   = regexp.MustCompile(`(?i)(SECRET|PASSWORD|PASSWD|PRIVATE_KEY|API_KEY|ACCESS_KEY|AUTH_TOKEN|GITHUB_TOKEN|AWS_SECRET)`)
)

func isLikelyHardcodedSecret(key, val string, hasVal bool) bool {
	if !hasVal {
		return false
	}
	v := strings.TrimSpace(val)
	if v == "" || strings.HasPrefix(v, "$") {
		return false
	}
	lowerVal := strings.ToLower(v)
	if slices.Contains([]string{"true", "false", "0", "1", "yes", "no", "none", "null"}, lowerVal) {
		return false
	}
	upperKey := strings.ToUpper(strings.TrimSpace(key))
	for _, prefix := range []string{"REQUIRE_", "ENABLE_", "DISABLE_", "ALLOW_", "USE_", "SKIP_", "HAS_", "IS_"} {
		if strings.HasPrefix(upperKey, prefix) {
			return false
		}
	}
	for _, suffix := range []string{"_FILE", "_PATH", "_DIR", "_HEADER", "_NAME", "_LEN", "_LENGTH", "_TTL", "_TIMEOUT", "_ENABLED", "_REQUIRED"} {
		if strings.HasSuffix(upperKey, suffix) {
			return false
		}
	}
	return secretKeyRE.MatchString(upperKey)
}

func assessHardening(df *ParsedDockerfile, r *TraceReport, chainAsc []int, runEvents []runEvent) HardeningAssessment {
	var findings []Finding
	score := 0
	addFinding := func(code, severity string, points int, msg string, line int) {
		findings = append(findings, Finding{
			Code:     code,
			Severity: severity,
			Points:   points,
			Message:  msg,
			Line:     line,
		})
		score += points
	}

	baseCat := classifyBaseImageCategory(r.RuntimeBase)
	minimalBase := baseCat == "scratch" || baseCat == "distroless" || baseCat == "minimal"
	targetLine := df.Stages[r.TargetStageIndex].Line

	// 1. Multi-stage & build-environment inheritance checks
	if r.SingleStage {
		if !minimalBase {
			addFinding("single_stage_build", "high", 25,
				"Single-stage Dockerfile without multi-stage builder separation; build and runtime environments are combined", targetLine)
		}
	} else if r.InheritsBuildStage {
		addFinding("inherits_build_environment", "high", 25,
			fmt.Sprintf("Target stage inherits directly from build stage (%s) instead of copying artifacts into a separate minimal runtime image", strings.Join(r.FromChain, " -> ")), targetLine)
	} else if !r.UsesMultiStageCopy && !minimalBase {
		addFinding("unused_multistage_separation", "medium", 15,
			"Dockerfile defines multiple stages but the deployed stage does not copy artifacts from a dedicated build stage", targetLine)
	}

	// 2. Base image category check
	switch baseCat {
	case "build-sdk":
		addFinding("sdk_runtime_base", "high", 20,
			fmt.Sprintf("Runtime stage uses a compiler/SDK base image (%s) containing full build toolchains", r.RuntimeBase), targetLine)
	case "full-distro":
		addFinding("full_os_runtime_base", "medium", 15,
			fmt.Sprintf("Runtime stage uses a full OS distribution base image (%s) with shell and package manager utilities", r.RuntimeBase), targetLine)
	case "language-runtime":
		addFinding("language_distro_runtime_base", "medium", 10,
			fmt.Sprintf("Runtime stage uses a general language distribution image (%s) rather than a minimal/distroless runtime", r.RuntimeBase), targetLine)
	case "distro-slim", "alpine":
		addFinding("non_minimal_runtime_base", "low", 5,
			fmt.Sprintf("Runtime stage uses %s (%s) which retains a shell and package manager", baseCat, r.RuntimeBase), targetLine)
	}

	// 3. Base image tag / digest pinning
	digestPinned := strings.Contains(r.RuntimeBase, "@sha256:") || strings.EqualFold(r.RuntimeBase, "scratch")
	floatingTag := false
	if baseCat == "unresolved-build-arg" {
		addFinding("unresolved_base_build_arg", "medium", 10,
			fmt.Sprintf("Runtime base image %q depends on an unresolved build argument; pass --build-arg to resolve", r.RuntimeBase), targetLine)
	} else if !digestPinned {
		afterSlash := r.RuntimeBase
		if idx := strings.LastIndexByte(r.RuntimeBase, '/'); idx >= 0 {
			afterSlash = r.RuntimeBase[idx+1:]
		}
		if !strings.Contains(afterSlash, ":") || strings.HasSuffix(strings.ToLower(afterSlash), ":latest") {
			floatingTag = true
			addFinding("floating_latest_tag", "medium", 10,
				fmt.Sprintf("Runtime base image %q uses an unpinned :latest or default tag", r.RuntimeBase), targetLine)
		}
	}

	// 4. USER check (non-root & numeric UID:GID)
	user := strings.TrimSpace(r.EffectiveUser)
	lowerUser := strings.ToLower(user)
	runsAsRoot := false
	numericNonRoot := false
	if user == "" {
		// Distroless :nonroot tags default to non-root UID 65532, though explicit numeric USER is still best practice
		if strings.Contains(strings.ToLower(r.RuntimeBase), ":nonroot") || strings.Contains(strings.ToLower(r.RuntimeBase), "-nonroot") {
			runsAsRoot = false
		} else {
			runsAsRoot = true
			addFinding("missing_user_instruction", "high", 15,
				"No USER instruction in the runtime stage chain; container runs as root (UID 0) by default", targetLine)
		}
	} else if lowerUser == "root" || lowerUser == "0" || strings.HasPrefix(lowerUser, "0:") || strings.HasPrefix(lowerUser, "root:") {
		runsAsRoot = true
		addFinding("explicit_root_user", "high", 15,
			fmt.Sprintf("Runtime stage explicitly sets USER %s", user), targetLine)
	} else if numericUserRE.MatchString(user) {
		numericNonRoot = true
	} else {
		addFinding("symbolic_user_name", "low", 5,
			fmt.Sprintf("USER %q uses a symbolic username instead of an explicit numeric UID:GID (cannot verify runAsNonRoot without image passwd)", user), targetLine)
	}

	// 5. Runtime stage RUN tools (package managers, compilers, downloaders, pipe-to-shell, chmod 777)
	var toolsUsed []string
	var firstToolLine int
	pipeToShellLine := 0
	chmodLine := 0

	for _, re := range runEvents {
		for _, tool := range runtimeToolRegexes {
			if tool.re.MatchString(re.command) {
				if !slices.Contains(toolsUsed, tool.name) {
					toolsUsed = append(toolsUsed, tool.name)
					if firstToolLine == 0 {
						firstToolLine = re.inst.Line
					}
				}
			}
		}
		if pipeToShellLine == 0 && pipeToShellRE.MatchString(re.command) {
			pipeToShellLine = re.inst.Line
		}
		if chmodLine == 0 && chmod777RE.MatchString(re.command) {
			chmodLine = re.inst.Line
		}
	}

	if len(toolsUsed) > 0 {
		addFinding("runtime_build_or_package_tools", "high", 15,
			fmt.Sprintf("Runtime stage chain executes package managers, compilers, or network tools (%s)", strings.Join(toolsUsed, ", ")), firstToolLine)
	}
	if pipeToShellLine > 0 {
		addFinding("remote_script_pipe_to_shell", "high", 20,
			"Runtime stage pipes curl/wget output directly into a shell", pipeToShellLine)
	}
	if chmodLine > 0 {
		addFinding("permissive_chmod_or_setuid", "high", 15,
			"Runtime stage grants world-writable (777) or setuid/setgid permissions", chmodLine)
	}

	// 6. Startup form (exec form vs shell form / shell wrapper)
	execFormStartup := true
	startupLine := targetLine
	if r.Entrypoint != nil && !r.Entrypoint.ExecForm {
		execFormStartup = false
		startupLine = r.Entrypoint.Line
	}
	if r.Cmd != nil && !r.Cmd.InheritedFromBaseImage && !r.Cmd.ExecForm {
		execFormStartup = false
		startupLine = r.Cmd.Line
	}
	if !execFormStartup {
		addFinding("shell_form_startup", "medium", 10,
			fmt.Sprintf("Startup instruction (%s) uses shell form instead of JSON exec array, requiring /bin/sh at runtime", r.StartupDeclaration), startupLine)
	} else if len(r.EffectiveCommand) > 0 {
		firstBin := path.Base(r.EffectiveCommand[0])
		if slices.Contains([]string{"sh", "bash", "dash", "ash", "zsh"}, firstBin) || strings.HasSuffix(firstBin, ".sh") {
			execFormStartup = false
			addFinding("shell_wrapper_entrypoint", "medium", 10,
				fmt.Sprintf("Startup command (%s) invokes a shell or .sh wrapper script, requiring a shell in the runtime image", r.EffectiveCommand[0]), startupLine)
		}
	}

	// 7. Check for ADD, privileged ports, and hardcoded secret-like ENV/ARG in runtime chain
	addFindingEmitted := false
	seenSecretKeys := map[string]bool{}
	for _, stIdx := range chainAsc {
		for _, inst := range df.Stages[stIdx].Instructions {
			if inst.Command == "ADD" && !addFindingEmitted {
				addFindingEmitted = true
				addFinding("add_instruction_used", "low", 5,
					"Uses ADD instead of COPY in runtime stage chain", inst.Line)
			}
			if inst.Command == "ENV" || inst.Command == "ARG" {
				var kvs []KeyValue
				if inst.Command == "ENV" {
					kvs = parseEnvInstruction(inst, df.Escape)
				} else {
					kvs = parseArgInstruction(inst)
				}
				for _, kv := range kvs {
					if !seenSecretKeys[kv.Key] && isLikelyHardcodedSecret(kv.Key, kv.Value, kv.HasValue) {
						seenSecretKeys[kv.Key] = true
						addFinding("hardcoded_secret_env", "high", 15,
							fmt.Sprintf("%s %s sets a non-empty value for a secret-like variable name", inst.Command, kv.Key), inst.Line)
					}
				}
			}
		}
	}
	for _, p := range r.ExposedPorts {
		if p > 0 && p < 1024 {
			addFinding("privileged_port_exposed", "low", 5,
				fmt.Sprintf("EXPOSE %d declares a privileged port (< 1024)", p), targetLine)
			break
		}
	}

	if score > 100 {
		score = 100
	}

	classification := "hardened"
	switch {
	case score >= 55:
		classification = "terrible"
	case score >= 30:
		classification = "unhardened"
	case score > 10:
		classification = "partially-hardened"
	}

	return HardeningAssessment{
		Classification:      classification,
		UnhardenedScore:     score,
		MinimalBase:         minimalBase,
		BaseCategory:        baseCat,
		DigestPinned:        digestPinned,
		FloatingTag:         floatingTag,
		RunsAsRoot:          runsAsRoot,
		NumericNonRootUser:  numericNonRoot,
		EffectiveUser:       user,
		ExecFormStartup:     execFormStartup,
		NoRuntimeBuildTools: len(toolsUsed) == 0,
		RuntimeToolsUsed:    toolsUsed,
		Findings:            findings,
	}
}

// FormatMarkdownTable formats the key stage-trace and hardening properties as a Markdown summary.
func (r *TraceReport) FormatMarkdownTable() string {
	var b strings.Builder
	execLabel := r.ExecutableTrace.Executable
	if execLabel == "" {
		execLabel = "Startup executable"
	} else {
		execLabel = fmt.Sprintf("`%s` executable", execLabel)
	}
	b.WriteString("| Property | Origin |\n")
	b.WriteString("|---|---|\n")
	b.WriteString(fmt.Sprintf("| Deployed stage | `%s` (stage %d of %d) |\n", stageDisplayName(r.TargetStageName, r.TargetStageIndex), r.TargetStageIndex+1, r.StageCount))
	b.WriteString(fmt.Sprintf("| `FROM` chain | `%s` |\n", strings.Join(r.FromChain, " -> ")))
	b.WriteString(fmt.Sprintf("| Runtime base | `%s` (%s) |\n", r.RuntimeBase, r.Hardening.BaseCategory))
	b.WriteString(fmt.Sprintf("| Startup declaration | `%s` |\n", r.StartupDeclaration))
	b.WriteString(fmt.Sprintf("| %s | %s |\n", execLabel, r.ExecutableTrace.OriginSummary))
	b.WriteString(fmt.Sprintf("| Multi-stage pattern | `%s` (inherits build stage: `%t`, runs in build env: `%t`) |\n", r.MultiStagePattern, r.InheritsBuildStage, r.RunsInBuildEnv))
	b.WriteString(fmt.Sprintf("| Hardening assessment | **%s** (unhardened score: %d/100, runs as root: `%t`) |\n", strings.ToUpper(r.Hardening.Classification), r.Hardening.UnhardenedScore, r.Hardening.RunsAsRoot))
	return b.String()
}

func stageDisplayName(name string, index int) string {
	if name != "" {
		return name
	}
	return fmt.Sprintf("stage-%d", index)
}
