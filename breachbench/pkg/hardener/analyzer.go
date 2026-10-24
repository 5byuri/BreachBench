package hardener

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"google.golang.org/genai"
)

// DockerfileAnalysis represents the extracted components and security posture
// findings of an unhardened Debian/Ubuntu Dockerfile.
type DockerfileAnalysis struct {
	OriginalBaseImage string   `json:"originalBaseImage"`
	BuilderBaseImage  string   `json:"builderBaseImage"`
	AptPackages       []string `json:"aptPackages"`
	AppBuildSteps     []string `json:"appBuildSteps"`
	FinalCopySteps    []string `json:"finalCopySteps"`
	EnvVars           []string `json:"envVars"`
	ExposePorts       []string `json:"exposePorts"`
	Workdir           string   `json:"workdir"`
	Entrypoint        string   `json:"entrypoint"`
	Cmd               string   `json:"cmd"`
	DetectedIssues    []string `json:"detectedIssues"`
}

var (
	aptInstallRegex = regexp.MustCompile(`apt(?:-get)?\s+(?:-[a-zA-Z0-9=-]+\s+)*install\s+([^&;|]+)`)
	validDebPkgName = regexp.MustCompile(`^[a-z0-9][a-z0-9+.-]+$`)
	fromStageRegex  = regexp.MustCompile(`(?im)^\s*FROM\s+(?:--platform=\S+\s+)?([^\s#]+)(?:\s+[aA][sS]\s+([^\s#]+))?`)
	distroBaseRegex = regexp.MustCompile(`(?i)^(?:docker\.io/|ghcr\.io/)?(?:library/)?(?:ubuntu|debian|python|node|golang|rust|ruby|php|openjdk|buildpack-deps|nvidia/cuda)(?::\S+|@\S+)?$`)
)

// IsUnhardenedDistroDockerfile uses regex and stage-alias resolution to determine whether
// a Dockerfile's final runtime stage starts from an unhardened Debian/Ubuntu-family distro image
// rather than scratch, distroless, or alpine. Returns (matched, resolvedRuntimeBaseImage).
func IsUnhardenedDistroDockerfile(dockerfileContent string) (bool, string) {
	argDefaults := make(map[string]string)
	for _, line := range joinContinuationLines(dockerfileContent) {
		if strings.HasPrefix(strings.ToUpper(line), "ARG ") {
			argExpr := strings.TrimSpace(line[4:])
			if kv := strings.SplitN(argExpr, "=", 2); len(kv) == 2 {
				argDefaults[strings.TrimSpace(kv[0])] = strings.Trim(strings.TrimSpace(kv[1]), `"'`)
			}
		}
	}

	matches := fromStageRegex.FindAllStringSubmatch(dockerfileContent, -1)
	if len(matches) == 0 {
		return false, ""
	}

	aliases := make(map[string]string)
	var finalBase string
	for _, m := range matches {
		img := m[1]
		alias := ""
		if len(m) > 2 {
			alias = m[2]
		}
		for k, v := range argDefaults {
			img = strings.ReplaceAll(img, "${"+k+"}", v)
			img = strings.ReplaceAll(img, "$"+k, v)
		}
		if resolved, ok := aliases[img]; ok {
			img = resolved
		}
		if alias != "" {
			aliases[alias] = img
		}
		finalBase = img
	}

	lower := strings.ToLower(finalBase)
	if strings.Contains(lower, "scratch") || strings.Contains(lower, "distroless") || strings.Contains(lower, "alpine") {
		return false, finalBase
	}
	if distroBaseRegex.MatchString(finalBase) {
		return true, finalBase
	}
	return false, finalBase
}

// AnalyzeDockerfile inspects an unhardened Dockerfile using Gemini (google.golang.org/genai)
// with a deterministic fallback parser so it always succeeds even offline.
func AnalyzeDockerfile(ctx context.Context, dockerfileContent string, apiKey string) (*DockerfileAnalysis, error) {
	if strings.TrimSpace(dockerfileContent) == "" {
		return nil, fmt.Errorf("dockerfile content is empty")
	}

	deterministic := AnalyzeDockerfileDeterministic(dockerfileContent)

	if apiKey == "" {
		apiKey = os.Getenv("GEMINI_API_KEY")
	}
	if strings.TrimSpace(apiKey) == "" {
		return deterministic, nil
	}

	client, err := genai.NewClient(ctx, &genai.ClientConfig{
		APIKey:  apiKey,
		Backend: genai.BackendGeminiAPI,
	})
	if err != nil {
		return deterministic, nil
	}

	prompt := fmt.Sprintf(`Analyze the following unhardened Dockerfile and extract a structured JSON object matching these exact keys:
- "originalBaseImage": string (the primary or final runtime FROM image, e.g. "ubuntu:22.04" or "debian:bookworm-slim")
- "builderBaseImage": string (the Debian or Ubuntu base image to use for the deb2scratch builder stage)
- "aptPackages": array of strings (valid Debian/Ubuntu runtime package names installed via apt/apt-get)
- "appBuildSteps": array of strings (non-apt RUN build instructions to preserve in the builder stage)
- "finalCopySteps": array of strings (COPY or ADD instructions from the Dockerfile)
- "envVars": array of strings (ENV key=value pairs)
- "exposePorts": array of strings (exposed ports from EXPOSE directives)
- "workdir": string (WORKDIR path, or "/home/nonroot" if none)
- "entrypoint": string (ENTRYPOINT directive value if present)
- "cmd": string (CMD directive value if present)
- "detectedIssues": array of strings (4-5 specific container security vulnerabilities present in the original Dockerfile)

Dockerfile:
%s`, dockerfileContent)

	cfg := &genai.GenerateContentConfig{
		ResponseMIMEType: "application/json",
	}

	resp, err := client.Models.GenerateContent(ctx, "gemini-flash-latest", genai.Text(prompt), cfg)
	if err != nil || resp == nil || resp.Text() == "" {
		return deterministic, nil
	}

	var parsed DockerfileAnalysis
	if err := json.Unmarshal([]byte(resp.Text()), &parsed); err != nil {
		return deterministic, nil
	}

	mergeWithDeterministic(&parsed, deterministic)
	return &parsed, nil
}

// AnalyzeDockerfileDeterministic parses a Dockerfile without external API calls.
func AnalyzeDockerfileDeterministic(dockerfileContent string) *DockerfileAnalysis {
	logicalLines := joinContinuationLines(dockerfileContent)

	originalBase := "debian:bookworm-slim"
	var aptPackages []string
	var appBuildSteps []string
	var finalCopySteps []string
	var envVars []string
	var exposePorts []string
	var workdir string
	var entrypoint string
	var cmd string
	hasNonRootUser := false

	seenPkg := make(map[string]bool)
	stageAliases := make(map[string]string)
	argDefaults := make(map[string]string)

	for _, line := range logicalLines {
		upper := strings.ToUpper(line)
		switch {
		case strings.HasPrefix(upper, "ARG "):
			argExpr := strings.TrimSpace(line[4:])
			if kv := strings.SplitN(argExpr, "=", 2); len(kv) == 2 {
				argDefaults[strings.TrimSpace(kv[0])] = strings.Trim(strings.TrimSpace(kv[1]), `"'`)
			}
		case strings.HasPrefix(upper, "FROM "):
			fields := strings.Fields(line)
			var img string
			var alias string
			for i := 1; i < len(fields); i++ {
				if strings.HasPrefix(fields[i], "--") {
					continue
				}
				if img == "" {
					img = fields[i]
				} else if strings.EqualFold(fields[i], "AS") && i+1 < len(fields) {
					alias = fields[i+1]
					break
				}
			}
			for k, v := range argDefaults {
				img = strings.ReplaceAll(img, "${"+k+"}", v)
				img = strings.ReplaceAll(img, "$"+k, v)
			}
			if resolved, isAlias := stageAliases[img]; isAlias {
				img = resolved
			}
			if alias != "" && img != "" {
				stageAliases[alias] = img
			}
			if img != "" {
				originalBase = img
			}
		case strings.HasPrefix(upper, "USER "):
			u := strings.TrimSpace(line[5:])
			if u != "" && u != "root" && u != "0" && u != "0:0" {
				hasNonRootUser = true
			}
		case strings.HasPrefix(upper, "WORKDIR "):
			workdir = strings.TrimSpace(line[8:])
		case strings.HasPrefix(upper, "EXPOSE "):
			exposePorts = append(exposePorts, strings.TrimSpace(line[7:]))
		case strings.HasPrefix(upper, "ENV "):
			envVars = append(envVars, strings.TrimSpace(line[4:]))
		case strings.HasPrefix(upper, "ENTRYPOINT "):
			entrypoint = strings.TrimSpace(line[11:])
		case strings.HasPrefix(upper, "CMD "):
			cmd = strings.TrimSpace(line[4:])
		case strings.HasPrefix(upper, "COPY "), strings.HasPrefix(upper, "ADD "):
			finalCopySteps = append(finalCopySteps, line)
		case strings.HasPrefix(upper, "RUN "):
			runBody := strings.TrimSpace(line[4:])
			if strings.Contains(runBody, "apt-get") || strings.Contains(runBody, "apt ") {
				matches := aptInstallRegex.FindAllStringSubmatch(runBody, -1)
				for _, m := range matches {
					for _, tok := range strings.Fields(m[1]) {
						clean := strings.Trim(tok, `"'`)
						if validDebPkgName.MatchString(clean) && !seenPkg[clean] {
							seenPkg[clean] = true
							aptPackages = append(aptPackages, clean)
						}
					}
				}
			} else {
				appBuildSteps = append(appBuildSteps, line)
			}
		}
	}

	if len(aptPackages) == 0 {
		aptPackages = []string{"ca-certificates", "tzdata"}
	}

	builderBase := originalBase
	lowerBase := strings.ToLower(builderBase)
	if lowerBase == "scratch" || strings.Contains(lowerBase, "distroless") {
		builderBase = "debian:bookworm-slim"
	}

	if workdir == "" {
		workdir = "/home/nonroot"
	}

	issues := []string{
		fmt.Sprintf("Uses full distribution base image (`%s`) in runtime stage, leaving interactive shells (`/bin/sh`, `/bin/bash`) and coreutils accessible after RCE", originalBase),
	}
	if !hasNonRootUser {
		issues = append(issues, "Container executes as `root` (UID 0) without an unprivileged `USER` directive, amplifying container breakout risk")
	}
	issues = append(issues,
		"Package managers (`apt`, `dpkg`) remain in the image, enabling attackers to download post-exploitation tooling inside the container",
		"No immutable CycloneDX Software Bill of Materials (`/sbom.json`) attested inside the runtime rootfs",
		"Unneeded transitive OS binaries and shared libraries increase CVE surface area",
	)

	return &DockerfileAnalysis{
		OriginalBaseImage: originalBase,
		BuilderBaseImage:  builderBase,
		AptPackages:       aptPackages,
		AppBuildSteps:     appBuildSteps,
		FinalCopySteps:    finalCopySteps,
		EnvVars:           envVars,
		ExposePorts:       exposePorts,
		Workdir:           workdir,
		Entrypoint:        entrypoint,
		Cmd:               cmd,
		DetectedIssues:    issues,
	}
}

func joinContinuationLines(dockerfile string) []string {
	var logical []string
	var buf strings.Builder

	for _, rawLine := range strings.Split(dockerfile, "\n") {
		trimmed := strings.TrimSpace(rawLine)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasSuffix(trimmed, "\\") {
			buf.WriteString(strings.TrimSpace(strings.TrimSuffix(trimmed, "\\")))
			buf.WriteString(" ")
		} else {
			buf.WriteString(trimmed)
			logical = append(logical, strings.TrimSpace(buf.String()))
			buf.Reset()
		}
	}
	if buf.Len() > 0 {
		logical = append(logical, strings.TrimSpace(buf.String()))
	}
	return logical
}

func mergeWithDeterministic(target, fallback *DockerfileAnalysis) {
	if target.OriginalBaseImage == "" {
		target.OriginalBaseImage = fallback.OriginalBaseImage
	}
	if target.BuilderBaseImage == "" {
		target.BuilderBaseImage = fallback.BuilderBaseImage
	}
	if len(target.AptPackages) == 0 {
		target.AptPackages = fallback.AptPackages
	}
	if target.Workdir == "" {
		target.Workdir = fallback.Workdir
	}
	if target.Entrypoint == "" {
		target.Entrypoint = fallback.Entrypoint
	}
	if target.Cmd == "" {
		target.Cmd = fallback.Cmd
	}
	if len(target.DetectedIssues) == 0 {
		target.DetectedIssues = fallback.DetectedIssues
	}
}
