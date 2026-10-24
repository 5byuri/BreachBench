package imagehardening

import (
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
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"
)

// Only these fields may enter an agent transcript. Image arguments, environment,
// labels, history, and health checks can contain credentials and are never requested.
type imageFacts struct {
	ID                  string                     `json:"id"`
	Architecture        string                     `json:"architecture"`
	OS                  string                     `json:"os"`
	SizeBytes           int64                      `json:"size_bytes"`
	User                string                     `json:"user"`
	WorkingDirectory    string                     `json:"working_directory"`
	EntrypointArguments int                        `json:"entrypoint_arguments"`
	CommandArguments    int                        `json:"command_arguments"`
	OnBuildTriggers     int                        `json:"onbuild_triggers"`
	ExposedPorts        map[string]json.RawMessage `json:"exposed_ports"`
	DeclaredVolumes     map[string]json.RawMessage `json:"declared_volumes"`
}

const imageFactsFormat = `{"id":{{json .Id}},"architecture":{{json .Architecture}},"os":{{json .Os}},"size_bytes":{{.Size}},"user":{{json (index .Config "User")}},"working_directory":{{json (index .Config "WorkingDir")}},"entrypoint_arguments":{{if index .Config "Entrypoint"}}{{len (index .Config "Entrypoint")}}{{else}}0{{end}},"command_arguments":{{if index .Config "Cmd"}}{{len (index .Config "Cmd")}}{{else}}0{{end}},"onbuild_triggers":{{if index .Config "OnBuild"}}{{len (index .Config "OnBuild")}}{{else}}0{{end}},"exposed_ports":{{json (index .Config "ExposedPorts")}},"declared_volumes":{{json (index .Config "Volumes")}}}`

type toolCapture func(context.Context, string, ...string) ([]byte, error)

func inspectImage(ctx context.Context, image string) (imageFacts, error) {
	return inspectImageWith(ctx, image, capture)
}

func inspectImageWith(ctx context.Context, image string, run toolCapture) (imageFacts, error) {
	var facts imageFacts
	if err := toolImageReference(image); err != nil {
		return facts, err
	}
	data, err := run(ctx, "docker", "image", "inspect", "--format", imageFactsFormat, "--", image)
	if err != nil {
		return facts, errors.New("local Docker image inspection failed")
	}
	if len(data) > 64*1024 || json.Unmarshal(data, &facts) != nil || !slimImageID(facts.ID) || facts.SizeBytes < 0 {
		return imageFacts{}, errors.New("Docker returned invalid image metadata")
	}
	return facts, nil
}

type slimMinifyResult struct {
	Image             string   `json:"image"`
	ArtifactDir       string   `json:"artifact_directory"`
	SeccompProfile    string   `json:"generated_seccomp_profile,omitempty"`
	ProfileSeconds    int      `json:"profile_seconds"`
	ProfilingNetwork  string   `json:"profiling_network"`
	IncludePaths      []string `json:"include_paths"`
	ApplicationTested bool     `json:"application_tested"`
	Scope             string   `json:"scope"`
}

// slimMinify profiles the original entrypoint/CMD, without updating packages or
// accepting model-authored commands. A separate, unchanged workload test must pass.
func slimMinify(ctx context.Context, slimBinary, sourceImage, candidateImage, artifactDir string, includePaths []string) (slimMinifyResult, error) {
	run := func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name == "docker" {
			return boundedToolCapture(ctx, name, args...)
		}
		log, err := os.OpenFile(filepath.Join(artifactDir, "slim.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			return nil, errors.New("cannot create private Slim diagnostic log without overwriting a file")
		}
		defer log.Close()
		return boundedToolCaptureLog(ctx, name, log, args...)
	}
	return slimMinifyWith(ctx, slimBinary, sourceImage, candidateImage, artifactDir, includePaths, run)
}

func slimMinifyWith(ctx context.Context, slimBinary, sourceImage, candidateImage, artifactDir string, includePaths []string, run toolCapture) (slimMinifyResult, error) {
	result := slimMinifyResult{}
	marker := make([]byte, 12)
	if _, err := rand.Read(marker); err != nil {
		return result, err
	}
	owner := hex.EncodeToString(marker)
	network := "hardening-profile-" + owner
	label := "container-hardening-work-bench.slim=" + owner
	args, err := slimBuildArgs(sourceImage, candidateImage, artifactDir, network, includePaths)
	if err != nil {
		return result, err
	}
	if slimBinary == "" || strings.HasPrefix(slimBinary, "-") || strings.ContainsFunc(slimBinary, unicode.IsControl) {
		return result, errors.New("a Slim executable is required")
	}
	info, err := os.Lstat(artifactDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 {
		return result, errors.New("artifact directory must be an existing private directory (0700), not a symlink")
	}
	// Slim requires TCP sensor IPC. An internal bridge permits that control plane
	// without giving the profiled application an Internet route.
	hostConfig, err := os.OpenFile(filepath.Join(artifactDir, "profiling-host-config.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return result, errors.New("cannot create private profiling configuration without overwriting a file")
	}
	_, writeErr := io.WriteString(hostConfig, `{"PortBindings":{"65501/tcp":[{"HostIp":"127.0.0.1","HostPort":""}],"65502/tcp":[{"HostIp":"127.0.0.1","HostPort":""}]}}`)
	closeErr := hostConfig.Close()
	if writeErr != nil || closeErr != nil {
		return result, errors.New("cannot write private profiling configuration")
	}
	if _, err := run(ctx, "docker", "network", "create", "--internal", "--driver", "bridge", "--label", label, "--opt", "com.docker.network.bridge.host_binding_ipv4=127.0.0.1", network); err != nil {
		return result, errors.New("could not create isolated internal profiling network")
	}
	defer cleanupSlimResources(label, network, run)
	if _, err := run(ctx, slimBinary, append(args, "--label", label)...); err != nil {
		return result, errors.New("Slim profiling/minification failed; no validated candidate is available")
	}
	result = slimMinifyResult{
		Image: candidateImage, ArtifactDir: artifactDir, ProfileSeconds: 10, ProfilingNetwork: "owned internal bridge, loopback-only sensor IPC; final deployment policy is separate",
		IncludePaths: append([]string{}, includePaths...), ApplicationTested: false,
		Scope: "Original image files retained by Slim using a ten-second runtime observation window and explicit retention paths; unobserved behavior still requires workload tests. Generated profiles are not applied automatically. Slim may run a privileged profiling sensor: use trusted images on an isolated Docker host.",
	}
	entries, err := os.ReadDir(artifactDir)
	if err != nil {
		return result, fmt.Errorf("read Slim artifact directory: %w", err)
	}
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), "-seccomp.json") && entry.Name() != "seccomp.json" {
			continue
		}
		profilePath := filepath.Join(artifactDir, entry.Name())
		info, err := os.Lstat(profilePath)
		if err != nil || !info.Mode().IsRegular() || info.Size() > 2*1024*1024 {
			continue
		}
		data, err := os.ReadFile(profilePath)
		var profile struct{ DefaultAction string }
		if err == nil && json.Unmarshal(data, &profile) == nil && profile.DefaultAction != "" && profile.DefaultAction != "SCMP_ACT_ALLOW" {
			result.SeccompProfile = profilePath
			break
		}
	}
	return result, nil
}

func slimBuildArgs(sourceImage, candidateImage, artifactDir, network string, includePaths []string) ([]string, error) {
	for _, image := range []string{sourceImage, candidateImage} {
		if err := toolImageReference(image); err != nil {
			return nil, err
		}
	}
	if sourceImage == candidateImage {
		return nil, errors.New("Slim candidate must differ from source image")
	}
	if !filepath.IsAbs(artifactDir) || filepath.Clean(artifactDir) != artifactDir || artifactDir == string(filepath.Separator) || strings.ContainsFunc(artifactDir, unicode.IsControl) {
		return nil, errors.New("artifact directory must be a clean, absolute non-root path")
	}
	if len(includePaths) > 32 {
		return nil, errors.New("at most 32 retention paths are allowed")
	}
	if !strings.HasPrefix(network, "hardening-profile-") || len(network) > 80 || strings.Trim(strings.TrimPrefix(network, "hardening-profile-"), "0123456789abcdef") != "" {
		return nil, errors.New("profiling network must be owned by this hardening run")
	}
	for _, value := range includePaths {
		if err := slimRetentionPath(value); err != nil {
			return nil, err
		}
	}
	args := []string{
		"--check-version=false", "--report=" + filepath.Join(artifactDir, "slim.report.json"),
		"--state-path=" + filepath.Join(artifactDir, "state"),
		"build", "--target", sourceImage, "--tag", candidateImage,
		"--pull=false", "--http-probe=false", "--continue-after=10", "--network=" + network,
		"--cro-host-config-file", filepath.Join(artifactDir, "profiling-host-config.json"),
		"--include-shell=false", "--include-new=false", "--include-cert-all=false", "--include-cert-bundles-only=true", "--include-distro-info=true", "--obfuscate-metadata=false",
		"--run-target-as-user=true", "--keep-perms=true", "--copy-meta-artifacts", artifactDir,
	}
	paths := append([]string{}, includePaths...)
	sort.Strings(paths)
	for _, value := range paths {
		args = append(args, "--include-path", value, "--preserve-path", value)
	}
	return args, nil
}

func slimRetentionPath(value string) error {
	if len(value) == 0 || len(value) > 4096 || !path.IsAbs(value) || path.Clean(value) != value || value == "/" || strings.ContainsAny(value, ":#*?[]\\") || strings.ContainsFunc(value, unicode.IsControl) {
		return errors.New("retention paths must be bounded, literal, clean absolute paths without root, traversal, glob, or permission syntax")
	}
	return nil
}

func toolImageReference(value string) error {
	if err := imageReference(value); err != nil {
		return err
	}
	if len(value) > 512 || strings.ContainsFunc(value, unicode.IsControl) {
		return errors.New("image reference contains control characters or exceeds 512 bytes")
	}
	return nil
}

func slimImageID(value string) bool {
	if !strings.HasPrefix(value, "sha256:") || len(value) != 71 {
		return false
	}
	_, err := hex.DecodeString(strings.TrimPrefix(value, "sha256:"))
	return err == nil
}

func boundedToolCapture(ctx context.Context, name string, args ...string) ([]byte, error) {
	return boundedToolCaptureLog(ctx, name, nil, args...)
}

func boundedToolCaptureLog(ctx context.Context, name string, log io.Writer, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	// Slim binds many flags to DSLIM_* variables, including host-exec and mount.
	// Ignore them: the only permitted actions are the argument vector above.
	cmd.Env = slimEnvironment(os.Environ())
	var stdout, stderr pentestOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if log != nil {
		// The owner-only log is for local troubleshooting, never model input.
		_, _ = io.WriteString(log, "stdout (maximum 64 KiB):\n")
		_, _ = log.Write(stdout.Bytes())
		_, _ = io.WriteString(log, "\nstderr (maximum 64 KiB):\n")
		_, _ = log.Write(stderr.Bytes())
		if err != nil {
			_, _ = io.WriteString(log, "\nexecution: "+err.Error()+"\n")
		}
	}
	if err != nil {
		// Raw tool diagnostics can contain image metadata; never return them to the model.
		return nil, errors.New("local tool execution failed")
	}
	return stdout.Bytes(), nil
}

func slimEnvironment(environment []string) []string {
	clean := []string{}
	for _, entry := range environment {
		if !strings.HasPrefix(entry, "DSLIM_") && !strings.HasPrefix(entry, "MINT_") && !strings.HasPrefix(entry, "GEMINI_API_KEY=") && !strings.HasPrefix(entry, "GOOGLE_API_KEY=") {
			clean = append(clean, entry)
		}
	}
	return clean
}

func cleanupSlimResources(label, network string, run toolCapture) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	data, err := run(ctx, "docker", "ps", "-aq", "--no-trunc", "--filter", "label="+label)
	if err == nil {
		for _, id := range strings.Fields(string(data)) {
			if len(id) != 64 || strings.Trim(id, "0123456789abcdef") != "" {
				continue
			}
			_, _ = run(ctx, "docker", "rm", "-f", "--", id)
		}
	}
	_, _ = run(ctx, "docker", "network", "rm", "--", network)
}
