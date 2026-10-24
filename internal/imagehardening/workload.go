package imagehardening

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/url"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

type workloadSpec struct {
	Mode                  string              `json:"mode"`
	Command               []string            `json:"command,omitempty"`
	Port                  int                 `json:"port,omitempty"`
	HTTPChecks            []workloadHTTPCheck `json:"http_checks,omitempty"`
	StartupTimeoutSeconds int                 `json:"startup_timeout_seconds,omitempty"`
	ProbePath             string              `json:"-"`
}

type workloadHTTPCheck struct {
	Path         string `json:"path"`
	Status       int    `json:"status"`
	BodyContains string `json:"body_contains,omitempty"`
}

type genericRuntimePolicy struct {
	User          string   `json:"user"`
	WritablePaths []string `json:"writable_paths,omitempty"`
	Network       string   `json:"network"`
}

type workloadHTTPResult struct {
	Path       string `json:"path"`
	Status     int    `json:"status"`
	BodySHA256 string `json:"body_sha256"`
	Passed     bool   `json:"passed"`
	ErrorCode  string `json:"error_code,omitempty"`
}

type workloadEvidence struct {
	Mode            string               `json:"mode"`
	Status          string               `json:"status"`
	ImageID         string               `json:"image_id,omitempty"`
	Coverage        string               `json:"coverage"`
	CommandOverride bool                 `json:"command_override"`
	ExitCode        *int                 `json:"exit_code,omitempty"`
	HTTP            []workloadHTTPResult `json:"http,omitempty"`
}

func validateWorkloadSpec(spec workloadSpec) error {
	if spec.StartupTimeoutSeconds < 0 || spec.StartupTimeoutSeconds > 120 {
		return errors.New("workload timeout must be zero (30 seconds) or 1–120 seconds")
	}
	switch spec.Mode {
	case "batch":
		if spec.Port != 0 || len(spec.HTTPChecks) != 0 || len(spec.Command) > 128 {
			return errors.New("batch workloads accept only an optional finite command, not HTTP settings")
		}
		for i, value := range spec.Command {
			if len(value) > 8192 || strings.ContainsRune(value, 0) || (i == 0 && (value == "" || strings.HasPrefix(value, "-"))) {
				return errors.New("invalid batch command argv")
			}
		}
	case "http":
		if len(spec.Command) != 0 || spec.Port < 1 || spec.Port > 65535 || len(spec.HTTPChecks) == 0 || len(spec.HTTPChecks) > 16 {
			return errors.New("HTTP workloads preserve the image command and require a port and 1–16 explicit checks")
		}
		for _, check := range spec.HTTPChecks {
			parsed, err := url.ParseRequestURI(check.Path)
			if err != nil || len(check.Path) > 2048 || !strings.HasPrefix(check.Path, "/") || strings.HasPrefix(check.Path, "//") || strings.ContainsRune(check.Path, '#') || strings.ContainsFunc(check.Path, unicode.IsControl) || parsed.IsAbs() || parsed.Host != "" || parsed.Fragment != "" || check.Status < 200 || check.Status > 599 || len(check.BodyContains) > 4096 {
				return errors.New("HTTP checks require bounded local paths, explicit status codes, and bounded body expectations")
			}
		}
	default:
		return errors.New("workload mode must be batch or http")
	}
	return nil
}

func validateGenericPolicy(policy genericRuntimePolicy) error {
	if err := genericUser(policy.User); err != nil {
		return err
	}
	if policy.Network != "none" && policy.Network != "internal" && policy.Network != "bridge" {
		return errors.New("network policy must be none, internal, or explicitly declared bridge (unrestricted external egress)")
	}
	if len(policy.WritablePaths) > 16 {
		return errors.New("at most 16 narrow writable directories are allowed")
	}
	seen := map[string]bool{}
	for _, value := range policy.WritablePaths {
		if len(value) == 0 || len(value) > 4096 || !path.IsAbs(value) || path.Clean(value) != value || strings.ContainsAny(value, ":,#*?[]\\") || strings.ContainsFunc(value, unicode.IsControl) || seen[value] {
			return errors.New("writable paths must be unique, literal, clean absolute directories")
		}
		for _, protected := range []string{"/proc", "/sys", "/dev", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/root", "/boot", "/.hardening-probe"} {
			if value == protected || strings.HasPrefix(value, protected+"/") {
				return errors.New("writable paths cannot cover system, executable, credential, or kernel paths")
			}
		}
		for _, broad := range []string{"/", "/app", "/opt", "/home", "/srv", "/var", "/var/lib", "/var/cache", "/var/log"} {
			if value == broad {
				return errors.New("declare narrow runtime directories, not broad application or system roots")
			}
		}
		for previous := range seen {
			if strings.HasPrefix(value, previous+"/") || strings.HasPrefix(previous, value+"/") {
				return errors.New("writable directories must not overlap")
			}
		}
		seen[value] = true
	}
	return nil
}

func genericRunArgs(image, name, network string, hardened bool, policy genericRuntimePolicy, spec workloadSpec) ([]string, error) {
	if err := toolImageReference(image); err != nil {
		return nil, err
	}
	if err := validateGenericPolicy(policy); err != nil {
		return nil, err
	}
	if err := validateWorkloadSpec(spec); err != nil {
		return nil, err
	}
	if !ownedWorkloadName(name) || (policy.Network != "none" && !ownedWorkloadName(network)) || (policy.Network == "none" && network != "") {
		return nil, errors.New("invalid owned workload resources or network policy")
	}
	args := []string{"run", "--name", name, "--label=container-hardening-work-bench.workload=true", "--pull=never", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory=512m", "--cpus=1", "--pids-limit=128"}
	if policy.Network == "none" {
		args = append(args, "--network=none")
	} else {
		args = append(args, "--network="+network)
	}
	if spec.Mode == "http" {
		if err := validateWorkloadProbe(spec.ProbePath); err != nil {
			return nil, err
		}
		args = append(args, "--detach", "--mount", "type=bind,source="+spec.ProbePath+",target=/.hardening-probe,readonly")
	}
	if hardened {
		args = append(args, "--read-only", "--user", policy.User, "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777")
		for _, directory := range policy.WritablePaths {
			if directory != "/tmp" && !strings.HasPrefix(directory, "/tmp/") {
				args = append(args, "--tmpfs="+directory+":rw,noexec,nosuid,nodev,size=64m,mode=1777")
			}
		}
	}
	if len(spec.Command) > 0 {
		args = append(args, "--entrypoint="+spec.Command[0])
	}
	args = append(args, image)
	if len(spec.Command) > 0 {
		args = append(args, spec.Command[1:]...)
	}
	return args, nil
}

func ownedWorkloadName(value string) bool {
	const prefix = "hardening-workload-"
	return strings.HasPrefix(value, prefix) && len(value) == len(prefix)+24 && strings.Trim(strings.TrimPrefix(value, prefix), "0123456789abcdef") == ""
}

type workloadDocker func(context.Context, ...string) ([]byte, int, error)

func checkWorkload(ctx context.Context, image string, hardened bool, policy genericRuntimePolicy, spec workloadSpec) (workloadEvidence, error) {
	return checkWorkloadWith(ctx, image, hardened, policy, spec, runWorkloadDocker)
}

func checkWorkloadWith(ctx context.Context, image string, hardened bool, policy genericRuntimePolicy, spec workloadSpec, run workloadDocker) (workloadEvidence, error) {
	evidence := workloadEvidence{Mode: spec.Mode, Status: "inconclusive", CommandOverride: len(spec.Command) > 0, Coverage: "Caller-declared checks only; application behavior outside these checks is not verified"}
	if err := validateWorkloadSpec(spec); err != nil {
		return evidence, err
	}
	if err := validateGenericPolicy(policy); err != nil {
		return evidence, err
	}
	if err := toolImageReference(image); err != nil {
		return evidence, err
	}
	if spec.Mode == "http" {
		if err := validateWorkloadProbe(spec.ProbePath); err != nil {
			return evidence, err
		}
	}
	data, code, err := run(ctx, "image", "inspect", "--format", "{{.Id}}", "--", image)
	imageID := strings.TrimSpace(string(data))
	if err != nil || code != 0 || !slimImageID(imageID) {
		return evidence, errors.New("cannot pin local workload image")
	}
	evidence.ImageID = imageID
	marker := make([]byte, 12)
	if _, err := rand.Read(marker); err != nil {
		return evidence, err
	}
	name := "hardening-workload-" + hex.EncodeToString(marker)
	network := ""
	if policy.Network != "none" {
		if _, err := rand.Read(marker); err != nil {
			return evidence, err
		}
		network = "hardening-workload-" + hex.EncodeToString(marker)
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _, _ = run(cleanup, "rm", "-f", "--volumes", "--", name)
		if network != "" {
			_, _, _ = run(cleanup, "network", "rm", "--", network)
		}
	}()
	if network != "" {
		networkArgs := []string{"network", "create", "--driver", "bridge", "--label=container-hardening-work-bench.workload=true", "--opt", "com.docker.network.bridge.host_binding_ipv4=127.0.0.1"}
		if policy.Network == "internal" {
			networkArgs = append(networkArgs, "--internal")
		}
		if _, code, err := run(ctx, append(networkArgs, network)...); err != nil || code != 0 {
			return evidence, errors.New("cannot create owned workload network")
		}
	}
	args, err := genericRunArgs(imageID, name, network, hardened, policy, spec)
	if err != nil {
		return evidence, err
	}
	seconds := spec.StartupTimeoutSeconds
	if seconds == 0 {
		seconds = 30
	}
	checkCtx, cancel := context.WithTimeout(ctx, time.Duration(seconds)*time.Second)
	defer cancel()
	_, code, err = run(checkCtx, args...)
	if err != nil || code != 0 {
		if spec.Mode == "batch" && err == nil && code > 0 && code < 125 {
			evidence.Status, evidence.ExitCode = "failed", &code
		}
		return evidence, errors.New("workload command failed to start or complete successfully")
	}
	if spec.Mode == "batch" {
		evidence.Status, evidence.ExitCode = "passed", &code
		if len(spec.Command) == 0 {
			evidence.Coverage = "Original image ENTRYPOINT/CMD exited successfully; no additional behavior is inferred"
		} else {
			evidence.Coverage = "Caller-supplied finite command exited successfully; it replaces the image entrypoint and is not proof that the original service starts"
		}
		return evidence, nil
	}
	checks, err := json.Marshal(spec.HTTPChecks)
	if err != nil {
		return evidence, errors.New("cannot encode declared HTTP workload checks")
	}
	data, code, err = run(checkCtx, "exec", name, "/.hardening-probe", "--port", strconv.Itoa(spec.Port), "--http-checks-json", string(checks), "--timeout-seconds", strconv.Itoa(seconds))
	if err != nil {
		return evidence, errors.New("HTTP workload probe did not complete")
	}
	evidence.HTTP, err = parseWorkloadHTTPProbe(data, spec.HTTPChecks)
	if err != nil || code != 0 {
		evidence.Status = "failed"
		return evidence, errors.New("declared HTTP workload checks did not pass")
	}
	data, code, err = run(checkCtx, "inspect", "--format", "{{.State.Running}}", "--", name)
	if err != nil || code != 0 || strings.TrimSpace(string(data)) != "true" {
		evidence.Status = "failed"
		return evidence, errors.New("HTTP workload stopped before validation completed")
	}
	evidence.Status = "passed"
	evidence.Coverage = "Original image ENTRYPOINT/CMD served caller-declared loopback HTTP checks from a read-only temporary probe; the checker uses no host ports, redirects, proxies, or external targets and does not inventory the application's own dependency connections"
	return evidence, nil
}

func validateWorkloadProbe(file string) error {
	if !filepath.IsAbs(file) || filepath.Clean(file) != file || strings.ContainsRune(file, ',') || strings.ContainsFunc(file, unicode.IsControl) {
		return errors.New("HTTP workload requires an internally configured trusted probe binary path")
	}
	info, err := os.Lstat(file)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() == 0 || info.Size() > 64*1024*1024 {
		return errors.New("HTTP workload probe must be a bounded, executable regular file, not a symlink")
	}
	return nil
}

func canonicalWorkloadPaths(ctx context.Context, image, helper string, paths []string) ([]string, error) {
	return canonicalWorkloadPathsWith(ctx, image, helper, paths, runWorkloadDocker)
}

func canonicalWorkloadPathsWith(ctx context.Context, image, helper string, paths []string, run workloadDocker) ([]string, error) {
	if err := toolImageReference(image); err != nil {
		return nil, err
	}
	if err := validateWorkloadProbe(helper); err != nil {
		return nil, err
	}
	if err := validateGenericPolicy(genericRuntimePolicy{User: "1:1", Network: "none", WritablePaths: paths}); err != nil {
		return nil, err
	}
	data, code, err := run(ctx, "image", "inspect", "--format", "{{.Id}}", "--", image)
	imageID := strings.TrimSpace(string(data))
	if err != nil || code != 0 || !slimImageID(imageID) {
		return nil, errors.New("cannot pin image for writable-path preflight")
	}
	marker := make([]byte, 12)
	if _, err := rand.Read(marker); err != nil {
		return nil, err
	}
	name := "hardening-workload-" + hex.EncodeToString(marker)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _, _ = run(cleanup, "rm", "-f", "--volumes", "--", name)
	}()
	// /tmp is always writable in candidates, so its implicit mount needs the same
	// canonical-path check even when no extra directories were requested.
	requested := []string{"/tmp"}
	indices := make([]int, 0, len(paths))
	for _, directory := range paths {
		if directory == "/tmp" {
			indices = append(indices, 0)
		} else {
			indices = append(indices, len(requested))
			requested = append(requested, directory)
		}
	}
	encoded, err := json.Marshal(requested)
	if err != nil {
		return nil, errors.New("cannot encode writable-path preflight")
	}
	probeCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	data, code, err = run(probeCtx, "run", "--rm", "--name", name, "--label=container-hardening-work-bench.workload=true", "--pull=never", "--read-only", "--no-healthcheck", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--network=none", "--memory=512m", "--cpus=1", "--pids-limit=128", "--mount", "type=bind,source="+helper+",target=/.hardening-probe,readonly", "--entrypoint=/.hardening-probe", imageID, "--canonical-writable-paths-json", string(encoded))
	var result struct {
		Version string   `json:"version"`
		Paths   []string `json:"paths"`
	}
	if err != nil || code != 0 || len(data) > 64*1024 || json.Unmarshal(data, &result) != nil || result.Version != "generic-paths-v1" || len(result.Paths) != len(requested) || result.Paths[0] != "/tmp" {
		return nil, errors.New("writable-path preflight failed or implicit /tmp is a symlink alias")
	}
	canonical := make([]string, 0, len(paths))
	for _, index := range indices {
		canonical = append(canonical, result.Paths[index])
	}
	if err := validateGenericPolicy(genericRuntimePolicy{User: "1:1", Network: "none", WritablePaths: canonical}); err != nil {
		return nil, errors.New("canonical writable directories overlap or cover protected paths")
	}
	return canonical, nil
}

func parseWorkloadHTTPProbe(data []byte, checks []workloadHTTPCheck) ([]workloadHTTPResult, error) {
	var result struct {
		Version string               `json:"version"`
		Passed  bool                 `json:"passed"`
		Checks  []workloadHTTPResult `json:"checks"`
	}
	if len(data) > 64*1024 || json.Unmarshal(data, &result) != nil || result.Version != "generic-http-v1" || len(result.Checks) != len(checks) || len(checks) == 0 {
		return nil, errors.New("HTTP probe returned incomplete evidence")
	}
	for index, check := range result.Checks {
		if check.Path != checks[index].Path || check.Status != checks[index].Status || !check.Passed || check.ErrorCode != "" || !toolDigest(check.BodySHA256) {
			return result.Checks, errors.New("HTTP probe assertion failed")
		}
	}
	if !result.Passed {
		return result.Checks, errors.New("HTTP probe did not pass")
	}
	return result.Checks, nil
}

func runWorkloadDocker(ctx context.Context, args ...string) ([]byte, int, error) {
	command := exec.CommandContext(ctx, "docker", args...)
	command.Env = slimEnvironment(os.Environ())
	var stdout, stderr pentestOutput
	command.Stdout, command.Stderr = &stdout, &stderr
	err := command.Run()
	if ctx.Err() != nil {
		return stdout.Bytes(), -1, ctx.Err()
	}
	if err == nil {
		return stdout.Bytes(), 0, nil
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) {
		return stdout.Bytes(), exit.ExitCode(), nil
	}
	return stdout.Bytes(), -1, errors.New("Docker workload execution failed")
}
