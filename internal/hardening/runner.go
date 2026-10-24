package hardening

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"time"
)

//go:embed assets/probe.go.txt
var probeSource []byte

type BuildResult struct {
	ImageID      string `json:"imageID"`
	BundleSHA256 string `json:"bundleSHA256"`
	Platform     string `json:"platform"`
}

func command(ctx context.Context, out io.Writer, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = out
	cmd.Stderr = out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %s: %w", name, args[0], err)
	}
	return nil
}
func capture(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s %s: %w: %s", name, args[0], err, strings.TrimSpace(stderr.String()))
	}
	return b, nil
}
func writeJSON(file string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file, append(b, '\n'), 0600)
}

func Build(ctx context.Context, dir string, out io.Writer) error {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	b, err := ReadBundle(dir)
	if err != nil {
		return err
	}
	for _, name := range []string{"build.json", "verification.json"} {
		if e := os.Remove(filepath.Join(dir, name)); e != nil && !os.IsNotExist(e) {
			return e
		}
	}
	recipe, err := os.ReadFile(filepath.Join(dir, "Dockerfile"))
	if err != nil {
		return err
	}
	locked, refs, err := lockImages(ctx, string(recipe), b.Config.Platform, out)
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile.locked"), []byte(locked), 0600); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(dir, "images.lock.json"), refs); err != nil {
		return err
	}
	tag := "breachbench/" + b.Config.Name + ":hardened"
	if err := command(ctx, out, "docker", "build", "--platform", b.Config.Platform, "--file", filepath.Join(dir, "Dockerfile.locked"), "--tag", tag, dir); err != nil {
		return err
	}
	id, err := capture(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", tag)
	if err != nil {
		return err
	}
	sum, err := hashFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		return err
	}
	return writeJSON(filepath.Join(dir, "build.json"), BuildResult{strings.TrimSpace(string(id)), sum, b.Config.Platform})
}

func lockImages(ctx context.Context, recipe, platform string, out io.Writer) (string, map[string]string, error) {
	lines := strings.Split(recipe, "\n")
	refs := map[string]string{}
	for i, line := range lines {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[0] != "FROM" {
			continue
		}
		ref := fields[1]
		if ref == "scratch" {
			continue
		}
		if err := command(ctx, out, "docker", "pull", "--platform", platform, ref); err != nil {
			return "", nil, err
		}
		data, err := capture(ctx, "docker", "image", "inspect", "--format", "{{json .RepoDigests}}", ref)
		if err != nil {
			return "", nil, err
		}
		var digests []string
		if err := json.Unmarshal(data, &digests); err != nil {
			return "", nil, err
		}
		if len(digests) == 0 {
			return "", nil, fmt.Errorf("image %s has no registry digest", ref)
		}
		parts := strings.Split(digests[0], "@")
		if len(parts) != 2 || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(parts[1]) {
			return "", nil, fmt.Errorf("invalid image digest")
		}
		refs[ref] = strings.Split(ref, "@")[0] + "@" + parts[1]
		fields[1] = refs[ref]
		lines[i] = strings.Join(fields, " ")
	}
	return strings.Join(lines, "\n"), refs, nil
}

type Verification struct {
	ImageID string            `json:"imageID"`
	Passed  bool              `json:"passed"`
	Checks  map[string]bool   `json:"checks"`
	Details map[string]string `json:"details"`
	Limits  []string          `json:"limits"`
}

func Verify(ctx context.Context, dir string, out io.Writer) (err error) {
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	result := Verification{Checks: map[string]bool{}, Details: map[string]string{"probe_sha256": ProbeDigest()}, Limits: []string{"Readiness is not full workload coverage.", "Kubernetes NetworkPolicy enforcement and external credential scopes are not verified by this local Docker test.", "Known utility names are inspected; this is not a semantic inventory of every executable.", "The verification probe is mounted only for this test and is not part of the final image."}}
	defer func() {
		result.Passed = err == nil
		if err != nil {
			result.Details["error"] = err.Error()
		}
		if e := writeJSON(filepath.Join(dir, "verification.json"), result); e != nil && err == nil {
			err = e
		}
	}()
	b, err := ReadBundle(dir)
	if err != nil {
		return err
	}
	var built BuildResult
	if err = readJSON(filepath.Join(dir, "build.json"), &built, true); err != nil {
		return fmt.Errorf("build the bundle first: %w", err)
	}
	sum, err := hashFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		return err
	}
	if sum != built.BundleSHA256 || built.Platform != b.Config.Platform || !regexp.MustCompile(`^sha256:[a-f0-9]{64}$`).MatchString(built.ImageID) {
		return fmt.Errorf("build does not match this bundle; rebuild")
	}
	result.ImageID = built.ImageID
	probeDir, err := os.MkdirTemp("", "breachbench-probe-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(probeDir)
	probeFile := filepath.Join(probeDir, "probe.go")
	probeBinary := filepath.Join(probeDir, "probe")
	if err = os.WriteFile(probeFile, probeSource, 0600); err != nil {
		return err
	}
	build := exec.CommandContext(ctx, "go", "build", "-trimpath", "-o", probeBinary, probeFile)
	build.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+strings.TrimPrefix(b.Config.Platform, "linux/"), "CGO_ENABLED=0")
	build.Stdout = out
	build.Stderr = out
	if err = build.Run(); err != nil {
		return fmt.Errorf("build verification probe: %w", err)
	}
	args := RuntimeArgs(dir, b.Config, built.ImageID, probeBinary)
	for _, s := range b.Config.Secrets {
		if _, ok := os.LookupEnv(s.Env); !ok {
			return fmt.Errorf("set %s for the runtime smoke test", s.Env)
		}
	}
	idBytes, err := capture(ctx, "docker", args...)
	if err != nil {
		return err
	}
	id := strings.TrimSpace(string(idBytes))
	// Cleanup uses an independent bounded context, including after cancellation.
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		if _, e := capture(clean, "docker", "rm", "--force", id); e != nil && err == nil {
			err = e
		}
	}()
	if err = inspectRootFS(ctx, id); err != nil {
		return err
	}
	result.Checks["known_shells_downloaders_package_managers_absent"] = true
	if _, err = capture(ctx, "docker", "start", id); err != nil {
		return err
	}
	probeArgs := []string{"exec", id, "/.__breachbench_probe", "-port", fmt.Sprint(b.Config.Port), "-http", b.Config.HealthPath, "-php=" + fmt.Sprint(b.Config.Runtime == "php")}
	probeOutput, err := capture(ctx, "docker", probeArgs...)
	if err != nil {
		return err
	}
	var measured struct {
		Checks  map[string]bool   `json:"checks"`
		Details map[string]string `json:"details"`
	}
	if err = json.Unmarshal(probeOutput, &measured); err != nil {
		return fmt.Errorf("invalid probe result: %w", err)
	}
	for k, v := range measured.Checks {
		result.Checks[k] = v
	}
	for k, v := range measured.Details {
		result.Details[k] = v
	}
	for _, k := range []string{"nonroot", "no_new_privileges", "capabilities_dropped", "seccomp_active", "root_read_only", "network_isolated", "ptrace_blocked", "mount_blocked", "bpf_blocked", "application_ready"} {
		if !result.Checks[k] {
			return fmt.Errorf("runtime check failed: %s (%s)", k, result.Details[k])
		}
	}
	fmt.Fprintln(out, "Image and runtime checks passed. See verification.json for scope and evidence.")
	return nil
}

func RuntimeArgs(dir string, c Config, image, probe string) []string {
	args := []string{"create", "--platform", c.Platform, "--network", "none", "--read-only", "--user", "65532:65532", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true", "--security-opt", "seccomp=" + filepath.Join(dir, "seccomp.json"), "--memory", fmt.Sprintf("%dm", c.MemoryMiB), "--memory-swap", fmt.Sprintf("%dm", c.MemoryMiB), "--cpus", fmt.Sprintf("%.3f", float64(c.CPUMillis)/1000), "--pids-limit", fmt.Sprint(c.PIDs), "--env", "HOME=/tmp", "--env", "TMPDIR=/tmp", "--env", fmt.Sprintf("PORT=%d", c.Port)}
	if probe != "" {
		args = append(args, "--mount", "type=bind,source="+probe+",target=/.__breachbench_probe,readonly")
	}
	for _, p := range c.Writable {
		args = append(args, "--tmpfs", fmt.Sprintf("%s:rw,noexec,nosuid,nodev,size=%dm,uid=65532,gid=65532,mode=0700", p, c.TempMiB))
	}
	for _, s := range c.Secrets {
		args = append(args, "--env", s.Env)
	}
	for k, v := range c.Env {
		args = append(args, "--env", k+"="+v)
	}
	return append(args, image)
}

func inspectRootFS(ctx context.Context, id string) error {
	cmd := exec.CommandContext(ctx, "docker", "export", id)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err = cmd.Start(); err != nil {
		return err
	}
	problem := checkArchive(stdout)
	if problem != nil {
		_ = cmd.Process.Kill()
	}
	waitErr := cmd.Wait()
	if problem != nil {
		return problem
	}
	if waitErr != nil {
		return fmt.Errorf("image export failed: %w: %s", waitErr, stderr.String())
	}
	return nil
}
func checkArchive(r io.Reader) error {
	tr := tar.NewReader(r)
	for {
		h, err := tr.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		p := path.Clean(strings.TrimPrefix(h.Name, "/"))
		name := path.Base(p)
		if h.Mode&06000 != 0 && (h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA) {
			return fmt.Errorf("setuid/setgid file found: %s", p)
		}
		executable := (h.Typeflag == tar.TypeReg || h.Typeflag == tar.TypeRegA) && h.Mode&0111 != 0
		link := h.Typeflag == tar.TypeSymlink || h.Typeflag == tar.TypeLink
		if slices.Contains([]string{"sh", "bash", "dash", "ash", "zsh", "fish", "busybox", "curl", "wget", "apt", "apt-get", "apk", "dpkg", "yum", "dnf", "npm", "npx", "composer", "pip", "pip3"}, name) && (executable || link) {
			return fmt.Errorf("runtime utility found: %s", p)
		}
	}
}

func ProbeDigest() string { h := sha256.Sum256(probeSource); return hex.EncodeToString(h[:]) }
