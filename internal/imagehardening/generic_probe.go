package imagehardening

import (
	"context"
	"crypto/rand"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"
	"unicode"
)

//go:embed internal/containmentprobe/main.go
var genericProbeSource string

type genericOperationEvidence struct {
	Status    string `json:"status"`
	ErrorCode string `json:"error_code,omitempty"`
	Stage     string `json:"stage,omitempty"`
}

type genericWriteEvidence struct {
	Path string `json:"path"`
	genericOperationEvidence
}

type genericShellEvidence struct {
	Command   []string `json:"command"`
	Status    string   `json:"status"`
	ExitCode  int      `json:"exit_code"`
	ErrorCode string   `json:"error_code,omitempty"`
}

type genericProbeEvidence struct {
	Version          string                   `json:"version"`
	Nonce            string                   `json:"nonce"`
	UID              uint32                   `json:"uid"`
	GID              uint32                   `json:"gid"`
	ProtectedWrites  []genericWriteEvidence   `json:"protected_writes"`
	LocalToolInstall genericOperationEvidence `json:"local_tool_install"`
	Shells           []genericShellEvidence   `json:"shells"`
	WritablePaths    []genericWriteEvidence   `json:"writable_paths"`
	EgressTested     bool                     `json:"egress_tested"`
	Scope            string                   `json:"scope"`
}

func genericProbeTarget(architecture string) (goarch, goarm, suffix string, err error) {
	architecture = strings.TrimPrefix(architecture, "linux/")
	switch architecture {
	case "arm/v7", "armv7", "armv7l", "arm":
		return "arm", "7", "armv7", nil
	case "arm/v6", "armv6", "armv6l":
		return "arm", "6", "armv6", nil
	case "arm64/v8", "aarch64":
		return "arm64", "", "arm64", nil
	case "x86_64":
		return "amd64", "", "amd64", nil
	case "386", "amd64", "arm64", "loong64", "mips", "mipsle", "mips64", "mips64le", "ppc64", "ppc64le", "riscv64", "s390x":
		return architecture, "", architecture, nil
	default:
		return "", "", "", errors.New("unsupported Linux image architecture for static containment probe")
	}
}

func buildGenericProbe(ctx context.Context, arch, artifactDir string) (string, error) {
	goarch, goarm, suffix, err := genericProbeTarget(arch)
	if err != nil {
		return "", err
	}
	info, err := os.Lstat(artifactDir)
	if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 || info.Mode().Perm()&0077 != 0 || !filepath.IsAbs(artifactDir) || filepath.Clean(artifactDir) != artifactDir {
		return "", errors.New("probe artifacts require an existing private absolute directory (0700), not a symlink")
	}
	result := filepath.Join(artifactDir, "containment-probe-"+suffix)
	if _, err := os.Lstat(result); !os.IsNotExist(err) {
		return "", errors.New("probe artifact already exists or cannot be checked")
	}
	temporary, err := os.MkdirTemp(artifactDir, "probe-build-")
	if err != nil {
		return "", errors.New("cannot create private probe build directory")
	}
	defer os.RemoveAll(temporary)
	source := filepath.Join(temporary, "main.go")
	if err := os.WriteFile(source, []byte(genericProbeSource), 0600); err != nil {
		return "", errors.New("cannot write embedded public probe source")
	}
	built := filepath.Join(temporary, "probe")
	cmd := exec.CommandContext(ctx, "go", "build", "-trimpath", "-buildvcs=false", "-ldflags=-s -w", "-o", built, source)
	cmd.Dir = temporary
	cmd.Env = genericProbeBuildEnvironment(os.Environ(), goarch, goarm)
	if os.Getenv("GOCACHE") == "" {
		cmd.Env = append(cmd.Env, "GOCACHE="+filepath.Join(temporary, "go-cache"))
	}
	var output pentestOutput
	cmd.Stdout, cmd.Stderr = &output, &output
	if err := cmd.Run(); err != nil {
		return "", errors.New("static Linux containment probe build failed; check the local Go toolchain and architecture")
	}
	out, err := os.OpenFile(result, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0555)
	if err != nil {
		return "", errors.New("cannot create probe artifact without overwriting an existing path")
	}
	in, err := os.Open(built)
	if err != nil {
		out.Close()
		os.Remove(result)
		return "", errors.New("cannot open built containment probe")
	}
	_, copyErr := io.Copy(out, in)
	in.Close()
	modeErr := out.Chmod(0555)
	closeErr := out.Close()
	if copyErr != nil || modeErr != nil || closeErr != nil {
		os.Remove(result)
		return "", errors.New("cannot save complete containment probe artifact")
	}
	return result, nil
}

func genericProbeBuildEnvironment(existing []string, goarch, goarm string) []string {
	settings := map[string]string{"CGO_ENABLED": "0", "GOOS": "linux", "GOARCH": goarch, "GOARM": goarm, "GOENV": "off", "GOWORK": "off", "GO111MODULE": "off", "GOTOOLCHAIN": "local", "GOPROXY": "off", "GOSUMDB": "off", "GOFLAGS": ""}
	result := []string{}
	for _, value := range existing {
		key, _, _ := strings.Cut(value, "=")
		if key == "GEMINI_API_KEY" || key == "GOOGLE_API_KEY" {
			continue
		}
		if _, replace := settings[key]; !replace {
			result = append(result, value)
		}
	}
	for key, value := range settings {
		result = append(result, key+"="+value)
	}
	return result
}

func genericWritablePaths(values []string) ([]string, error) {
	if len(values) > 16 {
		return nil, errors.New("at most sixteen declared writable directories are supported")
	}
	result := []string{"/tmp"}
	seen := map[string]bool{"/tmp": true}
	for _, value := range values {
		if !path.IsAbs(value) || path.Clean(value) != value || value == "/" || len(value) > 256 || strings.ContainsAny(value, ",:") || strings.ContainsFunc(value, unicode.IsControl) {
			return nil, errors.New("writable directories must be bounded clean absolute container paths")
		}
		for _, reserved := range []string{"/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/proc", "/sys", "/dev", "/boot", "/root", "/.hardening-probe"} {
			if value == reserved || strings.HasPrefix(value, reserved+"/") {
				return nil, errors.New("writable directory overlaps a reserved probe or kernel path")
			}
		}
		if !seen[value] {
			result = append(result, value)
			seen[value] = true
		}
	}
	return result, nil
}

func genericProbeRunArgs(image, helper, name, user, nonce string, hardened bool, writablePaths []string) ([]string, error) {
	if err := toolImageReference(image); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(helper) || filepath.Clean(helper) != helper || strings.ContainsAny(helper, ",\r\n\x00") {
		return nil, errors.New("probe helper must be an absolute path safe for a single read-only bind mount")
	}
	if len(nonce) != 32 || strings.Trim(nonce, "0123456789abcdef") != "" {
		return nil, errors.New("invalid probe nonce")
	}
	writable, err := genericWritablePaths(writablePaths)
	if err != nil {
		return nil, err
	}
	var args []string
	if hardened {
		if _, err := hardenedArgs(image, user, "", "", nil); err != nil {
			return nil, err
		}
		for _, part := range strings.Split(user, ":") {
			if _, err := strconv.ParseUint(part, 10, 32); err != nil {
				return nil, errors.New("candidate UID:GID must fit unsigned 32-bit integers")
			}
		}
		args, err = hardenedArgs(image, user, "", "", nil)
		if err != nil {
			return nil, err
		}
		args = args[:len(args)-1]
		for _, directory := range writable {
			if directory != "/tmp" {
				args = append(args, "--tmpfs="+directory+":rw,noexec,nosuid,nodev,size=64m,mode=1777")
			}
		}
	} else {
		args = []string{"--rm", "--pull=never", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--network=none", "--memory=512m", "--cpus=1", "--pids-limit=128"}
	}
	args = append([]string{"run", "--name", name, "--label=container-hardening-work-bench.generic-probe=true", "--no-healthcheck", "--entrypoint=/.hardening-probe", "--mount=type=bind,source=" + helper + ",target=/.hardening-probe,readonly"}, args...)
	args = append(args, image, "--nonce", nonce)
	for _, directory := range writable {
		args = append(args, "--writable-path", directory)
	}
	return args, nil
}

func probeImage(ctx context.Context, image, helperPath, user string, hardened bool, writablePaths []string) (genericProbeEvidence, error) {
	var result genericProbeEvidence
	info, err := os.Lstat(helperPath)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 || info.Size() > 32*1024*1024 || !strings.HasPrefix(filepath.Base(helperPath), "containment-probe-") {
		return result, errors.New("a regular executable containment probe artifact is required")
	}
	f, err := os.Open(helperPath)
	if err != nil {
		return result, errors.New("cannot open containment probe artifact")
	}
	var magic [4]byte
	_, readErr := io.ReadFull(f, magic[:])
	f.Close()
	if readErr != nil || string(magic[:]) != "\x7fELF" {
		return result, errors.New("containment probe must be a built Linux ELF executable")
	}
	marker := make([]byte, 16)
	if _, err := rand.Read(marker); err != nil {
		return result, err
	}
	nonce := hex.EncodeToString(marker)
	name := "hardening-generic-probe-" + nonce
	args, err := genericProbeRunArgs(image, helperPath, name, user, nonce, hardened, writablePaths)
	if err != nil {
		return result, err
	}
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run()
	}()
	probe, cancel := context.WithTimeout(ctx, 35*time.Second)
	defer cancel()
	cmd := exec.CommandContext(probe, "docker", args...)
	var stdout, stderr pentestOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return result, errors.New("generic containment probe could not complete; Docker, architecture, timeout or startup failure is inconclusive")
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(stdout.Bytes(), &fields) != nil || fields["uid"] == nil || fields["gid"] == nil || json.Unmarshal(stdout.Bytes(), &result) != nil || result.Version != "generic-containment-v1" || result.Nonce != nonce || len(result.ProtectedWrites) != 3 || len(result.Shells) != 13 || result.EgressTested {
		return genericProbeEvidence{}, errors.New("generic containment probe returned incomplete or invalid evidence")
	}
	return result, nil
}
