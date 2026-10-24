package imagehardening

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strings"
	"time"
)

// External commands use argument vectors, never a shell. JSON stdout is reserved for agents.
func capture(ctx context.Context, name string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stderr = os.Stderr
	data, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("%s failed: %w", name, err)
	}
	return data, nil
}

func harden(args []string, out io.Writer) error {
	if len(args) > 0 && (args[0] == "auto" || args[0] == "agent") {
		return genericCLI(args, out)
	}
	if len(args) > 0 && args[0] == "tool-demo" {
		return toolCLI(args, out)
	}
	if len(args) > 0 && (args[0] == "gemini" || args[0] == "pentest" || args[0] == "demo") {
		return agentCLI(args, out)
	}
	if len(args) == 0 {
		return errors.New("usage: harden <auto|agent|tool-demo|gemini|pentest|demo|inspect|scan|config|build|minify|run|verify|compare> [flags]; use harden <command> -h")
	}
	action := args[0]
	f := flag.NewFlagSet("harden "+action, flag.ContinueOnError)
	image := f.String("image", "", "Local image reference (prefer a digest)")
	target := f.String("target", "", "New output image tag; must differ from input")
	path := f.String("path", ".", "Build context or configuration directory")
	file := f.String("file", "Containerfile", "Build file")
	container := f.String("container", "", "Existing container to inspect/verify")
	user := f.String("user", "65532:65532", "Non-root UID:GID for hardened test run")
	seccomp := f.String("seccomp", "", "Reviewed seccomp JSON profile; default is Docker's built-in profile")
	apparmor := f.String("apparmor", "", "Already-loaded AppArmor profile name")
	timeout := f.Duration("timeout", 10*time.Minute, "Timeout for the complete command")
	before := f.String("before", "", "Before Trivy JSON report")
	after := f.String("after", "", "After Trivy JSON report")
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if *timeout <= 0 {
		return errors.New("timeout must be positive")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	var result any
	switch action {
	case "inspect", "verify":
		if *container == "" {
			return errors.New("--container is required")
		}
		data, err := capture(ctx, "docker", "container", "inspect", "--", *container)
		if err != nil {
			return err
		}
		if action == "inspect" {
			// Return only hardening metadata, not environment variables or mount source paths.
			result, err = inspectReport(data)
		} else {
			result, err = verifyReport(data)
		}
		if err != nil {
			return err
		}
	case "scan":
		if err := imageReference(*image); err != nil {
			return err
		}
		data, err := capture(ctx, "trivy", "image", "--format", "json", "--scanners", "vuln,misconfig,secret", "--image-config-scanners", "misconfig", "--", *image)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("invalid Trivy JSON: %w", err)
		}
	case "config":
		data, err := capture(ctx, "trivy", "config", "--format", "json", "--", *path)
		if err != nil {
			return err
		}
		if err := json.Unmarshal(data, &result); err != nil {
			return fmt.Errorf("invalid Trivy JSON: %w", err)
		}
	case "build", "minify":
		if err := imageReference(*target); err != nil {
			return fmt.Errorf("target: %w", err)
		}
		if *target == *image {
			return errors.New("target must differ from input image")
		}
		var err error
		if action == "build" {
			_, err = capture(ctx, "docker", "build", "-f", *file, "-t", *target, "--", *path)
		} else {
			if err := imageReference(*image); err != nil {
				return err
			}
			// Profiling executes the image; no host mounts or credentials are forwarded.
			_, err = capture(ctx, "slim", "build", "--target", *image, "--tag", *target)
		}
		if err != nil {
			return err
		}
		result = map[string]any{"image": *target, "application_tested": false, "action": action}
	case "run":
		if err := imageReference(*image); err != nil {
			return err
		}
		runArgs, err := hardenedArgs(*image, *user, *seccomp, *apparmor, f.Args())
		if err != nil {
			return err
		}
		// A named container permits cleanup even when the client times out.
		name := fmt.Sprintf("hardening-test-%d-%d", os.Getpid(), time.Now().UnixNano())
		runArgs = append([]string{"run", "--name", name}, runArgs...)
		defer func() {
			cleanup, stop := context.WithTimeout(context.Background(), 15*time.Second)
			defer stop()
			_ = exec.CommandContext(cleanup, "docker", "rm", "-f", name).Run()
		}()
		data, err := capture(ctx, "docker", runArgs...)
		if err != nil {
			return err
		}
		result = map[string]any{"image": *image, "test_passed": true, "stdout": string(data), "network": "none", "scope": "supplied command only; no claim of complete application coverage"}
	case "compare":
		var err error
		result, err = compareReports(*before, *after)
		if err != nil {
			return err
		}
	default:
		return fmt.Errorf("unknown harden command %q", action)
	}
	return json.NewEncoder(out).Encode(result)
}

func imageReference(value string) error {
	if value == "" || strings.HasPrefix(value, "-") || strings.ContainsAny(value, "\r\n\t ") {
		return errors.New("a non-empty image reference without whitespace or leading '-' is required")
	}
	return nil
}

func hardenedArgs(image, user, seccomp, apparmor string, command []string) ([]string, error) {
	parts := strings.Split(user, ":")
	if len(parts) != 2 {
		return nil, errors.New("user must be a numeric non-root UID:GID")
	}
	for i, p := range parts {
		if p == "" {
			return nil, errors.New("empty UID/GID")
		}
		for _, c := range p {
			if c < '0' || c > '9' {
				return nil, errors.New("UID/GID must be numeric")
			}
		}
		if i == 0 && strings.TrimLeft(p, "0") == "" {
			return nil, errors.New("UID must not be root")
		}
	}
	args := []string{"--rm", "--pull=never", "--read-only", "--user", user, "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--network=none", "--memory=512m", "--cpus=1", "--pids-limit=128", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m"}
	if seccomp != "" {
		if seccomp == "unconfined" {
			return nil, errors.New("unconfined seccomp is not hardening")
		}
		data, err := os.ReadFile(seccomp)
		if err != nil {
			return nil, err
		}
		var profile struct{ DefaultAction string }
		if err := json.Unmarshal(data, &profile); err != nil {
			return nil, err
		}
		if profile.DefaultAction == "" || profile.DefaultAction == "SCMP_ACT_ALLOW" {
			return nil, errors.New("seccomp profile must have a restrictive defaultAction")
		}
		args = append(args, "--security-opt=seccomp="+seccomp)
	}
	if apparmor != "" {
		if apparmor == "unconfined" {
			return nil, errors.New("unconfined AppArmor is not hardening")
		}
		args = append(args, "--security-opt=apparmor="+apparmor)
	}
	return append(append(args, image), command...), nil
}

type inspectedContainer struct {
	Config     struct{ User string }
	HostConfig struct {
		ReadonlyRootfs bool
		Privileged     bool
		CapDrop        []string
		CapAdd         []string
		SecurityOpt    []string
		NetworkMode    string
		Memory         int64
		NanoCpus       int64
		PidsLimit      *int64
		Binds          []string
		Devices        []json.RawMessage
	}
	Mounts []struct {
		Type        string
		Destination string
		RW          bool
	}
}

func inspectReport(data []byte) (inspectedContainer, error) {
	var containers []inspectedContainer
	err := json.Unmarshal(data, &containers)
	if err != nil {
		return inspectedContainer{}, err
	}
	if len(containers) != 1 {
		return inspectedContainer{}, errors.New("expected exactly one container")
	}
	c := containers[0]
	// Bind specifications can disclose host paths; report mount destinations instead.
	c.HostConfig.Binds = nil
	return c, nil
}

func verifyReport(data []byte) (any, error) {
	c, err := inspectReport(data)
	if err != nil {
		return nil, err
	}
	var failures []string
	check := func(ok bool, message string) {
		if !ok {
			failures = append(failures, message)
		}
	}
	_, userErr := hardenedArgs("unused", c.Config.User, "", "", nil)
	check(userErr == nil, "explicit numeric non-root UID:GID missing")
	check(c.HostConfig.ReadonlyRootfs, "root filesystem is writable")
	check(!c.HostConfig.Privileged, "container is privileged")
	dropAll, nnp, confined := false, false, true
	for _, cap := range c.HostConfig.CapDrop {
		if strings.EqualFold(cap, "ALL") {
			dropAll = true
		}
	}
	for _, opt := range c.HostConfig.SecurityOpt {
		if opt == "no-new-privileges" || opt == "no-new-privileges:true" || opt == "no-new-privileges=true" {
			nnp = true
		}
		if opt == "seccomp=unconfined" || opt == "apparmor=unconfined" {
			confined = false
		}
	}
	check(dropAll && len(c.HostConfig.CapAdd) == 0, "all capabilities must be dropped without additions")
	check(nnp, "no-new-privileges missing")
	check(confined, "security profile explicitly unconfined")
	check(c.HostConfig.NetworkMode == "none", "network is not disabled; external policy enforcement unverified")
	check(c.HostConfig.Memory > 0 && c.HostConfig.NanoCpus > 0 && c.HostConfig.PidsLimit != nil && *c.HostConfig.PidsLimit > 0, "memory/CPU/PID limits missing")
	check(len(c.HostConfig.Devices) == 0, "host devices exposed")
	for _, m := range c.Mounts {
		check(m.Type == "tmpfs", "non-tmpfs mount requires review: "+m.Destination)
	}
	return map[string]any{"baseline_passed": len(failures) == 0, "failures": failures, "scope": "Docker configuration only; syscall, LSM, filesystem and network enforcement require workload probes"}, nil
}

func compareReports(before, after string) (any, error) {
	read := func(path string) (map[string]bool, error) {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, err
		}
		var report struct {
			Results []struct {
				Target          string
				Vulnerabilities []struct{ VulnerabilityID, PkgName, InstalledVersion string }
			}
		}
		if err := json.Unmarshal(data, &report); err != nil {
			return nil, err
		}
		if report.Results == nil {
			return nil, errors.New("expected a Trivy report with Results")
		}
		ids := map[string]bool{}
		for _, r := range report.Results {
			for _, v := range r.Vulnerabilities {
				ids[r.Target+"|"+v.PkgName+"|"+v.InstalledVersion+"|"+v.VulnerabilityID] = true
			}
		}
		return ids, nil
	}
	a, err := read(before)
	if err != nil {
		return nil, err
	}
	b, err := read(after)
	if err != nil {
		return nil, err
	}
	removed, added := []string{}, []string{}
	for id := range a {
		if !b[id] {
			removed = append(removed, id)
		}
	}
	for id := range b {
		if !a[id] {
			added = append(added, id)
		}
	}
	return map[string]any{"before": len(a), "after": len(b), "removed": removed, "added": added, "scope": "vulnerability finding differences only; removal does not prove remediation"}, nil
}
