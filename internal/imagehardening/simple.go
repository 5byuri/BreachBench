package imagehardening

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
)

// HardenImage is the one-image front door; it never starts the application.
func HardenImage(ctx context.Context, image, mode string, demo bool, out io.Writer) error {
	if demo {
		version, err := boundedToolCapture(ctx, "docker", "version", "--format", "{{.Server.Version}}")
		if err != nil || !safeDemoDockerVersion(strings.TrimSpace(string(version))) {
			return errors.New("browser demo publishing requires Docker Engine 28.0.0 or newer; older engines can expose localhost-published ports to the local network. Harden without --demo; do not publish this vulnerable demo on this engine")
		}
	}
	return hardenImageWith(ctx, image, mode, demo, out, filepath.Join("demo", "runs"), hardenStatic)
}

func safeDemoDockerVersion(version string) bool {
	parts := strings.Split(version, ".")
	if len(parts) != 3 {
		return false
	}
	for _, part := range parts {
		if _, err := strconv.ParseUint(part, 10, 32); err != nil {
			return false
		}
	}
	major, _ := strconv.ParseUint(parts[0], 10, 32)
	return major >= 28
}

func hardenImageWith(ctx context.Context, image, mode string, demo bool, out io.Writer, parent string, run func(context.Context, staticConfig) (*staticReport, error)) error {
	if err := toolImageReference(image); err != nil {
		return fmt.Errorf("image: %w", err)
	}
	if mode != "argon" && mode != "tools" {
		return errors.New("mode must be argon or tools")
	}
	marker := make([]byte, 6)
	if _, err := rand.Read(marker); err != nil {
		return err
	}
	stamp := hex.EncodeToString(marker)
	if err := os.MkdirAll(parent, 0700); err != nil {
		return err
	}
	artifacts, err := filepath.Abs(filepath.Join(parent, "image-"+stamp))
	if err != nil {
		return err
	}
	config := staticConfig{Image: image, Target: "breachbench/hardened:" + stamp, Artifacts: artifacts, Mode: mode, Model: "gemini-4-argon", Policy: genericRuntimePolicy{Network: "none"}}
	if demo {
		config.Policy.Network = "bridge"
	}
	var outputErr error
	print := func(format string, values ...any) {
		if outputErr == nil {
			_, outputErr = fmt.Fprintf(out, format, values...)
		}
	}
	print("\nBreachBench | Harden an image\n\n  Input   %s\n  Engine  %s\n\n", terminalText(image, 512), mode)
	if demo {
		print("  Local demo: loopback publishing; outbound network is ALLOWED.\n\n")
	}
	config.Progress = func(message string) { print("  > %s...\n", message) }
	config.Inspected = func(analysis staticImageAnalysis) {
		print("\n  DETECTED\n    Linux / %s\n    Candidate identity: %s\n    Declared ports: %s\n    Known tool entrypoints: %d; removal candidates: %d\n", terminalText(analysis.Architecture, 32), terminalText(analysis.User, 64), simpleList(analysis.ExposedPorts), len(analysis.PresentTools), len(analysis.EligibleRemovals))
		if analysis.UserChanged {
			print("    Image requests root; candidate will use a non-root identity.\n")
		}
		if analysis.ShellRequired {
			print("    Startup may need a shell; required/uncertain tools are retained.\n")
		}
		print("    Tools found: %s\n\n", simpleList(analysis.PresentTools))
	}
	report, runErr := run(ctx, config)
	if runErr != nil || report == nil || !report.CandidateCreated || !report.DeploymentWritten {
		print("\n  Hardening did not finish. No runnable result is advertised.\n  Evidence (may be partial): %s\n", terminalText(artifacts, 1024))
		if runErr == nil {
			runErr = errors.New("hardening returned no completed candidate and deployment")
		}
		return errors.Join(runErr, outputErr)
	}
	command, mapping, err := simpleRunCommand(report, demo)
	if err != nil {
		return errors.Join(err, outputErr)
	}
	launcher := filepath.Join(artifacts, "run.sh")
	if err := os.WriteFile(launcher, []byte("#!/bin/sh\n# Static candidate; compatibility is unverified.\nexec "+command+" \"$@\"\n"), 0700); err != nil {
		return errors.Join(err, outputErr)
	}
	removed := []string{}
	if report.Filesystem != nil {
		removed = report.Filesystem.RemovedEntries
	}
	print("\n  CANDIDATE READY\n\n")
	if outputErr == nil {
		table := tabwriter.NewWriter(out, 0, 4, 2, ' ', 0)
		fmt.Fprintf(table, "  CHANGE\tRESULT\n  Tool entries removed\t%d (actual filesystem entries)\n  Image identity\t%s\n  Root filesystem\tRead-only at launch\n  Linux capabilities\tAll dropped at launch\n  No-new-privileges\tEnabled at launch\n  Network\t%s\n", len(removed), terminalText(report.Policy.User, 64), report.Policy.Network)
		outputErr = table.Flush()
	}
	print("\n  Removed: %s\n  Application/runtime versions: unchanged\n\n  Image:    %s\n  Evidence: %s\n", simpleList(removed), terminalText(report.Image, 512), terminalText(artifacts, 1024))
	if mapping != "" {
		print("  Demo mapping: %s (declared port, not a readiness check)\n", mapping)
	} else if demo {
		print("  No declared TCP port: no port was published.\n")
	}
	print("\n  Run it:\n\n    %s\n\n  Or use the saved launcher:\n    %s\n\n  Not runtime-tested. Required writes, services and network access are not inferred.\n  This reduces attack surface; it does not fix vulnerabilities or prove RCE is blocked.\n", command, shellWord(launcher))
	return outputErr
}

func simpleList(values []string) string {
	if len(values) == 0 {
		return "none"
	}
	return terminalText(strings.Join(values, ", "), 1800)
}

func simpleRunCommand(report *staticReport, demo bool) (string, string, error) {
	if err := toolImageReference(report.Image); err != nil {
		return "", "", err
	}
	if err := validateGenericPolicy(report.Policy); err != nil {
		return "", "", err
	}
	if report.Policy.Network != "none" && report.Policy.Network != "bridge" {
		return "", "", errors.New("simple launch supports only none or bridge networking")
	}
	args := []string{"docker", "run", "--rm", "--pull=never", "--read-only", "--user=" + report.Policy.User, "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory=512m", "--cpus=1", "--pids-limit=128", "--network=" + report.Policy.Network, "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777"}
	for _, directory := range report.Policy.WritablePaths {
		if directory != "/tmp" && !strings.HasPrefix(directory, "/tmp/") {
			args = append(args, "--tmpfs="+directory+":rw,noexec,nosuid,nodev,size=64m,mode=1777")
		}
	}
	mapping := ""
	if demo && report.Policy.Network == "bridge" && report.Analysis != nil {
		// EXPOSE is only a launch hint, never proof of an HTTP service or readiness.
		for _, exposed := range report.Analysis.ExposedPorts {
			if !strings.HasSuffix(exposed, "/tcp") {
				continue
			}
			port, err := strconv.Atoi(strings.TrimSuffix(exposed, "/tcp"))
			if err != nil || port < 1 || port > 65535 {
				return "", "", errors.New("invalid declared TCP port")
			}
			host := port + 1
			if host > 65535 {
				host = 65534
			}
			host = availableDemoPort(host)
			mapping = fmt.Sprintf("127.0.0.1:%d:%d", host, port)
			args = append(args, "--publish="+mapping)
			break
		}
	}
	args = append(args, report.Image)
	for i, argument := range args {
		args[i] = shellWord(argument)
	}
	return strings.Join(args, " "), mapping, nil
}

func availableDemoPort(preferred int) int {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", preferred))
	if err != nil {
		listener, err = net.Listen("tcp", "127.0.0.1:0")
	}
	if err != nil {
		return preferred
	}
	defer listener.Close()
	// Availability is a launch hint only; the port can be taken after this check.
	return listener.Addr().(*net.TCPAddr).Port
}

func shellWord(value string) string {
	if value != "" && strings.Trim(value, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_./:=,@%+-") == "" {
		return value
	}
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}
