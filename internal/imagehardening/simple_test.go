package imagehardening

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func simpleTestReport(config staticConfig) *staticReport {
	return &staticReport{
		Image: config.Target, CandidateCreated: true, DeploymentWritten: true, Compatibility: "unverified",
		Policy: genericRuntimePolicy{User: "10001:0", Network: config.Policy.Network, WritablePaths: []string{"/app/cache's data"}},
		Analysis: &staticImageAnalysis{Architecture: "amd64", User: "10001:0", ExposedPorts: []string{"3000/tcp"},
			PresentTools: []string{"/bin/sh", "/usr/bin/curl", "/usr/bin/wget"}, EligibleRemovals: []string{"/bin/sh", "/usr/bin/curl", "/usr/bin/wget"}},
		Filesystem: &imageRebuildEvidence{RemovedEntries: []string{"/usr/bin/curl"}},
	}
}

func TestSimpleImageDefaultsFreshOutputsAndExplicitDemo(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "private results")
	var previous staticConfig
	for _, demo := range []bool{false, true} {
		var output bytes.Buffer
		var observed staticConfig
		err := hardenImageWith(context.Background(), "local/app:before", "argon", demo, &output, parent, func(_ context.Context, config staticConfig) (*staticReport, error) {
			observed = config
			if config.Image != "local/app:before" || config.Mode != "argon" || config.Model != "gemini-4-argon" || !filepath.IsAbs(config.Artifacts) || filepath.Dir(config.Artifacts) != parent {
				t.Fatalf("unexpected automatic configuration: %+v", config)
			}
			if _, err := os.Stat(config.Artifacts); !os.IsNotExist(err) {
				t.Fatal("runner must receive a new, unoccupied artifact path")
			}
			if err := os.Mkdir(config.Artifacts, 0700); err != nil {
				t.Fatal(err)
			}
			result := simpleTestReport(config)
			config.Progress("Inspecting image")
			config.Inspected(*result.Analysis)
			return result, nil
		})
		if err != nil {
			t.Fatal(err)
		}
		if !regexp.MustCompile(`^breachbench/hardened:[0-9a-f]{12}$`).MatchString(observed.Target) || observed.Target == previous.Target || observed.Artifacts == previous.Artifacts {
			t.Fatalf("output is not fresh and automatic: %+v", observed)
		}
		text := output.String()
		for _, expected := range []string{"Inspecting image", "DETECTED", "Candidate identity: 10001:0", "removal candidates: 3", "Removed: /usr/bin/curl", "Not runtime-tested", "--read-only", "--user=10001:0"} {
			if !strings.Contains(text, expected) {
				t.Fatalf("missing %q in output: %s", expected, text)
			}
		}
		if !regexp.MustCompile(`Tool entries removed\s+1 \(actual filesystem entries\)`).MatchString(text) {
			t.Fatal("summary counted eligible tools instead of actual removals")
		}
		launcher := filepath.Join(observed.Artifacts, "run.sh")
		data, err := os.ReadFile(launcher)
		if err != nil || !bytes.Contains(data, []byte("exec docker run ")) || !bytes.Contains(data, []byte(shellWord("--tmpfs=/app/cache's data:rw,noexec,nosuid,nodev,size=64m,mode=1777"))) {
			t.Fatalf("missing protected, quoted launcher: %q %v", data, err)
		}
		for _, path := range []string{parent, observed.Artifacts, launcher} {
			info, err := os.Stat(path)
			if err != nil || info.Mode().Perm()&0077 != 0 {
				t.Fatalf("artifact is not owner-only: %s %v", path, err)
			}
		}
		if demo {
			if observed.Policy.Network != "bridge" || !strings.Contains(text, "outbound network is ALLOWED") || !regexp.MustCompile(`--publish=127\.0\.0\.1:[0-9]+:3000`).Match(data) {
				t.Fatal("demo did not explicitly disclose bridge egress and loopback mapping")
			}
		} else if observed.Policy.Network != "none" || !bytes.Contains(data, []byte("--network=none")) || strings.Contains(text, "--publish") {
			t.Fatal("default launch broadened network access or published a port")
		}
		previous = observed
	}
}

func TestSimpleImageRejectsInvalidInputBeforeRunner(t *testing.T) {
	for _, test := range []struct{ image, mode string }{{"", "tools"}, {"-flag", "tools"}, {"image with spaces", "tools"}, {"image\x1b", "tools"}, {"local/app:before", "invalid"}} {
		parent := filepath.Join(t.TempDir(), "unused")
		err := hardenImageWith(context.Background(), test.image, test.mode, false, &bytes.Buffer{}, parent, func(context.Context, staticConfig) (*staticReport, error) {
			t.Fatal("invalid input reached runner")
			return nil, nil
		})
		if err == nil {
			t.Fatalf("invalid configuration accepted: %+v", test)
		}
		if _, err := os.Stat(parent); !os.IsNotExist(err) {
			t.Fatal("invalid input created output directories")
		}
	}
}

func TestSimpleImageFailureNeverAdvertisesLaunch(t *testing.T) {
	for _, state := range []string{"runner error", "nil report", "missing candidate", "missing deployment"} {
		t.Run(state, func(t *testing.T) {
			var output bytes.Buffer
			var artifacts string
			err := hardenImageWith(context.Background(), "local/app:before", "tools", false, &output, t.TempDir(), func(_ context.Context, config staticConfig) (*staticReport, error) {
				artifacts = config.Artifacts
				report := simpleTestReport(config)
				switch state {
				case "runner error":
					return report, errors.New("export failed")
				case "nil report":
					return nil, nil
				case "missing candidate":
					report.CandidateCreated = false
				case "missing deployment":
					report.DeploymentWritten = false
				}
				return report, nil
			})
			if err == nil || strings.Contains(output.String(), "CANDIDATE READY") || strings.Contains(output.String(), "docker run") || strings.Contains(output.String(), "Run it:") {
				t.Fatalf("failed workflow advertised success: %s %v", output.String(), err)
			}
			if _, err := os.Stat(filepath.Join(artifacts, "run.sh")); !os.IsNotExist(err) {
				t.Fatal("failed workflow wrote a launcher")
			}
		})
	}
}

func TestSimpleRunCommandPreservesControlsAndQuotes(t *testing.T) {
	report := simpleTestReport(staticConfig{Target: "local/app:after", Policy: genericRuntimePolicy{Network: "none"}})
	command, mapping, err := simpleRunCommand(report, false)
	if err != nil || mapping != "" {
		t.Fatal(command, mapping, err)
	}
	for _, argument := range []string{"--rm", "--pull=never", "--read-only", "--user=10001:0", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--memory=512m", "--cpus=1", "--pids-limit=128", "--network=none", "--tmpfs=/tmp:rw,noexec,nosuid,nodev,size=64m,mode=1777", shellWord("--tmpfs=/app/cache's data:rw,noexec,nosuid,nodev,size=64m,mode=1777")} {
		if !strings.Contains(command, argument) {
			t.Errorf("missing launch protection %q", argument)
		}
	}
	if strings.Contains(command, "--publish") || strings.Contains(command, "--entrypoint") || strings.Contains(command, "--privileged") || !strings.HasSuffix(command, " local/app:after") {
		t.Fatal("launch changed application entrypoint or broadened privileges", command)
	}
	for value, expected := range map[string]string{"": "''", "local/app:v1": "local/app:v1", "has spaces": "'has spaces'", "it's": "'it'\"'\"'s'", "$(printf nope);": "'$(printf nope);'"} {
		if got := shellWord(value); got != expected {
			t.Errorf("unsafe shell quoting of %q: got %q, want %q", value, got, expected)
		}
	}
	report.Policy.User = "0:0"
	if command, _, err := simpleRunCommand(report, false); err == nil || command != "" {
		t.Fatal("root policy produced a launch command")
	}
}

func TestSimpleImageUsesOnlyNonExecutingStaticDockerOperations(t *testing.T) {
	dir := t.TempDir()
	logPath := installStaticFakeDocker(t, dir, "sha256:"+strings.Repeat("a", 64), "public-env-sentinel", "public-command-sentinel")
	parent := filepath.Join(dir, "results")
	var output bytes.Buffer
	if err := hardenImageWith(context.Background(), "local/static-fixture:before", "tools", false, &output, parent, hardenStatic); err != nil {
		t.Fatal(err)
	}
	commands, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(strings.TrimSpace(string(commands)), "\n") {
		verb := strings.Split(line, "\t")[0]
		if verb != "image" && verb != "container" && verb != "create" && verb != "rm" {
			t.Fatalf("static front door executed a runtime/build command: %q", line)
		}
	}
	entries, err := os.ReadDir(parent)
	if err != nil || len(entries) != 1 {
		t.Fatal("missing unique evidence directory", err)
	}
	data, err := os.ReadFile(filepath.Join(parent, entries[0].Name(), "report.json"))
	var report staticReport
	if err != nil || json.Unmarshal(data, &report) != nil || report.ApplicationTested || report.Compatibility != "unverified" {
		t.Fatal("front door claimed runtime validation", err)
	}
}

func TestSimpleDemoRejectsUnsafeOrUnverifiedEngineVersions(t *testing.T) {
	for version, want := range map[string]bool{"27.5.1": false, "28.0.0": true, "29.2.1": true, "28.0.0-rc1": false, "28.unknown": false, "28.0.0.extra": false, "": false, "unknown": false, "28": false} {
		if got := safeDemoDockerVersion(version); got != want {
			t.Errorf("version %q: safe=%v, want %v", version, got, want)
		}
	}
}
