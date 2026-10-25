package imagehardening

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStaticToolsNeverExecuteTargetApplication(t *testing.T) {
	for _, failExport := range []bool{false, true} {
		name := "candidate"
		if failExport {
			name = "export_failure"
		}
		t.Run(name, func(t *testing.T) {
			const source = "local/static-fixture:before"
			const target = "local/static-fixture:after"
			const environmentSecret = "static-test-environment-secret-not-for-report"
			const commandSecret = "static-test-command-secret-not-for-report"
			sourceID := "sha256:" + strings.Repeat("a", 64)
			dir := t.TempDir()
			logPath := installStaticFakeDocker(t, dir, sourceID, environmentSecret, commandSecret)
			if failExport {
				t.Setenv("STATIC_TEST_EXPORT_FAIL", "1")
			}
			artifacts := filepath.Join(dir, "artifacts")
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			report, err := hardenStatic(ctx, staticConfig{Image: source, Target: target, Artifacts: artifacts, Mode: "tools"})
			if report == nil || report.ApplicationTested || report.Compatibility != "unverified" {
				t.Fatalf("static route must not claim application validation: report=%+v error=%v", report, err)
			}
			if failExport {
				if err == nil || report.CandidateCreated || report.DeploymentWritten {
					t.Fatalf("failed export claimed a candidate or deployment: report=%+v error=%v", report, err)
				}
				if _, statErr := os.Stat(filepath.Join(artifacts, "compose.json")); !os.IsNotExist(statErr) {
					t.Fatalf("failed export wrote deployment: %v", statErr)
				}
			} else {
				if err != nil || !report.CandidateCreated || !report.DeploymentWritten || report.Policy.User != "10001:10001" {
					t.Fatalf("static tools did not produce an untested candidate: report=%+v error=%v", report, err)
				}
				if report.Filesystem == nil || report.Filesystem.ApplicationFilesModified || len(report.Filesystem.RemovedEntries) == 0 {
					t.Fatalf("expected bounded entry pruning without application edits: %+v", report.Filesystem)
				}
				data, readErr := os.ReadFile(filepath.Join(artifacts, "compose.json"))
				if readErr != nil {
					t.Fatal(readErr)
				}
				var compose struct {
					Services map[string]struct {
						Image       string `json:"image"`
						User        string `json:"user"`
						ReadOnly    bool   `json:"read_only"`
						NetworkMode string `json:"network_mode"`
					} `json:"services"`
				}
				if json.Unmarshal(data, &compose) != nil || compose.Services["app"].Image != target || compose.Services["app"].User != "10001:10001" || !compose.Services["app"].ReadOnly || compose.Services["app"].NetworkMode != "none" {
					t.Fatalf("unexpected restrictive deployment: %s", data)
				}
			}
			data, readErr := os.ReadFile(filepath.Join(artifacts, "report.json"))
			if readErr != nil {
				t.Fatal(readErr)
			}
			encoded, marshalErr := json.Marshal(report)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			for _, secret := range []string{environmentSecret, commandSecret} {
				if bytes.Contains(data, []byte(secret)) || bytes.Contains(encoded, []byte(secret)) {
					t.Fatal("static report exposed original environment or command values")
				}
			}
			if !bytes.Contains(data, []byte(`"application_tested": false`)) && !bytes.Contains(data, []byte(`"application_tested":false`)) {
				t.Fatal("saved report omitted explicit application_tested=false")
			}
			commands, readErr := os.ReadFile(logPath)
			if readErr != nil {
				t.Fatal(readErr)
			}
			mutableInspects, creates, loads := 0, 0, 0
			for _, line := range strings.Split(strings.TrimSpace(string(commands)), "\n") {
				args := strings.Split(line, "\t")
				if len(args) < 2 {
					t.Fatalf("unexpected Docker invocation: %q", line)
				}
				switch args[0] + " " + args[1] {
				case "image ls", "container export", "rm -fv":
				case "image inspect":
					if args[len(args)-1] == source {
						mutableInspects++
					} else if args[len(args)-1] != sourceID {
						t.Fatalf("unexpected inspection target: %q", line)
					}
				case "image load":
					loads++
				default:
					if args[0] != "create" {
						t.Fatalf("static mode invoked a runtime/build command: %q", line)
					}
					creates++
					safeEntrypoint := strings.Contains(line, "--entrypoint=/.not-executed") || strings.Contains(line, "--entrypoint=/.breachbench-not-executed")
					if args[len(args)-1] != sourceID || !safeEntrypoint || !strings.Contains(line, "--network=none") {
						t.Fatalf("export container was not pinned and non-executing: %q", line)
					}
				}
			}
			if mutableInspects != 1 || creates == 0 || (failExport && loads != 0) || (!failExport && loads != 1) {
				t.Fatalf("unexpected immutable inspection/repack sequence: %s", commands)
			}
		})
	}
}

func installStaticFakeDocker(t *testing.T, dir, sourceID, environmentSecret, commandSecret string) string {
	t.Helper()
	var rootfs bytes.Buffer
	archive := tar.NewWriter(&rootfs)
	for _, name := range []string{"etc", "usr", "usr/bin", "custom", "tmp"} {
		if err := archive.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeDir, Mode: 0755}); err != nil {
			t.Fatal(err)
		}
	}
	for name, body := range map[string]string{
		"custom/app":   "\x7fELFpublic synthetic application bytes; must never execute",
		"usr/bin/dash": "\x7fELFpublic synthetic shell bytes",
		"usr/bin/curl": "\x7fELFpublic synthetic download tool bytes",
		"etc/passwd":   "app:x:10001:10001::/custom:/usr/bin/sh\n",
		"etc/group":    "app:x:10001:\n",
	} {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0755, Typeflag: tar.TypeReg, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := archive.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"bin": "usr/bin", "usr/bin/sh": "dash"} {
		if err := archive.WriteHeader(&tar.Header{Name: name, Mode: 0777, Typeflag: tar.TypeSymlink, Linkname: target}); err != nil {
			t.Fatal(err)
		}
	}
	if err := archive.Close(); err != nil {
		t.Fatal(err)
	}
	metadata, err := json.Marshal([]any{map[string]any{"Id": sourceID, "Architecture": "amd64", "Os": "linux", "Config": map[string]any{
		"User": "10001:10001", "WorkingDir": "/custom", "Entrypoint": []string{"/custom/app", commandSecret}, "Cmd": []string{"serve"},
		"Env": []string{"PRIVATE_TEST_SECRET=" + environmentSecret, "PATH=/usr/bin:/bin"},
	}}})
	if err != nil {
		t.Fatal(err)
	}
	files := map[string][]byte{"rootfs.tar": rootfs.Bytes(), "inspect.json": metadata, "docker": []byte(`#!/bin/sh
printf '%s' "$1" >> "$STATIC_TEST_DOCKER_LOG"
shift_first=1
for argument in "$@"; do
    if [ "$shift_first" = 1 ]; then shift_first=0; continue; fi
    printf '\t%s' "$argument" >> "$STATIC_TEST_DOCKER_LOG"
done
printf '\n' >> "$STATIC_TEST_DOCKER_LOG"
case "$1 $2" in
    'image ls') exit 0 ;;
    'image inspect') /bin/cat "$STATIC_TEST_INSPECT"; exit $? ;;
    'container export')
        [ "$STATIC_TEST_EXPORT_FAIL" = 1 ] && exit 42
        if [ "$3" = '--output' ]; then /bin/cp "$STATIC_TEST_ROOTFS" "$4"; else /bin/cat "$STATIC_TEST_ROOTFS"; fi
        exit $? ;;
    'image load') printf 'Loaded synthetic image\n'; exit 0 ;;
    'rm -fv') exit 0 ;;
esac
if [ "$1" = create ]; then printf 'synthetic-never-started-container\n'; exit 0; fi
exit 99
`)}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0700); err != nil {
			t.Fatal(err)
		}
	}
	logPath := filepath.Join(dir, "docker.log")
	t.Setenv("STATIC_TEST_DOCKER_LOG", logPath)
	t.Setenv("STATIC_TEST_INSPECT", filepath.Join(dir, "inspect.json"))
	t.Setenv("STATIC_TEST_ROOTFS", filepath.Join(dir, "rootfs.tar"))
	t.Setenv("STATIC_TEST_EXPORT_FAIL", "")
	t.Setenv("PATH", dir)
	return logPath
}
