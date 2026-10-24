package imagehardening

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func workloadTestProbe(t *testing.T) string {
	t.Helper()
	file := filepath.Join(t.TempDir(), "probe")
	if err := os.WriteFile(file, []byte("trusted-test-probe-placeholder"), 0700); err != nil {
		t.Fatal(err)
	}
	return file
}

func TestWorkloadSpecValidation(t *testing.T) {
	for _, spec := range []workloadSpec{
		{}, {Mode: "node"}, {Mode: "batch", Port: 8080}, {Mode: "batch", Command: []string{"--flag"}}, {Mode: "batch", Command: []string{"cmd", "a\x00b"}}, {Mode: "batch", StartupTimeoutSeconds: 121},
		{Mode: "http", Port: 8080}, {Mode: "http", Port: 8080, Command: []string{"replace-service"}, HTTPChecks: []workloadHTTPCheck{{Path: "/", Status: 200}}},
	} {
		if validateWorkloadSpec(spec) == nil {
			t.Errorf("invalid workload accepted: %+v", spec)
		}
	}
	for _, path := range []string{"https://example.org", "//example.org", "/hello#fragment", "/hello\nheader", "relative", "/%zz"} {
		if validateWorkloadSpec(workloadSpec{Mode: "http", Port: 8080, HTTPChecks: []workloadHTTPCheck{{Path: path, Status: 200}}}) == nil {
			t.Errorf("invalid HTTP path accepted: %q", path)
		}
	}
	for _, spec := range []workloadSpec{{Mode: "batch"}, {Mode: "batch", Command: []string{"/usr/bin/python3", "-m", "unittest"}}, {Mode: "http", Port: 8080, HTTPChecks: []workloadHTTPCheck{{Path: "/health?check=ready", Status: 200, BodyContains: "healthy"}}}} {
		if err := validateWorkloadSpec(spec); err != nil {
			t.Errorf("valid workload rejected: %v", err)
		}
	}
	var spec workloadSpec
	if err := json.Unmarshal([]byte(`{"mode":"batch","ProbePath":"/secret","probe_path":"/secret"}`), &spec); err != nil || spec.ProbePath != "" {
		t.Fatal("trusted helper path can be set through workload JSON")
	}
}

func TestGenericPolicyNarrowWritableDirectories(t *testing.T) {
	for _, directory := range []string{"/", "/app", "/usr", "/usr/local/bin", "/etc/config", "/proc/self", "/sys", "/dev/shm", "/root/.ssh", "/var", "/var/lib", "/app/../etc", "/app/cache/", "/app/cache:rw", "/app/cache,size=1g", "/app/[cache]", "/app/ca\x00che"} {
		if validateGenericPolicy(genericRuntimePolicy{User: "65532:65532", Network: "none", WritablePaths: []string{directory}}) == nil {
			t.Errorf("unsafe directory accepted: %q", directory)
		}
	}
	for _, directories := range [][]string{{"/app/cache", "/app/cache"}, {"/app/cache", "/app/cache/child"}} {
		if validateGenericPolicy(genericRuntimePolicy{User: "65532:65532", Network: "none", WritablePaths: directories}) == nil {
			t.Errorf("duplicate or overlapping mounts accepted: %q", directories)
		}
	}
	for _, user := range []string{"0:0", "root", "65532:4294967296", ""} {
		if validateGenericPolicy(genericRuntimePolicy{User: user, Network: "none"}) == nil {
			t.Errorf("invalid user accepted: %s", user)
		}
	}
	if err := validateGenericPolicy(genericRuntimePolicy{User: "1001:0", Network: "none"}); err != nil {
		t.Fatalf("non-root UID with existing root-group membership rejected: %v", err)
	}
	if validateGenericPolicy(genericRuntimePolicy{User: "65532:65532", Network: "host"}) == nil {
		t.Fatal("host network policy accepted")
	}
	if err := validateGenericPolicy(genericRuntimePolicy{User: "65532:65532", Network: "internal", WritablePaths: []string{"/app/.next/cache", "/var/cache/nginx", "/run"}}); err != nil {
		t.Fatal(err)
	}
}

func TestGenericRunArgsPreserveRealBaselineAndHTTPEntrypoint(t *testing.T) {
	name := "hardening-workload-" + strings.Repeat("a", 24)
	network := "hardening-workload-" + strings.Repeat("b", 24)
	policy := genericRuntimePolicy{User: "1234:1234", Network: "internal", WritablePaths: []string{"/app/.next/cache"}}
	spec := workloadSpec{Mode: "http", Port: 8080, ProbePath: workloadTestProbe(t), HTTPChecks: []workloadHTTPCheck{{Path: "/health", Status: 200}}}
	for _, hardened := range []bool{false, true} {
		args, err := genericRunArgs("fixture:server", name, network, hardened, policy, spec)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--entrypoint") || args[len(args)-1] != "fixture:server" || strings.Contains(joined, "--publish") {
			t.Fatal("HTTP check changed original command or exposed a host port")
		}
		if strings.Contains(joined, "--user") != hardened || strings.Contains(joined, "--read-only") != hardened || strings.Contains(joined, "--tmpfs") != hardened {
			t.Fatal("baseline security settings manufactured or candidate protections missing")
		}
		for _, required := range []string{"--detach", "target=/.hardening-probe,readonly", "--network=" + network, "--pull=never", "--cap-drop=ALL", "--security-opt=no-new-privileges:true"} {
			if !strings.Contains(joined, required) {
				t.Errorf("missing %s", required)
			}
		}
		for _, forbidden := range []string{"--privileged", "--volume", "--env", "--security-opt=seccomp=unconfined"} {
			if strings.Contains(joined, forbidden) {
				t.Errorf("unsafe option %s", forbidden)
			}
		}
		if hardened && !strings.Contains(joined, "--tmpfs=/app/.next/cache:rw,noexec,nosuid,nodev,size=64m,mode=1777") {
			t.Fatal("declared narrow cache exception missing")
		}
	}
	policy.Network = "none"
	if _, err := genericRunArgs("fixture:server", name, "", true, policy, spec); err != nil {
		t.Fatalf("loopback HTTP unnecessarily requires external networking: %v", err)
	}
	args, err := genericRunArgs("fixture:batch", name, "", true, policy, workloadSpec{Mode: "batch", Command: []string{"/app/self-test", "--smoke"}})
	if err != nil || args[len(args)-1] != "--smoke" || !containsArg(args, "--entrypoint=/app/self-test") || !containsArg(args, "--network=none") {
		t.Fatalf("batch command scope incorrect: %v %v", args, err)
	}
	if _, err := genericRunArgs("fixture", name, "arbitrary-network", true, policy, workloadSpec{Mode: "batch"}); err == nil {
		t.Fatal("arbitrary network allowed")
	}
}

func TestWorkloadHTTPProbeValidation(t *testing.T) {
	valid := workloadTestProbe(t)
	for _, file := range []string{"", "relative", valid + ",target=/secret", filepath.Dir(valid)} {
		if validateWorkloadProbe(file) == nil {
			t.Errorf("invalid probe accepted: %q", file)
		}
	}
	link := filepath.Join(filepath.Dir(valid), "link")
	if err := os.Symlink(valid, link); err != nil {
		t.Fatal(err)
	}
	if validateWorkloadProbe(link) == nil {
		t.Fatal("symlink probe accepted")
	}
	if err := validateWorkloadProbe(valid); err != nil {
		t.Fatal(err)
	}
}

func TestWorkloadHTTPProbeRejectsFalsePasses(t *testing.T) {
	checks := []workloadHTTPCheck{{Path: "/health", Status: 200, BodyContains: "healthy"}}
	good := `{"version":"generic-http-v1","passed":true,"checks":[{"path":"/health","status":200,"passed":true,"body_sha256":"` + strings.Repeat("a", 64) + `"}]}`
	if results, err := parseWorkloadHTTPProbe([]byte(good), checks); err != nil || len(results) != 1 || !results[0].Passed {
		t.Fatalf("valid helper evidence rejected: %v", err)
	}
	for _, bad := range []string{
		`{}`, strings.ReplaceAll(good, "generic-http-v1", "unrecognized"), strings.ReplaceAll(good, `"passed":true`, `"passed":false`),
		strings.ReplaceAll(good, "/health", "/wrong"), strings.ReplaceAll(good, `"status":200`, `"status":404`), strings.ReplaceAll(good, strings.Repeat("a", 64), "not-a-hash"),
		strings.Replace(good, `"checks":[{`, `"checks":[{"error_code":"BODY_MISMATCH",`, 1),
	} {
		if _, err := parseWorkloadHTTPProbe([]byte(bad), checks); err == nil {
			t.Errorf("false HTTP pass accepted: %s", bad)
		}
	}
}

func TestCheckWorkloadLifecyclePinsImageAndCleansExactResources(t *testing.T) {
	imageID := "sha256:" + strings.Repeat("a", 64)
	probePath := workloadTestProbe(t)
	var calls [][]string
	var container, network string
	run := func(ctx context.Context, args ...string) ([]byte, int, error) {
		calls = append(calls, append([]string{}, args...))
		switch args[0] {
		case "image":
			return []byte(imageID), 0, nil
		case "network":
			if args[1] == "create" {
				network = args[len(args)-1]
				if !ownedWorkloadName(network) || !containsArg(args, "--internal") {
					t.Fatal("network is not owned/internal")
				}
			} else if args[len(args)-1] != network {
				t.Fatal("cleanup targeted foreign network")
			}
		case "run":
			container = args[2]
			if !ownedWorkloadName(container) || args[len(args)-1] != imageID || containsArg(args, "--publish") {
				t.Fatal("workload not pinned or a host port exposed")
			}
		case "exec":
			if args[1] != container || args[2] != "/.hardening-probe" || !containsArg(args, "--http-checks-json") || !containsArg(args, "--timeout-seconds") {
				t.Fatal("HTTP probe did not use fixed trusted helper")
			}
			return []byte(`{"version":"generic-http-v1","passed":true,"checks":[{"path":"/health","status":200,"passed":true,"body_sha256":"` + strings.Repeat("b", 64) + `"}]}`), 0, nil
		case "inspect":
			return []byte("true"), 0, nil
		case "rm":
			if args[len(args)-1] != container || ctx.Err() != nil || !containsArg(args, "--volumes") {
				t.Fatal("cleanup not exact or inherited canceled context")
			}
		default:
			t.Fatalf("unexpected Docker command: %q", args)
		}
		return nil, 0, nil
	}
	evidence, err := checkWorkloadWith(context.Background(), "fixture:server", true, genericRuntimePolicy{User: "65532:65532", Network: "internal"}, workloadSpec{Mode: "http", Port: 8080, ProbePath: probePath, HTTPChecks: []workloadHTTPCheck{{Path: "/health", Status: 200, BodyContains: "healthy"}}}, run)
	if err != nil || evidence.Status != "passed" || evidence.ImageID != imageID || evidence.CommandOverride || len(evidence.HTTP) != 1 {
		t.Fatalf("workload evidence: %+v %v", evidence, err)
	}
	if len(calls) < 2 || !reflect.DeepEqual(calls[len(calls)-2], []string{"rm", "-f", "--volumes", "--", container}) || !reflect.DeepEqual(calls[len(calls)-1], []string{"network", "rm", "--", network}) {
		t.Fatalf("scoped resources not cleaned: %q", calls)
	}
}

func TestCheckWorkloadBatchFailureAndCanceledCleanup(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cleaned := false
	run := func(commandCtx context.Context, args ...string) ([]byte, int, error) {
		switch args[0] {
		case "image":
			return []byte("sha256:" + strings.Repeat("b", 64)), 0, nil
		case "run":
			cancel()
			return nil, -1, context.Canceled
		case "rm":
			cleaned = commandCtx.Err() == nil && containsArg(args, "--volumes")
			return nil, 0, nil
		}
		return nil, -1, errors.New("unexpected command")
	}
	evidence, err := checkWorkloadWith(ctx, "fixture:batch", true, genericRuntimePolicy{User: "65532:65532", Network: "none"}, workloadSpec{Mode: "batch", Command: []string{"/app/self-test"}}, run)
	if err == nil || evidence.Status == "passed" || !cleaned || !evidence.CommandOverride {
		t.Fatalf("canceled workload or cleanup failed: %+v %v", evidence, err)
	}
}

func TestHTTPFailedProbeOrStoppedServiceCannotPass(t *testing.T) {
	probePath := workloadTestProbe(t)
	for _, running := range []bool{false, true} {
		run := func(_ context.Context, args ...string) ([]byte, int, error) {
			switch args[0] {
			case "image":
				return []byte("sha256:" + strings.Repeat("a", 64)), 0, nil
			case "exec":
				if running {
					return []byte(`{"version":"generic-http-v1","passed":false,"checks":[]}`), 1, nil
				}
				return []byte(`{"version":"generic-http-v1","passed":true,"checks":[{"path":"/","status":200,"passed":true,"body_sha256":"` + strings.Repeat("a", 64) + `"}]}`), 0, nil
			case "inspect":
				return []byte("false"), 0, nil
			}
			return nil, 0, nil
		}
		evidence, err := checkWorkloadWith(context.Background(), "fixture:server", true, genericRuntimePolicy{User: "65532:65532", Network: "none"}, workloadSpec{Mode: "http", Port: 8080, ProbePath: probePath, HTTPChecks: []workloadHTTPCheck{{Path: "/", Status: 200}}}, run)
		if err == nil || evidence.Status == "passed" {
			t.Fatal("failed probe or stopped service passed")
		}
	}
}

func TestCanonicalWorkloadPathsUsesReadOnlyHelperAndChecksImplicitTmp(t *testing.T) {
	helper := workloadTestProbe(t)
	var container string
	cleaned := false
	run := func(ctx context.Context, args ...string) ([]byte, int, error) {
		switch args[0] {
		case "image":
			return []byte("sha256:" + strings.Repeat("a", 64)), 0, nil
		case "run":
			for _, required := range []string{"--rm", "--read-only", "--no-healthcheck", "--network=none", "--entrypoint=/.hardening-probe", "--canonical-writable-paths-json"} {
				if !containsArg(args, required) {
					t.Errorf("missing fixed preflight option %s", required)
				}
			}
			if containsArg(args, "--user") || strings.Contains(strings.Join(args, " "), "--tmpfs") {
				t.Fatal("preflight changed original USER or mounted proposed writable paths before checking them")
			}
			for index, arg := range args {
				if arg == "--name" {
					container = args[index+1]
				}
			}
			if !ownedWorkloadName(container) || args[len(args)-1] != `["/tmp","/var/run/app-cache"]` {
				t.Fatal("preflight omitted implicit /tmp or reordered paths")
			}
			return []byte(`{"version":"generic-paths-v1","paths":["/tmp","/run/app-cache"]}`), 0, nil
		case "rm":
			cleaned = args[len(args)-1] == container && ctx.Err() == nil && containsArg(args, "--volumes")
			return nil, 0, nil
		}
		return nil, -1, errors.New("unexpected Docker command")
	}
	canonical, err := canonicalWorkloadPathsWith(context.Background(), "fixture", helper, []string{"/tmp", "/var/run/app-cache"}, run)
	if err != nil || !reflect.DeepEqual(canonical, []string{"/tmp", "/run/app-cache"}) || !cleaned {
		t.Fatalf("canonical preflight failed: %q %v cleaned=%t", canonical, err, cleaned)
	}
}

func TestCanonicalWorkloadPathsRejectAliasesAndIncompleteEvidence(t *testing.T) {
	helper := workloadTestProbe(t)
	for _, output := range []string{
		`{"version":"generic-paths-v1","paths":["/var/tmp","/run/cache"]}`,
		`{"version":"generic-paths-v1","paths":["/tmp","/etc"]}`,
		`{"version":"generic-paths-v1","paths":["/tmp","/app"]}`,
		`{"version":"generic-paths-v1","paths":["/tmp"]}`,
		`{"version":"wrong","paths":["/tmp","/run/cache"]}`,
	} {
		run := func(_ context.Context, args ...string) ([]byte, int, error) {
			if args[0] == "image" {
				return []byte("sha256:" + strings.Repeat("a", 64)), 0, nil
			}
			if args[0] == "run" {
				return []byte(output), 0, nil
			}
			return nil, 0, nil
		}
		if paths, err := canonicalWorkloadPathsWith(context.Background(), "fixture", helper, []string{"/app/cache"}, run); err == nil {
			t.Errorf("unsafe canonical evidence accepted: %q", paths)
		}
	}
}

func TestDeclaredBridgeNetworkIsOwnedButNotCalledInternal(t *testing.T) {
	created := false
	run := func(_ context.Context, args ...string) ([]byte, int, error) {
		if args[0] == "image" {
			return []byte("sha256:" + strings.Repeat("a", 64)), 0, nil
		}
		if args[0] == "network" && args[1] == "create" {
			created = true
			if containsArg(args, "--internal") || !ownedWorkloadName(args[len(args)-1]) {
				t.Fatal("declared bridge policy was not honored or used an unrelated network")
			}
		}
		return nil, 0, nil
	}
	evidence, err := checkWorkloadWith(context.Background(), "fixture", true, genericRuntimePolicy{User: "65532:65532", Network: "bridge"}, workloadSpec{Mode: "batch"}, run)
	if err != nil || evidence.Status != "passed" || !created {
		t.Fatalf("explicit bridge workload failed: %+v %v", evidence, err)
	}
}
