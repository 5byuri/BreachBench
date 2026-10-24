package imagehardening

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"text/template"
)

func TestImageFactsExcludeSensitiveDockerFields(t *testing.T) {
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "docker" || len(args) != 6 || args[0] != "image" || args[1] != "inspect" || args[2] != "--format" || args[4] != "--" || args[5] != "fixture:base" {
			t.Fatalf("unexpected argv: %s %q", name, args)
		}
		for _, forbidden := range []string{".Config.Env", ".Config.Labels", ".Config.Healthcheck", "json .Config.Cmd", "json .Config.Entrypoint", `json (index .Config "Cmd")`, `json (index .Config "Entrypoint")`, `json (index .Config "OnBuild")`} {
			if strings.Contains(args[3], forbidden) {
				t.Errorf("requests sensitive field %q", forbidden)
			}
		}
		return []byte(`{"id":"sha256:` + strings.Repeat("a", 64) + `","size_bytes":123,"user":"1000","entrypoint_arguments":1,"command_arguments":2,"exposed_ports":{"8080/tcp":{}}}`), nil
	}
	facts, err := inspectImageWith(context.Background(), "fixture:base", run)
	if err != nil || facts.SizeBytes != 123 || facts.EntrypointArguments != 1 {
		t.Fatalf("facts=%+v err=%v", facts, err)
	}
	encoded, err := json.Marshal(facts)
	if err != nil || strings.Contains(string(encoded), "password") {
		t.Fatal("invalid safe facts")
	}
}

func TestImageFactsTemplateHandlesMissingConfigFields(t *testing.T) {
	for _, config := range []map[string]any{
		{},
		{"Entrypoint": []string{"app"}, "Cmd": []string{"--test"}, "OnBuild": []string{"RUN hidden"}},
	} {
		tmpl, err := template.New("inspect").Option("missingkey=error").Funcs(template.FuncMap{"json": func(value any) (string, error) {
			data, err := json.Marshal(value)
			return string(data), err
		}}).Parse(imageFactsFormat)
		if err != nil {
			t.Fatal(err)
		}
		var out bytes.Buffer
		err = tmpl.Execute(&out, map[string]any{"Id": "sha256:" + strings.Repeat("b", 64), "Architecture": "arm64", "Os": "linux", "Size": 123, "Config": config})
		if err != nil {
			t.Fatal(err)
		}
		var facts imageFacts
		if err := json.Unmarshal(out.Bytes(), &facts); err != nil {
			t.Fatalf("invalid metadata: %s: %v", out.String(), err)
		}
		if facts.OnBuildTriggers != lenValue(config["OnBuild"]) || strings.Contains(out.String(), "RUN hidden") {
			t.Fatalf("OnBuild contents leaked or count wrong: %s", out.String())
		}
	}
}

func lenValue(value any) int {
	if values, ok := value.([]string); ok {
		return len(values)
	}
	return 0
}

func TestSlimRetentionPathValidation(t *testing.T) {
	for _, value := range []string{"", "/", "relative", "/app/../bin", "/app/", "/app//file", "/app/*", "/app?[a]", "/app:777#0#0", "/app\x00file", "/app\nfile", "/app\\file"} {
		if slimRetentionPath(value) == nil {
			t.Errorf("accepted unsafe path %q", value)
		}
	}
	for _, value := range []string{"/app", "/usr/local/bin/node", "/app/static assets"} {
		if err := slimRetentionPath(value); err != nil {
			t.Errorf("rejected literal path %q: %v", value, err)
		}
	}
}

func TestSlimBuildUsesFixedOfflinePolicyAndRetention(t *testing.T) {
	dir := t.TempDir()
	args, err := slimBuildArgs("fixture:base", "fixture:slim", dir, "hardening-profile-0123456789abcdef", []string{"/usr/local/bin/node", "/app"})
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"--http-probe=false", "--continue-after=10", "--network=hardening-profile-0123456789abcdef", "--pull=false", "--include-new=false", "--include-shell=false", "--include-cert-all=false", "--run-target-as-user=true", "--cro-host-config-file"} {
		if !containsArg(args, required) {
			t.Errorf("missing %s", required)
		}
	}
	for _, forbidden := range []string{"--exec", "--entrypoint", "--cmd", "--mount", "--env", "--host-exec"} {
		if containsArg(args, forbidden) {
			t.Errorf("unexpected unsafe flag %s", forbidden)
		}
	}
	wantTail := []string{"--include-path", "/app", "--preserve-path", "/app", "--include-path", "/usr/local/bin/node", "--preserve-path", "/usr/local/bin/node"}
	if !reflect.DeepEqual(args[len(args)-len(wantTail):], wantTail) {
		t.Fatalf("retention argv: %q", args)
	}
}

func TestSlimMinifyRejectsUnsafeInputsBeforeExecution(t *testing.T) {
	run := func(context.Context, string, ...string) ([]byte, error) {
		t.Fatal("must not run an invalid request")
		return nil, nil
	}
	for _, test := range []struct {
		source, candidate, artifact string
		paths                       []string
	}{
		{"same:tag", "same:tag", t.TempDir(), nil},
		{"--flag", "candidate:tag", t.TempDir(), nil},
		{"source:tag", "candidate:tag\x00", t.TempDir(), nil},
		{"source:tag", "candidate:tag", "/", nil},
		{"source:tag", "candidate:tag", t.TempDir(), []string{"/"}},
		{"source:tag", "candidate:tag", t.TempDir(), make([]string, 33)},
	} {
		if _, err := slimMinifyWith(context.Background(), "slim", test.source, test.candidate, test.artifact, test.paths, run); err == nil {
			t.Errorf("accepted invalid request: %+v", test)
		}
	}
}

func TestSlimMinifySurfacesOnlyExistingRestrictiveProfile(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(dir, "fixture-seccomp.json")
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name == "docker" {
			if len(args) >= 2 && args[0] == "network" && args[1] == "create" && (!containsArg(args, "--internal") || !containsArg(args, "com.docker.network.bridge.host_binding_ipv4=127.0.0.1")) {
				t.Fatalf("unsafe network creation: %q", args)
			}
			return nil, nil
		}
		if name != "/tools/slim" || !containsArg(args, "--target") {
			t.Fatalf("unexpected tool: %s %q", name, args)
		}
		if err := os.WriteFile(profile, []byte(`{"defaultAction":"SCMP_ACT_ERRNO"}`), 0600); err != nil {
			t.Fatal(err)
		}
		return []byte("not forwarded: sensitive tool log"), nil
	}
	result, err := slimMinifyWith(context.Background(), "/tools/slim", "base:tag", "candidate:tag", dir, []string{"/app"}, run)
	if err != nil || result.SeccompProfile != profile || result.ApplicationTested || result.ProfileSeconds != 10 {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	data, _ := json.Marshal(result)
	if strings.Contains(string(data), "sensitive") {
		t.Fatal("tool logs leaked into model result")
	}
	config, err := os.ReadFile(filepath.Join(dir, "profiling-host-config.json"))
	if err != nil || !strings.Contains(string(config), `"HostIp":"127.0.0.1"`) || strings.Contains(string(config), `"HostIp":"0.0.0.0"`) {
		t.Fatalf("unsafe sensor binding config: %s err=%v", config, err)
	}
	failureDir := filepath.Join(dir, "failure")
	if err := os.Mkdir(failureDir, 0700); err != nil {
		t.Fatal(err)
	}
	_, err = slimMinifyWith(context.Background(), "/tools/slim", "base:tag", "candidate:tag", failureDir, nil, func(_ context.Context, name string, _ ...string) ([]byte, error) {
		if name == "docker" {
			return nil, nil
		}
		return nil, errors.New("SECRET")
	})
	if err == nil || strings.Contains(err.Error(), "SECRET") {
		t.Fatal("tool error leaked or lost")
	}
}

func TestSlimCleanupOnlyRemovesOwnedContainerIDsAndNetwork(t *testing.T) {
	id := strings.Repeat("a", 64)
	var calls [][]string
	run := func(_ context.Context, name string, args ...string) ([]byte, error) {
		if name != "docker" {
			t.Fatalf("unexpected executable %q", name)
		}
		calls = append(calls, append([]string{}, args...))
		if args[0] == "ps" {
			return []byte(id + "\n--all\nnot-an-id"), nil
		}
		return nil, nil
	}
	cleanupSlimResources("owner=test", "hardening-profile-abc", run)
	if len(calls) != 3 || !reflect.DeepEqual(calls[1], []string{"rm", "-f", "--", id}) || !reflect.DeepEqual(calls[2], []string{"network", "rm", "--", "hardening-profile-abc"}) {
		t.Fatalf("unsafe cleanup: %q", calls)
	}
}

func TestSlimCleansInternalNetworkAfterCancellation(t *testing.T) {
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	network, removed := "", false
	run := func(callContext context.Context, name string, args ...string) ([]byte, error) {
		if name == "slim" {
			cancel()
			return nil, ctx.Err()
		}
		if args[0] == "network" && args[1] == "create" {
			network = args[len(args)-1]
		}
		if args[0] == "network" && args[1] == "rm" {
			if callContext.Err() != nil || args[len(args)-1] != network || network == "" {
				t.Fatalf("cleanup reused canceled context or wrong network: %q", args)
			}
			removed = true
		}
		return nil, nil
	}
	if _, err := slimMinifyWith(ctx, "slim", "source:tag", "candidate:tag", dir, nil, run); err == nil || !removed {
		t.Fatalf("network cleanup missing: removed=%v err=%v", removed, err)
	}
}

func TestSlimIgnoresEnvironmentFlagInjection(t *testing.T) {
	environment := []string{"PATH=/tools", "DOCKER_HOST=unix:///docker.sock", "DSLIM_HOST_EXEC=bad", "DSLIM_MOUNT=bad", "MINT_HOST_EXEC=bad", "GEMINI_API_KEY=fake", "GOOGLE_API_KEY=fake"}
	want := []string{"PATH=/tools", "DOCKER_HOST=unix:///docker.sock"}
	if got := slimEnvironment(environment); !reflect.DeepEqual(got, want) {
		t.Fatalf("unexpected executable environment: %q", got)
	}
}

func containsArg(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}
