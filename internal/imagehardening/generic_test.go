package imagehardening

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ai "google.golang.org/genai/interactions/models/interactions"
)

func TestGenericCLIHasNoNodeFixtureRequirement(t *testing.T) {
	for _, args := range [][]string{{"auto"}, {"agent", "--mode=invalid"}, {"auto", "--checks=x", "--timeout=0"}} {
		if genericCLI(args, &strings.Builder{}) == nil {
			t.Fatal("invalid settings accepted")
		}
	}
	if err := genericUser("1001:0"); err != nil {
		t.Fatal("legitimate non-root user with GID0 rejected")
	}
	for _, user := range []string{"0:0", "root", "1:2:3", "1:-1", "4294967296:1"} {
		if genericUser(user) == nil {
			t.Fatal("unsafe identity accepted")
		}
	}
}

func TestGenericRemovalCallCannotSelectApplicationCodeOrRequiredShell(t *testing.T) {
	for _, paths := range [][]string{{"/app/server.js"}, {"/usr/bin/node"}, {"/usr/bin/bash"}} {
		step := ai.NewStep(ai.FunctionCallStep{ID: "x", Name: "remove_unneeded_tools", Arguments: map[string]any{"remove_paths": paths}})
		if _, _, err := genericRemovalCall([]ai.Step{step}, []string{"/usr/bin/curl"}); err == nil {
			t.Fatal("disallowed removal accepted")
		}
	}
	step := ai.NewStep(ai.FunctionCallStep{ID: "x", Name: "remove_unneeded_tools", Arguments: map[string]any{"remove_paths": []string{"/usr/bin/curl"}}})
	if _, paths, err := genericRemovalCall([]ai.Step{step}, []string{"/usr/bin/curl"}); err != nil || len(paths) != 1 {
		t.Fatal(err)
	}
	if _, _, err := genericRemovalCall([]ai.Step{step, step}, []string{"/usr/bin/curl"}); err == nil {
		t.Fatal("parallel mutable tool calls accepted")
	}
}

func TestGenericRepairRestoresToolsInsteadOfWeakeningTests(t *testing.T) {
	allowed := []string{"/bin/sh", "/usr/bin/curl"}
	if len(genericRemovalAttempt(allowed, 0)) != 2 || len(genericRemovalAttempt(allowed, 1)) != 1 || len(genericRemovalAttempt(allowed, 2)) != 0 {
		t.Fatal("repair does not conservatively retain more tools")
	}
}

func TestGenericPolicyRequiresDeclaredImageVolume(t *testing.T) {
	metadata := localImageMetadata{Config: map[string]json.RawMessage{"Volumes": json.RawMessage(`{"/var/lib/postgresql/data":{}}`)}}
	if validateImageVolumes(metadata, genericRuntimePolicy{}) == nil {
		t.Fatal("anonymous writable mount silently allowed")
	}
	if err := validateImageVolumes(metadata, genericRuntimePolicy{WritablePaths: []string{"/var/lib/postgresql/data"}}); err != nil {
		t.Fatal(err)
	}
}

func TestGenericJSONRejectsExtraDocumentsAndUnknownFields(t *testing.T) {
	for _, text := range []string{`{"mode":"batch"} {}`, `{"mode":"batch","node_file":"/app/app.js"}`} {
		path := filepath.Join(t.TempDir(), "spec.json")
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		var spec workloadSpec
		if readGenericJSON(path, &spec) == nil {
			t.Fatal("invalid specification accepted")
		}
	}
}

func TestGenericContainmentDoesNotRequireShellRemovalWhenAppNeedsShell(t *testing.T) {
	probe := genericProbeEvidence{UID: 1000, GID: 0, ProtectedWrites: []genericWriteEvidence{{Path: "/", genericOperationEvidence: genericOperationEvidence{Status: "denied"}}}, LocalToolInstall: genericOperationEvidence{Status: "denied", Stage: "create_directory"}, Shells: []genericShellEvidence{{Status: "accessible"}}, WritablePaths: []genericWriteEvidence{{Path: "/tmp", genericOperationEvidence: genericOperationEvidence{Status: "allowed"}}}}
	if err := validateGenericContainment(probe, genericRuntimePolicy{User: "1000:0"}); err != nil {
		t.Fatal(err)
	}
	probe.LocalToolInstall.Stage = "execute_marker"
	if validateGenericContainment(probe, genericRuntimePolicy{User: "1000:0"}) == nil {
		t.Fatal("execution denial mistaken for installation-write denial")
	}
	probe.LocalToolInstall.Status = "allowed"
	if validateGenericContainment(probe, genericRuntimePolicy{User: "1000:0"}) == nil {
		t.Fatal("failed containment accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := filterRootfs(ctx, strings.NewReader(""), &strings.Builder{}, nil); err == nil {
		t.Fatal("cancellation ignored")
	}
}
