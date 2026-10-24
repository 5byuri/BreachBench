package imagehardening

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestToolAgentRequiresExplicitScopeBeforeTools(t *testing.T) {
	for _, config := range []toolAgentConfig{{}, {Trusted: true}} {
		if _, err := toolAgent(context.Background(), config); err == nil {
			t.Fatal("missing scope declaration accepted")
		}
	}
}

func TestToolUser(t *testing.T) {
	for _, value := range []string{"", "root", "0:1", "000:1", "1000:0", "-1:1", "1:1\nRUN bad", "4294967296:1"} {
		if toolUser(value) == nil {
			t.Fatalf("unsafe user accepted: %q", value)
		}
	}
	if err := toolUser("65532:65532"); err != nil {
		t.Fatal(err)
	}
}

func TestToolArgumentsRejectUnknownAndOversizedFields(t *testing.T) {
	var target struct {
		User string `json:"user"`
	}
	if decodeToolArguments(map[string]any{"user": "1000:1000", "command": "anything"}, &target) == nil {
		t.Fatal("unknown command accepted")
	}
	if decodeToolArguments(map[string]any{"user": strings.Repeat("x", 8193)}, &target) == nil {
		t.Fatal("oversized input accepted")
	}
	if err := decodeToolArguments(map[string]any{"user": "1000:1000"}, &target); err != nil {
		t.Fatal(err)
	}
}

func TestToolPolicyAndArtifacts(t *testing.T) {
	data, err := json.Marshal(toolCompose("candidate:test", "1000:1000"))
	if err != nil {
		t.Fatal(err)
	}
	var policy struct {
		Services map[string]struct {
			Image    string
			User     string
			ReadOnly bool     `json:"read_only"`
			Network  string   `json:"network_mode"`
			CapDrop  []string `json:"cap_drop"`
			Security []string `json:"security_opt"`
		}
	}
	if err := json.Unmarshal(data, &policy); err != nil {
		t.Fatal(err)
	}
	app := policy.Services["app"]
	if app.Image != "candidate:test" || app.User != "1000:1000" || !app.ReadOnly || app.Network != "none" || len(app.CapDrop) != 1 || app.CapDrop[0] != "ALL" || len(app.Security) != 1 || app.Security[0] != "no-new-privileges:true" {
		t.Fatalf("missing controls: %s", data)
	}
	path := filepath.Join(t.TempDir(), "report.json")
	if err := writeToolJSON(path, policy); err != nil {
		t.Fatal(err)
	}
	if err := writeToolJSON(path, policy); err == nil {
		t.Fatal("overwrote existing artifact")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatal("artifact must be private")
	}
}

func TestToolCLIRejectsUnsupportedInputBeforeExecution(t *testing.T) {
	for _, args := range [][]string{{"agent", "--timeout=0"}, {"agent", "unexpected"}, {"tool-demo", "--image=production", "--artifacts=x"}, {"agent", "--scripted"}, {"agent", "--demo-engine=docker"}, {"tool-demo", "--demo-engine=docker"}} {
		if toolCLI(args, &strings.Builder{}) == nil {
			t.Fatalf("invalid input accepted: %v", args)
		}
	}
}

func TestScriptedDemoIsFixedAndNeverPretendsToBeModelOutput(t *testing.T) {
	for i, name := range []string{"inspect_image", "minimize_image", "validate_candidate"} {
		call := scriptedDemoStep(i).FunctionCallStep
		if call == nil || call.Name != name || !strings.HasPrefix(call.ID, "scripted-") {
			t.Fatal("unexpected scripted command")
		}
	}
	if _, err := toolAgent(context.Background(), toolAgentConfig{DemoDocker: true}); err == nil {
		t.Fatal("fixture build allowed outside explicit scripted scope")
	}
}

func TestToolComparisonUsesMeasuredEvidence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "comparison.md")
	if err := writeToolComparison(path, toolPassingReport()); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, required := range []string{"| Effective UID | 0 | 65532 |", "denied (EROFS)", "Unavailable at all six tested paths", "not a remote exploit"} {
		if !strings.Contains(string(data), required) {
			t.Fatalf("missing measured detail %q", required)
		}
	}
}
