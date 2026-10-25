package imagehardening

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/genai"
	ai "google.golang.org/genai/interactions/models/interactions"
)

func staticAgentTestAnalysis() staticImageAnalysis {
	return staticImageAnalysis{
		SourceID: "sha256:" + strings.Repeat("a", 64), Architecture: "arm64", User: "65532:65532", UserChanged: true,
		PresentTools: []string{"/bin/sh", "/usr/bin/curl"}, EligibleRemovals: []string{"/bin/sh", "/usr/bin/curl"},
		DeclaredVolumes: []string{}, ExposedPorts: []string{"3000/tcp"}, Unknowns: []string{"Runtime behavior was not observed"},
	}
}

func staticAgentTestCall(id, name string, arguments map[string]any) ai.Step {
	return ai.NewStep(ai.FunctionCallStep{ID: id, Name: name, Arguments: arguments})
}

func staticAgentTestPlan(paths []string) [][]ai.Step {
	return [][]ai.Step{
		{staticAgentTestCall("inspect", "inspect_image_static", map[string]any{})},
		{staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": paths})},
		{staticAgentTestCall("apply", "apply_static_hardening", map[string]any{})},
	}
}

func TestStaticAgentUsesOrderedFormalToolsAndStopsAfterApplication(t *testing.T) {
	analysis := staticAgentTestAnalysis()
	policy := genericRuntimePolicy{User: "65532:65532", WritablePaths: []string{"/tmp"}, Network: "none"}
	plan := staticAgentTestPlan([]string{"/usr/bin/curl"})
	plan[0] = append([]ai.Step{ai.NewStep(ai.ThoughtStep{Signature: genai.Ptr("opaque-thought-signature")})}, plan[0]...)
	requests, applied := 0, 0
	request := func(_ context.Context, model, system string, history []ai.Step, tools []ai.Tool) ([]ai.Step, error) {
		if model != "gemini-4-argon" || !strings.Contains(system, "unverified static candidate") || !strings.Contains(system, "untrusted data") {
			t.Fatal("missing model or static-only scope")
		}
		if requests >= len(plan) {
			t.Fatal("requested another model interaction after application")
		}
		expected := []string{"inspect_image_static", "remove_unneeded_tools", "apply_static_hardening"}[requests]
		if len(tools) != 1 || tools[0].Function == nil || *tools[0].Function.Name != expected {
			t.Fatalf("wrong staged tool: %+v", tools)
		}
		if requests == 1 {
			if len(history) != 4 || history[1].ThoughtStep == nil || *history[1].ThoughtStep.Signature != "opaque-thought-signature" || history[2].FunctionCallStep.ID != "inspect" {
				t.Fatal("inspection history or thought signature was discarded")
			}
			result := history[3].FunctionResultStep
			if result == nil || result.CallID != "inspect" || result.IsError == nil || *result.IsError {
				t.Fatal("inspection is not a linked successful function result")
			}
			var observed struct {
				Analysis staticImageAnalysis  `json:"analysis"`
				Policy   genericRuntimePolicy `json:"fixed_runtime_policy"`
				Scope    string               `json:"scope"`
			}
			if err := json.Unmarshal([]byte(result.Result.ArrayOfFunctionResultSubcontent[0].TextContent.Text), &observed); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(observed.Analysis, analysis) || !reflect.DeepEqual(observed.Policy, policy) || !strings.Contains(observed.Scope, "not tested") {
				t.Fatal("inspection changed policy or claimed runtime validation")
			}
		}
		if requests == 2 {
			if len(history) != 6 || history[5].FunctionResultStep == nil || history[5].FunctionResultStep.CallID != "remove" {
				t.Fatal("selection result is not linked to its function call")
			}
			result := history[5].FunctionResultStep.Result.ArrayOfFunctionResultSubcontent[0].TextContent.Text
			if !strings.Contains(result, `"applied":false`) || !strings.Contains(result, `"compatibility_tested":false`) {
				t.Fatal("selection was presented as an applied or tested candidate")
			}
		}
		steps := plan[requests]
		requests++
		return steps, nil
	}
	evidence, err := runStaticAgentWith(context.Background(), "gemini-4-argon", analysis, policy, func(_ context.Context, paths []string) error {
		applied++
		if !reflect.DeepEqual(paths, []string{"/usr/bin/curl"}) {
			t.Fatalf("wrong callback paths: %q", paths)
		}
		paths[0] = "callback mutation must not alter evidence"
		return nil
	}, request)
	if err != nil || requests != 3 || applied != 1 || !evidence.Applied {
		t.Fatalf("evidence=%+v requests=%d applied=%d err=%v", evidence, requests, applied, err)
	}
	if !reflect.DeepEqual(evidence.ToolCalls, []string{"inspect_image_static", "remove_unneeded_tools", "apply_static_hardening"}) || !reflect.DeepEqual(evidence.SelectedTools, []string{"/usr/bin/curl"}) {
		t.Fatalf("wrong evidence: %+v", evidence)
	}
}

func TestStaticAgentAcceptsExplicitEmptyRemovalWithoutInventingWork(t *testing.T) {
	plan := staticAgentTestPlan([]string{})
	requests, applied := 0, 0
	evidence, err := runStaticAgentWith(context.Background(), "gemini-4-argon", staticAgentTestAnalysis(), genericRuntimePolicy{User: "1000:0", Network: "internal"}, func(_ context.Context, paths []string) error {
		applied++
		if paths == nil || len(paths) != 0 {
			t.Fatal("explicit empty selection was not preserved")
		}
		return nil
	}, func(context.Context, string, string, []ai.Step, []ai.Tool) ([]ai.Step, error) {
		steps := plan[requests]
		requests++
		return steps, nil
	})
	if err != nil || !evidence.Applied || applied != 1 || evidence.SelectedTools == nil || len(evidence.SelectedTools) != 0 {
		t.Fatalf("evidence=%+v applied=%d err=%v", evidence, applied, err)
	}
}

func TestStaticAgentRejectsUnsafeOrOutOfOrderCallsBeforeApplication(t *testing.T) {
	inspect := staticAgentTestCall("inspect", "inspect_image_static", map[string]any{})
	remove := staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": []string{"/usr/bin/curl"}})
	apply := staticAgentTestCall("apply", "apply_static_hardening", map[string]any{})
	tests := []struct {
		name string
		plan [][]ai.Step
	}{
		{"remove before inspect", [][]ai.Step{{remove}}},
		{"apply before inspect", [][]ai.Step{{apply}}},
		{"apply before selection", [][]ai.Step{{inspect}, {apply}}},
		{"arbitrary command", [][]ai.Step{{staticAgentTestCall("exec", "execute", map[string]any{"command": "PRIVATE-DATA"})}}},
		{"missing call id", [][]ai.Step{{staticAgentTestCall("", "inspect_image_static", map[string]any{})}}},
		{"reused call id", [][]ai.Step{{inspect}, {staticAgentTestCall("inspect", "remove_unneeded_tools", map[string]any{"remove_paths": []string{}})}}},
		{"inspection arguments", [][]ai.Step{{staticAgentTestCall("inspect", "inspect_image_static", map[string]any{"argv": "PRIVATE-DATA"})}}},
		{"missing array", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{})}}},
		{"null array", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": nil})}}},
		{"wrong case array key", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"REMOVE_PATHS": []string{}})}}},
		{"duplicate case array keys", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": []string{}, "REMOVE_PATHS": []string{}})}}},
		{"wrong array type", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": "/bin/sh"})}}},
		{"duplicate path", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": []string{"/bin/sh", "/bin/sh"}})}}},
		{"runtime path", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": []string{"/usr/local/bin/node"}})}}},
		{"ineligible fixed tool", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": []string{"/bin/bash"}})}}},
		{"traversal", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": []string{"/bin/../app/PRIVATE-DATA"}})}}},
		{"broaden policy during selection", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": []string{}, "network": "host"})}}},
		{"broaden policy during apply", [][]ai.Step{{inspect}, {remove}, {staticAgentTestCall("apply", "apply_static_hardening", map[string]any{"user": "0:0"})}}},
		{"batch skips reading inspection", [][]ai.Step{{inspect, remove}}},
		{"duplicate apply in batch", [][]ai.Step{{inspect}, {remove}, {apply, staticAgentTestCall("apply-again", "apply_static_hardening", map[string]any{})}}},
		{"oversized args", [][]ai.Step{{inspect}, {staticAgentTestCall("remove", "remove_unneeded_tools", map[string]any{"remove_paths": []string{strings.Repeat("PRIVATE-DATA", 8192)}})}}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			requests, applied := 0, 0
			evidence, err := runStaticAgentWith(context.Background(), "gemini-4-argon", staticAgentTestAnalysis(), genericRuntimePolicy{User: "65532:65532", Network: "none"}, func(context.Context, []string) error {
				applied++
				return nil
			}, func(context.Context, string, string, []ai.Step, []ai.Tool) ([]ai.Step, error) {
				if requests >= len(test.plan) {
					t.Fatal("invalid model output should fail closed")
				}
				steps := test.plan[requests]
				requests++
				return steps, nil
			})
			if err == nil || evidence.Applied || applied != 0 || strings.Contains(err.Error(), "PRIVATE-DATA") {
				t.Fatalf("evidence=%+v applied=%d err=%v", evidence, applied, err)
			}
		})
	}
}

func TestStaticAgentApplicationFailureIsNotSuccessOrRawOutput(t *testing.T) {
	plan, requests, applied := staticAgentTestPlan([]string{"/bin/sh"}), 0, 0
	evidence, err := runStaticAgentWith(context.Background(), "gemini-4-argon", staticAgentTestAnalysis(), genericRuntimePolicy{User: "65532:65532", Network: "none"}, func(context.Context, []string) error {
		applied++
		return errors.New("PRIVATE-DATA raw command output or credentials")
	}, func(context.Context, string, string, []ai.Step, []ai.Tool) ([]ai.Step, error) {
		if requests >= len(plan) {
			t.Fatal("callback failure must not be sent back to Argon")
		}
		steps := plan[requests]
		requests++
		return steps, nil
	})
	if err == nil || strings.Contains(err.Error(), "PRIVATE-DATA") || evidence.Applied || applied != 1 || requests != 3 {
		t.Fatalf("evidence=%+v requests=%d applied=%d err=%v", evidence, requests, applied, err)
	}
}

func TestStaticAgentBoundsEmptyThoughtOnlyAndOversizedResponses(t *testing.T) {
	for _, test := range []struct {
		name     string
		steps    []ai.Step
		requests int
	}{
		{"empty", nil, 1},
		{"thought only", []ai.Step{ai.NewStep(ai.ThoughtStep{Signature: genai.Ptr("signature")})}, 6},
		{"too many steps", make([]ai.Step, 33), 1},
		{"oversized", []ai.Step{argonUserInput(strings.Repeat("x", 256*1024))}, 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			requests := 0
			evidence, err := runStaticAgentWith(context.Background(), "gemini-4-argon", staticAgentTestAnalysis(), genericRuntimePolicy{User: "65532:65532", Network: "none"}, func(context.Context, []string) error {
				t.Fatal("must not apply without a valid protocol")
				return nil
			}, func(context.Context, string, string, []ai.Step, []ai.Tool) ([]ai.Step, error) {
				requests++
				if requests > 6 {
					t.Fatal("unbounded model loop")
				}
				return test.steps, nil
			})
			if err == nil || evidence.Applied || requests != test.requests {
				t.Fatalf("evidence=%+v requests=%d err=%v", evidence, requests, err)
			}
		})
	}
}

func TestStaticAgentPreflightRejectsInvalidInventoryOrPolicy(t *testing.T) {
	for _, test := range []struct {
		name   string
		change func(*staticImageAnalysis, *genericRuntimePolicy)
	}{
		{"non-tool inventory", func(a *staticImageAnalysis, _ *genericRuntimePolicy) { a.EligibleRemovals = []string{"/app/server"} }},
		{"duplicate inventory", func(a *staticImageAnalysis, _ *genericRuntimePolicy) {
			a.EligibleRemovals = []string{"/bin/sh", "/bin/sh"}
		}},
		{"required shell inventory", func(a *staticImageAnalysis, _ *genericRuntimePolicy) { a.ShellRequired = true }},
		{"root user", func(_ *staticImageAnalysis, p *genericRuntimePolicy) { p.User = "0:0" }},
		{"host network", func(_ *staticImageAnalysis, p *genericRuntimePolicy) { p.Network = "host" }},
		{"broad writable", func(_ *staticImageAnalysis, p *genericRuntimePolicy) { p.WritablePaths = []string{"/app"} }},
		{"oversized result", func(a *staticImageAnalysis, _ *genericRuntimePolicy) {
			a.Unknowns = []string{strings.Repeat("x", 64*1024)}
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			analysis, policy := staticAgentTestAnalysis(), genericRuntimePolicy{User: "65532:65532", Network: "none"}
			test.change(&analysis, &policy)
			evidence, err := runStaticAgentWith(context.Background(), "gemini-4-argon", analysis, policy, func(context.Context, []string) error {
				t.Fatal("invalid preflight reached apply")
				return nil
			}, func(context.Context, string, string, []ai.Step, []ai.Tool) ([]ai.Step, error) {
				t.Fatal("invalid preflight reached the model")
				return nil, nil
			})
			if err == nil || evidence.Applied {
				t.Fatalf("evidence=%+v err=%v", evidence, err)
			}
		})
	}
}

func TestStaticAgentCancellationAndRequestFailureDoNotApply(t *testing.T) {
	for _, cancelBefore := range []bool{true, false} {
		ctx, cancel := context.WithCancel(context.Background())
		if cancelBefore {
			cancel()
		}
		requests := 0
		plan := staticAgentTestPlan([]string{})
		evidence, err := runStaticAgentWith(ctx, "gemini-4-argon", staticAgentTestAnalysis(), genericRuntimePolicy{User: "65532:65532", Network: "none"}, func(context.Context, []string) error {
			t.Fatal("cancelled work must not apply")
			return nil
		}, func(context.Context, string, string, []ai.Step, []ai.Tool) ([]ai.Step, error) {
			steps := plan[requests]
			requests++
			if requests == 3 {
				cancel()
			}
			return steps, nil
		})
		cancel()
		if !errors.Is(err, context.Canceled) || evidence.Applied || (cancelBefore && requests != 0) {
			t.Fatalf("evidence=%+v requests=%d err=%v", evidence, requests, err)
		}
	}
	want := errors.New("Gemini tool request failed (HTTP 429)")
	evidence, err := runStaticAgentWith(context.Background(), "gemini-4-argon", staticAgentTestAnalysis(), genericRuntimePolicy{User: "65532:65532", Network: "none"}, func(context.Context, []string) error {
		t.Fatal("model failure must not fall back to applying tools")
		return nil
	}, func(context.Context, string, string, []ai.Step, []ai.Tool) ([]ai.Step, error) { return nil, want })
	if !errors.Is(err, want) || evidence.Applied {
		t.Fatalf("evidence=%+v err=%v", evidence, err)
	}
}

func TestStaticAgentSchemasOfferNoCommandOrPolicyArguments(t *testing.T) {
	tools := staticAgentTools()
	for index, tool := range tools {
		schema := tool.Function.Parameters.(map[string]any)
		properties := schema["properties"].(map[string]any)
		if schema["additionalProperties"] != false {
			t.Fatal("tool schema permits arbitrary fields")
		}
		if index == 1 {
			if len(properties) != 1 || properties["remove_paths"] == nil || !reflect.DeepEqual(schema["required"], []string{"remove_paths"}) {
				t.Fatal("removal tool exposes more than its required path array")
			}
		} else if len(properties) != 0 {
			t.Fatal("inspection/application tool exposes arguments")
		}
	}
}
