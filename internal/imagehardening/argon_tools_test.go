package imagehardening

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/genai"
	ai "google.golang.org/genai/interactions/models/interactions"
)

func argonTestTools() []ai.Tool {
	return []ai.Tool{ai.NewTool(ai.Function{Name: genai.Ptr("inspect_image"), Parameters: map[string]any{"type": "object", "properties": map[string]any{}}})}
}

func TestArgonToolStatelessHistory(t *testing.T) {
	const fakeKey = "fake-argon-tool-test-key"
	t.Setenv("GEMINI_API_KEY", fakeKey)
	requests := 0
	mockGeminiHTTP(t, func(r *http.Request) (*http.Response, error) {
		requests++
		if r.Method != http.MethodPost || r.URL.Host != "generativelanguage.googleapis.com" || !strings.HasSuffix(r.URL.Path, "/interactions") {
			t.Fatalf("unexpected tool endpoint: %s %s", r.Method, r.URL.Redacted())
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(data), fakeKey) {
			t.Fatal("API key leaked into body")
		}
		var body struct {
			Model               string    `json:"model"`
			Store               *bool     `json:"store"`
			Input               []ai.Step `json:"input"`
			Tools               []ai.Tool `json:"tools"`
			PreviousInteraction string    `json:"previous_interaction_id"`
			System              string    `json:"system_instruction"`
			Config              struct {
				MaxTokens int    `json:"max_output_tokens"`
				Choice    string `json:"tool_choice"`
			} `json:"generation_config"`
		}
		if err := json.Unmarshal(data, &body); err != nil {
			t.Fatal(err)
		}
		if body.Model != "gemini-4-argon" || body.Store == nil || *body.Store || body.PreviousInteraction != "" || body.System != "Only constrained tools." {
			t.Fatal("missing stateless model/system settings")
		}
		if body.Config.MaxTokens != 4096 || body.Config.Choice != "any" || len(body.Tools) != 1 || body.Tools[0].Function == nil || *body.Tools[0].Function.Name != "inspect_image" {
			t.Fatal("missing bounded real function declaration")
		}
		if len(body.Input) == 0 || body.Input[0].UserInputStep == nil || body.Input[0].UserInputStep.Content[0].TextContent.Text != "Harden the public fixture." {
			t.Fatal("initial user input not preserved")
		}
		if requests == 1 {
			return geminiTestResponse(r, 200, `{"id":"turn1","status":"requires_action","steps":[{"type":"thought","signature":"opaque-server-signature"},{"type":"function_call","id":"call1","name":"inspect_image","arguments":{}}]}`), nil
		}
		if len(body.Input) != 4 || body.Input[1].ThoughtStep == nil || *body.Input[1].ThoughtStep.Signature != "opaque-server-signature" || body.Input[2].FunctionCallStep == nil || body.Input[2].FunctionCallStep.ID != "call1" {
			t.Fatal("model history or thought signature was discarded")
		}
		result := body.Input[3].FunctionResultStep
		if result == nil || result.CallID != "call1" || result.Name == nil || *result.Name != "inspect_image" || result.IsError == nil || *result.IsError {
			t.Fatal("formal function result not linked to call")
		}
		if got := result.Result.ArrayOfFunctionResultSubcontent[0].TextContent.Text; got != `{"shell_present":true}` {
			t.Fatalf("wrong tool result: %s", got)
		}
		return geminiTestResponse(r, 200, `{"id":"turn2","status":"completed","steps":[{"type":"function_call","id":"call2","name":"inspect_image","arguments":{}}]}`), nil
	})
	history := []ai.Step{argonUserInput("Harden the public fixture.")}
	steps, err := requestArgonTools(context.Background(), "gemini-4-argon", "Only constrained tools.", history, argonTestTools())
	if err != nil || len(steps) != 2 || steps[1].FunctionCallStep == nil {
		t.Fatalf("first tool call: %v", err)
	}
	history = append(history, steps...)
	result, err := argonToolResult(*steps[1].FunctionCallStep, map[string]bool{"shell_present": true}, false)
	if err != nil {
		t.Fatal(err)
	}
	history = append(history, result)
	if _, err := requestArgonTools(context.Background(), "gemini-4-argon", "Only constrained tools.", history, argonTestTools()); err != nil || requests != 2 {
		t.Fatalf("next tool call: %v", err)
	}
}

func TestArgonToolFailuresDoNotEchoSDKDetails(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "fake-tool-key")
	for _, tc := range []struct {
		name string
		body string
		err  error
	}{
		{name: "transport", err: errors.New("private-image-metadata fake-tool-key")},
		{name: "failed", body: `{"status":"failed","error":{"message":"private-image-metadata fake-tool-key"}}`},
		{name: "empty", body: `{"status":"completed","steps":[]}`},
		{name: "incomplete", body: `{"status":"incomplete","steps":[{"type":"function_call","id":"partial","name":"inspect_image","arguments":{}}]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			mockGeminiHTTP(t, func(r *http.Request) (*http.Response, error) {
				if tc.err != nil {
					return nil, tc.err
				}
				return geminiTestResponse(r, 200, tc.body), nil
			})
			_, err := requestArgonTools(context.Background(), "gemini-4-argon", "tools", []ai.Step{argonUserInput("public")}, argonTestTools())
			if err == nil || strings.Contains(err.Error(), "private-image-metadata") || strings.Contains(err.Error(), "fake-tool-key") {
				t.Fatalf("unsafe failure: %v", err)
			}
		})
	}
}

func TestArgonToolConversationBounds(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "fake-tool-key")
	mockGeminiHTTP(t, func(r *http.Request) (*http.Response, error) {
		t.Fatal("invalid input reached Gemini")
		return nil, errors.New("unexpected request")
	})
	for _, history := range [][]ai.Step{nil, make([]ai.Step, 129), {argonUserInput(strings.Repeat("x", 1024*1024))}} {
		if _, err := requestArgonTools(context.Background(), "gemini-4-argon", "tools", history, argonTestTools()); err == nil {
			t.Fatal("invalid conversation accepted")
		}
	}
	if _, err := requestArgonTools(context.Background(), "gemini-4-argon", "tools", []ai.Step{argonUserInput("public")}, nil); err == nil {
		t.Fatal("missing tools accepted")
	}
}

func TestArgonToolResultValidation(t *testing.T) {
	for _, call := range []ai.FunctionCallStep{{}, {ID: "id"}, {Name: "inspect_image"}} {
		if _, err := argonToolResult(call, nil, true); err == nil {
			t.Fatal("unlinked result accepted")
		}
	}
	call := ai.FunctionCallStep{ID: "id", Name: "inspect_image"}
	for _, result := range []any{make(chan int), strings.Repeat("x", 64*1024)} {
		if _, err := argonToolResult(call, result, false); err == nil {
			t.Fatal("invalid result accepted")
		}
	}
	step, err := argonToolResult(call, map[string]string{"error": "tool unavailable"}, true)
	if err != nil || step.FunctionResultStep.IsError == nil || !*step.FunctionResultStep.IsError {
		t.Fatal("error result flag missing")
	}
}
