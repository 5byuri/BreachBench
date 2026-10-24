package imagehardening

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"runtime"

	"google.golang.org/genai"
	"google.golang.org/genai/interactions/models/apierrors"
	ai "google.golang.org/genai/interactions/models/interactions"
	"google.golang.org/genai/interactions/models/operations"
)

func newGeminiClient(ctx context.Context) (*genai.Client, error) {
	key, err := resolveGeminiKey(os.Getenv("GEMINI_API_KEY"), func() ([]byte, error) {
		if runtime.GOOS != "darwin" {
			return nil, os.ErrNotExist
		}
		return exec.CommandContext(ctx, "/usr/bin/security", "find-generic-password", "-a", "GEMINI_API_KEY", "-s", "container-hardening-work-bench.gemini", "-w").Output()
	})
	if err != nil {
		return nil, err
	}
	client, err := genai.NewClient(ctx, &genai.ClientConfig{APIKey: key, Backend: genai.BackendGeminiAPI})
	if err != nil {
		return nil, errors.New("could not initialize Gemini client")
	}
	return client, nil
}

// The caller retains every returned step, including thought signatures, before
// appending function results and requesting the next stateless interaction.
func requestArgonTools(ctx context.Context, model, system string, history []ai.Step, tools []ai.Tool) ([]ai.Step, error) {
	if len(history) == 0 || len(history) > 128 || len(tools) == 0 || len(tools) > 16 {
		return nil, errors.New("invalid or oversized Argon tool conversation")
	}
	body := operations.NewCreateInteractionRequestBody(ai.CreateModelInteraction{
		Model: ai.Model(model), Store: genai.Ptr(false),
		Input: genai.Ptr(ai.NewInteractionsInput(history)), SystemInstruction: genai.Ptr(system),
		Tools: tools,
		GenerationConfig: &ai.GenerationConfig{
			MaxOutputTokens: genai.Ptr(4096), ToolChoice: genai.Ptr(ai.NewToolChoice(ai.ToolChoiceTypeAny)),
		},
	})
	encoded, err := json.Marshal(body)
	if err != nil || len(encoded) > 1024*1024 {
		return nil, errors.New("invalid or oversized Argon tool request")
	}
	client, err := newGeminiClient(ctx)
	if err != nil {
		return nil, err
	}
	response, err := client.Interactions.Create(ctx, operations.CreateInteractionRequest{Body: body})
	if err != nil {
		// SDK errors can echo request bodies or credentials.
		var apiError *apierrors.APIError
		var clientError *apierrors.CreateInteractionClientError
		var serverError *apierrors.CreateInteractionServerError
		var networkError net.Error
		switch {
		case errors.As(err, &apiError):
			return nil, fmt.Errorf("Gemini tool request failed (HTTP %d); check model access, quota and request compatibility", apiError.StatusCode)
		case errors.As(err, &clientError) && clientError.HTTPMeta.Response != nil:
			return nil, fmt.Errorf("Gemini tool request failed (HTTP %d); check model access, quota and request compatibility", clientError.HTTPMeta.Response.StatusCode)
		case errors.As(err, &serverError) && serverError.HTTPMeta.Response != nil:
			return nil, fmt.Errorf("Gemini tool request failed (HTTP %d); provider error", serverError.HTTPMeta.Response.StatusCode)
		case errors.As(err, &networkError) && networkError.Timeout():
			return nil, errors.New("Gemini tool request timed out")
		default:
			return nil, errors.New("Gemini tool request failed; check API key, model access, quota and network")
		}
	}
	if response == nil || response.Interaction == nil {
		return nil, errors.New("Gemini returned no tool interaction")
	}
	interaction := response.Interaction
	if interaction.Status != ai.InteractionStatusCompleted && interaction.Status != ai.InteractionStatusRequiresAction {
		return nil, errors.New("Gemini tool interaction did not complete")
	}
	encoded, err = json.Marshal(interaction.Steps)
	if err != nil || len(interaction.Steps) == 0 || len(interaction.Steps) > 32 || len(encoded) > 256*1024 {
		return nil, errors.New("Gemini returned empty, invalid or oversized tool steps")
	}
	return interaction.Steps, nil
}

func argonUserInput(text string) ai.Step {
	return ai.NewStep(ai.UserInputStep{Content: []ai.Content{ai.NewContent(ai.TextContent{Text: text})}})
}

func argonToolResult(call ai.FunctionCallStep, result any, isError bool) (ai.Step, error) {
	if call.ID == "" || call.Name == "" {
		return ai.Step{}, errors.New("Gemini tool call is missing its name or ID")
	}
	data, err := json.Marshal(result)
	if err != nil || len(data) > 64*1024 {
		return ai.Step{}, errors.New("invalid or oversized local tool result")
	}
	return ai.NewStep(ai.FunctionResultStep{
		CallID: call.ID, Name: genai.Ptr(call.Name), IsError: genai.Ptr(isError),
		Result: ai.NewFunctionResultStepResultUnion([]ai.FunctionResultSubcontent{
			ai.NewFunctionResultSubcontent(ai.TextContent{Text: string(data)}),
		}),
	}), nil
}
