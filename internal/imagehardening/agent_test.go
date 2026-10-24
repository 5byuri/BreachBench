package imagehardening

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParsePlan(t *testing.T) {
	for _, input := range []string{`{}`, `not JSON`, `{"containerfile":""}`, `{"containerfile":"RUN echo hacked"}`} {
		if _, err := parsePlan(input); err == nil {
			t.Fatalf("accepted invalid plan %s", input)
		}
	}
	plan, err := parsePlan(`{"containerfile":"FROM node:24\nUSER 65532:65532\n","changes":["non-root"],"limitations":[]}`)
	if err != nil || len(plan.Changes) != 1 {
		t.Fatalf("valid plan: %v", err)
	}
}

func TestGeminiDoesNotOverwrite(t *testing.T) {
	dir := t.TempDir()
	output := filepath.Join(dir, "candidate")
	if err := os.WriteFile(output, []byte("keep"), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := geminiHarden(context.Background(), "gemini-4-argon", "missing", output, "", ".")
	if err == nil {
		t.Fatal("existing output accepted")
	}
	data, _ := os.ReadFile(output)
	if string(data) != "keep" {
		t.Fatal("output changed")
	}
}

func TestMissingGeminiKey(t *testing.T) {
	_, err := resolveGeminiKey("", func() ([]byte, error) { return nil, os.ErrNotExist })
	if err == nil || !strings.Contains(err.Error(), "GEMINI_API_KEY") {
		t.Fatalf("expected key error, got %v", err)
	}
}

func TestGeminiKeyEnvironmentPrecedesKeychain(t *testing.T) {
	key, err := resolveGeminiKey(" fake-environment-key ", func() ([]byte, error) {
		t.Fatal("environment key must not access Keychain")
		return nil, nil
	})
	if err != nil || key != "fake-environment-key" {
		t.Fatal("environment key was not preferred")
	}
}

func TestGeminiKeychainFallback(t *testing.T) {
	key, err := resolveGeminiKey("", func() ([]byte, error) { return []byte("fake-keychain-key\n"), nil })
	if err != nil || key != "fake-keychain-key" {
		t.Fatal("Keychain key was not loaded")
	}
	for _, data := range [][]byte{nil, []byte("  \n")} {
		if _, err := resolveGeminiKey("", func() ([]byte, error) { return data, nil }); err == nil {
			t.Fatal("empty Keychain key accepted")
		}
	}
	if _, err := resolveGeminiKey("", func() ([]byte, error) { return []byte("fake-secret"), os.ErrPermission }); err == nil || strings.Contains(err.Error(), "fake-secret") {
		t.Fatal("Keychain failure accepted or exposed its output")
	}
}

type geminiTestTransport func(*http.Request) (*http.Response, error)

func (f geminiTestTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func mockGeminiHTTP(t *testing.T, fn geminiTestTransport) {
	t.Helper()
	previous := http.DefaultTransport
	http.DefaultTransport = fn
	t.Cleanup(func() { http.DefaultTransport = previous })
}

func geminiTestResponse(r *http.Request, status int, body string) *http.Response {
	return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: r}
}

func TestRequestHardeningUsesSDKInteractions(t *testing.T) {
	const fakeKey = "fake-gemini-key-for-local-test"
	const source = "FROM node:24\nCOPY app.js /app/app.js\n"
	t.Setenv("GEMINI_API_KEY", fakeKey)
	wanted := hardeningPlan{Containerfile: "FROM node:24\nUSER 65532:65532\n", Changes: []string{"non-root"}, Limitations: []string{"application still needs testing"}}
	planJSON, err := json.Marshal(wanted)
	if err != nil {
		t.Fatal(err)
	}
	responseJSON, err := json.Marshal(map[string]any{
		"id": "local-interaction", "status": "completed",
		"steps": []any{map[string]any{"type": "model_output", "content": []any{map[string]any{"type": "text", "text": string(planJSON)}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	mockGeminiHTTP(t, func(r *http.Request) (*http.Response, error) {
		calls++
		if r.Method != http.MethodPost || r.URL.Host != "generativelanguage.googleapis.com" || !strings.HasSuffix(r.URL.Path, "/interactions") {
			t.Errorf("unexpected SDK endpoint: %s %s", r.Method, r.URL.Redacted())
		}
		data, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		if strings.Contains(string(data), fakeKey) {
			t.Error("API key leaked into request body")
		}
		var body struct {
			Model          string `json:"model"`
			Store          *bool  `json:"store"`
			Input          string `json:"input"`
			ResponseFormat struct {
				Type     string `json:"type"`
				MimeType string `json:"mime_type"`
				Schema   struct {
					Type       string                     `json:"type"`
					Properties map[string]json.RawMessage `json:"properties"`
					Required   []string                   `json:"required"`
				} `json:"schema"`
			} `json:"response_format"`
		}
		if err := json.Unmarshal(data, &body); err != nil {
			t.Errorf("invalid SDK request JSON: %v", err)
		}
		if body.Model != "gemini-4-argon" || body.Store == nil || *body.Store {
			t.Error("model or explicit store:false missing")
		}
		if !strings.Contains(body.Input, source) || !strings.Contains(body.Input, "<containerfile>") {
			t.Error("source Containerfile missing from untrusted input")
		}
		format := body.ResponseFormat
		if format.Type != "text" || format.MimeType != "application/json" || format.Schema.Type != "object" || len(format.Schema.Required) != 3 {
			t.Error("structured JSON response schema missing")
		}
		for _, field := range []string{"containerfile", "changes", "limitations"} {
			if _, ok := format.Schema.Properties[field]; !ok {
				t.Errorf("response schema missing %s", field)
			}
		}
		return geminiTestResponse(r, http.StatusOK, string(responseJSON)), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	got, err := requestHardening(ctx, "gemini-4-argon", source)
	if err != nil {
		t.Fatal(err)
	}
	if calls != 1 || got.Containerfile != wanted.Containerfile || len(got.Changes) != 1 || got.Changes[0] != wanted.Changes[0] || len(got.Limitations) != 1 || got.Limitations[0] != wanted.Limitations[0] {
		t.Fatalf("unexpected SDK result: calls=%d plan=%+v", calls, got)
	}
}

func TestRequestHardeningRedactsRemoteError(t *testing.T) {
	const fakeKey = "fake-secret-that-must-not-appear"
	t.Setenv("GEMINI_API_KEY", fakeKey)
	calls := 0
	mockGeminiHTTP(t, func(r *http.Request) (*http.Response, error) {
		calls++
		return geminiTestResponse(r, http.StatusForbidden, `{"error":{"code":403,"message":"denied key `+fakeKey+`","status":"PERMISSION_DENIED"}}`), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	_, err := requestHardening(ctx, "gemini-4-argon", "FROM node:24")
	if calls != 1 || err == nil || strings.Contains(err.Error(), fakeKey) || !strings.Contains(err.Error(), "Gemini request failed") {
		t.Fatalf("remote error not safely redacted: calls=%d error=%v", calls, err)
	}
}

func TestRequestHardeningRejectsIncompleteResponse(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "fake-unused-key")
	mockGeminiHTTP(t, func(r *http.Request) (*http.Response, error) {
		return geminiTestResponse(r, http.StatusOK, `{"id":"local-incomplete","status":"incomplete","steps":[{"type":"model_output","content":[{"type":"text","text":"{\"containerfile\":\"FROM node:24\"}"}]}]}`), nil
	})
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := requestHardening(ctx, "gemini-4-argon", "FROM node:24"); err == nil {
		t.Fatal("accepted an incomplete model response")
	}
}

func TestGeminiCompositeValidatesBeforeIO(t *testing.T) {
	t.Setenv("GEMINI_API_KEY", "fake-unused-key")
	t.Setenv("PATH", t.TempDir())
	mockGeminiHTTP(t, func(r *http.Request) (*http.Response, error) {
		t.Error("validation made an unexpected API request")
		return geminiTestResponse(r, http.StatusForbidden, `{}`), nil
	})
	for _, tc := range []struct {
		name, app, target, want string
	}{
		{"missing target", `["node","/app/test.js"]`, "", "--baseline requires --target"},
		{"missing app", "", "app:new", "--app-command-json"},
		{"invalid JSON", "not JSON", "app:new", "--app-command-json"},
		{"empty argv", "[]", "app:new", "--app-command-json"},
		{"null argument", `["node",null]`, "app:new", "must all be strings"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			output := filepath.Join(dir, "candidate")
			args := []string{"gemini", "--baseline", "app:before", "--file", filepath.Join(dir, "missing-source"), "--output", output, "--app-command-json", tc.app}
			if tc.target != "" {
				args = append(args, "--target", tc.target)
			}
			if err := agentCLI(args, io.Discard); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("expected validation before file/Docker/API access, got %v", err)
			}
			if _, err := os.Stat(output); !os.IsNotExist(err) {
				t.Fatal("validation created a candidate output")
			}
		})
	}
}
