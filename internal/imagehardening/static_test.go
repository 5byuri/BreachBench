package imagehardening

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
)

func TestStaticCLIRequiresNoWorkloadAndDefaultsToArgon(t *testing.T) {
	var output strings.Builder
	called := false
	err := staticCLIWith([]string{"--image=local/app:before", "--target=local/app:after", "--artifacts=" + filepath.Join(t.TempDir(), "results"), "--format=human"}, &output,
		func(_ context.Context, config staticConfig) (*staticReport, error) {
			called = true
			if config.Mode != "argon" || config.Model != "gemini-4-argon" {
				t.Fatalf("unexpected config: %+v", config)
			}
			return &staticReport{Image: config.Target, CandidateCreated: true, Compatibility: "unverified", Policy: genericRuntimePolicy{User: "10001:10001"}}, nil
		})
	if err != nil || !called || !strings.Contains(output.String(), "NOT RUNTIME TESTED") || strings.Contains(output.String(), "PASS") {
		t.Fatalf("static output is misleading: %q, %v", output.String(), err)
	}
}

func TestStaticCLIRejectsBadInputBeforeTools(t *testing.T) {
	base := []string{"--image=local/app:before", "--target=local/app:after", "--artifacts=results"}
	for _, extra := range [][]string{{"..."}, {"--mode=invalid"}, {"--timeout=0"}, {"--format=xml"}, {"--checks=x"}, {"--target=local/app:before"}} {
		err := staticCLIWith(append(append([]string{}, base...), extra...), &strings.Builder{}, func(context.Context, staticConfig) (*staticReport, error) {
			t.Fatal("invalid CLI reached tools")
			return nil, nil
		})
		if err == nil {
			t.Fatalf("invalid arguments accepted: %v", extra)
		}
	}
}

func TestStaticFailureKeepsUnverifiedReport(t *testing.T) {
	var output strings.Builder
	err := staticCLIWith([]string{"--image=local/app:before", "--target=local/app:after", "--artifacts=results", "--format=json"}, &output,
		func(context.Context, staticConfig) (*staticReport, error) {
			return &staticReport{Compatibility: "unverified"}, errors.New("no candidate")
		})
	if err == nil || !strings.Contains(output.String(), `"application_tested":false`) || !strings.Contains(output.String(), `"candidate_created":false`) {
		t.Fatalf("failed static route claimed success: %q, %v", output.String(), err)
	}
}
