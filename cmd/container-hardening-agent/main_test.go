package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestStandaloneHelpDoesNotRequireDockerOrCredentials(t *testing.T) {
	for _, args := range [][]string{nil, {"--help"}, {"harden"}, {"harden", "--help"}} {
		var output bytes.Buffer
		if err := run(args, &output); err != nil || !strings.Contains(output.String(), "container-hardening-agent") || !strings.Contains(output.String(), "auto, agent") {
			t.Fatalf("help missing: %s %v", output.String(), err)
		}
	}
}

func TestStandaloneRoutesBothCompatibilityForms(t *testing.T) {
	for _, args := range [][]string{{"auto"}, {"harden", "auto"}} {
		var output bytes.Buffer
		if err := run(args, &output); err == nil || !strings.Contains(err.Error(), "--checks is required") {
			t.Fatalf("command did not reach image engine: %v", err)
		}
	}
	if err := run([]string{"unknown"}, &bytes.Buffer{}); err == nil || !strings.Contains(err.Error(), "unknown harden command") {
		t.Fatalf("unsupported command did not fail: %v", err)
	}
}
