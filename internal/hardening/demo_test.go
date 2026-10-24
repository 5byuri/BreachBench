package hardening

import (
	"archive/tar"
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestInventoryDoesNotConfusePackageMetadataWithExecutables(t *testing.T) {
	for _, file := range []struct {
		kind      byte
		mode      int64
		wantError bool
	}{
		{tar.TypeDir, 0755, false}, {tar.TypeReg, 0644, false},
		{tar.TypeReg, 0755, true}, {tar.TypeSymlink, 0777, true}, {tar.TypeLink, 0644, true},
	} {
		var data bytes.Buffer
		w := tar.NewWriter(&data)
		if err := w.WriteHeader(&tar.Header{Name: "etc/dpkg", Typeflag: file.kind, Mode: file.mode}); err != nil {
			t.Fatal(err)
		}
		if err := w.Close(); err != nil {
			t.Fatal(err)
		}
		if err := checkArchive(&data); (err != nil) != file.wantError {
			t.Fatalf("kind %d mode %o: %v", file.kind, file.mode, err)
		}
	}
}

func demoExpected() (map[string]DemoObservation, map[string]DemoObservation) {
	before, after := map[string]DemoObservation{}, map[string]DemoObservation{}
	for _, name := range demoCases {
		before[name] = DemoObservation{Succeeded: true}
		after[name] = before[name]
	}
	after["shell"] = DemoObservation{Error: "ENOENT"}
	after["app_write"] = DemoObservation{Error: "EROFS"}
	after["root_write"] = DemoObservation{Error: "EROFS"}
	after["egress"] = DemoObservation{Error: "ENETUNREACH"}
	return before, after
}

func TestDemoRejectsMissingEvidenceAndWrongFailureReasons(t *testing.T) {
	before, after := demoExpected()
	if _, err := evaluateDemo(before, after); err != nil {
		t.Fatal(err)
	}
	for _, name := range demoCases {
		t.Run(name, func(t *testing.T) {
			before, after := demoExpected()
			delete(after, name)
			if _, err := evaluateDemo(before, after); err == nil {
				t.Fatal("missing evidence accepted")
			}
			before, after = demoExpected()
			after[name] = DemoObservation{Error: "unexpected response"}
			if _, err := evaluateDemo(before, after); err == nil {
				t.Fatal("unrelated failure accepted")
			}
			before, after = demoExpected()
			before[name] = DemoObservation{Error: "ENOENT"}
			if _, err := evaluateDemo(before, after); err == nil {
				t.Fatal("failed positive control accepted")
			}
		})
	}
}

func TestDemoFailureWritesHonestReportAndPreservesExistingOutput(t *testing.T) {
	// An empty executable search path forces preflight failure without using Docker.
	t.Setenv("PATH", t.TempDir())
	out := filepath.Join(t.TempDir(), "demo")
	if err := Demo(context.Background(), out, io.Discard); err == nil {
		t.Fatal("missing Docker accepted")
	}
	var r DemoResult
	if err := readJSON(filepath.Join(out, "results.json"), &r, true); err != nil {
		t.Fatal(err)
	}
	if r.Passed || r.Completed || r.Phase != "docker-preflight" || r.Error == "" || len(r.After) != 0 {
		t.Fatalf("misleading evidence: %+v", r)
	}
	if _, err := ReadBundle(filepath.Join(out, "hardened")); err != nil {
		t.Fatal(err)
	}
	html, err := os.ReadFile(filepath.Join(out, "report.html"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(html), "NOT PROVEN") || !strings.Contains(string(html), "Not run") {
		t.Fatal("misleading report")
	}
	old, err := os.ReadFile(filepath.Join(out, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := Demo(context.Background(), out, io.Discard); err == nil {
		t.Fatal("overwrote results")
	}
	newData, err := os.ReadFile(filepath.Join(out, "results.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(old) != string(newData) {
		t.Fatal("existing results changed")
	}
}

func TestRuntimeArgsWithoutDiagnosticMountRetainControls(t *testing.T) {
	_, c := fixture(t, "node")
	args := RuntimeArgs("/bundle", c, "image", "")
	if slices.Contains(args, "--mount") {
		t.Fatal("unexpected probe mount")
	}
	for _, required := range []string{"--read-only", "none", "65532:65532", "ALL", "no-new-privileges:true", "seccomp=/bundle/seccomp.json"} {
		if !slices.Contains(args, required) {
			t.Fatalf("missing %s", required)
		}
	}
	withProbe := RuntimeArgs("/bundle", c, "image", "/probe")
	if !slices.Contains(withProbe, "type=bind,source=/probe,target=/.__breachbench_probe,readonly") {
		t.Fatal("verification probe mount missing")
	}
}
