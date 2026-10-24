package imagehardening

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func humanReportFixture() *genericReport {
	hash := strings.Repeat("a", 64)
	workload := func() *workloadEvidence {
		return &workloadEvidence{Mode: "http", Status: "passed", HTTP: []workloadHTTPResult{{Path: "/health", Status: 200, BodySHA256: hash, Passed: true}}}
	}
	probe := func(uid uint32, hardened bool) *genericProbeEvidence {
		result := &genericProbeEvidence{Version: "generic-containment-v1", UID: uid, GID: uid, LocalToolInstall: genericOperationEvidence{Status: "allowed", Stage: "execute_marker"}}
		writeStatus, shellStatus := "allowed", "accessible"
		if hardened {
			writeStatus, shellStatus = "denied", "unavailable"
			result.LocalToolInstall = genericOperationEvidence{Status: "denied", Stage: "create_directory", ErrorCode: "EROFS"}
		}
		for _, path := range []string{"/", "/usr", "/etc"} {
			operation := genericOperationEvidence{Status: writeStatus}
			if hardened {
				operation.ErrorCode = "EROFS"
			}
			result.ProtectedWrites = append(result.ProtectedWrites, genericWriteEvidence{Path: path, genericOperationEvidence: operation})
		}
		for range 13 {
			result.Shells = append(result.Shells, genericShellEvidence{Status: shellStatus})
		}
		return result
	}
	return &genericReport{
		Mode: "argon", Source: "local/app:before", Image: "local/app:hardened", Completed: true,
		Policy:           genericRuntimePolicy{User: "65532:65532", Network: "internal"},
		BaselineWorkload: workload(), CandidateWorkload: workload(), BaselineProbe: probe(0, false), CandidateProbe: probe(65532, true),
		Attempts: []genericAttempt{{Removed: []string{"requested", "not-necessarily-present", "other"}, Rebuild: &imageRebuildEvidence{RemovedEntries: []string{"/usr/bin/curl", "/bin/sh"}, RetainedEntries: 100, RootfsSHA256: hash}}},
	}
}

func TestGenericHumanShowsEvidenceAndActualFinalRemovalCount(t *testing.T) {
	report := humanReportFixture()
	before, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	config := genericConfig{Mode: "argon", Model: "gemini-4-argon", Image: report.Source, Target: report.Image, Artifacts: "/tmp/example-results"}
	if err := writeGenericHumanHeader(&output, config); err != nil {
		t.Fatal(err)
	}
	if err := writeGenericHuman(&output, config, report, nil); err != nil {
		t.Fatal(err)
	}
	text := output.String()
	for _, wanted := range []string{"BreachBench", "argon / gemini-4-argon", "Result: PASS", "BEFORE", "AFTER", "1 HTTP checks passed", "65532:65532", "3 allowed / 0 denied", "0 allowed / 3 denied", "13 / 13", "0 / 13", "OBSERVED", "Copied unchanged", "NOT TESTED", "Actual tool entries removed in final candidate: 2", "/tmp/example-results/report.json", "/tmp/example-results/compose.json"} {
		if !strings.Contains(text, wanted) {
			t.Errorf("human report is missing %q:\n%s", wanted, text)
		}
	}
	after, err := json.Marshal(report)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("presentation mutated the machine report")
	}
	if strings.Contains(text, `"source":`) || strings.Contains(text, "Actual tool entries removed in final candidate: 3") {
		t.Fatal("human report dumped JSON or counted selected rather than removed entries")
	}
}

func TestGenericHumanCannotGreenwashMissingOrFailedEvidence(t *testing.T) {
	for _, test := range []struct {
		name string
		edit func(*genericReport)
		want string
	}{
		{"not completed", func(r *genericReport) { r.Completed = false }, "INCOMPLETE"},
		{"baseline missing", func(r *genericReport) { r.BaselineWorkload = nil }, "INCOMPLETE"},
		{"candidate missing", func(r *genericReport) { r.CandidateProbe = nil }, "INCOMPLETE"},
		{"HTTP assertions missing", func(r *genericReport) { r.CandidateWorkload.HTTP = nil }, "INCOMPLETE"},
		{"HTTP status missing", func(r *genericReport) { r.CandidateWorkload.HTTP[0].Status = 0 }, "INCOMPLETE"},
		{"HTTP assertion failed", func(r *genericReport) { r.CandidateWorkload.Status = "failed" }, "FAILED"},
		{"candidate root", func(r *genericReport) { r.CandidateProbe.UID = 0 }, "FAILED"},
		{"write allowed", func(r *genericReport) { r.CandidateProbe.ProtectedWrites[0].Status = "allowed" }, "FAILED"},
		{"write denial incomplete", func(r *genericReport) { r.CandidateProbe.ProtectedWrites[0].ErrorCode = "" }, "INCOMPLETE"},
		{"shell evidence missing", func(r *genericReport) { r.CandidateProbe.Shells = nil }, "INCOMPLETE"},
		{"shell evidence inconclusive", func(r *genericReport) { r.CandidateProbe.Shells[0].Status = "inconclusive" }, "INCOMPLETE"},
		{"only execution denied", func(r *genericReport) { r.CandidateProbe.LocalToolInstall.Stage = "execute_marker" }, "INCOMPLETE"},
		{"install allowed", func(r *genericReport) { r.CandidateProbe.LocalToolInstall.Status = "allowed" }, "FAILED"},
		{"missing repack evidence", func(r *genericReport) { r.Attempts[0].Rebuild = nil }, "INCOMPLETE"},
		{"runtime modified", func(r *genericReport) { r.Attempts[0].Rebuild.ApplicationFilesModified = true }, "FAILED"},
		{"report failure", func(r *genericReport) { r.Error = "cannot save evidence" }, "FAILED"},
	} {
		t.Run(test.name, func(t *testing.T) {
			report := humanReportFixture()
			test.edit(report)
			var output bytes.Buffer
			if err := writeGenericHuman(&output, genericConfig{}, report, nil); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(output.String(), "Result: "+test.want) || strings.Contains(output.String(), "Validated image:") {
				t.Fatalf("invalid evidence greenwashed:\n%s", output.String())
			}
		})
	}
	for _, runErr := range []error{nil, errors.New("failed before image inspection")} {
		var output bytes.Buffer
		if err := writeGenericHuman(&output, genericConfig{}, nil, runErr); err != nil || strings.Contains(output.String(), "Result: PASS") {
			t.Fatalf("nil evidence passed: %s %v", output.String(), err)
		}
	}
}

func TestGenericHumanSanitizesTerminalControlsAndDoesNotClaimEgressTest(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	report := humanReportFixture()
	report.Policy.Network = "bridge"
	report.Image = "evil\x1b]0;title\a\n\r\t\u202eimage"
	config := genericConfig{Mode: "argon", Model: "model\x1b[31m\u202e", Image: report.Image, Target: report.Image}
	var output bytes.Buffer
	_ = writeGenericHumanHeader(&output, config)
	_ = writeGenericHuman(&output, config, report, errors.New("failure\x1b[2J\n\u202ereason"))
	if strings.ContainsAny(output.String(), "\x1b\a\r\u202e") || !strings.Contains(output.String(), "bridge (external egress allowed)") || !strings.Contains(output.String(), "Egress was NOT TESTED") {
		t.Fatalf("unsafe or misleading terminal report: %q", output.String())
	}
	if got := terminalText(strings.Repeat("x", 10000), 32); len(got) != 35 {
		t.Fatalf("untrusted text not bounded: %d", len(got))
	}
}

func TestGenericOutputFormatKeepsPipesAndBuffersMachineReadable(t *testing.T) {
	for _, format := range []string{"auto", "json"} {
		if selected, err := genericOutputFormat(format, &bytes.Buffer{}); err != nil || selected != "json" {
			t.Fatalf("buffer format: %s %v", selected, err)
		}
	}
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	defer writer.Close()
	if selected, err := genericOutputFormat("auto", writer); err != nil || selected != "json" {
		t.Fatal("a pipe was treated as an interactive terminal")
	}
	if selected, err := genericOutputFormat("human", &bytes.Buffer{}); err != nil || selected != "human" {
		t.Fatal("explicit human output was not respected")
	}
	if _, err := genericOutputFormat("yaml", &bytes.Buffer{}); err == nil {
		t.Fatal("unknown format accepted")
	}
}

func TestGenericCLIFormatsSuccessAndPartialMachineReports(t *testing.T) {
	dir := t.TempDir()
	checks := filepath.Join(dir, "checks.json")
	if err := os.WriteFile(checks, []byte(`{"mode":"batch"}`), 0600); err != nil {
		t.Fatal(err)
	}
	for _, format := range []string{"auto", "json", "human"} {
		for _, partial := range []bool{false, true} {
			t.Run(format+" partial="+strconv.FormatBool(partial), func(t *testing.T) {
				report := humanReportFixture()
				var wantedErr error
				if partial {
					report.Completed, report.CandidateProbe, report.CandidateWorkload = false, nil, nil
					wantedErr = errors.New("candidate did not pass")
				}
				var output bytes.Buffer
				err := genericCLIWith([]string{"agent", "--checks", checks, "--format", format, "--artifacts", filepath.Join(dir, "results")}, &output, func(_ context.Context, config genericConfig) (*genericReport, error) {
					if format == "human" {
						if config.Progress == nil {
							t.Fatal("human progress callback missing")
						}
						config.phase("Verified source stage\x1b[31m", true)
						if partial {
							config.phase("Candidate validation", false)
						}
					} else if config.Progress != nil {
						t.Fatal("machine mode enabled stdout progress")
					}
					return report, wantedErr
				})
				if !errors.Is(err, wantedErr) {
					t.Fatalf("CLI lost original execution error: %v", err)
				}
				if format == "human" {
					wanted := "Result: PASS"
					if partial {
						wanted = "Result: FAILED"
					}
					if !strings.Contains(output.String(), wanted) || !strings.Contains(output.String(), "[PASS] Verified source stage") || strings.ContainsRune(output.String(), '\x1b') {
						t.Fatalf("human CLI output missing or unsafe: %q", output.String())
					}
					if partial && !strings.Contains(output.String(), "[FAILED] Candidate validation") {
						t.Fatal("failed progress stage was displayed as passed")
					}
					return
				}
				decoder := json.NewDecoder(&output)
				var actual genericReport
				if err := decoder.Decode(&actual); err != nil {
					t.Fatalf("stdout was not pure JSON: %v", err)
				}
				if err := decoder.Decode(new(any)); err != io.EOF {
					t.Fatalf("stdout contained more than one JSON object: %v", err)
				}
				wantedJSON, _ := json.Marshal(report)
				actualJSON, _ := json.Marshal(actual)
				if !bytes.Equal(wantedJSON, actualJSON) {
					t.Fatal("machine report semantics changed")
				}
			})
		}
	}
	if err := genericCLIWith([]string{"auto", "--format=yaml"}, &bytes.Buffer{}, func(context.Context, genericConfig) (*genericReport, error) {
		t.Fatal("invalid presentation format started the hardening workflow")
		return nil, nil
	}); err == nil || !strings.Contains(err.Error(), "--format") {
		t.Fatalf("invalid format error missing: %v", err)
	}
}

func TestGenericHumanBatchEvidenceDoesNotClaimOriginalEntrypointWasChecked(t *testing.T) {
	zero := 0
	for _, override := range []bool{false, true} {
		evidence := &workloadEvidence{Mode: "batch", Status: "passed", ExitCode: &zero, CommandOverride: override}
		text, status := humanWorkload(evidence)
		if status != "PASS" || strings.Contains(text, "Original") == override {
			t.Fatalf("batch command coverage mislabeled: %s %s", text, status)
		}
	}
	for _, evidence := range []*workloadEvidence{{Mode: "batch", Status: "passed"}, {Mode: "unknown", Status: "passed"}} {
		if _, status := humanWorkload(evidence); status == "PASS" {
			t.Fatal("incomplete command evidence passed")
		}
	}
}

func TestGenericHumanIncludesLastFailedCandidateApplicationEvidence(t *testing.T) {
	report := humanReportFixture()
	report.Completed, report.CandidateWorkload, report.CandidateProbe = false, nil, nil
	report.Attempts[0].Workload = &workloadEvidence{Mode: "http", Status: "failed"}
	rows := genericHumanRows(report)
	if rows[0].after != "Failed" || rows[0].status != "FAILED" {
		t.Fatal("known failed application check was hidden as missing evidence")
	}
}

type presentationErrorWriter struct{}

func (presentationErrorWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestGenericHumanPropagatesOutputFailure(t *testing.T) {
	if err := writeGenericHuman(presentationErrorWriter{}, genericConfig{}, humanReportFixture(), nil); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("output error swallowed: %v", err)
	}
}
