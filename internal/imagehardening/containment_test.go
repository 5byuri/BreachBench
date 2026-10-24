package imagehardening

import (
	"context"
	"strings"
	"testing"
)

func TestToolContainmentPreservesActualBaselineAndDefaultCommand(t *testing.T) {
	for _, hardened := range []bool{false, true} {
		args, err := toolContainmentRunArgs("image-id", "owned-name", "1234:1234", hardened, nil)
		if err != nil {
			t.Fatal(err)
		}
		joined := strings.Join(args, " ")
		if strings.Contains(joined, "--entrypoint") || args[len(args)-1] != "image-id" {
			t.Fatal("application check changed original ENTRYPOINT/CMD")
		}
		if strings.Contains(joined, "--user") != hardened || strings.Contains(joined, "--read-only") != hardened {
			t.Fatal("baseline USER/read-only changed or candidate policy missing")
		}
		for _, required := range []string{"--pull=never", "--network=none", "--cap-drop=ALL", "--security-opt=no-new-privileges:true", "--pids-limit=128"} {
			if !strings.Contains(joined, required) {
				t.Errorf("missing %s", required)
			}
		}
		if strings.Contains(joined, "--mount") || strings.Contains(joined, "--volume") || strings.Contains(joined, "--privileged") {
			t.Fatal("host resources exposed")
		}
	}
	args, err := toolContainmentRunArgs("image-id", "owned-name", "1234:1234", true, []string{"node", "-e", "fixed-script"})
	if err != nil || !strings.Contains(strings.Join(args, " "), "--entrypoint=node") || strings.Join(args[len(args)-3:], " ") != "image-id -e fixed-script" {
		t.Fatalf("fixed probe argv incorrect: %v %v", args, err)
	}
}

func toolPassingReport() toolContainmentReport {
	root, uid := 0, 65532
	hash := strings.Repeat("a", 64)
	baseline := &toolRuntimeEvidence{UID: &root, RuntimeSHA256: hash, ApplicationSHA256: hash, ProtectedWrite: toolOperationEvidence{Status: "allowed"}, LocalToolInstall: toolOperationEvidence{Status: "allowed"}}
	candidate := &toolRuntimeEvidence{UID: &uid, RuntimeSHA256: hash, ApplicationSHA256: hash, ProtectedWrite: toolOperationEvidence{Status: "denied", ErrorCode: "EROFS"}, LocalToolInstall: toolOperationEvidence{Status: "denied", ErrorCode: "EROFS"}}
	r := toolContainmentReport{Baseline: toolImageContainment{Application: pentestCheck{Status: "passed"}, Runtime: baseline}, Candidate: toolImageContainment{Application: pentestCheck{Status: "passed"}, Runtime: candidate}}
	for _, path := range []string{"/bin/sh", "/bin/bash", "/bin/ash", "/usr/bin/sh", "/busybox", "/bin/busybox"} {
		r.Baseline.Shells = append(r.Baseline.Shells, toolShellEvidence{Command: []string{path}, pentestCheck: pentestCheck{Status: "accessible"}})
		r.Candidate.Shells = append(r.Candidate.Shells, toolShellEvidence{Command: []string{path}, pentestCheck: pentestCheck{Status: "unavailable"}})
	}
	return r
}

func TestToolContainmentRejectsFalseSecurityPasses(t *testing.T) {
	for _, tc := range []struct {
		name string
		edit func(*toolContainmentReport)
	}{
		{"application regression", func(r *toolContainmentReport) { r.Candidate.Application.Status = "failed" }},
		{"missing runtime", func(r *toolContainmentReport) { r.Candidate.Runtime = nil }},
		{"runtime upgrade", func(r *toolContainmentReport) { r.Candidate.Runtime.RuntimeSHA256 = strings.Repeat("b", 64) }},
		{"application modified", func(r *toolContainmentReport) { r.Candidate.Runtime.ApplicationSHA256 = strings.Repeat("b", 64) }},
		{"root candidate", func(r *toolContainmentReport) { *r.Candidate.Runtime.UID = 0 }},
		{"writable candidate", func(r *toolContainmentReport) { r.Candidate.Runtime.ProtectedWrite.Status = "allowed" }},
		{"installation still works", func(r *toolContainmentReport) { r.Candidate.Runtime.LocalToolInstall.Status = "allowed" }},
		{"missing path is not permission denial", func(r *toolContainmentReport) { r.Candidate.Runtime.LocalToolInstall.ErrorCode = "ENOENT" }},
		{"unknown baseline", func(r *toolContainmentReport) { r.Baseline.Runtime.ProtectedWrite.Status = "inconclusive" }},
		{"shell still accessible", func(r *toolContainmentReport) { r.Candidate.Shells[0].Status = "accessible" }},
		{"shell evidence missing", func(r *toolContainmentReport) { r.Candidate.Shells = r.Candidate.Shells[:5] }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := toolPassingReport()
			tc.edit(&r)
			if err := evaluateToolContainment(&r); err == nil || r.Passed {
				t.Fatal("invalid security evidence passed")
			}
		})
	}
	r := toolPassingReport()
	if err := evaluateToolContainment(&r); err != nil || !r.Passed || !r.ImprovementDemonstrated {
		t.Fatalf("complete comparison failed: %v", err)
	}
}

func TestToolContainmentDoesNotInventImprovement(t *testing.T) {
	r := toolPassingReport()
	*r.Baseline.Runtime.UID = *r.Candidate.Runtime.UID
	r.Baseline.Runtime.ProtectedWrite = r.Candidate.Runtime.ProtectedWrite
	r.Baseline.Runtime.LocalToolInstall = r.Candidate.Runtime.LocalToolInstall
	for i := range r.Baseline.Shells {
		r.Baseline.Shells[i].Status = "unavailable"
	}
	if err := evaluateToolContainment(&r); err != nil || !r.Passed || r.ImprovementDemonstrated || len(r.Improvements) != 0 {
		t.Fatalf("already-protected baseline reported invented improvement: %+v %v", r, err)
	}
}

func TestToolApplicationFailureIsNotContainmentSuccess(t *testing.T) {
	for _, tc := range []struct {
		code int
		err  error
		want string
	}{{0, nil, "passed"}, {1, nil, "failed"}, {125, nil, "inconclusive"}, {127, nil, "inconclusive"}, {-1, context.DeadlineExceeded, "inconclusive"}} {
		if got := toolApplicationCheck(nil, nil, tc.code, tc.err); got.Status != tc.want {
			t.Fatalf("exit %d: got %s, want %s", tc.code, got.Status, tc.want)
		}
	}
}

func TestToolContainmentRequiresNumericNonRootCandidate(t *testing.T) {
	for _, user := range []string{"0:0", "000:0", "root", "user:group", ""} {
		if _, err := toolContainment(context.Background(), "baseline", "candidate", user); err == nil {
			t.Errorf("accepted unsafe candidate user %q", user)
		}
	}
}
