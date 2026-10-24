package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
)

func TestHTTPCheckValidationHasNoExternalTargets(t *testing.T) {
	for _, raw := range []string{
		`[]`, `null`, `[{"path":"http://example.test/","status":200}]`, `[{"path":"//example.test/","status":200}]`,
		`[{"path":"/health\r\nX-Test: injected","status":200}]`, `[{"path":"/health","status":0}]`, `[{"path":"/health","status":200,"method":"POST"}]`,
		`[{"path":"/health","status":200}] {}`,
	} {
		if _, err := parseHTTPChecks(raw, 3000, 30); err == nil {
			t.Errorf("accepted unsafe HTTP checks %s", raw)
		}
	}
	for _, limit := range []int{0, 121} {
		if _, err := parseHTTPChecks(`[{"path":"/health","status":200}]`, 3000, limit); err == nil {
			t.Fatal("accepted unbounded deadline")
		}
	}
	if checks, err := parseHTTPChecks(`[{"path":"/health?detail=1","status":200,"body_contains":"healthy"}]`, 3000, 30); err != nil || len(checks) != 1 {
		t.Fatalf("valid loopback assertion rejected: %v", err)
	}
	for _, size := range []int{4096, 4097} {
		raw, _ := json.Marshal([]httpCheck{{Path: "/health", Status: 200, BodyContains: strings.Repeat("a", size)}})
		_, err := parseHTTPChecks(string(raw), 3000, 30)
		if (err != nil) != (size > 4096) {
			t.Fatalf("HTTP body assertion limit disagrees with workload validation at %d", size)
		}
	}
}

func TestProtectedWriteProbeCreatesOnlyMissingOwnedDirectory(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "missing-root")
	if got := protectedWriteProbe(dir, strings.Repeat("a", 32)); got.Status != "allowed" {
		t.Fatalf("writable missing root reported as %s: %s", got.Status, got.ErrorCode)
	}
	if _, err := os.Lstat(dir); !os.IsNotExist(err) {
		t.Fatalf("temporary measured directory not removed: %v", err)
	}
	// A missing ancestor is not evidence that the root filesystem denied a write.
	if got := protectedWriteProbe(filepath.Join(dir, "child"), strings.Repeat("a", 32)); got.Status != "inconclusive" || got.ErrorCode != "ENOENT" {
		t.Fatalf("missing parent produced false denial evidence: %+v", got)
	}
}

func TestProtectedWriteProbeDoesNotFollowAliases(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	for _, destination := range []string{target, filepath.Join(dir, "nonexistent")} {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(destination, link); err != nil {
			t.Fatal(err)
		}
		if got := protectedWriteProbe(link, strings.Repeat("a", 32)); got.Status != "inconclusive" {
			t.Fatalf("symlink produced usable permission evidence: %+v", got)
		}
		if err := os.Remove(link); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(target)
	if err != nil || len(entries) != 0 {
		t.Fatalf("probe wrote through alias: %v %v", entries, err)
	}
}

func TestProtectedWriteProbeClassifiesRealDenial(t *testing.T) {
	for _, err := range []error{syscall.EROFS, syscall.EACCES, syscall.EPERM} {
		if got := result(err); got.Status != "denied" {
			t.Fatalf("real denial not recognized: %+v", got)
		}
	}
	if os.Geteuid() == 0 {
		t.Skip("root can bypass the permission-only fixture")
	}
	parent := t.TempDir()
	if err := os.Chmod(parent, 0555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(parent, 0700) })
	if got := protectedWriteProbe(filepath.Join(parent, "missing-root"), strings.Repeat("a", 32)); got.Status != "denied" || got.ErrorCode != "EACCES" {
		t.Fatalf("permission denied root creation not measured: %+v", got)
	}
}

func TestCanonicalPathsRejectProtectedSymlinkTargets(t *testing.T) {
	dir := t.TempDir()
	allowed := filepath.Join(dir, "state")
	if err := os.Mkdir(allowed, 0700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink("/usr", link); err != nil {
		t.Fatal(err)
	}
	for _, paths := range [][]string{{"/"}, {"/etc"}, {link}, {filepath.Join(link, "new-data")}, {"/tmp/../etc"}} {
		raw, _ := json.Marshal(paths)
		if _, err := canonicalPaths(string(raw)); err == nil {
			t.Fatalf("accepted protected writable path %v", paths)
		}
	}
	newLeaf := filepath.Join(allowed, "new", "data")
	raw, _ := json.Marshal([]string{newLeaf})
	resolved, err := canonicalPaths(string(raw))
	canonicalParent, _ := filepath.EvalSymlinks(allowed)
	if err != nil || len(resolved) != 1 || resolved[0] != filepath.Join(canonicalParent, "new", "data") {
		t.Fatalf("safe new data path rejected: %v %v", resolved, err)
	}
	file := filepath.Join(allowed, "file")
	if err := os.WriteFile(file, []byte("public"), 0600); err != nil {
		t.Fatal(err)
	}
	raw, _ = json.Marshal([]string{file})
	if _, err := canonicalPaths(string(raw)); err == nil {
		t.Fatal("accepted a file as writable directory")
	}
}

func TestCanonicalPathsAllowSixteenDeclarationsAndImplicitTmp(t *testing.T) {
	dir := t.TempDir()
	values := []string{filepath.Join(dir, "tmp")}
	for _, name := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l", "m", "n", "o", "p"} {
		values = append(values, filepath.Join(dir, name))
	}
	raw, _ := json.Marshal(values)
	if got, err := canonicalPaths(string(raw)); err != nil || len(got) != 17 {
		t.Fatalf("seventeen effective writable paths rejected: %v %v", got, err)
	}
	values = append(values, filepath.Join(dir, "q"))
	raw, _ = json.Marshal(values)
	if _, err := canonicalPaths(string(raw)); err == nil {
		t.Fatal("accepted more than seventeen effective writable paths")
	}
}

func TestProbeDoesNotTreatMissingTargetAsPermissionDenied(t *testing.T) {
	if got := result(os.ErrNotExist); got.Status != "target_unavailable" {
		t.Fatalf("missing path reported as %s", got.Status)
	}
	if got := result(os.ErrPermission); got.Status != "denied" {
		t.Fatalf("permission denial reported as %s", got.Status)
	}
	if validNonce(strings.Repeat("a", 32)) == false || validNonce("'; malicious") {
		t.Fatal("invalid nonce validation")
	}
}
