package hardening

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestFailedVerificationCannotLeaveAStalePass(t *testing.T) {
	dir, c := fixture(t, "go")
	out := filepath.Join(t.TempDir(), "bundle")
	if e := Generate(dir, out, c); e != nil {
		t.Fatal(e)
	}
	if e := writeJSON(filepath.Join(out, "verification.json"), Verification{Passed: true}); e != nil {
		t.Fatal(e)
	}
	if e := Verify(context.Background(), out, io.Discard); e == nil {
		t.Fatal("verified an unbuilt bundle")
	}
	var report Verification
	if e := readJSON(filepath.Join(out, "verification.json"), &report, true); e != nil {
		t.Fatal(e)
	}
	if report.Passed || report.Details["error"] == "" {
		t.Fatal("stale pass retained")
	}
}

func TestEnvironmentIsLiteralAndCannotOverrideRuntimePolicy(t *testing.T) {
	dir, c := fixture(t, "php")
	c.Env = map[string]string{"APP_ENV": "production", "LITERAL": "$value"}
	if e := c.Validate(dir); e != nil {
		t.Fatal(e)
	}
	compose, _ := Deployment(c)
	env := compose["services"].(map[string]any)[c.Name].(map[string]any)["environment"].(map[string]string)
	if env["LITERAL"] != "$$value" {
		t.Fatal("Compose may interpolate application value")
	}
	if !strings.Contains(PHPConfig(c), "env[APP_ENV] = $APP_ENV") {
		t.Fatal("FPM lost explicit application environment")
	}
	c.Env["LD_AUDIT"] = "evil.so"
	if c.Validate(dir) == nil {
		t.Fatal("allowed loader injection through environment")
	}
}

func TestProbeBuildsSupportedArchitectures(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "probe.go")
	if err := os.WriteFile(source, probeSource, 0600); err != nil {
		t.Fatal(err)
	}
	for _, arch := range []string{"amd64", "arm64"} {
		cmd := exec.Command("go", "build", "-o", filepath.Join(dir, "probe-"+arch), source)
		cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s probe: %v\n%s", arch, err, out)
		}
	}
}

func fixture(t *testing.T, kind string) (string, Config) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "app")
	if e := os.Mkdir(dir, 0755); e != nil {
		t.Fatal(e)
	}
	files := map[string]string{}
	switch kind {
	case "go":
		files["go.mod"] = "module example.com/demo\n\ngo 1.27.2\n"
		files["main.go"] = "package main\nfunc main() {}\n"
	case "node":
		files["package.json"] = `{"name":"demo","version":"1.0.0","scripts":{"start":"node server.js"},"engines":{"node":"24"}}`
		files["package-lock.json"] = `{"lockfileVersion":3,"packages":{}}`
		files["server.js"] = "console.log('hello')"
	case "next":
		files["package.json"] = `{"dependencies":{"next":"16.1.5"},"scripts":{"build":"next build"}}`
		files["package-lock.json"] = `{"lockfileVersion":3,"packages":{}}`
		files["next.config.mjs"] = `export default {output: 'standalone'}`
	case "php":
		files["composer.json"] = `{"require":{"php":"^8.4","ext-pdo_mysql":"*"}}`
		files["composer.lock"] = `{"packages":[{"require":{"ext-intl":"*"}}]}`
	}
	for p, data := range files {
		if e := os.WriteFile(filepath.Join(dir, p), []byte(data), 0644); e != nil {
			t.Fatal(e)
		}
	}
	c, e := Detect(dir)
	if e != nil {
		t.Fatal(e)
	}
	return dir, c
}

func TestProfilesProduceDirectNonRootEntrypoints(t *testing.T) {
	for _, kind := range []string{"go", "node", "next", "php"} {
		t.Run(kind, func(t *testing.T) {
			dir, c := fixture(t, kind)
			recipe, e := ImageRecipe(dir, c)
			if e != nil {
				t.Fatal(e)
			}
			last := recipe[strings.LastIndex(recipe, "FROM "):]
			for _, want := range []string{"USER 65532:65532", "ENTRYPOINT [", "distroless/"} {
				if !strings.Contains(last, want) {
					t.Fatalf("missing %s", want)
				}
			}
			for _, bad := range []string{"RUN ", "npm start", "/bin/sh", "apt-get", "composer install"} {
				if strings.Contains(last, bad) {
					t.Fatalf("builder content in runtime: %s", bad)
				}
			}
		})
	}
}

func TestSeccompCannotReenablePrivilegedCalls(t *testing.T) {
	_, c := fixture(t, "go")
	for _, platform := range []string{"linux/amd64", "linux/arm64"} {
		c.Platform = platform
		data, e := Seccomp(c)
		if e != nil {
			t.Fatal(e)
		}
		var p struct {
			Default       string        `json:"defaultAction"`
			Rules         []syscallRule `json:"syscalls"`
			Architectures []string      `json:"architectures"`
		}
		if e = json.Unmarshal(data, &p); e != nil {
			t.Fatal(e)
		}
		if p.Default != "SCMP_ACT_ERRNO" || len(p.Architectures) != 1 {
			t.Fatal("permissive seccomp default/compat architecture")
		}
		clone, clone3, execve := false, false, false
		for _, r := range p.Rules {
			if r.Includes != nil || r.Excludes != nil {
				t.Fatal("unresolved Docker conditions")
			}
			for _, n := range r.Names {
				if slices.Contains(forbiddenCalls, n) {
					t.Fatalf("forbidden syscall %s", n)
				}
				if n == "clone" {
					clone = len(r.Args) > 0
				}
				if n == "clone3" {
					clone3 = r.Action == "SCMP_ACT_ERRNO" && r.ErrnoRet != nil && *r.ErrnoRet == 38
				}
				if n == "execve" {
					execve = true
				}
			}
		}
		if !clone || !clone3 || !execve {
			t.Fatal("lost runtime startup/fallback restrictions")
		}
	}
	for _, n := range forbiddenCalls {
		c.Syscalls = []string{"execve", n}
		if _, e := Seccomp(c); e == nil {
			t.Fatalf("allowed forbidden override %s", n)
		}
	}
}

func TestNarrowedSyscallsPreserveArgumentRestrictions(t *testing.T) {
	_, c := fixture(t, "node")
	c.Syscalls = []string{"execve", "socket", "clone", "read", "write", "exit_group"}
	b, e := Seccomp(c)
	if e != nil {
		t.Fatal(e)
	}
	var p struct {
		Rules []syscallRule `json:"syscalls"`
	}
	json.Unmarshal(b, &p)
	for _, r := range p.Rules {
		if r.Action != "SCMP_ACT_ALLOW" {
			continue
		}
		for _, n := range r.Names {
			if !slices.Contains(c.Syscalls, n) {
				t.Fatal(n)
			}
			if (n == "socket" || n == "clone") && len(r.Args) == 0 {
				t.Fatal("removed argument filters")
			}
		}
	}
}

func TestValidationRejectsUnsafeConfiguration(t *testing.T) {
	dir, base := fixture(t, "go")
	cases := map[string]func(*Config){"image-injection": func(c *Config) { c.Version = "1.27\nRUN evil" }, "entry-injection": func(c *Config) { c.Entry = ".;evil" }, "traversal": func(c *Config) { c.Entry = "../outside" }, "writable-root": func(c *Config) { c.Writable = []string{"/"} }, "writable-bin": func(c *Config) { c.Writable = []string{"/tmp", "/usr/bin"} }, "overlap": func(c *Config) { c.Writable = []string{"/tmp", "/tmp/sub"} }, "all-egress": func(c *Config) { c.Egress = []Destination{{"0.0.0.0/0", 443, "TCP"}} }, "egress-port": func(c *Config) { c.Egress = []Destination{{"10.0.0.1/32", 0, "TCP"}} }, "root-port": func(c *Config) { c.Port = 80 }, "secret-options": func(c *Config) { c.Secrets = []Secret{{"app-secret", "key", "LD_PRELOAD"}} }, "invalid-arch": func(c *Config) { c.Platform = "linux/386" }, "startup-blocked": func(c *Config) { c.Syscalls = []string{"read"} }}
	for name, change := range cases {
		t.Run(name, func(t *testing.T) {
			c := base
			change(&c)
			if c.Validate(dir) == nil {
				t.Fatal("accepted unsafe config")
			}
		})
	}
}

func TestSnapshotExcludesSecretsAndDetectsChanges(t *testing.T) {
	dir, c := fixture(t, "node")
	for _, name := range []string{".env.production", "auth.json", ".npmrc", "private.key", "name with spaces.txt"} {
		os.WriteFile(filepath.Join(dir, name), []byte("test"), 0600)
	}
	out := filepath.Join(t.TempDir(), "bundle")
	if e := Generate(dir, out, c); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadBundle(out); e != nil {
		t.Fatal(e)
	}
	for _, name := range []string{".env.production", "auth.json", ".npmrc", "private.key"} {
		if _, e := os.Stat(filepath.Join(out, "app", name)); !os.IsNotExist(e) {
			t.Fatalf("secret copied: %s", name)
		}
	}
	if e := Generate(dir, out, c); e == nil {
		t.Fatal("overwrote bundle")
	}
	if e := os.WriteFile(filepath.Join(out, "app", "server.js"), []byte("changed"), 0644); e != nil {
		t.Fatal(e)
	}
	if _, e := ReadBundle(out); e == nil {
		t.Fatal("missed source modification")
	}
}

func TestUnexpectedFilesAndSourceSymlinksRejected(t *testing.T) {
	dir, c := fixture(t, "go")
	out := filepath.Join(t.TempDir(), "bundle")
	if e := Generate(dir, out, c); e != nil {
		t.Fatal(e)
	}
	os.WriteFile(filepath.Join(out, "app", "extra.go"), []byte("package main"), 0600)
	if _, e := ReadBundle(out); e == nil {
		t.Fatal("accepted injected file")
	}
	outside := filepath.Join(t.TempDir(), "secret")
	os.WriteFile(outside, []byte("secret"), 0600)
	os.Symlink(outside, filepath.Join(dir, "data"))
	if e := Generate(dir, filepath.Join(t.TempDir(), "bundle"), c); e == nil {
		t.Fatal("followed source symlink")
	}
	if e := Generate(dir, filepath.Join(dir, "bundle"), c); e == nil {
		t.Fatal("allowed recursive source output")
	}
}

func TestDeploymentsDenyByDefaultAndScopeSecretRefs(t *testing.T) {
	_, c := fixture(t, "php")
	c.Secrets = []Secret{{"database", "password", "DB_PASSWORD"}}
	compose, kube := Deployment(c)
	svc := compose["services"].(map[string]any)[c.Name].(map[string]any)
	if svc["network_mode"] != "none" || svc["read_only"] != true || svc["user"] != "65532:65532" {
		t.Fatal("permissive Compose settings")
	}
	items := kube["items"].([]any)
	sa := items[0].(map[string]any)
	policy := items[1].(map[string]any)["spec"].(map[string]any)
	if sa["automountServiceAccountToken"] != false || len(policy["egress"].([]any)) != 0 {
		t.Fatal("default permissions/egress")
	}
	c.Egress = []Destination{{"10.20.30.40/32", 5432, "TCP"}}
	_, kube = Deployment(c)
	encoded, _ := json.Marshal(kube)
	for _, expected := range []string{"10.20.30.40/32", "secretKeyRef", "DB_PASSWORD", "readOnlyRootFilesystem", "Localhost"} {
		if !bytes.Contains(encoded, []byte(expected)) {
			t.Fatal(expected)
		}
	}
	if bytes.Contains(encoded, []byte("RoleBinding")) {
		t.Fatal("unexpected API permissions")
	}
}

func TestArchiveRejectsUtilitiesAndSetuid(t *testing.T) {
	for _, h := range []*tar.Header{{Name: "usr/bin/bash", Mode: 0755}, {Name: "bin/sh", Typeflag: tar.TypeSymlink, Linkname: "busybox", Mode: 0777}, {Name: "usr/bin/helper", Mode: 04755}} {
		var b bytes.Buffer
		w := tar.NewWriter(&b)
		w.WriteHeader(h)
		w.Close()
		if checkArchive(&b) == nil {
			t.Fatalf("accepted %s", h.Name)
		}
	}
	var b bytes.Buffer
	w := tar.NewWriter(&b)
	w.WriteHeader(&tar.Header{Name: "app/server", Mode: 0755})
	w.Close()
	if e := checkArchive(&b); e != nil {
		t.Fatal(e)
	}
}

func TestPHPExtensionsIncludeTransitiveProductionRequirements(t *testing.T) {
	dir, _ := fixture(t, "php")
	extensions, packages, e := phpExtensions(dir)
	if e != nil {
		t.Fatal(e)
	}
	if !slices.Contains(extensions, "intl") || !slices.Contains(extensions, "pdo_mysql") || !slices.Contains(packages, "libicu-dev") {
		t.Fatal("missing transitive extension")
	}
	os.WriteFile(filepath.Join(dir, "composer.lock"), []byte(`{"packages":[{"require":{"ext-unknown":"*"}}]}`), 0600)
	if _, _, e := phpExtensions(dir); e == nil {
		t.Fatal("guessed unknown extension")
	}
}

func TestAmbiguousApplicationsAndCommandsFail(t *testing.T) {
	dir, _ := fixture(t, "go")
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{}`), 0600)
	if _, e := Detect(dir); e == nil {
		t.Fatal("guessed monorepo")
	}
	dir, _ = fixture(t, "node")
	os.WriteFile(filepath.Join(dir, "package.json"), []byte(`{"scripts":{"start":"sh run.sh"}}`), 0600)
	if _, e := Detect(dir); e == nil {
		t.Fatal("accepted shell startup")
	}
}
