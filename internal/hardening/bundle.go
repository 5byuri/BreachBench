package hardening

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"strings"
)

type Bundle struct {
	Config Config            `json:"config"`
	Files  map[string]string `json:"files"`
	Notes  []string          `json:"notes"`
}

func Generate(source, output string, c Config) error {
	var err error
	source, err = filepath.Abs(source)
	if err != nil {
		return err
	}
	source, err = filepath.EvalSymlinks(source)
	if err != nil {
		return err
	}
	output, err = filepath.Abs(output)
	if err != nil {
		return err
	}
	if _, err := os.Lstat(output); !os.IsNotExist(err) {
		return fmt.Errorf("output must not already exist: %s", output)
	}
	parent, err := filepath.EvalSymlinks(filepath.Dir(output))
	if err != nil {
		return err
	}
	output = filepath.Join(parent, filepath.Base(output))
	if output == source || strings.HasPrefix(output, source+string(os.PathSeparator)) {
		return fmt.Errorf("output must be outside the application directory")
	}
	if err := c.Validate(source); err != nil {
		return err
	}
	if c.Runtime == "next" {
		if err := requireNextStandalone(source); err != nil {
			return err
		}
	}
	recipe, err := ImageRecipe(source, c)
	if err != nil {
		return err
	}
	profile, err := Seccomp(c)
	if err != nil {
		return err
	}
	tmp, err := os.MkdirTemp(parent, ".hardening-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	if err := snapshot(source, filepath.Join(tmp, "app")); err != nil {
		return err
	}
	files := map[string][]byte{"Dockerfile": []byte(recipe), "seccomp.json": profile}
	compose, kube := Deployment(c)
	files["compose.json"], err = json.MarshalIndent(compose, "", "  ")
	if err != nil {
		return err
	}
	files["kubernetes.json"], err = json.MarshalIndent(kube, "", "  ")
	if err != nil {
		return err
	}
	files["config.json"], err = json.MarshalIndent(c, "", "  ")
	if err != nil {
		return err
	}
	if c.Runtime == "php" {
		files["collect-php-runtime.sh"] = []byte(phpCollector)
		files["php.ini"] = []byte(phpINI)
		files["php-fpm.conf"] = []byte(PHPConfig(c))
	}
	files["README.md"] = []byte(bundleReadme(c))
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(tmp, name), append(data, '\n'), 0600); err != nil {
			return err
		}
	}
	b := Bundle{Config: c, Files: map[string]string{}, Notes: []string{
		"Generated configuration is not proof that controls are enforced. Run harden verify and application integration tests.",
		"Kubernetes: install seccomp.json on every eligible node at /var/lib/kubelet/seccomp/breachbench/" + c.Name + ".json before deployment; requires a NetworkPolicy-enforcing CNI.",
		"Compose uses network_mode:none: no ingress, egress, or DNS. Use Kubernetes for declared network exceptions and service access.",
		"Existing Secret references grant no new IAM/database permissions. Provision narrowly scoped credentials in the external service.",
		"Writable directories are ephemeral. Existing data under those mount points is hidden; seed it deliberately if needed.",
		"Static Go builds require CGO_ENABLED=0 compatibility and embedded assets; unsupported native dependencies fail at build time.",
		"The build resolves base tags to digests. Packages in upstream build stages can still change; this is not a bit-reproducibility guarantee.",
		"No shell or downloader does not prevent runtime code execution, access to app credentials, or exfiltration through allowed responses.",
		"Seccomp source: " + ProfileSource,
	}}
	if err := filepath.WalkDir(tmp, func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(tmp, p)
		if e != nil {
			return e
		}
		sum, e := hashFile(p)
		if e != nil {
			return e
		}
		b.Files[filepath.ToSlash(rel)] = sum
		return nil
	}); err != nil {
		return err
	}
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(tmp, "bundle.json"), append(data, '\n'), 0600); err != nil {
		return err
	}
	return os.Rename(tmp, output)
}

// Snapshot refuses symlinks and special files, so a build cannot accidentally
// import host data outside the selected application. Known secret files are excluded.
func snapshot(source, dest string) error {
	var total int64
	return filepath.WalkDir(source, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(source, p)
		if err != nil {
			return err
		}
		if rel != "." && excluded(d.Name()) {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source symlink %q needs an explicit vendored copy", rel)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		target := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0755)
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("unsupported source file %q", rel)
		}
		total += info.Size()
		if total > 512<<20 {
			return fmt.Errorf("source exceeds 512 MiB; select an application subdirectory")
		}
		in, err := os.Open(p)
		if err != nil {
			return err
		}
		defer in.Close()
		out, err := os.OpenFile(target, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()&0755)
		if err != nil {
			return err
		}
		_, err = io.Copy(out, in)
		closeErr := out.Close()
		if err != nil {
			return err
		}
		return closeErr
	})
}
func excluded(name string) bool {
	l := strings.ToLower(name)
	for _, n := range []string{".git", ".svn", ".hg", "node_modules", "vendor", ".next", ".aws", ".ssh", ".npmrc", "auth.json", ".ds_store", "hardening.json"} {
		if l == n {
			return true
		}
	}
	return strings.HasPrefix(l, ".env") || strings.HasSuffix(l, ".pem") || strings.HasSuffix(l, ".key") || strings.HasSuffix(l, ".p12") || strings.HasSuffix(l, ".pfx") || l == "id_rsa" || l == "id_ed25519"
}
func hashFile(path string) (string, error) {
	f, e := os.Open(path)
	if e != nil {
		return "", e
	}
	defer f.Close()
	h := sha256.New()
	if _, e = io.Copy(h, f); e != nil {
		return "", e
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func ReadBundle(dir string) (Bundle, error) {
	var b Bundle
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		return b, err
	}
	dir, err = filepath.Abs(dir)
	if err != nil {
		return b, err
	}
	if err := readJSON(filepath.Join(dir, "bundle.json"), &b, true); err != nil {
		return b, err
	}
	if err := b.Config.Validate(filepath.Join(dir, "app")); err != nil {
		return b, err
	}
	for _, required := range []string{"Dockerfile", "seccomp.json", "config.json", "compose.json", "kubernetes.json"} {
		if _, ok := b.Files[required]; !ok {
			return b, fmt.Errorf("bundle missing %s", required)
		}
	}
	for rel, want := range b.Files {
		if rel == "." || rel == ".." || strings.HasPrefix(rel, "/") || strings.HasPrefix(rel, "../") || path.Clean(rel) != rel {
			return b, fmt.Errorf("invalid bundle path %q", rel)
		}
		p := filepath.Join(dir, filepath.FromSlash(rel))
		real, err := filepath.EvalSymlinks(p)
		if err != nil {
			return b, err
		}
		abs, err := filepath.Abs(p)
		if err != nil {
			return b, err
		}
		if real != abs {
			return b, fmt.Errorf("bundle symlink refused: %s", rel)
		}
		got, err := hashFile(p)
		if err != nil {
			return b, err
		}
		if got != want {
			return b, fmt.Errorf("bundle changed: %s; regenerate from configuration", rel)
		}
	}
	if err := filepath.WalkDir(filepath.Join(dir, "app"), func(p string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.IsDir() {
			return nil
		}
		rel, e := filepath.Rel(dir, p)
		if e != nil {
			return e
		}
		if _, ok := b.Files[filepath.ToSlash(rel)]; !ok {
			return fmt.Errorf("unexpected application file: %s; regenerate the bundle", rel)
		}
		return nil
	}); err != nil {
		return b, err
	}
	return b, nil
}

func bundleReadme(c Config) string {
	return fmt.Sprintf(`# %s hardening bundle

Generated for %s %s (%s). This bundle has not been built or runtime-verified yet.

From BreachBench:

    go run . harden build /absolute/path/to/this/bundle
    go run . harden verify /absolute/path/to/this/bundle

Build creates Dockerfile.locked, images.lock.json, build.json and a local image.
Verification uses an isolated Docker network namespace with no external network,
the generated seccomp policy, a non-root UID, no capabilities, a read-only root,
resource limits and explicit temporary mounts. It checks image contents, kernel
controls and application readiness. A TCP or FPM ping is not a functional test.

## Deployment

After harden build: docker compose -f compose.json up --no-build
Compose has network_mode:none, so it is suitable for isolated/offline workloads.
Use Kubernetes for service access and declared egress rules. Compose does not
translate Kubernetes NetworkPolicies into Docker firewall rules.

Kubernetes: first build and push the image to your registry, replace the image
reference with that registry digest, and install seccomp.json on each eligible
node as /var/lib/kubelet/seccomp/breachbench/%s.json. Then apply kubernetes.json
in the intended namespace. The manifest uses a ClusterIP Service, same-namespace
pod ingress, default-deny egress and only the configured CIDR/port exceptions.
DNS is not implicitly enabled: declare your resolver CIDR and UDP/TCP 53 if needed.
NetworkPolicy requires an enforcing CNI. Node traffic and allowed reply traffic
have the documented Kubernetes exceptions; this is not a data-loss prevention tool.

Secrets refer to existing Kubernetes Secret keys. Compose requires their named
environment variables to be set externally. Never put secret values in config.
The generated ServiceAccount has no token automount and no RoleBindings.
External database/cloud permissions still need to be scoped at their provider.

All writable directories are empty ephemeral mounts; application uploads, cache,
or sessions will disappear at container removal. Mounting over an existing path
hides image contents there. Persistent data requires a separately reviewed design.
No-new-privileges, capability dropping and read-only root are deployment controls;
running the image alone does not activate them. Kubernetes emptyDir does not add
the Compose tmpfs noexec/nosuid/nodev mount flags, and pod PID limits need node policy.

Go supports static, self-contained applications. Node requires npm package-lock.json
and a direct JS entrypoint. Next.js requires standalone output. PHP uses FPM and
Composer production dependencies; a separate web server must speak FastCGI.
Native libraries and workload-specific subprocess requirements need application
integration tests. Build-time package scripts execute in Docker build stages.
Known secret filenames are excluded, but source code may contain other secrets;
review the captured app directory before sharing or publishing an image.

Seccomp is based on %s with privileged calls removed. Optional syscalls can only
narrow it. Include startup and all supported workloads in any measured allowlist.
execve remains available for container startup; no pathname-specific shell claim
is made. Runtime code execution and process-memory disclosure still require patches.
`, c.Name, c.Runtime, c.Version, c.Platform, c.Name, ProfileSource)
}
