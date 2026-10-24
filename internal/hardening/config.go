package hardening

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"slices"
	"strings"
)

// Config contains requirements that cannot safely be inferred from source alone.
// Secrets name existing Kubernetes secrets; credential values never belong here.
type Config struct {
	Name       string            `json:"name"`
	Runtime    string            `json:"runtime"`
	Version    string            `json:"version"`
	Platform   string            `json:"platform"`
	Entry      string            `json:"entry"`
	Port       int               `json:"port"`
	HealthPath string            `json:"healthPath,omitempty"`
	Build      bool              `json:"build"`
	Writable   []string          `json:"writable"`
	Egress     []Destination     `json:"egress"`
	Secrets    []Secret          `json:"secrets"`
	Env        map[string]string `json:"env,omitempty"`
	Syscalls   []string          `json:"syscalls,omitempty"`
	MemoryMiB  int               `json:"memoryMiB"`
	CPUMillis  int               `json:"cpuMillis"`
	PIDs       int               `json:"pids"`
	TempMiB    int               `json:"tempMiB"`
}
type Destination struct {
	CIDR     string `json:"cidr"`
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}
type Secret struct {
	Name string `json:"name"`
	Key  string `json:"key"`
	Env  string `json:"env"`
}
type Package struct {
	Main         string            `json:"main"`
	Scripts      map[string]string `json:"scripts"`
	Engines      map[string]string `json:"engines"`
	Dependencies map[string]string `json:"dependencies"`
}
type Composer struct {
	Require map[string]string `json:"require"`
}

var nameRE = regexp.MustCompile(`^[a-z][a-z0-9-]{0,48}$`)
var pathRE = regexp.MustCompile(`^[a-zA-Z0-9_./-]+$`)
var versionRE = regexp.MustCompile(`^[0-9]+(?:\.[0-9]+){0,2}$`)
var envRE = regexp.MustCompile(`^[A-Z_][A-Z0-9_]*$`)

func readJSON(file string, v any, strict bool) error {
	f, err := os.Open(file)
	if err != nil {
		return err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 4<<20))
	if strict {
		d.DisallowUnknownFields()
	}
	if err := d.Decode(v); err != nil {
		return fmt.Errorf("%s: %w", file, err)
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return fmt.Errorf("%s: expected exactly one JSON object", file)
	}
	return nil
}

func Detect(dir string) (Config, error) {
	c := Config{Name: strings.ToLower(filepath.Base(dir)), Platform: "linux/" + runtime.GOARCH,
		Writable: []string{"/tmp"}, Egress: []Destination{}, Secrets: []Secret{}, MemoryMiB: 512, CPUMillis: 1000, PIDs: 128, TempMiB: 64}
	if !nameRE.MatchString(c.Name) {
		c.Name = "app"
	}
	var found []string
	for file, kind := range map[string]string{"go.mod": "go", "package.json": "node", "composer.json": "php"} {
		if _, err := os.Stat(filepath.Join(dir, file)); err == nil {
			found = append(found, kind)
		} else if !os.IsNotExist(err) {
			return c, err
		}
	}
	if len(found) != 1 {
		return c, fmt.Errorf("expected one application manifest (go.mod, package.json or composer.json); found %d; select an application subdirectory or provide an explicit config", len(found))
	}
	c.Runtime = found[0]
	switch c.Runtime {
	case "go":
		b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err != nil {
			return c, err
		}
		m := regexp.MustCompile(`(?m)^go\s+(\d+\.\d+(?:\.\d+)?)\s*$`).FindStringSubmatch(string(b))
		if len(m) != 2 {
			return c, fmt.Errorf("go.mod needs a go version")
		}
		c.Version = m[1]
		c.Entry = "."
		c.Port = 8080
	case "node":
		var p Package
		if err := readJSON(filepath.Join(dir, "package.json"), &p, false); err != nil {
			return c, err
		}
		// A range is not a runtime selection. Require an explicit version when ambiguous.
		v := regexp.MustCompile(`^(22|24|26)(?:\.x|\.\d+(?:\.\d+|\.x)?)?$`).FindStringSubmatch(p.Engines["node"])
		if len(v) > 0 {
			c.Version = v[1]
		} else if p.Engines["node"] == "" {
			c.Version = "24"
		} else {
			return c, fmt.Errorf("engines.node %q is ambiguous; provide config.version (22, 24 or 26)", p.Engines["node"])
		}
		c.Port = 3000
		c.Build = p.Scripts["build"] != ""
		if _, next := p.Dependencies["next"]; next {
			c.Runtime = "next"
			c.Entry = "server.js"
			c.Build = true
		} else {
			m := regexp.MustCompile(`^node\s+([a-zA-Z0-9_./-]+\.(?:js|mjs|cjs))$`).FindStringSubmatch(strings.TrimSpace(p.Scripts["start"]))
			if len(m) > 0 {
				c.Entry = m[1]
			} else if p.Scripts["start"] != "" {
				return c, fmt.Errorf("start script is not a direct Node invocation; provide config.entry and explicit environment requirements")
			} else if p.Main != "" {
				c.Entry = p.Main
			} else {
				return c, fmt.Errorf("cannot infer a direct Node entrypoint; provide config.entry instead of a shell/npm start command")
			}
		}
	case "php":
		var p Composer
		if err := readJSON(filepath.Join(dir, "composer.json"), &p, false); err != nil {
			return c, err
		}
		v := regexp.MustCompile(`^[~^]?(8\.[345])(?:\.\d+|\.\*)?$`).FindStringSubmatch(p.Require["php"])
		if len(v) == 0 {
			return c, fmt.Errorf("cannot select PHP runtime from composer require.php %q; provide config.version", p.Require["php"])
		}
		c.Version = v[1]
		c.Port = 9000
		c.Entry = "public/index.php"
	}
	return c, c.Validate(dir)
}

func Load(dir, file string) (Config, error) {
	if file == "" {
		return Detect(dir)
	}
	var c Config
	if err := readJSON(file, &c, true); err != nil {
		return c, err
	}
	return c, c.Validate(dir)
}

func (c Config) Validate(dir string) error {
	if !nameRE.MatchString(c.Name) {
		return fmt.Errorf("name must be a lowercase DNS label, max 49 characters")
	}
	if !slices.Contains([]string{"go", "node", "next", "php"}, c.Runtime) {
		return fmt.Errorf("unsupported runtime %q", c.Runtime)
	}
	if !versionRE.MatchString(c.Version) {
		return fmt.Errorf("version must select a numeric runtime version")
	}
	if c.Runtime == "node" || c.Runtime == "next" {
		if !slices.Contains([]string{"22", "24", "26"}, c.Version) {
			return fmt.Errorf("Node profiles support major versions 22, 24 and 26")
		}
	}
	if c.Runtime == "php" && !slices.Contains([]string{"8.3", "8.4", "8.5"}, c.Version) {
		return fmt.Errorf("PHP profiles support 8.3, 8.4 and 8.5")
	}
	if c.Platform != "linux/amd64" && c.Platform != "linux/arm64" {
		return fmt.Errorf("platform must be linux/amd64 or linux/arm64")
	}
	if c.Port < 1024 || c.Port > 65535 {
		return fmt.Errorf("port must be unprivileged (1024..65535)")
	}
	if c.MemoryMiB < 32 || c.MemoryMiB > 65536 || c.CPUMillis < 100 || c.CPUMillis > 64000 || c.PIDs < 16 || c.PIDs > 65536 || c.TempMiB < 1 || c.TempMiB > 4096 {
		return fmt.Errorf("invalid resource limits")
	}
	if !safeRelative(c.Entry) {
		return fmt.Errorf("entry must be a simple relative path inside the application")
	}
	if c.HealthPath != "" && (!strings.HasPrefix(c.HealthPath, "/") || strings.ContainsAny(c.HealthPath, "\r\n")) {
		return fmt.Errorf("healthPath must be an HTTP path")
	}
	if c.Runtime == "php" && c.HealthPath != "" {
		return fmt.Errorf("PHP-FPM speaks FastCGI; HTTP healthPath is not supported")
	}
	if len(c.Writable) > 16 {
		return fmt.Errorf("too many writable directories")
	}
	for i, p := range c.Writable {
		if !pathRE.MatchString(p) || path.Clean(p) != p || !strings.HasPrefix(p, "/") || p == "/" {
			return fmt.Errorf("invalid writable directory %q", p)
		}
		allowed := p == "/tmp" || strings.HasPrefix(p, "/app/") || strings.HasPrefix(p, "/var/") || strings.HasPrefix(p, "/run/")
		if !allowed {
			return fmt.Errorf("writable directory %q must be /tmp or a subdirectory of /app, /var or /run", p)
		}
		for _, q := range c.Writable[:i] {
			if p == q || strings.HasPrefix(p, q+"/") || strings.HasPrefix(q, p+"/") {
				return fmt.Errorf("overlapping writable directories")
			}
		}
	}
	if !slices.Contains(c.Writable, "/tmp") {
		return fmt.Errorf("/tmp is required for runtime temporary files")
	}
	for _, e := range c.Egress {
		p, err := netip.ParsePrefix(e.CIDR)
		if err != nil || p != p.Masked() {
			return fmt.Errorf("egress requires a canonical CIDR: %q", e.CIDR)
		}
		if p.Bits() == 0 {
			return fmt.Errorf("unrestricted egress CIDRs are not supported")
		}
		if e.Port < 1 || e.Port > 65535 || (e.Protocol != "TCP" && e.Protocol != "UDP") {
			return fmt.Errorf("egress requires a port and TCP/UDP protocol")
		}
	}
	seen := map[string]bool{}
	for k, v := range c.Env {
		if !envRE.MatchString(k) || reservedEnv(k) || len(v) > 8192 || strings.ContainsRune(v, 0) {
			return fmt.Errorf("invalid or reserved environment setting %q", k)
		}
		seen[k] = true
	}
	for _, s := range c.Secrets {
		if !nameRE.MatchString(s.Name) || !regexp.MustCompile(`^[a-zA-Z0-9_.-]+$`).MatchString(s.Key) || !envRE.MatchString(s.Env) || seen[s.Env] {
			return fmt.Errorf("invalid or duplicate secret reference")
		}
		if reservedEnv(s.Env) {
			return fmt.Errorf("reserved runtime environment name %s", s.Env)
		}
		seen[s.Env] = true
	}
	for _, s := range c.Syscalls {
		if !regexp.MustCompile(`^[a-z][a-z0-9_]*$`).MatchString(s) {
			return fmt.Errorf("invalid syscall name")
		}
	}
	if len(c.Syscalls) > 0 && !slices.Contains(c.Syscalls, "execve") {
		return fmt.Errorf("syscall list must include startup execve")
	}
	manifest := "go.mod"
	if c.Runtime == "node" || c.Runtime == "next" {
		manifest = "package.json"
	}
	if c.Runtime == "php" {
		manifest = "composer.json"
	}
	if _, err := os.Stat(filepath.Join(dir, manifest)); err != nil {
		return err
	}
	if c.Runtime == "node" || c.Runtime == "next" {
		if _, err := os.Stat(filepath.Join(dir, "package-lock.json")); err != nil {
			return fmt.Errorf("Node builds require package-lock.json (npm ci): %w", err)
		}
	}
	if c.Runtime == "php" {
		if _, err := os.Stat(filepath.Join(dir, "composer.lock")); err != nil {
			return fmt.Errorf("PHP builds require composer.lock: %w", err)
		}
	}
	return nil
}

func reservedEnv(k string) bool {
	return strings.HasPrefix(k, "LD_") || strings.HasPrefix(k, "DYLD_") || slices.Contains([]string{"PATH", "NODE_OPTIONS", "NODE_ENV", "PHPRC", "PHP_INI_SCAN_DIR", "PORT", "HOSTNAME", "HOME", "TMPDIR"}, k)
}

func safeRelative(p string) bool {
	return p != "" && pathRE.MatchString(p) && !strings.HasPrefix(p, "/") && path.Clean(p) == p && p != ".." && !strings.HasPrefix(p, "../") && !strings.HasPrefix(p, "-")
}
