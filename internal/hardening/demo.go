package hardening

import (
	"bytes"
	"context"
	"crypto/rand"
	"embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed assets/demo/* assets/demo-client.js
var demoAssets embed.FS

type DemoObservation struct {
	Succeeded bool   `json:"succeeded"`
	Error     string `json:"error"`
}

type DemoResult struct {
	RunID        string                     `json:"runID"`
	Started      string                     `json:"started"`
	Finished     string                     `json:"finished"`
	Phase        string                     `json:"phase"`
	Completed    bool                       `json:"completed"`
	Passed       bool                       `json:"passed"`
	Error        string                     `json:"error,omitempty"`
	SourceHash   string                     `json:"sourceSHA256"`
	Images       map[string]string          `json:"images"`
	Before       map[string]DemoObservation `json:"before"`
	After        map[string]DemoObservation `json:"after"`
	Checks       map[string]bool            `json:"checks"`
	Verification *Verification              `json:"runtimeVerification,omitempty"`
}

// Demo runs only embedded training code, on an internal network with no published ports.
func Demo(ctx context.Context, dir string, out io.Writer) (err error) {
	dir, err = filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err = os.Mkdir(dir, 0700); err != nil {
		return fmt.Errorf("choose a new output directory: %w", err)
	}
	log, err := os.OpenFile(filepath.Join(dir, "run.log"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer log.Close()
	out = io.MultiWriter(out, log)
	nonce := make([]byte, 12)
	if _, err = rand.Read(nonce); err != nil {
		return err
	}
	r := DemoResult{RunID: hex.EncodeToString(nonce), Started: time.Now().UTC().Format(time.RFC3339), Phase: "prepare", Images: map[string]string{}, Checks: map[string]bool{}}
	defer func() {
		r.Finished = time.Now().UTC().Format(time.RFC3339)
		r.Passed = err == nil && r.Completed
		if err != nil {
			r.Error = err.Error()
		}
		err = errors.Join(err, writeJSON(filepath.Join(dir, "results.json"), r), writeDemoHTML(filepath.Join(dir, "report.html"), r))
	}()
	app := filepath.Join(dir, "app")
	if err = os.Mkdir(app, 0700); err != nil {
		return err
	}
	for _, name := range []string{"server.js", "package.json", "package-lock.json"} {
		data, e := demoAssets.ReadFile("assets/demo/" + name)
		if e != nil {
			return e
		}
		if err = os.WriteFile(filepath.Join(app, name), data, 0644); err != nil {
			return err
		}
	}
	c, err := Detect(app)
	if err != nil {
		return err
	}
	c.Name = "demo-" + r.RunID
	c.HealthPath = "/health"
	c.Env = map[string]string{"DEMO_SECRET": "synthetic-demo-value-not-a-real-credential"}
	bundle := filepath.Join(dir, "hardened")
	if err = Generate(app, bundle, c); err != nil {
		return err
	}
	r.SourceHash, err = hashFile(filepath.Join(app, "server.js"))
	if err != nil {
		return err
	}
	hash, err := hashFile(filepath.Join(bundle, "app", "server.js"))
	if err != nil {
		return err
	}
	r.Checks["identical_application_source"] = hash == r.SourceHash
	if !r.Checks["identical_application_source"] {
		return fmt.Errorf("application source changed during hardening")
	}
	baselineRecipe := "FROM node:24-trixie-slim\nWORKDIR /app\nCOPY app/ ./\nENV PORT=3000\nCMD [\"node\", \"server.js\"]\n"
	if err = os.WriteFile(filepath.Join(dir, "Dockerfile.baseline"), []byte(baselineRecipe), 0600); err != nil {
		return err
	}
	client, err := demoAssets.ReadFile("assets/demo-client.js")
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "client.js"), client, 0600); err != nil {
		return err
	}
	r.Phase = "docker-preflight"
	if _, err = capture(ctx, "docker", "info", "--format", "{{.ServerVersion}}"); err != nil {
		return err
	}
	var containers []string
	network := "breachbench-demo-" + r.RunID
	networkCreated := false
	defer func() {
		clean, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		defer cancel()
		for i := len(containers) - 1; i >= 0; i-- {
			_, e := capture(clean, "docker", "rm", "--force", containers[i])
			err = errors.Join(err, e)
		}
		if networkCreated {
			_, e := capture(clean, "docker", "network", "rm", network)
			err = errors.Join(err, e)
		}
	}()
	r.Phase = "build-baseline"
	fmt.Fprintln(out, "1/4 Building the deliberately vulnerable baseline")
	locked, refs, err := lockImages(ctx, baselineRecipe, c.Platform, out)
	if err != nil {
		return err
	}
	if err = os.WriteFile(filepath.Join(dir, "Dockerfile.baseline.locked"), []byte(locked), 0600); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "baseline-images.lock.json"), refs); err != nil {
		return err
	}
	baselineTag := "breachbench/" + c.Name + ":baseline"
	// Send only the baseline source to the builder, excluding growing result artifacts.
	baselineContext := filepath.Join(dir, "baseline-context")
	if err = os.Mkdir(baselineContext, 0700); err != nil {
		return err
	}
	if err = os.Mkdir(filepath.Join(baselineContext, "app"), 0700); err != nil {
		return err
	}
	for _, name := range []string{"server.js", "package.json", "package-lock.json"} {
		b, e := os.ReadFile(filepath.Join(app, name))
		if e != nil {
			return e
		}
		if err = os.WriteFile(filepath.Join(baselineContext, "app", name), b, 0600); err != nil {
			return err
		}
	}
	if err = command(ctx, out, "docker", "build", "--platform", c.Platform, "-f", filepath.Join(dir, "Dockerfile.baseline.locked"), "-t", baselineTag, baselineContext); err != nil {
		return err
	}
	id, err := capture(ctx, "docker", "image", "inspect", "--format", "{{.Id}}", baselineTag)
	if err != nil {
		return err
	}
	r.Images["baseline"] = strings.TrimSpace(string(id))
	if _, err = capture(ctx, "docker", "network", "create", "--internal", network); err != nil {
		return err
	}
	networkCreated = true
	start := func(args []string) (string, error) {
		b, e := capture(ctx, "docker", args...)
		if e != nil {
			return "", e
		}
		id := strings.TrimSpace(string(b))
		containers = append(containers, id)
		_, e = capture(ctx, "docker", "start", id)
		return id, e
	}
	baseArgs := []string{"create", "--platform", c.Platform, "--network", network, "--memory", "256m", "--cpus", "1", "--pids-limit", "64", "--security-opt", "no-new-privileges:true"}
	sink, err := start(append(append([]string{}, baseArgs...), r.Images["baseline"], "node", "-e", "require('node:http').createServer((q,s)=>s.end(q.url.slice(1))).listen(8080,'0.0.0.0')"))
	if err != nil {
		return err
	}
	ip, err := capture(ctx, "docker", "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", sink)
	if err != nil {
		return err
	}
	sinkIP := strings.TrimSpace(string(ip))
	address, err := netip.ParseAddr(sinkIP)
	if err != nil || !address.Is4() {
		return fmt.Errorf("expected an IPv4 address for the local test sink")
	}
	baseline, err := start(append(append([]string{}, baseArgs...), "--env", "DEMO_SECRET="+c.Env["DEMO_SECRET"], r.Images["baseline"]))
	if err != nil {
		return err
	}
	r.Phase = "test-baseline"
	fmt.Fprintln(out, "2/4 Exercising the HTTP flaw and baseline follow-on actions")
	r.Before, err = demoProbe(ctx, baseline, "/usr/local/bin/node", r.RunID, sinkIP, client)
	if err != nil {
		return err
	}
	if err = checkDemoBaseline(r.Before); err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "before.json"), r.Before); err != nil {
		return err
	}
	r.Phase = "harden"
	fmt.Fprintln(out, "3/4 Building and verifying the hardened image from identical source")
	if err = Build(ctx, bundle, out); err != nil {
		return err
	}
	if err = Verify(ctx, bundle, out); err != nil {
		return err
	}
	var verified Verification
	if err = readJSON(filepath.Join(bundle, "verification.json"), &verified, true); err != nil {
		return err
	}
	r.Verification = &verified
	r.Images["hardened"] = verified.ImageID
	hardened, err := start(RuntimeArgs(bundle, c, verified.ImageID, ""))
	if err != nil {
		return err
	}
	r.Phase = "test-hardened"
	fmt.Fprintln(out, "4/4 Repeating identical probes and rechecking the network positive control")
	r.After, err = demoProbe(ctx, hardened, "/nodejs/bin/node", r.RunID, sinkIP, client)
	if err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "after.json"), r.After); err != nil {
		return err
	}
	control, err := demoProbe(ctx, baseline, "/usr/local/bin/node", r.RunID, sinkIP, client)
	if err != nil {
		return err
	}
	if err = writeJSON(filepath.Join(dir, "baseline-recheck.json"), control); err != nil {
		return err
	}
	if err = checkDemoBaseline(control); err != nil {
		return fmt.Errorf("baseline recheck: %w", err)
	}
	r.Checks["baseline_recheck"] = true
	checks, e := evaluateDemo(r.Before, r.After)
	for k, v := range checks {
		r.Checks[k] = v
	}
	if e != nil {
		return e
	}
	if !verified.Passed {
		return fmt.Errorf("runtime verification did not pass")
	}
	r.Checks["runtime_verified"] = true
	r.Completed = true
	r.Phase = "complete"
	fmt.Fprintln(out, "Measured containment passed. RCE and the worker's dummy secret remain reachable. See report.html and results.json.")
	return nil
}

func demoProbe(ctx context.Context, container, node, nonce, sink string, client []byte) (map[string]DemoObservation, error) {
	cmd := exec.CommandContext(ctx, "docker", "exec", "-i", container, node, "-", nonce, sink)
	cmd.Stdin = bytes.NewReader(client)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	b, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("HTTP probe: %w: %s", err, stderr.String())
	}
	var result map[string]DemoObservation
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, err
	}
	return result, nil
}

var demoCases = []string{"code_execution", "shell", "app_write", "root_write", "tmp_write", "worker_secret", "egress"}

func checkDemoBaseline(before map[string]DemoObservation) error {
	for _, name := range demoCases {
		if result, ok := before[name]; !ok || !result.Succeeded || result.Error != "" {
			return fmt.Errorf("baseline positive control failed: %s (%s)", name, result.Error)
		}
	}
	return nil
}

func evaluateDemo(before, after map[string]DemoObservation) (map[string]bool, error) {
	checks := map[string]bool{}
	if err := checkDemoBaseline(before); err != nil {
		return checks, err
	}
	for _, name := range demoCases {
		r, ok := after[name]
		pass := ok
		switch name {
		case "shell":
			pass = pass && !r.Succeeded && r.Error == "ENOENT"
		case "app_write", "root_write":
			pass = pass && !r.Succeeded && r.Error == "EROFS"
		case "egress":
			pass = pass && !r.Succeeded && (r.Error == "ENETUNREACH" || r.Error == "EHOSTUNREACH" || r.Error == "ETIMEDOUT")
		default:
			pass = pass && r.Succeeded && r.Error == ""
		}
		checks[name] = pass
	}
	for _, name := range demoCases {
		if !checks[name] {
			return checks, fmt.Errorf("unexpected hardened outcome: %s", name)
		}
	}
	return checks, nil
}

func writeDemoHTML(file string, r DemoResult) error {
	const page = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>BreachBench containment proof</title>
<style>body{font:17px system-ui;background:#10151d;color:#e3eaf3;max-width:1050px;margin:48px auto;padding:0 24px}h1{font-size:38px}strong{color:#7de0bb}table{border-collapse:collapse;width:100%;margin:28px 0}th,td{text-align:left;padding:14px;border-bottom:1px solid #374252}code{overflow-wrap:anywhere}small{color:#aebccc}a{color:#7dc8ff}.error{color:#ffb7a7}</style>
<small>BREACHBENCH / LOCAL TRAINING APP / {{.RunID}}</small><h1>Same flaw. Measured containment.</h1>
{{if .Passed}}<strong>PASS — all expected before/after outcomes measured.</strong>{{else}}<strong>NOT PROVEN — this run did not pass.</strong>{{end}}
<p>Phase: {{.Phase}} · Started {{.Started}} · Finished {{.Finished}}</p>{{if .Error}}<p class="error">{{.Error}}</p>{{end}}
<p>This synthetic application intentionally evaluates HTTP input. It is not a reproduction of PHP2Shell, React2Shell, or a named CVE. No host ports are published. Only synthetic data and a local network sink are used.</p>
<table><thead><tr><th>Probe</th><th>Before</th><th>After</th><th>Expected comparison met</th></tr></thead><tbody>
{{range $name := cases}}<tr><td>{{$name}}</td><td>{{observation $.Before $name}}</td><td>{{observation $.After $name}}</td><td>{{if index $.Checks $name}}Yes{{else}}Not proven{{end}}</td></tr>{{end}}
</tbody></table>
<p>RCE, access to the worker's dummy secret, and writes to designated temporary storage should still succeed. Hardening must block the shell, application/root writes, and access to the test sink. It does not fix the flaw.</p>
{{if .Verification}}<h2>Runtime measurements</h2><ul>{{range $key, $value := .Verification.Checks}}<li>{{$key}}: {{$value}}</li>{{end}}</ul>{{end}}
<p>The network comparison uses Docker's offline mode. It does not prove Kubernetes NetworkPolicy enforcement or external IAM scopes. A passing health endpoint does not establish full application compatibility. The image inventory checks known utility names.</p>
<p>Source SHA-256: <code>{{.SourceHash}}</code></p>{{range $name, $image := .Images}}<p>{{$name}} image: <code>{{$image}}</code></p>{{end}}
<p><a href="results.json">Full JSON evidence</a> · <a href="run.log">Build and test log</a> · <a href="hardened/verification.json">Runtime evidence</a></p></html>`
	t, err := template.New("demo").Funcs(template.FuncMap{"cases": func() []string { return demoCases }, "observation": func(m map[string]DemoObservation, name string) string {
		r, ok := m[name]
		if !ok {
			return "Not run"
		}
		if r.Succeeded {
			return "Succeeded"
		}
		return "Failed: " + r.Error
	}}).Parse(page)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	err = t.Execute(f, r)
	return errors.Join(err, f.Close())
}
