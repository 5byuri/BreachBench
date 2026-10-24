package imagehardening

import (
	"context"
	_ "embed"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

//go:embed fixtures/tool-hardening/app.js
var toolDemoApplication string

func toolCLI(args []string, out io.Writer) error {
	f := flag.NewFlagSet("harden "+args[0], flag.ContinueOnError)
	image := f.String("image", "", "Existing local image with finite offline Node self-test at /app/app.js")
	target := f.String("target", "", "NEW output image tag")
	artifacts := f.String("artifacts", "", "NEW local directory for report, deployment policy and tool artifacts")
	model := f.String("model", "gemini-4-argon", "Gemini model with function calling")
	slim := f.String("slim", "slim", "Installed SlimToolkit executable")
	offline := f.Bool("offline-workload", false, "Declare that the finite workload requires no external network")
	trusted := f.Bool("trusted-workload", false, "Acknowledge Slim's privileged profiler; use only trusted images on an isolated Docker host")
	scripted := f.Bool("scripted", false, "tool-demo only: run fixed tool steps without calling a model; reported explicitly")
	demoEngine := f.String("demo-engine", "slim", "tool-demo --scripted only: slim or fixed Docker fixture commands (docker)")
	timeout := f.Duration("timeout", 15*time.Minute, "Overall tool-agent timeout")
	if err := f.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 || *timeout <= 0 {
		return errors.New("unexpected arguments or nonpositive timeout")
	}
	if *scripted && args[0] != "tool-demo" {
		return errors.New("--scripted is only for the embedded public tool-demo")
	}
	if *demoEngine != "slim" && (*demoEngine != "docker" || args[0] != "tool-demo" || !*scripted) {
		return errors.New("--demo-engine=docker requires tool-demo --scripted")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	config := toolAgentConfig{Image: *image, Target: *target, Artifacts: *artifacts, Model: *model, Slim: *slim, Offline: *offline, Trusted: *trusted, Scripted: *scripted}
	config.DemoDocker = *demoEngine == "docker"
	var report *toolAgentReport
	var err error
	if args[0] == "tool-demo" {
		report, err = toolDemo(ctx, config)
	} else {
		report, err = toolAgent(ctx, config)
	}
	if report != nil {
		if encodeErr := json.NewEncoder(out).Encode(report); encodeErr != nil {
			return encodeErr
		}
	}
	return err
}

// toolDemo builds only a public synthetic fixture; no project code/config is sent to Gemini.
func toolDemo(ctx context.Context, config toolAgentConfig) (*toolAgentReport, error) {
	if config.Image != "" || config.Target != "" {
		return nil, errors.New("tool-demo owns its fixture images; use agent for a supplied image")
	}
	if config.Artifacts == "" {
		return nil, errors.New("--artifacts must name a new directory")
	}
	data, err := capture(ctx, "docker", "image", "ls", "--no-trunc", "--format", "{{.ID}} {{.Repository}}:{{.Tag}}")
	if err != nil {
		return nil, err
	}
	id := ""
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[1] == "node:24-trixie-slim" && slimImageID(fields[0]) {
			id = fields[0]
			break
		}
	}
	if id == "" {
		return nil, errors.New("demo requires an existing local node:24-trixie-slim image; no image is pulled automatically")
	}
	dir, err := os.MkdirTemp("", "hardening-tool-fixture-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(dir)
	stamp := fmt.Sprintf("%d-%d", os.Getpid(), time.Now().UnixNano())
	source, baseline := "hardening-tool-demo:"+stamp+"-source", "hardening-tool-demo:"+stamp+"-baseline"
	config.Image, config.Target, config.Offline = baseline, "hardening-tool-demo:"+stamp+"-hardened", true
	config.Trusted = true
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_ = exec.CommandContext(cleanup, "docker", "image", "rm", source).Run()
	}()
	if _, err := capture(ctx, "docker", "image", "tag", id, source); err != nil {
		return nil, err
	}
	containerfile := "FROM " + source + "\nWORKDIR /app\nCOPY app.js /app/app.js\nENTRYPOINT [\"node\"]\nCMD [\"/app/app.js\"]\n"
	for name, content := range map[string]string{"Containerfile": containerfile, "app.js": toolDemoApplication} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0644); err != nil {
			return nil, err
		}
	}
	if _, err := capture(ctx, "docker", "build", "--pull=false", "--network=none", "-f", filepath.Join(dir, "Containerfile"), "-t", baseline, "--", dir); err != nil {
		return nil, err
	}
	return toolAgent(ctx, config)
}
