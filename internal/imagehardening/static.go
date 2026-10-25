package imagehardening

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type staticConfig struct {
	Image, Target, Artifacts, Model, Mode string
	Policy                                genericRuntimePolicy
	Progress                              func(string)
	Inspected                             func(staticImageAnalysis)
}

type staticReport struct {
	Mode              string                `json:"mode"`
	Source            string                `json:"source"`
	Image             string                `json:"image"`
	CandidateCreated  bool                  `json:"candidate_created"`
	ApplicationTested bool                  `json:"application_tested"`
	Compatibility     string                `json:"compatibility"`
	Analysis          *staticImageAnalysis  `json:"analysis,omitempty"`
	Policy            genericRuntimePolicy  `json:"runtime_policy"`
	SelectedTools     []string              `json:"selected_tool_paths"`
	Filesystem        *imageRebuildEvidence `json:"filesystem,omitempty"`
	Agent             *staticAgentEvidence  `json:"agent,omitempty"`
	DeploymentWritten bool                  `json:"deployment_written"`
	Limitations       []string              `json:"limitations"`
	Error             string                `json:"error,omitempty"`
}

func staticCLI(args []string, out io.Writer) error {
	return staticCLIWith(args, out, hardenStatic)
}

func staticCLIWith(args []string, out io.Writer, run func(context.Context, staticConfig) (*staticReport, error)) error {
	f := flag.NewFlagSet("harden static", flag.ContinueOnError)
	var config staticConfig
	f.StringVar(&config.Image, "image", "", "Existing local Linux image; never started")
	f.StringVar(&config.Target, "target", "", "New untested candidate image tag")
	f.StringVar(&config.Artifacts, "artifacts", "", "New private output directory")
	f.StringVar(&config.Mode, "mode", "argon", "argon (bounded tool agent) or tools (deterministic, no API key)")
	f.StringVar(&config.Model, "model", "gemini-4-argon", "Gemini model for argon mode")
	policy := f.String("policy", "", "Optional explicit runtime policy JSON; no workload file required")
	format := f.String("format", "auto", "auto, human, or json")
	timeout := f.Duration("timeout", 15*time.Minute, "Complete static workflow timeout")
	if err := f.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if f.NArg() != 0 || *timeout <= 0 || (config.Mode != "tools" && config.Mode != "argon") {
		return errors.New("unexpected arguments, invalid mode, or nonpositive timeout")
	}
	if err := toolImageReference(config.Image); err != nil {
		return fmt.Errorf("--image: %w", err)
	}
	if err := toolImageReference(config.Target); err != nil {
		return fmt.Errorf("--target: %w", err)
	}
	if config.Image == config.Target || config.Artifacts == "" {
		return errors.New("choose a different --target and a new --artifacts directory")
	}
	selectedFormat, err := genericOutputFormat(*format, out)
	if err != nil {
		return err
	}
	if *policy != "" {
		if err := readGenericJSON(*policy, &config.Policy); err != nil {
			return err
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	report, runErr := run(ctx, config)
	if report == nil {
		return runErr
	}
	if selectedFormat == "json" {
		return errors.Join(runErr, json.NewEncoder(out).Encode(report))
	}
	return errors.Join(runErr, writeStaticHuman(out, config.Artifacts, report))
}

func hardenStatic(ctx context.Context, config staticConfig) (report *staticReport, resultErr error) {
	if err := toolImageReference(config.Image); err != nil {
		return nil, err
	}
	if config.Image == config.Target {
		return nil, errors.New("source and target must differ")
	}
	if config.Mode != "tools" && config.Mode != "argon" {
		return nil, errors.New("mode must be tools or argon")
	}
	if err := toolImageReference(config.Target); err != nil {
		return nil, err
	}
	if err := newImageTag(ctx, config.Target); err != nil {
		return nil, err
	}
	if config.Artifacts == "" {
		return nil, errors.New("--artifacts must name a new private directory")
	}
	if err := os.Mkdir(config.Artifacts, 0700); err != nil {
		return nil, err
	}
	absolute, err := filepath.Abs(config.Artifacts)
	if err != nil {
		return nil, err
	}
	report = &staticReport{Mode: "static-" + config.Mode, Source: config.Image, Image: config.Target,
		Compatibility: "unverified", SelectedTools: []string{}, Policy: config.Policy,
		Limitations: []string{
			"Target application and probes were not started; compatibility, shell access, write denial and network containment were not tested",
			"Static declarations do not prove runtime/subprocess, writable-path, credential or network requirements; removals are candidates, not proven-unused packages",
			"Only fixed tool entrypoints can be pruned; libraries, application code and retained runtime/dependency versions are not changed",
			"Shell absence does not prevent Python, PHP or Node code execution, data access or exploitation of application vulnerabilities",
			"Runtime controls require compose.json or equivalent deployment configuration; they are not enforced by the image alone",
			"Default network=none, read-only root, ephemeral /tmp and resource limits are restrictive assumptions, not inferred application requirements",
			"Original image environment defaults are preserved locally, not sent to the model; embedded credentials are not automatically removed",
		}}
	defer func() {
		if resultErr != nil {
			report.Error = resultErr.Error()
		}
		resultErr = errors.Join(resultErr, writeToolJSON(filepath.Join(absolute, "report.json"), report))
	}()
	// Pin all inspection/repack operations to the same immutable local configuration ID.
	if config.Progress != nil {
		config.Progress("Inspecting image configuration and filesystem")
	}
	metadata, err := inspectLocalMetadata(ctx, config.Image)
	if err != nil {
		return report, err
	}
	analysis, err := inspectStaticImage(ctx, metadata.ID, absolute, config.Policy)
	if err != nil {
		return report, err
	}
	if analysis.SourceID != metadata.ID {
		return report, errors.New("static inspection did not retain the pinned source identity")
	}
	report.Analysis = &analysis
	config.Policy.User = analysis.User
	if config.Policy.Network == "" {
		config.Policy.Network = "none"
	}
	if err := validateGenericPolicy(config.Policy); err != nil {
		return report, err
	}
	if err := validateImageVolumes(metadata, config.Policy); err != nil {
		return report, err
	}
	report.Policy = config.Policy
	if config.Inspected != nil {
		config.Inspected(analysis)
	}
	if config.Policy.Network == "bridge" {
		report.Limitations = append(report.Limitations, "Explicit bridge permits external egress; no network containment is claimed")
	}
	apply := func(ctx context.Context, removals []string) error {
		if config.Progress != nil {
			config.Progress("Repacking image with selected tool removals")
		}
		report.SelectedTools = append([]string{}, removals...)
		if err := writeToolJSON(filepath.Join(absolute, "plan.json"), map[string]any{"selected_tool_paths": removals, "runtime_policy": config.Policy, "application_tested": false}); err != nil {
			return err
		}
		evidence, err := rebuildImage(ctx, metadata.ID, config.Target, config.Policy.User, absolute, removals)
		report.Filesystem = &evidence
		if err != nil {
			return err
		}
		report.CandidateCreated = true
		if config.Progress != nil {
			config.Progress("Saving runtime protections and evidence")
		}
		if err := writeToolJSON(filepath.Join(absolute, "compose.json"), genericCompose(config.Target, config.Policy, workloadSpec{})); err != nil {
			return err
		}
		report.DeploymentWritten = true
		return nil
	}
	if config.Mode == "argon" {
		if config.Progress != nil {
			config.Progress("Argon is choosing bounded hardening actions")
		}
		evidence, err := runStaticAgent(ctx, config.Model, analysis, config.Policy, apply)
		report.Agent = &evidence
		return report, err
	}
	return report, apply(ctx, analysis.EligibleRemovals)
}

func writeStaticHuman(out io.Writer, artifacts string, report *staticReport) error {
	status := "NOT CREATED"
	if report.CandidateCreated {
		status = "CANDIDATE CREATED — NOT RUNTIME TESTED"
	}
	removed := []string{}
	if report.Filesystem != nil {
		removed = report.Filesystem.RemovedEntries
	}
	deployment := "not written"
	if report.DeploymentWritten {
		deployment = filepath.Join(artifacts, "compose.json")
	}
	_, err := fmt.Fprintf(out, "\nBreachBench · static hardening\n%s\n\n  Mode        %s\n  Image       %s\n  Identity    %s\n  Removed     %d actual tool entries\n  Tools       %s\n  Deployment  %s\n  Evidence    %s\n\nNo application or probe was started. Compatibility is unverified.\nRuntime controls need compose.json; hardening is not an RCE patch.\n",
		status, terminalText(report.Mode, 64), terminalText(report.Image, 512), terminalText(report.Policy.User, 64), len(removed), terminalText(strings.Join(removed, ", "), 2000), terminalText(deployment, 1024), terminalText(filepath.Join(artifacts, "report.json"), 1024))
	return err
}
