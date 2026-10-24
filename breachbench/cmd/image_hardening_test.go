package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func imageHardeningTestCommand(t *testing.T, args ...string) (string, error) {
	t.Helper()
	root := &cobra.Command{Use: "breachbench", SilenceErrors: true, SilenceUsage: true, RunE: func(*cobra.Command, []string) error {
		t.Fatal("image command entered the root token UI")
		return nil
	}}
	root.AddCommand(newHardenCommand())
	var output bytes.Buffer
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs(args)
	err := root.Execute()
	return output.String(), err
}

func TestImageHardeningRoutingPreservesEngineFlagsAndErrors(t *testing.T) {
	for _, test := range []struct {
		args []string
		want string
	}{
		{[]string{"harden", "auto"}, "--checks is required"},
		{[]string{"harden", "agent", "--mode=invalid"}, "invalid mode"},
		{[]string{"harden", "image", "auto"}, "--checks is required"},
		{[]string{"harden", "image", "verify"}, "--container is required"},
		{[]string{"harden", "image", "build"}, "target:"},
		{[]string{"harden", "image", "unknown"}, "unknown harden command"},
		{[]string{"harden", "auto", "--not-a-real-engine-flag"}, "flag provided but not defined"},
	} {
		t.Run(strings.Join(test.args, " "), func(t *testing.T) {
			_, err := imageHardeningTestCommand(t, test.args...)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("routing error = %v; want %q", err, test.want)
			}
		})
	}
}

func TestImageHardeningHelpAndNativeCommandsRemainAvailable(t *testing.T) {
	output, err := imageHardeningTestCommand(t, "harden", "--help")
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"auto", "agent", "image", "demo", "detect", "build", "verify", "trace", "scrape"} {
		if !strings.Contains(output, name) {
			t.Errorf("harden help lost %s", name)
		}
	}
	for _, args := range [][]string{{"harden", "image"}, {"harden", "image", "--help"}} {
		output, err := imageHardeningTestCommand(t, args...)
		if err != nil || !strings.Contains(output, "Commands: auto, agent") || !strings.Contains(output, "build, minify, run, verify") {
			t.Fatalf("compatibility help missing: %s %v", output, err)
		}
	}
	for _, test := range []struct{ action, usage string }{{"demo", "demo OUTPUT"}, {"detect", "detect APP"}, {"build", "build BUNDLE"}, {"verify", "verify BUNDLE"}, {"trace", "trace [DOCKERFILE_OR_DIR]"}, {"scrape", "scrape [OUTPUT_DIR]"}} {
		found := false
		for _, command := range newHardenCommand().Commands() {
			if command.Name() == test.action {
				found = command.Use == test.usage && !command.DisableFlagParsing
			}
		}
		if !found {
			t.Errorf("native command %s was replaced", test.action)
		}
	}
	if _, err := imageHardeningTestCommand(t, "harden", "image", "demo", "--help"); err != nil {
		t.Fatalf("legacy demo help should not run Docker: %v", err)
	}
}

func TestEveryImageCommandAliasUsesPassThroughFlags(t *testing.T) {
	commands := map[string]*cobra.Command{}
	for _, command := range newHardenCommand().Commands() {
		commands[command.Name()] = command
	}
	for _, name := range []string{"auto", "agent", "gemini", "pentest", "tool-demo", "inspect", "scan", "config", "minify", "run", "compare", "image"} {
		command := commands[name]
		if command == nil || !command.DisableFlagParsing || command.RunE == nil {
			t.Errorf("image alias %s is missing or intercepts engine flags", name)
		}
	}
}

func TestImageCommandErrorsDoNotAppendUsageToStructuredStdout(t *testing.T) {
	for _, args := range [][]string{{"harden", "auto"}, {"harden", "image", "auto"}} {
		root := &cobra.Command{Use: "breachbench", SilenceErrors: true}
		root.AddCommand(newHardenCommand())
		var output bytes.Buffer
		root.SetOut(&output)
		root.SetErr(&bytes.Buffer{})
		root.SetArgs(args)
		if err := root.Execute(); err == nil || output.Len() != 0 {
			t.Fatalf("failed image command polluted stdout: %q, %v", output.String(), err)
		}
	}
}
