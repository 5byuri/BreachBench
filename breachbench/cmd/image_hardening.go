package cmd

import (
	"strings"

	"BreachBench/internal/imagehardening"
	"github.com/spf13/cobra"
)

func newImageHardeningCommands(harden *cobra.Command) {
	commands := []struct{ name, description string }{
		{"auto", "Harden an existing image with deterministic tools and declared workload checks"},
		{"agent", "Let Gemini Argon select bounded image-hardening actions"},
		{"gemini", "Generate a candidate Containerfile through the Gemini API"},
		{"pentest", "Run the legacy local before/after containment checks"},
		{"tool-demo", "Run the explicitly scoped public tool-hardening fixture"},
		{"inspect", "Inspect the hardening settings of an existing container"},
		{"scan", "Scan an image through Trivy"},
		{"config", "Scan deployment configuration through Trivy"},
		{"minify", "Profile and minimize an image through SlimToolkit"},
		{"run", "Run a supplied command inside a restricted disposable container"},
		{"compare", "Compare before/after Trivy reports"},
	}
	for _, entry := range commands {
		action := entry.name
		harden.AddCommand(&cobra.Command{
			Use: action + " [flags]", Short: entry.description, DisableFlagParsing: true, SilenceUsage: true,
			RunE: func(command *cobra.Command, args []string) error {
				return imagehardening.Run(append([]string{action}, args...), command.OutOrStdout())
			},
		})
	}
	// Native app-bundle build/verify/demo commands keep their existing meanings.
	// The image namespace exposes the complete former workbench command set.
	legacyNames := []string{"auto", "agent", "tool-demo", "gemini", "pentest", "demo", "inspect", "scan", "config", "build", "minify", "run", "verify", "compare"}
	harden.AddCommand(&cobra.Command{
		Use: "image COMMAND [flags]", Short: "Use the complete image-hardening command set without changing native bundle commands",
		Long:               "Image-hardening compatibility namespace. Native harden APP, demo, build, and verify remain unchanged.\n\nCommands: " + strings.Join(legacyNames, ", ") + ".\nUse image COMMAND --help for that command's flags.",
		DisableFlagParsing: true,
		SilenceUsage:       true,
		RunE: func(command *cobra.Command, args []string) error {
			if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
				return command.Help()
			}
			return imagehardening.Run(args, command.OutOrStdout())
		},
	})
}
