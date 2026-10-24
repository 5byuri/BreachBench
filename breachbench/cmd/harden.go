package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"time"

	"BreachBench/internal/hardening"
	"github.com/spf13/cobra"
)

func newHardenCommand() *cobra.Command {
	var config, output string
	harden := &cobra.Command{Use: "harden APP", Short: "Generate minimal images and runtime policies for Go, Node/Next.js and PHP", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		source, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		c, err := hardening.Load(source, config)
		if err != nil {
			return err
		}
		if output == "" {
			output = filepath.Join(filepath.Dir(source), c.Name+"-hardened")
		}
		if err := hardening.Generate(source, output, c); err != nil {
			return err
		}
		fmt.Fprintf(cmd.OutOrStdout(), "Generated %s. Build and verify it before deployment.\n", output)
		return nil
	}}
	harden.Flags().StringVar(&config, "config", "", "Application requirements JSON (no credential values)")
	harden.Flags().StringVarP(&output, "output", "o", "", "New bundle directory outside the application")
	var demoTimeout time.Duration
	demo := &cobra.Command{Use: "demo OUTPUT", Short: "Run an isolated vulnerable-versus-hardened training demo and save evidence", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(cmd.Context(), demoTimeout)
		defer cancel()
		return hardening.Demo(ctx, args[0], cmd.OutOrStdout())
	}}
	demo.Flags().DurationVar(&demoTimeout, "timeout", 20*time.Minute, "Maximum build and test time")
	harden.AddCommand(demo)
	harden.AddCommand(&cobra.Command{Use: "detect APP", Short: "Inspect manifests and print a reviewable application configuration", Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
		p, err := filepath.Abs(args[0])
		if err != nil {
			return err
		}
		c, err := hardening.Detect(p)
		if err != nil {
			return err
		}
		e := json.NewEncoder(cmd.OutOrStdout())
		e.SetIndent("", "  ")
		return e.Encode(c)
	}})
	for _, action := range []string{"build", "verify"} {
		var timeout time.Duration
		sub := &cobra.Command{Use: action + " BUNDLE", Short: map[string]string{"build": "Resolve base digests and build a local hardened image", "verify": "Check image contents, runtime restrictions and application readiness"}[action], Args: cobra.ExactArgs(1), RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			if action == "build" {
				return hardening.Build(ctx, args[0], cmd.OutOrStdout())
			}
			return hardening.Verify(ctx, args[0], cmd.OutOrStdout())
		}}
		sub.Flags().DurationVar(&timeout, "timeout", 15*time.Minute, "Maximum execution time")
		harden.AddCommand(sub)
	}
	harden.AddCommand(newTraceCommand())
	harden.AddCommand(newScrapeCommand())
	newImageHardeningCommands(harden)
	return harden
}

func init() { rootCmd.AddCommand(newHardenCommand()) }
