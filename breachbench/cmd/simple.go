package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"BreachBench/internal/imagehardening"
	"github.com/spf13/cobra"
)

func newSimpleImageCommand() *cobra.Command {
	return simpleImageCommandWith(imagehardening.HardenImage)
}

func simpleImageCommandWith(run func(context.Context, string, string, bool, io.Writer) error) *cobra.Command {
	var mode string
	var demo bool
	command := &cobra.Command{
		Use: "harden-image [IMAGE]", Short: "Inspect an image, harden it, and print its Docker run command",
		Long: "Provide a local Linux image, or omit it for a prompt. Output tags and private reports are automatic.\nNo workload/policy JSON is needed. Static candidates are not runtime-tested.\n--demo requires Docker Engine 28+, opts into bridge networking and publishes one declared TCP port on loopback only; outbound traffic is allowed.",
		Args: cobra.MaximumNArgs(1), SilenceUsage: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			image := ""
			if len(args) == 1 {
				image = args[0]
			} else {
				if _, err := fmt.Fprint(cmd.OutOrStdout(), "Docker image to harden: "); err != nil {
					return err
				}
				line, err := bufio.NewReader(io.LimitReader(cmd.InOrStdin(), 514)).ReadString('\n')
				if err != nil && !errors.Is(err, io.EOF) {
					return err
				}
				image = strings.TrimSpace(line)
				if image == "" {
					return errors.New("provide a local image: breachbench IMAGE")
				}
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 15*time.Minute)
			defer cancel()
			return run(ctx, image, mode, demo, cmd.OutOrStdout())
		},
	}
	command.Flags().StringVar(&mode, "mode", "argon", "argon (existing Gemini credentials) or tools (no API key)")
	command.Flags().BoolVar(&demo, "demo", false, "Print a loopback-only demo run command (outbound networking allowed)")
	return command
}
