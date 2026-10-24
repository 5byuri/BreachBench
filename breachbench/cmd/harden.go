package cmd

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"strings"

	"github.com/spf13/cobra"
)

func init() {
	var config, output string
	command := &cobra.Command{
		Use:   "harden [mode]",
		Short: "Inspect, harden and verify containers with the in-repo work-bench",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(command *cobra.Command, args []string) error {
			mode := "run"
			if len(args) == 1 {
				mode = args[0]
			}
			standard := map[string]bool{"run": true, "verify": true, "inspect_container": true, "scan_image": true, "propose_hardening": true, "build_candidate": true, "test_application": true, "verify_hardening": true, "compare_results": true}
			special := map[string]bool{"cluster-test": true, "resource-test": true, "lsm-test": true, "remediation-test": true, "slim-demo": true, "lsm-check": true}
			if !standard[mode] && !special[mode] {
				return fmt.Errorf("unsupported hardening mode: %s", mode)
			}
			rootBytes, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
			if err != nil {
				return fmt.Errorf("run harden inside the BreachBench checkout: %w", err)
			}
			root := strings.TrimSpace(string(rootBytes))
			var program string
			var argv []string
			if runtime.GOOS == "windows" {
				program = "wsl"
				argv = []string{"-d", "Ubuntu", "--", "bash", "hardening/wsl-run.sh", mode}
			} else {
				program = "bash"
				argv = []string{"hardening/wsl-run.sh", mode}
			}
			if standard[mode] {
				argv = append(argv, config, output)
			}
			process := exec.CommandContext(command.Context(), program, argv...)
			process.Dir, process.Stdin, process.Stdout, process.Stderr = root, os.Stdin, os.Stdout, os.Stderr
			return process.Run()
		},
	}
	command.Flags().StringVar(&config, "config", "hardening/demo/config.json", "Workload JSON configuration relative to the checkout root")
	command.Flags().StringVar(&output, "output", ".breachbench/workflow", "Local evidence directory")
	rootCmd.AddCommand(command)
}
