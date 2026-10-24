package main

import (
	"fmt"
	"io"
	"os"

	"BreachBench/internal/imagehardening"
)

func run(args []string, out io.Writer) error {
	if len(args) > 0 && args[0] == "harden" {
		args = args[1:]
	}
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		_, err := fmt.Fprintln(out, "Usage: container-hardening-agent [harden] COMMAND [flags]\nCommands: auto, agent, tool-demo, gemini, pentest, demo, inspect, scan, config, build, minify, run, verify, compare\nUse COMMAND --help for its flags. The original build/Devguard scanner entrypoint is not included.")
		return err
	}
	return imagehardening.Run(args, out)
}

func main() {
	if err := run(os.Args[1:], os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
