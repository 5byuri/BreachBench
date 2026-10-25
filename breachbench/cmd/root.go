package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = newRootCommand()

func newRootCommand() *cobra.Command {
	command := newSimpleImageCommand()
	command.Use = "breachbench [IMAGE]"
	return command
}

// Execute adds all child commands to the root command and sets flags appropriately.
// This is called by main.main(). It only needs to happen once to the rootCmd.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}

func init() {
	// Here you will define your flags and configuration settings.
	// Cobra supports persistent flags, which, if defined here,
	// will be global for your application.
	var cfgFile string
	var cli bool

	rootCmd.PersistentFlags().StringVar(&cfgFile, "pentest", "p", "Run a pentest against a specific OCI Image")
	rootCmd.PersistentFlags().BoolVar(&cli, "cli", false, "cli-mode")
	// Cobra also supports local flags, which will only run
	// when this action is called directly.
	rootCmd.Flags().BoolP("cli-mode", "c", false, "Cli mode for BreachBench")
	rootCmd.AddCommand(newSimpleImageCommand())
}
