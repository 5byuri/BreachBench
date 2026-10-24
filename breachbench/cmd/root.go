package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "BreachBench",
	Short: "BreachBench runs adversarial security benchmarks against deterministically generated OCI container images",
	Long: `BreachBench runs adversarial security benchmarks against deterministically generated OCI container images, providing reproducible targets for evaluating container security.

	This tool is built for the purpose of evaluating the security of containerized applications, Gemini Argon 4 will be used to test the security of these applications.`,
	// Uncomment the following line if your bare application
	// has an action associated with it:
	RunE: func(cmd *cobra.Command, args []string) error {
		// Connect your OAuth implementation to the token returned by this UI.
		_, err := promptGeminiToken(cmd)
		return err
	},
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
}
