package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"BreachBench/internal/dockerfile"
	"github.com/spf13/cobra"
)

func newTraceCommand() *cobra.Command {
	var target, format string
	var buildArgs []string

	cmd := &cobra.Command{
		Use:   "trace [DOCKERFILE_OR_DIR]",
		Short: "Trace a Dockerfile runtime stage back to its FROM image, startup command, executable origin, and hardening status",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			pathArg := "Dockerfile"
			if len(args) > 0 {
				pathArg = args[0]
			}
			resolvedPath, err := resolveDockerfilePath(pathArg)
			if err != nil {
				return err
			}
			data, err := os.ReadFile(resolvedPath)
			if err != nil {
				return err
			}
			argMap := map[string]string{}
			for _, kv := range buildArgs {
				if eq := strings.IndexByte(kv, '='); eq > 0 {
					argMap[kv[:eq]] = kv[eq+1:]
				}
			}
			report, err := dockerfile.Analyze(string(data), dockerfile.TraceOptions{
				Target:    target,
				BuildArgs: argMap,
			})
			if err != nil {
				return err
			}

			switch strings.ToLower(format) {
			case "markdown", "md", "table":
				_, err = fmt.Fprint(cmd.OutOrStdout(), report.FormatMarkdownTable())
				return err
			default:
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(report)
			}
		},
	}

	cmd.Flags().StringVarP(&target, "target", "t", "", "Target build stage name or index (defaults to the last stage)")
	cmd.Flags().StringArrayVar(&buildArgs, "build-arg", nil, "Build argument KEY=VALUE used when resolving FROM and instructions")
	cmd.Flags().StringVarP(&format, "format", "f", "json", "Output format: json or markdown")
	return cmd
}

func newScrapeCommand() *cobra.Command {
	var (
		outputDir        string
		limit            int
		minStars         int
		languages        string
		queries          []string
		onlyUnhardened   bool
		noMultiStageOnly bool
		concurrency      int
		token            string
		timeout          time.Duration
	)

	cmd := &cobra.Command{
		Use:   "scrape [OUTPUT_DIR]",
		Short: "Scrape popular GitHub repositories for Dockerfiles, trace runtime stages, and identify unhardened single-stage builds",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			outDir := outputDir
			if len(args) > 0 && outDir == "" {
				outDir = args[0]
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()

			var langList []string
			if strings.TrimSpace(languages) != "" {
				for _, l := range strings.Split(languages, ",") {
					if trimmed := strings.TrimSpace(l); trimmed != "" {
						langList = append(langList, trimmed)
					}
				}
			}

			res, err := dockerfile.ScrapePopularRepos(ctx, dockerfile.ScrapeOptions{
				Queries:            queries,
				Languages:          langList,
				MinStars:           minStars,
				MaxReposWithDocker: limit,
				OnlyUnhardened:     onlyUnhardened,
				NoMultiStageOnly:   noMultiStageOnly,
				Concurrency:        concurrency,
				Token:              token,
			}, cmd.ErrOrStderr())
			if err != nil {
				return err
			}

			if outDir != "" {
				if err := dockerfile.SaveScrapeArtifacts(outDir, res); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Saved %d analyzed Dockerfiles (%d unhardened) to %s (results.json, report.md, report.html, dockerfiles/)\n",
					res.Summary.ReposWithDockerfile, len(res.Unhardened), outDir)
				return nil
			}

			enc := json.NewEncoder(cmd.OutOrStdout())
			enc.SetIndent("", "  ")
			return enc.Encode(res)
		},
	}

	cmd.Flags().StringVarP(&outputDir, "output", "o", "", "Directory to write results.json, report.md, report.html, and scraped Dockerfiles")
	cmd.Flags().IntVarP(&limit, "limit", "n", 40, "Maximum number of popular repositories with Dockerfiles to analyze")
	cmd.Flags().IntVar(&minStars, "min-stars", 2000, "Minimum GitHub star count for repository discovery")
	cmd.Flags().StringVar(&languages, "languages", "", "Comma-separated languages to filter (e.g. go,python,typescript,php)")
	cmd.Flags().StringArrayVarP(&queries, "query", "q", nil, "Custom GitHub repository search query (repeatable)")
	cmd.Flags().BoolVar(&onlyUnhardened, "only-unhardened", true, "Filter highlighted list to unhardened or build-environment-inheriting Dockerfiles")
	cmd.Flags().BoolVar(&noMultiStageOnly, "no-multistage", false, "Filter highlighted list strictly to single-stage or inherited-build-stage Dockerfiles")
	cmd.Flags().IntVar(&concurrency, "concurrency", 8, "Number of concurrent Dockerfile fetch workers")
	cmd.Flags().StringVar(&token, "token", "", "Optional GitHub token (defaults to GITHUB_TOKEN, GH_TOKEN, or gh auth token)")
	cmd.Flags().DurationVar(&timeout, "timeout", 5*time.Minute, "Maximum scrape execution time")
	return cmd
}

func resolveDockerfilePath(p string) (string, error) {
	info, err := os.Stat(p)
	if err != nil {
		return "", err
	}
	if !info.IsDir() {
		return p, nil
	}
	for _, candidate := range []string{"Dockerfile", "Containerfile", "docker/Dockerfile", "build/Dockerfile"} {
		candPath := filepath.Join(p, candidate)
		if st, err := os.Stat(candPath); err == nil && !st.IsDir() {
			return candPath, nil
		}
	}
	return "", fmt.Errorf("no Dockerfile or Containerfile found in %s", p)
}

func init() {
	rootCmd.AddCommand(newTraceCommand())
	rootCmd.AddCommand(newScrapeCommand())
}
