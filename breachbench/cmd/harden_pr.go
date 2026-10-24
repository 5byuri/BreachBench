package cmd

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"BreachBench/breachbench/pkg/githubbot"
	"BreachBench/breachbench/pkg/hardener"

	"github.com/spf13/cobra"
)

var (
	targetRepo     string
	dockerfilePath string
	topStars       int
	outputDir      string
	hardenedFile   string
	hardenerCmd    string
	autoFork       bool
	dryRun         bool
)

func generateHardenedDockerfile(ctx context.Context, rawDockerfile string, analysis *hardener.DockerfileAnalysis) (string, error) {
	fileOverride := strings.TrimSpace(hardenedFile)
	if fileOverride == "" {
		fileOverride = strings.TrimSpace(os.Getenv("HARDENED_DOCKERFILE_PATH"))
	}
	if fileOverride != "" {
		b, err := os.ReadFile(fileOverride)
		if err != nil {
			return "", fmt.Errorf("read --hardened-file %s: %w", fileOverride, err)
		}
		return string(b), nil
	}

	cmdOverride := strings.TrimSpace(hardenerCmd)
	if cmdOverride == "" {
		cmdOverride = strings.TrimSpace(os.Getenv("BREACHBENCH_HARDENER_CMD"))
	}
	if cmdOverride != "" {
		c := exec.CommandContext(ctx, "sh", "-c", cmdOverride)
		c.Stdin = strings.NewReader(rawDockerfile)
		out, err := c.Output()
		if err != nil {
			return "", fmt.Errorf("run --hardener-cmd %q: %w", cmdOverride, err)
		}
		if len(strings.TrimSpace(string(out))) > 0 {
			return string(out), nil
		}
	}

	return hardener.RenderHardenedDockerfile(analysis)
}

var hardenPrCmd = &cobra.Command{
	Use:   "harden-pr",
	Short: "Scrape top-starred GitHub repositories for unhardened distro Dockerfiles and harden them to FROM scratch",
	Long: `Scrapes the most-starred GitHub repositories (or targets a specific owner/repo), uses a distro
FROM-directive regex engine to detect unhardened Debian/Ubuntu-family Dockerfiles, transforms each into
a hardened multi-stage FROM scratch Containerfile using the OCI Community's Container Hardening Work Bench
(deb2scratch), and outputs hardened artifacts or opens Pull Requests.`,
	RunE: func(cmd *cobra.Command, args []string) error {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
		defer cancel()

		if strings.TrimSpace(targetRepo) == "" && topStars <= 0 {
			return fmt.Errorf("either --top-stars (-t, e.g. --top-stars 10) or --repo (-r) must be provided")
		}

		ghToken := githubbot.ResolveGitHubToken(os.Getenv("GITHUB_TOKEN"))
		if !dryRun && ghToken == "" {
			return fmt.Errorf("GITHUB_TOKEN environment variable is required to open Pull Requests (or pass --dry-run to preview locally)")
		}

		ghClient := githubbot.NewClient(ghToken)

		if topStars > 0 {
			fmt.Printf("==> Scraping GitHub's most-starred repositories to find top %d with unhardened distro Dockerfiles...\n", topStars)
			targets, err := ghClient.ScrapeTopStarredDistroRepos(ctx, topStars)
			if err != nil {
				return fmt.Errorf("failed to scrape top-starred repositories: %w", err)
			}

			fmt.Printf("\n==> Top %d Most-Starred Repositories Matching Distro Base Regex:\n", len(targets))
			for i, t := range targets {
				fmt.Printf("  [%2d] %-35s (%7d ⭐) | %-24s | FROM %s\n",
					i+1, t.FullName, t.Stars, t.DockerfilePath, t.RuntimeBaseImage)
			}

			for i, t := range targets {
				fmt.Printf("\n================================================================================\n")
				fmt.Printf("==> [%d/%d] Hardening %s (%d ⭐) — %s (Base: %s)\n",
					i+1, len(targets), t.FullName, t.Stars, t.DockerfilePath, t.RuntimeBaseImage)
				fmt.Printf("================================================================================\n")

				analysis, err := hardener.AnalyzeDockerfile(ctx, t.DockerfileContent, os.Getenv("GEMINI_API_KEY"))
				if err != nil {
					return fmt.Errorf("analyze %s: %w", t.FullName, err)
				}
				hardenedDockerfile, err := generateHardenedDockerfile(ctx, t.DockerfileContent, analysis)
				if err != nil {
					return fmt.Errorf("render %s: %w", t.FullName, err)
				}

				entryCmd := strings.TrimSpace(analysis.Entrypoint + " " + analysis.Cmd)
				prBody := githubbot.RenderPRBody(githubbot.PRReportData{
					RepoFullName:      t.FullName,
					DockerfilePath:    t.DockerfilePath,
					OriginalBaseImage: analysis.OriginalBaseImage,
					BuilderBaseImage:  analysis.BuilderBaseImage,
					AptPackages:       analysis.AptPackages,
					DetectedIssues:    analysis.DetectedIssues,
					EntrypointOrCmd:   entryCmd,
				})

				if strings.TrimSpace(outputDir) != "" {
					repoSlug := strings.ReplaceAll(t.FullName, "/", "__")
					repoOut := filepath.Join(outputDir, fmt.Sprintf("%02d_%s", i+1, repoSlug))
					if err := os.MkdirAll(repoOut, 0o755); err != nil {
						return fmt.Errorf("mkdir %s: %w", repoOut, err)
					}
					_ = os.WriteFile(filepath.Join(repoOut, "Dockerfile.original"), []byte(t.DockerfileContent), 0o644)
					_ = os.WriteFile(filepath.Join(repoOut, "Dockerfile.hardened"), []byte(hardenedDockerfile), 0o644)
					_ = os.WriteFile(filepath.Join(repoOut, "PR_REPORT.md"), []byte(prBody), 0o644)
					fmt.Printf("==> Saved artifacts to %s/\n", repoOut)
				}

				if dryRun {
					fmt.Println(hardenedDockerfile)
				}
			}
			return nil
		}

		parts := strings.Split(strings.TrimPrefix(targetRepo, "https://github.com/"), "/")
		if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
			return fmt.Errorf("invalid --repo %q: expected format owner/repo (e.g. ollama/ollama)", targetRepo)
		}
		owner, repo := parts[0], strings.TrimSuffix(parts[1], ".git")

		targetOwner, targetRepoName := owner, repo
		if !dryRun && autoFork {
			fmt.Printf("==> Forking upstream repository %s/%s into authenticated account...\n", owner, repo)
			forkOwner, forkRepo, err := ghClient.EnsureFork(ctx, owner, repo)
			if err != nil {
				return fmt.Errorf("failed to fork %s/%s: %w", owner, repo, err)
			}
			targetOwner, targetRepoName = forkOwner, forkRepo
			fmt.Printf("==> Using fork: %s/%s\n", targetOwner, targetRepoName)
		}

		fmt.Printf("==> Resolving default branch for %s/%s...\n", targetOwner, targetRepoName)
		baseBranch, baseSHA, err := ghClient.GetDefaultBranch(ctx, targetOwner, targetRepoName)
		if err != nil {
			return fmt.Errorf("failed to get default branch: %w", err)
		}

		fmt.Printf("==> Fetching %s from %s/%s@%s...\n", dockerfilePath, targetOwner, targetRepoName, baseBranch)
		rawDockerfile, fileSHA, err := ghClient.GetFileContent(ctx, targetOwner, targetRepoName, dockerfilePath, baseBranch)
		if err != nil {
			return fmt.Errorf("failed to fetch %s: %w", dockerfilePath, err)
		}

		if ok, baseImg := hardener.IsUnhardenedDistroDockerfile(rawDockerfile); ok {
			fmt.Printf("==> Regex matched unhardened distro base image: %s\n", baseImg)
		}

		fmt.Printf("==> Analyzing Dockerfile and extracting packages/runtime steps...\n")
		analysis, err := hardener.AnalyzeDockerfile(ctx, rawDockerfile, os.Getenv("GEMINI_API_KEY"))
		if err != nil {
			return fmt.Errorf("failed to analyze Dockerfile: %w", err)
		}

		fmt.Printf("==> Rendering hardened multi-stage FROM scratch Dockerfile (deb2scratch)...\n")
		hardenedDockerfile, err := generateHardenedDockerfile(ctx, rawDockerfile, analysis)
		if err != nil {
			return fmt.Errorf("failed to render hardened Dockerfile: %w", err)
		}

		entryCmd := analysis.Cmd
		if analysis.Entrypoint != "" {
			entryCmd = analysis.Entrypoint + " " + analysis.Cmd
		}
		prBody := githubbot.RenderPRBody(githubbot.PRReportData{
			RepoFullName:      fmt.Sprintf("%s/%s", owner, repo),
			DockerfilePath:    dockerfilePath,
			OriginalBaseImage: analysis.OriginalBaseImage,
			BuilderBaseImage:  analysis.BuilderBaseImage,
			AptPackages:       analysis.AptPackages,
			DetectedIssues:    analysis.DetectedIssues,
			EntrypointOrCmd:   strings.TrimSpace(entryCmd),
		})

		if dryRun {
			fmt.Println("\n==================== HARDENED DOCKERFILE ====================")
			fmt.Println(hardenedDockerfile)
			fmt.Println("\n==================== PULL REQUEST BODY ======================")
			fmt.Println(prBody)
			return nil
		}

		newBranch := fmt.Sprintf("breachbench/harden-dockerfile-%d", time.Now().Unix())
		fmt.Printf("==> Creating branch %s from %s (%s)...\n", newBranch, baseBranch, baseSHA[:7])
		if err := ghClient.CreateBranch(ctx, targetOwner, targetRepoName, newBranch, baseSHA); err != nil {
			return fmt.Errorf("failed to create branch %s: %w", newBranch, err)
		}

		commitMsg := fmt.Sprintf("security(docker): harden %s to minimal scratch rootfs via BreachBench", dockerfilePath)
		fmt.Printf("==> Committing hardened %s to %s/%s@%s...\n", dockerfilePath, targetOwner, targetRepoName, newBranch)
		if err := ghClient.UpdateFile(ctx, targetOwner, targetRepoName, dockerfilePath, newBranch, commitMsg, hardenedDockerfile, fileSHA); err != nil {
			return fmt.Errorf("failed to commit hardened Dockerfile: %w", err)
		}

		prTitle := fmt.Sprintf("🛡️ [BreachBench] Harden %s (%s -> scratch non-root)", dockerfilePath, analysis.OriginalBaseImage)
		fmt.Printf("==> Opening Pull Request on %s/%s...\n", targetOwner, targetRepoName)
		prURL, err := ghClient.CreatePullRequest(ctx, targetOwner, targetRepoName, prTitle, prBody, newBranch, baseBranch)
		if err != nil {
			return fmt.Errorf("failed to create Pull Request: %w", err)
		}

		fmt.Printf("\n✅ Pull Request successfully opened!\n🔗 URL: %s\n", prURL)
		return nil
	},
}

func init() {
	hardenPrCmd.Flags().IntVarP(&topStars, "top-stars", "t", 0, "Scrape top N most-starred GitHub repos with unhardened distro Dockerfiles and harden them (e.g. --top-stars 10)")
	hardenPrCmd.Flags().StringVarP(&targetRepo, "repo", "r", "", "Target a single GitHub repository in owner/repo format")
	hardenPrCmd.Flags().StringVarP(&dockerfilePath, "dockerfile", "f", "Dockerfile", "Path to the Dockerfile inside the repository")
	hardenPrCmd.Flags().StringVarP(&outputDir, "output-dir", "o", "", "Directory to save original & hardened Dockerfiles and PR reports")
	hardenPrCmd.Flags().StringVar(&hardenedFile, "hardened-file", "", "Path to a pre-generated hardened Dockerfile to commit directly (overrides built-in hardener)")
	hardenPrCmd.Flags().StringVar(&hardenerCmd, "hardener-cmd", "", "External shell command/binary that reads the raw Dockerfile from stdin and prints the hardened Dockerfile to stdout")
	hardenPrCmd.Flags().BoolVar(&autoFork, "fork", false, "Automatically fork the target repo into your GitHub account before opening the PR")
	hardenPrCmd.Flags().BoolVar(&dryRun, "dry-run", false, "Fetch and harden the Dockerfile(s) and print previews without pushing to GitHub")

	rootCmd.AddCommand(hardenPrCmd)
}
