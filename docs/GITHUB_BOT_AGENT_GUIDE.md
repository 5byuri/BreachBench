# 🤖 BreachBench GitHub Hardening Bot — AI Agent & Developer Integration Guide

> **Purpose of this document**: Handover and configuration reference for developers and AI coding agents integrating custom container-hardening logic (`deb2scratch` / `container-hardening-work-bench`) with the **BreachBench GitHub Scraper & Pull Request Bot**.

---

## 1. Architecture & File Map

The GitHub Bot is implemented in **both Python and Go** with identical CLI flags, environment variables, and plug-in hooks:

| Component | Go Implementation | Python Implementation | Responsibility |
| :--- | :--- | :--- | :--- |
| **CLI Entrypoint & Orchestrator** | `breachbench/cmd/harden_pr.go` (`harden-pr`) | `scripts/harden_pr.py` | Parses CLI flags, orchestrates scraping, invokes the hardener hook, and opens GitHub PRs |
| **GitHub REST API Client** | `breachbench/pkg/githubbot/client.go` | `scripts/harden_pr.py` (`github_request`, `ensure_fork`) | Star-ranked repo search, raw `Dockerfile` fetching, forking (`POST /repos/{owner}/{repo}/forks`), branch creation, file commits, and PR creation |
| **PR Markdown Report Renderer** | `breachbench/pkg/githubbot/pr_template.go` | `scripts/harden_pr.py` (`render_pr_body`) | Renders the Before/After Security Posture Scorecard and Mermaid pipeline diagram |
| **Distro Regex Detector** | `breachbench/pkg/hardener/analyzer.go` (`IsUnhardenedDistroDockerfile`) | `scripts/harden_pr.py` (`is_unhardened_distro_dockerfile`) | Resolves `ARG` and multi-stage `FROM ... AS ...` aliases to verify the final stage uses an unhardened distro (`ubuntu`, `debian`, `python`, `node`, etc.) |
| **Hardening Plug-in Hook** | `generateHardenedDockerfile()` in `breachbench/cmd/harden_pr.go` & `breachbench/pkg/hardener/deb2scratch.go` | `generate_hardened_dockerfile()` in `scripts/harden_pr.py` | **Plug-in boundary** where custom `Dockerfile` hardening logic is executed |

---

## 2. Authentication & GitHub Token Setup

The bot authenticates against the GitHub REST API (`https://api.github.com`) using the following automatic resolution chain:

1. **`GITHUB_TOKEN` Environment Variable**:
   ```bash
   export GITHUB_TOKEN="ghp_YOUR_GITHUB_TOKEN"
   ```
2. **Automatic Git Credential Keychain Fallback**:
   - If `GITHUB_TOKEN` is unset — or if a fine-grained PAT returns `HTTP 403 (Resource not accessible by personal access token)` on write operations — both the Go and Python bots automatically query `git credential fill` (`host=github.com`) and fall back to the local Git keychain token.

### Required Token Scopes (for `--fork` and PR Creation)
- **Classic PAT (`ghp_...`) / OAuth (`gho_...`)**: `public_repo` (or `repo`).
- **Fine-Grained PAT (`github_pat_...`)**:
  - **Administration**: `Read and write` (required to create forks)
  - **Contents**: `Read and write` (required to create branches and commit the hardened `Dockerfile`)
  - **Pull requests**: `Read and write` (required to open the Pull Request)

---

## 3. How an AI Agent Can Plug In Custom Hardening Logic (3 Ways)

The GitHub Bot is decoupled from the `Dockerfile` transformation logic so an AI agent or teammate can replace the built-in placeholder hardener without touching any GitHub API or PR orchestration code.

### Option A: Pass a Pre-Generated Hardened Dockerfile (`--hardened-file`) — *Zero Code Changes*
If your pipeline already generates a hardened `Dockerfile` on disk (e.g., `/tmp/Dockerfile.hardened`), pass it directly to the bot to fork the target repo, commit your file, and open the PR:

```bash
# Python
python3 scripts/harden_pr.py \
  --repo ollama/ollama \
  --dockerfile Dockerfile \
  --hardened-file /tmp/Dockerfile.hardened \
  --fork -v

# Go CLI
go run . harden-pr \
  --repo ollama/ollama \
  --dockerfile Dockerfile \
  --hardened-file /tmp/Dockerfile.hardened \
  --fork
```
*(Can also be set via environment variable: `export HARDENED_DOCKERFILE_PATH="/tmp/Dockerfile.hardened"`)*

---

### Option B: Pipe Through an External Hardener Script/Binary (`--hardener-cmd`) — *Zero Code Changes*
Pass any shell command or executable via `--hardener-cmd` (or `export BREACHBENCH_HARDENER_CMD="..."`).
- The bot passes the **raw upstream `Dockerfile` via `stdin`** to your command and reads the **hardened `Dockerfile` from `stdout`**:

```bash
# Python
python3 scripts/harden_pr.py \
  --repo ollama/ollama \
  --dockerfile Dockerfile \
  --hardener-cmd "./my-custom-hardener --mode scratch" \
  --fork -v

# Go CLI
go run . harden-pr \
  --repo ollama/ollama \
  --dockerfile Dockerfile \
  --hardener-cmd "./my-custom-hardener --mode scratch" \
  --fork
```

---

### Option C: Replace the Native Function in Code (Go or Python)
If the AI agent is writing the hardener directly inside this repository:

1. **In Go**:
   - Edit `RenderHardenedDockerfile(analysis *DockerfileAnalysis) (string, error)` in `breachbench/pkg/hardener/deb2scratch.go` (or `AnalyzeDockerfile` in `breachbench/pkg/hardener/analyzer.go`), **OR**
   - Edit `generateHardenedDockerfile(ctx, rawDockerfile, analysis)` in `breachbench/cmd/harden_pr.go` (lines 28–60), which receives the raw upstream `Dockerfile` string (`rawDockerfile`) and returns the hardened `Dockerfile` string.
2. **In Python**:
   - Edit `generate_hardened_dockerfile(raw_dockerfile: str, analysis: dict, ...)` in `scripts/harden_pr.py` (lines 624–656), which receives `raw_dockerfile` and returns the hardened `Dockerfile` string.

---

## 4. CLI Reference & End-to-End Commands

### 1. Fork a Repo, Harden Its `Dockerfile`, and Open a Live Pull Request
```bash
python3 scripts/harden_pr.py --repo ollama/ollama --dockerfile Dockerfile --fork -v
```
- **Verified Live Output**: **[https://github.com/Lvcaa/ollama/pull/1](https://github.com/Lvcaa/ollama/pull/1)**

### 2. Preview Hardened Output & PR Markdown Locally (`--dry-run`)
```bash
python3 scripts/harden_pr.py --repo ollama/ollama --dockerfile Dockerfile --dry-run -v
```

### 3. Scrape Top 10 Most-Starred GitHub Repos with Unhardened Distro `Dockerfile`s
```bash
python3 scripts/harden_pr.py --top-stars 10 --dry-run -o /tmp/top10_hardened -v
```
Saves `<rank>_<owner>__<repo>/Dockerfile.original`, `Dockerfile.hardened`, and `PR_REPORT.md` for each matched repository.
