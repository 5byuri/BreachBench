package dockerfile

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// ScrapeOptions configures the GitHub popular-repository Dockerfile scraper.
type ScrapeOptions struct {
	Queries            []string
	Languages          []string
	MinStars           int
	MaxReposWithDocker int
	MaxReposToCheck    int
	OnlyUnhardened     bool
	NoMultiStageOnly   bool
	Concurrency        int
	Token              string
	APIBaseURL         string
	RawBaseURL         string
	HTTPClient         *http.Client
	CandidatePaths     []string
}

// RepoDockerfileReport holds a scraped GitHub repository metadata, Dockerfile content, stage trace, and hardening score.
type RepoDockerfileReport struct {
	FullName       string       `json:"fullName"`
	HTMLURL        string       `json:"htmlUrl"`
	Description    string       `json:"description,omitempty"`
	Stars          int          `json:"stars"`
	Language       string       `json:"language,omitempty"`
	DefaultBranch  string       `json:"defaultBranch"`
	DockerfilePath string       `json:"dockerfilePath"`
	DockerfileURL  string       `json:"dockerfileUrl"`
	SavedFile      string       `json:"savedFile,omitempty"`
	Dockerfile     string       `json:"-"`
	Trace          *TraceReport `json:"trace"`
}

// ScrapeSummary aggregates statistics across all scraped repositories.
type ScrapeSummary struct {
	TotalReposChecked         int            `json:"totalReposChecked"`
	ReposWithDockerfile       int            `json:"reposWithDockerfile"`
	SingleStageCount          int            `json:"singleStageCount"`
	InheritedBuildStageCount  int            `json:"inheritedBuildStageCount"`
	MultiStageCopyCount       int            `json:"multiStageCopyCount"`
	RunsInBuildEnvCount       int            `json:"runsInBuildEnvCount"`
	RunsAsRootCount           int            `json:"runsAsRootCount"`
	UnhardenedOrTerribleCount int            `json:"unhardenedOrTerribleCount"`
	TerribleCount             int            `json:"terribleCount"`
	PartiallyHardenedCount    int            `json:"partiallyHardenedCount"`
	HardenedCount             int            `json:"hardenedCount"`
	HardenCompatibleCount     int            `json:"hardenCompatibleCount"`
	ByBaseCategory            map[string]int `json:"byBaseCategory"`
	ByDetectedRuntime         map[string]int `json:"byDetectedRuntime"`
}

// ScrapeResult contains the full results of a GitHub Dockerfile scrape run.
type ScrapeResult struct {
	StartedAt  string                 `json:"startedAt"`
	FinishedAt string                 `json:"finishedAt"`
	Summary    ScrapeSummary          `json:"summary"`
	Unhardened []RepoDockerfileReport `json:"unhardened"`
	All        []RepoDockerfileReport `json:"all"`
}

var defaultCandidatePaths = []string{
	"Dockerfile",
	"Containerfile",
	"docker/Dockerfile",
	"build/Dockerfile",
	"deploy/Dockerfile",
	"Dockerfile.prod",
}

// ResolveGitHubToken resolves a GitHub token from explicit flag, environment variables,
// or local `gh auth token` if available. It never logs or persists the token.
func ResolveGitHubToken(explicit string) string {
	if t := strings.TrimSpace(explicit); t != "" {
		return t
	}
	for _, envName := range []string{"GITHUB_TOKEN", "GH_TOKEN"} {
		if t := strings.TrimSpace(os.Getenv(envName)); t != "" {
			return t
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "gh", "auth", "token").Output()
	if err == nil {
		if t := strings.TrimSpace(string(out)); t != "" {
			return t
		}
	}
	return ""
}

type ghSearchResponse struct {
	Items []ghRepoItem `json:"items"`
}

type ghRepoItem struct {
	FullName      string `json:"full_name"`
	HTMLURL       string `json:"html_url"`
	Description   string `json:"description"`
	Stars         int    `json:"stargazers_count"`
	Language      string `json:"language"`
	DefaultBranch string `json:"default_branch"`
	Fork          bool   `json:"fork"`
	Archived      bool   `json:"archived"`
}

// ScrapePopularRepos searches GitHub for the most popular repositories, fetches their Dockerfiles,
// traces their runtime stages back to FROM images, and identifies unhardened / single-stage Dockerfiles.
func ScrapePopularRepos(ctx context.Context, opts ScrapeOptions, progress io.Writer) (*ScrapeResult, error) {
	started := time.Now().UTC()
	if opts.MinStars <= 0 {
		opts.MinStars = 2000
	}
	if opts.MaxReposWithDocker <= 0 {
		opts.MaxReposWithDocker = 40
	}
	if opts.MaxReposToCheck <= 0 {
		opts.MaxReposToCheck = opts.MaxReposWithDocker * 6
		if opts.MaxReposToCheck < 120 {
			opts.MaxReposToCheck = 120
		}
	}
	if opts.Concurrency <= 0 {
		opts.Concurrency = 8
	}
	if opts.APIBaseURL == "" {
		opts.APIBaseURL = "https://api.github.com"
	}
	if opts.RawBaseURL == "" {
		opts.RawBaseURL = "https://raw.githubusercontent.com"
	}
	if opts.HTTPClient == nil {
		opts.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if len(opts.CandidatePaths) == 0 {
		opts.CandidatePaths = defaultCandidatePaths
	}
	token := ResolveGitHubToken(opts.Token)

	queries := buildSearchQueries(opts)
	var candidates []ghRepoItem
	seenRepos := map[string]bool{}

	for _, q := range queries {
		if len(candidates) >= opts.MaxReposToCheck {
			break
		}
		if progress != nil {
			fmt.Fprintf(progress, "Searching GitHub repositories: %s\n", q)
		}
		items, err := searchRepositories(ctx, opts.HTTPClient, opts.APIBaseURL, token, q, 100)
		if err != nil {
			if len(candidates) > 0 {
				if progress != nil {
					fmt.Fprintf(progress, "Warning: search query %q stopped early (%v); continuing with %d discovered repos\n", q, err, len(candidates))
				}
				break
			}
			return nil, err
		}
		for _, item := range items {
			if item.Archived || item.Fork || item.FullName == "" || seenRepos[item.FullName] {
				continue
			}
			seenRepos[item.FullName] = true
			candidates = append(candidates, item)
			if len(candidates) >= opts.MaxReposToCheck {
				break
			}
		}
	}

	// Sort candidate repositories by star count descending
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Stars != candidates[j].Stars {
			return candidates[i].Stars > candidates[j].Stars
		}
		return candidates[i].FullName < candidates[j].FullName
	})

	if progress != nil {
		fmt.Fprintf(progress, "Checking %d popular repositories for Dockerfiles...\n", len(candidates))
	}

	// Probe repositories in batches so we can stop early once MaxReposWithDocker is reached
	var allReports []RepoDockerfileReport
	var totalChecked int
	batchSize := opts.Concurrency * 3
	if batchSize < 16 {
		batchSize = 16
	}

	for startIdx := 0; startIdx < len(candidates) && len(allReports) < opts.MaxReposWithDocker; startIdx += batchSize {
		endIdx := startIdx + batchSize
		if endIdx > len(candidates) {
			endIdx = len(candidates)
		}
		batch := candidates[startIdx:endIdx]
		totalChecked += len(batch)

		type batchOutcome struct {
			idx    int
			report *RepoDockerfileReport
		}
		resultsCh := make(chan batchOutcome, len(batch))
		sem := make(chan struct{}, opts.Concurrency)
		var wg sync.WaitGroup

		for i, repo := range batch {
			wg.Add(1)
			go func(idx int, r ghRepoItem) {
				defer wg.Done()
				select {
				case sem <- struct{}{}:
				case <-ctx.Done():
					return
				}
				defer func() { <-sem }()

				rep := fetchAndAnalyzeRepoDockerfile(ctx, opts.HTTPClient, opts.RawBaseURL, r, opts.CandidatePaths)
				if rep != nil {
					resultsCh <- batchOutcome{idx: idx, report: rep}
				}
			}(i, repo)
		}
		wg.Wait()
		close(resultsCh)

		var found []batchOutcome
		for out := range resultsCh {
			found = append(found, out)
		}
		sort.Slice(found, func(i, j int) bool { return found[i].idx < found[j].idx })
		for _, f := range found {
			allReports = append(allReports, *f.report)
			if progress != nil {
				t := f.report.Trace
				fmt.Fprintf(progress, "  [%d/%d] %s (%d★) -> %s | pattern=%s | base=%s | score=%d (%s)\n",
					len(allReports), opts.MaxReposWithDocker,
					f.report.FullName, f.report.Stars, f.report.DockerfilePath,
					t.MultiStagePattern, t.RuntimeBase,
					t.Hardening.UnhardenedScore, t.Hardening.Classification)
			}
			if len(allReports) >= opts.MaxReposWithDocker {
				break
			}
		}
	}

	summary := computeScrapeSummary(totalChecked, allReports)

	var unhardened []RepoDockerfileReport
	for _, rep := range allReports {
		if !isUnhardenedCandidate(rep.Trace, opts.OnlyUnhardened, opts.NoMultiStageOnly) {
			continue
		}
		unhardened = append(unhardened, rep)
	}

	// Sort unhardened list: prioritize single-stage / inherited-build-env and higher unhardened score, then stars
	sort.Slice(unhardened, func(i, j int) bool {
		ti, tj := unhardened[i].Trace, unhardened[j].Trace
		noMultiI := ti.SingleStage || ti.InheritsBuildStage || !ti.UsesMultiStageCopy
		noMultiJ := tj.SingleStage || tj.InheritsBuildStage || !tj.UsesMultiStageCopy
		if noMultiI != noMultiJ {
			return noMultiI
		}
		if ti.Hardening.UnhardenedScore != tj.Hardening.UnhardenedScore {
			return ti.Hardening.UnhardenedScore > tj.Hardening.UnhardenedScore
		}
		return unhardened[i].Stars > unhardened[j].Stars
	})

	return &ScrapeResult{
		StartedAt:  started.Format(time.RFC3339),
		FinishedAt: time.Now().UTC().Format(time.RFC3339),
		Summary:    summary,
		Unhardened: unhardened,
		All:        allReports,
	}, nil
}

func isUnhardenedCandidate(t *TraceReport, onlyUnhardened, noMultiStageOnly bool) bool {
	if t == nil {
		return false
	}
	if noMultiStageOnly && t.UsesMultiStageCopy && !t.InheritsBuildStage && !t.RunsInBuildEnv {
		return false
	}
	if onlyUnhardened {
		return t.Hardening.Classification == "terrible" || t.Hardening.Classification == "unhardened" || t.SingleStage || t.InheritsBuildStage || t.RunsInBuildEnv
	}
	return t.Hardening.UnhardenedScore >= 25 || t.SingleStage || t.InheritsBuildStage || t.RunsInBuildEnv
}

func buildSearchQueries(opts ScrapeOptions) []string {
	if len(opts.Queries) > 0 {
		return opts.Queries
	}
	if len(opts.Languages) > 0 {
		var qs []string
		for _, lang := range opts.Languages {
			lang = strings.TrimSpace(lang)
			if lang != "" {
				qs = append(qs, fmt.Sprintf("stars:>%d language:%s archived:false", opts.MinStars, lang))
			}
		}
		return qs
	}
	return []string{
		fmt.Sprintf("stars:>%d archived:false", max(opts.MinStars, 10000)),
		fmt.Sprintf("stars:>%d language:python archived:false", opts.MinStars),
		fmt.Sprintf("stars:>%d language:go archived:false", opts.MinStars),
		fmt.Sprintf("stars:>%d language:typescript archived:false", opts.MinStars),
		fmt.Sprintf("stars:>%d language:javascript archived:false", opts.MinStars),
		fmt.Sprintf("stars:>%d language:php archived:false", max(opts.MinStars/2, 1000)),
		fmt.Sprintf("stars:>%d language:rust archived:false", opts.MinStars),
		fmt.Sprintf("stars:>%d language:ruby archived:false", max(opts.MinStars/2, 1000)),
	}
}

func searchRepositories(ctx context.Context, client *http.Client, apiBase, token, query string, perPage int) ([]ghRepoItem, error) {
	u, err := url.Parse(strings.TrimRight(apiBase, "/") + "/search/repositories")
	if err != nil {
		return nil, err
	}
	q := u.Query()
	q.Set("q", query)
	q.Set("sort", "stars")
	q.Set("order", "desc")
	q.Set("per_page", fmt.Sprint(perPage))
	u.RawQuery = q.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "BreachBench-Dockerfile-Scanner/1.0")
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return nil, fmt.Errorf("github search HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	var parsed ghSearchResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsed); err != nil {
		return nil, err
	}
	return parsed.Items, nil
}

func fetchAndAnalyzeRepoDockerfile(ctx context.Context, client *http.Client, rawBase string, repo ghRepoItem, candidatePaths []string) *RepoDockerfileReport {
	branch := repo.DefaultBranch
	if branch == "" {
		branch = "main"
	}
	base := strings.TrimRight(rawBase, "/")
	for _, relPath := range candidatePaths {
		rawURL := fmt.Sprintf("%s/%s/%s/%s", base, repo.FullName, branch, relPath)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
		if err != nil {
			continue
		}
		req.Header.Set("User-Agent", "BreachBench-Dockerfile-Scanner/1.0")
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		if resp.StatusCode != http.StatusOK {
			resp.Body.Close()
			continue
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
		resp.Body.Close()
		if err != nil || len(bytes.TrimSpace(data)) == 0 {
			continue
		}
		content := string(data)
		trace, err := Analyze(content, TraceOptions{})
		if err != nil {
			continue
		}
		htmlFileURL := fmt.Sprintf("%s/blob/%s/%s", strings.TrimRight(repo.HTMLURL, "/"), branch, relPath)
		return &RepoDockerfileReport{
			FullName:       repo.FullName,
			HTMLURL:        repo.HTMLURL,
			Description:    repo.Description,
			Stars:          repo.Stars,
			Language:       repo.Language,
			DefaultBranch:  branch,
			DockerfilePath: relPath,
			DockerfileURL:  htmlFileURL,
			Dockerfile:     content,
			Trace:          trace,
		}
	}
	return nil
}

func computeScrapeSummary(totalChecked int, reports []RepoDockerfileReport) ScrapeSummary {
	s := ScrapeSummary{
		TotalReposChecked:   totalChecked,
		ReposWithDockerfile: len(reports),
		ByBaseCategory:      map[string]int{},
		ByDetectedRuntime:   map[string]int{},
	}
	for _, r := range reports {
		t := r.Trace
		if t == nil {
			continue
		}
		if t.SingleStage {
			s.SingleStageCount++
		}
		if t.InheritsBuildStage {
			s.InheritedBuildStageCount++
		}
		if t.UsesMultiStageCopy {
			s.MultiStageCopyCount++
		}
		if t.RunsInBuildEnv {
			s.RunsInBuildEnvCount++
		}
		if t.Hardening.RunsAsRoot {
			s.RunsAsRootCount++
		}
		if t.HardenCompatible {
			s.HardenCompatibleCount++
		}
		switch t.Hardening.Classification {
		case "terrible":
			s.TerribleCount++
			s.UnhardenedOrTerribleCount++
		case "unhardened":
			s.UnhardenedOrTerribleCount++
		case "partially-hardened":
			s.PartiallyHardenedCount++
		case "hardened":
			s.HardenedCount++
		}
		s.ByBaseCategory[t.Hardening.BaseCategory]++
		s.ByDetectedRuntime[t.DetectedRuntime]++
	}
	return s
}

// SaveScrapeArtifacts writes the scrape results, saved Dockerfiles, Markdown report, and HTML report into dir.
func SaveScrapeArtifacts(dir string, result *ScrapeResult) error {
	if result == nil {
		return fmt.Errorf("nil scrape result")
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Join(dir, "dockerfiles"), 0755); err != nil {
		return err
	}

	saveDockerfile := func(rep *RepoDockerfileReport) error {
		if rep.Dockerfile == "" {
			return nil
		}
		safeName := strings.NewReplacer("/", "__", "\\", "__", ":", "_").Replace(rep.FullName + "__" + rep.DockerfilePath)
		if !strings.HasSuffix(safeName, ".Dockerfile") {
			safeName += ".Dockerfile"
		}
		rel := filepath.Join("dockerfiles", safeName)
		if err := os.WriteFile(filepath.Join(dir, rel), []byte(rep.Dockerfile), 0644); err != nil {
			return err
		}
		rep.SavedFile = rel
		return nil
	}

	savedByRepo := map[string]string{}
	for i := range result.All {
		if err := saveDockerfile(&result.All[i]); err != nil {
			return err
		}
		savedByRepo[result.All[i].FullName] = result.All[i].SavedFile
	}
	for i := range result.Unhardened {
		if saved, ok := savedByRepo[result.Unhardened[i].FullName]; ok {
			result.Unhardened[i].SavedFile = saved
		} else if err := saveDockerfile(&result.Unhardened[i]); err != nil {
			return err
		}
	}

	jsonBytes, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "results.json"), append(jsonBytes, '\n'), 0644); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "report.md"), []byte(FormatScrapeMarkdown(result)), 0644); err != nil {
		return err
	}
	return writeScrapeHTML(filepath.Join(dir, "report.html"), result)
}

// FormatScrapeMarkdown renders a comprehensive Markdown report of the scraped Dockerfiles and stage traces.
func FormatScrapeMarkdown(result *ScrapeResult) string {
	var b strings.Builder
	s := result.Summary
	b.WriteString("# GitHub Popular Repository Dockerfile Stage-Trace & Hardening Report\n\n")
	b.WriteString(fmt.Sprintf("- **Started:** `%s`\n", result.StartedAt))
	b.WriteString(fmt.Sprintf("- **Finished:** `%s`\n", result.FinishedAt))
	b.WriteString(fmt.Sprintf("- **Repositories checked:** %d\n", s.TotalReposChecked))
	b.WriteString(fmt.Sprintf("- **Repositories with Dockerfile analyzed:** %d\n\n", s.ReposWithDockerfile))

	b.WriteString("## Aggregate Findings\n\n")
	b.WriteString("| Metric | Count | Share of Analyzed Dockerfiles |\n")
	b.WriteString("|---|---:|---:|\n")
	pct := func(n int) string {
		if s.ReposWithDockerfile == 0 {
			return "0.0%"
		}
		return fmt.Sprintf("%.1f%%", float64(n)*100/float64(s.ReposWithDockerfile))
	}
	b.WriteString(fmt.Sprintf("| Single-stage builds (`StageCount == 1`, no multi-stage separation) | %d | %s |\n", s.SingleStageCount, pct(s.SingleStageCount)))
	b.WriteString(fmt.Sprintf("| Multi-stage inheriting build stage (`FROM <build-stage>`) | %d | %s |\n", s.InheritedBuildStageCount, pct(s.InheritedBuildStageCount)))
	b.WriteString(fmt.Sprintf("| Multi-stage copying into separate runtime (`COPY --from`) | %d | %s |\n", s.MultiStageCopyCount, pct(s.MultiStageCopyCount)))
	b.WriteString(fmt.Sprintf("| **Runs inside build environment** (`RunsInBuildEnv == true`) | **%d** | **%s** |\n", s.RunsInBuildEnvCount, pct(s.RunsInBuildEnvCount)))
	b.WriteString(fmt.Sprintf("| **Runs as root (`UID 0`)** | **%d** | **%s** |\n", s.RunsAsRootCount, pct(s.RunsAsRootCount)))
	b.WriteString(fmt.Sprintf("| **Unhardened or Terrible (`score >= 30`)** | **%d** | **%s** |\n", s.UnhardenedOrTerribleCount, pct(s.UnhardenedOrTerribleCount)))
	b.WriteString(fmt.Sprintf("| Terrible (`score >= 55`) | %d | %s |\n", s.TerribleCount, pct(s.TerribleCount)))
	b.WriteString(fmt.Sprintf("| Hardened (`score <= 10`) | %d | %s |\n", s.HardenedCount, pct(s.HardenedCount)))
	b.WriteString(fmt.Sprintf("| Compatible with `breachbench harden` (Go, Node, Next.js, PHP) | %d | %s |\n\n", s.HardenCompatibleCount, pct(s.HardenCompatibleCount)))

	b.WriteString("## Unhardened / Terrible Dockerfiles (Ranked)\n\n")
	b.WriteString("| Rank | Repository | Stars | Runtime | Pattern | Runtime Base | Runs in Build Env | Root | Score | Key Findings |\n")
	b.WriteString("|---:|---|---:|---|---|---|---|---|---:|---|\n")
	for i, rep := range result.Unhardened {
		t := rep.Trace
		var codes []string
		for _, f := range t.Hardening.Findings {
			codes = append(codes, "`"+f.Code+"`")
		}
		b.WriteString(fmt.Sprintf("| %d | [%s](%s) ([`%s`](%s)) | %d | `%s` | `%s` | `%s` | `%t` | `%t` | **%d** (`%s`) | %s |\n",
			i+1, rep.FullName, rep.HTMLURL, rep.DockerfilePath, rep.DockerfileURL,
			rep.Stars, t.DetectedRuntime, t.MultiStagePattern, t.RuntimeBase,
			t.RunsInBuildEnv, t.Hardening.RunsAsRoot,
			t.Hardening.UnhardenedScore, t.Hardening.Classification,
			strings.Join(codes, ", ")))
	}
	b.WriteString("\n")

	b.WriteString("## Stage-Trace Breakdown (Top Unhardened Repositories)\n\n")
	limit := min(len(result.Unhardened), 25)
	for i := 0; i < limit; i++ {
		rep := result.Unhardened[i]
		t := rep.Trace
		b.WriteString(fmt.Sprintf("### %d. `%s` (%d ★) — `%s`\n\n", i+1, rep.FullName, rep.Stars, rep.DockerfilePath))
		if rep.Description != "" {
			b.WriteString(fmt.Sprintf("> %s\n\n", rep.Description))
		}
		b.WriteString(t.FormatMarkdownTable())
		if len(t.Hardening.Findings) > 0 {
			b.WriteString("\n**Hardening defects:**\n")
			for _, f := range t.Hardening.Findings {
				b.WriteString(fmt.Sprintf("- **[%s / +%d pts]** `%s`: %s (line %d)\n", strings.ToUpper(f.Severity), f.Points, f.Code, f.Message, f.Line))
			}
		}
		b.WriteString("\n")
	}

	return b.String()
}

func writeScrapeHTML(file string, result *ScrapeResult) error {
	const page = `<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>BreachBench GitHub Dockerfile Hardening Report</title>
<style>body{font:15px/1.5 system-ui;background:#10151d;color:#e3eaf3;max-width:1280px;margin:40px auto;padding:0 24px}h1{font-size:32px;margin-bottom:8px}h2{margin-top:36px}table{border-collapse:collapse;width:100%;margin:20px 0;font-size:14px}th,td{text-align:left;padding:10px 12px;border-bottom:1px solid #2a3442;vertical-align:top}th{color:#94dafe;background:#161e29}code{background:#1b2432;padding:2px 5px;border-radius:4px;font-size:13px;overflow-wrap:anywhere}a{color:#7dc8ff;text-decoration:none}a:hover{text-decoration:underline}.badge{display:inline-block;padding:2px 8px;border-radius:4px;font-weight:600;font-size:12px}.terrible{background:#5c1f24;color:#ffb7a7}.unhardened{background:#5a3e1b;color:#ffd599}.partially-hardened{background:#1e3a5f;color:#94dafe}.hardened{background:#194a3a;color:#7de0bb}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:14px;margin:24px 0}.card{background:#161e29;border:1px solid #2a3442;border-radius:8px;padding:16px}.card strong{display:block;font-size:26px;color:#53a9f4}</style>
<small>BREACHBENCH / GITHUB DOCKERFILE STAGE TRACER &amp; HARDENING SCANNER</small>
<h1>Popular GitHub Repositories: Unhardened Dockerfile Report</h1>
<p>Started {{.StartedAt}} · Finished {{.FinishedAt}} · Checked {{.Summary.TotalReposChecked}} popular repositories · Analyzed {{.Summary.ReposWithDockerfile}} Dockerfiles</p>
<div class="cards">
  <div class="card"><strong>{{.Summary.SingleStageCount}}</strong>Single-stage Dockerfiles (no multi-stage builder)</div>
  <div class="card"><strong>{{.Summary.RunsInBuildEnvCount}}</strong>Run inside build environment</div>
  <div class="card"><strong>{{.Summary.RunsAsRootCount}}</strong>Run as root (UID 0)</div>
  <div class="card"><strong>{{.Summary.UnhardenedOrTerribleCount}}</strong>Unhardened or Terrible</div>
  <div class="card"><strong>{{.Summary.TerribleCount}}</strong>Terrible (score &ge; 55)</div>
  <div class="card"><strong>{{.Summary.HardenCompatibleCount}}</strong>Ready for <code>breachbench harden</code></div>
</div>
<h2>Unhardened &amp; Single-Stage Dockerfiles (Ranked)</h2>
<table><thead><tr><th>#</th><th>Repository</th><th>Stars</th><th>Runtime</th><th>Pattern &amp; FROM Chain</th><th>Runtime Base</th><th>Startup &amp; Executable Origin</th><th>Root</th><th>Score</th><th>Defects</th></tr></thead><tbody>
{{range $i, $r := .Unhardened}}<tr>
  <td>{{inc $i}}</td>
  <td><a href="{{$r.HTMLURL}}"><strong>{{$r.FullName}}</strong></a><br><small><a href="{{$r.DockerfileURL}}">{{$r.DockerfilePath}}</a></small></td>
  <td>{{$r.Stars}}</td>
  <td><code>{{$r.Trace.DetectedRuntime}}</code></td>
  <td><code>{{$r.Trace.MultiStagePattern}}</code><br><small><code>{{join $r.Trace.FromChain " → "}}</code></small></td>
  <td><code>{{$r.Trace.RuntimeBase}}</code><br><small>({{$r.Trace.Hardening.BaseCategory}})</small></td>
  <td><code>{{$r.Trace.StartupDeclaration}}</code><br><small>{{$r.Trace.ExecutableTrace.OriginSummary}}</small></td>
  <td>{{if $r.Trace.Hardening.RunsAsRoot}}<span class="badge terrible">root</span>{{else}}<span class="badge hardened">{{$r.Trace.EffectiveUser}}</span>{{end}}</td>
  <td><span class="badge {{$r.Trace.Hardening.Classification}}">{{$r.Trace.Hardening.UnhardenedScore}} ({{$r.Trace.Hardening.Classification}})</span></td>
  <td>{{range $f := $r.Trace.Hardening.Findings}}<code>{{$f.Code}}</code> {{end}}</td>
</tr>{{end}}
</tbody></table>
<p><a href="results.json">Full JSON evidence (results.json)</a> · <a href="report.md">Markdown report (report.md)</a></p></html>`

	t, err := template.New("scrape").Funcs(template.FuncMap{
		"inc":  func(i int) int { return i + 1 },
		"join": strings.Join,
	}).Parse(page)
	if err != nil {
		return err
	}
	f, err := os.OpenFile(file, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0644)
	if err != nil {
		return err
	}
	err = t.Execute(f, result)
	return errors.Join(err, f.Close())
}
