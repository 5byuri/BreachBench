package githubbot

import (
	"bytes"
	"context"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os/exec"
	"strings"
	"time"

	"BreachBench/breachbench/pkg/hardener"
)

const defaultBaseURL = "https://api.github.com"

var commonDockerfilePaths = []string{
	"Dockerfile",
	"docker/Dockerfile",
	"docker/api/Dockerfile",
	"api/Dockerfile",
	"backend/Dockerfile",
	".devops/cpu.Dockerfile",
}

// ScrapedRepoTarget holds a top-starred GitHub repository that was verified via regex
// to contain an unhardened distro-based Dockerfile.
type ScrapedRepoTarget struct {
	Owner             string
	Repo              string
	FullName          string
	Stars             int
	DockerfilePath    string
	DockerfileContent string
	DockerfileSHA     string
	RuntimeBaseImage  string
}

// Client wraps the GitHub REST API v3 for autonomous repository scraping,
// forking, Dockerfile patching, and Pull Request creation.
type Client struct {
	httpClient *http.Client
	token      string
	baseURL    string
}

// ResolveGitHubToken returns GITHUB_TOKEN from the environment, falling back to git credential fill.
func ResolveGitHubToken(envToken string) string {
	if tok := strings.TrimSpace(envToken); tok != "" {
		return tok
	}
	return gitCredentialToken()
}

func gitCredentialToken() string {
	cmd := exec.Command("git", "credential", "fill")
	cmd.Stdin = strings.NewReader("protocol=https\nhost=github.com\n\n")
	out, err := cmd.Output()
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "password=") {
			return strings.TrimSpace(strings.TrimPrefix(line, "password="))
		}
	}
	return ""
}

// NewClient initializes a new GitHub API client.
func NewClient(token string) *Client {
	return &Client{
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
		token:   ResolveGitHubToken(token),
		baseURL: defaultBaseURL,
	}
}

// SetBaseURL overrides the GitHub API endpoint (useful for testing or GitHub Enterprise).
func (c *Client) SetBaseURL(baseURL string) {
	c.baseURL = strings.TrimRight(baseURL, "/")
}

func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	req.Header.Set("User-Agent", "BreachBench-Hardening-Bot")
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if req.Body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
}

func (c *Client) doJSON(ctx context.Context, method, path string, reqBody any, respOut any) (int, error) {
	var bodyReader io.Reader
	if reqBody != nil {
		payload, err := json.Marshal(reqBody)
		if err != nil {
			return 0, fmt.Errorf("marshal request body: %w", err)
		}
		bodyReader = bytes.NewReader(payload)
	}

	fullURL := c.baseURL + path
	req, err := http.NewRequestWithContext(ctx, method, fullURL, bodyReader)
	if err != nil {
		return 0, fmt.Errorf("create request %s %s: %w", method, path, err)
	}
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return 0, fmt.Errorf("execute request %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()

	rawResp, err := io.ReadAll(resp.Body)
	if err != nil {
		return resp.StatusCode, fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var ghErr struct {
			Message string `json:"message"`
		}
		_ = json.Unmarshal(rawResp, &ghErr)
		if resp.StatusCode == http.StatusForbidden && strings.Contains(ghErr.Message, "Resource not accessible by personal access token") {
			if fallback := gitCredentialToken(); fallback != "" && fallback != c.token {
				c.token = fallback
				return c.doJSON(ctx, method, path, reqBody, respOut)
			}
		}
		if ghErr.Message != "" {
			return resp.StatusCode, fmt.Errorf("github api %s %s failed (HTTP %d): %s", method, path, resp.StatusCode, ghErr.Message)
		}
		return resp.StatusCode, fmt.Errorf("github api %s %s failed (HTTP %d): %s", method, path, resp.StatusCode, strings.TrimSpace(string(rawResp)))
	}

	if respOut != nil && len(rawResp) > 0 {
		if err := json.Unmarshal(rawResp, respOut); err != nil {
			return resp.StatusCode, fmt.Errorf("decode response from %s %s: %w", method, path, err)
		}
	}

	return resp.StatusCode, nil
}

// ScrapeTopStarredDistroRepos queries GitHub's highest-starred repositories in descending star order
// and walks down the list until it collects `limit` repositories that actually contain an unhardened
// Linux distro Dockerfile verified via regex.
func (c *Client) ScrapeTopStarredDistroRepos(ctx context.Context, limit int) ([]ScrapedRepoTarget, error) {
	if limit <= 0 {
		limit = 10
	}

	searchPath := "/search/repositories?q=stars:%3E45000&sort=stars&order=desc&per_page=100"
	var searchResp struct {
		Items []struct {
			FullName        string `json:"full_name"`
			StargazersCount int    `json:"stargazers_count"`
		} `json:"items"`
	}
	if _, err := c.doJSON(ctx, http.MethodGet, searchPath, nil, &searchResp); err != nil {
		return nil, fmt.Errorf("query top starred repositories: %w", err)
	}

	var results []ScrapedRepoTarget
	for _, item := range searchResp.Items {
		if len(results) >= limit {
			break
		}
		parts := strings.SplitN(item.FullName, "/", 2)
		if len(parts) != 2 {
			continue
		}
		owner, repo := parts[0], parts[1]

		for _, candidatePath := range commonDockerfilePaths {
			content, sha, err := c.fetchRawDockerfile(ctx, owner, repo, "HEAD", candidatePath)
			if err != nil {
				continue
			}
			if matched, baseImg := hardener.IsUnhardenedDistroDockerfile(content); matched {
				results = append(results, ScrapedRepoTarget{
					Owner:             owner,
					Repo:              repo,
					FullName:          item.FullName,
					Stars:             item.StargazersCount,
					DockerfilePath:    candidatePath,
					DockerfileContent: content,
					DockerfileSHA:     sha,
					RuntimeBaseImage:  baseImg,
				})
				break
			}
		}
	}

	return results, nil
}

func (c *Client) fetchRawDockerfile(ctx context.Context, owner, repo, ref, path string) (string, string, error) {
	rawURL := fmt.Sprintf("https://raw.githubusercontent.com/%s/%s/%s/%s",
		url.PathEscape(owner),
		url.PathEscape(repo),
		escapeGitRefPath(ref),
		escapeRepoFilePath(path),
	)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return "", "", err
	}
	req.Header.Set("User-Agent", "BreachBench-Hardening-Bot")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", "", fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	rawBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", "", err
	}

	header := fmt.Sprintf("blob %d\x00", len(rawBytes))
	h := sha1.New()
	h.Write([]byte(header))
	h.Write(rawBytes)
	blobSHA := hex.EncodeToString(h.Sum(nil))

	return string(rawBytes), blobSHA, nil
}

// GetAuthenticatedUser returns the login username of the authenticated GitHub user.
func (c *Client) GetAuthenticatedUser(ctx context.Context) (string, error) {
	var user struct {
		Login string `json:"login"`
	}
	if _, err := c.doJSON(ctx, http.MethodGet, "/user", nil, &user); err != nil {
		return "", err
	}
	if user.Login == "" {
		return "", fmt.Errorf("github api /user returned empty login")
	}
	return user.Login, nil
}

// EnsureFork creates or retrieves a fork of upstreamOwner/upstreamRepo under the authenticated user's account
// and polls until the fork repository is accessible and ready.
func (c *Client) EnsureFork(ctx context.Context, upstreamOwner, upstreamRepo string) (string, string, error) {
	path := fmt.Sprintf("/repos/%s/%s/forks", url.PathEscape(upstreamOwner), url.PathEscape(upstreamRepo))
	var forkResp struct {
		Name  string `json:"name"`
		Owner struct {
			Login string `json:"login"`
		} `json:"owner"`
	}
	if _, err := c.doJSON(ctx, http.MethodPost, path, map[string]any{}, &forkResp); err != nil {
		return "", "", fmt.Errorf("ensure fork for %s/%s: %w", upstreamOwner, upstreamRepo, err)
	}

	forkOwner := forkResp.Owner.Login
	forkRepo := forkResp.Name
	if forkOwner == "" {
		user, err := c.GetAuthenticatedUser(ctx)
		if err != nil {
			return "", "", fmt.Errorf("resolve fork owner: %w", err)
		}
		forkOwner = user
	}
	if forkRepo == "" {
		forkRepo = upstreamRepo
	}

	repoPath := fmt.Sprintf("/repos/%s/%s", url.PathEscape(forkOwner), url.PathEscape(forkRepo))
	for attempt := 0; attempt < 10; attempt++ {
		var repoInfo struct {
			ID            int64  `json:"id"`
			DefaultBranch string `json:"default_branch"`
		}
		_, err := c.doJSON(ctx, http.MethodGet, repoPath, nil, &repoInfo)
		if err == nil && repoInfo.ID != 0 && repoInfo.DefaultBranch != "" {
			return forkOwner, forkRepo, nil
		}

		select {
		case <-ctx.Done():
			return "", "", ctx.Err()
		case <-time.After(2 * time.Second):
		}
	}

	return "", "", fmt.Errorf("timed out waiting for fork %s/%s to become ready", forkOwner, forkRepo)
}

// GetDefaultBranch retrieves the repository's default branch name and its current HEAD commit SHA.
func (c *Client) GetDefaultBranch(ctx context.Context, owner, repo string) (string, string, error) {
	repoPath := fmt.Sprintf("/repos/%s/%s", url.PathEscape(owner), url.PathEscape(repo))
	var repoInfo struct {
		DefaultBranch string `json:"default_branch"`
	}
	if _, err := c.doJSON(ctx, http.MethodGet, repoPath, nil, &repoInfo); err == nil && repoInfo.DefaultBranch != "" {
		refPath := fmt.Sprintf("/repos/%s/%s/git/ref/heads/%s",
			url.PathEscape(owner),
			url.PathEscape(repo),
			escapeGitRefPath(repoInfo.DefaultBranch),
		)
		var refInfo struct {
			Object struct {
				SHA string `json:"sha"`
			} `json:"object"`
		}
		if _, err := c.doJSON(ctx, http.MethodGet, refPath, nil, &refInfo); err == nil && refInfo.Object.SHA != "" {
			return repoInfo.DefaultBranch, refInfo.Object.SHA, nil
		}
	}

	repoURL := fmt.Sprintf("https://github.com/%s/%s.git", owner, repo)
	out, err := exec.CommandContext(ctx, "git", "ls-remote", "--symref", repoURL, "HEAD").Output()
	if err != nil {
		return "", "", fmt.Errorf("resolve default branch for %s/%s via git ls-remote: %w", owner, repo, err)
	}

	branch := "main"
	var sha string
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "ref: refs/heads/") && strings.Contains(line, "\tHEAD") {
			rest := strings.TrimPrefix(line, "ref: refs/heads/")
			branch = strings.TrimSpace(strings.SplitN(rest, "\t", 2)[0])
		} else if strings.Contains(line, "\tHEAD") {
			sha = strings.TrimSpace(strings.SplitN(line, "\t", 2)[0])
		}
	}
	if sha == "" {
		return "", "", fmt.Errorf("empty HEAD SHA for %s/%s", owner, repo)
	}
	return branch, sha, nil
}

// GetFileContent fetches a file from the repository at the given ref and returns its decoded string content and blob SHA.
func (c *Client) GetFileContent(ctx context.Context, owner, repo, path, ref string) (string, string, error) {
	cleanPath := escapeRepoFilePath(path)
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), cleanPath)
	if ref != "" {
		apiPath += "?ref=" + url.QueryEscape(ref)
	}

	var fileInfo struct {
		Content  string `json:"content"`
		Encoding string `json:"encoding"`
		SHA      string `json:"sha"`
	}
	if _, err := c.doJSON(ctx, http.MethodGet, apiPath, nil, &fileInfo); err == nil && fileInfo.Content != "" {
		normalized := strings.ReplaceAll(fileInfo.Content, "\n", "")
		normalized = strings.ReplaceAll(normalized, "\r", "")
		decoded, err := base64.StdEncoding.DecodeString(normalized)
		if err != nil {
			return "", "", fmt.Errorf("decode base64 content for %s: %w", path, err)
		}
		return string(decoded), fileInfo.SHA, nil
	}

	targetRef := ref
	if targetRef == "" {
		targetRef = "HEAD"
	}
	return c.fetchRawDockerfile(ctx, owner, repo, targetRef, path)
}

// CreateBranch creates a new branch pointing to baseSHA on owner/repo.
func (c *Client) CreateBranch(ctx context.Context, owner, repo, newBranch, baseSHA string) error {
	refsPath := fmt.Sprintf("/repos/%s/%s/git/refs", url.PathEscape(owner), url.PathEscape(repo))
	reqBody := map[string]string{
		"ref": "refs/heads/" + strings.TrimPrefix(newBranch, "refs/heads/"),
		"sha": baseSHA,
	}
	status, err := c.doJSON(ctx, http.MethodPost, refsPath, reqBody, nil)
	if err == nil {
		return nil
	}
	if status == http.StatusUnprocessableEntity {
		updatePath := fmt.Sprintf("/repos/%s/%s/git/refs/heads/%s",
			url.PathEscape(owner),
			url.PathEscape(repo),
			escapeGitRefPath(strings.TrimPrefix(newBranch, "refs/heads/")),
		)
		updateBody := map[string]any{
			"sha":   baseSHA,
			"force": true,
		}
		if _, patchErr := c.doJSON(ctx, http.MethodPatch, updatePath, updateBody, nil); patchErr == nil {
			return nil
		}
	}
	return fmt.Errorf("create branch %s on %s/%s: %w", newBranch, owner, repo, err)
}

// UpdateFile commits newContent to path on the specified branch of owner/repo.
func (c *Client) UpdateFile(ctx context.Context, owner, repo, path, branch, message, newContent, oldFileSHA string) error {
	cleanPath := escapeRepoFilePath(path)
	apiPath := fmt.Sprintf("/repos/%s/%s/contents/%s", url.PathEscape(owner), url.PathEscape(repo), cleanPath)

	reqBody := map[string]string{
		"message": message,
		"content": base64.StdEncoding.EncodeToString([]byte(newContent)),
		"sha":     oldFileSHA,
		"branch":  branch,
	}
	if _, err := c.doJSON(ctx, http.MethodPut, apiPath, reqBody, nil); err != nil {
		return fmt.Errorf("update file %s on %s/%s (%s): %w", path, owner, repo, branch, err)
	}
	return nil
}

// CreatePullRequest opens a pull request on owner/repo and returns the resulting HTML URL.
func (c *Client) CreatePullRequest(ctx context.Context, owner, repo, title, body, headBranch, baseBranch string) (string, error) {
	apiPath := fmt.Sprintf("/repos/%s/%s/pulls", url.PathEscape(owner), url.PathEscape(repo))
	reqBody := map[string]string{
		"title": title,
		"body":  body,
		"head":  headBranch,
		"base":  baseBranch,
	}
	var prResp struct {
		HTMLURL string `json:"html_url"`
	}
	if _, err := c.doJSON(ctx, http.MethodPost, apiPath, reqBody, &prResp); err != nil {
		return "", fmt.Errorf("create pull request on %s/%s: %w", owner, repo, err)
	}
	return prResp.HTMLURL, nil
}

func escapeRepoFilePath(p string) string {
	trimmed := strings.TrimPrefix(p, "/")
	parts := strings.Split(trimmed, "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}

func escapeGitRefPath(ref string) string {
	parts := strings.Split(strings.TrimPrefix(ref, "/"), "/")
	for i, part := range parts {
		parts[i] = url.PathEscape(part)
	}
	return strings.Join(parts, "/")
}
