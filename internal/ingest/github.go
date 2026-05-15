package ingest

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
)

// parseGitHubURL pulls (owner, repo) from a github.com URL.
func parseGitHubURL(s string) (owner, repo string, err error) {
	u, err := url.Parse(s)
	if err != nil {
		return "", "", err
	}
	host := strings.ToLower(u.Host)
	if host != "github.com" && host != "www.github.com" {
		return "", "", ErrUnsupportedHost
	}
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	if len(parts) < 2 {
		return "", "", fmt.Errorf("github URL must include owner/repo: %s", s)
	}
	owner, repo = parts[0], strings.TrimSuffix(parts[1], ".git")
	if owner == "" || repo == "" {
		return "", "", fmt.Errorf("github URL has empty owner or repo: %s", s)
	}
	return owner, repo, nil
}

// fetchRepoMeta returns the raw GitHub /repos/{owner}/{repo} JSON.
func fetchRepoMeta(ctx context.Context, owner, repo string) (rawURL string, body []byte, err error) {
	rawURL = fmt.Sprintf("https://api.github.com/repos/%s/%s", escape(owner), escape(repo))
	status, body, _, err := httpGet(ctx, rawURL)
	if err != nil {
		return rawURL, nil, err
	}
	if err := requireOK(status, body, rawURL); err != nil {
		return rawURL, body, err
	}
	return rawURL, body, nil
}

// fetchFileAtRef returns the decoded file content (and the raw API response
// for evidence storage) for a path at a git ref.
func fetchFileAtRef(ctx context.Context, owner, repo, path, ref string) (rawURL string, apiBody []byte, decoded []byte, err error) {
	rawURL = fmt.Sprintf(
		"https://api.github.com/repos/%s/%s/contents/%s",
		escape(owner), escape(repo), strings.TrimPrefix(path, "/"),
	)
	if ref != "" {
		rawURL += "?ref=" + url.QueryEscape(ref)
	}
	status, apiBody, _, err := httpGet(ctx, rawURL)
	if err != nil {
		return rawURL, nil, nil, err
	}
	if err := requireOK(status, apiBody, rawURL); err != nil {
		return rawURL, apiBody, nil, err
	}
	var resp struct {
		Encoding string `json:"encoding"`
		Content  string `json:"content"`
	}
	if err := json.Unmarshal(apiBody, &resp); err != nil {
		return rawURL, apiBody, nil, fmt.Errorf("github contents decode: %w", err)
	}
	if resp.Encoding != "base64" {
		return rawURL, apiBody, nil, fmt.Errorf("unexpected encoding %q from github", resp.Encoding)
	}
	// Strip newlines (github wraps base64 at 60 cols).
	clean := strings.ReplaceAll(resp.Content, "\n", "")
	decoded, err = base64.StdEncoding.DecodeString(clean)
	if err != nil {
		return rawURL, apiBody, nil, fmt.Errorf("base64 decode: %w", err)
	}
	return rawURL, apiBody, decoded, nil
}

// resolveNpmCoordinate reads the repo's package.json at HEAD and returns
// the npm package name + version. Day-1 supports only repos that publish
// the root package.
func resolveNpmCoordinate(ctx context.Context, owner, repo string) (
	name, version string,
	pkgJSONRawURL string, apiBody []byte, pkgBytes []byte, err error,
) {
	rawURL, apiBody, decoded, err := fetchFileAtRef(ctx, owner, repo, "package.json", "")
	if err != nil {
		return "", "", rawURL, apiBody, decoded, err
	}
	var pkg struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Private bool   `json:"private"`
	}
	if err := json.Unmarshal(decoded, &pkg); err != nil {
		return "", "", rawURL, apiBody, decoded, fmt.Errorf("package.json decode: %w", err)
	}
	if pkg.Name == "" {
		return "", "", rawURL, apiBody, decoded, errors.New("package.json has no name")
	}
	if pkg.Version == "" {
		return "", "", rawURL, apiBody, decoded, errors.New("package.json has no version")
	}
	if pkg.Private {
		return "", "", rawURL, apiBody, decoded, errors.New("package is marked private")
	}
	return pkg.Name, pkg.Version, rawURL, apiBody, decoded, nil
}
