package ingest

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

const userAgent = "origin/0.1.0 (+https://github.com/fitzee/origin)"

// httpGet performs a GET with a sane timeout and our UA. It returns the
// status code, response bytes, and any transport error.
func httpGet(ctx context.Context, rawURL string) (status int, body []byte, finalURL string, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return 0, nil, "", err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, "", err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return resp.StatusCode, nil, resp.Request.URL.String(), err
	}
	return resp.StatusCode, b, resp.Request.URL.String(), nil
}

// httpPostJSON POSTs a JSON body and returns status/body.
func httpPostJSON(ctx context.Context, rawURL string, body io.Reader) (status int, respBody []byte, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, body)
	if err != nil {
		return 0, nil, err
	}
	req.Header.Set("User-Agent", userAgent)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 50*1024*1024))
	if err != nil {
		return resp.StatusCode, nil, err
	}
	return resp.StatusCode, b, nil
}

// requireOK returns an error unless status is 200.
func requireOK(status int, body []byte, fetchURL string) error {
	if status == http.StatusOK {
		return nil
	}
	snippet := body
	if len(snippet) > 200 {
		snippet = snippet[:200]
	}
	return fmt.Errorf("%s: HTTP %d: %s", fetchURL, status, snippet)
}

// escape is a small helper for URL path components.
func escape(s string) string { return url.PathEscape(s) }
