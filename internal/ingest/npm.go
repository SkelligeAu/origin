package ingest

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

// fetchNpmPackage returns the npm registry's full package document, which
// includes the per-version `time` map. Per-version endpoint
// (/registry/<name>/<version>) omits `time`, so we use the package-level
// document and slice out the version we want during normalization.
func fetchNpmPackage(ctx context.Context, name string) (rawURL string, body []byte, err error) {
	encName := url.PathEscape(name)
	rawURL = fmt.Sprintf("https://registry.npmjs.org/%s", encName)
	status, body, _, err := httpGet(ctx, rawURL)
	if err != nil {
		return rawURL, nil, err
	}
	if err := requireOK(status, body, rawURL); err != nil {
		return rawURL, body, err
	}
	return rawURL, body, nil
}

// extractNpmVersionDoc takes the full package document and extracts the
// per-version manifest plus the release timestamp for the requested
// version. Returns (versionDocBytes, releaseTimestamp).
//
// The returned versionDocBytes is the verbatim JSON of versions[version],
// augmented with a synthetic top-level "time" string so the downstream
// normalizer has both pieces in one input.
func extractNpmVersionDoc(packageBody []byte, version string) ([]byte, error) {
	var full map[string]json.RawMessage
	if err := json.Unmarshal(packageBody, &full); err != nil {
		return nil, fmt.Errorf("npm full package decode: %w", err)
	}
	versionsRaw, ok := full["versions"]
	if !ok {
		return nil, fmt.Errorf("npm package doc has no versions")
	}
	var versions map[string]json.RawMessage
	if err := json.Unmarshal(versionsRaw, &versions); err != nil {
		return nil, fmt.Errorf("npm versions decode: %w", err)
	}
	verRaw, ok := versions[version]
	if !ok {
		return nil, fmt.Errorf("npm versions missing %q", version)
	}
	// Extract time[version] if present.
	var timeMap map[string]string
	if t, ok := full["time"]; ok {
		_ = json.Unmarshal(t, &timeMap)
	}
	// Merge time into a copy of the version doc as field "time".
	var ver map[string]any
	if err := json.Unmarshal(verRaw, &ver); err != nil {
		return nil, fmt.Errorf("npm version decode: %w", err)
	}
	if ts, ok := timeMap[version]; ok && ts != "" {
		ver["time"] = ts
	}
	return json.Marshal(ver)
}
