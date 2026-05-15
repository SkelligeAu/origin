package ingest

import (
	"bytes"
	"context"
	"encoding/json"
)

// fetchRekorByHash searches Sigstore Rekor for log entries indexed by an
// artifact SHA-256 digest. Day-1 uses Rekor purely for presence/absence:
// we record the result count without verifying envelopes deeply.
//
// Endpoint: POST https://rekor.sigstore.dev/api/v1/index/retrieve
// Body:     {"hash": "sha256:<hex>"}
// Response: a JSON array of log entry UUIDs.
func fetchRekorByHash(ctx context.Context, sha256Hex string) (rawURL string, reqBody []byte, body []byte, count int, err error) {
	rawURL = "https://rekor.sigstore.dev/api/v1/index/retrieve"
	req := map[string]string{
		"hash": "sha256:" + sha256Hex,
	}
	reqBody, err = json.Marshal(req)
	if err != nil {
		return rawURL, nil, nil, 0, err
	}
	status, body, err := httpPostJSON(ctx, rawURL, bytes.NewReader(reqBody))
	if err != nil {
		return rawURL, reqBody, nil, 0, err
	}
	// Rekor returns 200 with an empty array when no hits; that's a normal
	// outcome here, not an error.
	if status == 200 {
		var uuids []string
		if jerr := json.Unmarshal(body, &uuids); jerr == nil {
			count = len(uuids)
		}
	}
	return rawURL, reqBody, body, count, requireOK(status, body, rawURL)
}
