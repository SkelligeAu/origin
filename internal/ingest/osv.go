package ingest

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
)

// fetchOSV queries https://api.osv.dev/v1/query for vulnerabilities
// affecting (npm, name, version). The response is verbatim raw evidence.
func fetchOSV(ctx context.Context, name, version string) (rawURL string, reqBody []byte, body []byte, err error) {
	rawURL = "https://api.osv.dev/v1/query"
	req := map[string]any{
		"version": version,
		"package": map[string]string{
			"name":      name,
			"ecosystem": "npm",
		},
	}
	reqBody, err = json.Marshal(req)
	if err != nil {
		return rawURL, nil, nil, err
	}
	status, body, err := httpPostJSON(ctx, rawURL, bytes.NewReader(reqBody))
	if err != nil {
		return rawURL, reqBody, nil, err
	}
	if err := requireOK(status, body, rawURL); err != nil {
		return rawURL, reqBody, body, fmt.Errorf("osv: %w", err)
	}
	return rawURL, reqBody, body, nil
}
