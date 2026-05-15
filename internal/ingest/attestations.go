package ingest

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
)

// PredicateTypeSLSAProvenanceV1 is the in-toto predicate type for SLSA
// Provenance v1 statements — the attestation form we verify Day-1.
const PredicateTypeSLSAProvenanceV1 = "https://slsa.dev/provenance/v1"

// AttestationEntry mirrors one entry of npm's /-/npm/v1/attestations
// response: a predicateType + an opaque "bundle" object that is a
// Sigstore bundle.
type AttestationEntry struct {
	PredicateType string          `json:"predicateType"`
	Bundle        json.RawMessage `json:"bundle"`
}

type attestationsResponse struct {
	Attestations []AttestationEntry `json:"attestations"`
}

// fetchNpmAttestations queries the npm attestations endpoint for
// "<name>@<version>" and returns the parsed list of attestation entries.
//
// The endpoint is documented at
// https://docs.npmjs.com/generating-provenance-statements and returns
// either a list of attestations or a 404 for packages without
// provenance. 404 is treated as "no attestations available" — a normal
// outcome — not an error.
func fetchNpmAttestations(ctx context.Context, name, version string) (
	rawURL string, body []byte, parsed *attestationsResponse, err error,
) {
	encName := url.PathEscape(name)
	encV := url.PathEscape(version)
	rawURL = fmt.Sprintf("https://registry.npmjs.org/-/npm/v1/attestations/%s@%s", encName, encV)
	status, body, _, err := httpGet(ctx, rawURL)
	if err != nil {
		return rawURL, nil, nil, err
	}
	if status == 404 {
		// "No attestations" is a legitimate, common outcome. Return an empty
		// parsed response so the caller's loop is a no-op.
		return rawURL, body, &attestationsResponse{}, nil
	}
	if err := requireOK(status, body, rawURL); err != nil {
		return rawURL, body, nil, err
	}
	var r attestationsResponse
	if jerr := json.Unmarshal(body, &r); jerr != nil {
		return rawURL, body, nil, fmt.Errorf("attestations decode: %w", jerr)
	}
	return rawURL, body, &r, nil
}

// findSLSAProvenance returns the first SLSA Provenance v1 entry in the
// list, or ErrNoSLSAProvenance if none is present.
func findSLSAProvenance(entries []AttestationEntry) (AttestationEntry, error) {
	for _, e := range entries {
		if e.PredicateType == PredicateTypeSLSAProvenanceV1 {
			return e, nil
		}
	}
	return AttestationEntry{}, ErrNoSLSAProvenance
}

// ErrNoSLSAProvenance is returned when an attestations response exists
// but contains no SLSA Provenance v1 entry. (npm's own publish
// attestation is also present but is signed with a static npm key, not
// Fulcio, so it falls outside this verifier's scope.)
var ErrNoSLSAProvenance = errors.New("no SLSA Provenance v1 attestation present")
