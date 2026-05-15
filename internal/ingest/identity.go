package ingest

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/SkelligeAu/origin/internal/raw"
)

// sigstoreIdentityIRI builds a deterministic identity IRI for a Sigstore-
// verified OIDC principal. Two attestations from the same workflow
// (different commits, different runs, different certs) collapse to the
// same identity IRI because the issuer + subject pair is stable across
// runs.
//
// Format: sigstore:fulcio:<sha256-hex(issuer + "\n" + subject)>
func sigstoreIdentityIRI(issuer, subject string) string {
	h := sha256.Sum256([]byte(issuer + "\n" + subject))
	return "sigstore:fulcio:" + hex.EncodeToString(h[:16]) // 16 bytes is plenty for collision resistance
}

// extractRepoURL pulls the GitHub repository URL out of an npm registry
// response. Handles the common cases:
//   "repository": "owner/repo"
//   "repository": { "type": "git", "url": "git+https://github.com/owner/repo.git" }
//   "repository": { "url": "https://github.com/owner/repo" }
func extractRepoURL(npmBody []byte) string {
	var raw struct {
		Repository json.RawMessage `json:"repository"`
	}
	if err := json.Unmarshal(npmBody, &raw); err != nil {
		return ""
	}
	if len(raw.Repository) == 0 {
		return ""
	}
	// String form?
	var s string
	if err := json.Unmarshal(raw.Repository, &s); err == nil && s != "" {
		return normalizeRepoURL(s)
	}
	// Object form?
	var obj struct {
		URL string `json:"url"`
	}
	if err := json.Unmarshal(raw.Repository, &obj); err == nil && obj.URL != "" {
		return normalizeRepoURL(obj.URL)
	}
	return ""
}

func normalizeRepoURL(s string) string {
	s = strings.TrimSpace(s)
	// Drop common prefixes / suffixes so the verifier can pull (owner, repo).
	for _, p := range []string{"git+ssh://git@", "git+https://", "git+http://", "git://", "git@"} {
		s = strings.TrimPrefix(s, p)
	}
	// "git@github.com:owner/repo" → "github.com/owner/repo"
	s = strings.Replace(s, "github.com:", "github.com/", 1)
	s = strings.TrimSuffix(s, ".git")
	// Ensure we return https URLs for downstream regex anchoring.
	if !strings.HasPrefix(s, "http") {
		s = "https://" + s
	}
	return s
}

// storeAttestationEvidence persists the verified provenance bundle as its
// own raw evidence record (so the assertion's evidence_id points at the
// specific bundle bytes, not the full attestations list). Returns the
// evidence id (sha256 of the bundle JSON).
func storeAttestationEvidence(
	store *raw.Store, priv ed25519.PrivateKey, fp string,
	attestor, now, attURL, name, version string, bundleJSON []byte,
) string {
	id, err := store.Put(raw.Metadata{
		Source:   "sigstore.bundle",
		Endpoint: attURL,
		RequestParams: map[string]string{
			"package":        name,
			"version":        version,
			"predicate_type": "https://slsa.dev/provenance/v1",
		},
		FetchedAt:      now,
		Fetcher:        attestor,
		ResponseStatus: 200,
	}, bundleJSON, priv, fp)
	if err != nil {
		// Should never fail for valid bundle bytes; surface loudly if it does.
		panic(fmt.Sprintf("storing attestation evidence: %v", err))
	}
	return id
}
