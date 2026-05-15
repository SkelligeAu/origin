package eval

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"

	"github.com/SkelligeAu/origin/internal/canon"
)

// canonicalClaimBytes produces the canonical (RFC 8785) JSON for a claim
// EXCLUDING fields that are local-event metadata or computed-from-canonical:
//
//   - id        — computed from the canonical bytes; including it would be circular
//   - signature — same reason
//   - evaluated_at — local wall-clock time of the evaluation event; per
//     epistemic-model.v1.md §5.2 local clock NEVER participates in canonical
//     identity.
//   - derivation.occurrences_cited — occurrences are local ingestion events;
//     a claim's identity is over what was reasoned about, not over which
//     particular local logs witnessed the inputs. Including this would
//     make claim IDs vary across federation peers — the opposite of what
//     Phase 3 set out to achieve. See layer-3.md §6.
//
// Lists that participate in identity are sorted in-place so source-
// ordering differences do not break identity.
func canonicalClaimBytes(c *TrustClaim) ([]byte, error) {
	cp := *c
	sortStrings(cp.Qualifiers)
	sortStrings(cp.IdentityIDsConsumed)
	sortStrings(cp.RawEvidenceIDsConsumed)
	sortStrings(cp.Derivation.RulesFired)
	sortStrings(cp.Derivation.MissingPredicates)

	b, err := json.Marshal(cp)
	if err != nil {
		return nil, err
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	delete(m, "id")
	delete(m, "signature")
	delete(m, "evaluated_at")
	// projection_manifest_hash includes the occurrences table → varies
	// per ingestor. Excluded from canonical bytes so claim IDs are
	// federation-stable.
	delete(m, "projection_manifest_hash")
	// identities_hash includes EVERY identity-side table — adding
	// unrelated identities to the projection (e.g. a peer_reports_*
	// import) would otherwise change every claim's ID even though the
	// policy never consumed the new identities. Excluded so Phase-3.5
	// criterion 6 holds: local claims remain byte-identical unless a
	// policy explicitly consumes peer reports.
	//
	// What remains in canonical bytes — identity_ids_consumed +
	// raw_evidence_ids_consumed — is sufficient: identity ids are
	// content-addressed (same id = same fact), so naming an id is
	// equivalent to embedding the canonical envelope.
	delete(m, "identities_hash")
	if d, ok := m["derivation"].(map[string]any); ok {
		delete(d, "occurrences_cited")
	}
	b2, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	return canon.CanonicalizeJSON(b2)
}

func sortStrings(s []string) {
	if len(s) < 2 {
		return
	}
	// stdlib sort.Strings imported via internal use; keep this file's
	// imports minimal — inline a tiny insertion sort sufficient for the
	// small slices that participate in claim canonicalization.
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

func ed25519SignClaim(priv ed25519.PrivateKey, fp string, msg []byte) (string, error) {
	sig := ed25519.Sign(priv, msg)
	return fmt.Sprintf("ed25519:%s:%s", fp, base64.StdEncoding.EncodeToString(sig)), nil
}
