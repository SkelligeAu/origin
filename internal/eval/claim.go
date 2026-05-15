package eval

// TrustClaim is the only output of a policy evaluation. It is a record of
// the evaluation event — NOT a "trust property" of the subject. Multiple
// claims about the same subject may exist (different policies, different
// times); none of them mutate.
//
// Phase 3 changes:
//   - IdentityIDsConsumed replaces AssertionIDsConsumed. Claims reason
//     about facts (identities, deduplicated), not about local ingestion
//     events. This makes claim identity stable across ingestors:
//     federation does not change verdicts.
//   - Derivation.OccurrencesCited maps each consumed identity to the
//     occurrence(s) that supported it. Single-witness vs corroborated
//     evidence is visible in the derivation but does not change the
//     claim's canonical bytes.
type TrustClaim struct {
	ID                     string            `json:"id"`
	Subject                string            `json:"subject"`
	PolicyID               string            `json:"policy_id"`
	PolicyVersion          string            `json:"policy_version"`
	PolicyHash             string            `json:"policy_hash"`
	Query                  string            `json:"query"`
	Verdict                string            `json:"verdict"`
	Qualifiers             []string          `json:"qualifiers"`
	EvaluatedAt            string            `json:"evaluated_at"`
	EvaluatorVersion       string            `json:"evaluator_version"`
	// IdentitiesHash is the hash of the FACT side of the projection
	// (identities + per-predicate tables + raw evidence). It is stable
	// across ingestors who observed the same evidence, which is what
	// keeps claim IDs federation-stable (layer-3.md §6).
	IdentitiesHash         string            `json:"identities_hash"`
	// ProjectionManifestHash is the hash of the FULL projection including
	// occurrences. It varies per ingestor. Recorded for local auditability
	// but EXCLUDED from canonical claim bytes.
	ProjectionManifestHash string            `json:"projection_manifest_hash"`
	VocabVersion           string            `json:"vocab_version"`
	NormalizerVersions     map[string]string `json:"normalizer_versions"`
	IdentityIDsConsumed    []string          `json:"identity_ids_consumed"`
	RawEvidenceIDsConsumed []string          `json:"raw_evidence_ids_consumed"`
	Derivation             Derivation        `json:"derivation"`
	Signature              string            `json:"signature"`
}

// Derivation is the structured proof trace.
type Derivation struct {
	RulesFired        []string            `json:"rules_fired"`
	MissingPredicates []string            `json:"missing_predicates"`
	InputCounts       map[string]int      `json:"input_counts"`
	// OccurrencesCited maps each identity_id consumed by the policy to
	// the occurrence_id(s) that supported it. Multiple occurrences mean
	// corroborated evidence. Not part of canonical identity (occurrences
	// are local events; the claim's identity is over what was reasoned
	// about, not over which local logs witnessed it).
	OccurrencesCited map[string][]string `json:"occurrences_cited,omitempty"`
}

// allowedVerdicts is the closed enum for verdict outputs.
var allowedVerdicts = map[string]bool{
	"trusted":               true,
	"conditional":           true,
	"rejected":              true,
	"insufficient_evidence": true,
}
