package eval

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"sort"
)

// Snapshot is the input handed to OPA. It is a closed view of the
// projection: only the rows the policy declared interest in.
//
// Phase 3 semantics:
//   - predicate rows are deduplicated by identity_id (one row per fact).
//   - the snapshot also carries per-identity occurrence lists so policies
//     and derivations can reason about corroboration (multiple ingestors
//     citing the same identity).
//   - ConsumedIdentityIDs is what claims record; ConsumedOccurrenceIDs
//     populates derivation.occurrences_cited.
type Snapshot struct {
	Subject  string                      `json:"subject"`
	ByPred   map[string][]map[string]any `json:"-"`
	RawEv    []map[string]any            `json:"raw_evidence"`
	Consumed Consumed                    `json:"-"`
}

// Consumed lists the IDs collected from the snapshot.
type Consumed struct {
	IdentityIDs          []string
	OccurrencesByID      map[string][]string // identity_id → [occurrence_id, ...]
	RawEvidenceIDs       []string
	NormalizerVers       map[string]string
}

// buildSnapshot pulls the rows the policy declares interest in.
func buildSnapshot(db *sql.DB, subject string, m *PolicyManifest) (*Snapshot, error) {
	snap := &Snapshot{
		Subject: subject,
		ByPred:  map[string][]map[string]any{},
		Consumed: Consumed{
			OccurrencesByID: map[string][]string{},
			NormalizerVers:  map[string]string{},
		},
	}

	subjects := []string{subject}
	if m.NeighborhoodDepth >= 1 {
		rows, err := db.Query(
			`SELECT DISTINCT object FROM depends_on WHERE subject = ? AND superseded_by IS NULL`,
			subject,
		)
		if err != nil {
			return nil, fmt.Errorf("neighborhood query: %w", err)
		}
		for rows.Next() {
			var obj string
			if err := rows.Scan(&obj); err != nil {
				rows.Close()
				return nil, err
			}
			subjects = append(subjects, obj)
		}
		rows.Close()
	}

	for _, pred := range m.RequiredPredicates {
		rows, err := queryPredicate(db, pred, subjects)
		if err != nil {
			return nil, fmt.Errorf("predicate %s: %w", pred, err)
		}
		snap.ByPred[pred] = rows
		for _, r := range rows {
			id, _ := r["identity_id"].(string)
			if id != "" {
				snap.Consumed.IdentityIDs = append(snap.Consumed.IdentityIDs, id)
				occs, err := queryOccurrencesForIdentity(db, id)
				if err != nil {
					return nil, fmt.Errorf("occurrences for %s: %w", id, err)
				}
				snap.Consumed.OccurrencesByID[id] = occs
			}
			if eid, ok := r["evidence_id"].(string); ok && eid != "" {
				snap.Consumed.RawEvidenceIDs = append(snap.Consumed.RawEvidenceIDs, eid)
			}
			if nv, ok := r["normalizer"].(string); ok {
				if name, ver := splitNormalizer(nv); name != "" {
					snap.Consumed.NormalizerVers[name] = ver
				}
			}
		}
	}

	for _, src := range m.RequiredRawSources {
		rows, err := queryRawEvidence(db, src)
		if err != nil {
			return nil, fmt.Errorf("raw_evidence for %s: %w", src, err)
		}
		snap.RawEv = append(snap.RawEv, rows...)
		for _, r := range rows {
			if id, ok := r["id"].(string); ok {
				snap.Consumed.RawEvidenceIDs = append(snap.Consumed.RawEvidenceIDs, id)
			}
		}
	}

	snap.Consumed.IdentityIDs = dedupSorted(snap.Consumed.IdentityIDs)
	snap.Consumed.RawEvidenceIDs = dedupSorted(snap.Consumed.RawEvidenceIDs)
	for k, v := range snap.Consumed.OccurrencesByID {
		snap.Consumed.OccurrencesByID[k] = dedupSorted(v)
	}
	return snap, nil
}

func (s *Snapshot) asOPAInput() map[string]any {
	out := map[string]any{
		"subject":      s.Subject,
		"raw_evidence": s.RawEv,
	}
	for pred, rows := range s.ByPred {
		out[pred] = rows
	}
	return out
}

func (s *Snapshot) inputCounts() map[string]int {
	out := map[string]int{
		"raw_evidence": len(s.RawEv),
	}
	for pred, rows := range s.ByPred {
		out[pred] = len(rows)
	}
	return out
}

func queryPredicate(db *sql.DB, pred string, subjects []string) ([]map[string]any, error) {
	cols, q := predicateQuery(pred)
	if q == "" {
		return nil, fmt.Errorf("no projection for predicate %q", pred)
	}
	placeholders := make([]string, len(subjects))
	args := make([]any, len(subjects))
	for i, s := range subjects {
		placeholders[i] = "?"
		args[i] = s
	}
	sql := fmt.Sprintf(`%s WHERE subject IN (%s) ORDER BY identity_id ASC`,
		q, joinComma(placeholders))
	rows, err := db.Query(sql, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			v := coerce(vals[i])
			if c == "superseded_by" && v == nil {
				continue
			}
			m[c] = v
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

func predicateQuery(pred string) ([]string, string) {
	switch pred {
	case "depends_on", "registry_reports_signing_key",
		"cryptographically_verified_signature_by", "cryptographic_verification_failed",
		"published_by", "affected_by", "attests_to",
		"peer_reports_cryptographic_verification_of",
		"peer_reports_cryptographic_verification_failed_of",
		"transparency_log_records_checkpoint",
		"peer_reports_transparency_log_records_checkpoint_of":
		cols := []string{"identity_id", "subject", "object", "observed_at", "evidence_id", "normalizer", "superseded_by"}
		return cols, fmt.Sprintf(`SELECT %s FROM %s`, joinComma(cols), pred)
	case "published_at":
		cols := []string{"identity_id", "subject", "object_literal", "object_datatype", "observed_at", "evidence_id", "normalizer", "superseded_by"}
		return cols, fmt.Sprintf(`SELECT %s FROM published_at`, joinComma(cols))
	}
	return nil, ""
}

func queryRawEvidence(db *sql.DB, source string) ([]map[string]any, error) {
	rows, err := db.Query(
		`SELECT id, source, endpoint, fetched_at, fetcher, response_status, payload_path, COALESCE(result_count, -1)
         FROM raw_evidence WHERE source = ? ORDER BY id ASC`,
		source,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	cols := []string{"id", "source", "endpoint", "fetched_at", "fetcher", "response_status", "payload_path", "result_count"}
	var out []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			return nil, err
		}
		m := make(map[string]any, len(cols))
		for i, c := range cols {
			v := coerce(vals[i])
			if c == "result_count" {
				if iv, ok := v.(int64); ok && iv == -1 {
					v = nil
				}
			}
			m[c] = v
		}
		out = append(out, m)
	}
	return out, rows.Err()
}

// queryOccurrencesForIdentity returns the occurrence IDs that cite an
// identity_id, ordered by chain position. Multiple occurrences mean
// corroborated evidence (multiple ingestors / federation imports).
func queryOccurrencesForIdentity(db *sql.DB, identityID string) ([]string, error) {
	rows, err := db.Query(
		`SELECT id FROM occurrences WHERE identity_id = ? ORDER BY ingested_at ASC, id ASC`,
		identityID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		out = append(out, id)
	}
	return out, rows.Err()
}

func coerce(v any) any {
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return v
}

func dedupSorted(in []string) []string {
	if len(in) == 0 {
		return in
	}
	sort.Strings(in)
	out := in[:1]
	for i := 1; i < len(in); i++ {
		if in[i] != in[i-1] {
			out = append(out, in[i])
		}
	}
	return out
}

func splitNormalizer(nv string) (name, version string) {
	for i := 0; i < len(nv); i++ {
		if nv[i] == '@' {
			return nv[:i], nv[i+1:]
		}
	}
	return nv, ""
}

func joinComma(parts []string) string {
	out := ""
	for i, p := range parts {
		if i > 0 {
			out += ", "
		}
		out += p
	}
	return out
}

func (s *Snapshot) asJSON() string {
	b, _ := json.MarshalIndent(s.asOPAInput(), "", "  ")
	return string(b)
}
