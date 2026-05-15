package project

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/fitzee/origin/internal/assertion"
	"github.com/fitzee/origin/internal/keys"
	"github.com/fitzee/origin/internal/raw"
	"github.com/fitzee/origin/internal/vocab"
)

const projectorVersion = "origin@0.1.0/projector"

// Projection is a handle to data/projections.
type Projection struct {
	Dir          string
	DBPath       string
	ManifestPath string
}

func New(dir string) *Projection {
	return &Projection{
		Dir:          dir,
		DBPath:       filepath.Join(dir, "index.sqlite"),
		ManifestPath: filepath.Join(dir, "MANIFEST.json"),
	}
}

// Build rebuilds the projection from scratch by walking the on-disk
// identity store, local + foreign occurrence logs, and raw evidence store.
//
// Phase 3 semantics: identities deduplicate naturally (one row per
// identity_id); occurrences accumulate (one row per occurrence_id, each
// citing one identity_id).
//
// Phase 3.5 semantics: foreign occurrence logs (one per registered peer
// under data/assertions/occurrences/foreign/<peer-log-id>/) project into
// the same occurrences table; the log_id column distinguishes them.
func (p *Projection) Build(
	idents *assertion.IdentityStore,
	occs *assertion.OccurrenceLog,
	foreignOccs []*assertion.OccurrenceLog,
	rawStore *raw.Store,
) error {
	if err := os.MkdirAll(p.Dir, 0755); err != nil {
		return err
	}
	for _, f := range []string{p.DBPath, p.ManifestPath} {
		_ = os.Remove(f)
	}
	for _, ext := range []string{"-journal", "-wal", "-shm"} {
		_ = os.Remove(p.DBPath + ext)
	}

	db, err := sql.Open("sqlite", p.DBPath)
	if err != nil {
		return err
	}
	defer db.Close()
	if _, err := db.Exec(schemaSQL); err != nil {
		return fmt.Errorf("apply schema: %w", err)
	}

	tx, err := db.Begin()
	if err != nil {
		return err
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()

	if err := rawStore.Walk(func(meta raw.Metadata, _ string) error {
		return insertRawEvidence(tx, meta)
	}); err != nil {
		return fmt.Errorf("project raw evidence: %w", err)
	}

	// Identities are projected first (occurrences foreign-key on identity_id).
	var identCount int
	if err := idents.Walk(func(i assertion.Identity) error {
		identCount++
		return insertIdentity(tx, i)
	}); err != nil {
		return fmt.Errorf("project identities: %w", err)
	}

	// Occurrences are projected in chain order so the occurrences table's
	// row order reflects the chain order for any given log_id. Local
	// occurrences are projected first, then each foreign log in
	// registration order.
	var occCount int
	if err := occs.Walk(func(o assertion.Occurrence) error {
		occCount++
		return insertOccurrence(tx, o)
	}); err != nil {
		return fmt.Errorf("project local occurrences: %w", err)
	}
	for _, fo := range foreignOccs {
		if err := fo.Walk(func(o assertion.Occurrence) error {
			occCount++
			return insertOccurrence(tx, o)
		}); err != nil {
			return fmt.Errorf("project foreign occurrences (%s): %w", fo.LogID, err)
		}
	}

	activeVocab := activeVocabVersion()
	for k, v := range map[string]string{
		"projector_version":  projectorVersion,
		"vocab_version":      activeVocab,
		"schema_hash":        schemaHash(),
		"identities_count":   fmt.Sprintf("%d", identCount),
		"occurrences_count":  fmt.Sprintf("%d", occCount),
		"built_at":           time.Now().UTC().Format(time.RFC3339),
	} {
		if _, err := tx.Exec(
			`INSERT OR REPLACE INTO projection_manifest(key,value) VALUES(?,?)`,
			k, v,
		); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return err
	}
	committed = true

	projHash, err := computeProjectionHash(db)
	if err != nil {
		return fmt.Errorf("compute projection hash: %w", err)
	}
	identsHash, err := computeIdentitiesHash(db)
	if err != nil {
		return fmt.Errorf("compute identities hash: %w", err)
	}
	for _, kv := range []struct{ k, v string }{
		{"projection_hash", projHash},
		{"identities_hash", identsHash},
	} {
		if _, err := db.Exec(
			`INSERT OR REPLACE INTO projection_manifest(key,value) VALUES(?,?)`,
			kv.k, kv.v,
		); err != nil {
			return err
		}
	}
	if err := p.writeManifestSidecar(projHash, identsHash, identCount, occCount); err != nil {
		return err
	}
	return nil
}

func (p *Projection) writeManifestSidecar(projHash, identsHash string, identCount, occCount int) error {
	man := map[string]any{
		"projector_version": projectorVersion,
		"vocab_version":     activeVocabVersion(),
		"schema_hash":       schemaHash(),
		"identities_count":  identCount,
		"occurrences_count": occCount,
		"projection_hash":   projHash,
		"identities_hash":   identsHash,
		"built_at":          time.Now().UTC().Format(time.RFC3339),
	}
	out, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p.ManifestPath, out, 0644)
}

func schemaHash() string {
	h := sha256.Sum256([]byte(schemaSQL))
	return hex.EncodeToString(h[:])
}

func activeVocabVersion() string {
	v, err := vocab.LoadLatest("vocab")
	if err != nil {
		return "unknown"
	}
	return v.Version
}

func insertRawEvidence(tx *sql.Tx, meta raw.Metadata) error {
	var rc any
	if meta.ResultCount != nil {
		rc = *meta.ResultCount
	}
	_, err := tx.Exec(`
        INSERT OR IGNORE INTO raw_evidence
            (id, source, endpoint, fetched_at, fetcher, response_status, payload_path, result_count)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		meta.ID, meta.Source, meta.Endpoint, meta.FetchedAt,
		meta.Fetcher, meta.ResponseStatus, meta.PayloadPath, rc,
	)
	return err
}

func insertIdentity(tx *sql.Tx, i assertion.Identity) error {
	// identities row
	if _, err := tx.Exec(
		`INSERT OR IGNORE INTO identities (id, predicate, subject) VALUES (?, ?, ?)`,
		i.ID, i.Predicate, i.Subject,
	); err != nil {
		return err
	}

	// identity_history row
	objKey := objectKey(i.Object)
	var revises any
	if i.Revises != nil {
		revises = *i.Revises
	}
	if _, err := tx.Exec(`
        INSERT OR REPLACE INTO identity_history
            (subject, predicate, object_key, identity_id, revises)
        VALUES (?, ?, ?, ?, ?)`,
		i.Subject, i.Predicate, objKey, i.ID, revises,
	); err != nil {
		return err
	}

	// per-predicate table
	switch i.Predicate {
	case "depends_on", "registry_reports_signing_key",
		"cryptographically_verified_signature_by", "cryptographic_verification_failed",
		"published_by", "affected_by", "attests_to",
		"transparency_log_records_checkpoint":
		if i.Object.Kind != assertion.ObjectIRI {
			return fmt.Errorf("predicate %s requires IRI object; got %s", i.Predicate, i.Object.Kind)
		}
		if _, err := tx.Exec(
			fmt.Sprintf(`INSERT OR IGNORE INTO %s
                (identity_id, subject, object, observed_at, evidence_id, normalizer)
                VALUES (?, ?, ?, ?, ?, ?)`, i.Predicate),
			i.ID, i.Subject, i.Object.IRI, i.ObservedAt, i.EvidenceID, i.Normalizer,
		); err != nil {
			return err
		}
	case "peer_reports_cryptographic_verification_of",
		"peer_reports_cryptographic_verification_failed_of",
		"peer_reports_transparency_log_records_checkpoint_of":
		// Object is a ref to a foreign identity ID.
		if i.Object.Kind != assertion.ObjectRef {
			return fmt.Errorf("predicate %s requires ref object; got %s", i.Predicate, i.Object.Kind)
		}
		if _, err := tx.Exec(
			fmt.Sprintf(`INSERT OR IGNORE INTO %s
                (identity_id, subject, object, observed_at, evidence_id, normalizer)
                VALUES (?, ?, ?, ?, ?, ?)`, i.Predicate),
			i.ID, i.Subject, i.Object.Ref, i.ObservedAt, i.EvidenceID, i.Normalizer,
		); err != nil {
			return err
		}
	case "published_at":
		if i.Object.Kind != assertion.ObjectLiteral {
			return fmt.Errorf("predicate published_at requires literal object")
		}
		if _, err := tx.Exec(`INSERT OR IGNORE INTO published_at
            (identity_id, subject, object_literal, object_datatype, observed_at, evidence_id, normalizer)
            VALUES (?, ?, ?, ?, ?, ?, ?)`,
			i.ID, i.Subject, i.Object.Literal, i.Object.Datatype, i.ObservedAt, i.EvidenceID, i.Normalizer,
		); err != nil {
			return err
		}
	case "revises", "derived_from":
		// Structural predicates exist only in identity_history above.
	default:
		return fmt.Errorf("unknown predicate %q", i.Predicate)
	}

	// Supersession: if this identity revises a prior, mark the prior as
	// superseded in its predicate table.
	if i.Revises != nil && *i.Revises != "" {
		var priorPred string
		err := tx.QueryRow(
			`SELECT predicate FROM identities WHERE id = ?`,
			*i.Revises,
		).Scan(&priorPred)
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("lookup revises target: %w", err)
		}
		if priorPred != "" {
			if _, err := tx.Exec(
				fmt.Sprintf(`UPDATE %s SET superseded_by = ? WHERE identity_id = ?`, priorPred),
				i.ID, *i.Revises,
			); err != nil {
				return fmt.Errorf("apply supersession: %w", err)
			}
		}
	}
	return nil
}

func insertOccurrence(tx *sql.Tx, o assertion.Occurrence) error {
	_, err := tx.Exec(`
        INSERT OR IGNORE INTO occurrences
            (id, identity_id, attestor, attestor_role, ingested_at, log_id, prev_chain_hash, chain_hash, signature)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		o.ID, o.IdentityID, o.Attestor, string(o.AttestorRole),
		o.IngestedAt, o.LogID, o.PrevChainHash, o.ChainHash, o.Signature,
	)
	return err
}

func objectKey(o assertion.Object) string {
	switch o.Kind {
	case assertion.ObjectIRI:
		return "iri:" + o.IRI
	case assertion.ObjectLiteral:
		return "lit:" + o.Datatype + ":" + o.Literal
	case assertion.ObjectRef:
		return "ref:" + o.Ref
	default:
		return "unknown:" + string(o.Kind)
	}
}

// computeProjectionHash hashes the contents of every projected table in
// canonical order. Identical projections produce identical hashes; any
// drift surfaces via `origin verify`. This hash varies per ingestor
// because the occurrences table varies (different log_id / attestor).
func computeProjectionHash(db *sql.DB) (string, error) {
	return hashTables(db, allTablesForProjectionHash())
}

// computeIdentitiesHash hashes only the FACT side of the projection —
// identities, identity_history, raw_evidence, and the per-predicate
// tables. It deliberately omits the occurrences table because
// occurrences are local ingestion events that vary across ingestors who
// observed the same evidence. Two ingestors with identical raw evidence
// + identical normalizer/verifier versions produce the same
// identities_hash. This is what TrustClaim canonical bytes should
// reference (layer-3.md §6: claim IDs stable across ingestors).
func computeIdentitiesHash(db *sql.DB) (string, error) {
	return hashTables(db, factTablesOnly())
}

func allTablesForProjectionHash() []tableSpec {
	// Full-fidelity hash for the local replay-determinism check. Includes
	// every column of every table so any single-byte projection drift
	// surfaces via verify. Used by computeProjectionHash; varies per
	// ingestor (occurrences and raw_evidence local fields).
	return []tableSpec{
		{"raw_evidence",
			`SELECT id, source, endpoint, fetched_at, fetcher, response_status, payload_path, COALESCE(result_count,-1)
             FROM raw_evidence ORDER BY id ASC`},
		{"identities",
			`SELECT id, predicate, subject FROM identities ORDER BY id ASC`},
		{"occurrences",
			`SELECT id, identity_id, attestor, attestor_role, ingested_at, log_id, prev_chain_hash, chain_hash, signature
             FROM occurrences ORDER BY id ASC`},
		{"identity_history",
			`SELECT subject, predicate, object_key, identity_id, COALESCE(revises,'')
             FROM identity_history ORDER BY subject, predicate, object_key, identity_id`},
		{"depends_on", perPredicateQuery("depends_on")},
		{"registry_reports_signing_key", perPredicateQuery("registry_reports_signing_key")},
		{"cryptographically_verified_signature_by", perPredicateQuery("cryptographically_verified_signature_by")},
		{"cryptographic_verification_failed", perPredicateQuery("cryptographic_verification_failed")},
		{"published_by", perPredicateQuery("published_by")},
		{"affected_by", perPredicateQuery("affected_by")},
		{"attests_to", perPredicateQuery("attests_to")},
		{"peer_reports_cryptographic_verification_of", perPredicateQuery("peer_reports_cryptographic_verification_of")},
		{"peer_reports_cryptographic_verification_failed_of", perPredicateQuery("peer_reports_cryptographic_verification_failed_of")},
		{"transparency_log_records_checkpoint", perPredicateQuery("transparency_log_records_checkpoint")},
		{"peer_reports_transparency_log_records_checkpoint_of", perPredicateQuery("peer_reports_transparency_log_records_checkpoint_of")},
		{"published_at",
			`SELECT identity_id, subject, object_literal, object_datatype, observed_at, evidence_id, normalizer, COALESCE(superseded_by,'')
             FROM published_at ORDER BY identity_id ASC`},
	}
}

func factTablesOnly() []tableSpec {
	// Federation-stable fact-side hash. Excludes:
	//   - the occurrences table entirely (local ingestion events)
	//   - raw_evidence local-event fields (fetched_at, fetcher, payload_path)
	// Two ingestors who saw the same evidence under the same vocab +
	// normalizer versions produce the same identities_hash.
	return []tableSpec{
		{"raw_evidence",
			`SELECT id, source, endpoint, response_status, COALESCE(result_count,-1)
             FROM raw_evidence ORDER BY id ASC`},
		{"identities",
			`SELECT id, predicate, subject FROM identities ORDER BY id ASC`},
		{"identity_history",
			`SELECT subject, predicate, object_key, identity_id, COALESCE(revises,'')
             FROM identity_history ORDER BY subject, predicate, object_key, identity_id`},
		{"depends_on", perPredicateQuery("depends_on")},
		{"registry_reports_signing_key", perPredicateQuery("registry_reports_signing_key")},
		{"cryptographically_verified_signature_by", perPredicateQuery("cryptographically_verified_signature_by")},
		{"cryptographic_verification_failed", perPredicateQuery("cryptographic_verification_failed")},
		{"published_by", perPredicateQuery("published_by")},
		{"affected_by", perPredicateQuery("affected_by")},
		{"attests_to", perPredicateQuery("attests_to")},
		{"peer_reports_cryptographic_verification_of", perPredicateQuery("peer_reports_cryptographic_verification_of")},
		{"peer_reports_cryptographic_verification_failed_of", perPredicateQuery("peer_reports_cryptographic_verification_failed_of")},
		{"transparency_log_records_checkpoint", perPredicateQuery("transparency_log_records_checkpoint")},
		{"peer_reports_transparency_log_records_checkpoint_of", perPredicateQuery("peer_reports_transparency_log_records_checkpoint_of")},
		{"published_at",
			`SELECT identity_id, subject, object_literal, object_datatype, observed_at, evidence_id, normalizer, COALESCE(superseded_by,'')
             FROM published_at ORDER BY identity_id ASC`},
	}
}

type tableSpec struct {
	name, query string
}

func hashTables(db *sql.DB, tables []tableSpec) (string, error) {
	h := sha256.New()
	for _, t := range tables {
		fmt.Fprintf(h, "TABLE %s\n", t.name)
		rows, err := db.Query(t.query)
		if err != nil {
			return "", fmt.Errorf("hash %s: %w", t.name, err)
		}
		cols, _ := rows.Columns()
		for rows.Next() {
			vals := make([]any, len(cols))
			ptrs := make([]any, len(cols))
			for i := range vals {
				ptrs[i] = &vals[i]
			}
			if err := rows.Scan(ptrs...); err != nil {
				rows.Close()
				return "", err
			}
			parts := make([]string, len(vals))
			for i, v := range vals {
				parts[i] = fmt.Sprintf("%v", v)
			}
			fmt.Fprintln(h, strings.Join(parts, "\t"))
		}
		if err := rows.Err(); err != nil {
			rows.Close()
			return "", err
		}
		rows.Close()
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func perPredicateQuery(table string) string {
	return fmt.Sprintf(`SELECT identity_id, subject, object, observed_at, evidence_id, normalizer, COALESCE(superseded_by,'')
                        FROM %s ORDER BY identity_id ASC`, table)
}

// suppress unused-keys import (used elsewhere when this file co-evolves).
var _ = keys.ResolveLogID
