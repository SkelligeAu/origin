package project

// schemaSQL is the projection schema. Its sha256 (over the literal bytes
// of this string) is recorded as `schema_hash` in MANIFEST.json. Adding,
// renaming, or reordering anything here changes the schema_hash; old
// projections will fail to verify against new code (this is the desired
// behaviour — `origin verify` is designed to surface schema drift).
//
// Phase 3 schema:
//   - identities table: one row per AssertionIdentity (content-addressable fact).
//   - occurrences table: every local ingestion event citing an identity.
//   - per-predicate tables: key on identity_id; attestor is NOT here (it
//     belongs to occurrences). Joining identity_id → occurrences yields
//     the corroboration view.
const schemaSQL = `
CREATE TABLE IF NOT EXISTS projection_manifest (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS raw_evidence (
    id              TEXT PRIMARY KEY,
    source          TEXT NOT NULL,
    endpoint        TEXT NOT NULL,
    fetched_at      TEXT NOT NULL,
    fetcher         TEXT NOT NULL,
    response_status INTEGER NOT NULL,
    payload_path    TEXT NOT NULL,
    result_count    INTEGER
);
CREATE INDEX IF NOT EXISTS raw_evidence_by_source ON raw_evidence(source);

-- Identity: a content-addressable fact. One row per identity_id.
CREATE TABLE IF NOT EXISTS identities (
    id         TEXT PRIMARY KEY,
    predicate  TEXT NOT NULL,
    subject    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS identities_by_subject   ON identities(subject);
CREATE INDEX IF NOT EXISTS identities_by_predicate ON identities(predicate);

-- Occurrence: a local ingestion event citing an identity. Multiple
-- occurrences per identity are legitimate (federation, mirroring,
-- multiple ingestors observing the same evidence). The chain hash + log
-- id distinguish each occurrence.
CREATE TABLE IF NOT EXISTS occurrences (
    id                 TEXT PRIMARY KEY,
    identity_id        TEXT NOT NULL REFERENCES identities(id),
    attestor           TEXT NOT NULL,
    attestor_role      TEXT NOT NULL,
    ingested_at        TEXT NOT NULL,
    log_id             TEXT NOT NULL,
    prev_chain_hash    TEXT NOT NULL,
    chain_hash         TEXT NOT NULL,
    signature          TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS occurrences_by_identity ON occurrences(identity_id);
CREATE INDEX IF NOT EXISTS occurrences_by_log      ON occurrences(log_id, chain_hash);

-- Supersession history: full chain by (subject, predicate, object_key).
CREATE TABLE IF NOT EXISTS identity_history (
    subject       TEXT NOT NULL,
    predicate     TEXT NOT NULL,
    object_key    TEXT NOT NULL,
    identity_id   TEXT NOT NULL,
    revises       TEXT,
    PRIMARY KEY (subject, predicate, object_key, identity_id)
);

-- Per-predicate tables. attestor is NOT here (occurrence concern).
-- evidence_id, observed_at, normalizer ARE here (identity-level).
CREATE TABLE IF NOT EXISTS depends_on (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS depends_on_subject ON depends_on(subject) WHERE superseded_by IS NULL;
CREATE INDEX IF NOT EXISTS depends_on_object  ON depends_on(object)  WHERE superseded_by IS NULL;

CREATE TABLE IF NOT EXISTS registry_reports_signing_key (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS registry_reports_signing_key_subject
    ON registry_reports_signing_key(subject) WHERE superseded_by IS NULL;

CREATE TABLE IF NOT EXISTS cryptographically_verified_signature_by (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS cryptographically_verified_signature_by_subject
    ON cryptographically_verified_signature_by(subject) WHERE superseded_by IS NULL;

CREATE TABLE IF NOT EXISTS cryptographic_verification_failed (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS cryptographic_verification_failed_subject
    ON cryptographic_verification_failed(subject) WHERE superseded_by IS NULL;

CREATE TABLE IF NOT EXISTS published_by (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS published_by_subject ON published_by(subject) WHERE superseded_by IS NULL;

CREATE TABLE IF NOT EXISTS published_at (
    identity_id     TEXT PRIMARY KEY,
    subject         TEXT NOT NULL,
    object_literal  TEXT NOT NULL,
    object_datatype TEXT NOT NULL,
    observed_at     TEXT NOT NULL,
    evidence_id     TEXT NOT NULL,
    normalizer      TEXT NOT NULL,
    superseded_by   TEXT
);
CREATE INDEX IF NOT EXISTS published_at_subject ON published_at(subject) WHERE superseded_by IS NULL;

CREATE TABLE IF NOT EXISTS affected_by (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS affected_by_subject ON affected_by(subject) WHERE superseded_by IS NULL;

CREATE TABLE IF NOT EXISTS attests_to (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);

-- Phase 3.5: peer-report predicates. Observation-class; emitted only by
-- the federation importer (normalizer = federation-import@v0.1.0). The
-- "object" column holds a ref to the foreign identity ID. These tables
-- look like other observation tables — the policy author decides whether
-- to consume them.
CREATE TABLE IF NOT EXISTS peer_reports_cryptographic_verification_of (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS peer_reports_cryptographic_verification_of_subject
    ON peer_reports_cryptographic_verification_of(subject) WHERE superseded_by IS NULL;

CREATE TABLE IF NOT EXISTS peer_reports_cryptographic_verification_failed_of (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS peer_reports_cryptographic_verification_failed_of_subject
    ON peer_reports_cryptographic_verification_failed_of(subject) WHERE superseded_by IS NULL;

-- Phase 5: transparency-log anchor predicates. Observation class. The
-- subject is a checkpoint:<sha256> IRI; the object is the provider's
-- entry IRI (or a ref to the foreign anchor for the peer-reports form).
-- Verify check #13 cross-references these against the local chain.
CREATE TABLE IF NOT EXISTS transparency_log_records_checkpoint (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS transparency_log_records_checkpoint_subject
    ON transparency_log_records_checkpoint(subject) WHERE superseded_by IS NULL;

CREATE TABLE IF NOT EXISTS peer_reports_transparency_log_records_checkpoint_of (
    identity_id   TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS peer_reports_transparency_log_records_checkpoint_of_subject
    ON peer_reports_transparency_log_records_checkpoint_of(subject) WHERE superseded_by IS NULL;
`
