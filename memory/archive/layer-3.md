# Phase 3 Plan: AssertionIdentity / AssertionOccurrence Split

> **Phase 3 thesis.** The Day-1+Phase-2+Phase-2.5 implementation fuses two distinct concepts into one struct: the canonical fact (`what was asserted`) and the local ingestion event (`who wrote it down, when, in what chain position`). Phase 3 separates them. After this phase, the same fact observed by two independent ingestors produces one AssertionIdentity and two AssertionOccurrences. Federation, mirroring, third-party co-attestation, and shared provenance logs become structurally natural; without this split they would have to be retrofitted with ad-hoc co-attestation hacks, each of which would erode the epistemic model.

This is invisible to single-ingestor users. It is foundational for everything that follows.

The model is `epistemic-model.v1.md` §6.3, made structural.

---

## 1. What is currently fused

Today's `assertion.Record` carries both shapes in one struct:

```
Record {
    ID            // hash of envelope below
    Envelope {    // ←--- partially AssertionIdentity, partially AssertionOccurrence
        Subject
        Predicate
        Object
        EvidenceID
        Attestor       ←--- THIS is occurrence: who recorded it
        ObservedAt
        Normalizer
        Vocab
        Revises
    }
    IngestedAt        ←--- occurrence (Day-1 refactor pulled this off the envelope)
    Signature         ←--- occurrence: signed by this ingestor's key
    PrevChainHash     ←--- occurrence: chain position
    ChainHash         ←--- occurrence: chain position
}
```

The fusion has one concrete consequence and one structural one:

**Concrete:** `Attestor` is in the envelope. Two ingestors observing the same npm response produce different `Attestor` values, therefore different envelope hashes, therefore different assertion IDs. The system cannot recognise that two ingestors saw the same fact.

**Structural:** there is no way to express "I (this log) am importing the observation that another log already made." The current model conflates "the fact" with "this log's witnessing of the fact," so anything importable through a federation boundary either duplicates the fact (creating spurious ontological multiplicity) or rewrites it as if locally observed (lying about provenance).

Both problems disappear after the split.

---

## 2. The split

### 2.1 AssertionIdentity (what was asserted)
A content-addressable fact, anchored to evidence. Identical across observers who saw the same source bytes through the same normalizer at the same source-claimed time. Carries no information about who recorded it locally.

Fields:
- `subject`
- `predicate`
- `object`
- `evidence_id` (sha256 of the raw bytes the fact was derived from)
- `observed_at` (source-claimed time, verbatim)
- `normalizer` (versioned identifier of the procedure that produced the fact)
- `vocab` (which vocabulary version declared the predicate)
- `revises` (nullable; supersession remains an identity-level concept)

`identity_id = sha256(JCS-canonical(envelope-above))`

Two ingestors with the same `sigstore-attestation-verifier@v0.1.0` and the same pinned trust root run against the same bundle bytes and produce the same identity. Same applies to all observation-class predicates.

### 2.2 AssertionOccurrence (the local ingestion event)
The record of "this log observed this identity at this time, signed by this ingestor, in this chain position." Multiple occurrences per identity are legitimate and operationally meaningful.

Fields:
- `identity_id` (hash of the identity envelope)
- `attestor` (the recording ingestor: `ingestor:origin@0.1.0:<keyfp>`)
- `ingested_at`
- `log_id` (which log this occurrence belongs to; defaults to `log:<attestor-keyfp>`)
- `prev_chain_hash`, `chain_hash` (this log's chain position)
- `signature` (Ed25519 signature over the canonical occurrence envelope by the attestor's key)

`occurrence_id = sha256(JCS-canonical(occurrence-envelope minus chain hashes and signature))`

Note: the occurrence envelope itself is content-addressed, distinct from the identity it names. Two ingestors recording the same identity produce different occurrence IDs because their `attestor` and `log_id` differ.

### 2.3 Disjointness
The two envelopes are disjoint by field. No field appears in both. This is enforced structurally (separate Go types, separate JSONL streams) so future refactors cannot reintroduce fusion accidentally.

---

## 3. Storage layout

```
data/
├── assertions/
│   ├── identities/
│   │   └── <yyyy-mm-dd>.jsonl       # one identity envelope per line
│   └── occurrences/
│       ├── <yyyy-mm-dd>.jsonl       # one occurrence envelope per line
│       └── chain.log                # chain over OCCURRENCES, per log_id
├── claims/                          # claims reference identity IDs
├── raw/                             # unchanged
├── projections/                     # schema-bumped (see §5)
└── log-id.txt                       # local log_id; generated on first run
```

The `chain.log` becomes per-log-id (each ingestor has its own chain). When a future federation path imports another log's occurrences, they enter a separate chain segment keyed by their `log_id`, never silently merged into the local chain.

Identities are deduplicated by content hash on insert: writing an identity whose `identity_id` already exists is a no-op. Occurrences are append-only as before.

---

## 4. Schemas

### 4.1 Identity envelope (JSONL line)

```json
{
  "id": "<sha256 hex of canonical envelope below>",
  "subject":    "pkg:npm/@sigstore/sign@2.3.2",
  "predicate":  "cryptographically_verified_signature_by",
  "object":     { "kind": "iri", "iri": "sigstore:fulcio:..." },
  "evidence_id": "<sha256 of the raw bundle>",
  "observed_at": "2024-05-16T17:12:04.041Z",
  "normalizer":  "sigstore-attestation-verifier@v0.1.0",
  "vocab":       "v3",
  "revises":     null
}
```

### 4.2 Occurrence envelope (JSONL line)

```json
{
  "id":           "<sha256 hex of canonical occurrence-envelope>",
  "identity_id":  "<id of the AssertionIdentity this occurrence names>",
  "attestor":     "ingestor:origin@0.1.0:<keyfp>",
  "ingested_at":  "2026-05-14T21:34:02Z",
  "log_id":       "log:<keyfp>",
  "prev_chain_hash": "<hex>",
  "chain_hash":      "<hex>",
  "signature":       "ed25519:<keyfp>:<base64>"
}
```

The signature covers `(identity_id || attestor || ingested_at || log_id || prev_chain_hash)` in canonical form. The chain hash is `sha256(prev_chain_hash || identity_id || attestor)` — incorporating attestor into the chain so that two ingestors writing the same identity produce diverging chain heads even if they processed identities in the same order.

### 4.3 Canonical computation
Both envelopes use the existing JCS pipeline. Canonical bytes are JCS over the envelope fields excluding the computed/signature/chain fields. Identity ID = sha256(canonical identity envelope). Occurrence ID = sha256(canonical occurrence envelope minus chain hashes and signature).

---

## 5. Projection schema bump

The projection's per-predicate tables key on `identity_id` (renamed from `assertion_id`) and drop the `attestor` column from those tables. A new `occurrences` table records occurrence data.

```sql
CREATE TABLE identities (
  id            TEXT PRIMARY KEY,
  predicate     TEXT NOT NULL,
  subject       TEXT NOT NULL
);
CREATE INDEX identities_by_subject ON identities(subject);

CREATE TABLE occurrences (
  id                TEXT PRIMARY KEY,
  identity_id       TEXT NOT NULL REFERENCES identities(id),
  attestor          TEXT NOT NULL,
  ingested_at       TEXT NOT NULL,
  log_id            TEXT NOT NULL,
  prev_chain_hash   TEXT NOT NULL,
  chain_hash        TEXT NOT NULL,
  signature         TEXT NOT NULL
);
CREATE INDEX occurrences_by_identity ON occurrences(identity_id);
CREATE INDEX occurrences_by_log     ON occurrences(log_id, chain_hash);

-- Per-predicate tables: identity_id PK, attestor REMOVED
CREATE TABLE depends_on (
  identity_id   TEXT PRIMARY KEY,
  subject       TEXT NOT NULL,
  object        TEXT NOT NULL,
  observed_at   TEXT NOT NULL,
  evidence_id   TEXT NOT NULL,
  normalizer    TEXT NOT NULL,
  superseded_by TEXT
);
-- ... same shape for every other predicate table
```

Queries that previously asked "is there a current row for this subject under this predicate" still work unchanged. Queries that asked "who attested to this" now join `identities → occurrences` and may return multiple rows. Single-witness vs multi-witness becomes a first-class join, not an implicit property.

The deduplication property: writing the same identity from two ingestors produces one row in `identities` and one row in each affected predicate table; the two occurrences appear as two rows in `occurrences`. The projection naturally distinguishes "one fact, two attestors" from "two distinct facts."

---

## 6. Claim format changes

Claims consume identities. Their derivation traces cite occurrences.

```json
{
  "id": "...",
  "subject": "...",
  "policy_id": "...",
  "policy_version": "...",
  "policy_hash": "...",
  "verdict": "...",
  "qualifiers": [...],

  "identity_ids_consumed": ["<identity-id>", ...],
  "raw_evidence_ids_consumed": [...],

  "derivation": {
    "rules_fired": [...],
    "missing_predicates": [...],
    "input_counts": {...},
    "occurrences_cited": {
      "<identity-id>": ["<occurrence-id>", ...]
    }
  },

  "evaluated_at": "...",
  "evaluator_version": "...",
  "projection_manifest_hash": "...",
  "vocab_version": "...",
  "normalizer_versions": {...},
  "signature": "..."
}
```

Two consequences worth highlighting:

- **Claim identity unaffected by ingestor identity.** A claim's ID is computed over its evaluation inputs; those inputs are identity IDs (deduplicated) plus the projection manifest. The claim is byte-identical regardless of which ingestor's occurrences populated the snapshot. Federation does not change verdicts.
- **`occurrences_cited` makes corroboration visible.** A claim whose `identity_ids_consumed` includes an identity supported by three independent occurrences from three independent ingestors carries strictly more weight than one supported by a single occurrence. Policies can opt into "minimum N independent occurrences" rules; independence semantics are still informal at this phase (left open in epistemic-model.v1.md §11).

---

## 7. Verify checks

Existing checks split along the new boundary:

1. **chain integrity** — now per-log-id. Each log's chain validates independently.
2. **identity reproducibility** — for every identity in the log, recompute its canonical envelope hash and confirm it equals the stored `id`. Catches tampering of identity content.
3. **occurrence signatures** — for every occurrence, recompute the canonical occurrence envelope, verify the signature against the attestor's recorded key. The local key resolver becomes a per-`attestor` lookup (still single-key Day 3 for our log; future federation extends this).
4. **identity ↔ occurrence linkage** — every occurrence's `identity_id` resolves to an existing identity record.
5. **raw evidence resolvability** — unchanged.
6. **projection determinism** — unchanged semantics; updated schema.
7. **claim envelope consistency** — unchanged (already removes `evaluated_at`).
8. **cryptographic re-verification** — unchanged.
9. **claim re-derivation determinism** — unchanged.

The system now has nine independent verify checks, each catching a distinct failure mode.

---

## 8. Migration

The Day-1 + Phase 2 + Phase 2.5 prototype has accumulated a small log under the fused shape. Migration path:

**Replay-from-raw.** The raw evidence directory is the canonical truth source. After Phase 3 lands:
1. Wipe `data/assertions/` and `data/projections/` and `data/claims/`.
2. Re-run `origin ingest` for every previously-ingested coordinate. The new normalizers + verifier emit identity + occurrence records under the new schema. Identities are deterministic across re-ingestions.
3. Re-run `origin project` (mandatory; schema_hash will have changed).
4. Re-run `origin eval` for every previously-evaluated (subject, policy) pair. Claims under the new format reference identity IDs.

This satisfies invariant 11 (correction means supersession, never mutation) because we are not mutating old records — we are replaying the raw evidence under new code that produces new (identity, occurrence) records. The old fused records remain on the filesystem until manually deleted; they are archived under `data.legacy/` rather than overwritten.

**Out of scope for Phase 3:** importing another origin node's occurrence log over a network or filesystem boundary. The architecture supports it after Phase 3; the import path is Phase 3.5 or later.

---

## 9. Verified-form predicate under the split

The verified-form predicate (`cryptographically_verified_signature_by`) deserves explicit treatment because invariant 16 (locality) interacts with the identity/occurrence split.

**Verified-form assertions remain identity-class.** Two ingestors running the same verifier code version against the same bundle bytes against the same pinned root produce the same verified-form fact. The fact is content-addressable on (artifact bytes, OIDC identity, verifier version, root version).

**Invariant 16 still binds.** A verified-form identity may appear in a log only via an occurrence emitted by an ingestor that locally executed the verification. Importing a verified-form identity from another log without local re-verification is forbidden. At the federation boundary (Phase 3.5+) a verified-form identity arrives as a non-verified-form predicate (e.g., `peer_reports_cryptographic_verification_of`), until the local node re-runs the verifier itself.

**Practical encoding.** To make this enforceable at occurrence-write time, occurrences carry an `attestor_role` discriminator: values are `observer`, `verifier`, `federated_importer`. Only `verifier`-role occurrences may name an identity whose predicate is in the verified-form family. Federation imports always use `federated_importer` and the cryptographic_verified_* predicates are explicitly disallowed for that role. The discriminator is part of the occurrence envelope (and thus signed).

The vocabulary file gets a `verification_class` field per predicate (`observation`, `verification`, `refutation`, `structural`) so the role check is data-driven, not hardcoded.

---

## 10. Sequence of work

Each step ends compiling, all existing tests passing, and the new tests for that step landing alongside.

1. **Identity + Occurrence types.** New package `internal/identity` and `internal/occurrence`. Pure Go types, canonical encoders, content-hash computers. Migrate `internal/assertion`'s shape behind the scenes.
2. **Vocab v4.** Add `verification_class` to each predicate. v3 remains loadable.
3. **Storage layer rework.** New JSONL directories. Idempotent identity writes. Append-only occurrence writes with chain advancement.
4. **Projection schema bump.** Tables as in §5. Build/rebuild logic updated. New `schema_hash`.
5. **Ingest connectors + normalizers updated.** Emit identity envelopes; wrap each in an occurrence envelope at write time. The `Attestor` field moves from envelope to occurrence everywhere.
6. **Verifier emits identity with role=verifier.** Failure path emits identity with role=verifier (refutation class). Observation path emits identity with role=observer.
7. **Claim format updated.** `identity_ids_consumed` replaces `assertion_ids_consumed`. `derivation.occurrences_cited` added.
8. **Verify split.** Nine checks instead of seven.
9. **Migration replay.** Document the replay-from-raw procedure; ship a one-shot helper command `origin migrate-v3 --confirm` that wipes `data/assertions/`, `data/projections/`, `data/claims/`, then re-runs ingest for every coordinate present in `data/raw/`'s npm.registry source.
10. **Federation hooks (Phase 3.5 preview only).** No implementation, but document the import-from-foreign-log interface so the next phase has a clean target: `LoadForeignOccurrenceLog(path, role=federated_importer)` accepts another origin's occurrence JSONL stream, verifies each occurrence's signature against the federated peer's published public key, and writes them into a separate log_id chain locally. Verified-form predicates from foreign logs are rewritten at the boundary to `peer_reports_*` predicates (vocabulary v4 additions).
11. **End-to-end demonstration.** Two ingestors (two key pairs) against the same fixture data; verify identities deduplicate and occurrences diverge.

---

## 11. Falsifiable success criteria

Mapping the user-stated criteria to falsifiable tests:

| # | User criterion | Test |
|---|---|---|
| 1 | Same evidence normalized twice produces the same AssertionIdentity. | A normalizer-only unit test: run the npm normalizer over the same `@sigstore/sign@2.3.2` registry record twice; assert the produced identity envelope bytes (canonical) hash to the same identity_id. |
| 2 | Two different ingestors record separate AssertionOccurrences for the same identity. | Run `origin ingest` from two separate working directories with two separate key pairs against the same package; merge the two `data/assertions/occurrences/` streams; the identity tables in both projections share IDs; the occurrence tables differ by `attestor` and `log_id`. |
| 3 | Replay verifies both the identity envelope and each occurrence chain. | `origin verify` runs all nine checks. Two checks fail distinctly under tampering: tampering with identity content fails `identity reproducibility`; tampering with an occurrence's chain fails `chain integrity` for the corresponding log_id without affecting the other log. |
| 4 | Projection deduplicates by AssertionIdentity but can show all occurrences. | A SQL query against the projection: `SELECT count(*) FROM identities` is the cardinality of distinct facts; `SELECT count(*) FROM occurrences` is the total observation events. The latter is ≥ the former. |
| 5 | Claims consume AssertionIdentity IDs; derivation can cite occurrence provenance. | A claim file shape check: `identity_ids_consumed` is non-empty; `derivation.occurrences_cited` maps each consumed identity to one or more occurrence IDs; the claim ID is byte-identical regardless of which ingestor's occurrences populated the projection. |
| 6 | Existing logs migrate or replay cleanly. | `origin migrate-v3 --confirm` produces a fresh data tree; subsequent `origin verify` passes all nine checks. Prior fused-shape records remain archived under `data.legacy/`, never silently rewritten. |

A seventh implicit criterion: the existing E2E demonstration (`pkg:npm/@sigstore/sign@2.3.2` → `trusted` via `release_signing/v2`) continues to work after migration, with the same verdict and qualifiers. Federation does not change verdicts; the user-visible behaviour is preserved.

---

## 12. Explicit non-goals (Phase 3)

The user enumeration of forbidden scope additions stands as-is:

- No new ecosystems. Still npm only.
- No new policies, no policy versions.
- No HTTP API, no UI.
- No identity clustering (Identities remain keyed principals per §6.2 of the epistemic model).
- No scoring, no numeric outputs.
- No recommendation logic.
- No network federation implementation. The hooks are designed; the network code is Phase 3.5+.
- No replacement of `sigstore-go` or any verifier library.

Additions discovered during Phase 3 implementation that fall outside this list are deferred without re-scoping.

---

## 13. What this phase does NOT close

- **Actual federation across a network or filesystem boundary.** Phase 3.5 candidate. The interfaces and the data shape are designed to make this an additive change.
- **Identity entity layer in projection** (Day-1 risk #10). Identity strings remain string columns. Promoting Identity to a first-class entity table is a Phase 4 candidate.
- **OPA full-recompute model** (Day-1 risk #14). Day-3 scale does not require incremental evaluation.
- **Cross-source independence semantics.** Mentioned in `epistemic-model.v1.md` §11; still unspecified.
- **Trust root governance / rotation policy.** Same model section.
- **Cryptographic drift policy.** Same.

These are tracked. Each becomes a future-phase candidate when concrete need arises.

---

## 14. Risks discovered ahead of implementation

These are worth flagging before code begins so they get explicit treatment, not silent compromises:

- **Existing claims become unreplayable post-migration.** Their `assertion_ids_consumed` references point at old (fused) IDs. Migration regenerates claims under the new format; the originals are archived. Operators expecting to re-run historical claim queries against the legacy data tree need `data.legacy/` preserved.
- **`evidence_id` in identity assumes the raw bytes are content-addressed.** They are today. Any future relaxation of raw evidence content-addressing (e.g., supporting an external blob store) must preserve content-addressability or this property breaks.
- **`log_id` defaulting to `log:<keyfp>` couples log identity to signing-key identity.** If an operator rotates their key, the new key starts a new log_id. This is correct (a new signer is a new attestor) but the implication should be documented: rotated-key occurrences do not silently merge into the rotated-from log; they form a new log that the rotated-from log can choose to import (Phase 3.5+).
- **Occurrence canonicalization must include `attestor`.** Otherwise two ingestors could co-sign the same identity bytes and produce identical occurrence IDs from different keys — a collision that would break the property "occurrences distinguish attestors." The schema in §4.2 already includes attestor in the canonical envelope; the implementation must not omit it during refactoring.
- **The chain hash formula change (now incorporating `attestor`) breaks bytewise comparison with the pre-Phase-3 chain.** Old chain values cannot be re-derived under the new formula. The migration archives them.

---

## 15. Closing test

Phase 3 is correct if a hostile reader inspecting only on-disk artifacts can answer these:

1. *Is this fact known to the system?* → query `identities` for matching subject/predicate/object → yes/no.
2. *Who has attested to it locally?* → join `identities → occurrences` on identity_id; the result lists every (attestor, ingested_at, log_id) tuple. Counts of distinct attestors and distinct log_ids are first-class observable.
3. *Did the same evidence enter two logs separately?* → same identity_id, different `log_id` rows in `occurrences`.
4. *Has this identity been verified locally?* → identity's predicate is in the verification class AND at least one occurrence has role=verifier. Importable from another log only as a `peer_reports_*` predicate, never as the verified form.
5. *Is the verdict on this subject the same regardless of who observed the evidence?* → yes, by construction: the projection deduplicates identities, claims consume identities, claim IDs are stable across ingestor identities.

If any answer requires reading source code beyond version metadata, the phase has drifted.

---

## Coda

This split is the structurally-important move the user has been pushing for since Phase 1. Until now the cost of fusion was zero (one ingestor, one log, no federation, no co-attestation). It is still zero today, which is the right moment to do this work. Every week of delay accumulates data in the wrong shape and raises the migration cost.

Phase 3 is therefore neither feature-additive nor capability-expansive. It is the structural prerequisite that makes everything after it (federation, mirroring, third-party co-attestation, SaaS ingestion without corrupting local-first semantics) representable without ad-hoc retrofits.

After Phase 3:
- **Phase 3.5** — actual federation across logs (import path, peer-key registry, role-discriminator enforcement).
- **Phase 4** — Identity entity layer, second ecosystem (PyPI), or independence semantics — whichever the system surfaces a need for first.
