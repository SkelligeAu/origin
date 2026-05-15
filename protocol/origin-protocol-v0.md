# Origin Protocol, version 0

**Status:** v0. This document specifies the canonical data, behaviour, and conformance requirements for an Origin-conformant implementation.

**Revision:** `v0.1.0` (2026-05-15). The full revision policy is normative and lives in §0.1.

**Authoritative.** Implementation behaviour MUST conform to this document. Where the implementation diverges from this document, either the implementation is incorrect or a new revision is required (see §0.1 for what change class is required). Silent edits to this document are forbidden.

**Out of scope.** Future revisions (v1+) will incorporate independence semantics for corroboration, an identity-entity layer, inclusion-proof verification against transparency logs, and other open items from `memory/epistemic-model.v1.md` §11. None of those are normative here.

---

## 0. Notation and conformance

This document uses the keywords MUST, MUST NOT, SHOULD, SHOULD NOT, and MAY per RFC 2119, restricted to the lowercase rendering where the visual emphasis is unnecessary.

An "Origin v0 implementation" is software that produces and verifies the artefacts defined in §3–§11 such that the byte-equality requirements in §14 hold against the test fixtures in `protocol/v0-fixtures/`. An implementation MAY add features beyond v0; it MUST NOT relax v0 requirements.

Cryptographic primitives referenced:

- **JCS** — JSON Canonicalization Scheme, RFC 8785.
- **SHA-256** — FIPS 180-4.
- **Ed25519** — RFC 8032.

All identifiers and signatures use lowercase hexadecimal encoding unless otherwise specified.

### 0.1 Specification revisioning

This specification is versioned independently of implementation releases.

The spec carries a `Revision:` line at the top of the document. An implementation is conformant to the exact revision named there, e.g. `v0.1.0`.

Revision classes:

- **Patch** (`v0.N.M`) — editorial corrections, typo fixes, clarifications, and non-normative examples. A patch revision MUST NOT change any canonical bytes produced by a conformant implementation, MUST NOT change fixture expected outputs, MUST NOT add or remove verification requirements, and MUST NOT alter conformance language.
- **Minor** (`v0.N.0`) — additive protocol changes only. A minor revision MAY add predicates, fixtures, optional behaviours, verify checks, or conformance requirements. A minor revision MUST NOT change canonical bytes for existing artefacts, MUST NOT alter existing fixture expected outputs, MUST NOT relax a MUST, and MUST NOT redefine existing predicates, envelope fields, verification classes, or federation rewrite rules.
- **Major** (`vN.0.0`) — breaking semantic or canonical changes. A major revision is required for any change that alters canonical bytes for an existing artefact, removes or redefines a verify check, changes an existing envelope field's meaning, alters the federation rewrite rule, changes no-laundering semantics, or relaxes an existing MUST. A major revision MUST use a new spec file (e.g., `origin-protocol-v1.md`) and MUST provide a fresh fixture corpus.

Existing minor revisions remain valid conformance targets. For example, an implementation conforming to `v0.1.0` remains honestly labelled `v0.1.0-conformant` after `v0.2.0` is published, but it is not `v0.2.0-conformant` unless it implements the new mandatory requirements.

Fixture policy:

- Each spec revision names the fixture corpus it governs.
- Patch revisions MUST NOT alter existing fixtures.
- Minor revisions MAY add fixtures but MUST NOT change existing fixture bytes or expected IDs.
- Major revisions MAY replace the fixture corpus, but prior fixture corpora remain archived.

Every spec revision MUST add one row to the Document history table identifying the revision, date, class, and rationale.

---

## 1. Terms

- **Identity** — A content-addressable canonical fact (§3). Identical bytes across observers; serves as the unit of deduplication.
- **Occurrence** — A local ingestion event citing an Identity (§4). One per local recording of a fact; signed by the ingestor.
- **TrustClaim** (or "claim") — The persisted output of a policy evaluation (§5). Records the verdict, the inputs consumed, and the derivation.
- **Raw evidence** — Verbatim bytes from an external source, content-addressed, with a signed metadata sidecar (§6).
- **Attestor** — An identity (in the §1-keyed-principal sense) recording an Occurrence. Distinct from "Identity" the type.
- **Attestor role** — One of {observer, verifier, federated_importer} (§4.4).
- **Verification class** — Property of a predicate, one of {observation, verification, refutation, structural} (§7.2).
- **Log** — A per-`log_id` append-only stream of Occurrences plus its chain.log (§9).
- **Vocabulary** — A versioned, signed document declaring the set of valid predicates and their verification classes (§7).
- **Peer** — Another Origin v0 implementation whose log can be imported (§10).
- **Checkpoint** — A signed snapshot of a local log at one moment, of the form `{log_id, seq, chain_hash, signed_at}` plus an Ed25519 signature (§11.1). Content-addressable; named in identities by the IRI `checkpoint:<sha256>`.
- **Anchor** — An observation-class Identity whose predicate is `transparency_log_records_checkpoint`, citing a Checkpoint as its subject and the transparency provider's response as its raw evidence (§11.2). Records that the local node submitted a Checkpoint to an external transparency system; does not assert that the provider is honest.

---

## 2. Document conventions

### 2.1 Canonical JSON

Whenever a "canonical encoding" of a value is specified, the implementation MUST produce that encoding by applying JCS (RFC 8785) to the JSON form of the value. JCS sorts object keys by their UTF-16 code-unit sequence, removes insignificant whitespace, and constrains string and number serialisations.

Implementations MUST reject values that contain JSON floating-point numbers. Numeric fields in v0 envelopes are either integers (e.g., HTTP status codes) or strings (e.g., timestamps). Float values are not part of the v0 schema and MUST NOT be introduced by an implementation.

### 2.2 Time

Timestamps are RFC 3339 strings in UTC. Implementations SHOULD use second precision; sub-second precision is permitted only where the source data provides it (e.g., an npm registry's `time.<version>` may carry milliseconds). Implementations MUST preserve source-provided timestamp strings verbatim — no rounding, no reformatting, no locale-dependent normalisation.

### 2.3 Hashes

A "hash" without further qualification is SHA-256, encoded as 64 lowercase hexadecimal characters.

### 2.4 Identifiers

- A **content hash** is the SHA-256 of canonical bytes.
- A **fingerprint** of an Ed25519 public key is the first 16 hex characters of `SHA-256(public_key_bytes)`.
- A **log_id** is the string `log:<fingerprint>` by default; implementations MAY allow operator override (typically via a file like `data/log-id.txt`) but MUST refuse to import another peer's log under the local node's log_id.

---

## 3. Identity envelope

An Identity is a canonical fact. Its envelope fields are listed below in the order required by JCS canonicalization (alphabetical by JSON key when canonicalised; the order shown is informative).

### 3.1 Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `evidence_id` | string (hex) | yes | Content hash of the raw evidence backing the fact. |
| `normalizer` | string | yes | Versioned identifier of the procedure that produced this Identity. Form: `<name>@<version>`. |
| `object` | object | yes | The object position. See §3.3. |
| `observed_at` | string (RFC 3339) | yes | The source-claimed time, verbatim. |
| `predicate` | string | yes | The predicate name. MUST be declared in the active vocabulary. |
| `revises` | string (hex) or null | yes | If non-null, the ID of an Identity this one supersedes. |
| `subject` | string | yes | The subject IRI (e.g., a PURL). |
| `vocab` | string | yes | The vocabulary version the predicate was looked up in. |

The Identity record carries an additional `id` field at the JSON top level (§3.2). The `id` is NOT part of the canonical envelope.

### 3.2 ID computation

```
canonical_bytes = JCS(envelope_fields_above)
id = SHA-256(canonical_bytes), lowercase hex
```

`id` is deterministic. Two implementations that compute the canonical form of the same envelope MUST produce the same `id`. The fixture in `protocol/v0-fixtures/identity/` confirms this byte-for-byte.

### 3.3 Object types

The `object` field is a discriminated union with a `kind` discriminator. Exactly one of three forms appears:

```
{ "kind": "iri",     "iri":     "<string>" }
{ "kind": "literal", "literal": "<string>", "datatype": "<string>" }
{ "kind": "ref",     "ref":     "<string>" }
```

- `iri` — the object is an external identifier (PURL, OIDC subject, vulnerability IRI, etc.).
- `literal` — the object is a typed literal value; `datatype` is required (e.g., `"xsd:dateTime"`).
- `ref` — the object is a reference to another Identity ID (e.g., the rewritten object in `peer_reports_*` predicates names a foreign Identity).

Other fields MUST be absent.

### 3.4 Validation

Implementations MUST reject Identities where:

- any required field is missing or empty;
- `observed_at` does not parse as RFC 3339;
- `object` is not a valid form per §3.3;
- `predicate` is not declared in the active vocabulary (§7).

Implementations MUST NOT mutate stored Identities. Corrections are encoded via `revises` (§8.2).

---

## 4. Occurrence envelope

An Occurrence is a local ingestion event citing an Identity. Multiple Occurrences may cite the same Identity (multiple ingestors, federation, etc.).

### 4.1 Fields

| Field | Type | Required | Description |
|---|---|---|---|
| `attestor` | string | yes | The recorder of this Occurrence (e.g., `ingestor:origin@0.1.0:<fp>` or `peer:<peer-log-id>`). |
| `attestor_role` | string | yes | One of `observer`, `verifier`, `federated_importer` (§4.4). |
| `identity_id` | string (hex) | yes | The Identity this Occurrence cites. |
| `ingested_at` | string (RFC 3339) | yes | The local recording time. |
| `log_id` | string | yes | The log this Occurrence belongs to. |
| `prev_chain_hash` | string (hex) | yes | Previous chain head; `0x00...00` for the first Occurrence in a log (§9.2). |

The Occurrence record carries three additional top-level fields not part of the canonical envelope: `id`, `chain_hash`, `signature`.

### 4.2 ID computation

```
canonical_bytes = JCS(envelope_fields_above)
id = SHA-256(canonical_bytes), lowercase hex
```

Note: `attestor` IS part of canonical bytes. Two ingestors recording the same Identity produce different Occurrence IDs because their `attestor` differs.

### 4.3 Signature

```
signature = "ed25519:" + fingerprint(public_key) + ":" + base64(Ed25519_sign(private_key, canonical_bytes))
```

The signature is over the same canonical bytes used to compute the `id`. Verification requires the public key indicated by the embedded fingerprint to be available in the implementation's key resolver.

### 4.4 Attestor role enumeration

Exactly one of:

- **`observer`** — The producing activity was a normalizer transcribing source bytes into an assertion (§7.2 observation class).
- **`verifier`** — The producing activity was a locally executed verification procedure (§7.2 verification or refutation class).
- **`federated_importer`** — This Occurrence was emitted by the local node at the import boundary while ingesting a peer's log (§10). MUST cite an Identity whose predicate has verification_class ∈ {observation, structural}. This is the no-laundering rule (§13 check #12).

### 4.5 Chain hash

```
chain_hash = SHA-256(decode_hex(prev_chain_hash) || decode_hex(id))
```

where `||` denotes concatenation of the 32-byte hash values. The first Occurrence in a log uses `prev_chain_hash = "0x00".repeat(32)` (genesis).

### 4.6 Validation

Implementations MUST reject Occurrences where:

- any required field is missing;
- `attestor_role` is not in the closed enum;
- the recomputed `id` differs from the stored `id`;
- the recomputed `chain_hash` differs from the stored `chain_hash`;
- the signature does not verify against the public key for the fingerprint indicated;
- the predicate's verification class violates §4.4 for the given role.

---

## 5. TrustClaim envelope

A TrustClaim is the output of one policy evaluation. It is a record of an evaluation event, not a fact about the world.

### 5.1 Fields

| Field | Type | Notes |
|---|---|---|
| `id` | string (hex) | Computed; see §5.3. |
| `subject` | string | Subject the policy was evaluated against. |
| `policy_id` | string | Policy identifier. |
| `policy_version` | string | Policy version (e.g., `v2`). |
| `policy_hash` | string (hex) | sha256 of `manifest.json || 0x00 || policy.rego`. |
| `query` | string | The Rego query expression (e.g., `data.release_signing.verdict`). |
| `verdict` | string | One of `trusted`, `conditional`, `rejected`, `insufficient_evidence`. |
| `qualifiers` | array of strings | Sorted; from the policy's enumerated qualifier vocabulary. |
| `evaluated_at` | string (RFC 3339) | Local wall-clock time at evaluation. NOT in canonical bytes. |
| `evaluator_version` | string | Versioned identifier of the evaluator. |
| `identities_hash` | string (hex) | Fact-side projection digest. NOT in canonical bytes. |
| `projection_manifest_hash` | string (hex) | Full projection digest. NOT in canonical bytes. |
| `vocab_version` | string | Active vocabulary version. |
| `normalizer_versions` | object | Map of normalizer-name → version for each one consumed. |
| `identity_ids_consumed` | array of strings (hex) | Sorted. |
| `raw_evidence_ids_consumed` | array of strings (hex) | Sorted. |
| `derivation` | object | See §5.2. |
| `signature` | string | Computed; see §5.4. |

### 5.2 Derivation

```
{
  "rules_fired":        [string],          sorted
  "missing_predicates": [string] or null,  sorted; null if empty
  "input_counts":       map of string→int,
  "occurrences_cited":  map of identity_id → [occurrence_id, ...]  NOT in canonical bytes
}
```

### 5.3 ID computation

The canonical bytes for the TrustClaim ID are the JCS encoding of the claim object with the following fields removed:

- `id`
- `signature`
- `evaluated_at`
- `projection_manifest_hash`
- `identities_hash`
- `derivation.occurrences_cited`

Arrays that participate in identity (qualifiers, identity_ids_consumed, raw_evidence_ids_consumed, derivation.rules_fired, derivation.missing_predicates) MUST be sorted lexicographically before canonicalisation.

The exclusion of `evaluated_at` ensures two evaluations on identical inputs produce identical claim IDs (the Phase-2.5 hardening rule). The exclusion of `projection_manifest_hash` and `identities_hash` ensures federation does not change verdicts: claim identity is over what the policy consumed, not over the projection's full local state. The exclusion of `derivation.occurrences_cited` keeps corroboration visible in the persisted record without coupling claim identity to which particular logs witnessed the inputs.

```
canonical_bytes = JCS(claim_object_with_fields_above_removed)
id = SHA-256(canonical_bytes), lowercase hex
```

### 5.4 Signature

```
signature = "ed25519:" + fingerprint(public_key) + ":" + base64(Ed25519_sign(private_key, canonical_bytes))
```

### 5.5 Verdict and qualifier vocabularies

The verdict MUST be drawn from the closed enum `{trusted, conditional, rejected, insufficient_evidence}`. Implementations MUST refuse to write a claim whose verdict is outside this set.

Qualifiers are an unordered set of strings declared by the policy's manifest. The policy author defines the enumerated qualifier vocabulary; the implementation enforces only that qualifiers are strings.

Numeric fields are forbidden anywhere in the claim envelope. Implementations MUST refuse to write a claim that contains any JSON number outside the int-valued `input_counts` map. This is enforced at write time.

---

## 6. Raw evidence records

Raw evidence is the substrate of every observation and the input to every verification. Each record has two on-disk artefacts:

### 6.1 Payload

The verbatim bytes from the external source, stored as `<root>/<source>/<yyyy-mm-dd>/<sha256>.bin`. The filename's `<sha256>` is the SHA-256 of the bytes; this provides content-addressing.

### 6.2 Metadata sidecar

A signed JSON sidecar at `<root>/<source>/<yyyy-mm-dd>/<sha256>.json` with fields:

```
{
  "id":             "<sha256 of payload bytes>",
  "source":         "<string>",
  "endpoint":       "<string>",
  "request_params": { ... },
  "fetched_at":     "<RFC 3339>",
  "fetcher":        "<string>",
  "response_status": <integer>,
  "payload_path":   "<filesystem path>",
  "payload_hash":   "<sha256 of payload bytes>",
  "result_count":   <integer> or absent,
  "signature":      "ed25519:..."
}
```

The signature is over the canonical (JCS) bytes of the metadata object with the `signature` field absent. The payload bytes are referenced by hash; tampering is detected because the filename and `payload_hash` no longer agree with the bytes.

`fetched_at`, `fetcher`, and `payload_path` are local-event metadata; they MUST NOT participate in the federation-stable `identities_hash` computation (§12.4).

---

## 7. Predicate vocabulary

### 7.1 File layout and versioning

A vocabulary is a JSON file at `vocab/v<N>.json` declaring the predicates valid for that version:

```
{
  "version":    "v<N>",
  "supersedes": "v<N-1>" or absent,
  "predicates": {
    "<predicate>": {
      "subject_kind":         "<string>",
      "object_kind":          "<string>",
      "object_datatype":      "<string>" (optional, for literal-object predicates),
      "verification_class":   "<string>",
      "description":          "<string>"
    },
    ...
  }
}
```

Vocabulary revision is additive. A new version MUST be a strict superset of the prior version's predicates (existing predicates retained). New predicates added; existing ones never silently changed.

The active vocabulary at a given run is the highest-numbered `vocab/v<N>.json` in the implementation's vocabulary directory. Implementations MUST refuse to write an Identity whose `predicate` is not declared in the active vocabulary.

### 7.2 Verification classes

Every predicate's `verification_class` is one of:

- **`observation`** — The producing activity recorded what an external source claimed. The fact's truth depends on the source's veracity. Examples: `published_at`, `published_by`, `registry_reports_signing_key`, `peer_reports_*`.
- **`verification`** — The producing activity executed a procedure against bytes anchored to a pinned trust root, and the procedure succeeded. Examples: `cryptographically_verified_signature_by`.
- **`refutation`** — The producing activity executed a verification procedure that did NOT succeed. Examples: `cryptographic_verification_failed`.
- **`structural`** — The predicate organises the log rather than asserting a fact about the world. Examples: `revises`, `derived_from`.

Verification class controls the legal attestor_role for Occurrences citing Identities of each class (§4.4).

### 7.3 Predicate naming conventions

- Observation predicates whose source identity matters SHOULD use `<source>_reports_X` (e.g., `registry_reports_signing_key`).
- Verification predicates of the cryptographic family SHOULD use `cryptographically_verified_<X>`.
- Refutation predicates SHOULD use `<verifier>_<X>_failed` or `cryptographic_<X>_failed`.
- Peer-derived observations from federation SHOULD use `peer_reports_<predicate-it-rewrites>`.

These conventions are SHOULD because the actual binding is via `verification_class`; the convention exists for human readability.

### 7.4 Vocabulary integrity

The active vocabulary's SHA-256 (over the file's raw bytes) is recorded in the projection MANIFEST and is INFORMATIVE — it is not part of canonical Identity bytes (the `vocab` field on the Identity envelope names the version, which is enough to look up the predicate definition at verify time).

---

## 8. Identity store

### 8.1 Layout

Identities are written to `<root>/<yyyy-mm-dd>.jsonl`, one Identity record per line, in JSON form. A new Identity whose `id` already exists in the store is a no-op.

### 8.2 Supersession

The `revises` field on an Identity carries the `id` of an earlier Identity it supersedes. Supersession is content-only; no Identity is ever removed or mutated. At projection time the superseded Identity remains, with its `superseded_by` link populated.

### 8.3 Walk order

When walking the store for projection or verification, implementations SHOULD walk by lexicographic file order. The Identity store has no inherent chain; ordering is for determinism in the projection-build step.

---

## 9. Occurrence log

### 9.1 Per-log-id chains

Each log_id has its own chain. The local log lives at `<root>/local/`; foreign logs live at `<root>/foreign/<peer-log-id>/` (after `:` → `_` filename mapping). Each directory contains daily JSONL files plus a `chain.log`.

### 9.2 chain.log format

One line per Occurrence, tab-separated:

```
<seq>\t<prev_chain_hash>\t<occurrence_id>\t<chain_hash>\n
```

`seq` starts at 1 and increments by 1 per append. The genesis `prev_chain_hash` is 64 hex zeros.

### 9.3 Append-only

Implementations MUST refuse to overwrite or modify chain.log entries or JSONL records. Corrections are not permitted at the Occurrence layer — only at the Identity layer via `revises`.

### 9.4 Foreign Occurrence preservation

Occurrences imported from a peer log (§10) are written verbatim into the corresponding `foreign/<peer-log-id>/` directory; their `attestor`, `signature`, `prev_chain_hash`, and `chain_hash` are unchanged from the peer's record. The implementation MUST NOT re-sign foreign Occurrences.

---

## 10. Federation

Filesystem federation is the v0 federation mode: a peer hands the local node a directory mirroring the peer's data layout, plus the peer's public key out-of-band.

### 10.1 Peer-key registry

Peer public keys live at `<root>/peers/<peer-log-id-with-colons-replaced-by-underscores>.pub`, raw 32-byte Ed25519. The registry is populated on first import (via the `--peer-key` flag) and consulted thereafter. A peer's key MUST NOT be silently overwritten; an attempt to register a different key for an existing peer is a hard error.

### 10.2 Foreign archive layout

The peer's archive is expected to contain:

```
<peer-data-root>/
├── assertions/
│   ├── identities/<yyyy-mm-dd>.jsonl
│   └── occurrences/local/<yyyy-mm-dd>.jsonl + chain.log
```

(Other files in the peer's data tree are ignored by the importer.)

### 10.3 Import procedure

For each foreign Occurrence in chain order:

1. Verify the Occurrence's `id` (recompute canonical bytes; SHA-256).
2. Verify the Occurrence's signature against the peer's public key.
3. Confirm `log_id` equals the import command's `--peer-log-id` argument.
4. Confirm chain continuity (this Occurrence's `prev_chain_hash` equals the previous Occurrence's `chain_hash`, or genesis for the first).
5. Persist the verbatim Occurrence bytes as raw evidence under `source = "foreign.occurrence"`.
6. Look up the foreign Identity by its `identity_id` in the peer's archive. If absent, reject the Occurrence with a hard error.
7. Verify the foreign Identity's `id` matches its canonical envelope hash.
8. Route by the foreign Identity's `verification_class`:
   - **observation** or **structural**: store the foreign Identity in the local Identity store (content-addressed; idempotent if already present); write the foreign Occurrence verbatim into `foreign/<peer-log-id>/`.
   - **verification** or **refutation**: do NOT store the foreign Identity in the local Identity store. Write the foreign Occurrence verbatim into `foreign/<peer-log-id>/`. Construct a NEW LOCAL Identity:
     - `subject` = foreign.subject
     - `predicate` = the rewrite mapping (§10.4)
     - `object` = `{ kind: ref, ref: <foreign Identity ID> }`
     - `evidence_id` = SHA-256 of the foreign Occurrence's JSON bytes
     - `observed_at` = foreign Occurrence's `ingested_at`
     - `normalizer` = `federation-import@v0.1.0`
     - `vocab` = active local vocabulary version
   - Store the rewritten local Identity. Emit a LOCAL Occurrence with `attestor_role = federated_importer`, `attestor = "peer:<peer-log-id>"`, signed by the local key, citing the rewritten local Identity.

### 10.4 Rewrite mapping

For v0, the only verification/refutation rewrites are:

| Foreign predicate | Rewritten predicate | Class |
|---|---|---|
| `cryptographically_verified_signature_by` | `peer_reports_cryptographic_verification_of` | observation |
| `cryptographic_verification_failed` | `peer_reports_cryptographic_verification_failed_of` | observation |

Other verification/refutation predicates introduced in future vocabularies MUST be paired with a corresponding `peer_reports_*` rewrite predicate before they can pass through the federation boundary.

### 10.5 The no-laundering rule

A `federated_importer`-role Occurrence MUST cite an Identity whose predicate has verification_class ∈ {observation, structural}. Implementations MUST refuse such writes at import time AND MUST detect violations at verify time (§13 check #12).

This rule preserves invariant 16 (verification locality) across federation boundaries.

---

## 11. Anchoring

Anchoring records that the local node has submitted a snapshot of its log to an external append-only system (a transparency log, a git ref, a signed pastebin — anything whose history is independently observable). The protocol does not depend on any particular provider, does not trust the provider as an authority, and does not adjudicate provider honesty. An anchor is evidence the operator submitted *something*; verification check #13 binds that evidence back to the local chain.

### 11.1 Checkpoint envelope

A Checkpoint is a small signed JSON document summarising the local log at one moment:

| Field | Type | Required | Constraints |
|---|---|---|---|
| `log_id` | string | yes | The local log_id whose head is being snapshotted. |
| `seq` | integer | yes | The sequence number of the chain head being signed. MUST be > 0. |
| `chain_hash` | string | yes | The chain_hash at that seq, 64 lowercase hex characters. |
| `signed_at` | string | yes | RFC 3339 UTC timestamp. |

The Checkpoint is wrapped in a Signed envelope:

```
{
  "checkpoint": { "log_id": ..., "seq": ..., "chain_hash": ..., "signed_at": ... },
  "signature":  "ed25519:<key-fingerprint>:<base64(sig)>"
}
```

`signature` is Ed25519 over the JCS canonical bytes of the `checkpoint` sub-object alone. The signature MUST be produced by the local log's signing key (the key whose fingerprint defines `log_id`).

### 11.2 Checkpoint IRI and storage

The canonical bytes of the Signed envelope hash to the Checkpoint's content hash. The IRI naming a Checkpoint elsewhere in the system is:

```
checkpoint:<sha256-of-signed-canonical-bytes>
```

A Checkpoint is stored as raw evidence under `<root>/raw/origin.checkpoint/<yyyy-mm-dd>/<sha256>.bin`. Checkpoints are NOT predicate-bearing Identities; they are evidence referenced by anchor Identities.

### 11.3 Anchor identity

When the operator obtains a response from a transparency provider (e.g., a Rekor log entry, a git commit SHA, a signed pastebin record) for a previously-produced Checkpoint, the local node MUST record the act as an Identity:

| Field | Value |
|---|---|
| `subject` | The Checkpoint IRI: `checkpoint:<sha256>` |
| `predicate` | `transparency_log_records_checkpoint` |
| `object` | `{ kind: iri, iri: "<provider-entry-iri>" }` |
| `evidence_id` | SHA-256 of the provider's response bytes (stored as raw evidence) |
| `observed_at` | RFC 3339 UTC timestamp of recording |
| `normalizer` | `transparency-anchor-recorder@v0.1.0` (or implementation-equivalent) |
| `vocab` | active local vocabulary version |

The predicate is OBSERVATION class. The Occurrence citing this Identity MUST have `attestor_role = observer`. No verification claim is implied by recording an anchor.

The provider-entry IRI is implementation-defined per provider: Sigstore Rekor uses `rekor:<entry-uuid>`; a git anchor uses `git:<commit-sha>`; pastebin/append-only-blob systems use a stable provider-specific prefix. The protocol does not enumerate providers.

### 11.4 What anchors do and do not claim

An anchor's truth content is:

- **Observed:** the operator obtained the recorded bytes from the named provider at `observed_at`.
- **Verifiable later (check #13):** the Checkpoint's `(log_id, seq, chain_hash)` triple matches the local chain.

An anchor does NOT claim:

- That the provider is honest about its append-only behaviour.
- That `observed_at` is accurate relative to the provider's record.
- That the provider's record is real (e.g., that a Rekor entry was actually inserted into the public log).
- That the underlying log content is true.

Inclusion-proof verification (cryptographically verifying that the provider actually committed to the bytes the operator received) is a separate, verification-class operation; v0 does not specify it. See §17.

### 11.5 Federation of anchors

Anchor Identities are observation class and therefore pass through the federation boundary unchanged via §10.3 step 8 (the observation/structural branch). No `peer_reports_*` rewrite is required at the boundary; the v6 vocabulary reserves `peer_reports_transparency_log_records_checkpoint_of` but implementations typically do NOT mint it — anchor identities are already correctly classified.

---

## 12. Policy execution

### 12.1 Policy structure

A policy lives at `policies/<id>/<version>/policy.rego` with a sibling `manifest.json`:

```
{
  "id":                 "<string>",
  "version":            "v<N>",
  "vocab_required":     "v<M>",
  "required_predicates":   [...],
  "required_raw_sources":  [...],
  "neighborhood_depth": <integer>,
  "allowed_verdicts":   [...],
  "queries":            { "<name>": "<rego query string>" }
}
```

### 12.2 Pure-function execution

Policies are evaluated as pure functions of `(snapshot, query)`. The snapshot is constructed by the evaluator from the projection; it includes only the rows the policy declared interest in via `required_predicates` and `required_raw_sources`. Policies MUST NOT perform I/O, MUST NOT call `http.send` or any equivalent, and MUST NOT consult external data sources at runtime.

### 12.3 The snapshot's identity_ids_consumed

The evaluator MUST record, for each Identity row included in the snapshot, the `identity_id` and any cited raw evidence ids. The TrustClaim's `identity_ids_consumed` and `raw_evidence_ids_consumed` arrays are populated from this set.

### 12.4 Projection manifest

The MANIFEST.json sidecar to the projection carries:

```
{
  "projector_version":  "<string>",
  "vocab_version":      "v<N>",
  "schema_hash":        "<hex>",
  "identities_count":   <integer>,
  "occurrences_count":  <integer>,
  "projection_hash":    "<hex>",
  "identities_hash":    "<hex>",
  "built_at":           "<RFC 3339>"
}
```

- `projection_hash` is over ALL projected tables in canonical order (including occurrences and full raw_evidence columns).
- `identities_hash` is over only the fact-side tables (identities, identity_history, per-predicate tables, raw_evidence with local-event fields excluded). It is stable across ingestors who saw the same evidence.
- `schema_hash` is the SHA-256 of the literal schema SQL string used by the implementation.

The implementation MUST recompute these on rebuild and refuse to load a projection whose recorded hash differs from a fresh rebuild.

---

## 13. Verify procedure

A conforming implementation MUST support a `verify` operation that performs the following thirteen checks. Each check is independent; failure of any check is a hard fail with the specific cause surfaced.

1. **Identity reproducibility.** For every Identity in the local store, recompute the canonical envelope hash and confirm equality with the stored `id`.
2. **Occurrence signatures.** For every Occurrence in the local log, recompute the canonical envelope hash, confirm equality with the stored `id`, and verify the signature against the attestor's public key.
3. **Chain integrity (local log).** Walk the local `chain.log`; confirm each entry's `prev_chain_hash` matches the previous entry's `chain_hash`; recompute each `chain_hash` and confirm equality.
4. **Identity ↔ occurrence linkage.** Every Occurrence's `identity_id` MUST resolve to an existing Identity record.
5. **Raw evidence resolvability.** For every Identity, the `evidence_id` MUST resolve to a raw record whose payload bytes hash to the stored hash.
6. **Projection determinism.** Rebuild the projection from scratch into a fresh database; confirm the resulting `projection_hash` matches the stored value byte-for-byte.
7. **Claim envelope consistency.** For each persisted TrustClaim, recompute the canonical bytes per §5.3 and confirm the SHA-256 matches the `id` field and the file name.
8. **Cryptographic re-verification.** For every Identity with predicate in the verification class, re-execute the relevant verification procedure against the on-disk evidence; assert the same positive outcome.
9. **Claim re-derivation determinism.** Re-evaluate every persisted TrustClaim against the current projection; recompute the claim's canonical bytes and ID; confirm equality with the stored value.
10. **Foreign chain integrity (per peer).** For each registered peer, walk that peer's chain.log under `foreign/<peer-log-id>/` and confirm chain-hash continuity (same as check 3, but per foreign log).
11. **Foreign occurrence signatures.** For every Occurrence in each foreign log, verify the signature against the peer's public key from the peer-key registry.
12. **No-laundering.** Walk every Occurrence with `attestor_role = federated_importer`; resolve its `identity_id`; assert the cited Identity's predicate has verification_class ∈ {observation, structural}. Any violation is a hard fail with the offending Occurrence ID surfaced.
13. **Anchor integrity.** For every Identity with predicate `transparency_log_records_checkpoint`, resolve the Checkpoint cited in its `subject` (a `checkpoint:<sha256>` IRI) to the raw evidence record holding the signed Checkpoint bytes. Parse the Checkpoint. Locate the chain whose `log_id` matches `checkpoint.log_id` (the local chain or a registered foreign chain). Categorise the outcome:
    - **OK** — a chain entry exists at `seq = checkpoint.seq` and its `chain_hash` equals `checkpoint.chain_hash`.
    - **TAMPER** — a chain entry exists at that seq but its `chain_hash` differs.
    - **TRUNCATED** — no chain entry exists at that seq (the chain is shorter than the anchor implies).
    - **MISSING_LOG** — `checkpoint.log_id` matches no local or registered foreign log.

    Any outcome other than OK is a hard fail with the offending anchor Identity ID and the failure category surfaced.

---

## 14. Conformance

Conformance is to a specific spec revision, named at the top of the document (see §0.1). The conformance label is `v<R>-conformant` where `<R>` is the revision tag (e.g., `v0.1.0-conformant`). An implementation MUST satisfy every mandatory item below for the named revision; it MAY also satisfy the optional items.

**Mandatory:**

1. Reproduce the byte-equal canonical encodings and IDs for every artefact in `protocol/v0-fixtures/` per §15.
2. Produce verify check #1 (identity reproducibility) outputs equivalent to the fixture's `verify-output.txt` for the federation fixture.
3. Refuse to write or accept any Identity, Occurrence, or TrustClaim that violates the validation rules in §3.4, §4.6, or §5.5.
4. Implement the rewrite rule in §10.3-§10.5 such that:
   - importing a verification-class foreign Identity does NOT add a row to the local verification-class predicate table;
   - the corresponding `peer_reports_*` observation Identity IS added;
   - the resulting federated_importer-role Occurrence cites the rewritten local Identity.
5. Implement the thirteen verify checks in §13. Implementations MAY add further checks; they MUST NOT skip any of these thirteen.

**Optional (an implementation MAY):**

- Add new predicates in a future vocabulary version. New verification-class predicates MUST ship with their `peer_reports_*` rewrite counterpart.
- Implement additional verifiers beyond Sigstore. The federation rewrite rule applies uniformly.
- Implement non-filesystem federation transports (network, gRPC, etc.) PROVIDED the import-boundary semantics in §10 are preserved.
- Add policies and policy versions; their authoring is outside this protocol's scope.

**Forbidden (an implementation MUST NOT):**

- Produce a TrustClaim whose verdict is outside the closed enum.
- Include any JSON floating-point number in any envelope.
- Mutate or remove records from the canonical stores (Identity, Occurrence, Raw evidence, Claim).
- Bypass the rewrite rule for verification-class foreign Identities.
- Fetch a root of trust at runtime; trust roots MUST be pinned in source.

---

## 15. Test fixtures

The fixture directory at `protocol/v0-fixtures/` contains the byte-equality reference. Layout:

```
v0-fixtures/
├── README.md
├── gen.go                                  regenerates every fixture deterministically
├── fixtures_test.go                        identity / occurrence / claim / raw-evidence / key fixtures
├── federation_test.go                      end-to-end no-laundering federation flow (synthetic peers)
├── anchor_test.go                          checkpoint + anchor identity + vocab-class invariant
├── keys/test-signer.pub                    32-byte raw Ed25519 public key
├── keys/test-signer.ed25519                64-byte raw Ed25519 private key
│                                            (TEST-ONLY; MUST NOT sign production data)
├── identity/
│   ├── observation.json                    sample observation-class Identity
│   ├── observation.canonical-bytes         JCS bytes of envelope (without `id`)
│   ├── observation.expected-id             SHA-256 of canonical-bytes, hex
│   ├── verified.json                       sample verification-class Identity
│   ├── verified.canonical-bytes
│   ├── verified.expected-id
│   ├── peer_reports.json                   sample peer_reports_* identity (object.kind = ref)
│   ├── peer_reports.canonical-bytes
│   └── peer_reports.expected-id
├── occurrence/
│   ├── observer.json                       sample observer-role Occurrence
│   ├── observer.canonical-bytes            JCS bytes of envelope (without `id`, `chain_hash`, `signature`)
│   ├── observer.expected-id
│   ├── observer.expected-signature         signed by keys/test-signer
│   ├── federated_importer.json             sample federated_importer-role Occurrence
│   ├── federated_importer.canonical-bytes
│   ├── federated_importer.expected-id
│   └── federated_importer.expected-signature
├── claim/
│   ├── sample.json                         sample TrustClaim
│   ├── sample.canonical-bytes              after the §5.3 exclusion set
│   └── sample.expected-id
├── raw-evidence/
│   ├── sample-payload.bin                  arbitrary bytes
│   └── sample-payload.expected-hash        SHA-256 of the payload, hex
└── anchor/
    ├── checkpoint.json                     sample Signed Checkpoint envelope
    ├── checkpoint.canonical-bytes          JCS bytes of the Signed envelope
    ├── checkpoint.expected-iri             checkpoint:<sha256>
    ├── provider-response.json              sample transparency-provider response bytes
    ├── provider-response.expected-hash     SHA-256 of provider response, hex
    ├── anchor-identity.json                sample transparency_log_records_checkpoint Identity
    ├── anchor-identity.canonical-bytes
    └── anchor-identity.expected-id
```

A conforming implementation MUST be able to:

- read `identity/observation.json`, JCS-canonicalise it, and produce bytes equal to `identity/observation.canonical-bytes`;
- hash those bytes and produce `identity/observation.expected-id`;
- read `anchor/checkpoint.json`, JCS-canonicalise the Signed envelope, hash the result, and produce `anchor/checkpoint.expected-iri`;
- read `anchor/anchor-identity.json` and produce `anchor/anchor-identity.expected-id` via the §3 identity canonicalisation rules;
- run the federation flow (`federation_test.go`) and produce the post-import state described in §10.3–§10.5 (no on-disk peer archives; the test constructs deterministic peer-a and peer-b states in a temporary directory and exercises the importer).

The test signing key is checked into the repository explicitly for fixture reproducibility. The key fingerprint is documented in the fixture's README. Implementations MAY (and SHOULD) refuse to sign production data with this fingerprint at runtime.

---

## 16. Security considerations

### 16.1 Trust roots

Cryptographic verification (§7.2 verification class) anchors to a root of trust that MUST be pinned in the implementation's source code, not fetched at runtime. Live-fetched roots cede the local-computation property (invariant 16) and are forbidden by this protocol.

For Sigstore-based verifiers, the public-good trusted-root JSON is the v0 reference root; implementations MAY use alternative private-instance roots PROVIDED the substitution is a source-tree change, visible in git history.

### 16.2 Peer compromise

A compromised peer can produce signed but malicious foreign Occurrences. The rewrite rule (§10.5) prevents this from reaching the local verified-form table. The peer's claims become local observations of what the peer claims — never local verifications.

A compromised peer's signing key, once detected, MAY be revoked via a per-peer revocation record at `<root>/peers/<peer-log-id>.revoked`. Occurrences whose foreign `ingested_at` is after the revocation time MUST be flagged distinctly in verify output (this provision is normative for v1; v0 implementations SHOULD support it but MAY not).

### 16.3 Registry compromise

If an external observation source (npm registry, OSV, etc.) is compromised, observation-class Identities derived from that source carry the compromise. The protocol does not detect this directly; corroboration across independent sources is the policy author's tool, not the protocol's. Independence semantics are an open question (`epistemic-model.v1.md` §11) and will be addressed in v1.

### 16.4 Verifier code trust

Verification-class predicates rely on the correctness of the implementation's verifier code (e.g., Sigstore signature checking). This is code trust, distinct from data trust. Auditing verifier correctness is a source-code review concern, not addressed by this protocol.

### 16.5 Replay vs drift

A successful verify in the past does not guarantee a successful verify now: cryptographic validity is time-dependent (cert expiry, root rotation). Check #8 (cryptographic re-verification) re-executes the verifier; a previously valid signature that no longer verifies is "drift" rather than "tamper". Implementations SHOULD distinguish these in error reporting; v0 does not mandate a particular schema for the distinction.

### 16.6 Anchor evidence epistemics

The `transparency_log_records_checkpoint` predicate is OBSERVATION class by construction (§11.4). Recording an anchor MUST NOT be treated as a verification of the underlying log content, of provider honesty, or of provider append-only behaviour. An anchor binds local-chain state to externally-visible bytes; its value is that *tampering with local history after submission becomes externally detectable* by anyone who can observe both the provider and the local chain.

Verify check #13 catches local-side tamper / truncation: if a previously-anchored seq is rewritten or removed, the (log_id, seq, chain_hash) triple recorded in the Checkpoint no longer matches the local chain, and check #13 fails. The provider's own honesty is NOT verified by the protocol; it is observable out-of-band by anyone who can read the provider's record.

Inclusion-proof verification — cryptographically confirming the provider actually committed to the bytes returned to the operator — is a separate, verification-class operation. v0 does not define an inclusion-proof predicate or procedure; this is reserved for a later revision.

---

## 17. Acknowledged limitations

The following are explicitly NOT specified by v0 and remain open:

- **Independence semantics.** Multiple observation predicates from different sources can corroborate a fact, but v0 does not define "independent". Multiple peers reporting the same observation from the same ultimate source are not independent in any deep sense.
- **Identity entity layer.** Identities (in the keyed-principal sense) appear as string columns. A v1+ revision will likely promote Identity to a typed entity table; the predicate-level shape does not yet require this.
- **Inclusion-proof verification of anchors.** v0 records anchors as observation-class evidence and binds the cited Checkpoint back to the local chain (check #13). It does NOT specify a verification-class predicate or procedure for cryptographically verifying inclusion proofs returned by a transparency provider. Such verification (e.g., Rekor inclusion proofs, signed-tree-head consistency proofs) is reserved for a future revision; it would mint a verification-class predicate paired with a `peer_reports_*` rewrite for the federation boundary.
- **Policy authoring against `peer_reports_*` and anchor predicates.** v0 declares these predicates but does not ship a reference policy that consumes them.
- **Conflict resolution.** Two peers reporting incompatible observations of the same fact (e.g., different `published_by` for the same `subject`) are recorded as distinct observations; the protocol does not adjudicate.

These items will be addressed in future protocol versions; their absence here is intentional.

---

## Appendix A: Vocabulary, v6

The reference vocabulary for v0 is `vocab/v6.json`. It declares the following predicates:

| Predicate | Verification class | Object kind |
|---|---|---|
| `depends_on` | observation | artifact |
| `registry_reports_signing_key` | observation | identity |
| `cryptographically_verified_signature_by` | verification | identity |
| `cryptographic_verification_failed` | refutation | identity |
| `published_by` | observation | identity |
| `published_at` | observation | literal (xsd:dateTime) |
| `affected_by` | observation | vulnerability_iri |
| `attests_to` | observation | any |
| `revises` | structural | assertion |
| `derived_from` | structural | assertion_or_claim |
| `peer_reports_cryptographic_verification_of` | observation | ref |
| `peer_reports_cryptographic_verification_failed_of` | observation | ref |
| `transparency_log_records_checkpoint` | observation | iri |
| `peer_reports_transparency_log_records_checkpoint_of` | observation | ref |

Versions v1 through v5 are retained in `vocab/` for reproducibility of identities recorded against earlier vocabularies. Vocabulary revision is additive (§7.1); an implementation MAY ship later supersets without losing v0 conformance.

---

## Appendix B: Closing test

An external party with access to this document, the fixture directory, and a working Origin-conformant implementation can:

1. Implement JCS, SHA-256, and Ed25519 (using any conforming library) and confirm fixture byte-equality.
2. Run the federation fixture's import scenario and produce the documented post-import state.
3. Generate their own Identity and Occurrence envelopes signed by their own keys, share them with another node running the same protocol, and federate without trust laundering.
4. Read §3-§13 and answer, for any observable behaviour in either implementation, which protocol rule governs that behaviour.

If any of these is not achievable from this document + fixture, the document has drifted from the implementation and an erratum revision is required.

---

## Document history

| Revision | Date | Class | Notes |
|---|---|---|---|
| `v0.1.0` | 2026-05-15 | minor (initial) | First published revision. Covers identity / occurrence / claim envelopes (§3-§5), raw evidence (§6), vocabulary v6 (§7, Appendix A), identity store + occurrence log (§8-§9), filesystem federation with the no-laundering rule (§10), transparency anchoring (§11), policy execution (§12), and the thirteen verify checks (§13). Earlier phase-3.5 draft text was never published and therefore not separately revisioned. |
