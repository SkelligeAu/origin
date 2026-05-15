# Glossary

Terms used across the project's documentation, in alphabetical order.

### Anchor
An observation-class identity recording that the local node submitted a Checkpoint to an external transparency system and received a response. The transparency system is a witness, not an authority. See [`invariants.md`](invariants.md) §9.

### Assertion
General term for a fact recorded in the system. In v0 the canonical assertion shape is the Identity envelope.

### Attestation (Sigstore)
A signed in-toto statement, typically wrapped in a DSSE envelope inside a Sigstore Bundle. Origin verifies SLSA Provenance v1 attestations from the npm attestations endpoint.

### Attestor
The recorder of an Occurrence. For local ingest, the form is `ingestor:<tool-version>:<key-fingerprint>`. For federation, `peer:<peer-log-id>`. Distinct from "identity" (the type that carries facts).

### Attestor role
One of `observer`, `verifier`, `federated_importer`. Discriminates how an Occurrence came to be recorded; governs which predicate classes are legal under that role.

### Canonical bytes
The RFC 8785 JCS encoding of an envelope. The unit hashed to produce content-addressed IDs and the unit signed by signatures.

### Checkpoint
A signed local document `(log_id, seq, chain_hash, signed_at)` summarising the local chain at one moment. Phase-5 artefact. Stored as raw evidence under `data/raw/origin.checkpoint/`.

### Claim — see TrustClaim.

### Content-addressed
Identified by the SHA-256 of its canonical bytes. Identities, Checkpoints, raw evidence payloads, and TrustClaims are all content-addressed. Two observers who produce the same bytes produce the same identifier.

### Derivation
The structured trace inside a TrustClaim recording which policy rules fired, which Identities were consumed, which raw evidence was consulted, which occurrences cited each Identity.

### Evidence ID
The content hash of a raw evidence payload. Every Identity carries an `evidence_id` pointing at the bytes that backed the observation.

### Federation
Filesystem-only sharing of canonical state between two Origin nodes. One node imports another's archive; the no-laundering rule (invariant 6) governs what crosses the boundary.

### Fingerprint
The first 16 hex characters of `SHA-256(public_key_bytes)`. Used in attestor strings, log IDs, and signature headers.

### Identity
The canonical content-addressable fact. Subject, predicate, object, evidence pointer, source-claimed time, normalizer version, vocab version. The fact, not the witness.

### Identities hash
Hash of the fact-side of the projection (Identities + per-predicate tables + raw-evidence content fields). Federation-stable: two ingestors with the same evidence produce the same `identities_hash`. Used to make claim IDs invariant across ingestors.

### JCS
JSON Canonicalization Scheme (RFC 8785). Sorts object keys by UTF-16 code-unit sequence; removes insignificant whitespace; constrains string and number serialisations. Origin's canonical encoding for all envelopes.

### Log
An append-only per-`log_id` stream of Occurrences plus its chain.log. The local log lives at `data/assertions/occurrences/local/`; each foreign log at `data/assertions/occurrences/foreign/<peer-log-id>/`.

### Log ID
A string of form `log:<key-fingerprint>` (default) or operator-overridden. Distinguishes the local log from each peer's log. Two peers must NEVER share a log_id.

### No-laundering rule
The protocol invariant that prevents foreign verification-class identities from becoming local verifications. Enforced at import time (importer refuses verification-class predicates under `federated_importer` role) AND at verify time (check #12).

### Normalizer
A versioned identifier (`<name>@<version>`) for the procedure that produced an Identity from raw evidence. Recorded in every Identity envelope so re-derivation is deterministic.

### Observation class
A predicate's `verification_class` that records what an external source claimed. Examples: `registry_reports_signing_key`, `published_at`, `peer_reports_*`.

### Occurrence
A local ingestion event citing an Identity. Distinct from the Identity itself: same Identity, multiple Occurrences (different ingestors / federation imports / multiple witnessings). Signed by the recording party.

### Peer
Another Origin node whose archive has been imported via filesystem federation.

### PURL
Package URL (`pkg:npm/foo@1.2.3`). Used as the subject IRI for npm release identities.

### Policy
A Rego module under `policies/<id>/<version>/`. Pure function from snapshot to TrustClaim. Cannot perform I/O. Cannot produce numerics.

### Predicate
A vocabulary term naming the kind of fact being asserted (`depends_on`, `cryptographically_verified_signature_by`, etc.). Declared with a `verification_class` in the active vocabulary version.

### Projection
The deterministic SQLite index built from the canonical log. Rebuildable from scratch. The shape policies query against.

### Projection hash
Hash of the full projection (all tables including occurrences). Varies per ingestor (occurrence sets differ). Used for replay determinism within one local archive, not federation.

### Raw evidence
Verbatim bytes from an external source, content-addressed, with a signed metadata sidecar. Stored under `data/raw/<source>/<yyyy-mm-dd>/<sha256>.bin+.json`.

### Refutation class
A predicate's `verification_class` that records a NEGATIVE outcome of a verification procedure ("we ran the verifier and it rejected"). Example: `cryptographic_verification_failed`. Still produced by verifier-role occurrences (it is OUR verifier's output).

### Replay
Re-deriving every projection, claim, and verification from the canonical log + code versions + pinned trust roots. The `origin verify` command performs this end-to-end across 13 checks.

### Snapshot
The closed view of the projection a policy sees during evaluation. Constructed from the policy's declared `required_predicates` and `required_raw_sources`.

### Structural class
A predicate's `verification_class` for meta-predicates that organise the log rather than assert facts about the world. Examples: `revises`, `derived_from`.

### Subject
The IRI an Identity is about. PURLs for npm releases, `checkpoint:<hash>` for Phase-5 checkpoints, etc.

### Supersession
The mechanism by which one Identity replaces another. A new Identity with `revises: <prior-id>` marks the prior as superseded. Neither is mutated; the prior remains in the log.

### Transparency log
An external append-only log (Rekor, signed git tag, signed paste, etc.) that records checkpoints submitted to it. A witness, not an authority. See [`invariants.md`](invariants.md) §9.

### TrustClaim
The output of one policy evaluation. A categorical verdict, an enumerated qualifier set, and a derivation DAG citing consumed Identities and raw evidence. Persisted under `data/claims/<id>.json`.

### Verdict
One of `trusted`, `conditional`, `rejected`, `insufficient_evidence`. The verdict enum is closed; no other values are permitted.

### Verification class
A predicate's `verification_class` value declaring how the predicate is produced. One of `observation`, `verification`, `refutation`, `structural`. Determines legal attestor_role for citing Occurrences.

### Verifier
A procedure (e.g., the Sigstore signature + Fulcio chain check) that produces verification- or refutation-class identities. Verifiers must execute locally against bytes anchored to a pinned trust root.

### Vocabulary
A versioned JSON file (`vocab/v<N>.json`) declaring valid predicates and their verification classes. The active version is the highest-numbered file present at startup.
