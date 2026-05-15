# Day-1 Technical Blueprint
## Provenance-Aware Software Trust Infrastructure

> **Central design commitment.** Canonical truth is an append-only log of signed, content-addressed assertions/quads. Everything else — projections, graphs, indexes, trust verdicts, explanations — is a deterministic, replayable function of that log.

This document supersedes earlier design iterations. The prior property-graph-centric design is discarded.

### Corrections applied during Day-1 implementation

Four substantive refinements emerged when the blueprint met code. All are reflected in the sections below.

1. **`ingested_at` is NOT in the canonical envelope.** The blueprint originally listed it as an envelope field. Doing so makes the assertion ID depend on local clock time, which breaks idempotence: re-ingesting unchanged source data produces a fresh ID and a duplicate row. The envelope hashes *the fact*; `ingested_at` is local observation metadata and lives on the record alongside chain hashes.

2. **`signed_by` is renamed to `registry_reports_signing_key`.** The original predicate name smuggled cryptographic verification past the evidence boundary. Day-1 only reads registry metadata (`dist.signatures[].keyid` from npm); no signature is verified against the artifact bytes. The verb in the predicate name now matches what was actually observed. A separate predicate `cryptographically_verified_signature_by` is reserved for Phase 2 when verification is wired in. The general lesson: predicate names that imply a verifiable property of an artifact MUST distinguish observation (`<source>_reports_X`) from cryptographic verification (`cryptographically_verified_X`).

3. **The `trusted` verdict is structurally unreachable Day-1.** A consequence of (2): the `release_signing` policy gates `trusted` on the verified-form predicate, which is never emitted by current normalizers. `conditional` is the strongest reachable verdict for a signed npm release. This is the correct and honest behaviour, not a gap — strong verdicts require evidence we have not produced.

4. **Open structural question: AssertionIdentity vs AssertionOccurrence.** The Day-1 record merges the canonical-fact fields (subject/predicate/object/evidence_id/attestor/observed_at/normalizer/vocab/revises — hashed to assertion_id) with the local-observation fields (ingested_at, prev_chain_hash, chain_hash, the local signature). Conceptually these are two different things: an **AssertionIdentity** (a content-addressable canonical fact, deterministic across observers) and an **AssertionOccurrence** (a local ingestion event — when/where this fact was seen, with what tool version, anchored to this particular log). Day-1 doesn't need the split — one ingestor, one log. But every Phase-2 feature that involves federation, log mirroring, third-party attestation, or multi-ingestor replay becomes substantially cleaner if the split exists. Design future surfaces from this shape; treat the merged-struct Day-1 form as a convenient simplification that the model will eventually outgrow.

---

## 1. The Invariant Manifesto

These are not implementation preferences. They are the constitution of the system. A change that violates any of these is not a feature; it is a different product.

1. **Observation is not inference.** A raw record from an external source records what the source said. It does not record what is true.
2. **Inference is not truth.** An assertion derived from observations is a *belief about what the source meant*, attributable to a versioned normalizer. It is not promoted to truth by being recorded.
3. **Trust is never stored as an intrinsic property.** No node, edge, table, or record carries a "trust" attribute. Trust exists only as a transient output of `(policy, query, projection_snapshot)`.
4. **The append-only assertion log is the canonical source of truth.** It is on disk, content-addressed, hash-chained. Files in directories. There is no database that is the source of truth.
5. **Every assertion is evidence-backed, content-addressed, signed/attested, and temporally scoped.** Missing any of these four, it is not an assertion; it is noise and must be rejected at write time.
6. **All projections are disposable.** Any projection (SQLite index, analytic view, search index) must be reconstructable bit-for-bit from `(log[0..T], projector_version)`. A projection that contains non-derivable data is a bug.
7. **Policies interpret evidence; they do not create evidence.** Policies are pure functions over projection snapshots. They emit claims. They never write to the assertion log.
8. **Every evaluation result carries its full provenance.** A claim is invalid unless it cites: the policy hash, the policy version, the normalizer versions for every assertion consumed, the projection manifest hash, and the assertion IDs consumed.
9. **`insufficient_evidence` is a first-class verdict.** It must never be silently coerced to `rejected`, `unknown`, low confidence, or a number near zero.
10. **AI may summarize, assist, or propose. AI may never create canonical trust relationships.** An AI-originated assertion enters the log only under an explicit `attestor=ai:<model>:<prompt-hash>` identity, and no policy may treat it as independent corroboration of evidence from non-AI attestors.
11. **Correction means supersession, never mutation.** A correction is a new signed assertion that `revises` a prior one. Both remain in the log forever.
12. **Replayability is mandatory.** The full state at time T is the deterministic output of `f(log[0..T], code_versions[0..T])`. No hidden state, no out-of-band caches, no operator memory. A `verify` command must prove this on every run.
13. **Independence is explicit, not assumed.** When a policy requires corroboration from "independent" attestors, `independent` is a defined operational predicate (distinct signing roots, distinct organizational principals). Two assertions sourced through the same upstream are not independent.
14. **Derived claims never silently masquerade as observed facts.** Any second-order assertion (one derived from other assertions or from a claim) carries `derived_from` pointers and is visibly second-order in every projection and report.
15. **The graph is an index, not truth.** Any graph-shaped representation is a derived view, queryable but not authoritative. Disagreement between graph and log is resolved by the log, always.
16. **Verified-form assertions are produced only by locally executed verification.** A predicate that asserts a verifiable property of an artifact (`cryptographically_verified_*`, `reproducibly_built_*`, `independently_attested_*`, any future predicate in this family) may be emitted only when this binary, in this run, executed the verification procedure end-to-end against the artifact bytes and the procedure succeeded. A verified-form assertion may never be derived from observing another party's claim that verification occurred — upstream registries, federated peers, cached verifiers, or any "trusted attestation service" that reports verification produces at best a `<source>_reports_verification_of_X` predicate (observation-level, weak corroboration). Re-verification at replay time must independently reproduce the result. Roots of trust (Fulcio cert bytes, etc.) are pinned inside the binary, never fetched at runtime. This rule preserves the integrity of the epistemic ladder: *reported → observed → verified → policy-derived verdict*. Without it, "verified" collapses into "reported" under operational pressure.

### Forbidden Patterns

The following are not optimization opportunities. They are anti-features. The architecture must make them mechanically difficult to introduce:

- Numeric trust scores in any output (claim verdict, projection column, report field).
- Aggregate scores that combine orthogonal dimensions.
- Edge properties carrying facts whose attestor is not recorded.
- Mutating updates to assertions, projections marked "canonical," or claim records.
- Policy outputs that are not in the enum `{trusted, conditional, rejected, insufficient_evidence}`.
- ML/embedding-based ranking, similarity-as-trust, or learned heuristics in the trust path.
- Caches or projections that retain data after the source assertions are superseded, without explicit `superseded_by` tracking.
- Prose explanations not anchored to a derivation DAG.
- Treating an upstream party's claim that verification occurred as itself a verified-form assertion. (Invariant 16.)
- Federation or import paths that let remote verified-form assertions enter the local log without local re-verification.
- Verification result caches where re-verification on replay is not deterministically guaranteed.

---

## 2. Day-1 Architecture

One process. One developer. No services.

```
        ┌──────────────┐
URL ───▶│   ingest     │── raw API responses ──▶ data/raw/...           (immutable)
        └──────┬───────┘
               │
               ▼
        ┌──────────────┐
        │  normalize   │── signed assertions ──▶ data/assertions/*.jsonl (append-only)
        └──────┬───────┘                          + chain.log (hash chain)
               │
               ▼
        ┌──────────────┐
        │   project    │── deterministic build ─▶ data/projections/index.sqlite
        └──────┬───────┘                          + MANIFEST.json
               │
               ▼
        ┌──────────────┐
        │    eval      │── OPA / Rego ──────────▶ data/claims/<claim-id>.json
        └──────┬───────┘                          (with derivation DAG)
               │
               ▼
        ┌──────────────┐
        │ why / report │── static HTML ─────────▶ data/reports/<run-id>.html
        └──────────────┘
```

Components:
- One Go or Rust CLI binary: `origin`. Bundles all subcommands.
- One external dependency at runtime: OPA (vendored as a library or invoked as a subprocess).
- No HTTP server. No queues. No graph DB. No container. No daemon.

The whole thing must run on a laptop offline after one warm cache pull, and `origin verify` must finish in seconds at Day-1 scale.

---

## 3. Directory Layout

Everything is files on disk. The shell is the audit tool.

```
data/
├── raw/                                  # immutable raw evidence
│   ├── github.api/2026-05-14/{sha256}.json
│   ├── npm.registry/2026-05-14/{sha256}.json
│   ├── osv.dev/2026-05-14/{sha256}.json
│   └── sigstore.rekor/2026-05-14/{sha256}.json
├── raw-index/raw-index.sqlite            # rebuildable lookup over raw/
├── assertions/                           # append-only, hash-chained
│   ├── 2026-05-14.jsonl                  # one signed assertion per line
│   └── chain.log                         # running hash chain anchor
├── vocab/
│   └── v1.json                           # signed predicate vocabulary
├── normalizers/
│   └── manifest.json                     # normalizer versions, hashes
├── policies/
│   ├── release_signing/
│   │   ├── policy.rego
│   │   └── manifest.json                 # id, version, hash, required predicates
│   └── dependency_hygiene/
│       ├── policy.rego
│       └── manifest.json
├── projections/
│   ├── index.sqlite                      # derived; rebuildable from assertions
│   └── MANIFEST.json                     # log_seq_processed, projector_version, schema_hash
├── claims/
│   └── {claim-id}.json                   # one claim per file, signed
├── reports/
│   └── {run-id}.html
└── keys/
    └── ingestor.ed25519                  # signing key for assertions
```

Properties:
- `raw/`, `assertions/`, `chain.log`, `claims/`, `vocab/`, `policies/` are **canonical**. Never mutated.
- `raw-index/`, `projections/`, `reports/` are **derived**. Deletable at any time.
- `keys/` is operator-managed. Lost key = lost ability to sign new assertions, but the log remains verifiable.

---

## 4. CLI Command Set

Eight commands. No more.

| Command | Description |
|---|---|
| `origin ingest <github-url>` | Fetch from GitHub + npm + OSV + Rekor; write raw records to `raw/`; emit assertions to `assertions/<today>.jsonl`; advance `chain.log`. |
| `origin project` | Rebuild or incrementally update `projections/index.sqlite` from the assertion log. Idempotent. Deterministic. |
| `origin eval <subject> --policy <name>` | Run a policy against the current projection. Write a TrustClaim to `claims/`. |
| `origin why <claim-id>` | Print the derivation DAG: rules fired, assertions consumed, evidence pointers, policy/normalizer/projector versions. |
| `origin explain <assertion-id>` | Print the assertion, its raw evidence record, its source URL, its normalizer, its signer, its chain position. |
| `origin verify` | Recompute hash chain; re-derive projection; re-evaluate all claims; assert byte-equality at every step. Exits non-zero on drift. |
| `origin report <subject>` | Emit a self-contained static HTML report including every relevant assertion, raw evidence link, claim, and derivation. |
| `origin export --format=nq` | Emit canonical assertion log as N-Quads for external interop (RDF stores, SPARQL endpoints). View only. |

There is no `delete`, no `update`, no `fix`. Corrections go through `ingest` with explicit supersession.

---

## 5. Minimal Entity Model

Four types. PROV-aligned. Nothing more.

| Entity | PROV class | Identifier | Day-1 role |
|---|---|---|---|
| **Artifact** | `prov:Entity` | PURL or content digest | A package release. |
| **Source** | `prov:Entity` | Repository URL + optional commit SHA | A repository or specific commit. |
| **Identity** | `prov:Agent` | `<kind>:<value>` (e.g., `npm:sindresorhus`, `gh:1234`, `sigstore:fulcio:<fp>`) | A keyed principal. *Not a person.* |
| **Attestation** | `prov:Entity` | content digest of DSSE envelope | A signed statement *about* a Subject. |

Day-1 deliberately omits: `Maintainer` (derived, not entity), `Build` (folded into `produced_from`), `Vulnerability` (referenced as opaque IRI, not modeled), `Cluster`, `Score`, `Trust*`.

Vulnerabilities are referenced as IRIs (e.g., `osv:CVE-2024-12345`) without internal modeling. Their structure lives in the raw OSV records; policies that need detail look there.

---

## 6. Minimal Predicate Vocabulary

Eight predicates. The vocabulary file `vocab/v1.json` is signed and content-hashed. New predicates require an additive vocabulary version (`v2`), signed, with rationale.

| Predicate | Subject → Object | Notes |
|---|---|---|
| `depends_on` | Artifact → Artifact | One row per resolved dependency. |
| `registry_reports_signing_key` | Artifact → Identity | Registry metadata reports a signing-key association. **Observation only; no cryptographic verification.** Reserve `cryptographically_verified_signature_by` for Phase 2. |
| `published_by` | Artifact → Identity | As recorded by the registry. |
| `published_at` | Artifact → xsd:dateTime literal | Release timestamp from registry. |
| `affected_by` | Artifact → Vulnerability-IRI | One row per OSV match. |
| `attests_to` | Attestation → Subject (Artifact/Source) | Pointer to attestation envelope. |
| `revises` | Assertion-id → Assertion-id | Supersession edge. Meta-predicate. |
| `derived_from` | Assertion-id → Assertion-id-or-Claim-id | Second-order claim provenance. Meta-predicate. |

Absence of evidence is **not** an assertion. It is observable by joining `raw-index/` (proof that we looked) against the predicate tables (proof of what we found). Policies that distinguish "we didn't look" from "we looked and found nothing" must reference the raw evidence table explicitly.

---

## 7. Assertion Schema

Canonical on-disk form: JSONL, one assertion per line. Each line is structurally a named-quad with metadata. Convertible to N-Quads via `export`.

```json
{
  "id": "<sha256 of canonical-JCS encoding of all fields below except id, signature, chain_hash>",
  "subject":     "pkg:npm/@sindresorhus/is@6.1.0",
  "predicate":   "published_at",
  "object":      { "literal": "2024-03-09T10:30:00Z", "datatype": "xsd:dateTime" },
  "evidence_id": "<sha256 of raw evidence record>",
  "attestor":    "ingestor:origin@v0.1.0:<key-fp>",
  "observed_at": "2024-03-09T10:30:00Z",
  "ingested_at": "2026-05-14T15:22:01Z",
  "normalizer":  "npm-registry-record@v0.1.0",
  "vocab":       "v1",
  "revises":     null,
  "signature":   "ed25519:<base64 sig over canonical form>",
  "prev_chain_hash": "<sha256>",
  "chain_hash":      "<sha256 of (prev_chain_hash || id)>"
}
```

Canonicalization: RFC 8785 JSON Canonicalization Scheme (JCS) for hashing. Signatures are Ed25519 over the canonical bytes excluding `id`, `signature`, `chain_hash`. The `id` is the SHA-256 of the same canonical bytes — so two writers that observe the same fact produce the same assertion ID. The chain hash is computed on append.

Validation at write time enforces invariant 5: every field present, signature verifies, predicate exists in declared vocabulary, evidence_id resolves to a real raw record, normalizer matches the manifest.

---

## 8. Raw Evidence Schema

One raw record per external API response. Stored as a metadata file plus a payload blob.

Metadata (`data/raw/{source}/{date}/{sha256}.json`):

```json
{
  "id":              "<sha256 of payload bytes>",
  "source":          "github.api",
  "endpoint":        "GET /repos/sindresorhus/is",
  "request_params":  { "ref": "v6.1.0" },
  "fetched_at":      "2026-05-14T15:21:58Z",
  "fetcher":         "origin@v0.1.0:<key-fp>",
  "response_status": 200,
  "response_headers": { "etag": "...", "x-ratelimit-remaining": "..." },
  "payload_path":    "data/raw/github.api/2026-05-14/{sha256}.bin",
  "payload_hash":    "<sha256>",
  "signature":       "ed25519:<base64 sig over canonical metadata>"
}
```

Payload is the verbatim response body. Stored as bytes, not parsed. Never modified.

Every raw record stands as evidence both of what the source said *and* of the fact that we asked. Policies needing "did we look?" check the `raw-index/` projection.

---

## 9. Evaluation Result Schema

A TrustClaim is the only output of evaluation. Persisted at `claims/<claim-id>.json`.

```json
{
  "id": "<sha256 of canonical form>",
  "subject":     "pkg:npm/@sindresorhus/is@6.1.0",
  "policy_id":   "release_signing",
  "policy_version": "v1",
  "policy_hash": "<sha256 of policy.rego + manifest>",
  "query":       "release_signing.verdict",

  "verdict":     "insufficient_evidence",
  "qualifiers":  ["no_signature_attestation_found"],

  "evaluated_at": "2026-05-14T15:22:30Z",
  "evaluator_version": "origin@v0.1.0",

  "projection_manifest_hash": "<sha256>",
  "vocab_version": "v1",
  "normalizer_versions": {
    "npm-registry-record": "v0.1.0",
    "github-repo-meta":    "v0.1.0",
    "osv-vuln-query":      "v0.1.0",
    "rekor-search":        "v0.1.0"
  },

  "assertion_ids_consumed": ["<aid1>", "<aid2>", "<aid3>"],
  "raw_evidence_ids_consumed": ["<rid5>"],

  "derivation": {
    "rules_fired": [
      {
        "rule": "release_signing.verdict_insufficient",
        "file": "policies/release_signing/policy.rego",
        "line": 23,
        "bindings": { "subject": "pkg:npm/@sindresorhus/is@6.1.0" },
        "preconditions_met":  ["published_at_exists", "rekor_was_queried"],
        "preconditions_unmet":["registry_reports_key", "verified_signature_exists"]
      }
    ],
    "missing_predicates": ["registry_reports_signing_key"]
  },

  "signature": "ed25519:<base64>"
}
```

Verdict is constrained to the four-value enum by JSON schema validation at write time. The schema is part of the binary; the binary refuses to write any other value. No numeric fields exist anywhere in this schema.

---

## 10. Policy Execution Model

A policy is a directory under `policies/`:

```
policies/release_signing/
├── policy.rego
└── manifest.json
```

Manifest (signed, content-hashed):

```json
{
  "id":      "release_signing",
  "version": "v1",
  "policy_hash": "<sha256 of policy.rego>",
  "vocab_required": "v1",
  "required_predicates":  ["registry_reports_signing_key", "published_at", "published_by"],
  "optional_predicates":  [],
  "neighborhood_depth":   1,
  "output_schema":        "trustclaim/v1",
  "allowed_verdicts":     ["trusted", "conditional", "rejected", "insufficient_evidence"]
}
```

Execution:
1. `origin eval` reads the manifest. Confirms vocabulary and projection schema compatibility.
2. Snapshots the projection at the current `MANIFEST.json` hash.
3. Extracts the subject's k-hop neighborhood (k = `neighborhood_depth`) over the `required_predicates` from SQLite. This subset becomes OPA's `input`.
4. Records the IDs of every assertion and raw evidence record included in the snapshot — these become `assertion_ids_consumed` and `raw_evidence_ids_consumed`.
5. Runs OPA on the policy with the snapshot as input. Captures the decision log.
6. Validates the verdict is in the allowed enum and contains no numeric fields. Refuses to write if it isn't.
7. Writes the TrustClaim, signed.

Policies cannot import side data. Policies cannot make HTTP calls. Policies see only the snapshot. This is enforced by running OPA in restricted mode with no `http.send` capability and no external `data.*` sources beyond the snapshot.

A policy that needs information not in the snapshot must declare a new required predicate, prompting a new ingestion path — never a backdoor.

---

## 11. Replay / Verify Model

`origin verify` is the determinism test. It must pass on every commit. It performs:

1. **Hash chain integrity.** Walk `assertions/*.jsonl` in chain order; recompute `chain_hash` for each line; verify each matches and matches `chain.log`.
2. **Assertion ID integrity.** For each assertion, recompute the canonical hash; verify it matches `id`.
3. **Signature verification.** Verify each assertion's signature against the attestor's declared key.
4. **Evidence resolvability.** For each assertion, verify `evidence_id` resolves to a raw record whose `payload_hash` matches its filename.
5. **Projection determinism.** Rebuild the projection from scratch into a temp SQLite; hash the dumped schema-ordered table contents; compare against `MANIFEST.json` `projection_hash`.
6. **Claim re-derivation.** Re-evaluate every claim against the rebuilt projection; verify byte-equal output.

Any mismatch is a hard fail. `verify` exits non-zero with the specific drift identified.

Determinism requirements baked in from Day 1:
- All timestamps stored as ISO-8601 UTC, second precision.
- All JSON canonicalization via JCS (RFC 8785).
- Projection rows ordered by `assertion_id` ASC during build, table-by-table.
- Policy evaluation traverses assertions in `assertion_id` ASC order.
- No `random()`, no `now()` inside any normalizer, projector, or policy.

---

## 12. Supersession / Correction Model

Mutation is never permitted. Correction is a new assertion.

A correction assertion carries the same shape as any other, with `revises` populated:

```json
{
  "id": "<new-id>",
  "subject":   "pkg:npm/example@1.0.0",
  "predicate": "published_at",
  "object":    { "literal": "2024-03-10T00:00:00Z", "datatype": "xsd:dateTime" },
  "revises":   "<prior-assertion-id>",
  ...
}
```

Projection rules:
- The projection's per-predicate table includes a `superseded_by` column.
- When a `revises` assertion is projected, the prior assertion row's `superseded_by` is set to the new assertion's id.
- Queries against the projection default to `WHERE superseded_by IS NULL` — they see the current view.
- A separate `assertion_history` table records the full chain by `(subject, predicate, object_key)` so any prior state is reconstructable.
- Time-travel queries are supported by reading `assertion_history` with a `transaction_time <= T` filter.

Superseded assertions remain forever in the log. They are never deleted, never overwritten. The cost of a correction is exactly one new line.

---

## 13. Projection Model

`projections/index.sqlite` is one SQLite file. Schema:

```sql
-- entity tables
CREATE TABLE artifacts   (purl TEXT PRIMARY KEY, kind TEXT, name TEXT, version TEXT);
CREATE TABLE sources     (iri  TEXT PRIMARY KEY, kind TEXT, repo_url TEXT, commit_sha TEXT);
CREATE TABLE identities  (id   TEXT PRIMARY KEY, kind TEXT, key_fp TEXT, login TEXT);
CREATE TABLE attestations(id   TEXT PRIMARY KEY, subject TEXT, predicate_type TEXT, envelope_hash TEXT);

-- one assertion-backed table per predicate
CREATE TABLE depends_on (
  assertion_id TEXT PRIMARY KEY,
  subject TEXT, object TEXT,
  observed_at TEXT, ingested_at TEXT,
  attestor TEXT, evidence_id TEXT, normalizer TEXT,
  superseded_by TEXT
);
CREATE TABLE registry_reports_signing_key (assertion_id TEXT PRIMARY KEY, subject TEXT, object TEXT, observed_at TEXT, attestor TEXT, evidence_id TEXT, normalizer TEXT, superseded_by TEXT);
CREATE TABLE published_by (assertion_id TEXT PRIMARY KEY, subject TEXT, object TEXT, observed_at TEXT, attestor TEXT, evidence_id TEXT, normalizer TEXT, superseded_by TEXT);
CREATE TABLE published_at (assertion_id TEXT PRIMARY KEY, subject TEXT, object_literal TEXT, observed_at TEXT, attestor TEXT, evidence_id TEXT, normalizer TEXT, superseded_by TEXT);
CREATE TABLE affected_by  (assertion_id TEXT PRIMARY KEY, subject TEXT, object_iri TEXT, observed_at TEXT, attestor TEXT, evidence_id TEXT, normalizer TEXT, superseded_by TEXT);

-- raw evidence index (proof of "we looked")
CREATE TABLE raw_evidence (
  id TEXT PRIMARY KEY, source TEXT, endpoint TEXT,
  fetched_at TEXT, payload_hash TEXT, payload_path TEXT,
  result_count INTEGER  -- nullable; null means "not applicable"
);

-- supersession history (full chain)
CREATE TABLE assertion_history (
  subject TEXT, predicate TEXT, object_key TEXT,
  assertion_id TEXT, revises TEXT,
  ingested_at TEXT,
  PRIMARY KEY (subject, predicate, object_key, ingested_at)
);

-- manifest
CREATE TABLE projection_manifest (
  key TEXT PRIMARY KEY, value TEXT
);
-- entries: log_seq_processed, projector_version, vocab_version, schema_hash, built_at
```

Properties:
- Every edge row carries `assertion_id`, `evidence_id`, `attestor`, `normalizer`. Provenance never severs.
- Schema is regenerated from `vocab/<version>.json` by the projector. New predicate = new table.
- `MANIFEST.json` accompanies the SQLite file with the projection hash so `verify` can detect drift.
- Indexes (`subject`, `object`, composite) are added by the projector. They do not affect the projection hash (computed on canonical-ordered row dumps, not file bytes).

The projection is *only* an index. Wiping `projections/` and rerunning `origin project` yields a byte-equivalent SQLite database (per the manifest hash).

---

## 14. End-to-End Trace: One npm Dependency

This trace matches the actual runtime behaviour of the Day-1 prototype.

**Input:** `origin ingest https://github.com/sindresorhus/is`
**Question:** Is the release `pkg:npm/@sindresorhus/is@8.1.0` signed, and corroborated by an independent witness?

**Step 1 — ingest** writes raw records:
```
raw/github.api/2026-05-14/{h1}.bin+.json     ← GET /repos/sindresorhus/is
raw/github.api/2026-05-14/{h2}.bin+.json     ← GET contents/package.json
raw/npm.registry/2026-05-14/{h3}.bin+.json   ← GET full package doc
raw/npm.tarball/2026-05-14/{h4}.bin+.json    ← GET dist.tarball (for SHA-256)
raw/osv.dev/2026-05-14/{h5}.bin+.json        ← POST query for the coordinate
raw/sigstore.rekor/2026-05-14/{h6}.bin+.json ← index/retrieve by tarball SHA-256 (result_count=0)
```

**Step 2 — normalize** emits three assertions to `assertions/<date>.jsonl` and advances `chain.log`:

From `{h3}` via `npm-registry-record@v0.1.0`:
```
<aid1> published_at(pkg:npm/@sindresorhus/is@8.1.0, "2026-05-11T11:22:36.268Z"^^xsd:dateTime)
<aid2> published_by(pkg:npm/@sindresorhus/is@8.1.0, npm:user:sindresorhus)
<aid3> registry_reports_signing_key(pkg:npm/@sindresorhus/is@8.1.0,
                                   npm:key:SHA256:DhQ8wR5APBvFHLF/+Tc+AYvPOdTpcIDqOhxsBHRwC7U)
```

OSV and Rekor emit no assertions — both returned empty result sets. Their evidence records remain in `raw_evidence` so policies can distinguish "we looked" from "we never asked."

Every assertion is signed by the ingestor key. Each appends one line to `chain.log` of the form `<seq>\t<prev_chain_hash>\t<assertion_id>\t<chain_hash>`.

**Step 3 — project**: `origin project` rebuilds `data/projections/index.sqlite`. After this:
- `published_at`, `published_by`, `registry_reports_signing_key` each contain one row for the subject.
- `depends_on`, `affected_by`, `attests_to` are empty for the subject.
- `raw_evidence` records all six fetches; `result_count` is `0` for `osv.dev` and `sigstore.rekor`, `NULL` for the others (where the concept doesn't apply).
- `MANIFEST.json` carries the `projection_hash`, `schema_hash`, `log_seq_processed`.

**Step 4 — eval**: `origin eval 'pkg:npm/@sindresorhus/is@8.1.0' --policy release_signing`

The manifest declares `required_predicates: [registry_reports_signing_key, published_at, published_by]` and `required_raw_sources: [npm.registry, sigstore.rekor]`. The evaluator snapshots all rows from those tables for the subject, hands them to OPA as `input`, and runs the policy.

The policy's verdict ladder (verbatim shape):
- `trusted` requires `cryptographically_verified_signature_by` (Phase-2 predicate, never present Day-1) AND `rekor_returned_hits`. Day-1 cannot reach this.
- `conditional` requires `registry_reports_signing_key` (the OBSERVATION we have) AND any Rekor activity (hit OR queried-without-hit).
- `insufficient_evidence` fires when no signing-key claim from any source exists.

Result: `conditional`, with qualifiers:
```
· registry_reports_signing_key
· no_cryptographic_verification_performed
· rekor_returned_no_entries
· npm_registry_consulted
```

The TrustClaim is written to `claims/<claim-id>.json` with `assertion_ids_consumed = [aid1, aid2, aid3]` and `raw_evidence_ids_consumed = [<npm.registry id>, <sigstore.rekor id>]`.

**Step 5 — why**: `origin why <claim-id>` prints (abridged):

```
Subject:    pkg:npm/@sindresorhus/is@8.1.0
Policy:     release_signing/v1  (hash bc7ae777…)
Verdict:    conditional

Qualifiers:
  · npm_registry_consulted
  · no_cryptographic_verification_performed
  · registry_reports_signing_key
  · rekor_returned_no_entries

Rules fired:
  · npm_was_queried
  · registry_reports_key
  · rekor_was_queried

Assertions consumed (3):
  · <aid1>  published_at = "2026-05-11T11:22:36.268Z"^^xsd:dateTime
            evidence=<h3>  normalizer=npm-registry-record@v0.1.0  attestor=ingestor:origin@0.1.0:<fp>
  · <aid2>  published_by = npm:user:sindresorhus
            evidence=<h3>  normalizer=npm-registry-record@v0.1.0
  · <aid3>  registry_reports_signing_key = npm:key:SHA256:DhQ8wR5APBv…
            evidence=<h3>  normalizer=npm-registry-record@v0.1.0

Raw evidence consumed (2):
  · <h6>   source=sigstore.rekor   result_count=0
  · <h3>   source=npm.registry    https://registry.npmjs.org/@sindresorhus%2Fis
```

`origin explain <aid3>` shows the signed assertion record plus its raw evidence sidecar (source, endpoint, fetched_at, fetcher, payload path).

Note the honest verdict ladder: `trusted` is permanently unreachable Day-1 because we never run cryptographic verification. That's a feature, not a bug — invariant #14 ("derived claims must never silently masquerade as observed facts") holds because the verdict name and qualifier list reflect *only* what was actually observed.

---

## 15. Explicit Non-Goals (Day 1)

The following are deliberately excluded. Attempting any of them on Day 1 is a scope error.

- Maintainer identity clustering (across keys, OIDC, registry logins).
- Any numeric trust score, anywhere, ever.
- Statistical inference, correlation analysis, "failure clusters."
- ML-based ranking, embeddings, or similarity-as-trust.
- Multi-language ecosystems beyond npm.
- Reproducible build verification.
- SBOM ingestion (SPDX, CycloneDX).
- Deep DSSE/in-toto envelope validation beyond presence/absence.
- A custom transparency log service.
- HTTP/GraphQL/SPARQL public APIs.
- Authentication, multi-user, RBAC.
- Distributed deployment, replication, sharding.
- Real-time ingestion / streaming.
- License analysis.
- Issue-tracker, PR, or community-health metrics.
- Any output that aggregates multiple dimensions into a single value.
- Third-party attestation submission into our log.
- AI-generated assertions in the canonical log.

---

## 16. Phase-2 Expansion Criteria

A capability moves from "non-goal" to "candidate" only when **all four gates** are passed:

1. **Invariant safety.** Adding it does not violate any invariant from §1.
2. **Concrete need.** A specific observed user problem requires it. No speculative features.
3. **Additive change.** Implementable as: new predicates (additive vocab version), new normalizers, new policies, new projection tables. Never as modifications to existing canonical structures.
4. **Verifiability preserved.** After the change, `origin verify` continues to pass byte-equality across the entire historical log.

Specific candidates and their gates:

| Phase-2 candidate | Gate beyond the four |
|---|---|
| Second ecosystem (PyPI / Maven) | Day-1 npm flow validated end-to-end on ≥50 representative repos with stable `verify`. |
| Deep DSSE/in-toto verification | Rekor lookup is stable; signing key/identity resolution model is written down. |
| Maintainer activity / dep freshness policies | Done by adding new predicates and policies; no vocab breakage. |
| HTTP API | A second concrete user needs it. Read-only first; never a write endpoint into the assertion log. |
| Identity clustering | Only as an explicit policy emitting `derived_from` claims with cited evidence signals. Never opaque. Never an entity in the ontology. |
| Third-party attestation submission | Attestor reputation model is written down. Root-of-trust set is published with rationale. Signed attestation envelopes verified before append. |
| Public transparency log anchoring | Hash chain has run cleanly for ≥6 months. Rekor (or chosen log) anchor format chosen. |
| Cloud deployment | Local-first remains the supported mode. Cloud is additive, not replacement. Object storage replaces files behind the same interface. |

Capabilities that will **never** be added regardless of demand:
- Numeric aggregate trust scores.
- ML/embedding-driven trust inference in the canonical or policy path.
- Hidden ranking heuristics that bypass policy evaluation.
- AI writing canonical assertions without explicit AI-attestor identity.
- Mutating updates to the assertion log.

---

## Closing Test

The architecture is correct if and only if a hostile reader can answer the following from on-disk artifacts alone, without running the binary:

1. *Where did this claim come from?* → `claims/<id>.json` → `assertion_ids_consumed` → `assertions/*.jsonl` → `evidence_id` → `raw/...`.
2. *Who signed each step?* → `attestor` field on every assertion; ingestor key in `keys/`.
3. *What policy decided this?* → `policy_hash` in the claim → `policies/<id>/policy.rego` at that hash.
4. *Could the same inputs produce a different output?* → No: `origin verify` confirms byte-equality across the entire chain.
5. *What did we know on date X?* → Project the log up to transaction-time X; evaluate at that snapshot.

If any of these answers requires reading the source code of the evaluator beyond version metadata, an invariant has been violated and the design has drifted.
