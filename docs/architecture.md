# Architecture

This document describes how the implementation is organised and how data flows through it. For the rules the architecture serves, see [`invariants.md`](invariants.md). For the protocol specification, see [`../protocol/origin-protocol-v0.md`](../protocol/origin-protocol-v0.md).

## Layers, top-down

```
                    ┌────────────────────────────────────────┐
                    │  Policies (Rego)                       │
                    │  release_signing/v2, dep_hygiene/v1    │
                    └────────────────────────────────────────┘
                                    ▲
                          input: snapshot
                                    │
                    ┌────────────────────────────────────────┐
                    │  Projection (SQLite)                   │
                    │  identities + occurrences + per-       │
                    │  predicate tables + raw_evidence       │
                    │  (deterministic, rebuildable)          │
                    └────────────────────────────────────────┘
                                    ▲
                              walk on demand
                                    │
                    ┌────────────────────────────────────────┐
                    │  Canonical log                         │
                    │  ┌────────────────┐  ┌──────────────┐  │
                    │  │ Identities     │  │ Occurrences  │  │
                    │  │ (content-addr) │  │ (per-log     │  │
                    │  │                │  │  hash chain) │  │
                    │  └────────────────┘  └──────────────┘  │
                    │  Raw evidence (content-addressed bytes)│
                    └────────────────────────────────────────┘
                                    ▲
                                 ingest
                                    │
                    ┌────────────────────────────────────────┐
                    │  External sources                      │
                    │  GitHub · npm · OSV · Rekor · Sigstore │
                    └────────────────────────────────────────┘
```

The boundaries are sharp:

- Bytes only cross upward into the log via signed Identity envelopes, with a versioned Normalizer in the metadata. Nothing else crosses.
- The projection is a pure function of the log + projector version. Any difference between projection and log on replay is a hard fail.
- Policies see only the snapshot. Nothing else.
- TrustClaim output is categorical. Nothing else.

## Building blocks

### Raw evidence

Verbatim bytes from an external source. Stored under `data/raw/<source>/<yyyy-mm-dd>/<sha256>.bin` with a signed metadata sidecar `<sha256>.json`. The filename's `<sha256>` is the content hash of the bytes; storage is content-addressed.

Each fetch produces a raw evidence record regardless of whether it triggers an Identity. A successful "we looked at OSV for `pkg:npm/foo@1.0.0`" with zero vulnerabilities returned is recorded; this is how the system distinguishes "we did not check" from "we checked and found nothing".

### Identities

The canonical fact. An Identity is the content-addressed envelope:

```
{
  "subject":     <IRI>,
  "predicate":   <vocabulary term>,
  "object":      <discriminated union: iri | literal | ref>,
  "evidence_id": <hash of a raw evidence payload>,
  "observed_at": <RFC 3339, source-claimed time>,
  "normalizer":  <versioned identifier>,
  "vocab":       <vocabulary version>,
  "revises":     <prior identity id, or null>
}
```

Its `id` is `SHA-256(JCS(envelope))`. Two ingestors who observe the same source bytes through the same normalizer produce the same Identity ID.

### Occurrences

The local event of recording an Identity. Distinct from the Identity itself:

```
{
  "identity_id":     <hash of the cited Identity>,
  "attestor":        <who recorded this — local ingestor or peer reference>,
  "attestor_role":   "observer" | "verifier" | "federated_importer",
  "ingested_at":     <RFC 3339, local time>,
  "log_id":          <log this Occurrence belongs to>,
  "prev_chain_hash": <hex>,
  "chain_hash":      <hex>,
  "signature":       <Ed25519 over canonical envelope>
}
```

Each Occurrence is signed and chained. Multiple Occurrences may cite one Identity (federation, multiple local witnessings, etc.).

### TrustClaims

The output of one policy evaluation. A record of an event, not a property of the subject:

```
{
  "subject":                <subject IRI>,
  "policy_id":              <string>,
  "policy_version":         <vN>,
  "policy_hash":            <hash of policy bundle>,
  "verdict":                <one of four enum values>,
  "qualifiers":             [enumerated strings],
  "identity_ids_consumed":  [sorted hashes],
  "raw_evidence_ids_consumed": [sorted hashes],
  "derivation": {
      "rules_fired":        [strings],
      "missing_predicates": [strings] or null,
      "input_counts":       {predicate → count},
      "occurrences_cited":  {identity_id → [occurrence_id]}
  },
  ...
}
```

Local timestamps (`evaluated_at`) and ingestor-specific hashes (`projection_manifest_hash`, `identities_hash`) live in the record but are excluded from the canonical bytes that compute the claim ID. The claim ID is byte-identical across ingestors who consumed the same Identities.

### Policies

Rego (OPA) modules under `policies/<id>/<version>/`. Each version is immutable. Policies are pure functions of the snapshot. The output is constrained to a categorical verdict plus enumerated qualifiers — no numeric fields, no free text.

Current policies:

- `release_signing/v1` — registry-claim-only model (frozen).
- `release_signing/v2` — adds verified-form signature requirement (current default).
- `dependency_hygiene/v1` — direct-dep + OSV check.

### Projection

`data/projections/index.sqlite`. One file. Built from scratch by walking the Identity store + occurrence logs + raw evidence store. Tables:

- `identities` — one row per Identity, with `(id, predicate, subject)`.
- `occurrences` — one row per Occurrence, with `attestor`, `attestor_role`, `log_id`, `chain_hash`, etc.
- `identity_history` — supersession chains (`revises` relationships).
- `raw_evidence` — every raw record, indexed by source.
- `<predicate>` — one table per predicate (per vocab v6), with PK `identity_id`.

A `MANIFEST.json` sidecar carries `projection_hash` (full state) and `identities_hash` (fact-side only, federation-stable).

### Federation

Filesystem-only. A peer's archive is imported via `origin import-occurrences` with the peer's public key and log id:

```
peer-a's data/                  ← imports peer-b's archive
├── assertions/identities/      ← peer-b's observation/structural identities are stored here
│                                  (foreign verification-class identities are NOT stored)
├── assertions/occurrences/
│   ├── local/                  ← peer-a's own occurrences (unchanged)
│   └── foreign/
│       └── log_<peer-b-fp>/    ← peer-b's occurrences, signed by peer-b, verbatim
├── peers/<peer-b-log-id>.pub   ← peer-b's pubkey
└── raw/foreign.occurrence/     ← verbatim foreign occurrence bytes (audit trail)
```

The rewrite rule (invariant 6) creates a NEW local Identity with predicate `peer_reports_cryptographic_verification_of` (or its refutation counterpart) for each foreign verification/refutation-class Identity. The local Identity references the foreign by ID; the foreign verification-class Identity itself is never placed in the local identity store.

### Anchoring

Optional. A checkpoint is the signed summary `(log_id, seq, chain_hash, signed_at)` written as raw evidence. The operator submits the checkpoint to a transparency system out-of-band (Rekor, git tag, signed paste, anything append-only) and feeds the system's response back into Origin via `origin record-anchor`. The resulting Identity is observation-class:

```
transparency_log_records_checkpoint(
    subject:      checkpoint:<hash>,
    object:       <provider-entry-IRI>,
    evidence_id:  <hash of provider response bytes>
)
```

Verify check #13 cross-references each anchor against the local chain and reports OK, TAMPER, TRUNCATED, or MISSING_LOG. The check never consults the transparency system at replay time.

## Data flow: `origin ingest <github-url|pkg:>`

```
1. Parse coordinate (github URL → resolve to pkg:npm/...)
2. Fetch from npm registry → raw evidence record
3. Normalize: emit Identities for published_at, published_by,
   registry_reports_signing_key, depends_on
4. Fetch from OSV → raw evidence record
5. Normalize: emit affected_by Identities (if any)
6. Fetch tarball → raw evidence record (content hash recorded)
7. Query Rekor by tarball SHA-256 → raw evidence record
8. Fetch npm attestations endpoint → raw evidence record
9. For the SLSA Provenance attestation:
     - run Sigstore verifier (local, against pinned Fulcio root)
     - if pass: emit cryptographically_verified_signature_by Identity
     - if fail: emit cryptographic_verification_failed Identity
10. For each emitted Identity, append an Occurrence to the local log
    (chain advances; signed by local ingestor key)
```

## Data flow: `origin verify`

The thirteen checks:

1. Identity reproducibility — recompute every Identity's canonical hash.
2. Occurrence signatures — verify signature + recompute Occurrence id.
3. Chain integrity (local log) — recompute chain hashes in sequence.
4. Identity ↔ occurrence linkage — every Occurrence cites an existing Identity.
5. Raw evidence resolvability — every Identity's `evidence_id` resolves.
6. Projection determinism — rebuild projection; assert `projection_hash` equality.
7. Claim envelope consistency — recompute every claim's canonical bytes.
8. Cryptographic re-verification — re-execute Sigstore verification on every verified-form Identity.
9. Claim re-derivation determinism — re-evaluate every claim and assert byte-identical ID.
10. Foreign chain integrity — same as #3 but per peer-log-id.
11. Foreign occurrence signatures — same as #2 but against peer public keys.
12. No-laundering — every `federated_importer`-role occurrence cites an observation- or structural-class predicate.
13. Anchor integrity — every anchor's `(log_id, seq, chain_hash)` triple matches the current chain.

Any single failure is a hard fail with the specific cause surfaced.

## Module boundaries

- `cmd/origin/` — CLI dispatch.
- `internal/canon/` — JCS canonicalisation (no dependencies; auditable in isolation).
- `internal/assertion/` — Identity + Occurrence types, stores, logs.
- `internal/chain/` — hash-chain primitives.
- `internal/raw/` — raw-evidence store.
- `internal/keys/` — local Ed25519 signing key + ring.
- `internal/vocab/` — vocabulary loader.
- `internal/sigstore/` — Sigstore verifier (uses `sigstore-go`).
- `internal/ingest/` — connectors (GitHub, npm, OSV, Rekor, npm-attestations) + normalizers.
- `internal/project/` — SQLite projector.
- `internal/eval/` — policy evaluator (OPA).
- `internal/explain/` — `why` + `explain` commands.
- `internal/verify/` — thirteen verify checks.
- `internal/report/` — static HTML report renderer.
- `internal/peers/` — peer pubkey registry.
- `internal/peerimport/` — federation importer.
- `internal/checkpoint/` — Phase-5 checkpoint signing + `origin checkpoint` CLI.
- `internal/anchor/` — Phase-5 `origin record-anchor` CLI.
- `internal/demo/` — `origin demo` flow + tarball.

External dependencies live in `go.mod` and are deliberately few:

- `modernc.org/sqlite` — pure-Go SQLite (no CGO).
- `github.com/sigstore/sigstore-go` — Sigstore primitives.
- `github.com/open-policy-agent/opa` — Rego evaluator.

No HTTP client beyond `net/http` stdlib. No external trust-root fetcher. No telemetry. No ML.
