# Origin

A provenance-backed evidentiary database for software artefacts. Origin records what was observed about software (releases, signatures, vulnerability advisories, attestations, peer claims) into an append-only signed log, projects that log into a queryable shape, and lets categorical trust policies derive **claims** from the recorded evidence.

Trust here is a query result over evidence and a versioned policy. It is not a stored property of any subject. Origin does not produce scores. It does not rank, recommend, or personalise. Same evidence, different policy: different verdict — both correct, both reproducible.

This repository contains a working reference implementation and a frozen v0 protocol specification.

> If you are coming from the broader trust, reputation, or supply-chain-security space, read [`docs/what-origin-is-not.md`](docs/what-origin-is-not.md) **first**. Several common assumptions about projects in this area — scores, AI reputation, consensus truth, popularity weighting, opaque heuristics — do not apply here, and the rest of the README will read differently if you start with them in mind.

---

## What problem this is for

Software supply-chain trust is increasingly mediated by attestations, signed releases, transparency logs, and registry metadata. The bottleneck is no longer producing those signals; it is reasoning about them honestly. Most existing tools either:

- collapse signals into an opaque score, or
- assert "trusted" based on which sources said what, with no operational distinction between *observation* and *verification*.

Origin's central commitment is that **observation is not inference, and verification is local.** A registry reporting that a package has a signing key is an observation. Local cryptographic verification of that signature against the artefact's bytes — anchored to a pinned trust root — is a separate kind of fact. Federation between Origin nodes does not let one node's verification become another node's verification. Anchoring a checkpoint into a transparency log is the local node's record of *having submitted* a checkpoint; it is not a claim that the underlying data is true.

If those distinctions matter for the system you are building, this might be useful. If you want a one-number trust score, Origin is not the right tool.

---

## What Origin is, in one sentence per layer

- **Canonical layer.** An append-only log of signed, content-addressed, JCS-canonicalised assertions; raw evidence stored verbatim and content-addressed; a per-log Merkle-ish hash chain.
- **Projection layer.** A deterministic SQLite index built from the log; rebuildable from scratch in seconds; useful for queries.
- **Policy layer.** Rego (OPA) policies that consume snapshots of the projection and produce categorical claims with derivation DAGs. No numerics in the output.
- **Federation layer.** Filesystem-only. One Origin node can import another's identity log + occurrence log; foreign verification-class predicates are rewritten as observation-class `peer_reports_*` at the boundary. The no-laundering invariant is enforced both at import time and at verify time.
- **Anchor layer.** Optional. Local chain heads can be signed as Checkpoints and submitted out-of-band to an external transparency system (Rekor, git tag, signed pastebin — anything append-only). The system's response is recorded as an observation-class fact. The transparency system is a timestamping witness, never an authority.

## What Origin is NOT

- It is not a trust score, ranking, or recommendation engine.
- It is not a SaaS. The implementation is a single CLI binary; bundles are portable directories.
- It is not a network service. Federation is filesystem-only.
- It is not an opinion. The system records evidence, derives claims under policy, and explains itself. It does not say "this is good."
- It is not a replacement for code review, build hygiene, or operational security. It is one piece of an audit story.

## Status

Early protocol software. The v0 protocol is frozen; the implementation passes its fixture byte-equality tests. External adversarial review is wanted.

The implementation is small (~5500 LOC of Go). There are corners that have not been stress-tested. See [`docs/threat-model.md`](docs/threat-model.md) for what Origin defends against and — more important — what it explicitly does not.

---

## Repository layout

```
origin/
├── cmd/origin/              CLI entry point
├── internal/                implementation packages
├── policies/                Rego policy directories, versioned per policy
├── vocab/                   versioned vocabulary files (predicate declarations)
├── protocol/
│   ├── origin-protocol-v0.md     frozen specification
│   └── v0-fixtures/              hermetic byte-equality test data
├── docs/
│   ├── invariants.md             rules implementations and reviewers can audit against
│   ├── epistemic-model.v1.md     formal epistemic model
│   ├── architecture.md           operational overview
│   ├── threat-model.md           what we do and do not defend against
│   ├── glossary.md               terms used across the docs
│   └── release-checklist.md      pre-release verification steps
├── examples/                copies of demo tarballs and federation walk-throughs
├── scripts/                 helper scripts
├── testdata/                shared test inputs
└── memory/archive/          phase-planning documents (historical, non-normative)
```

`data/` is the operator's working directory; it is gitignored. Never commit it.

---

## Quickstart

Requires Go 1.26 or later (matches `go.mod`).

```sh
# Build
go build -o origin ./cmd/origin

# Ingest a real npm package (one with Sigstore provenance)
./origin ingest 'pkg:npm/@sigstore/sign@2.3.2'

# Build the projection
./origin project

# Evaluate two policies
./origin eval 'pkg:npm/@sigstore/sign@2.3.2' --policy release_signing
./origin eval 'pkg:npm/@sigstore/sign@2.3.2' --policy dependency_hygiene

# Replay-check every canonical artefact (13 checks)
./origin verify
```

For verbose drill-down into any one fact:

```sh
./origin why     <claim-id>          # full derivation DAG
./origin explain <identity-id>       # one fact + its evidence
```

---

## Producing and sharing a portable demo

```sh
./origin demo 'pkg:npm/@sigstore/sign@2.3.2' --output ./out
```

The output is a single `origin-demo-<subject>-<timestamp>.tar.gz` containing the full canonical state, the projection, both claims, the HTML report, the protocol spec, the vocab, and the policies. Recipients can:

```sh
mkdir review && tar -xzf origin-demo-*.tar.gz -C review
cd review && origin verify        # all 13 checks pass offline
open data/reports/*.html          # the report opens with no network
```

If any of the 13 checks fail, the bundle is rejected. The verify output names the specific failing artefact and why.

---

## Federation, briefly

Two Origin nodes can share without one inheriting the other's verifications:

```sh
# Node A imports Node B's archive over filesystem
./origin import-occurrences /path/to/peer-b/data \
    --peer-key  <hex-of-peer-b-pubkey>            \
    --peer-log-id  log:<peer-b-fingerprint>
```

Foreign observation-class assertions land as-is in `data/assertions/occurrences/foreign/<peer-log-id>/`. Foreign verification-class assertions (e.g. `cryptographically_verified_signature_by`) are **rewritten at the boundary** as observation-class `peer_reports_*` predicates and stored separately. The original foreign verification-class identity is NOT placed in the local identity store.

Verify check #12 (no-laundering) enforces this structurally: every `federated_importer`-role occurrence must cite an observation- or structural-class predicate. Any violation fails verify with the offending occurrence ID surfaced.

See [`docs/architecture.md`](docs/architecture.md) for the data-flow diagram, and [`docs/threat-model.md`](docs/threat-model.md) for what this does and does not protect against.

---

## Anchoring, briefly

Local chain heads can be checkpointed and submitted to an external transparency system. The act of submission is recorded as an observation:

```sh
./origin checkpoint --output ./checkpoint.json    # signs current chain head
# (operator submits ./checkpoint.json to Rekor / git / etc. out-of-band)
./origin record-anchor \
    checkpoint:<hash> \
    rekor:<entry-id> \
    --evidence ./rekor-response.json
```

The new identity has predicate `transparency_log_records_checkpoint` (observation class). Verify check #13 cross-references the anchor against the current chain and reports OK, TAMPER, TRUNCATED, or MISSING_LOG.

Anchoring strengthens tamper-evidence. It does not produce verification, authority, consensus, or freshness guarantees. See [`docs/invariants.md`](docs/invariants.md).

---

## Running the protocol fixtures and tests

```sh
go test ./...
```

The fixture suite at `protocol/v0-fixtures/` runs in under a second with no network access. It re-derives every canonical envelope and asserts byte-equality against the committed reference files. Any implementation that produces matching outputs against the same fixture inputs is conformant under v0.

Federation rewrites are exercised by `TestFederation_RewriteRule`. Anchor invariants are exercised by `TestAnchorFixture` and `TestAnchorVocabClass`.

---

## How to review or attack the protocol

If you are evaluating Origin adversarially, the highest-leverage targets are:

1. **The invariants doc** [`docs/invariants.md`](docs/invariants.md). Every claim Origin makes rests on these. If a claim can be made to violate one, that is a finding.
2. **The verify procedure** ([`docs/architecture.md`](docs/architecture.md) §verify). Twelve checks plus one anchor check. If you can produce on-disk state that passes all 13 but is internally false (a forged or laundered claim), that is a major finding.
3. **The federation boundary** ([`docs/threat-model.md`](docs/threat-model.md) §federation). The rewrite rule is the single load-bearing line between "we federate" and "we launder trust". If a federated import can land a verified-form identity in the local verification table, that is a critical finding.
4. **The fixtures** ([`protocol/v0-fixtures/`](protocol/v0-fixtures/)). If the implementation drifts from the spec, the fixture self-test fails. Show us a drift we missed.
5. **The protocol spec** ([`protocol/origin-protocol-v0.md`](protocol/origin-protocol-v0.md)). Ambiguities are bugs.

See [`SECURITY.md`](SECURITY.md) for how to report findings.

---

## License

See [`LICENSE`](LICENSE).

## Contributing

See [`CONTRIBUTING.md`](CONTRIBUTING.md). Some contributions are out of scope by design (scores, ML inference in the trust path, runtime trust-root fetching, silent canonicalisation changes); the document explains why.
