# Phase 3.5 Plan: Filesystem Federation

> **Phase 3.5 thesis.** Phase 3 separated AssertionIdentity from AssertionOccurrence so that the same fact observed by two ingestors collapses to one identity and two occurrences. Phase 3.5 exercises that split: a foreign origin node's occurrence log is imported across a filesystem boundary. The test is whether the boundary enforces invariant 16 (verified-form locality) under operational pressure. If a peer says "I verified X" and our local node records that claim *as a verification we performed*, the system has laundered trust. The structural rule preventing this — verified-form predicates are rewritten at the import boundary as observation-class `peer_reports_*` predicates — is what this phase makes operational.

No network. No SaaS. No HTTP. No automatic peer discovery. The interface is filesystem-only: one origin node hands another node a directory of occurrence records and a public key, and the receiving node imports them in a way that preserves local epistemic integrity.

This phase is additive on Phase 3 and changes no existing data shapes incompatibly. It does require one storage-layout adjustment (the local occurrence log moves into a `local/` subdirectory so foreign logs can sit alongside under `foreign/<peer-log-id>/`).

---

## 1. The rewrite rule

The single rule that everything in this phase rests on:

**At the import boundary, foreign occurrences whose identity has `verification_class ∈ {verification, refutation}` MUST be rewritten as observation-class `peer_reports_*` predicates. The original foreign identity is NOT stored locally; only the rewritten local identity (which references the foreign identity by ID-as-ref) enters the local identity store.**

Examples:

| Foreign identity predicate | At local import boundary becomes |
|---|---|
| `cryptographically_verified_signature_by` (verification) | `peer_reports_cryptographic_verification_of` (observation) |
| `cryptographic_verification_failed` (refutation) | `peer_reports_cryptographic_verification_failed_of` (observation) |
| `registry_reports_signing_key` (observation) | imported as-is (no rewrite needed) |
| `published_at`, `published_by`, `depends_on` (observation) | imported as-is |
| `revises`, `derived_from` (structural) | imported as-is |

The object of a rewritten identity is `{kind: ref, ref: <foreign-identity-id>}` — the local fact is "the peer reports that they verified the identity with this ID." A future local verifier run can independently produce a verified-form identity; until then, the peer's verification is observation-only.

This rule is enforced at TWO layers:
- **At import time:** the importer refuses to write a federated_importer-role occurrence that names a verification-class predicate. The vocab-driven `roleFor(predicate)` check from Phase 3 already provides this; the importer respects it.
- **At verify time:** a new check walks every federated_importer occurrence and asserts its identity's predicate has `verification_class ∈ {observation, structural}`. Any violation surfaces.

---

## 2. Scope (in / out)

**In scope:**
- One new CLI: `origin import-occurrences <path> --peer-key <pubkey> --peer-log-id <log:id>`.
- Local peer-key registry at `data/peers/<peer-log-id>.pub`.
- Storage layout change: local occurrences move from `data/assertions/occurrences/*.jsonl` to `data/assertions/occurrences/local/*.jsonl`; foreign occurrences live under `data/assertions/occurrences/foreign/<peer-log-id>/*.jsonl`. Each chain is independent.
- Vocab v5 (additive): two new observation-class predicates — `peer_reports_cryptographic_verification_of` and `peer_reports_cryptographic_verification_failed_of`.
- Boundary rewrite for verification/refutation-class foreign identities.
- Foreign occurrences stored as raw evidence too (source `foreign.occurrence`) so an auditor can re-execute peer signature verification against the original bytes.
- Verify extension: foreign chain integrity per peer-log-id; foreign occurrence signatures against peer keys; no-laundering check.
- Projection extension: occurrences table already carries `attestor_role` and `log_id`; queries that filter "local-only" become trivial joins.
- One end-to-end demonstration: ingestor A imports ingestor B's log; local claims unchanged; the imported peer-reports predicate visible in projection but excluded from `release_signing/v2` reasoning.

**Out of scope (explicit non-goals):**
- No network. No SaaS. No HTTP. No automatic discovery. No DHT. No gossip.
- No re-signing of foreign occurrences. Foreign records preserve their original peer signatures.
- No peer-key rotation handling (a rotated peer key is a new peer-log-id; old occurrences remain verifiable under their original key as long as the original key is retained in the registry).
- No automatic re-verification of foreign verified-form claims. Promoting a `peer_reports_*` observation to a local verified-form predicate requires running the local verifier against the original artifact bytes — that is just normal local ingestion, not a federation primitive.
- No transitive trust. A peer's claim that ANOTHER peer verified something is two layers of observation; no path through that chain produces a local verified-form identity.
- No conflict resolution beyond per-log-id chain integrity. If two peers happen to choose the same log_id (unlikely with key-fp-derived defaults; possible if both override via `log-id.txt`), the second import is refused with a clear error.
- No new policies. `release_signing/v2` and `dependency_hygiene/v1` remain frozen. Phase 3.5 does not introduce policies that consume `peer_reports_*` predicates; that is policy-author work in a later phase.

---

## 3. New CLI: `origin import-occurrences`

```
origin import-occurrences <path> \
    --peer-key   <hex-or-file>     # 32-byte ed25519 public key
    --peer-log-id <log:id>          # the foreign log identifier
    [--register-only]               # store peer key but do not import yet
```

The `<path>` is one of:
- A directory mirroring the foreign node's occurrence layout (`<path>/*.jsonl` + `<path>/chain.log`).
- A single JSONL file containing the foreign occurrences in chain order, plus a sibling `chain.log` if available.

On first encounter with a peer-log-id, the public key is stored at `data/peers/<peer-log-id>.pub`. On subsequent imports for the same peer-log-id, the supplied `--peer-key` must match the stored key (a hard fail otherwise); if `--peer-key` is omitted, the stored key is used.

### Import algorithm

```
For each foreign occurrence in chain order:
    1. Verify the occurrence's id (recompute canonical hash).
    2. Verify the occurrence's signature against the peer public key.
    3. Confirm the occurrence's log_id == --peer-log-id (refuse otherwise).
    4. Confirm chain continuity: prev_chain_hash equals the prior
       occurrence's chain_hash (or chain.Genesis for the first).
    5. Store the verbatim occurrence JSONL bytes under
       data/raw/foreign.occurrence/<date>/<sha256>.bin (audit trail).
    6. Look up the foreign identity by its identity_id:
        - If we have foreign identity bytes (peer also shipped them):
          verify their canonical hash, then route by verification_class.
        - If we don't (occurrence imported alone): we cannot synthesise
          the identity; refuse this occurrence with a clear error
          ("identity %s not in local store; supply the identity envelope
          via --foreign-identities <path> or import a fuller archive").
    7. Route by verification_class of the foreign identity's predicate:
        - observation, structural:
            Store the foreign identity AS-IS in our identity store
            (content-addressed; if we already have it, no-op).
            Write the foreign occurrence into
            data/assertions/occurrences/foreign/<peer-log-id>/<date>.jsonl
            with its OWN chain advancing in
            data/assertions/occurrences/foreign/<peer-log-id>/chain.log.
            The occurrence's attestor remains the peer's attestor; its
            attestor_role remains whatever the peer recorded (observer);
            its signature remains the peer's signature.
        - verification, refutation:
            DO NOT store the foreign identity in our local identity store.
            Construct a local rewritten identity:
                subject:    same as foreign
                predicate:  peer_reports_<class>_of  (vocab v5)
                object:     { kind: ref, ref: <foreign-identity-id> }
                evidence_id: <sha256 of the foreign occurrence bytes
                             we just stored under foreign.occurrence>
                observed_at: foreign occurrence's ingested_at
                normalizer:  "federation-import@v0.1.0"
                vocab:       active vocab version
            Store the rewritten local identity (idempotent).
            Append a LOCAL occurrence (signed by our key) with
                attestor_role: federated_importer
                attestor:      "peer:<peer-log-id>"
                log_id:        our local log
            The local occurrence cites the rewritten local identity, NOT
            the foreign verified-form identity. The foreign verified-form
            identity is never present in our local log under any form.
```

### Sticky points the algorithm closes

- The original foreign occurrence's bytes ARE preserved (in `data/raw/foreign.occurrence/...`). An auditor can re-run signature verification against the peer's recorded key. Nothing of forensic value is lost.
- For verification/refutation imports, the LOCAL occurrence is signed by US (the importer), saying "I, this local node, observed that the peer claimed to have verified X." That's a true claim; we did observe their claim. We didn't verify X ourselves.
- The foreign chain for observation/structural imports advances in `foreign/<peer-log-id>/chain.log`. For verification/refutation rewrites, the LOCAL chain advances (we wrote a new local occurrence). The foreign chain at that position records "the peer wrote a verification occurrence we refused to import as-is"; we record this by writing a sentinel `data/assertions/occurrences/foreign/<peer-log-id>/skipped.jsonl` listing the foreign occurrence IDs we declined to import directly. The skipped log advances the foreign chain locally so chain integrity survives.

---

## 4. Vocab v5 (additive)

Two new predicates added to `vocab/v5.json`; everything else unchanged.

```jsonc
"peer_reports_cryptographic_verification_of": {
  "subject_kind": "artifact",
  "object_kind":  "ref",
  "verification_class": "observation",
  "description": "A federated peer claims to have cryptographically verified a signature for the artifact, with the foreign identity ID as the reference. OBSERVATION class: we did not verify the signature ourselves. Promotion to local verified-form requires running the local verifier (invariant 16 + layer-3.5.md §1)."
},
"peer_reports_cryptographic_verification_failed_of": {
  "subject_kind": "artifact",
  "object_kind":  "ref",
  "verification_class": "observation",
  "description": "A federated peer claims their verifier rejected an attestation for the artifact. OBSERVATION class: their negative judgement is our observation, not our refutation."
}
```

Note: both are observation-class. They could conceivably be a fourth class (`federated_observation`) but Phase 3.5 deliberately keeps the class enum small. Observation is correct: we observed the peer's claim. Policies that want to distinguish "we observed directly" from "we observed via a peer" can match on the predicate name's `peer_reports_` prefix.

---

## 5. Storage layout change

Day-3 layout is `data/assertions/occurrences/*.jsonl` + `chain.log`. Phase 3.5 introduces a one-time migration:

```
data/assertions/occurrences/
├── local/                                 (moved from root)
│   ├── <yyyy-mm-dd>.jsonl
│   └── chain.log
├── foreign/
│   └── <peer-log-id>/
│       ├── <yyyy-mm-dd>.jsonl
│       ├── chain.log
│       └── skipped.jsonl                 (verification/refutation IDs we refused)
└── (nothing else)
```

Migration helper: `origin migrate-v3.5 --confirm` moves existing occurrences/*.jsonl and chain.log into `local/`. The OccurrenceLog type accepts a directory; callers point it at the appropriate subdirectory.

Raw evidence layout gains a new source:

```
data/raw/foreign.occurrence/<yyyy-mm-dd>/<sha256>.bin    (foreign occurrence JSONL bytes)
data/raw/foreign.occurrence/<yyyy-mm-dd>/<sha256>.json   (metadata sidecar)
```

The peer-key registry:

```
data/peers/<peer-log-id>.pub                            (32-byte raw ed25519 public key)
```

---

## 6. Projection extensions

The Phase 3 projection schema already has `occurrences` with `log_id` and `attestor_role` columns. Two query patterns become useful in Phase 3.5; both are additive views, not schema changes:

```sql
-- "facts witnessed by local ingestors only"
SELECT DISTINCT identity_id FROM occurrences WHERE attestor_role = 'observer' OR attestor_role = 'verifier';

-- "facts where a peer claimed verification but we have not"
SELECT i.id, i.subject
FROM identities i
JOIN peer_reports_cryptographic_verification_of p ON p.object = i.id
WHERE NOT EXISTS (
  SELECT 1 FROM cryptographically_verified_signature_by v WHERE v.subject = i.subject
);
```

The second query is the operational version of "trust laundering would have hidden this." If it's non-empty, the system is honestly reporting "the peer says verified, we have not confirmed." That is exactly the visibility the rewrite rule is meant to preserve.

The `identities_hash` computation continues to exclude occurrence-side variation, so claim IDs remain federation-stable. Importing peer occurrences does NOT change any local claim's ID unless the import added new IDENTITIES that policies happen to consume — and the rewrite rule ensures imported verified-form facts never become local verified-form identities, so existing `release_signing/v2` claims are unaffected by imports.

---

## 7. Verify extensions

Phase 3 has 9 checks. Phase 3.5 adds three:

10. **Foreign chain integrity (per peer-log-id).** For each subdirectory under `foreign/`, walk its chain.log and confirm hash continuity. Run the same algorithm as the local chain check, just with a different chain root.

11. **Foreign occurrence signatures.** For each foreign occurrence in each foreign log, verify the signature against the peer public key registered at `data/peers/<peer-log-id>.pub`. If the registry lacks the key, refuse with a clear error.

12. **No-laundering check.** Walk every federated_importer-role occurrence in the local log; resolve its identity_id; assert the identity's predicate has `verification_class ∈ {observation, structural}`. Any violation is a hard fail with the offending identity ID surfaced. This check enforces the rewrite rule structurally — even if a future code change tried to import a verified-form predicate via the federated_importer role, verify would catch it on the next run.

The full verify suite becomes twelve checks. The closing test for Phase 3.5 is that all twelve pass on a data tree containing both local ingestions and peer imports.

---

## 8. Falsifiable success criteria

User-stated seven, mapped to specific tests:

| # | Criterion | Test |
|---|---|---|
| 1 | Foreign occurrences verify against the peer public key. | Import ingestor B's log into ingestor A. Tamper with one foreign occurrence's signature byte; re-run `origin verify` on A; the foreign-occurrence-signatures check fails with the specific occurrence ID. |
| 2 | Foreign log chains validate independently. | After import, A's `verify` includes a "foreign chain integrity (per log)" line showing B's chain head; tampering with a foreign chain.log line breaks that check only, not the local chain. |
| 3 | Imported occurrences remain under their original log_id. | Query `SELECT DISTINCT log_id FROM occurrences` on A's projection; the result includes A's local log_id AND B's log_id; no occurrence has had its log_id rewritten. |
| 4 | Imported verified-form claims do NOT become local verified facts. | B's log contains a `cryptographically_verified_signature_by` identity. After import to A, `SELECT COUNT(*) FROM cryptographically_verified_signature_by` on A is unchanged from before the import. The foreign verified-form identity is NOT present in A's identities table. |
| 5 | Verified-form imports become `peer_reports_*` observation identities. | After import, `SELECT * FROM peer_reports_cryptographic_verification_of` on A returns one row whose `object` column contains B's foreign identity ID. |
| 6 | Local claims remain byte-identical unless a policy explicitly consumes peer reports. | Re-run `origin eval pkg:npm/@sigstore/sign@2.3.2 --policy release_signing` on A after the import; the claim ID is byte-identical to the pre-import claim ID. (The `release_signing/v2` policy does not consume `peer_reports_*` predicates.) |
| 7 | `origin verify` passes across local + imported logs. | After import, all twelve verify checks pass on A. |

A seventh implicit criterion: the no-laundering check (verify #12) refuses to pass if any code path bypasses the rewrite rule. We will deliberately construct a test case that tries to import a verified-form occurrence as-is and confirm the importer rejects it.

---

## 9. Sequence of work

Each step ends compiling, all existing tests passing.

1. **Vocab v5.** Add the two `peer_reports_*` predicates; vocab loader unchanged.
2. **Storage migration helper.** `origin migrate-v3.5 --confirm` moves `data/assertions/occurrences/*.jsonl` and `chain.log` into `local/`. Run once; preserves existing chain hashes (they're over occurrence IDs, not paths).
3. **OccurrenceLog accepts arbitrary directory + log_id.** Already does; the only change is callers point at `occurrences/local/` instead of `occurrences/`.
4. **Peer-key registry.** New package `internal/peers/`. Load/store `data/peers/<peer-log-id>.pub`. Lookup-by-log-id and -by-fingerprint.
5. **Foreign occurrence reader.** New helper that walks a foreign occurrence directory (JSONL + chain.log), verifying signatures and chain continuity inline.
6. **Boundary rewrite logic.** `internal/import/` package containing the import algorithm of §3.
7. **CLI: `origin import-occurrences`** wired to the importer; flag parsing; first-import vs subsequent-import semantics.
8. **Projection updates.** Per-predicate table for the two new predicates (object stored as ref-id text); projector dispatches; snapshot builder dispatches.
9. **Verify additions.** Three new checks; reorder into a stable order; update the closing-test section of `epistemic-model.v1.md` §12.
10. **End-to-end demonstration.** Two ingestors (the existing two-process setup from Phase 3); B publishes its occurrence log + identity log to a directory; A imports it; checks 1-7 of §8 all hold.

---

## 10. Explicit non-goals (Phase 3.5)

- No network. No HTTP. No gRPC. No DHT. No content-addressed peer-to-peer.
- No transparency-log anchoring of the local chain (deferred).
- No peer reputation. The local node trusts or distrusts a peer entirely; there is no gradient.
- No automatic peer discovery. Every import is operator-initiated with explicit `--peer-key` on first encounter.
- No transitive trust. A peer's claim that ANOTHER peer verified something is two layers of observation; we cannot promote either to local verification.
- No automatic re-verification on import. If a policy wants to escalate `peer_reports_cryptographic_verification_of` to local `cryptographically_verified_signature_by`, the operator must run `origin ingest` for that package — the same path any new package takes. Phase 3.5 deliberately does not add a shortcut.
- No policies that consume the new `peer_reports_*` predicates. Their existence in vocab makes such policies POSSIBLE, but writing them is a later phase's concern.
- No replacement of existing policies. `release_signing/v2` and `dependency_hygiene/v1` are frozen.

---

## 11. Risks discovered ahead of implementation

- **Foreign identity availability.** If a peer ships only their occurrence log without the corresponding identity envelopes, we cannot determine the predicate of each foreign occurrence's identity (and thus cannot apply the rewrite rule). Mitigation: foreign identity envelopes are ALSO importable via the same archive shape (`identities/*.jsonl` alongside `occurrences/`). The importer requires identity envelopes for every cited identity; missing identities are a hard error, not a silent skip.
- **Foreign chain partial archives.** A peer that ships only the most recent N occurrences will have a non-Genesis prev_chain_hash on its first entry. The importer accepts this by treating the supplied prev_chain_hash as the chain root for that segment, but records the gap explicitly in `data/assertions/occurrences/foreign/<peer-log-id>/segment-info.json` so verify reports "this is a partial chain segment, gaps before <hash>."
- **Peer key compromise.** If a peer key is compromised, occurrences signed by the now-compromised key remain syntactically valid. Mitigation: a per-peer revocation record under `data/peers/<peer-log-id>.revoked` with a revocation time; verify reports occurrences whose foreign `ingested_at` is after the revocation time as "post-revocation" with a distinct status. This is documentation-and-data-driven; no policy change implied.
- **Vocab divergence.** A peer running an older vocab might emit identities under predicates we don't recognise. Mitigation: the importer's vocab lookup is for OUR active vocab; foreign predicates we don't recognise fall through to "store identity as-is, occurrence goes into foreign chain, but no per-predicate-table row emitted." We don't reason about unknown predicates but we don't silently drop them either.
- **Two ingestors choose the same log_id.** Default log_id is `log:<keyfp>` so collisions are astronomically unlikely. Operators using `data/log-id.txt` to override can collide. Mitigation: the importer refuses to write into `foreign/<peer-log-id>/` if `<peer-log-id>` equals the local log_id; clear error message.
- **Federated_importer occurrences for observation-class predicates.** Phase 3.5 keeps foreign occurrences for observation-class predicates as-is (signed by the peer, in `foreign/<peer-log-id>/`). The local chain does not advance for these imports. This means the local chain only advances on local actions, including the rewrite-occurrence emissions described in §3 for verification-class imports. That is a feature: the local chain reflects "what this local node did," not "what passed through this local node." Audit trail is preserved across both chains.

---

## 12. Closing test

Phase 3.5 is correct if a hostile reader inspecting only on-disk artifacts can answer:

1. *Did this fact come from us or from a peer?* → join `identities → occurrences`; if the only occurrences have `attestor_role = federated_importer` or `log_id` is under `foreign/`, the fact came from a peer.
2. *Has any verified-form claim been imported as-verified?* → SQL: any row in `cryptographically_verified_signature_by` whose `identity_id` has NO occurrence with `attestor_role = verifier` (i.e., only `federated_importer` occurrences cite it) is a violation. Verify check #12 enforces zero such rows.
3. *Can a peer's faulty verifier corrupt our verdicts?* → No: the rewrite rule means `release_signing/v2` only sees `cryptographically_verified_signature_by` rows produced by our local verifier. Peer claims live under `peer_reports_*` predicates that this policy does not consume.
4. *If a peer's chain is broken, does it break our chain?* → No: chains are per-log-id; foreign chain integrity is a separate verify check.
5. *Did we observe the peer's claim faithfully?* → Foreign occurrence bytes are stored under `data/raw/foreign.occurrence/` and can be re-verified against the peer key registered at `data/peers/<peer-log-id>.pub`. The auditor can re-execute the signature check on the original bytes.

If any answer requires reading source beyond version metadata, the phase has drifted.

---

## Coda

Phase 3 made the split conceptual. Phase 3.5 makes it operational. The combined invariant — verification is a local-computation event that may never be inherited — survives its first real test in this phase. Every future phase that touches federation, mirroring, SaaS ingestion, or third-party attestation submission can be evaluated against the rules established here.

After 3.5:
- **Phase 4** — second ecosystem (PyPI), Identity entity layer, or independence semantics. Whichever the system surfaces a concrete need for first.
- **Phase 5+** — transparency-log anchoring of local chain; policy authoring against `peer_reports_*` predicates; conflict-resolution policies for federated environments.
