# Phase 2.5 Plan: Hardening

> **Phase 2.5 thesis.** Phase 2 added capability (the verified-form path). Phase 2.5 hardens what just shipped. No new ecosystems, no new policies, no new connectors, no federation. Three specific structural defects must close before any further capability lands, because each one threatens an invariant the system depends on.

The defects this phase resolves:

1. **`evaluated_at` corrupts claim identity.** TrustClaim IDs depend on wall-clock time, so identical evaluations on identical inputs produce different IDs. This silently violates determinism, replayability, claim identity, and derivation stability. It is not a minor bug — it is invariant erosion at the claim layer, in exactly the same shape the Day-1 `ingested_at` refactor closed at the assertion layer. Closing it now, before more claims accumulate, is mandatory.
2. **Verification failure is silently indistinguishable from absence.** Now that locally verified assertions exist (Phase 2), "no verified-form assertion for this subject" can mean any of: never checked, checked-nothing-present, checked-malformed, checked-cryptographically-invalid, checked-semantically-incoherent. These are operationally different states (the last in particular is potentially a forged-attestation signal). Collapsing them into "no assertion" forfeits the audit value of the verification we did run.
3. **Verifier edges are under-tested.** The Phase-2 verifier was validated on one happy-path package end-to-end. Counter-examples — wrong digest, wrong repo, malformed bundle, wrong issuer — are claimed to be rejected but not proven. A regression in the verifier would silently let the wrong thing through and only `verify` on a tampered bundle would catch it, much later.

This document is bounded. Scope expansions detected during implementation will be deferred to Phase 3.

---

## 1. Determinism fix: claim envelope refactor

**The problem in code.** `internal/eval/run.go` builds a TrustClaim with `EvaluatedAt: time.Now().UTC().Format(time.RFC3339)`. `internal/eval/sign.go` then marshals the entire struct, removes `id` and `signature`, canonicalizes, hashes, and that hash is the claim ID. Because `EvaluatedAt` is in the canonical bytes, two evaluations against byte-identical inputs produce different IDs.

**The fix.** Treat `evaluated_at` exactly the way Day-1 treats `ingested_at` for assertions: record-level metadata, NOT part of the canonical envelope. The canonical envelope hashes the *evaluation*; the wall-clock time of *when* the evaluation was run is local-event metadata.

**Canonical claim envelope (post-fix) hashes over:**
- `subject`, `policy_id`, `policy_version`, `policy_hash`, `query`
- `verdict`, `qualifiers` (sorted)
- `vocab_version`, `normalizer_versions` (key-ordered by JCS)
- `assertion_ids_consumed` (sorted), `raw_evidence_ids_consumed` (sorted)
- `derivation.rules_fired` (sorted), `derivation.missing_predicates` (sorted), `derivation.input_counts` (key-ordered)
- `projection_manifest_hash`
- `evaluator_version`

**Out of the envelope (record-level fields):**
- `evaluated_at` — local timestamp of when this evaluation was run
- `id`, `signature` — derived from the envelope

**Implications**

- Re-evaluating an unchanged subject under an unchanged policy against an unchanged projection produces a byte-identical claim ID. The eval command becomes idempotent on identity (the second eval can detect "this exact claim already exists" and short-circuit).
- The `claims/<id>.json` file remains canonical; multiple `evaluated_at` values for the same claim ID just mean "we re-evaluated; the answer didn't change." Storage policy: keep the first observation by default; superseded ones use the existing `revises` mechanism if we ever need a re-evaluation chain.
- `verify` gains a stronger check: re-evaluate every claim against the current projection and confirm the recomputed claim ID matches the file. This is the **re-evaluation determinism** check that the current `claim envelope consistency` check cannot perform (because evaluated_at differs).

**Sequence-of-bytes for the new canonical form.** Sorting must be deterministic. We will sort string-array fields in place at marshaling time using stdlib `sort.Strings`. The `derivation.input_counts` map is canonicalized by JCS as part of the envelope canonicalization.

---

## 2. Verification failure semantics

**The minimum structure needed**, no more:

- One new predicate: `cryptographic_verification_failed`. Subject = artifact PURL; object = an IRI for the claimed identity (the OIDC subject extracted from the attestation cert, even when the cert chain or signature did not validate). When the bundle can't be parsed enough to produce a claimed identity, the object falls back to a synthetic `sigstore:unparseable_bundle:<sha256-of-bundle-bytes>` IRI so the assertion can still be emitted and the bundle still be cited.
- One new raw evidence source: `sigstore.verification_failure`. Payload is a JSON object with `{reason, cert_fingerprint?, oidc_subject?, oidc_issuer?, bundle_evidence_id}`. The `bundle_evidence_id` points back to the raw bundle that failed; the verification-failure record is its own evidence object so the assertion's `evidence_id` cites it, not the bundle directly.
- One enumerated reason vocabulary (NOT a separate predicate per reason — that would be ontology explosion):
  - `bundle_parse_failed`
  - `signature_invalid`
  - `certificate_chain_invalid`
  - `transparency_log_proof_invalid`
  - `subject_digest_mismatch`
  - `oidc_subject_coherence_failed`
  - `unknown` (for verifier-internal errors that don't map cleanly)

**State distinguishability after Phase 2.5:**

| Operational state | Detection |
|---|---|
| Never checked | No `npm.attestations` row in `raw_evidence` |
| Checked, nothing present | `npm.attestations` row with `result_count = 0` |
| Checked, malformed bundle | `cryptographic_verification_failed` assertion; sidecar reason = `bundle_parse_failed` |
| Checked, cryptographically invalid | `cryptographic_verification_failed`; reason ∈ {signature_invalid, certificate_chain_invalid, transparency_log_proof_invalid, subject_digest_mismatch} |
| Checked, semantically incoherent | `cryptographic_verification_failed`; reason = `oidc_subject_coherence_failed` (this is the potentially-malicious case) |
| Checked, verified | `cryptographically_verified_signature_by` assertion |

Six operational states, all distinguishable from existing on-disk structure. Policy authors can join the `cryptographic_verification_failed` table to the raw evidence reason payload when they want fine-grained distinctions; policies that don't care about the breakdown can just check "is there a failed assertion?"

**Naming discipline (invariant from `feedback-predicate-semantics`).** `cryptographic_verification_failed` is honest: we DID run cryptographic verification, and the OUTCOME was failure. The verb describes the action we performed, not an inference about the artifact's properties. This passes the predicate-semantics test.

**Where the failure assertion gets emitted.** Today the verifier returns `Result{Verified: false, Reason: "..."}` and the connector logs the message but emits no assertion. After this phase, the connector:
1. Always stores the raw bundle as `sigstore.bundle` evidence (already done).
2. On failure, builds a structured failure record with the reason mapped to one of the enum values, stores it as a `sigstore.verification_failure` raw evidence record.
3. Extracts a best-effort claimed identity from the cert (fallback to synthetic if unparseable).
4. Emits the `cryptographic_verification_failed` assertion whose `evidence_id` points at the verification-failure record.

The bundle remains on disk regardless; the failure record adds *typed* metadata about WHY we refused.

---

## 3. Verifier edge tests

A `internal/sigstore/verify_test.go` suite with at least these cases, each as a deterministic table-driven test using a vendored test fixture bundle in `internal/sigstore/testdata/`:

1. **Happy path** — valid bundle, correct sha512, correct expected repo → `Verified=true` with populated OIDC subject and issuer.
2. **Wrong digest** — valid bundle, deliberately wrong sha512 → `Verified=false`, reason matches `subject_digest_mismatch` (after Phase 2.5's reason classification).
3. **Wrong repo** — valid bundle, repo URL that doesn't match the OIDC subject → `Verified=false`, reason matches `oidc_subject_coherence_failed`.
4. **Malformed bundle** — random bytes / truncated JSON → `Verified=false`, reason matches `bundle_parse_failed`. No panic.
5. **Bundle with no DSSE envelope** — valid Sigstore bundle structure but missing the envelope → `Verified=false`, classifies as `bundle_parse_failed`.
6. **Issuer mismatch** — if we can construct a fixture from a non-GitHub-Actions OIDC issuer, the OIDC issuer check rejects it. (May be deferred if a real fixture is hard to obtain.)

The test fixture: copy the `@sigstore/sign@2.3.2` bundle bytes from a Phase-2 ingest into `internal/sigstore/testdata/bundle_sigstore_sign_2_3_2.json` and a known-good digest into a const. Tests run hermetically (no network). The fixture's pinned trusted root is the same `trusted_root_public_good.json` already in source.

**The reason-classification layer is itself testable.** The mapping from `sigstore-go`'s returned error to our enum lives in one place (a new file `internal/sigstore/reason.go`). Each test asserts both the boolean verdict and the classified reason. If `sigstore-go` rewords an error in a future release, the mapping fails predictably and we know to patch it.

---

## 4. Vocab v3 (additive)

`vocab/v3.json` is `v2.json` plus exactly one new predicate:

```jsonc
"cryptographic_verification_failed": {
  "subject_kind": "artifact",
  "object_kind": "identity",
  "description": "This binary executed cryptographic verification of an attestation for the artifact and the verification did not succeed. The attestation's claimed identity is the object. The structured reason is recorded in the assertion's evidence sidecar (a sigstore.verification_failure raw record). OBSERVATIONAL of our own verification attempt — does NOT imply anything about the artifact except that an attestation present at the time of attempt did not pass our verifier."
}
```

Vocab v3 supersedes v2; v2 remains loadable for replaying historical assertions. Ingest emits under v3 going forward.

No other ontology changes. No new entity types. No new top-level concepts.

---

## 5. Sequence of work

Each step ends compiling, `go test ./...` passing, and `origin verify` passing on the existing data directory (with any necessary one-time re-projection).

1. **Reason mapper.** New file `internal/sigstore/reason.go` defines the reason enum and a function `ClassifyReason(error) string`. Initial mapping is heuristic over sigstore-go's error strings; refined as the test suite exposes edge cases.
2. **Verifier returns structured reason.** Extend `sigstore.Result` with a `ReasonCode` field. Existing `Reason` (free text) stays for human display.
3. **Verifier tests.** Vendor the fixture bundle, write the six test cases. Land the test file before the ingest changes so regressions are caught immediately.
4. **Vocab v3.** Add the predicate, bump active vocab.
5. **Projection schema bump.** Add `cryptographic_verification_failed` table; add to projector dispatch; add to snapshot builder. Schema hash will change (expected — projection rebuild required).
6. **Ingest connector wiring.** On Verified=false, write a `sigstore.verification_failure` raw record + emit the new assertion. Existing `sigstore.bundle` raw record continues to be written.
7. **Claim envelope refactor.** Move `evaluated_at` out of canonical bytes; update `canonicalClaimBytes` to omit it; persist it as a record-level field. Update tests.
8. **Verify check #7: claim re-derivation determinism.** New check: for every persisted claim, re-evaluate against the current projection, recompute its claim ID, confirm it matches the filename and the `id` field. Failures here mean: someone tampered with a claim, or the projection drifted, or the policy hash changed (which is itself a finding).
9. **End-to-end test.** Force a verification failure (point ingest at a package where we know cross-source coherence will fail OR use a constructed test). Confirm the failed-form assertion exists, `release_signing/v2` still emits a verdict (currently `conditional`, because v2 doesn't yet know about the failed-form predicate — and that's correct; Phase 2.5 does not update policies).

---

## 6. Falsifiable success criteria

Phase 2.5 is done when ALL hold:

1. Two `origin eval` runs against an unchanged log + projection + policy produce byte-identical claim files (same ID, same canonical bytes). Only `evaluated_at` differs *outside* the canonical envelope.
2. `origin verify` gains a sixth check (claim re-derivation determinism) and it passes on the existing on-disk state.
3. A package with a deliberately-mismatched expected repo (we construct this case in test) produces NO `cryptographically_verified_signature_by` assertion, DOES produce a `cryptographic_verification_failed` assertion, and the failure record's reason is `oidc_subject_coherence_failed`.
4. A malformed bundle (truncated JSON) classifies as `bundle_parse_failed` and the verifier does not panic.
5. The six operational verification states are all individually distinguishable from on-disk artifacts alone, without running the binary.
6. `internal/sigstore/verify_test.go` runs hermetically (no network), under one second, covering at least the five primary edges. Code coverage for `internal/sigstore/verify.go` reaches ≥ 80%.
7. `release_signing/v2` is unchanged. No policies are modified in Phase 2.5.

---

## 7. Explicit non-goals (Phase 2.5)

- No new ecosystems. Still npm only.
- No new connectors beyond the verification-failure sidecar record.
- No new policies or policy versions. `release_signing/v2` and `dependency_hygiene/v1` are frozen for this phase.
- No federation, no AssertionIdentity/Occurrence split — Phase 3 candidate.
- No HTTP API, no UI changes (the static HTML report continues to work).
- No expansion of the reason vocabulary beyond the seven values listed in §2. Operators wanting finer distinctions can read the raw failure record directly.
- No replacement of the `sigstore-go` library. If a verifier-internal error doesn't map cleanly to a reason, `unknown` is the legitimate fallback; we don't fork the library to surface better error types.
- No retroactive re-evaluation of historical claims. Existing claims with `evaluated_at` in their canonical bytes are migrated on first re-evaluation, not by bulk rewrite (which would be mutation, forbidden). Until they're re-evaluated their claim IDs remain frozen at the old shape; the new `verify` check tolerates legacy-shape claims via a documented compatibility flag that defaults off and will be removed once the data set is exhausted.

---

## 8. What this phase does NOT close

Two Day-1 risks still survive Phase 2.5:

- **Identity layer unmodeled in projection** (Day-1 risk #10). Identity is still a string column, not an entity table. Phase-3 candidate.
- **OPA full-recompute model** (Day-1 risk #14). Day-1 scale makes this invisible; Phase-3+ work item.

Two structural questions remain deferred:

- **AssertionIdentity vs AssertionOccurrence.** Phase 3 candidate per `memory/layer-2.md` §13.
- **Transparency-log anchoring of the local chain.** Deferred until Phase 2.5's hardening is in place and verified-form assertion volume justifies the operational cost of external anchoring.

---

## Closing test

Phase 2.5 is correct if a hostile reader inspecting only the on-disk artifacts can answer the following:

1. *Did we evaluate this claim deterministically?* → Two re-evaluations produce identical IDs; `verify` proves it.
2. *Was an attestation checked for this package?* → If no `npm.attestations` raw record exists, no. Otherwise yes.
3. *If an attestation was checked, did it verify?* → `cryptographically_verified_signature_by` assertion exists → yes. `cryptographic_verification_failed` assertion exists → no. Both absent → checked but no attestation present (`result_count = 0`).
4. *Why did verification fail?* → The failed assertion's evidence_id resolves to a `sigstore.verification_failure` raw record whose payload contains the reason code from the enum.
5. *Will the verifier reject these failure cases tomorrow?* → The vendored test fixture suite is hermetic and runs in CI; a regression in classification fails loudly.

If any answer requires reading code beyond version metadata, the phase has drifted.
