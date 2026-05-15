# Phase 2 Plan: Cryptographic Verification Pathway

> **Phase-2 thesis.** Day-1 produced a working provenance compiler where every assertion is some form of "ingestor reports X from source Y." Phase 2 closes the semantic gap by producing the system's first *verified-form* assertions — predicates that exist only when we have run cryptographic verification ourselves, not when a source claimed something. Until at least one such assertion exists end-to-end, the verification half of the invariants is a placeholder.

This document presumes `memory/layer-1.md` as the operating reference. Phase 2 is additive over Day 1: nothing in Day 1 changes incompatibly.

---

## 1. Why this, and not the alternatives

Three Phase-2 candidates were on the table:

| Candidate | Closes a semantic gap? | Strengthens an invariant? | Scope discipline |
|---|---|---|---|
| **Verified-vs-reported (proposed)** | Yes — `cryptographically_verified_signature_by` becomes producible | Yes — observation/inference boundary lands in code, not just naming | One new predicate, one connector, one verifier, one policy bump |
| Identity/Occurrence split + 2nd ingestor | No, but proves federation shape works before more data accumulates | Yes — structurally separates canonical fact from local event | Larger refactor; reduces cost of every later feature |
| More ecosystems (PyPI/Maven) | No — replicates a Day-1 shape sideways | No | Scope creep; defer |
| HTTP API | No | No | Defer until a second user exists |

The verified-form pathway wins because it is the smallest move that demonstrably changes what the system *is* — Day 1 cannot reach `trusted` for anything; after Phase 2 it can, for one bounded class of artifact. Federation is the second-strongest move and is named below as the next-after-this candidate.

---

## 2. Phase-2 scope (in / out)

**In scope:**
- One new predicate: `cryptographically_verified_signature_by`.
- Vocab v2 (additive over v1; v1 remains valid for all existing assertions).
- One new connector: Sigstore attestation fetcher for npm packages that publish provenance (`/-/npm/v1/attestations/<pkg>@<version>` or Rekor by Fulcio-cert subject).
- One new normalizer: `sigstore-attestation-verifier@v0.1.0` — performs DSSE + Fulcio cert-chain verification and emits the assertion *only* when verification passes.
- Schema addition: one new table `cryptographically_verified_signature_by` mirroring the existing IRI-object table shape.
- One new policy version: `release_signing/v2`, identical to v1 except the `trusted` branch becomes reachable.
- `verify` extended: re-run cryptographic verification for every verified-form assertion on replay; byte-equal-on-rebuild guarantees previously, now plus cryptographic-validity-on-rebuild.

**Out of scope (explicit non-goals):**
- New ecosystems. Still npm only.
- The Identity/Occurrence split. Recorded as Phase 3 candidate.
- Aggregated trust scores, ranking, similarity, ML — same forbidden list as Day 1.
- Failure-mode predicates (e.g. `attestation_failed_verification`). The fact that we *attempted* verification is captured by raw evidence; emitting failure as a typed assertion is deferred until a policy needs it.
- Identity clustering across `npm:user:*`, `gh:*`, and Fulcio OIDC subjects. Deferred.
- HTTP API, multi-user, distributed deployment, transparency log anchoring.
- Replacing the Day-1 `registry_reports_signing_key` predicate. It coexists with the verified form; the policy decides which to weight.

---

## 3. New predicate + vocab v2

```jsonc
// vocab/v2.json (excerpt — full file is v1.json + the new entry below)
{
  "version": "v2",
  "supersedes": "v1",
  "predicates": {
    /* … all v1 predicates carry forward unchanged … */
    "cryptographically_verified_signature_by": {
      "subject_kind": "artifact",
      "object_kind": "identity",
      "description": "A signature over the artifact's bytes was fetched and validated by this binary against a known public key whose provenance is in turn anchored to a trusted root (Fulcio for Sigstore). This is a VERIFICATION outcome, not a registry claim. Policies requiring strong evidence MUST require this predicate; the reported-form predicate `registry_reports_signing_key` is admissible only as weak corroboration."
    }
  }
}
```

Vocab loading discipline (a Day-1 risk this resolves): vocab files become the runtime source of truth. On startup, `origin` loads `vocab/<latest>.json` and rejects any assertion whose predicate is not declared. The vocab file is content-hashed; its hash is recorded in every projection MANIFEST.json and in every TrustClaim.

---

## 4. New connector: Sigstore attestation fetcher

Endpoint priority (try in order, record raw evidence for each attempt):

1. **npm attestations API:** `https://registry.npmjs.org/-/npm/v1/attestations/<pkg>@<version>`. Returns DSSE envelopes if the package was published with provenance. Newer npm publish flows produce these.
2. **Rekor by certificate subject:** if the GitHub repo for the package is known, query Rekor for entries where the Fulcio cert's OIDC subject matches that repo. This catches attestations that exist in Rekor but weren't surfaced via the npm API.

Both responses are stored verbatim under `data/raw/sigstore.attestations/...` and `data/raw/sigstore.rekor/...`. The existing Rekor-by-SHA-256 lookup is preserved unchanged — it remains an honest, mostly-empty corroboration channel — but is no longer the only Rekor pathway.

The connector is rate-limit-aware and treats "no attestation available" as a normal outcome (most npm packages do not yet publish provenance). Only network errors and malformed responses are surfaced as failures.

---

## 5. New normalizer: `sigstore-attestation-verifier@v0.1.0`

This is the heart of Phase 2. It is the first piece of code in the system whose output depends on the *outcome of a computation* rather than the *content of a fetch*.

Verification steps, each of which must succeed to emit an assertion:

1. **Envelope decode.** Parse the DSSE envelope (payload + per-signer entries). Reject unknown payload types — Day-1 supports `application/vnd.in-toto+json` with predicate type `https://slsa.dev/provenance/v1` only.
2. **Subject match.** The in-toto subject digest(s) must include the SHA-256 of the npm tarball (which we already fetched and content-addressed during Day-1 ingest). If no subject matches, abort.
3. **Signature verification.** Verify the DSSE signature against the public key embedded in the signer's certificate.
4. **Certificate chain verification.** Verify the embedded certificate chains to a pinned Fulcio root. Roots are pinned in code at `internal/sigstore/roots.go`; the file declares the root certificate bytes verbatim and the root-of-trust authority (we treat the Sigstore public-good instance as trusted Day-1; that's the same root every consumer of Sigstore uses today, and we document this as our explicit root-of-trust choice).
5. **Certificate validity window.** The cert must have been valid at the time the artifact was signed. The signing time comes from the cert's NotBefore/NotAfter and the Rekor-recorded inclusion time (if available).
6. **OIDC subject extraction.** Pull the OIDC subject and issuer from the cert's SAN extension. For GitHub Actions, this looks like `https://github.com/<owner>/<repo>/.github/workflows/<file>@refs/...` with issuer `https://token.actions.githubusercontent.com`.
7. **Subject-source coherence.** The OIDC subject must reference the same GitHub repository the package's `repository` field points at. This catches the case where a malicious package is published with a valid attestation that points at someone else's CI.

Only when steps 1-7 all pass does the normalizer emit:

```
<pkg-purl> cryptographically_verified_signature_by <oidc-identity-iri>
```

The `oidc-identity-iri` form is `sigstore:fulcio:<sha256 of cert subject + issuer>` so identities under this scheme have a deterministic IRI that doesn't depend on display-format choices.

Verification failures (envelope decodes but doesn't verify) are NOT emitted as assertions in Phase 2. The raw evidence record remains on disk. A future Phase-2.x predicate `attestation_present_but_did_not_verify` may be added if a policy actually needs to distinguish "we never looked" / "we looked, nothing was there" / "we looked, something was there but invalid." Deferred until that need is concrete.

Library choice: `github.com/sigstore/sigstore-go` (the official Go library). Adds substantial transitive deps but vendoring our own DSSE+Fulcio verifier is exactly the kind of homegrown-crypto trap we should avoid.

---

## 6. Projection schema changes

Additive. One new table:

```sql
CREATE TABLE IF NOT EXISTS cryptographically_verified_signature_by (
    assertion_id  TEXT PRIMARY KEY,
    subject       TEXT NOT NULL,
    object        TEXT NOT NULL,
    observed_at   TEXT NOT NULL,
    attestor      TEXT NOT NULL,
    evidence_id   TEXT NOT NULL,
    normalizer    TEXT NOT NULL,
    superseded_by TEXT
);
CREATE INDEX IF NOT EXISTS cryptographically_verified_signature_by_subject
    ON cryptographically_verified_signature_by(subject) WHERE superseded_by IS NULL;
```

The `schema_hash` changes when this table is added — old projections will fail `origin verify`'s projection-determinism check against new code. That's correct: a schema change is genuinely a different projection. The MANIFEST.json's `vocab_version: v2` field signals which schema applies.

Migration path for existing data: none required. Old assertions remain in the log; rebuilding the projection under v2 yields a superset of the v1 projection (every v1 row, plus possibly new verified-form rows from a re-ingest).

---

## 7. Policy update: `release_signing/v2`

Identical to v1 except:

- Manifest `required_predicates` adds `cryptographically_verified_signature_by`.
- `verified_signature_exists` rule (which existed but was permanently false in v1) becomes meaningful — it checks the new table.
- The `trusted` branch fires when both `verified_signature_exists` AND `rekor_returned_hits`. Single-witness verification (verified but no Rekor hit) downgrades to `conditional`.

`release_signing/v1` remains in place. Existing claims signed against v1 retain their `policy_hash`; they're still valid records of v1 evaluations. v2 is a new policy version, not an in-place edit. This is consistent with the supersession invariant: never mutate, always supersede.

`dependency_hygiene` is unchanged in Phase 2. Phase 3 candidates include extending it to consume verified-form predicates for transitive deps.

---

## 8. `verify` extensions

Day-1 `verify` performs five checks (chain, ids+sigs, evidence, projection determinism, claim envelope consistency). Phase 2 adds a sixth:

6. **Cryptographic re-verification.** For every assertion under predicate `cryptographically_verified_signature_by`, fetch the evidence record, re-run the full DSSE + Fulcio chain verification, and confirm it still passes today. Tampering with the raw evidence, attestation expiry, or Fulcio root rotation surface here.

A subtle question lives here: cryptographic verification depends on time. A signature valid today might fail tomorrow if the cert expires. Day-1 `verify` was purely byte-equality (time-independent). Phase 2 `verify` becomes partially time-dependent: re-verification at time T2 of an assertion produced at T1 can legitimately fail if intervening certificate state changed.

Treatment: re-verification failures are reported as `cryptographic_verification_drift`, distinct from `tamper_detected`. The latter is a hard fail; the former is a notice. Operators decide whether expired-cert drift should invalidate downstream claims (probably no — the verification was valid at the time it occurred and the claim records that time).

This also forces a small invariant refinement worth recording: **deterministic replay is byte-equal across time, but cryptographic validity may not be**. The system needs both checks and they have different failure semantics.

---

## 9. Success criteria (falsifiable)

Phase 2 is done when all of these hold for at least one real npm package that publishes Sigstore provenance:

1. `origin ingest <github-url>` produces a `cryptographically_verified_signature_by` assertion for the package, signed by the local ingestor.
2. `origin eval <subject> --policy release_signing` yields `verdict: trusted`.
3. `origin why <claim-id>` shows the verified-form assertion in the consumed-assertion list, traceable back to the raw DSSE envelope on disk.
4. `origin verify` reports `cryptographic re-verification: N assertions pass` and exits clean.
5. Tampering with the raw DSSE envelope bytes (changing one byte) causes `origin verify` to fail with a clear cryptographic-verification error, not a generic hash mismatch.
6. `origin ingest` on a package WITHOUT provenance produces zero verified-form assertions and the policy correctly downgrades to `conditional` rather than `insufficient_evidence` (because the reported-form is still present).
7. A package whose attestation is valid but whose OIDC subject points at a different GitHub repo (we construct this case for the test) does NOT produce a verified-form assertion. This proves step 7 of the verifier — subject/source coherence — is load-bearing.

Pick targets: `sigstore/cosign` (the canonical example), one of the `@octokit/*` packages (npm-side examples with provenance), and a counter-example we build ourselves where attestation exists but doesn't match.

---

## 10. Sequence of work

Each step ends compiling and passing `go test ./...` and `origin verify`.

1. **Vocab v2 + loader.** Add `vocab/v2.json`. Add `internal/vocab/` package. Wire it into the ingest path so new assertions are validated against the loaded vocab. Day-1 risk #5 (vocab file not authoritative) closes here.
2. **Fulcio root pinning.** New file `internal/sigstore/roots.go` with the Sigstore public-good Fulcio root certificate(s) and a documented root-of-trust choice. No external fetches.
3. **DSSE/Fulcio verifier module.** `internal/sigstore/verify.go` wrapping `sigstore-go`. Pure function: `(envelope_bytes, expected_subject_sha256, expected_oidc_subject_prefix) → (ok bool, oidc_identity_iri string, reason string)`. No I/O, no logging into assertions.
4. **Attestation connector.** Hits npm attestations API + Rekor-by-cert-subject; stores raw evidence; passes envelope bytes to the verifier.
5. **Normalizer wiring.** The connector calls the verifier; on success it constructs the envelope and the ingest pipeline appends it like any other assertion. On failure, no assertion (raw evidence remains).
6. **Schema bump + projector dispatch.** Add the new table; add the predicate to the projector's `case` and the snapshot builder's `case`.
7. **Policy v2.** Copy `policies/release_signing/v1` → `v2`; flip the `verified_signature_exists` gate from "always false" to "the new predicate's table has a current row for this subject." Manifest required_predicates updated. Add a Day-2 selector in CLI: `--policy-version` argument optional, defaulting to highest.
8. **Verify check #6.** Iterate verified-form assertions; re-fetch the DSSE envelope from raw evidence; re-run the verifier. Report drift vs tamper distinctly.
9. **End-to-end test.** Ingest the three target packages; produce expected verdicts; tamper-test fails verify.

Estimated size: ~600-900 LOC of Go plus ~50 lines of policy/manifest. Sigstore-go pulls a large transitive dep tree; that's the right call but it doubles build time.

---

## 11. Day-1 risks this phase closes (or doesn't)

From the discovered-risks list in the Day-1 final report:

- **Risk #2 (predicate names smuggle inference) — partially closed.** The verified-form predicate is the canonical example of "name matches verification level"; future predicates inherit the pattern.
- **Risk #3 (Rekor lookup structurally empty) — addressed.** The new lookup-by-cert-subject path is the right Rekor channel for npm-with-provenance. The SHA-256 path remains for orthogonal corroboration.
- **Risk #5 (vocab file not runtime source of truth) — closed.** Vocab loader is a step-1 prerequisite.
- **Risk #6 (policy required_predicates advisory) — partially closed.** Snapshot builder will refuse to compile a snapshot for a policy that references undeclared predicates. The Day-1 escape hatch (referencing the verified-form predicate before it existed) goes away once it exists.
- **Risk #7 (`evaluated_at` breaks claim replay determinism) — not closed.** Independent fix. Recommend addressing in a small bug-fix PR alongside Phase-2 work: derive `evaluated_at` deterministically from `max(ingested_at among consumed assertions)`.
- **Risk #15 (no third-party attestation submit path) — not addressed.** Still single-ingestor. Deferred to Phase 3 (federation).

---

## 12. Deferred to Phase 3+

In priority order:

1. **AssertionIdentity / AssertionOccurrence split + second ingestor.** Federation, mirroring, replay. Required before multi-operator deployment. The longer this waits, the more data accumulates in the merged-struct form.
2. **Second ecosystem (PyPI).** Replicates the Day-1 + Phase-2 patterns once they're stable. PyPI has its own attestation story (recent Sigstore integration); the verifier abstraction from Phase 2 should accommodate it without a redesign.
3. **Maintainer / activity policies.** Once vocab v3 introduces `last_commit_at` and `commit_count` predicates from GitHub data, a `maintainer_activity` policy becomes meaningful.
4. **Public read-only API.** Only after a second concrete user needs it. Never a write endpoint into the assertion log; third-party attestation submission has its own design (root-of-trust attestor set, etc.).
5. **Transparency log anchoring.** After Phase 2 cleanly emits verified-form assertions, anchor the chain externally (Rekor or our own log) so the integrity claim becomes externally checkable.

---

## 13. The road not taken (this phase)

If priorities shift, the strongest alternative is the **AssertionIdentity / AssertionOccurrence split** described in `memory/layer-1.md` §"Corrections applied during Day-1 implementation" #4. That move:

- Separates the canonical fact (`identity_id = sha256(envelope)`) from the local observation event (ingestor, ingested_at, chain hashes, local signature).
- Enables federation, mirroring, third-party co-attestation by construction.
- Is roughly the same engineering effort as Phase-2-verification.
- Does NOT close a semantic gap in the trust ladder, but DOES reduce the cost of every later Phase.

The recommendation here is verification depth first because closing the verified-vs-reported gap demonstrably changes what verdicts the system can produce, while the identity/occurrence split is structurally important but invisible to a Day-1 user. Different priorities pick the other order; both are defensible.

---

## Closing test

Phase 2 is correct if and only if the following all hold for an unbiased reader inspecting on-disk artifacts:

- A package with valid Sigstore provenance produces a `trusted` verdict for `release_signing/v2`, and every step from raw DSSE envelope → verifier output → assertion → claim is traceable.
- A package without provenance produces `conditional` (because reported-form signing key is present but verified form is not).
- A package with a forged/mismatched attestation does NOT produce a verified-form assertion; the raw evidence captures that we looked and didn't accept what we found.
- `origin verify` re-runs cryptographic verification end-to-end and distinguishes time-induced drift from genuine tamper.
- The system never emits a verified-form assertion based on what a registry said. Verification is something this binary did, or the assertion does not exist.

If any of these tests fails, the phase is not done.
