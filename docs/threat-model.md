# Threat Model

This document enumerates the threats Origin's protocol and reference implementation aim to defend against, the threats they explicitly do NOT defend against, and the operator assumptions baked into both.

It is written for readers who want to attack the system. If you are reviewing Origin adversarially, the entries below are the most fruitful starting points.

## Operator assumptions

Origin assumes:

- The operator controls the host running `origin`. If the host is compromised, no Origin invariant can save the operator.
- The operator does not commit private keys to public repositories. The `.gitignore` includes `data/`; the file `data/keys/ingestor.ed25519` exists per host and never leaves it.
- The operator runs `origin verify` before trusting any third-party tarball or peer import.
- Vendored cryptographic libraries (`sigstore-go`, stdlib `crypto/ed25519`) are correct. Verifier-library bugs are upstream concerns.

If any of these assumptions does not hold, the threat model below also does not hold.

## Threat: semantic laundering

**Pattern.** A claim is made in one verification class and reinterpreted in another. The classic case: a registry reports a signing key, and a consumer treats this as cryptographic verification of the signature against the artefact bytes.

**Defence.**

- Predicate naming distinguishes observation (`<source>_reports_X`) from verification (`cryptographically_verified_X`).
- Vocabulary declares `verification_class` per predicate.
- Policies that require strong evidence must require verification-class predicates explicitly.
- The current `release_signing/v2` policy gates `trusted` on a verification-class predicate; observation-class evidence yields at best `conditional`.

**Residual.** A policy author could write a policy that consumes observation-class evidence as if it were verified. The protocol cannot prevent badly-written policies, but the policy hash is recorded in every claim, so the author and version are auditable.

## Threat: trust inheritance via federation

**Pattern.** Node A "imports" Node B's archive, including B's verification-class claims. A naively treats B's verifications as A's verifications.

**Defence.**

- The federation rewrite rule (invariant 6) requires every foreign verification-class identity to be rewritten as an observation-class `peer_reports_*` predicate. The foreign verification-class identity is NOT placed in A's local identity store.
- The no-laundering check (verify #12) walks every `federated_importer`-role occurrence and asserts the cited identity's predicate is observation- or structural-class. Any violation is a hard fail.

**Residual.** A custom importer that bypasses `internal/peerimport/` and writes directly to the identity store could violate the rule. Verify #12 catches this at the next verify run. A future Phase 5.6-style check could detect anchor equivocation as well.

## Threat: forged or malformed attestations

**Pattern.** An attacker produces a Sigstore-shaped bundle whose internal claims do not actually verify. They submit it via npm provenance or publish it through a controlled channel.

**Defence.**

- `internal/sigstore/verify.go` runs end-to-end verification: DSSE signature against the embedded leaf certificate, certificate chain against the pinned Fulcio root, OIDC subject matched against the package's repository URL.
- Failures are classified into seven reason codes (`bundle_parse_failed`, `signature_invalid`, `certificate_chain_invalid`, `transparency_log_proof_invalid`, `subject_digest_mismatch`, `oidc_subject_coherence_failed`, `input_invalid`).
- The verifier hermetic test suite (`internal/sigstore/verify_test.go`) covers each rejection path against a known-good fixture bundle.

**Residual.** A bug in `sigstore-go` could cause a forged bundle to pass. We track upstream advisories. The mitigation is "update the dependency".

## Threat: compromised peer

**Pattern.** A federation peer's signing key is compromised. The attacker publishes false identities + occurrences signed by the peer's key.

**Defence.**

- All foreign occurrences are verified against the peer's registered public key at import time (verify check #11).
- Foreign occurrences cannot become local verifications (invariant 6).
- The foreign archive is stored under `foreign/<peer-log-id>/` so the source is permanently identifiable.

**Residual.** A compromised peer can produce arbitrary observation-class claims that we will record. Whether a policy weights those claims is the policy author's call. The peer-key registry supports per-peer revocation records (`<peer-log-id>.revoked`); the v0 implementation does not yet automate revocation processing — that is a v1 candidate.

## Threat: retroactive chain rewriting

**Pattern.** An attacker with write access to the local archive modifies past entries in the chain, hoping no one notices.

**Defence.**

- The local chain is a hash chain (verify check #3): any modification at position N invalidates every subsequent chain_hash.
- Identity IDs are content-addressed (verify check #1): modifying an Identity changes its ID, which no longer matches what occurrences reference.
- The projection is rebuilt from scratch and byte-equality-checked (verify check #6).
- If a checkpoint has been anchored externally before the rewrite, verify check #13 detects the mismatch between the anchored chain head and the current state.

**Residual.** An attacker with write access who modifies the archive BEFORE any external anchoring leaves the chain internally consistent but rewritten. External anchoring (Phase 5) is the defence; without it, "an attacker with full archive write access" wins this particular fight. This is the explicit reason anchoring exists.

## Threat: chain truncation post-anchor

**Pattern.** The attacker removes recent chain entries after an anchor was published externally.

**Defence.**

- Verify check #13 reports `TRUNCATED` when an anchor's recorded `(log_id, seq)` no longer exists in the chain.
- The external transparency system continues to hold the original anchor; an auditor with access to that system can detect the rewrite even if the local archive shows only the new state.

**Residual.** Same as above: an attacker who rewrites BEFORE the next anchor wins. Increasing anchor frequency shrinks the window.

## Threat: registry compromise (upstream observation source)

**Pattern.** npm, OSV, GitHub, or another upstream source returns false data — wrong publisher, wrong vulnerability mapping, wrong timestamp.

**Defence.** None at the protocol level. Origin records what the source returned, faithfully. The source's veracity is outside Origin's competence.

**Residual.** Always. Mitigations are:

- Use observation-class predicates that name the source explicitly (`registry_reports_signing_key`, not `signed_by`).
- Independent corroboration across sources is a policy concern. A future "multi-source corroboration" policy could require at least N independent attestors before treating an observation as strong.
- Independence semantics are formally an open question in [`epistemic-model.v1.md`](epistemic-model.v1.md) §11; "two sources both routed through the same upstream are not independent" is the principle, but the protocol does not yet formalise it.

## Threat: dishonest transparency provider

**Pattern.** A transparency log provider (Rekor, equivalent) returns false timestamps, selectively serves different inclusion proofs to different queriers, or refuses to anchor certain checkpoints.

**Defence.**

- The anchor predicate is observation-class. Origin records what the provider returned; it does not claim the response was truthful.
- Policy authors who treat anchors as authority do so at their own risk; the predicate description in vocab v6 explicitly warns against this.
- Multiple anchors from multiple providers reduce single-point-of-failure but do not produce consensus.

**Residual.** If a policy weights anchor presence heavily, a dishonest provider can mislead that policy. The protocol cannot fix policy choices; it can only label evidence honestly.

## Threat: timestamp forgery

**Pattern.** A provider claims an inclusion time earlier than actual submission.

**Defence.** Origin does not assert timestamp accuracy. The provider's claimed timestamp is recorded; whether it is truthful is a property of the provider.

**Residual.** Operators needing stronger timestamp guarantees should use providers that publish signed tree heads (witnessed Rekor, TSA-anchored Sigstore). Phase 5.5 could add inclusion-proof verification including witness-signature verification; v0 does not.

## Threat: imported fake checkpoints

**Pattern.** A peer reports an anchor for a fake checkpoint citing chain heads the peer never had.

**Defence.**

- Verify check #11 confirms the peer signed the occurrence.
- Verify check #13 reports `MISSING_LOG` when an anchor references a log_id with no chain present locally.
- The fake checkpoint's content hash references bytes that may not exist; raw evidence resolvability (check #5) fails.

**Residual.** A peer can claim arbitrary checkpoints; their claims are recorded as observations. Policies that consume peer-reported anchors authoritatively are vulnerable.

## Threat: replay drift

**Pattern.** A previously-verified identity no longer verifies because a certificate has expired, a trust root has rotated, or the verifier library has been updated.

**Defence.**

- Verify check #8 re-executes cryptographic verification on every run; failures are distinguished from tamper.
- Trust roots are pinned in source; rotation requires a deliberate source change.

**Residual.** Time-bound cryptographic state will drift. The operator must decide whether time-induced drift (cert expiry) invalidates a previously-recorded fact for their use case. v0 reports the drift; policy decides.

## Threat: canonicalisation drift

**Pattern.** Two implementations canonicalise the same envelope differently, producing different IDs for the same fact. Federation between them breaks.

**Defence.**

- `protocol/v0-fixtures/` contains canonical-bytes reference files for every artefact shape.
- The fixture self-test asserts byte-equality on every CI run.
- The protocol spec [`origin-protocol-v0.md`](../protocol/origin-protocol-v0.md) §2.1 states the canonicalisation rule (RFC 8785 JCS, no floats).

**Residual.** A spec ambiguity (which JCS sub-case applies to a particular Unicode character, etc.) could produce drift. Such cases are findings; fix-forward path is documented in [`CONTRIBUTING.md`](../CONTRIBUTING.md).

## Threat: fixture drift

**Pattern.** Fixtures committed to the repo no longer match what the implementation produces, because someone forgot to run `gen.go` after a refactor.

**Defence.**

- The fixture self-test (`fixtures_test.go`) fails immediately when this happens.
- CI runs `go test ./...` on every PR.

**Residual.** None — this is a regression the test suite catches.

## Threat: operator carelessness

**Pattern.** Operator commits `data/` to a public repo; shares a tarball that includes their signing key; runs `origin` in a hostile environment.

**Defence.**

- `.gitignore` includes `data/`, `*.tar.gz`, build artefacts.
- Demo tarballs include a per-demo signing key, never a production key. (Future Phase-5.5 read-only Ring mode would let demo bundles ship without a private key at all.)
- Test signing key in fixtures is documented as TEST-ONLY in multiple places.

**Residual.** The operator can always do the wrong thing. The project provides defaults that make accidents harder, not impossible.

## Threats Origin explicitly does NOT defend against

This list exists so reviewers can stop testing these and focus on the meaningful surface:

- **Cryptographic primitive break.** SHA-256 collision, Ed25519 forgery: out of scope. We rely on stdlib + sigstore-go for primitives.
- **Compiler / runtime compromise.** A malicious Go toolchain can produce arbitrary output. Reproducible builds are a future concern; v0 does not address them.
- **Side-channel attacks.** Timing, power, EM. None addressed.
- **Denial of service.** The CLI can be made slow by large inputs; this is not a protocol-level concern.
- **Privacy of operator behaviour.** Origin records what an operator ingested. If the operator's activity itself is sensitive, the operator must handle that separately.

## Where to attack productively

If you want to find something material, the highest-value targets in declining order:

1. **The no-laundering rule.** Any path that lets a verification-class predicate cross the federation boundary intact is critical.
2. **Verify #1, #6, #9.** Any inconsistency that passes byte-equality despite logical drift.
3. **Anchor integrity #13.** Edge cases the categories (TAMPER / TRUNCATED / MISSING_LOG) do not cover.
4. **Canonicalisation against the v0-fixtures.** Anything that makes the fixture self-test diverge from the spec.
5. **Refutation predicate emission.** A failure path that does not emit `cryptographic_verification_failed` when it should.
6. **Policy purity.** Any code path through OPA that makes a policy non-deterministic.
