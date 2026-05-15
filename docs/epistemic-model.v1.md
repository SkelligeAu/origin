# Origin Epistemic Model v1

> A formal statement of what origin claims to know, how it claims to know it, and what it refuses to claim. This document precedes ecosystem expansion. It is the standard future work is measured against.

This document is normative. It is not a description of the implementation — it is the model the implementation must serve. Where implementation lags the model, the implementation is wrong. Where the model lags implementation, the model is wrong; clarifying revisions are issued explicitly, with version bumps, never silent edits.

## 0. Preamble

Origin is, structurally, a provenance compiler and an evidentiary database. Its outputs are evaluations of evidence under explicit policy. It is not a recommendation engine, a knowledge graph product, a trust score, or a registry. It does not encode opinion. It does not perform inference that cannot be traced to specific inputs through versioned code.

This document defines the *epistemic* shape of the system: the kinds of things it can know, the procedures by which it comes to know them, the conditions under which knowledge persists or expires, and the boundary between what is in the system's epistemic competence and what is not.

The numbered invariants referenced below live in `memory/layer-1.md`.

---

## 1. Assertion classes

Origin records four classes of assertion. The class of an assertion is a function of *which kind of activity produced it*, not of its surface predicate name.

### 1.1 Observed assertions
A statement that some external source made a claim. The assertion's existence proves the source's claim was recorded; it does not prove the claim is true. The signer is origin's ingestor (witnessing that we fetched these bytes and parsed them this way); the speaker is the external source.

Examples (Day-1 vocab): `published_at`, `published_by`, `depends_on`, `affected_by`, `registry_reports_signing_key`.

### 1.2 Verified assertions
A statement that origin executed a procedure against bytes and the procedure succeeded. The signer is origin's ingestor; the *producer* of the verifiable fact is origin's verification code, anchored to a root of trust chosen by origin. The procedure must be deterministic enough to re-execute on replay.

Examples (Phase-2 vocab): `cryptographically_verified_signature_by`.

### 1.3 Refuted assertions
A statement that origin executed a verification procedure against bytes and the procedure did not succeed. Refuted assertions are observations of our own verifier's behaviour. They carry structured reason codes; they do not carry the failed claim as if it were true.

Examples (Phase-2.5 vocab): `cryptographic_verification_failed`.

Refutation is a positive epistemic state — it is operationally distinct from silence. The system knows it tried and did not succeed; future questions about the subject must account for that fact.

### 1.4 Structural assertions
A statement about the log itself: supersession, derivation chains, and other meta-relations. Structural assertions do not assert facts about the world; they reorganise other assertions.

Examples: `revises`, `derived_from`.

### 1.5 Disjointness
The classes are disjoint by predicate. No predicate may emit assertions in more than one class. Renaming or repurposing a predicate across classes is forbidden; new classes are introduced by new predicates with rationale and ontology versioning.

---

## 2. Observation vs verification

This is the load-bearing distinction of the entire model.

### 2.1 Definitions
An **observation** records what was said. An external source produced bytes; origin fetched them, parsed them via a versioned normalizer, and recorded the parse result as an assertion. The assertion's truth value depends on the source's veracity, which origin does not vouch for.

A **verification** records what was computed. Origin's code, in some specific run, took bytes, applied a procedure anchored to a pinned root of trust, and produced a result. The assertion's truth value depends on the correctness of origin's verification code (auditable in the source tree) and on the inputs (re-fetchable from the log).

### 2.2 Producers
Observations are produced by **normalizers**: pure functions from raw bytes to typed assertions. Normalizers do not verify; they transcribe.

Verifications are produced by **verifiers**: pure functions from raw bytes plus a pinned trust root to typed assertions. Verifiers are the only place verified-form assertions originate.

### 2.3 Naming
Predicate names must reflect the producing activity. The pattern `<source>_reports_X` denotes observation; the pattern `<procedure>_verified_X` (or variants like `cryptographically_verified_X`) denotes verification. Names that imply verifiable artifact properties may not be applied to assertions produced by normalizers. See `feedback-predicate-semantics` in auto-memory.

### 2.4 Trust shape
Trusting an observation is trusting the source.
Trusting a verification is trusting the verifier (origin's code) and the pinned root of trust (origin's choice of which authority to anchor against).

These are different kinds of trust. The first is data trust; the second is code trust. They cannot substitute for each other and must not be conflated in policy reasoning.

### 2.5 No promotion
An observation does not become a verification because it has been corroborated by another observation. Two sources reporting the same signing key produces a stronger observation; it does not produce a verification. Verifications only come from verifiers.

---

## 3. Locality rules

Locality is the rule that prevents verification from being inherited.

### 3.1 The rule (invariant 16)
A verified-form assertion may be emitted only when this binary, in this run, executed the verification procedure end-to-end against the artifact bytes and the procedure succeeded. Verified-form assertions may never be derived from observing another party's claim that verification occurred.

### 3.2 Root of trust
The verifier's root of trust (Fulcio root certificates for Sigstore, equivalent anchors for future verifiers) is pinned in the binary's source tree. Origin does not fetch its root of trust at runtime. Updating the root is a visible, attributable act recorded in git history. Live TUF-style updates are explicitly forbidden by this model, regardless of operational convenience.

### 3.3 Re-execution
On replay, the verifier re-executes the procedure against the on-disk evidence. A verified-form assertion that cannot be re-derived is treated as drift or tamper, not as authoritative history.

### 3.4 Federated input
When origin gains the ability to ingest assertions produced by other parties (Phase 3+), those assertions enter the log only as observations. A federated peer's claim that it verified X becomes, at the boundary, a `peer_reports_verification_of_X` predicate (observation class). To carry verified-form weight in origin's log, the artifact must be re-verified locally. There is no middle ground.

### 3.5 Code trust is not data trust
Trusting the embedded Sigstore verification library to implement DSSE/Fulcio correctly is a code-trust act, audited by reading the library and its dependency graph. This is distinct from trusting any data record that asserts verification occurred. The locality rule constrains data trust; it does not relax code trust review obligations.

---

## 4. Replay semantics

### 4.1 The replay rule
The full state of origin at any point in time T is the deterministic output of `f(log[0..T], code_versions[0..T], pinned_roots[0..T])`. No hidden state. No out-of-band caches. No operator memory.

### 4.2 Replay of observations
A replayed observation re-canonicalises the original raw evidence through the same normalizer version recorded in the assertion. Output bytes must equal the assertion's recorded canonical form. A divergence is either evidence tampering (raw bytes changed), normalizer drift (code changed without a version bump), or canonicalisation drift (a JCS bug).

### 4.3 Replay of verifications
A replayed verification re-executes the verifier against the original bundle bytes under the original pinned root. Two distinct failure modes exist:

- **Tamper**: the bundle bytes have changed, or the pinned root has rotated such that the previously valid cert chain no longer chains. The replay refuses; the system reports a failure that requires human inspection.
- **Drift**: the verification was valid at the time it was performed but is no longer (e.g., the signing certificate has expired and a stricter replay rejects it). Drift is distinct from tamper because the original verification's correctness is not in doubt — only its present-time validity.

The system reports drift and tamper distinctly. Drift does not invalidate historical claims that consumed the verification; it informs whether the underlying fact should be re-validated for present-time use.

### 4.4 Replay of refutations
A refutation replays like a verification: re-execute the procedure and confirm the same negative outcome. If a previously refuted attestation now passes verification, the system flags a refutation-to-verification transition for inspection (this can happen legitimately if, for example, the original failure was a transient transparency-log inclusion issue and inclusion has since been confirmed; it can also happen illegitimately if someone hand-edited a bundle to make it verify).

### 4.5 Replay of claims
A replayed claim re-evaluates the policy at the recorded version against the projection at the recorded manifest hash. The recomputed claim ID must equal the persisted claim ID. After Phase 2.5, this check is enforceable because `evaluated_at` lives outside the canonical envelope.

### 4.6 Replay scope
Replay confirms internal consistency. It does not confirm external truth. A successful replay proves origin has not internally drifted; it does not prove the external world has not changed.

---

## 5. Temporal semantics

### 5.1 Bitemporality
Every assertion carries two temporal fields:

- `observed_at` — the time the assertion's source claims the fact held. For observations, this is the source-side timestamp (e.g., the registry's `time.<version>` field). For verifications, this is the time at which our verifier ran.
- `ingested_at` — the time origin wrote the assertion to its log. Record-level metadata, not part of the canonical envelope.

The pair enables time-travel queries: "what did we know about X on date D" requires filtering by `ingested_at <= D`.

### 5.2 Canonicalisation discipline
Local clock times do not participate in canonical identity. `ingested_at` is record-level. `evaluated_at` (for claims) is record-level (post-Phase-2.5). The canonical envelope hashes only the fact and its source's temporal claim.

### 5.3 Source-claimed time
`observed_at` is taken from the source verbatim. Origin does not normalise, round, or reformat source-claimed timestamps in ways that would change their byte form, except to validate that the value parses as ISO 8601. The raw evidence retains the original textual form for forensic inspection.

### 5.4 Verifier-temporal duality
Cryptographic validity is time-dependent in ways canonical identity is not. A verified-form assertion records that verification succeeded at `observed_at`. Re-verifying at a later time may legitimately diverge if certificates have expired or roots have rotated. See §4.3.

### 5.5 Time-travel limits
Origin can answer "what did we know on D" by replaying assertions with `ingested_at <= D`. It cannot answer "what was true on D" — the system has no access to ground truth, only to recorded evidence. The distinction is invariant 1 (observation is not inference) applied to history.

---

## 6. Identity semantics

### 6.1 Identities are keyed principals
An Identity is a stable IRI for a signing key, OIDC subject, registry login, or other cryptographic or registry-administrative principal. Identities are not people. The system does not attempt to determine whether two identities denote the same person.

Identity IRI families:
- `npm:user:<login>` — registry-administered username.
- `npm:key:SHA256:<base64>` — npm's static signing key reference.
- `sigstore:fulcio:<hex>` — content-addressable hash of `(issuer, subject)` from a Fulcio cert. Stable across multiple runs of the same workflow.

### 6.2 No clustering
Day-1 and Phase-2 deliberately do not cluster identities. A package signed by `sigstore:fulcio:abc...` and published by `npm:user:foo` is two distinct identities related only by appearing on the same artifact. The system makes no claim about whether the human behind one is the human behind the other.

Future clustering, if introduced, is itself a second-order assertion (`derived_from` a clustering procedure) and must obey invariant 14 (derived claims never silently masquerade as observed facts). Clustering with opaque ML is forbidden by the project's stance (`project-origin-what-it-is`).

### 6.3 Assertion identity vs assertion occurrence
The canonical hash of an assertion's envelope is its *identity*: a deterministic fingerprint of the fact being asserted. The local event of writing it to a log — `ingested_at`, the local signer's signature, chain position — is its *occurrence*. Day-1 fuses these in one struct; the conceptual split is documented in `project-origin-identity-vs-occurrence` and is mandatory before federation. The model treats them as distinct even where the implementation has not yet separated them.

### 6.4 Equality
Two assertions with the same identity (same envelope hash) are the same assertion regardless of where, when, or by whom they were observed. Two assertions with different identities are different assertions regardless of any surface resemblance.

---

## 7. Failure semantics

Failure is a first-class observable. Silence is not.

### 7.1 Six operational states
For any (subject, predicate-family) pair, exactly one of the following states holds in the log:

| State | On-disk signature |
|---|---|
| **Not attempted** | No raw evidence of a fetch targeting this subject-family. |
| **Attempted, no candidate** | Raw evidence shows the source was queried; the response was empty. |
| **Attempted, malformed** | Refutation assertion present; reason code = `bundle_parse_failed` (or equivalent). |
| **Attempted, cryptographically invalid** | Refutation present; reason ∈ {`signature_invalid`, `certificate_chain_invalid`, `transparency_log_proof_invalid`, `subject_digest_mismatch`}. |
| **Attempted, semantically incoherent** | Refutation present; reason = `oidc_subject_coherence_failed` (potentially malicious). |
| **Verified** | Verified-form assertion present. |

All six states are distinguishable from on-disk artifacts alone, without running the binary.

### 7.2 Reason vocabulary
Reason codes are an enumerated set, not free text. Adding a reason is a vocabulary change subject to ontology-migration discipline (`feedback-ontology-migrations`).

### 7.3 Refutation as evidence
A refutation is not a privative claim ("X is not signed"). It is a positive claim about the verifier's own behaviour ("our verifier executed and rejected this attestation, for this reason"). This distinction matters: a refutation can be true while the underlying signing relation is also true, because the refusal might reflect a verifier bug, a transient registry state, or a deliberately constructed counter-example.

### 7.4 Absence handling
Absence — no raw evidence of attempt — is not refutation. Policies that distinguish "uncertain because we didn't look" from "uncertain because we looked and refused" must consult both the assertion tables and the raw evidence table. The system makes this join straightforward; policies that do not perform it are conflating two distinct epistemic states.

---

## 8. Derivation rules

### 8.1 Claims are records, not facts
A claim is the persisted record of an evaluation: a policy applied to a snapshot of the projection. The claim is not a new fact about the world. It is a fact about our reasoning process. Future evaluations may consume claims (via `derived_from`), but consumed claims arrive as inputs to second-order reasoning, never as observations of the world.

### 8.2 Pure policies
Policies are pure functions: `f(snapshot, query) -> {verdict, qualifiers, trace}`. They cannot perform I/O. They cannot consult side data not in the snapshot. They cannot call `http.send` or any equivalent. This is enforced by the policy runtime.

### 8.3 Output shape
- Verdict ∈ {trusted, conditional, rejected, insufficient_evidence}.
- Qualifiers are an unordered set of strings drawn from an enumerated vocabulary declared by the policy.
- Trace lists the rule names that fired.
- No numeric scores. No confidence values. No aggregate fields.

A policy whose output includes any numeric field is refused by the runtime. This is structural, not advisory.

### 8.4 Derivation provenance
Every claim records:
- The policy ID, version, and hash.
- The query expression.
- The projection manifest hash (snapshotting what the policy saw).
- The set of consumed assertion IDs and raw evidence IDs.
- The vocab version and the normalizer versions for each consumed assertion's predicate.

Any one of these would let a sceptic reconstruct the evaluation. All five together make the reconstruction exact.

### 8.5 Reproducibility
A policy evaluated against an unchanged snapshot must produce a byte-identical claim envelope. The `verify` command enforces this on every run after Phase 2.5.

### 8.6 No silent second-order escalation
A second-order assertion (one derived from claims or from other assertions) must carry `derived_from` pointers. Projections render it visibly second-order. Policies that mix first-order and second-order evidence weight them differently, and the difference is encoded explicitly in the policy, not in the assertion form.

---

## 9. Admissible evidence classes

The model recognises five admissible evidence classes. Anything else is inadmissible.

### 9.1 Raw evidence
Bytes from an external source, fetched by origin, content-addressed, with a signed metadata sidecar that records what was fetched, when, from where, and by whom. Raw evidence is the substrate of every observed assertion and the input to every verification.

### 9.2 Signed observational assertions
Produced by versioned normalizers from raw evidence. Strength: depends on the source. Weight in policy: configurable, typically weak in isolation, stronger when corroborated by independent sources (where independence is operationally defined, not assumed).

### 9.3 Signed verified assertions
Produced by versioned local verifiers from raw evidence and pinned roots of trust. Strength: depends on the verifier's correctness and the soundness of the trust root. Weight in policy: strong.

### 9.4 Signed refutation assertions
Produced by the same verifiers on failure. Strength: as strong as the verifier's negative judgement. Weight in policy: a strong negative signal that consumed evidence was tested and rejected.

### 9.5 Structural assertions
`revises`, `derived_from`, and future meta-assertions. Strength: their truth value is structural (they reorganise the log), not empirical.

### 9.6 Inadmissible
Explicitly outside the model:
- Unsigned data of any kind.
- Data whose evidence pointer cannot be resolved on disk.
- Claims by other parties to have already performed verification (these are observations of those claims, not verifications).
- Cached verification results where re-execution is not deterministically guaranteed.
- ML model outputs as evidence in the trust path.
- Free-text human commentary.
- Statistical correlations not derived from explicit policy rules over admissible inputs.

### 9.7 Weight is a policy concern, not an evidence property
Each evidence class has structural strength, but the *weighting* of evidence is the policy's responsibility. The model does not pre-weight evidence into a global hierarchy. Two correctly written policies looking at the same evidence may legitimately produce different verdicts, and that is correct — the model's job is to make the disagreement visible and reproducible, not to adjudicate it.

---

## 10. What this model is NOT

To prevent drift, the model also declares what it explicitly does not claim or attempt.

- **Not a theory of human trust.** Origin reasons about software artifacts and the procedures we can run against them. It does not model trust between people, organisations, or institutions.
- **Not a theory of truth.** Origin records what was observed and what was verified. It does not adjudicate the underlying truth of source claims. Two sources reporting different things produces two observations, not a vote.
- **Not a unified scoring framework.** The model rejects aggregate scores. Policies produce categorical verdicts with enumerated qualifiers; consumers compose them as they see fit. The model never collapses dimensions on behalf of a consumer.
- **Not a knowledge graph product.** Property-graph projections are derived indexes, not authoritative state. The canonical form is the signed append-only log.
- **Not a recommendation engine.** Verdicts are evaluations of evidence, not preferences. Origin does not personalise.
- **Not opinionated about ecosystems.** The Day-1 + Phase-2 implementation targets npm. The model is ecosystem-agnostic: any verifier producing locally-executed cryptographic outputs over content-addressed bytes can plug in.
- **Not closed.** The model is v1 and will revise. Revisions are explicit and versioned. The implementation may not exceed the model.

---

## 11. Open questions / future revisions

Items the model deliberately leaves underspecified at v1, to be resolved by future versions with explicit rationale:

- **AssertionIdentity vs AssertionOccurrence implementation.** Conceptually disjoint in §6.3; structurally fused in the Day-1 record. Phase 3 candidate.
- **Independence semantics.** §2.5 mentions "independent sources" but does not formally define independence. A future model version will codify when two attestors count as independent (different root keys, different organisational principals, different sourcing pathways).
- **Verifier composition.** When two verifiers each produce verified-form assertions over the same artifact, the model treats them as two independent verifications. The model does not yet specify how policies should weight them differently from a single verification.
- **Trust root governance.** §3.2 mandates pinning roots in source. The governance of how roots are chosen, rotated, and audited is a procedural matter the model does not yet specify. It is a documentation deficit, not a structural one.
- **Cryptographic drift policy.** §4.3 distinguishes drift from tamper. The specific operational handling of drift (e.g., does an expired-cert verification still count for derivation purposes? for what window?) is left to future policy guidance.
- **Cross-ecosystem identity reconciliation.** §6.2 forbids identity clustering. A future version may allow *explicit* second-order clustering predicates (`derived_from` chains) provided they obey the existing rules; the criteria for such introductions are not yet specified.

---

## 12. Authority and revision

This document is authoritative for the project's epistemological commitments at version v1.

Revisions to this document are themselves versioned. A revision is a new file `epistemic-model.v<N>.md` with a `supersedes` field naming the prior version. The prior version remains in the repository. Historical claims made under earlier model versions retain their original interpretation; new claims must conform to the model active at the time of their evaluation.

No silent edits.

---

### Closing test for this model

The model holds if and only if these statements are simultaneously true:

1. Every assertion in any origin log can be classified into exactly one of the four classes in §1.
2. Every assertion's producing activity can be identified from its predicate and recorded normalizer/verifier version.
3. Every verified-form assertion was produced by a procedure executable by origin against the on-disk evidence; re-executing the procedure on replay yields a result whose category (verified / drift / tamper) is decidable.
4. Every refutation carries a reason code from the enumerated vocabulary.
5. Every claim's derivation is reproducible from `(log[0..T], code_versions[0..T], pinned_roots[0..T])`.
6. No assertion's truth is asserted to be intrinsic to its subject. Every assertion is about an observation, a verification, a refutation, or a structural relation.
7. No part of the system stores or emits a numeric trust score.
8. The model's own scope is enforced: nothing in §9.6 ("Inadmissible") appears anywhere in the trust path.

If any of these fails for any production output, the implementation has drifted from the model.
