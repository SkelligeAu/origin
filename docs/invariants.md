# Invariants

These are the rules Origin holds. Implementations conform to v0 of the protocol only if every invariant on this list is preserved, by construction, in their code paths. Reviewers should test against these rules; any concrete case that violates one is a finding.

The list is intentionally short and load-bearing. Each invariant has a short statement, a longer explanation, and the specific implementation mechanism that enforces it.

---

## 1. Observation is not inference

**Statement.** A predicate's name and verification class describe *the activity that produced it*. An "observation-class" predicate records what some external source said; a "verification-class" predicate records that this binary executed a verification procedure end-to-end. The system does NOT silently promote observation into verification, nor accept "registry said it" as equivalent to "we verified it".

**Why.** Without this distinction, every aggregator becomes a trust laundromat. "The registry says it is signed" is not "we verified the signature". Conflating them is the failure mode every existing trust-score product falls into.

**Enforcement.**

- Vocabulary v6 declares `verification_class` per predicate. The active vocabulary is loaded at ingest time; assertions with unknown predicates are refused.
- Naming conventions documented in [`CONTRIBUTING.md`](../CONTRIBUTING.md): `<source>_reports_X` for observation; `cryptographically_verified_X` (or similar) for verification.
- The federation rewrite rule (invariant 6) prevents an observation from being promoted at the import boundary.

## 2. Verification is local

**Statement.** A verification-class assertion may be emitted only when this binary, in this run, executed the verification procedure end-to-end against the artefact bytes, anchored to a root of trust pinned in source code. Verification is never inherited.

**Why.** The single most dangerous failure mode of a trust system is "someone else verified it, so we did too". Verification is a *computation* over *bytes* against a *pinned root* — not a claim accepted from outside.

**Enforcement.**

- Vocabulary `verification_class = verification` predicates are emitted exclusively by code in `internal/sigstore/` (Sigstore) and any future verifier package. The emitting path always reads bytes from disk and runs the procedure.
- Trust roots are embedded files (`internal/sigstore/trusted_root_public_good.json`). The implementation does not fetch trust roots at runtime; doing so would be a category-2 finding under [`SECURITY.md`](../SECURITY.md).
- Verify check #8 re-executes the verification procedure during replay; a previously-verified identity that no longer verifies is reported distinctly.

## 3. Trust is not stored

**Statement.** No node, edge, table, or record carries a "trust" attribute. Trust exists only as the categorical output of a policy evaluation against a projection snapshot.

**Why.** Stored trust attributes invite mutation, drift, and silent recomputation. A TrustClaim is a record of *one evaluation event*, not a property the subject possesses.

**Enforcement.**

- TrustClaim records are persisted in `data/claims/` as a derivation, not as a subject property.
- The projection schema has no "trust" column anywhere.
- Verdicts are a closed enum of four strings (`trusted`, `conditional`, `rejected`, `insufficient_evidence`); writes outside the enum are refused.

## 4. Facts are content-addressed

**Statement.** Every canonical fact (Identity, TrustClaim, raw evidence payload, Checkpoint) is identified by the SHA-256 of its canonical bytes. Two observers seeing the same fact compute the same identifier.

**Why.** Federation depends on it. Replay depends on it. Tamper-evidence depends on it.

**Enforcement.**

- `internal/canon/canon.go` implements RFC 8785 JCS directly. Floats and unknown shapes are rejected at canonicalisation time.
- Identity envelopes deliberately exclude `ingested_at` (a local-event field), so the same fact ingested by two ingestors produces the same Identity ID.
- Fixture self-tests in `protocol/v0-fixtures/` byte-equality-assert canonicalisation on every CI run.

## 5. Occurrences are local witnessing events

**Statement.** Identities are *what* was asserted. Occurrences are *who*, *when*, *in which chain*. The two are structurally distinct.

**Why.** Without the split, federation forces "either duplicate facts or rewrite history". The split lets multiple ingestors share Identities while preserving each one's local record of having observed them.

**Enforcement.**

- `internal/assertion/identity.go` and `internal/assertion/occurrence.go` are separate types with disjoint field sets.
- The on-disk layout `data/assertions/identities/` vs `data/assertions/occurrences/local/+foreign/<peer>/` enforces the separation.
- Verify check #4 confirms every Occurrence's `identity_id` resolves; check #2 verifies every Occurrence signature independently.

## 6. Federation must not inflate truth

**Statement.** A peer's verification-class identity does NOT become a local verification-class identity. At the import boundary, foreign verification-class identities are rewritten as observation-class `peer_reports_*` predicates that reference the foreign identity by ID. The foreign verification-class identity is not stored in the local identity store.

**Why.** Federation is valuable. Trust laundering across federation is catastrophic. The rewrite rule is the one line between them.

**Enforcement.**

- `internal/peerimport/peerimport.go` implements the rewrite. Verification-class foreign identities are explicitly excluded from local identity storage.
- The vocab-driven `roleFor(predicate)` check refuses `federated_importer`-role occurrences that cite verification-class predicates.
- Verify check #12 (no-laundering) walks every `federated_importer` occurrence and asserts the cited identity's predicate is observation- or structural-class. Any violation is a hard fail.

## 7. Failure is first-class

**Statement.** Verification failure is an observable event with a structured reason code, not silence. "We did not look", "we looked and found nothing", "we looked and refused" are six distinct on-disk states.

**Why.** A negative judgement by our verifier is useful information. Silence about whether a check ran is dangerous information.

**Enforcement.**

- `cryptographic_verification_failed` predicate exists for the refutation case, with seven enumerated reason codes in the structured failure record.
- Raw evidence records of every fetch (including those that returned nothing) are stored under `data/raw/`. Policies can join against `raw_evidence` to detect "we looked but found nothing".
- The six operational states (never checked / attempted-empty / malformed / cryptographically invalid / semantically incoherent / verified) are individually queryable.

## 8. Replayability is mandatory

**Statement.** The full state of an Origin archive at time T is the deterministic output of `f(log[0..T], code_versions[0..T], pinned_roots[0..T])`. No hidden state. No process memory. No out-of-band caches.

**Why.** This is what makes an Origin archive auditable by a third party offline.

**Enforcement.**

- Verify checks #1 (identity reproducibility), #6 (projection determinism), #8 (cryptographic re-verification), #9 (claim re-derivation determinism), #13 (anchor integrity) all re-execute deterministic derivations and assert byte-equality.
- Local timestamps (`ingested_at`, `evaluated_at`) are excluded from canonical-bytes hashing precisely so re-derivation reproduces.
- The fixture self-test (`protocol/v0-fixtures/fixtures_test.go`) runs on every CI invocation.

## 9. Anchoring is witnessing, not authority

**Statement.** A transparency-log anchor is a record that the local node submitted a checkpoint to an external system and the system returned a response. The anchor is observation-class. It is evidence of "we did the thing"; it is NOT evidence that the underlying log content is true, that the timestamp is accurate, or that any external party agrees.

**Why.** Transparency systems are timestamping witnesses, not consensus oracles. Treating them as oracles is trust laundering one layer up.

**Enforcement.**

- `transparency_log_records_checkpoint` predicate is declared `verification_class: observation` in vocab v6.
- The implementation has no `cryptographically_verified_inclusion_in_log` predicate in v6. (A future Phase 5.5 may add one as verification-class, with its own pinned tree-head root and verifier code.)
- Verify check #13 detects local tampering relative to an anchor (TAMPER / TRUNCATED / MISSING_LOG); it does NOT consult the transparency system at replay time. Provider unavailability does not affect verify.
- No policy in this repository consumes anchor predicates as authority. Policy authors who do so must document the trade-off explicitly.

## 10. Policies derive claims; they do not create evidence

**Statement.** A policy is a pure function `(snapshot, query) → claim`. It cannot perform I/O. It cannot consult external data. It cannot append to the assertion log. Its output is a categorical verdict plus enumerated qualifiers plus a derivation DAG.

**Why.** A policy that can write to the evidence store is a back door. A policy that fetches data at evaluation time is non-deterministic. Both break replay.

**Enforcement.**

- The OPA evaluator is configured without `http.send` capability and without external `data.*` sources beyond the snapshot.
- Policy `required_predicates` declares the snapshot's shape; nothing outside that shape is observable.
- TrustClaims are written by the eval pipeline, not by the policy.

## 11. No scores

**Statement.** Verdicts are categorical: `trusted`, `conditional`, `rejected`, `insufficient_evidence`. No numeric score, percentage, or aggregate appears in any TrustClaim, raw evidence record, or projection cell.

**Why.** Aggregation discards the information that makes a verdict reviewable. Categorical outputs with enumerated qualifiers preserve the audit story.

**Enforcement.**

- The TrustClaim JSON schema is enforced at write time; numeric verdict fields are refused.
- Qualifiers are an unordered set of strings drawn from the policy's enumerated vocabulary.
- Policies that introduce numeric outputs will be rejected at review time per [`CONTRIBUTING.md`](../CONTRIBUTING.md).
- The implementation does not import any statistics, ML, or ranking library.
