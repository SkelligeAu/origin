# Phase 5 Plan: Transparency Log Anchoring

> **Phase 5 thesis.** External tamper-evidence is currently absent: the local chain is internally verifiable but a sufficiently powerful adversary with write access can rewrite the entire log to any other internally-consistent state and no verify check will catch them. Phase 5 closes that gap by allowing the local node to publish *checkpoints* (signed summaries of the local chain head at a moment in time) into an external transparency system, then *record the act of having done so* as an observation-class fact in the local log. The transparency system becomes a witness: evidence that a particular checkpoint existed at or before a particular time. It does NOT become an authority, a consensus, a vote, or a source of truth.

This phase is additive only. Every existing invariant survives. Replay still works offline. Federation rules unchanged. The protocol gains one new vocabulary version and (optionally) one new verify check. Nothing else moves.

The bar is high for what could count as "structurally correct." Every line of this plan was written to keep anchoring from accidentally smuggling authority into the epistemic model. If a reviewer can point at any section and say "this would let a transparency provider's say-so flip a verdict," the design has failed and the section must be revised.

---

## 1. The core operation

Two artefacts and one external act:

1. **Checkpoint** — a signed local document of the form `(log_id, seq, chain_hash_at_seq, signed_at, signature)`. Produced from the local chain. Carries its own content hash. Content-addressable; small (~250 bytes); store as a raw-evidence record under `source = "origin.checkpoint"`.

2. **External submission** — the operator hands the checkpoint to some transparency system (Rekor, a git commit, a Merkle log, a signed pastebin — Phase 5 is agnostic). The system returns a record acknowledging receipt, typically a log entry ID plus an inclusion proof. This response is bytes; store them as a raw-evidence record under `source = "<provider>.anchor"` (e.g. `sigstore.rekor.anchor`).

3. **Anchor identity** — an observation-class assertion the local node makes about its own act of submission:

   ```
   transparency_log_records_checkpoint(
     subject:    <iri for our checkpoint>,
     object:     <iri for the transparency-system entry>,
     evidence_id: <hash of the provider's response bytes>
   )
   ```

   This assertion records what the local node observed when it submitted the checkpoint. It does not record that the underlying log content is true, agreed-with, or authoritative. The transparency system is a *timestamping witness*; its acknowledgement is bytes we observed it return.

The whole anchoring operation is, in epistemic terms, ONE observation of the form "we submitted X to Y and Y responded with Z." Everything else falls out from existing invariants.

---

## 2. Invariant preservation, point by point

Phase 5 is correct only if all eight of the user-stated invariants survive intact:

| Invariant | How Phase 5 preserves it |
|---|---|
| Observation is not inference | Anchor identities use only observation-class predicates. The new predicates are named to describe *what was observed*, not what was concluded. |
| Verification is local | Phase 5 introduces no `cryptographically_verified_*` predicates. Inclusion-proof verification is deliberately deferred. The system never claims to have "verified" anchoring. |
| Federation must not inflate truth | Imported anchor observations become `peer_reports_transparency_log_records_checkpoint_of` — observation-class, no different from any other peer-reported observation. The no-laundering rule catches violations. |
| Canonical identities remain content-addressed | Adding or removing an anchor changes NO existing assertion ID, occurrence ID, or claim ID. The anchor identity is itself content-addressed like every other identity. |
| Replay determinism intact | Anchor identities replay deterministically from raw evidence bytes. The transparency system is never consulted during replay. |
| No numeric trust semantics | Anchors do not produce scores, weights, or confidence values. They produce identities, classified categorically. |
| No hidden state | Every anchor lives on disk: the checkpoint, the provider response, the resulting identity. Nothing in process memory carries trust meaning. |
| No runtime trust-root fetching | If Phase 5.5 ever ships inclusion-proof verification, the transparency log's tree-head verification key is pinned in source code, never fetched. Phase 5 itself runs no verification. |

---

## 3. Ontology additions (vocabulary v6)

Two new predicates. Both observation class. Nothing else changes.

### 3.1 `transparency_log_records_checkpoint` — observation

- `subject_kind`: `iri` (a `checkpoint:<sha256>` URI naming a local checkpoint)
- `object_kind`: `iri` (a `<provider>:<entry-id>` URI naming the external record)
- `verification_class`: `observation`
- Description: "The local node submitted a checkpoint to a transparency system and recorded the system's response. OBSERVATION class: the assertion records what was returned, not whether the timestamp is accurate, the provider is trustworthy, or the underlying log content is true. The evidence_id points at the bytes the provider returned. Policies requiring strong tamper-evidence may consume this predicate as weak corroboration. Promotion to a verified-form inclusion proof requires running an inclusion-proof verifier locally (Phase 5.5 candidate; not part of v6)."

### 3.2 `peer_reports_transparency_log_records_checkpoint_of` — observation

- `subject_kind`: `iri` (the same `checkpoint:<sha256>` form)
- `object_kind`: `ref` (a reference to the foreign anchor identity ID)
- `verification_class`: `observation`
- Description: "A federated peer claims to have observed an anchor record for the named checkpoint. OBSERVATION class: this is our observation of the peer's observation; it inherits no authority from the original transparency system. Object is a ref to the peer's anchor identity ID."

### 3.3 Why not also a verification-class predicate?

A future `cryptographically_verified_inclusion_in_log` predicate would require:

- Pinning the transparency log's tree-head verification key in source.
- Implementing inclusion-proof verification locally (a non-trivial cryptographic procedure).
- A new test fixture covering both happy and adversarial inclusion proofs.

This is Phase 5.5 work. Phase 5 deliberately ships only the observation predicate because:

- **Tamper-evidence is already strengthened by the observation form** (see §5 and §7 below); cryptographic inclusion verification adds confidence but not categorical capability.
- **Smaller surface to audit.** The Phase 5 changes touch nothing requiring cryptographic care; reviewers can focus on the structural correctness of the rewrite rule and the new verify check.
- **The user's "boring, inevitable" guidance.** Observation-only matches that brief; adding a verifier doesn't.

The naming of the v6 predicate already anticipates v6.5: `transparency_log_records_checkpoint` (observation) sits alongside a future `cryptographically_verified_inclusion_in_log` (verification) without overlap.

---

## 4. Checkpoint structure

A checkpoint is a signed canonical document with the following fields:

```
{
  "log_id":      "<our local log_id>",
  "seq":         <integer chain sequence number>,
  "chain_hash":  "<hex>",
  "signed_at":   "<RFC 3339>"
}
```

The bytes signed are the JCS canonical encoding of the four fields above. The signature is Ed25519 by the local key, same format as occurrence signatures: `ed25519:<fp>:<base64>`.

On disk the checkpoint is a `signed` envelope:

```
{
  "checkpoint": { log_id, seq, chain_hash, signed_at },
  "signature":  "ed25519:..."
}
```

The checkpoint's IRI is `checkpoint:<sha256 of signed envelope canonical bytes>`. This IRI appears as the `subject` in anchor identities.

Checkpoints are NOT predicate-bearing identities. They are raw evidence (canonical bytes the system produced locally and stores under `data/raw/origin.checkpoint/...`). The anchor identity is what carries vocabulary status; the checkpoint is a referenced artefact.

This is the same pattern as `data/raw/sigstore.bundle/` carrying Sigstore bundles that are referenced by verified-form identities.

---

## 5. The anchoring flow

Manual, operator-initiated, no network code in Phase 5 itself. The CLI surface is two new subcommands:

### 5.1 `origin checkpoint [--output <path>]`

Constructs a Checkpoint from the current local chain head, signs it with the local key, writes it to `<path>` (default: `./checkpoint-<seq>.json`). Also writes the bytes as raw evidence under `data/raw/origin.checkpoint/`.

This command produces an artefact suitable for submission to any transparency system. The operator handles the actual submission out-of-band — copies the file to a Rekor CLI, commits it to a git repo with a signed tag, etc.

### 5.2 `origin record-anchor <checkpoint-iri> <provider-entry-iri> --evidence <path>`

Records an anchor identity. Inputs:

- `<checkpoint-iri>`: a `checkpoint:<sha256>` IRI, expected to be present in `data/raw/origin.checkpoint/`.
- `<provider-entry-iri>`: e.g. `rekor:42:e3a1...`. Schema is implementation-defined per provider; the IRI's exact form does not affect identity hashing beyond its string value.
- `--evidence <path>`: path to the bytes the transparency provider returned (inclusion proof, log entry record, etc.). Imported into `data/raw/<provider>.anchor/` as a raw evidence record.

The command emits the anchor identity under `transparency_log_records_checkpoint` and an observer-role occurrence by the local key. Both content-addressable; both replayable.

This separation — checkpoint generation versus anchor recording — exists deliberately so submission is out-of-band. No HTTP code in the binary. If the operator wants automation, that's a shell wrapper outside Origin's surface.

### 5.3 Why not "origin anchor <provider>"?

Tempting but wrong for Phase 5. Adding a provider-aware submission step would introduce:

- Network code (forbidden by user direction).
- Provider abstractions (a `Submitter` interface, etc.).
- Configuration for endpoints, auth, retries.
- Per-provider error handling.

All of that is operationally heavy and adds zero epistemic value. The data shapes are the load-bearing part; transmission is just I/O. Phase 5 ships the shapes; future phases or external tooling do the transmission.

---

## 6. Federation interaction

A peer's anchor identity is observation-class. At the federation import boundary it follows the standard Phase-3.5 rules:

- Foreign Identity has predicate `transparency_log_records_checkpoint` (observation class).
- The importer stores the foreign Identity in the local Identity store (observation-class identities pass through as-is).
- The foreign Occurrence is preserved verbatim in `foreign/<peer-log-id>/`.

No rewrite is required for the observation-class anchor itself. However, an operator might want to distinguish "we anchored this checkpoint" from "a peer told us they anchored this checkpoint." To make that distinction visible in policy queries:

- Each anchor identity carries its own `evidence_id` (the response bytes). Two different anchors of the same checkpoint by two different parties produce DIFFERENT identity IDs because the evidence bytes differ.
- The `attestor` on the citing occurrence distinguishes who recorded it.

A policy author wanting "at least one anchor that this local node produced itself" can join the anchor identities to local occurrences with `attestor_role = observer`. Peer-imported anchors have `attestor_role = federated_importer` (Phase 3.5 §3) on their citing local occurrence — wait, this is wrong. Let me reconsider.

Actually, since the anchor predicate is observation-class, the foreign Occurrence (signed by the peer with role=observer) gets stored verbatim in `foreign/<peer-log-id>/`. The local node does NOT need to write a new federated_importer occurrence in this case — that's only required for verification-class predicates per Phase 3.5 §10.3.

But this means peer-imported anchors look identical to local anchors at the identity layer (same observation-class predicate, same shape). Distinguishing requires querying the occurrences table for log_id and attestor_role.

For clarity, the v6 vocabulary also includes the rewrite predicate `peer_reports_transparency_log_records_checkpoint_of` — though strictly it is NOT required by the federation boundary rule (the underlying predicate is already observation class). It exists for cases where a policy author wants a structurally clear answer to "this came from a peer's anchor" without joining tables. Implementations MAY emit this rewrite identity OR pass through the original anchor identity; either is structurally honest.

For Phase 5 minimum, the implementation passes through anchor identities unchanged. The `peer_reports_*` predicate is reserved in vocabulary for future use.

(Open question for review: should the importer emit BOTH the passed-through anchor AND a `peer_reports_*` rewrite, so policies have a clean per-source predicate? My current preference is: no — that's ontology bloat. The attestor/log_id columns on the occurrence already carry the distinction. The rewrite predicate is reserved but not minted on first encounter.)

---

## 7. Verify extensions

Exactly one new check. Number twelve in the existing list becomes thirteen:

### 7.1 Verify check #13 — anchor integrity

For every Identity with predicate `transparency_log_records_checkpoint`:

1. Resolve the subject IRI (`checkpoint:<sha256>`) to a checkpoint raw-evidence record.
2. Parse the checkpoint envelope; verify its signature is valid by SOME attestor key the registry knows.
3. Read the checkpoint's `(log_id, seq, chain_hash)` triple.
4. For that `log_id` (local or foreign), walk the chain.log to find the entry at sequence `seq`.
5. Confirm the chain entry's `chain_hash` equals the checkpoint's `chain_hash`.

Any mismatch is a hard fail with categorisation:

- **TAMPER**: the local chain at `seq` exists but `chain_hash` differs. Implies someone rewrote the chain after anchoring.
- **TRUNCATED**: no chain entry exists at `seq` (the chain is shorter than the anchor claimed). Implies post-anchor truncation.
- **MISSING_LOG**: `log_id` is neither local nor a known foreign log. Implies the anchor was misimported or refers to an unknown log.

This is the load-bearing tamper-evidence check. Adding it is the entire structural reason Phase 5 exists.

### 7.2 No other new checks

- Inclusion-proof verification (checking the provider response actually proves inclusion) is deferred to Phase 5.5.
- "Anchor freshness" (checking how old anchors are) is a policy concern, not a verify concern.
- "Anchor coverage" (checking that anchors exist at all) is a policy concern.

This keeps Phase 5 verify additions to exactly one check.

---

## 8. Replay semantics

The user explicitly asked for four cases.

### 8.1 Replay with missing transparency system

Replay is offline. The transparency system is never consulted. All anchor data — checkpoints, provider responses, anchor identities — is local. Verify check #13 walks local chains and resolves local raw evidence; no network access.

**Outcome:** all twelve checks plus #13 still pass on the local archive. Transparency system unavailability is invisible to verify.

### 8.2 Replay with diverged inclusion proof

If a future Phase 5.5 implements inclusion-proof verification and the recorded proof no longer verifies against the transparency system's *current* tree head (e.g., provider has rotated keys, re-issued tree, etc.), that's **drift**:

- The proof was valid at the time we recorded it.
- The proof is no longer valid against the current external state.
- This is not tamper; the local archive is internally consistent.
- It is signalled distinctly so operators can investigate.

Phase 5 itself does not detect this case because Phase 5 does no inclusion-proof verification. The case is documented for Phase 5.5.

### 8.3 Replay with stale witness checkpoints

If we recorded an anchor that says "tree head was T1 at time X" and the witness's tree head is now T2, that's expected — the tree has grown. Stale tree-head info doesn't invalidate our recorded anchor. Replay verifies our recorded data; current external state is irrelevant.

### 8.4 Tamper vs drift vs external unavailability

| Failure | Cause | Phase 5 detection |
|---|---|---|
| **Tamper** | Local archive bytes modified after anchoring. | Verify check #13 fails with `TAMPER` or `TRUNCATED` status. |
| **Drift** | External system's view of inclusion no longer matches our record. | Not detected by Phase 5 (requires inclusion-proof verification, Phase 5.5). |
| **External unavailability** | Transparency system offline at audit time. | No verify failure; verify never contacts the system. |

The distinction matters: tamper is bad and surfaces; drift is informational and is silent in v5; unavailability is irrelevant.

---

## 9. Fixture strategy

Phase 4 established that fixtures are hermetic, byte-equal, and shipped in the repo. Phase 5 extends this without contacting Rekor or any live system.

### 9.1 Fake transparency-log response

Construct a synthetic provider response with the JSON shape Rekor (or chosen reference provider) would use, but with fixed, documented bytes. Key fields populated; no signatures need to verify because Phase 5 does not run inclusion-proof verification.

The fixture's provider IRI uses a clearly-synthetic prefix: `fakelog:fixture:<id>` — so no implementation accidentally treats fixture data as production data.

### 9.2 Fixture artefacts

Under `protocol/v0-fixtures/anchor/`:

```
anchor/
├── checkpoint.json              signed checkpoint (uses test key from §14)
├── checkpoint.canonical-bytes   JCS bytes
├── checkpoint.expected-iri      "checkpoint:<sha256>"
├── provider-response.json       synthetic transparency-system response
├── provider-response.expected-hash
├── anchor-identity.json         emitted anchor identity (observation class)
├── anchor-identity.canonical-bytes
└── anchor-identity.expected-id
```

The fixture test (`anchor_test.go`) re-derives every value and byte-equality-asserts. Same shape as the existing fixture tests.

### 9.3 Federation fixture

Already covered: the existing `TestFederation_RewriteRule` machinery handles observation-class predicates transparently. A future fixture can demonstrate "peer anchors visible in local projection without authority promotion" by adding a peer-side anchor identity. Not required for Phase 5 acceptance; documented as a desirable Phase-5-follow-up test.

---

## 10. Threat analysis

### 10.1 Retroactive log rewriting

**Threat:** an operator modifies the local log after anchoring, then re-anchors the modified state. The new anchor exists; the old anchor — if it was already published externally — also exists, separately.

**Mitigation:** verify check #13 detects internal inconsistency between anchored chain heads and current chain content. The old anchor remains in the external transparency system; an auditor with access to that system can detect the rewrite even if the local archive shows only the new anchor. Origin-side detection is local-archive-only; external auditing is the operator's responsibility.

**Residual risk:** an attacker with full local control and no prior external publication can produce a consistent rewritten archive. Phase 5 does not prevent this; transparency systems with external witnesses do.

### 10.2 Selective disclosure

**Threat:** the operator anchors only some checkpoints; gaps in coverage hide modified ranges.

**Mitigation:** none in Phase 5. Coverage is a policy concern. Operators or policy authors who care about coverage can write policies that flag "checkpoints with no anchor record." The model doesn't impose coverage requirements.

**Note:** this is acceptable. Phase 5 strengthens tamper-evidence where anchors exist; it does not promise to detect their absence. Documented as a known limitation.

### 10.3 Anchor equivocation

**Threat:** the operator submits two different checkpoints under colluding circumstances, presenting different views to different auditors.

**Mitigation:** both anchors exist as separate identities. The conflict is detectable to anyone who sees both records. Within Origin, two anchor identities citing different chain heads for the same `(log_id, seq)` is a structural anomaly verify can flag — this is a candidate refinement of check #13 (left for Phase 5.5: "same log_id+seq → must have same chain_hash across all anchors").

### 10.4 Hostile transparency provider

**Threat:** provider refuses to anchor; lies about timestamps; selectively serves different inclusion proofs to different queriers.

**Mitigations:**

- The provider can ONLY make claims about what's in their log; they cannot rewrite our local archive.
- The anchor predicate is OBSERVATION class: we record what they returned, not whether it was truthful.
- Multiple anchors from multiple providers reduce single-point-of-failure but do not produce consensus; each provider's claim is one observation.
- No policy in Phase 5 consumes anchor observations as authority. Future policy authors must decide on weighting; if a policy treats provider claims as conclusive, that's a policy bug, not a protocol bug.

**Residual risk:** unbounded provider lying remains a risk insofar as a policy decides to consume anchor observations strongly. The protocol cannot prevent this; it can only label the evidence honestly.

### 10.5 Timestamp forgery

**Threat:** provider claims an inclusion time earlier than actual submission.

**Mitigation:** Phase 5 does not assert timestamp accuracy. Anchor identities record what was observed, including the provider's claimed timestamp; whether that timestamp is accurate is a question about the provider, not about Origin.

Operators who need stronger timestamp guarantees should use providers that publish witness signatures over their tree heads (e.g., signed checkpoint via Sigstore's TSA, or witnessed Rekor). Phase 5 supports recording such evidence; Phase 5.5 would verify witness signatures locally.

### 10.6 Imported fake checkpoints

**Threat:** a peer reports a fake anchor for a fake checkpoint.

**Mitigations:**

- Federation passes through observation-class identities, but they're attested by the peer's key. Verify check #11 (foreign occurrence signatures) confirms the peer signed.
- The peer can ONLY make claims; we record what they claimed. No verification claim crosses the federation boundary.
- The fake checkpoint subject IRI references bytes that may not exist locally; verify check #13 cannot resolve the chain (`MISSING_LOG` or no matching seq).
- The fake anchor is recorded but flagged by check #13 as referring to an unverifiable chain.

**Outcome:** peer-imported fake anchors produce verifiable-locally `MISSING_LOG` failures, which are operator-visible. The peer's claim is recorded; the local archive is not corrupted.

### 10.7 What anchoring DOES prove

- A specific checkpoint with a specific `(log_id, seq, chain_hash)` existed at the local node at the moment the checkpoint was signed.
- The bytes of the checkpoint were submitted to the named transparency system, and the system returned the recorded response.
- If verify check #13 passes, the current local archive's chain at `(log_id, seq)` still has the recorded head.

### 10.8 What anchoring DOES NOT prove

- The provider's timestamp is accurate.
- The provider is honest.
- Other observers agree.
- The underlying log content is true.
- Other observers have seen the same data.
- The state is the *current* state (anchors are about specific past moments).
- The anchor IS verified (cryptographic inclusion verification is Phase 5.5).
- The absence of anchors implies tampering.

---

## 11. Falsifiable success criteria

| # | Criterion | Test |
|---|---|---|
| 1 | A checkpoint can be produced from the current chain and is content-addressable. | `origin checkpoint` writes a checkpoint file; the file's signature verifies; its content hash is recorded as a raw-evidence record. |
| 2 | An anchor identity can be recorded without network access. | `origin record-anchor` succeeds against fixture inputs; the resulting identity is content-addressed and observation-class. |
| 3 | Anchor identities are observation-class and pass through federation. | Importing a peer's archive containing an anchor identity produces a local row with the same `transparency_log_records_checkpoint` predicate; verify check #12 (no-laundering) confirms no federated_importer occurrences cite verification/refutation-class predicates. |
| 4 | Verify check #13 detects post-anchor tampering. | After anchoring a chain at seq 5, modifying chain.log at seq 3 (within the anchored prefix), verify reports `TAMPER` for the anchor. |
| 5 | Verify check #13 detects post-anchor truncation. | After anchoring at seq 10 and removing chain entries after seq 5, verify reports `TRUNCATED`. |
| 6 | Existing claim IDs are unchanged by anchoring. | Compute claim ID before any anchor exists; record an anchor; recompute the same claim — IDs are byte-identical. |
| 7 | Replay works offline. | Move the archive to a network-isolated machine; `origin verify` passes all thirteen checks. |
| 8 | No new policies consume anchor predicates. | `release_signing/v2` and `dependency_hygiene/v1` remain frozen. No `cls-verification` styled identities are added for the anchor predicate (it's `cls-observation`). |
| 9 | Fixture round-trips. | `protocol/v0-fixtures/anchor/` fixture test passes byte-equality against the implementation. |

---

## 12. Implementation plan (minimal additive surface)

Ten steps, each ending with a clean build and existing tests still passing.

1. **Vocab v6.** Add the two predicates with `verification_class: observation`. Bump the active vocab.
2. **Checkpoint type and signing.** New file `internal/checkpoint/checkpoint.go` defining the envelope shape, canonicalisation, signing, content-hashing. Mirrors `internal/assertion/identity.go` in shape.
3. **`origin checkpoint` subcommand.** New package `internal/checkpoint/run.go`. Reads chain head, signs a Checkpoint, writes raw evidence under `data/raw/origin.checkpoint/`, outputs the file to `--output`.
4. **`origin record-anchor` subcommand.** New package `internal/anchor/run.go`. Reads a checkpoint IRI, a provider entry IRI, and the provider response file. Stores the response as raw evidence under `data/raw/<provider>.anchor/`. Emits an `transparency_log_records_checkpoint` identity and an observer-role occurrence.
5. **Verify check #13.** Walks anchor identities; resolves their subjects to checkpoints; cross-references chain state; reports `OK`, `TAMPER`, `TRUNCATED`, or `MISSING_LOG`.
6. **Projection schema additions.** A new table `transparency_log_records_checkpoint` keyed on identity_id with subject/object/etc.; projector dispatch updated; snapshot builder dispatch updated.
7. **Fixture additions.** Extend `protocol/v0-fixtures/gen.go` and `anchor_test.go`. Synthetic `fakelog:fixture` provider URIs. Byte-equality tests.
8. **Spec revision.** Append a new section to `protocol/origin-protocol-v0.md` introducing the anchor identities and the new verify check OR cut `origin-protocol-v0.1.md` if the change feels like a v1 boundary. Decide during implementation; default to v0.x revision since this is purely additive.
9. **Two-node anchor demonstration.** Extend the federation fixture so peer-B has an anchor; importing produces a local row in `transparency_log_records_checkpoint`; verify still passes.
10. **End-to-end demo.** Run the full `origin demo` flow including a checkpoint-and-anchor step. Verify the resulting tarball still replays cleanly.

Estimated incremental surface: ~600-800 lines of Go plus the fixture data. No new external dependencies. No network code.

---

## 13. Explicit non-goals (Phase 5)

- No network code. No HTTP. No Rekor SDK integration. The CLI surface only handles already-fetched evidence.
- No verification-class predicates. No inclusion-proof verification. No tree-head signature verification.
- No new policies that consume anchor predicates.
- No automation of "submit checkpoint to provider X." The operator handles submission out-of-band.
- No consensus semantics. Multiple anchors do not vote, agree, or produce derived facts.
- No anchor freshness policies. "How old is your most recent anchor" is not enforced.
- No anchor coverage policies. "Did you anchor every Nth checkpoint" is not enforced.
- No anchor revocation, replacement, or supersession. Anchors are append-only like everything else.
- No protocol-version bump. The protocol gains additive predicates and one verify check; the existing fixtures are unchanged.
- No UI changes. The HTML report MAY surface anchor identities (they show up automatically in the identities table), but no special "anchored" badge is introduced.

---

## 14. The role of policies (reserved for Phase 5+)

Phase 5 introduces vocabulary and structural support for anchors. It deliberately does NOT introduce policies that consume anchor predicates. A future policy author might write:

```
release_signing/v3:
  - trusted requires: verified-form signature AND
                      (an anchor identity exists for the chain head at
                       evaluation time OR an anchor identity exists for
                       a chain head whose seq is at most N less than
                       the current head)
```

That policy is a Phase-6 concern. Its author must answer:

- What kind of anchor counts? Local only? Federated allowed? Specific providers?
- How fresh must the anchor be?
- What happens when no anchor exists?

These are policy questions, not protocol questions. Phase 5 leaves them open and provides the evidence shape needed to answer them.

---

## 15. The thing this phase does NOT do

This must be said plainly because the temptation to slip will be real:

Phase 5 does not make Origin "more trusted." It does not produce a number. It does not give anyone a badge. It does not tell you whether a package is safe.

It produces ONE new kind of observation: "we recorded our submission of a checkpoint to an external system at a moment in time, and here is what the system returned."

Every other property a transparency log might seem to offer — authority, consensus, accuracy of timestamps, agreement among observers, broad publication — is a property of the system you submit to, not of Origin. Origin records what it observed. That is the whole contribution.

A reviewer reading the Phase 5 implementation diff who finds anything that crosses this line — anything that consumes anchors as authority, anything that scores based on anchor counts, anything that automatically promotes peer anchor reports — has found a bug. The phase is structurally correct only insofar as none of those things exist in the diff.

---

## 16. Closing test

Phase 5 is correct if and only if a hostile reader can answer these from on-disk artefacts:

1. **Is this checkpoint anchored?** → Query `transparency_log_records_checkpoint` for the matching subject IRI. Yes/no.
2. **Where was it anchored?** → The `object` IRI names the provider and the entry. The provider's bytes are in `data/raw/<provider>.anchor/`.
3. **Was it I or a peer who recorded the anchor?** → Join to the occurrences table on identity_id; inspect `log_id` and `attestor_role`.
4. **Has the chain been modified since anchoring?** → Verify check #13. `OK` means no detected modification; `TAMPER` / `TRUNCATED` means yes.
5. **Did anchoring change any claim's verdict?** → No, by construction. Claim IDs are stable across anchor additions; policies that don't consume anchor predicates produce identical claims pre- and post-anchor. Demonstrable via `origin verify` reproducing the same claim ID before and after.
6. **Is anchoring authoritative?** → No. The predicate name (`transparency_log_records_checkpoint`) is observation-class; the description in vocab v6 says so explicitly; policies do not consume it as authority; the audit trail makes the source visible.

If any answer requires inference from the source code beyond version metadata, the phase has drifted.

---

## 17. Phase 5+ candidates that build on this

After Phase 5:

- **Phase 5.5 — inclusion-proof verification.** Adds `cryptographically_verified_inclusion_in_log` (verification class). Implements local verification of provider inclusion proofs against pinned tree-head keys. Adds verify check #14.
- **Phase 5.6 — anchor equivocation detection.** Strengthens verify check #13: same `(log_id, seq)` across multiple anchor identities must agree on `chain_hash`. Catches local equivocation.
- **Phase 6 — policy authoring against anchor predicates.** `release_signing/v3` or similar that consumes anchor evidence as one input among many.
- **Phase 6.x — witness anchoring.** Multiple transparency logs anchoring the same checkpoint; "witness diversity" as an observation.

None of these are Phase 5 work. They are listed only to confirm Phase 5 is a foundation, not a one-off.

---

## Coda

Phase 5 is small on purpose. Done correctly, the system gains stronger external tamper-evidence while remaining locally verifiable, offline-replayable, federation-clean, and free of authority semantics. Done incorrectly — by introducing a single verification-class anchor predicate, or by letting a policy consume anchors as authority, or by treating multiple-provider anchors as consensus — the system gets a trust-laundering surface that Phase 1-4 spent five iterations preventing.

The implementation diff should be small (~600-800 LOC). The auditable property should be visible from the spec: there is exactly one new kind of observation, classified honestly, that strengthens an existing audit story without inflating any claim.

If during implementation a section feels ambitious, the design has drifted. Return to this document and find the line that says "Phase 5 deliberately does not do X" — almost certainly the right move is to honour it.
