# Phase 4 Plan: Origin Protocol Spec + Public Demo Surface

> **Phase 4 thesis.** Five phases have established the semantics: append-only signed assertions, content-addressed identity, deterministic projection, policy-derived claims, cryptographic verification with locality, filesystem federation without laundering. The semantics now do real work. Adding capability surface from here risks codifying soft edges before they harden. Phase 4 freezes what exists: a normative protocol specification, an interoperability fixture other implementations can validate against, and a single polished public artifact — a paste-a-package-get-a-report flow — that surfaces the protocol's invariants rather than hiding them.

The shift is from "does it work?" to "could another implementation be measured against this?" External review is now the highest-leverage next step. No new ecosystems. No new verifiers. No new policies. No SaaS, no API, no hosted service. The public demo is a CLI command that produces a self-contained artifact — viewable offline, verifiable cryptographically by anyone with `origin`.

---

## 1. Scope (in / out)

**In scope:**
- A normative document `protocol/origin-protocol-v0.md` checked into the repository. Versioned. Future revisions are new files (`v1.md`, etc.), never silent edits.
- Authoritative envelope schemas for Identity, Occurrence, TrustClaim, RawEvidence, and the projection MANIFEST — with field types, validation rules, canonicalization rules, and example values.
- Authoritative statement of the four verification classes (observation, verification, refutation, structural) and the rules that bind them.
- Authoritative statement of the federation rewrite rule (Phase 3.5 §1) and the no-laundering invariant (manifesto #16).
- Authoritative statement of canonicalization (RFC 8785), hashing (SHA-256), signature (Ed25519), and chain construction.
- A test-fixture directory `protocol/v0-fixtures/` containing: a canonical Identity envelope and its expected ID; a canonical Occurrence and its expected ID + signature against a published test key; a sample raw evidence record with its content hash; a sample TrustClaim and its expected ID under the canonical bytes excluded list; a two-node federation archive (peer A's data + peer B's data + the expected post-import projection state). Any conforming implementation can re-run JCS + SHA-256 against the fixture and confirm byte-equality.
- A new CLI subcommand `origin demo <github-url>` that runs ingest → project → eval → verify → report, then bundles the resulting `data/` directory plus the HTML report into a single shareable tarball `origin-demo-<subject>-<timestamp>.tar.gz`. Recipients with the `origin` binary can run `origin verify` on the unpacked archive and reproduce every claim.
- A polished static HTML report (`origin report`) that surfaces the protocol concepts — identities deduplicated, occurrences citing them, verification class of each predicate visible, federation status visible, every claim clickable down to canonical bytes on disk.

**Out of scope (explicit non-goals):**
- No new ecosystems. Still npm only.
- No new policies, no policy revisions.
- No new verifiers.
- No new connectors.
- No hosted service. No HTTP server. No web app. No SaaS. The "public demo surface" is a CLI command producing a portable artifact.
- No protocol versioning beyond v0. Phase 4 ships v0; v1 is whenever a substantive change requires it, governed by the same revision discipline as `epistemic-model.v1.md`.
- No JSON Schema generators. Schemas in the spec are hand-written and verified against the fixture; we are NOT shipping a tooling chain.
- No marketing language in the spec or the demo. The spec is engineering-prose. The demo surfaces evidence, not opinion.
- No "share to social" features. The tarball IS the share format.

---

## 2. Protocol spec document structure

`protocol/origin-protocol-v0.md` is normative. Its structure:

```
§0   Notation and conformance terms (MUST, SHOULD, MAY per RFC 2119)
§1   Terms
§2   Document conventions (canonical JSON, time, hashing)
§3   Envelope: Identity
       — field set, types, validation rules
       — canonical encoding
       — ID computation
       — example with expected hash
§4   Envelope: Occurrence
       — field set, attestor_role enumeration
       — canonical encoding (excluded fields enumerated)
       — ID computation
       — signature scheme
       — chain hash construction
       — example with expected hash and signature
§5   Envelope: TrustClaim
       — field set
       — canonical bytes — explicit list of excluded fields
       — ID computation
       — example
§6   Raw evidence records
       — metadata sidecar shape
       — content addressing rule for payload bytes
§7   Predicate vocabulary
       — versioning rules (additive only; new file per version)
       — verification_class enumeration (the four classes)
       — predicate naming conventions (observation vs verification vs refutation)
       — observation reporters use <source>_reports_X
       — verified-form uses cryptographically_verified_X (and any future family)
       — refutation form: <verifier>_<failed>_<X>
§8   Identity store
       — content-addressable; idempotent writes
       — supersession via revises
§9   Occurrence log
       — per-log-id chains
       — chain.log line format
       — append-only constraint
§10  Federation
       — peer-key registry shape
       — foreign log archive layout
       — import boundary procedure (verbatim from layer-3.5.md §3)
       — the rewrite rule for verification/refutation class
       — peer_reports_* observation predicates
§11  Policy execution
       — pure-function model
       — closed verdict enum {trusted, conditional, rejected, insufficient_evidence}
       — derivation DAG shape
§12  The verify procedure
       — the twelve checks enumerated; each one normative
§13  Conformance
       — what makes an implementation Origin-Protocol-v0-conformant
       — required fixture-byte-equality
       — optional vs mandatory features
§14  Test fixtures
       — location and format
       — how to use them
§15  Security considerations
       — root-of-trust pinning
       — invariant 16 (verification locality)
       — adversarial models (peer compromise, registry compromise, etc.)
§16  Acknowledged limitations
       — points at memory/epistemic-model.v1.md §11 (open questions)
```

The spec lives in `protocol/` not `memory/` because it is a deliverable, not a working memory artifact. Memory continues to hold project state; the protocol is now versioned engineering output.

---

## 3. Interoperability fixture

A directory at `protocol/v0-fixtures/` containing exactly the bytes an external implementation must be able to reproduce:

```
protocol/v0-fixtures/
├── README.md                           how to use these fixtures
├── identity/
│   ├── observation.json                 sample observation-class identity
│   ├── observation.expected-id          expected sha256 of canonical bytes
│   ├── observation.canonical-bytes      the literal RFC 8785 bytes
│   ├── verified.json                    sample verification-class identity
│   ├── verified.expected-id
│   └── verified.canonical-bytes
├── occurrence/
│   ├── observer.json                    sample observer-role occurrence
│   ├── observer.expected-id
│   ├── observer.canonical-bytes
│   ├── observer.expected-signature      signature with the published test key
│   ├── federated_importer.json
│   ├── federated_importer.expected-id
│   ├── federated_importer.expected-signature
├── claim/
│   ├── sample.json                      a TrustClaim
│   ├── sample.canonical-bytes           bytes after excluding evaluated_at,
│   │                                    projection_manifest_hash,
│   │                                    identities_hash,
│   │                                    occurrences_cited
│   └── sample.expected-id
├── raw-evidence/
│   ├── npm-record.bin                   verbatim npm registry response
│   ├── npm-record.expected-hash         sha256 of the bytes
├── federation/
│   ├── peer-a/data/...                  full ingestor-A archive
│   ├── peer-b/data/...                  full ingestor-B archive
│   ├── post-import/identities_hash      expected after A imports B
│   ├── post-import/claim-id             expected claim ID after import
│   └── post-import/verify-output.txt    expected `origin verify` output
├── keys/
│   ├── test-signer.pub                  published test signing key
│   └── test-signer.ed25519              private key for fixture generation
```

The fixture is hermetic — no network access required to validate. Implementations can run their canonicalizer over `observation.json`, compare to `observation.canonical-bytes` byte-for-byte, hash, compare to `observation.expected-id`.

For federation, the fixture provides a CONSTRUCTED two-node scenario rather than relying on live npm/Sigstore data, because live data drifts. The peer-a and peer-b archives are checked into git as immutable snapshots.

---

## 4. Public demo surface

A single new CLI subcommand:

```
origin demo <github-url|pkg:npm/...> [--output <dir>]
```

Behaviour:
1. Run `origin ingest <url>`.
2. Run `origin project`.
3. Run `origin eval <subject> --policy release_signing`.
4. Run `origin eval <subject> --policy dependency_hygiene`.
5. Run `origin verify`.
6. Run `origin report <subject>` (the existing HTML generator, polished).
7. Bundle the `data/` directory plus the report plus a copy of the protocol spec into `<output>/origin-demo-<short-subject>-<timestamp>.tar.gz`. Default output is the current directory.

The tarball is the share format. Anyone with the `origin` binary can `tar -xzf` it and run `origin verify` against the unpacked tree to confirm cryptographic integrity end-to-end. The HTML report works offline.

The HTML report itself is polished, NOT redesigned. Phase 1's report had the right shape; Phase 4 makes it presentation-ready:
- Surface the verification class of each predicate (observation / verification / refutation / structural).
- Visibly distinguish locally-verified identities from peer-reported ones (when imports exist).
- Click-through from any claim to its derivation DAG (already present); from any derivation node to the canonical evidence file on disk (already present).
- A "How to verify this report" section embedded in the HTML, with the exact command and expected output.
- Link to the protocol spec.

No new dependencies. No JavaScript framework. Static HTML, monospace where appropriate, the same CSS the existing report uses — refined where it helps readability.

---

## 5. Falsifiable success criteria

| # | Criterion | Test |
|---|---|---|
| 1 | Protocol spec exists and is normative. | `protocol/origin-protocol-v0.md` is in the repo; its §3-§12 cite specific Go types as informative-only references but state behaviour abstractly. A reader who knows JCS + Ed25519 + SHA-256 can re-implement the canonicalization and ID computation from §3-§5 alone. |
| 2 | Fixture bytes are reproducible. | Running the existing `origin` binary against the fixture inputs produces the documented expected IDs and signatures. A small test harness in `protocol/v0-fixtures/test.go` walks every fixture file and asserts byte-equality. |
| 3 | Two-node federation fixture round-trips. | A test imports `peer-b` into a fresh data directory seeded by `peer-a`, runs verify, and confirms post-import identities_hash + claim ID match `post-import/*` literally. |
| 4 | Demo command produces a portable artifact. | `origin demo pkg:npm/@sigstore/sign@2.3.2 --output /tmp` writes a tarball; unpacking it in a fresh directory and running `origin verify` on the unpacked tree passes all 12 checks. |
| 5 | Polished report surfaces verification class. | Inspecting the generated HTML for `@sigstore/sign@2.3.2` shows: which identities are verification-class (one row), which are observation-class (the rest), which (if any) are peer-reported, all clickable down to disk. |
| 6 | No new ecosystem, verifier, policy, or service. | `git diff` between the start and end of Phase 4 touches only: the protocol document, fixtures, the demo subcommand, the report renderer, and minor refactors. No new sources, normalizers, verifiers, policies, or network surfaces. |
| 7 | Conformance check exists. | The protocol spec's §13 lists exactly the byte-equality requirements that make an implementation conformant. A new implementation could be tested against the fixture without contacting any origin-affiliated party. |

---

## 6. Sequence of work

1. **Author `protocol/origin-protocol-v0.md`.** First draft from a careful read of `memory/epistemic-model.v1.md`, `memory/layer-1.md` through `memory/layer-3.5.md`, and the implementation. Aim for ~1500-2500 lines, normative tone, RFC-style.
2. **Generate fixtures.** Write a small Go test program that:
   - Produces the canonical bytes for each fixture envelope.
   - Hashes them.
   - Signs the occurrence fixtures with a vendored test signing key.
   - Writes everything into `protocol/v0-fixtures/`.
   - The test key's PRIVATE key is committed to the repo (this is a test key, not a real signing key); explicitly documented as such.
3. **Fixture self-test.** Add `protocol/v0-fixtures/fixtures_test.go` that re-derives the IDs and signatures and asserts byte-equality. This runs on every `go test ./...`.
4. **Construct the two-node federation fixture.** Take the two real ingestor-A/B archives (already exist on disk from Phase 3.5), strip them down to a minimal reproducible subset, freeze them under `protocol/v0-fixtures/federation/`. The constructed peer-b key is replaced with the fixture test key (re-signing the foreign occurrences). Record the expected post-import outputs.
5. **`origin demo` subcommand.** New file `internal/demo/run.go`. Calls into existing ingest/project/eval/verify/report subcommands. Bundles results. The "embed protocol spec" step copies `protocol/origin-protocol-v0.md` into the tarball at `protocol/origin-protocol-v0.md`.
6. **Report polish.** `internal/report/run.go`: surface `verification_class` next to each identity row; group occurrences by attestor_role; add a "How to verify" section with copy-paste commands; link to the protocol spec at the relative path within the tarball.
7. **End-to-end demo on a real package.** Run `origin demo pkg:npm/@sigstore/sign@2.3.2`; unpack the tarball; run `origin verify`; open the HTML; confirm Criterion 5 is visibly satisfied.
8. **Public-facing README change** (optional, can defer to a Phase 4.5): rewrite the repo's top-level README to lead with the protocol spec and the demo command, not the implementation tour. The README change is small and non-load-bearing; defer if Phase 4 scope already feels full.

---

## 7. Risks discovered ahead of implementation

- **Spec/implementation drift.** Writing the spec from the current implementation makes it accurate today. Future implementation changes that don't update the spec will silently invalidate the spec. Mitigation: the fixture self-test (§5.2) is the safety net — any implementation change that breaks fixture byte-equality breaks CI, forcing a spec update or a deliberate revision (v1).
- **Fixture obsolescence.** The federation fixture uses a constructed two-node scenario rather than live npm data, but the protocol's behaviour against live data is what users want assurance about. Mitigation: the demo command (§4) operates on live data; the fixture proves the algorithm; the demo proves the algorithm on real inputs.
- **Tarball portability.** Tarball contains absolute paths under `data/raw/...` etc. that are recreated relative to the unpack location. The `origin verify` command must resolve everything relative to its working directory (it already does for Phase 1-3.5; confirmed in implementation).
- **Spec scope creep.** A protocol spec invites the temptation to specify behaviour the implementation hasn't yet committed to. Mitigation: §0 of the spec MUST state that v0 specifies ONLY what is implemented as of Phase 3.5. Anything aspirational lives in `epistemic-model.v1.md` §11 (open questions), not in the protocol.
- **Test key leak confusion.** The fixture private key is checked into the repo. Mitigation: §14 of the spec and the fixtures README both prominently warn "this key is for fixture reproduction only and MUST NOT be used to sign production assertions." The key fingerprint is documented so operators can refuse it at runtime if a future verifier wants to.
- **HTML report aesthetics drag implementation time.** Phase 4 scope tolerates restraint — the report polish is "surface what's structurally present," not "design a UI." If polishing the report takes more than half the phase, the work has drifted.
- **Demo command tarball collision with existing CLI.** The demo command must not interfere with `origin ingest` / `project` / `eval` / `verify` / `report` semantics. It is purely a sequencer over them. No new state. No new files except the tarball output.

---

## 8. Closing test

Phase 4 is correct if and only if:

1. An external party with the protocol document and the test fixture but no access to this repository can:
   - Implement the canonicalization, hashing, and signature procedures.
   - Reproduce the fixture IDs and signatures byte-for-byte.
   - Run the federation fixture's import scenario and produce the documented post-import state.
2. A reader of the spec's §13 (Conformance) can state precisely which behaviours are mandatory and which are optional.
3. A reader of an `origin demo` tarball can:
   - View the HTML report offline and see verification class for every identity, distinguish locally-verified from peer-reported facts, and click through any claim to its on-disk derivation.
   - Run `origin verify` on the unpacked directory and confirm all 12 checks pass.
   - Read the embedded `protocol/origin-protocol-v0.md` and find the rule that governs every observable behaviour in the report.
4. `git diff` from Phase 3.5 to Phase 4 does NOT touch `internal/ingest/`, `internal/sigstore/`, `internal/peerimport/`, `internal/project/projector.go`, or `internal/verify/run.go` except for trivial fixture-wiring. No new ecosystems. No new verifiers. No new policies. No new HTTP code.

If any of these fails, the phase has drifted.

---

## 9. After Phase 4

Possible Phase 5 directions, ordered by structural payoff (not by feature coverage):

1. **Independence semantics.** `epistemic-model.v1.md` §11 flagged this as open. Once `peer_reports_*` predicates are in real use, policies can begin to consume them with explicit independence rules ("at least N independent attestors"). Spec change required; potentially Origin Protocol v1.
2. **Second ecosystem (PyPI).** Replicates the npm pattern sideways. The protocol spec generalises if the verifier abstraction holds; if not, the spec reveals the gap.
3. **Identity entity layer in projection.** Identity is still a string column. Promoting it to a typed entity table enables clustering policies and Phase-6-style identity reasoning. Schema change → projection hash change → migration → Origin Protocol v1.
4. **Transparency-log anchoring of the local chain.** External anchor (Rekor or our own log). Adds an additional verify check and an optional federation primitive.
5. **Policy authoring against `peer_reports_*`.** A new policy that accepts peer reports as weak corroboration of a locally-verified claim. Concrete need: detect cases where multiple peers report failed verifications even when local says trusted.

All of these are additive on a frozen v0 protocol. They are Phase 5+ work, not Phase 4 work.

---

## Coda

Phase 4 is restraint. The temptation after five productive phases is to keep building. The bigger value lives in freezing what works, letting it be reviewed, and producing the smallest possible artifact that lets others verify the system's claims without trusting our description of them.

If by the end of Phase 4 someone can run `origin demo pkg:npm/<some-package>`, share the resulting tarball, and the recipient can run `tar -xzf` + `origin verify` + open the HTML and walk every assertion back to a signed canonical byte sequence — Phase 4 has succeeded. Everything beyond that is Phase 5+.
