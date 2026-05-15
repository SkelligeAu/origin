# Contributing to Origin

Origin is a protocol project before it is a software project. Contributions are welcome and the bar is high. Some categories of contribution are explicitly out of scope.

## Read before contributing

- [`README.md`](README.md) — what Origin is and is not.
- [`docs/invariants.md`](docs/invariants.md) — the rules.
- [`docs/epistemic-model.v1.md`](docs/epistemic-model.v1.md) — the formal model.
- [`protocol/origin-protocol-v0.md`](protocol/origin-protocol-v0.md) — the normative spec.
- [`docs/threat-model.md`](docs/threat-model.md) — what we defend against and what we do not.

If you have not skimmed those, the rest of this document will not make sense.

## What we want

- **Bug reports and reproductions.** A small failing test is the best gift. Aim it at a specific invariant or verify check.
- **Spec clarifications.** If two reasonable implementers would interpret a spec line differently, the spec is wrong; propose a clarification.
- **Fixture coverage.** Adversarial test cases — especially around the federation rewrite rule, anchor integrity, and the no-laundering check — are extremely welcome.
- **Performance work** in non-load-bearing code paths (JSON parsing, projection rebuilds, etc.) is fine. Performance work on canonicalisation or signing requires a fixture-equality before-and-after.
- **Independent implementations** of v0 conformant against the fixtures. We would like there to be more than one Origin.
- **Documentation tightening.** Plain prose, technical, precise, sceptical. Nothing aspirational that the code does not deliver.

## What we do not want

These are categorical rejections, not "let's discuss":

- **Numeric trust scores.** Verdicts are categorical (`trusted`, `conditional`, `rejected`, `insufficient_evidence`). No "trust 0–100", no "confidence percentage". This is non-negotiable.
- **Machine-learning inference in the trust path.** Embeddings, similarity ranking, "this looks like that". Not here.
- **Runtime trust-root fetching.** Trust roots are pinned in source code. Any PR that fetches one at startup, refreshes via TUF at runtime, or otherwise softens the pinning will be closed.
- **Silent canonicalisation changes.** Any change to JCS-output, hash construction, or signature scheme requires a protocol version bump (v0 → v1) plus fixture regeneration plus reviewer sign-off. No exceptions.
- **Verification-class predicates without a verifier.** A predicate's `verification_class` of `verification` is a claim that the implementation runs a procedure. If there is no procedure, the predicate is observation-class instead.
- **Federation paths that bypass the rewrite rule.** The boundary rewrite is the line between federation and laundering. Code that ingests a peer's `verification`-class identity into the local verification table will be rejected.
- **Hosted-service patterns.** No HTTP server, no SaaS hooks, no cluster semantics in this repo. The CLI is the interface.
- **"AI-platform" framing in documentation.** Origin is a provenance compiler. Doc PRs that frame it as a trust-AI product will be closed.

## Protocol changes

Anything that changes byte-equality against `protocol/v0-fixtures/` is a protocol change. The process is:

1. Open an issue describing the change and the motivating concrete need.
2. Draft a spec revision (`protocol/origin-protocol-v1.md` if substantive, or a numbered erratum if clarifying).
3. Update fixtures via `cd protocol/v0-fixtures && go run gen.go` and commit the regenerated artefacts.
4. Update the fixture tests so they re-pass on the new artefacts.
5. Update `CONTRIBUTING.md` and `docs/release-checklist.md` if the change affects the contributor workflow.
6. Reviewer sign-off from at least one other contributor familiar with the protocol.

For changes that only add a new predicate or a new verifier without altering existing canonical encodings, fixture regeneration is not required; the additive predicate's own fixture lands alongside.

## New predicates

When proposing a new predicate in the vocabulary:

1. Decide the `verification_class`: `observation`, `verification`, `refutation`, or `structural`. The wrong choice is a structural bug.
2. Write the predicate's `description` field carefully. The description is normative; it is read by future contributors and external reviewers. State what *was observed* (for observation-class) or what *was executed* (for verification-class).
3. Name the predicate to match what it actually records. `<source>_reports_X` for observation, `cryptographically_verified_X` (or similar) for verification. Names that imply more than the code does are a structural bug.
4. If the predicate is in the verification or refutation class, ship the verifier in the same change set. Land observation-class predicates alone is fine; land verification-class predicates without their verifier is not.
5. Add a fixture under `protocol/v0-fixtures/` exercising the predicate.
6. If federation matters, add or extend `peer_reports_*` rewrite handling.

## New policies

Policies live under `policies/<id>/<version>/`. Each version is immutable; revisions ship as new directories (`v1`, `v2`, ...).

When proposing a new policy or policy version:

1. State the question the policy answers. One sentence.
2. Declare `required_predicates` and `required_raw_sources` in the manifest.
3. Use only the four allowed verdicts.
4. Use enumerated qualifiers; document them in the policy's package comment.
5. Add an end-to-end test demonstrating each verdict against constructed snapshot inputs.
6. Confirm `release_signing/v2` and `dependency_hygiene/v1` still produce byte-identical claim IDs on unrelated subjects (no regressions to existing policies).

## New ecosystems or normalizers

Adding a new ecosystem (PyPI, Maven, etc.) requires:

1. A new ingest connector under `internal/ingest/<source>.go`.
2. A new normalizer with a versioned identifier (`<source>-<form>@v0.1.0`).
3. The connector emits raw evidence verbatim under a new `source` namespace.
4. The normalizer produces only predicates whose names match what was observed.
5. End-to-end tests against at least one real package, with the chosen package documented in the test's `// Package known to publish provenance` comment.
6. Notes in the spec under §7.4 (Vocabulary integrity) if any predicate-class assumptions need to be revised.

## Style

- Go: standard `gofmt`. Names should describe what the value is, not why it exists.
- Comments explain WHY, not WHAT, except for canonicalisation procedures where exact byte behaviour matters.
- Documentation: tight prose. Avoid filler. Avoid marketing voice.
- Commit messages: subject line `area: short imperative description`. Body explains WHY.
- Do not include AI-assistant co-author trailers in commits or doc bylines. Contributions are by their human authors.

## Pull request checklist

Before opening a PR:

- [ ] `go test ./...` passes locally.
- [ ] `go build ./...` succeeds with no warnings.
- [ ] `./origin verify` passes on a representative archive (your own `data/` directory after a fresh `ingest`+`project`+`eval`).
- [ ] Fixture self-tests pass (`go test ./protocol/v0-fixtures/`).
- [ ] If you added a predicate, the vocab description states the verification class plainly.
- [ ] If you touched canonicalisation, the fixture is regenerated and the regeneration is in the same PR.
- [ ] If you touched federation, you have a test exercising the boundary rule.
- [ ] No new dependencies without rationale in the PR description.
- [ ] No commits to `data/`, no commits of private keys (other than the test signer documented in `protocol/v0-fixtures/keys/`).

## Where to start

- Look for `// TODO(phase-N+1)` comments in source.
- The threat model documents specific deferred concerns; each is a candidate task.
- Independent implementations of the protocol in other languages are highly welcome.
