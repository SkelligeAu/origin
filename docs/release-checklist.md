# Release Checklist

Pre-release verification steps. Every public release must pass every item, in order.

If any check fails, fix the cause and restart from the top. Skipping items is not an option.

## 1. Code health

- [ ] `go build ./...` succeeds with no warnings.
- [ ] `go vet ./...` is clean.
- [ ] `go test ./...` passes locally on a fresh checkout (no cached state).

## 2. Fixture byte-equality

- [ ] `go test ./protocol/v0-fixtures/` passes all subtests:
  - [ ] `TestIdentityFixture/{observation, verified, peer_reports}`
  - [ ] `TestOccurrenceFixture/{observer, federated_importer}`
  - [ ] `TestClaimFixture`
  - [ ] `TestRawEvidenceFixture`
  - [ ] `TestKeyDeterminism`
  - [ ] `TestFixtureLayout`
  - [ ] `TestFederation_RewriteRule`
  - [ ] `TestAnchorFixture/{checkpoint, provider_response, anchor_identity}`
  - [ ] `TestAnchorVocabClass`
- [ ] If any fixture was regenerated for this release, the regeneration is in this PR with a clear rationale.

## 3. End-to-end demo

- [ ] `./origin demo 'pkg:npm/@sigstore/sign@2.3.2' --output ./out` succeeds.
- [ ] The resulting tarball unpacks cleanly into a fresh directory.
- [ ] `cd <unpacked-dir> && origin verify` passes all 13 checks.
- [ ] Opening `data/reports/*.html` in a browser shows verification-class tags on identity rows and a working "How to verify this report" section.
- [ ] The tarball does NOT include any private keys other than the per-demo signing key documented inside `data/keys/`.

## 4. Tamper-evidence sanity

- [ ] Tamper one byte of one chain.log entry in the unpacked demo. Re-run `origin verify`. Confirm at least three checks fail (typically: occurrence signatures, chain integrity, projection determinism, anchor integrity).
- [ ] Restore. Re-run verify. All 13 pass.
- [ ] If Phase-5 anchors are present: truncate chain.log below the anchored seq. Confirm check #13 reports `TRUNCATED`.
- [ ] Restore. Re-run verify. All 13 pass.

## 5. Protocol and spec review

- [ ] If `protocol/origin-protocol-v0.md` changed: changes are erratum-level (typo, clarification) only. Substantive changes require v1 + a separate PR + spec-reviewer sign-off.
- [ ] If a new vocabulary version was added (`vocab/v<N+1>.json`): the new file is a strict superset of the prior; description fields are honest about what the predicate records; `verification_class` values are correct.
- [ ] If a new verification-class predicate exists: a verifier exists in the same change; a hermetic test fixture exists; no path emits the predicate without the verifier succeeding.
- [ ] If a new policy version exists: the prior version remains in place (immutability); the new version is in its own directory; tests cover every verdict reachable by the new policy.

## 6. Repository hygiene

- [ ] `.gitignore` is present and includes `data/`, `*.tar.gz`, `origin` binary, `.DS_Store`.
- [ ] `git status --ignored` shows the expected ignored set; nothing important was accidentally caught.
- [ ] No files matching `*.ed25519` are tracked except `protocol/v0-fixtures/keys/test-signer.ed25519` (the documented test key).
- [ ] No personal data, credentials, or local environment leakage in any tracked file.
- [ ] No compiled binaries committed.
- [ ] No editor backups, OS junk (`.DS_Store`, `Thumbs.db`), or scratch files.
- [ ] No commits with "AI-assistant co-author" trailers or similar artefacts.

## 7. Documentation review

- [ ] `README.md` quickstart works on a clean clone (`go build` → `ingest` → `project` → `eval` → `verify`).
- [ ] `docs/invariants.md` matches the active enforcement mechanisms (no claimed invariant is silently unenforced).
- [ ] `docs/architecture.md` matches the current module layout under `internal/`.
- [ ] `docs/threat-model.md` mentions any threat first surfaced during this release.
- [ ] `SECURITY.md` contact placeholder is replaced with a real reporting address.
- [ ] `CONTRIBUTING.md` constraints match what the codebase enforces (no aspirational rules).
- [ ] `LICENSE` is populated with an actual license, not the placeholder.

## 8. External dependencies

- [ ] `go.mod` has been reviewed; no dependency added since last release without rationale in commit history.
- [ ] `go.sum` is in sync (`go mod tidy` produces no changes).
- [ ] No dependency on a non-vendored trust root, transparency client, or network library beyond stdlib `net/http`.

## 9. Phase status

- [ ] `memory/archive/README.md` table reflects which phases are complete in this release.
- [ ] Any new phase document landing in this release is in `memory/archive/` (it is historical the moment the work is done).

## 10. Final verification

- [ ] Run the full demo flow on a machine without prior project context (fresh clone, no `data/`, no cached Go modules).
- [ ] Read `README.md` from the perspective of someone who has never seen the project. If a sentence is unclear, fix it.
- [ ] Confirm that opening `protocol/origin-protocol-v0.md` and `docs/invariants.md` side-by-side gives a complete picture of what the system claims to do.

## Notes for tagged releases

When tagging a release:

- Use semantic versioning starting at `v0.1.0`.
- The tag message references the v0 protocol version (e.g., "Origin v0.1.0 — protocol v0").
- Pre-1.0 releases may break the v0 protocol; if so, the change is a v1 bump and the spec must be updated.
- Release notes link to the merged PR list, the threat-model changes (if any), and the fixture regeneration (if any).
