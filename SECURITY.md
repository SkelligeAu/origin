# Security Policy

Origin is early protocol software. The v0 specification is frozen pending external review; the reference implementation has not yet been through independent security audit. Findings — particularly semantic and structural — are welcome.

## What is in scope

The following are all in-scope security concerns and we want to hear about them:

- **Protocol invariant violations.** If you can construct on-disk state that passes all 13 verify checks but violates one of the invariants in [`docs/invariants.md`](docs/invariants.md), that is a finding. The most valuable ones target the no-laundering rule, verification locality, and replay determinism.
- **Canonicalisation drift.** If the implementation's JCS output differs from the protocol spec's stated canonical encoding for any v0-fixture input, that is a finding.
- **Trust-laundering paths.** Any code path through which a peer's verification-class claim becomes part of the local verification-class table is a critical finding.
- **Identity forgery.** Any way to make a forged Identity or Occurrence pass content-addressing and signature verification.
- **Replay non-determinism.** Any input that causes two `origin verify` runs on the same archive to disagree.
- **Federation boundary bypass.** Any way to import a foreign log such that the no-laundering check passes but a verified-form predicate has crossed the boundary.
- **Anchor laundering.** Any way to make an external transparency-log claim count as local verification.
- **Specification ambiguity.** If the spec admits two reasonable implementations that disagree on byte output, that is a defect we want to fix in v1.

## What is out of scope

- **External attestation source compromise.** If npm, OSV, or Sigstore publishes false data, Origin records the false data faithfully. That is a property of the external source, not of Origin. Independent corroboration across sources is a policy concern.
- **Operator key compromise.** If a signing key is compromised, the operator must rotate it. Origin does not detect compromise.
- **Verifier library bugs.** If a vendored library (e.g. `sigstore-go`) has a verification bug, that is upstream's responsibility. We track the dependency and ship updates.
- **Performance.** Origin is not yet performance-tuned. Slow paths are not security issues unless they enable a different attack.
- **Operational mistakes.** If an operator commits private keys to git, includes `data/` in a public archive, or runs Origin in a hostile environment without sandboxing — those are operator concerns. The project provides `.gitignore`, fixture-only test keys, and clearly-named "do not commit" paths to make accidents harder, but cannot prevent them.

## Reporting a vulnerability

For non-trivial findings — anything affecting the protocol, the canonicalisation, or the verify checks — please report privately first. Two channels:

**Primary channel — GitHub private vulnerability reporting.**
Visit https://github.com/SkelligeAu/origin/security/advisories and click *Report a vulnerability*. GitHub will walk you through a short form and route the report directly to the maintainer with a structured workflow for triage, embargo, and (if appropriate) CVE assignment.

**Fallback channel — email.**
`matt@skellige.com.au`. Use this if you do not have a GitHub account or prefer email. The address reaches the same maintainer; reports submitted by either channel are treated equivalently.

Include:

1. A concrete reproduction (ideally as a test case or a small archive).
2. Which invariant or check the finding violates.
3. Whether the issue is in the spec, the reference implementation, or both.
4. Your name or handle for credit (or "anonymous" if preferred).

We will acknowledge receipt within a reasonable window, work with you on disclosure timing, and credit the finding in the release notes once a fix or spec revision lands.

For obvious bugs that do not touch the protocol invariants (e.g. a CLI usage typo), a GitHub issue or pull request is fine.

## No bug bounty

There is no monetary bounty programme at this stage. Credit and acknowledgement are what we can offer.

## Disclosure preferences

We prefer coordinated disclosure for protocol-level findings: report, allow time for a fix or spec revision, public disclosure once the fix is in a released version.

For findings that are already public (e.g. via an academic paper or a tweet), we will address them publicly with no embargo.

## Cryptographic primitives and trust roots

Origin relies on Ed25519 (RFC 8032), SHA-256, and JCS (RFC 8785). It pins the Sigstore public-good trusted root in source (`internal/sigstore/trusted_root_public_good.json`). Live fetching of trust roots is prohibited by the protocol; if you find code that does so, that is a finding.

Future versions may add inclusion-proof verification (Phase 5.5) with pinned tree-head verification keys. Same rule: pinned in source, never fetched at runtime.

## Versioning of fixes

Security fixes that do not change canonical encoding land in the reference implementation without a protocol version bump. Fixes that change canonical encoding require a protocol revision (v0 → v1). Both kinds are noted in release notes.
