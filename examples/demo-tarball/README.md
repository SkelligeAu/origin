# Example: Demo Tarball

End-to-end production and offline verification of an `origin demo` bundle. Demonstrates Phase-4 deliverable §4: a single CLI command producing a portable, offline-verifiable archive.

## Prerequisites

- Origin binary built (`go build -o origin ./cmd/origin` from repo root).
- Network access to npm + Sigstore (only during the `demo` step; verification is offline).

## Step 1 — produce the bundle

From the repo root:

```sh
mkdir -p /tmp/origin-example-out
./origin demo 'pkg:npm/@sigstore/sign@2.3.2' --output /tmp/origin-example-out
```

Expected output (final lines):

```
✓ demo bundle: /tmp/origin-example-out/origin-demo-pkg_npm__at_sigstore_sign_at_2.3.2-<timestamp>.tar.gz
```

The tarball is around 80–120 KB. It contains:

- `data/` — the full canonical state: raw evidence, identity log, occurrence log, projection, claims, signing key.
- `vocab/` — vocabulary versions referenced by the recorded identities.
- `policies/` — the policies that produced the claims.
- `protocol/origin-protocol-v0.md` — the frozen spec, included so the bundle is self-describing.

## Step 2 — share

Copy or send the tarball. No special transport is required; it is bytes.

```sh
ls -lh /tmp/origin-example-out/*.tar.gz
```

## Step 3 — verify offline

On a clean machine (no Origin data, no cached state — only the binary and the tarball):

```sh
mkdir -p /tmp/origin-review
tar -xzf /path/to/origin-demo-*.tar.gz -C /tmp/origin-review
cd /tmp/origin-review
./origin verify       # or `origin verify` if installed on PATH
```

Expected: all 13 checks pass:

```
✓ identity reproducibility: 10 identities reproducibility OK
✓ occurrence signatures: 10 occurrence signatures OK
✓ chain integrity (local log): 10 entries, head=...
✓ identity ↔ occurrence linkage: 10 occurrence→identity links resolved
✓ raw evidence resolvability: 10 evidence references resolved
✓ projection determinism: projection_hash matches (...)
✓ claim envelope consistency: 2 claim envelopes consistent
✓ cryptographic re-verification: 1 verified-form identities re-verified
✓ claim re-derivation determinism: 2 claims re-derived to byte-identical IDs
✓ foreign chain integrity (per peer): no foreign logs
✓ foreign occurrence signatures: no foreign occurrences
✓ no-laundering (federated_importer → observation only): 10 occurrences walked, 0 federated_importer
✓ anchor integrity (chain consistency): no anchors recorded
```

If any check fails, the bundle is invalid. The error message identifies which artefact and why.

## Step 4 — open the report

```sh
open data/reports/*.html        # macOS
xdg-open data/reports/*.html    # Linux
```

The report is self-contained HTML. Inspect:

- Verification class tags per identity (observation / verification / refutation / structural).
- Trust-claim verdicts with qualifier lists (no numeric scores anywhere).
- The "How to verify this report" pre-formatted commands.

## Step 5 — drill into one fact

```sh
./origin why <claim-id>            # full derivation DAG
./origin explain <identity-id>     # one fact + its raw evidence
```

Every line of these outputs links back to a file on disk.

## Tamper check

To convince yourself the verification is real, modify one byte:

```sh
# Tamper one byte inside a chain.log line
python3 - <<'PY'
with open("data/assertions/occurrences/local/chain.log") as f:
    lines = f.readlines()
parts = lines[4].strip().split('\t')
parts[3] = parts[3][:-1] + ('1' if parts[3][-1] != '1' else '2')
lines[4] = '\t'.join(parts) + '\n'
open("data/assertions/occurrences/local/chain.log", "w").writelines(lines)
PY
./origin verify
```

You will see multiple check failures simultaneously: chain integrity, identity ↔ occurrence linkage, projection determinism, no-laundering, and (if anchors are present) anchor integrity. Restore from the original tarball to make verify pass again.

## What this demonstrates

- A single command produces an archive that an unrelated party can independently verify, offline, with no shared trust assumptions beyond the binary itself.
- The same canonical state replays to the same projection, the same claims, and the same verdicts.
- Tampering is detected at multiple layers; no single check is the only line of defence.

For the rules these flows preserve, see [`../../docs/invariants.md`](../../docs/invariants.md).
