# Example: Two-Node Filesystem Federation

End-to-end demonstration of Phase-3.5 filesystem federation. Two Origin nodes (A and B) operate independently with separate signing keys and separate working directories. Node A imports Node B's archive. The no-laundering rule is exercised: B's verification-class identities are rewritten as observation-class `peer_reports_*` predicates in A's local store.

## Why this matters

Without the rewrite, federation would let B's "I verified X" silently become A's "I verified X" — trust laundering, the precise failure mode every existing federated security system suffers. Origin's rewrite is the structural line between safe federation and laundering.

## Prerequisites

- Origin binary built.
- A working directory you do not mind populating: `/tmp/origin-fed-example`.

## Step 1 — set up two independent nodes

```sh
mkdir -p /tmp/origin-fed-example/node-a /tmp/origin-fed-example/node-b
# Copy vocab + policies into each so they can run standalone.
cp -r vocab policies /tmp/origin-fed-example/node-a/
cp -r vocab policies /tmp/origin-fed-example/node-b/
cp ./origin /tmp/origin-fed-example/node-a/
cp ./origin /tmp/origin-fed-example/node-b/
```

Each node gets its own signing key on first run.

## Step 2 — ingest the same package on both nodes

```sh
(cd /tmp/origin-fed-example/node-a && ./origin ingest 'pkg:npm/@sigstore/sign@2.3.2')
(cd /tmp/origin-fed-example/node-b && ./origin ingest 'pkg:npm/@sigstore/sign@2.3.2')
```

Both nodes now have:

- The same Identity IDs (content-addressed; same evidence + same normalizer versions = same hashes).
- DIFFERENT Occurrence IDs (different attestor keys, different chain positions).
- Each has its own verified-form identity (Sigstore provenance verification ran locally on each).

Confirm:

```sh
diff <(cat /tmp/origin-fed-example/node-a/data/assertions/identities/*.jsonl | python3 -c "import json,sys
for l in sys.stdin: print(json.loads(l)['id'])" | sort) \
     <(cat /tmp/origin-fed-example/node-b/data/assertions/identities/*.jsonl | python3 -c "import json,sys
for l in sys.stdin: print(json.loads(l)['id'])" | sort) \
&& echo "✓ identity IDs are byte-identical across nodes"
```

## Step 3 — capture B's signing key

```sh
B_KEY=$(xxd -p /tmp/origin-fed-example/node-b/data/keys/ingestor.pub | tr -d '\n')
B_LOG="log:$(echo -n $B_KEY | xxd -r -p | shasum -a 256 | awk '{print substr($1,1,16)}')"
echo "B's pubkey: $B_KEY"
echo "B's log_id: $B_LOG"
```

## Step 4 — A imports B's archive

```sh
(cd /tmp/origin-fed-example/node-a && \
   ./origin import-occurrences /tmp/origin-fed-example/node-b/data \
     --peer-key $B_KEY \
     --peer-log-id $B_LOG)
```

Expected output includes:

```
→ identities:     10 read
→ occurrences:    10 read
→ observations:   9 imported as-is
→ verifications:  1 rewritten as peer_reports_*
→ local emits:    1 federated_importer occurrences
✓ import complete
```

The single verification — B's `cryptographically_verified_signature_by` — was NOT placed in A's local identity store. Instead a NEW local identity with predicate `peer_reports_cryptographic_verification_of` was created, citing B's foreign identity by ID-as-ref.

## Step 5 — verify the rewrite

```sh
(cd /tmp/origin-fed-example/node-a && ./origin project >/dev/null 2>&1 && \
   sqlite3 data/projections/index.sqlite \
   'SELECT "cryptographically_verified rows:", COUNT(*) FROM cryptographically_verified_signature_by;
    SELECT "peer_reports rows:", COUNT(*) FROM peer_reports_cryptographic_verification_of;')
```

Expected:

```
cryptographically_verified rows:|1     ← A's own verification, unchanged
peer_reports rows:|1                   ← B's verification, rewritten as observation
```

The local verification table is unchanged in count. B's evidence is visible via the observation-class predicate.

## Step 6 — confirm the no-laundering rule structurally

```sh
(cd /tmp/origin-fed-example/node-a && ./origin verify)
```

Expected: all 12 checks pass. Crucially:

```
✓ no-laundering (federated_importer → observation only):
    21 occurrences walked, 1 federated_importer (all observation/structural)
```

The single `federated_importer`-role occurrence cites an observation-class predicate (`peer_reports_*`). If a future change accidentally lets a verification-class predicate slip through, this check fails.

## Step 7 — confirm claim stability

```sh
# Re-evaluate the policy on A
(cd /tmp/origin-fed-example/node-a && \
   ./origin eval 'pkg:npm/@sigstore/sign@2.3.2' --policy release_signing 2>&1 | tail -1)
```

The claim ID is byte-identical to what A produced before importing B's archive. Federation does NOT change verdicts; B's evidence is recorded but not consumed by the current `release_signing/v2` policy (which doesn't query `peer_reports_*`).

A future policy that explicitly weights `peer_reports_*` would consume B's evidence. The policy author decides the weighting; the protocol guarantees the evidence is honestly labelled.

## What this demonstrates

| Property | Mechanism |
|---|---|
| Same evidence → same Identity ID across nodes | Content-addressing of canonical envelopes |
| Different ingestors → different Occurrence IDs | Per-attestor canonical occurrence envelopes |
| Verified-form does not cross the boundary | Rewrite rule in `internal/peerimport/peerimport.go` |
| Boundary violation is structurally detectable | Verify check #12 walks every `federated_importer` occurrence |
| Local claim IDs unchanged by federation | `identities_hash` excludes occurrences; claim canonical bytes exclude both |

## What this does NOT demonstrate

- Network federation. v0 is filesystem-only. Multi-machine federation is "copy the archive over secure transport, then import locally".
- Independence semantics. Two peers reporting the same observation from the same upstream are not independent in a deep sense; the protocol does not yet formalise this.
- Conflict resolution. Two peers reporting incompatible observations of the same fact are recorded as distinct observations; the protocol does not adjudicate.

For the full rules, see [`../../docs/invariants.md`](../../docs/invariants.md) and [`../../docs/threat-model.md`](../../docs/threat-model.md).
