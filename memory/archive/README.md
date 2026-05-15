# Archive: Phase Planning Documents

This directory holds the iterative planning documents produced during the project's first five phases. They are **historical**, not normative.

For current normative material, see:

- `protocol/origin-protocol-v0.md` — frozen protocol specification.
- `docs/epistemic-model.v1.md` — formal epistemic model.
- `docs/invariants.md` — the rules implementations and contributors must hold.
- `docs/architecture.md` — operational overview of the implementation.

## Reading order (if you want the design lineage)

The phase documents are best read in order:

| File | Phase | Theme |
|---|---|---|
| `layer-1.md` | Day-1 blueprint | Append-only signed log, projection, eval, verify. |
| `layer-2.md` | Phase 2 | Verification depth via Sigstore/Fulcio. |
| `layer-2.5.md` | Phase 2.5 | Determinism hardening, failure semantics. |
| `layer-3.md` | Phase 3 | AssertionIdentity / AssertionOccurrence split. |
| `layer-3.5.md` | Phase 3.5 | Filesystem federation, the no-laundering rule. |
| `layer-4.md` | Phase 4 | Protocol spec freeze + interop fixtures + portable demo. |
| `layer-5.md` | Phase 5 | Transparency-log anchoring, observation-class only. |

Each document explains why a phase was scoped the way it was, what risks were flagged, and what was deferred. Some sections in these archives have been superseded by the normative documents above — when in doubt, the normative documents win.

## Why preserve them?

Audit-trail honesty. Future contributors evaluating "why was X done this way?" should be able to find the original deliberation. Several Phase-N decisions only make sense in the context of Phase-N-1 risks the team had just discovered. Discarding the planning history would obscure that.
