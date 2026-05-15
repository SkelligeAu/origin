# What Origin Is Not

Reviewers familiar with the broader trust, reputation, and supply-chain-security landscape will recognise patterns this project does NOT adopt. This document names them and rejects them, structurally and philosophically.

If you map any of the patterns below onto Origin during review, you are reviewing a different project.

---

## Not a trust score

Origin produces no numeric scores, no percentages, no aggregate weights. Verdicts are categorical — `trusted`, `conditional`, `rejected`, `insufficient_evidence` — and qualifiers are an enumerated set of strings. There are no numbers anywhere in the trust path.

*Why.* Aggregation collapses the audit story into a single value. A "0.87 trust score" tells you nothing about which evidence was consumed, which rule fired, or what changes would flip the verdict. Categorical outputs with enumerated qualifiers keep the chain back to canonical bytes intact.

## Not AI reputation

No machine learning. No embeddings. No similarity ranking. No learned trust models. No "this looks like that".

*Why.* Learned models cannot be re-derived from canonical inputs. Replay requires determinism; ML breaks it. The trust path is a pure function of evidence and a versioned policy, evaluated by code that can be read in an afternoon.

## Not consensus truth

Origin does not vote, average, or majority-rule across observers. Multiple observers who see the same fact deduplicate to one Identity (content-addressing). Multiple observers who disagree produce multiple distinct observations, all recorded, none adjudicated.

*Why.* Consensus is a political concept; truth is not. Recording disagreement honestly is more useful than fabricating agreement. A future policy may weight independent attestors, but the protocol itself records, it does not adjudicate.

## Not a recommendation ranker

Origin produces no "top N" lists, no orderings of subjects, no personalised output. The CLI evaluates one subject against one policy at a time.

*Why.* Ranking implies preference; preference requires a reference frame. Origin's job is to record evidence and derive verdicts under explicit policy. The consumer decides what to do with a verdict.

## Not popularity-weighted

Origin does not weight evidence by download counts, GitHub stars, npm popularity, "what other systems trust", or any social signal.

*Why.* Popularity is not provenance. "Many people use it" is orthogonal to whether anything was verified. Popularity signals may be recorded as observations if a source provides them, but no policy in this repository weights them, and the protocol does not endorse the practice.

## Not a centralized authority

Origin has no central registry, no authoritative trust server, no master allowlist or blocklist. There is no Origin server. There is no Origin account. There is no "official" verdict.

*Why.* A central authority is a single point of compromise and a coordination dependency. Each operator runs their own Origin; trust roots are pinned per-implementation; federation is filesystem-only. Two operators reaching different verdicts on the same artefact is a feature, not a bug — different policies legitimately produce different outputs.

## Not blockchain-style social trust

Origin uses hash chains internally and (optionally) external transparency logs as witnesses. It does NOT use proof-of-work, proof-of-stake, token economics, governance tokens, peer-voting consensus, or any "trust emerging from network participation" pattern.

*Why.* Those mechanisms produce social-consensus signals — facts about the network's politics — that are orthogonal to evidence about the artefact. Origin records evidence about artefacts. Networks of people doing things to each other are a separate (also worthwhile, but different) problem.

## Not opaque heuristics

Origin has no "secret sauce" scoring function, no hidden weights, no black-box rules. Every verdict has a derivation DAG. Every input has an evidence pointer. Every predicate has a declared verification class and a description that names what it records.

*Why.* Opacity defeats audit. If a reviewer cannot trace a claim back to canonical bytes through readable source code, the claim is not auditable, and the system has failed its purpose.

---

## What Origin IS

Read in order:

- [`../README.md`](../README.md) — what the project is, layered top-down.
- [`invariants.md`](invariants.md) — the rules it holds.
- [`architecture.md`](architecture.md) — how the implementation is organised.
- [`../protocol/origin-protocol-v0.md`](../protocol/origin-protocol-v0.md) — the frozen normative specification.

Origin is a provenance compiler and an evidentiary database. It records what was observed, derives claims under explicit policy, and explains itself. That is the whole offer.
