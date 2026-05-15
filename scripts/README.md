# Scripts

Helper scripts for development and CI workflows. Scripts are convenience wrappers around the `origin` CLI; they do NOT implement protocol behaviour or replace any verify check.

## Conventions

- Scripts run from the repo root.
- Scripts must be idempotent and re-runnable.
- Scripts must not commit to `data/`, `*.tar.gz`, or any artefact `.gitignore` excludes.
- Scripts should fail loudly: `set -euo pipefail` for bash, equivalent for other languages.
- Scripts should not require credentials or environment variables not already in `.env.example` (if present).

## Index

This directory is currently empty. Candidate scripts (add as concrete need arises):

- `regenerate-fixtures.sh` — runs `cd protocol/v0-fixtures && go run gen.go` and stages the diff for review.
- `release-precheck.sh` — runs the full `docs/release-checklist.md` programmatically: tests, demo build, demo verify, tamper-check.
- `smoke-test.sh` — small `ingest` → `project` → `eval` → `verify` loop against a known-good package.

If you add one, document it in this README.
