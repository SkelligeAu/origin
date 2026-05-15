# Test Data

Shared test inputs used across packages. Each subdirectory is owned by the package that consumes it.

This is distinct from `protocol/v0-fixtures/`, which holds the byte-equality references for protocol conformance. Fixtures there are normative; data here is operational.

## Current contents

Empty. Add shared test inputs as concrete need arises — for example:

- A captured npm registry response for offline ingest tests.
- A constructed malformed Sigstore bundle for the verifier's adversarial-fixture test.
- An archive demonstrating a specific tamper scenario.

## Convention

- One subdirectory per scenario, with a `README.md` explaining what the input is and which test consumes it.
- Inputs must be small (target < 10 KB per file).
- No live-fetched data that may drift. Capture deterministically from a known source and pin the version in the README.
- No credentials, real signing keys, or operator data.
