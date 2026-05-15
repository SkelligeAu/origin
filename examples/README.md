# Examples

Concrete walk-throughs of the Origin flows described in [`../README.md`](../README.md). Each subdirectory is a self-contained demonstration.

## Index

- [`demo-tarball/`](demo-tarball/) — produce, share, and verify a portable demo bundle for one npm package.
- [`two-node-federation/`](two-node-federation/) — set up two Origin nodes, import one's archive into the other, demonstrate the no-laundering rule end-to-end.

## Convention

Examples are operator scripts plus documentation; they do not introduce new Origin features. Anything they demonstrate is available via the standard CLI commands.

Examples may include sample output, but do NOT commit `data/` directories or working state. The walk-throughs run on a clean clone.
