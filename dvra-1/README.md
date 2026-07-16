# DVRA implementation 1

This directory contains the first DVRA implementation: a compact Rust security
code-review benchmark.

Its value is density: many planted issues, decoys, tool-visibility differences,
and threat-model-dependent cases in one small review target.

## Canonical layout

- `source/`: canonical learner-facing Rust crate.
- `scenarios/public/index.toml`: public scenario index without verdicts,
  vulnerable lines, concrete triggers, or fixes.
- `instructor-oracle/`: benchmark gold labels and reviewer notes.
- `tools/dvra1`: small lab helper for unpacking, testing, packaging, and audit.
- `infrastructure/compose.yaml`: containerized test/audit/FFI gates.
- `build.rs`, `records.rs`: standalone review excerpts retained from the
  original bundle.

The canonical source of truth for development is `source/`. Benchmark labels
are deliberately outside that learner tree. Generated learner bundles are
written to `dist/`, which is intentionally ignored by git.

## Intended use

Give learners `source/` or a bundle produced by:

```sh
./tools/dvra1 package-learner
```

For benchmark evaluation, use `instructor-oracle/` as the gold-label reference.
For challenge-style classroom use, distribute only the learner bundle.

## Quick start

```sh
./tools/dvra1 test
./tools/dvra1 audit
./tools/dvra1 package-learner
```

Optional heavy gates:

```sh
./tools/dvra1 test-ffi
./tools/dvra1 fuzz-route
./tools/dvra1 fuzz-parser
./tools/dvra1 miri
```

Docker gates:

```sh
docker compose -f infrastructure/compose.yaml config
docker compose -f infrastructure/compose.yaml run --rm test
docker compose -f infrastructure/compose.yaml run --rm audit
docker compose -f infrastructure/compose.yaml --profile ffi run --rm test-ffi
```

For details, see `docs/verification.md`.
