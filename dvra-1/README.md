# DVRA-1: compact code-review benchmark

DVRA-1 is a compact Rust security code-review benchmark. It is intentionally
not a live web service: the application surface is a std-only request router
with feature modules that model common service routes and review targets.

Its value is density: many planted issues, decoys, tool-visibility differences,
and threat-model-dependent cases in one small review target.

## Application surface

The learner-facing crate models an internal service with routes for:

- user search and data-access review;
- document object access and tenant/owner authorization;
- file download/upload path handling;
- proxy/path parsing and parser differentials;
- request validation, framing, header parsing, and nested input parsing;
- auth token handling and logging;
- hook execution driven by configuration;
- unsafe, concurrency, panic-safety, build-script, and optional FFI review.

It contains 22 gold-labeled findings spanning reachable vulnerabilities,
decoys, fuzz/Miri-only cases, and threat-model-dependent behavior.

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
