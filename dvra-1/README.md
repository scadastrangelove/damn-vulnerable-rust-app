# DVRA implementation 1

This directory contains the first DVRA implementation: a compact Rust security
code-review benchmark.

Unlike `dvra-2`, this implementation is intentionally not a realistic
multi-service application. Its value is density: many planted issues, decoys,
tool-visibility differences, and threat-model-dependent cases in one small
review target.

## Canonical layout

- `source/`: canonical learner-facing Rust crate.
- `scenarios/public/index.toml`: public scenario index without verdicts,
  vulnerable lines, concrete triggers, or fixes.
- `instructor-oracle/`: private truth files for instructors and graders.
- `tools/dvra1`: small lab helper for unpacking, testing, packaging, and audit.
- `infrastructure/compose.yaml`: containerized test/audit/FFI gates.
- `dist/`: generated learner bundles.
- `damn-vulnerable-rust.tar.gz`: legacy original bundle kept for provenance.
- `build.rs`, `records.rs`: standalone review excerpts retained from the
  original bundle.

The canonical source of truth for development is `source/`. The instructor truth
is deliberately outside that tree.

## Intended use

Give learners `source/` or a bundle produced by:

```sh
./tools/dvra1 package-learner
```

Do not give learners `instructor-oracle/`.

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

## Parity with DVRA-2

`dvra-1` should feel operationally aligned with `dvra-2`, but it should not
become the same style of lab. The parity target is:

- one canonical source layout;
- private instructor truth separated from learner material;
- learner-safe bundle generation;
- public scenario metadata;
- explicit verification and audit gates;
- a small command facade for common workflows.

See `docs/parity-with-dvra-2.md`.
