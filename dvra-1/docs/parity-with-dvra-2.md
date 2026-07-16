# DVRA-1 operational parity

This note explains how `dvra-1` aligns with the repository-wide DVRA contract
without turning it into the same kind of lab as `dvra-2`.

## Positioning

`dvra-1` is a compact Rust security code-review benchmark. Its value is density:
many review cases, decoys, and tool-visibility differences in one small crate.

`dvra-2` is a realistic artifact-processing application lab with a multi-crate
workspace, API/worker split, container isolation, scenario manifests, and richer
runtime gates.

Operational parity therefore means shared publication discipline, not identical
architecture.

## Current status

| Area | `dvra-1` status |
| --- | --- |
| Canonical source | `source/` is the authoritative learner-facing crate. |
| Instructor truth | `instructor-oracle/MANIFEST.toml` and `instructor-oracle/ANSWER_KEY.md` are private. |
| Public metadata | `scenarios/public/index.toml` contains prompts without verdicts, vulnerable lines, triggers, or fixes. |
| Learner bundle | `./tools/dvra1 package-learner` builds `dist/dvra-1-learner.tar.gz`. |
| Audit gate | `./tools/dvra1 audit` checks the public/private split and learner bundle. |
| Default verification | `./tools/dvra1 test` runs the std-only test gate. |
| Optional heavy gates | `test-ffi`, `fuzz-route`, `fuzz-parser`, and `miri` are available through `tools/dvra1`. |
| Provenance | `damn-vulnerable-rust.tar.gz` is retained as the original bundle, not as learner distribution. |

## Distribution rule

Give learners either:

- the `source/` tree plus `scenarios/public/index.toml`; or
- the archive produced by `./tools/dvra1 package-learner`.

Do not distribute `instructor-oracle/` or the legacy
`damn-vulnerable-rust.tar.gz` to learners.

## Remaining intentional differences from DVRA-2

- `dvra-1` is not a live HTTP application.
- It does not need Docker as part of the default workflow.
- It keeps scenarios in a compact index instead of one public file per case.
- Optional fuzz, Miri, sanitizer, and FFI gates depend on host tooling and are
  not part of the fast default test.

Those differences are deliberate. They preserve `dvra-1` as the dense
code-review benchmark in the collection.

## Publication checklist

Before publishing or redistributing `dvra-1`, run:

```sh
./tools/dvra1 test
./tools/dvra1 audit
./tools/dvra1 package-learner
```

Then inspect the learner archive if desired:

```sh
tar -tzf dist/dvra-1-learner.tar.gz
```

The archive must not contain `ANSWER_KEY.md` or `MANIFEST.toml`.
