# QA Plan

DVRA has intentionally vulnerable code, so QA must prove both that the lab works
and that the guardrails still hold.

## Gate Levels

| Gate | Purpose |
| --- | --- |
| `cargo run -p dvra-labctl -- audit` | Checks completeness of public manifests, docs, fixtures, and lab placeholders. |
| `cargo run -p dvra-labctl -- doctor` | Reports local tool readiness without hanging on broken Docker builders. |
| Rust gates | Format, unit tests, Loom feature model, Clippy warnings-as-errors. |
| Fuzz build gate | Ensures the excluded `cargo-fuzz` target still compiles. |
| Local reproducers | Exercises fast scenarios without Docker. |
| Runtime Docker gates | Builds and runs API, worker, and fake metadata service with restrictions. |
| Miri Docker gates | Reproduces unsafe defects with a pinned nightly and no runtime network. |

## Required Local Commands

```sh
cargo run -p dvra-labctl -- audit
cargo run -p dvra-labctl -- doctor
cargo fmt --all -- --check
cargo test --workspace --locked
cargo test -p dvra-unsafe-cache --features loom-model --locked
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo check --manifest-path fuzz/Cargo.toml --locked
```

## Required Scenario Commands

```sh
cargo run -p dvra-labctl -- reproduce DVRA-001
cargo run -p dvra-labctl -- reproduce DVRA-004
cargo run -p dvra-labctl -- reproduce DVRA-006
cargo run -p dvra-labctl -- reproduce DVRA-009
cargo run -p dvra-labctl -- reproduce DVRA-014
```

`DVRA-008` and `DVRA-013` are heavy gates and should be run in the Miri
container described in `docs/verification.md`.

## Safety Regression Checks

For every container run, preserve these constraints unless a future scenario
documents a narrower exception:

- non-root user;
- read-only root filesystem;
- writable `/tmp/dvra` only;
- no Docker socket mount;
- no host home directory mount;
- no real cloud credentials;
- dropped Linux capabilities;
- `no-new-privileges`;
- CPU, memory, and PID limits;
- `network none` for worker and Miri reproducers.

## Release Checklist

Before cutting a lab release:

1. Run the local commands above.
2. Run the direct Docker commands or Compose commands from `docs/verification.md`.
3. Confirm `cargo run -p dvra-labctl -- audit` passes after any scenario change.
4. Confirm `scenarios/public` links to `instructor-oracle/scenarios.yaml`
   instead of duplicating labels inline.
5. Record tool versions in the benchmark oracle or release notes.
