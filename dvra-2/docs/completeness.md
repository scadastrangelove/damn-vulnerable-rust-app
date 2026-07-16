# Completeness Review

This document is the MVP acceptance checklist. It describes what is intentionally
complete now and what is intentionally deferred to later lab versions.

## MVP Scope

| Requirement | Evidence |
| --- | --- |
| Realistic Rust artifact-processing story | `apps/api`, `apps/worker`, `crates/config`, `crates/binary-parser`, `crates/worker-engine` |
| Multi-tenant API exercise | `DVRA-001`, `apps/api`, `crates/auth` |
| Config-dependent command injection exercise | `DVRA-004`, `crates/worker-engine`, `configs/tenant-vulnerable.yaml`, `configs/operator-safe.yaml` |
| Parser mismatch exercise found by differential fuzzing | `DVRA-006`, `crates/binary-parser`, `fuzz/fuzz_targets/dvra_006_differential.rs` |
| Panic-safety unsafe collection exercise | `DVRA-008`, `crates/unsafe-cache`, `tools/miri-reproduce.sh` |
| Invalid `Send`/`Sync` exercise | `DVRA-009`, `crates/unsafe-cache`, Loom feature test |
| Reachability/false-positive pair | `DVRA-013`, `DVRA-014`, `apps/api`, `crates/worker-engine` |
| Public scenario metadata separated from labels | `scenarios/public/*.yaml`, `benchmark_oracle: instructor-oracle/scenarios.yaml` |
| Benchmark oracle | `instructor-oracle/scenarios.yaml`, `docs/benchmark-oracle.md`, `docs/private-oracle.schema.example.yaml` |
| Isolated runtime path | `infrastructure/compose.yaml`, Dockerfiles, direct Docker commands in `docs/verification.md` |
| External-history labs excluded from root workspace | `labs/*/README.md`, workspace `exclude` |

## Scenario Coverage

The MVP has seven public scenario files because the sixth exercise is a pair:
one real unsafe defect outside the registered route graph and one safe
fixed-program command execution path.

| Exercise | Scenario IDs |
| --- | --- |
| IDOR | `DVRA-001` |
| Config-dependent shell injection | `DVRA-004` |
| Parser validator/normalizer mismatch | `DVRA-006` |
| Panic-safety unsafe collection | `DVRA-008` |
| Invalid `Send`/`Sync` | `DVRA-009` |
| Reachability plus false-positive comparison | `DVRA-013`, `DVRA-014` |

## Deliberate Deferrals

These are intentionally not implemented in the MVP:

- FFI ownership mismatch and sanitizer exercises.
- Vulnerable dependency and malicious `build.rs` supply-chain fixtures.
- Historical Rust standard-library CVE containers.
- Compiler soundness demonstrations such as `cve-rs`.
- Hidden scoring service and full CI tool matrix.

The placeholders in `labs/` document where these belong. They should remain
outside the root workspace until each lab has a pinned disposable container and
its own verification story.

## Completion Gate

Run:

```sh
cargo run -p dvra-labctl -- audit
```

The audit checks that required public manifests, benchmark oracle, docs,
fixtures, Dockerfiles, and excluded lab placeholders exist.
