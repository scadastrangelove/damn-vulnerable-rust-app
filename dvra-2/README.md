# Damn Vulnerable Rust Application

DVRA is a deliberately vulnerable Rust lab for learning the difference between
a suspicious code pattern, a real local defect, and an application vulnerability
that is built, reachable, attacker-controlled, and impactful.

This repository is intentionally unsafe. Do not deploy it on a public network,
do not run the worker against untrusted local files, and do not copy vulnerable
patterns into production code.

## What is included

The MVP implements the six exercise groups from the design note:

| ID | Theme | Primary reproducer |
| --- | --- | --- |
| DVRA-001 | Cross-tenant IDOR in the API | `cargo run -p dvra-labctl -- reproduce DVRA-001` |
| DVRA-004 | Config-dependent shell command injection | `cargo run -p dvra-labctl -- reproduce DVRA-004` |
| DVRA-006 | Validator/normalizer parser mismatch | `cargo run -p dvra-labctl -- reproduce DVRA-006` |
| DVRA-008 | Panic-unsound unsafe collection | `docker compose -f infrastructure/compose.yaml --profile labs run --rm dvra-miri-008` |
| DVRA-009 | Invalid `Send`/`Sync` promises | `cargo run -p dvra-labctl -- reproduce DVRA-009` |
| DVRA-013 | Real unsafe defect in an unregistered route | `docker compose -f infrastructure/compose.yaml --profile labs run --rm dvra-miri-013` |
| DVRA-014 | Scary-looking `Command::new` without shell | `cargo run -p dvra-labctl -- reproduce DVRA-014` |

DVRA-013 and DVRA-014 are paired with the sixth exercise: one is a real defect
outside the production route graph; the other looks scary to simple pattern
matching but does not invoke a shell.

## Quick start

```sh
cargo test --workspace --locked
cargo run -p dvra-labctl -- list
cargo run -p dvra-labctl -- doctor
docker compose -f infrastructure/compose.yaml up --build api
../tools/dvra-docker dvra-2 config
```

The API binds to `127.0.0.1:3000` on the host. Inside the container it listens
on `0.0.0.0:3000`, with the Compose port mapping restricted to localhost.

For the full verification checklist, including container and Miri gates, see
`docs/verification.md`.

For QA and scope review, see `docs/qa.md` and `docs/completeness.md`.

## Repository map

- `apps/api`: Axum API with seeded tenants/projects and an unregistered legacy
  decoder function.
- `apps/mock-metadata-service`: fake cloud metadata endpoint for isolated lab
  networks.
- `apps/worker`: offline artifact worker that refuses process mode unless
  `DVRA_LAB_MODE=isolated` and the work directory is under `/tmp/dvra`.
- `crates/*`: reusable lab building blocks.
- `tools/labctl`: small reproducer/doctor helper.
- `scenarios/public`: learner-facing scenario metadata. It points to the
  benchmark oracle without duplicating labels inline.
- `instructor-oracle/scenarios.yaml`: benchmark gold labels.
- `docs/private-oracle.schema.example.yaml`: example oracle shape.
- `docs/completeness.md`: MVP scope and deferral audit.
- `docs/qa.md`: quality gates and release checklist.
- `docs/instructor-guide.md`: course-facing review flow and rubric.
- `fuzz`: excluded `cargo-fuzz` package for DVRA-006 differential fuzzing.
- `labs`: placeholders for pinned external-history labs that are not built from
  the root workspace.

## Truth model

Every finding should be classified with five independent axes:

```text
defect && built && reachable && attacker_controlled && impactful
```

The public scenario files describe the exercise. The benchmark gold labels live
in `instructor-oracle/scenarios.yaml`. That split lets tools run on prompts and
code while evaluators compare against explicit truth labels.
