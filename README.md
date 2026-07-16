# DVRA implementations

This directory collects multiple implementations of Damn Vulnerable Rust
Application in one place. The goal is to keep a shared security-training and QA
contract while allowing each implementation to have a different scale and
teaching role.

All implementations are deliberately vulnerable. Do not run them as public
services, attach real secrets, mount home directories, expose SSH/GPG agents, or
mount the Docker socket. Heavy Docker, Miri, fuzzing, and sanitizer gates should
run only in disposable environments, such as a local VM or a throwaway remote
builder.

## Application model

DVRA models an artifact-processing platform: tenants own projects, upload or
fetch artifacts, parse custom binary records, run worker-side post-processing,
and interact with internal services such as fake metadata endpoints. That shape
is intentionally broad enough to exercise both ordinary web security and
Rust-specific review skills:

- multi-tenant authorization and object ownership;
- parser/validator disagreements and fuzzing targets;
- filesystem and bundle extraction boundaries;
- command execution controlled by configuration or tenant input;
- HTTP fetching, redirects, and SSRF;
- unsafe-code invariants, panic safety, `Send`/`Sync`, Miri, and Loom;
- false positives where suspicious code is safe, dead, or not
  attacker-controlled.

## Repository map

| Path | Role | Status |
| --- | --- | --- |
| `dvra-1/` | Compact code-review benchmark with many planted findings, decoys, public scenario prompts, and a gold oracle. | Imported as implementation 1 |
| `dvra-2/` | Realistic artifact-processing service/lab with API, worker, fuzzing, Loom, Miri, and Docker isolation. | Imported as implementation 2 |
| `dvra-3/` | Application lab `0.2.0-alpha.2` with Axum API, SSRF/internal metadata lab, bundle traversal, fuzz/Miri/Loom scenarios, public scenarios, and a gold oracle. | Imported as implementation 3 |
| `tools/dvra-docker` | Root Docker/Compose facade for all implementations. | Shared helper |
| `rust-security-code-review-canonical_1.md` | Shared reference/checklist for Rust security review methodology. | Reference material |

See `BENCHMARK.md` for the published gold-label oracle locations.

## Shared Docker facade

Use `tools/dvra-docker` from the repository root to discover and run the
containerized workflows:

```sh
tools/dvra-docker list
tools/dvra-docker dvra-1 test
tools/dvra-docker dvra-1 audit
tools/dvra-docker dvra-2 config
tools/dvra-docker dvra-2 up
tools/dvra-docker dvra-3 config
tools/dvra-docker dvra-3 ssrf-config
```

The default commands are intentionally conservative. Dangerous or heavy gates
remain explicit (`dvra-1 test-ffi`, `dvra-2 miri-008`, `dvra-2 miri-013`,
`dvra-3 ssrf-up`).

## Implementation 1

`dvra-1` is a compact review benchmark with an explicit learner/gold-label split:

- It is a small std-only request router, not a live web server.
- The domain is an internal service with routes for user search, document
  access, file download/upload, proxying, parsing, auth, hooks, and optional FFI.
- It is dense by design: 22 planted review cases include reachable bugs, decoys,
  fuzz/Miri-only cases, and threat-model-dependent findings.
- `source/` contains the learner-facing Rust crate;
- `scenarios/public/index.toml` contains learner-facing scenario prompts;
- `instructor-oracle/MANIFEST.toml` and `instructor-oracle/ANSWER_KEY.md`
  publish the benchmark gold labels;
- `tools/dvra1` builds learner-safe bundles and audits the layout;
- `infrastructure/compose.yaml` runs the default test/audit gates in an
  isolated container.

Main entry points:

```sh
cd dvra-1
./tools/dvra1 test
./tools/dvra1 audit
./tools/dvra1 package-learner
../tools/dvra-docker dvra-1 test
```

## Implementation 2

`dvra-2` is a realistic artifact-processing service with separate applications,
crates, scenario manifests, Docker support, and QA documentation.

- `apps/api` exposes a tenant/project artifact API and an intentionally
  unregistered legacy decoder.
- `apps/worker` processes artifacts under an isolated `/tmp/dvra` work area.
- `apps/mock-metadata-service` supports isolated network/security exercises.
- The scenario set covers cross-tenant IDOR, config-dependent shell execution,
  parser offset mismatch, panic-unsound unsafe collections, invalid `Send`/`Sync`,
  an unreachable unsafe defect, and a fixed-program `Command::new` false
  positive.
- Heavy paths use Docker profiles and Miri/Loom reproducer commands.

Main entry points:

```sh
cd dvra-2
cargo run -p dvra-labctl -- audit
cargo run -p dvra-labctl -- doctor
cargo test --workspace --locked
```

Documentation:

- `dvra-2/README.md` — implementation overview;
- `dvra-2/docs/completeness.md` — MVP completeness checklist;
- `dvra-2/docs/qa.md` — QA plan and release checklist;
- `dvra-2/docs/verification.md` — local and Docker/Miri gates;
- `dvra-2/docs/instructor-guide.md` — instructor-facing workflow.

Heavy Docker/Miri gates should be run in a disposable environment with Docker
Compose available.

## Implementation 3

`dvra-3` is another workspace implementation, closer to a full application lab:

- `apps/api` is an Axum web API with vulnerable and fixed comparison routes.
- Tenants can read artifacts, submit bundles, trigger parser paths, run gated
  post-processing, and ask the service to fetch URLs.
- `apps/metadata-service` is an internal fake cloud metadata service used by
  the SSRF lab.
- Crates split the app into config, bundle parsing, HTTP fetch policy, binary
  parser, domain model, and unsafe-cache labs.
- The scenario set covers IDOR, command injection, parser normalization bugs,
  panic safety, invalid `Sync`, unreachable command injection, debug secret
  logging, bundle traversal, and SSRF into fake metadata.
- `scenarios/public` contains learner-facing descriptions;
  `instructor-oracle/scenarios.yaml` publishes the benchmark gold labels.
- `scripts/labctl` and `infrastructure/compose*.yaml` provide local,
  Dockerized, and SSRF-profile workflows.

Main entry points:

```sh
cd dvra-3
./scripts/labctl verify-layout
./scripts/labctl doctor
./scripts/labctl test
../tools/dvra-docker dvra-3 config
```

Import archives and generated learner bundles are intentionally ignored by git;
the published repository contains the source, documentation, scenarios, and
Docker workflows.

## Shared contract

All three implementations follow the same high-level rules:

- learner-facing scenario metadata and benchmark gold labels are separate files;
- planted defects, decoys, reachability labels, and expected tool signals are
  intentionally published for benchmark use;
- every implementation needs a clear reproducer and verification story;
- dangerous runtime paths need explicit gates and a Docker/disposable execution
  path;
- historical, FFI, supply-chain, and compiler-hole labs must not accidentally
  become part of an ordinary root build.

## Contact

Sergey Gordeychik

- Email: scadastrangelove@gmail.com
- X/Twitter: [@scadasl](https://x.com/scadasl)
- Blog: [scadastrangelove.blogspot.com](https://scadastrangelove.blogspot.com/)

Issues and pull requests are welcome.

For the upstream C/C++ reference pipeline, see
[anthropics/defending-code-reference-harness](https://github.com/anthropics/defending-code-reference-harness).

## License

Apache-2.0 — see [LICENSE](https://github.com/scadastrangelove/damn-vulnerable-rust-app/blob/main/LICENSE).
