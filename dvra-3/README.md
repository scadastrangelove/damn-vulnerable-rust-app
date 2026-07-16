# Damn Vulnerable Rust Application (DVRA)

DVRA `0.2.0-alpha.2` is a deliberately vulnerable Rust application for security
code review, SAST/DAST evaluation, fuzzing, Miri, Loom, threat-model analysis,
and reachability reasoning.

> **Safety warning**
>
> DVRA contains deliberate command injection, unsafe-code soundness bugs, data
> races, denial-of-service conditions, and vulnerable-looking decoys. Run it only
> in a disposable local container or VM. Never expose it to an untrusted network,
> mount host secrets, pass cloud credentials, or run it as root.

## What makes DVRA different

Each scenario is classified on five independent axes:

1. Does a real defect exist?
2. Is the code built in this profile?
3. Is it reachable from a production entry point?
4. Can the relevant input be controlled by the attacker in the selected threat model?
5. Does exploitation have meaningful impact?

This allows the same application to contain:

- reachable vulnerabilities;
- real defects outside the request path;
- vulnerable dependencies that do not reach the final binary;
- suspicious but safe code;
- defects found by fuzzing or Miri but usually missed by ordinary linters;
- findings whose severity changes when configuration ownership changes.

## Implemented scenarios

| ID | Scenario | Primary discovery method |
|---|---|---|
| DVRA-001 | Cross-tenant artifact access (IDOR) | Manual review, integration test |
| DVRA-002 | Shell injection through tenant-controlled processing configuration | Threat modeling, DAST |
| DVRA-003 | Parser offset mismatch after normalization | Coverage-guided fuzzing |
| DVRA-004 | Panic-safety double drop in a safe API | Miri, unsafe review |
| DVRA-005 | Incorrect `Sync` implementation causing a data race | Loom, unsafe review |
| DVRA-006 | Real command injection code not reachable from the API, plus a safe look-alike | Reachability analysis |
| DVRA-007 | Secret-bearing configuration emitted to debug logs | Threat model and deployment review |
| DVRA-008 | Bundle extraction path traversal across job directories | Manual review, DAST |
| DVRA-009 | SSRF into an internal fake metadata service | Threat modeling, DAST |

## Repository layout

```text
apps/api/                 Axum HTTP API
apps/metadata-service/    internal fake metadata endpoint for SSRF labs
crates/core/              multi-tenant domain model
crates/fetch/             vulnerable and egress-policy HTTP clients
crates/config/            config and command-execution scenarios
crates/bundle/            bundle parser and extraction traversal scenario
crates/parser/            vulnerable and reference binary parsers
crates/unsafe-cache/      panic-safety and concurrency soundness labs
fuzz/                     cargo-fuzz target and seed corpus
scenarios/public/         student-facing scenario descriptions
labs/                     isolated historical/compiler/supply-chain exercises
infrastructure/           Docker and Compose isolation
scripts/labctl            common lab commands
```

## Quick start

The default profile is intentionally safer: command/filesystem labs and the
SSRF lab use separate acknowledgement gates, and the fake metadata service is
not started.

```bash
cargo run -p dvra-api
```

Open another terminal:

```bash
curl http://127.0.0.1:3000/health
curl -H 'x-tenant: blue' http://127.0.0.1:3000/v1/artifacts/2
curl -H 'x-tenant: blue' http://127.0.0.1:3000/v1/fixed/artifacts/2
```

Run the deliberately dangerous command/filesystem lab only in a disposable
local VM or container:

```bash
DVRA_LAB_MODE=vulnerable DVRA_ACK_INSECURE=I_UNDERSTAND cargo run -p dvra-api
```

Run DVRA-009 only through the contained Compose profile. It starts an internal
fake metadata service without publishing it to the host; the API is reachable
only through `127.0.0.1:3000` for the local reproducer:

```bash
./scripts/labctl run-ssrf
./scripts/labctl reproduce DVRA-009
./scripts/labctl stop-ssrf
```

## Verification commands

The repository ships a `Cargo.lock` for reproducible application-lab builds.
Regenerate it only when intentionally updating dependencies.

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features --locked
cargo test --workspace --locked

# Deterministic parser reproducer
cargo test -p dvra-parser vulnerable_seed_panics --locked

# Loom proves the incorrect Sync implementation is racy.
cargo test -p dvra-unsafe-cache --features loom-tests loom_detects_data_race --locked

# Miri is expected to report undefined behavior for the ignored test.
cargo +nightly miri test -p dvra-unsafe-cache miri_finds_panic_safety_bug -- --ignored

# Fuzz target
cargo install cargo-fuzz
cargo fuzz run differential_parser
```

## Lab controller

```bash
./scripts/labctl doctor
./scripts/labctl run
./scripts/labctl run-dangerous
./scripts/labctl run-ssrf
./scripts/labctl stop-ssrf
./scripts/labctl reproduce DVRA-001
./scripts/labctl reproduce DVRA-003
./scripts/labctl reproduce DVRA-008
./scripts/labctl reproduce DVRA-009
```

From this implementation directory, Docker workflows are also available through
the shared repository helper:

```bash
../tools/dvra-docker dvra-3 config
../tools/dvra-docker dvra-3 up
../tools/dvra-docker dvra-3 ssrf-config
../tools/dvra-docker dvra-3 ssrf-up
../tools/dvra-docker dvra-3 ssrf-down
```

Benchmark gold labels live in `instructor-oracle/scenarios.yaml`. For
challenge-style classroom use, distribute a branch or bundle without that
directory until grading.

## Source inspirations

DVRA reimplements vulnerability classes rather than copying third-party PoCs into
the main application. Historical or compiler-specific demonstrations belong in
isolated `labs/` directories.

- Rust CVE reproductions: https://github.com/Qwaz/rust-cve
- Rudra: https://github.com/sslab-gatech/Rudra
- Rudra PoCs: https://github.com/sslab-gatech/Rudra-PoC
- `cve-rs`: https://github.com/Speykious/cve-rs
- RustSec advisory database: https://github.com/RustSec/advisory-db
- Rust Fuzz Book: https://rust-fuzz.github.io/book/
- Miri: https://github.com/rust-lang/miri
- Loom: https://github.com/tokio-rs/loom

See [docs/DESIGN.md](docs/DESIGN.md) for the threat models and benchmark design.
