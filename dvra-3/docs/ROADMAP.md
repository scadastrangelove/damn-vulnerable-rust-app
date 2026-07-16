# Roadmap

## v0.2 — application surfaces

- [x] archive-like bundle extraction with lexical path traversal;
- [ ] archive extraction through pre-existing symlinks;
- [ ] compressed archive expansion and decompression limits;
- [x] SSRF with a fake metadata service and configurable egress policy;
- async cancellation and transaction consistency;
- bounded versus unbounded job queues;
- authentication/JWT validation and state-transition bugs.

## v0.3 — native boundaries

- C FFI ownership mismatch under AddressSanitizer;
- callback lifetime violation;
- invalid `repr`/ABI assumptions;
- safe wrapper whose contract can be violated from ordinary safe code.

## v0.4 — supply chain

- RustSec fixture that is in `Cargo.lock` and reachable;
- the same advisory as a dev-only or feature-disabled dependency;
- procedural macro and build-script trust exercises;
- `cargo-audit`, `cargo-deny`, and `cargo-vet` comparison.

## v0.5 — archaeology

- pinned standard-library CVEs from `Qwaz/rust-cve`;
- selected Rudra-PoC patterns with original and minimized forms;
- isolated `cve-rs` compiler-soundness demonstration;
- versioned expectations for vulnerable and fixed toolchains.

## v1.0 — benchmark packaging

- separate student and instructor distributions;
- hidden regression corpus;
- SARIF ingestion and scoring;
- per-tool version matrix;
- reproducible container images and signed release artifacts.
