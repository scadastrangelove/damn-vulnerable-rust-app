# Damn Vulnerable Rust

This crate is a deliberately vulnerable Rust code-review target for DVRA-1.

It is not production software, not a scanner, and not a benchmark of scanners.
The goal is to practice deciding whether suspicious code is an application
security finding under a stated threat model.

> Do not deploy this code. Do not expose it to a network. Educational use only.

## Threat model

Review the handlers as request-processing logic for a shared service.

- Attacker-controlled: request path, query values, headers, and body when the
  request comes from the public edge.
- Trusted by assumption: the already-authenticated principal and admin flag.
  These identify the caller; they do not automatically grant object-level
  access.
- Trusted by assumption: operator configuration loaded at startup, unless your
  review establishes a path that changes that assumption.
- Assets: other users' data, credentials and credential-derived material,
  process availability, and memory safety.

Several review outcomes depend on these assumptions. If you change an
assumption, state the new model explicitly.

## Run

```sh
cargo run
cargo test
```

The default build is std-only and does not require a C compiler.

Optional gates:

```sh
cargo test --features ffi
cargo +nightly fuzz run route
cargo +nightly fuzz run parser_equivalence
cargo +nightly miri test
RUSTFLAGS="-Zsanitizer=thread" cargo +nightly test --features race-demo
```

Some optional commands require nightly Rust, `cargo-fuzz`, Miri, sanitizer
support, or a C compiler.

## Review task

For each scenario, produce a short review note:

1. verdict under the stated threat model;
2. class of issue, if any;
3. exact evidence in the code;
4. reachability argument;
5. impact argument;
6. patch or proof that no patch is required;
7. regression-test idea.

Do not rely only on pattern matching. Some scary-looking code is intentionally
there to test reachability and invariant reasoning; some plain-looking code
requires dynamic or model-based investigation.

## Layout

```text
src/
  lib.rs
  db.rs
  features/
    auth.rs
    collect.rs
    concurrency.rs
    dedup.rs
    documents.rs
    ffi.rs
    file_download.rs
    framing.rs
    header_parse.rs
    hooks.rs
    native.rs
    nested.rs
    profile.rs
    proxy.rs
    records.rs
    upload.rs
    user_search.rs
    validation.rs
  ffi_shim.c
build.rs
fuzz/
```

The learner-facing scenario index is distributed outside this crate under
`scenarios/public/index.toml` in the DVRA-1 bundle. Instructor truth is not part
of this source tree.
