# DVRA-1 verification

Run commands through the wrapper helper or directly from the canonical
learner-facing crate in `source/`.

## Helper commands

```sh
./tools/dvra1 test
./tools/dvra1 audit
./tools/dvra1 package-learner
```

## Default gate

The default build is std-only and does not require a C compiler.

```sh
./tools/dvra1 test
```

Last local check: default tests pass with UB-oriented checks kept out of the
ordinary suite.

## Optional FFI gate

Requires a C compiler and the optional `cc` build dependency.

```sh
./tools/dvra1 test-ffi
```

## Fuzz gates

Requires nightly and `cargo-fuzz`.

```sh
./tools/dvra1 fuzz-route
./tools/dvra1 fuzz-parser
```

The route target is expected to find panic/abort-style bugs. The parser target
checks an invariant rather than waiting for a crash.

## Miri gate

Requires nightly with Miri.

```sh
./tools/dvra1 miri
```

Use this for UB-oriented exercises such as higher-order invariants and
panic-safety bugs.

## Race/sanitizer gate

Requires nightly and sanitizer support on the host platform.

```sh
RUSTFLAGS="-Zsanitizer=thread" cargo +nightly test --features race-demo
```

This is intentionally not part of the normal test suite.

## Packaging check

Before distributing to learners, build the learner bundle:

```sh
./tools/dvra1 package-learner
```

Then run:

```sh
./tools/dvra1 audit
```

The legacy `damn-vulnerable-rust.tar.gz` includes instructor truth and is kept
only for provenance. Do not distribute it to learners.

## Docker gates

The Docker workflow mirrors the local helper commands while keeping Cargo state,
build output, and generated learner archives under `/tmp` inside the container.
The default services run with no network, dropped capabilities,
`no-new-privileges`, PID/memory/CPU limits, and a read-only root filesystem.
The `/tmp` tmpfs is executable because Cargo runs build scripts and test
binaries from `CARGO_TARGET_DIR`.

```sh
docker compose -f infrastructure/compose.yaml config
docker compose -f infrastructure/compose.yaml run --rm test
docker compose -f infrastructure/compose.yaml run --rm audit
```

The optional FFI tier is behind an explicit profile:

```sh
docker compose -f infrastructure/compose.yaml --profile ffi run --rm test-ffi
```

From the repository root, the same gates are available through:

```sh
tools/dvra-docker dvra-1 config
tools/dvra-docker dvra-1 test
tools/dvra-docker dvra-1 audit
tools/dvra-docker dvra-1 test-ffi
```
