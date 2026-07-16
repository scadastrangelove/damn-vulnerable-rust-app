# Standard-library archaeology placeholder

Add one directory per CVE. Required files:

- `rust-toolchain.toml` with the vulnerable compiler;
- a minimal reproducer;
- `expected.md` describing behavior on vulnerable and fixed compilers;
- a Dockerfile with `--network=none` execution instructions;
- source attribution to the corresponding `Qwaz/rust-cve` entry.
