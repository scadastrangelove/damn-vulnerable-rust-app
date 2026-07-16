# Compiler Soundness

Compiler soundness demonstrations such as `cve-rs` are intentionally separate
from the main application. They are not dependencies of the root workspace and
should not be built by ordinary `cargo test --workspace`.

Use pinned toolchains and isolated containers for these labs.
