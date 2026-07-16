# Standard Library Archaeology

Historical standard-library CVEs belong in pinned containers with old Rust
toolchains. They are intentionally excluded from the root workspace so the main
DVRA application continues to build on the current pinned toolchain.

Future labs should live in subdirectories named by CVE and include the exact
toolchain, command, and expected failure mode.
