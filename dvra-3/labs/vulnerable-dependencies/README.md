# Vulnerable dependency fixtures

Each future fixture should contain a complete lockfile, the relevant RustSec
advisory identifier, a reachable and an unreachable use case, and an upgraded
fixed variant. Keep fixtures excluded from the root workspace so ordinary builds
do not execute old build scripts or fetch intentionally vulnerable packages.
