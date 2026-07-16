# Isolated labs

These directories are intentionally excluded from the root Cargo workspace.
Future additions should pin their own toolchain and execute inside a container
with network disabled and strict resource limits.

## Planned sources

### Standard-library archaeology

Use individual reproductions from https://github.com/Qwaz/rust-cve. Each case
must record the affected Rust range and must not be silently compiled with a
modern toolchain, because the historical bug may already be fixed.

### Rudra patterns

Use https://github.com/sslab-gatech/Rudra-PoC as a source of invariant patterns:
panic safety, uninitialized exposure, higher-order unsafe contracts, variance,
and incorrect Send/Sync. Reimplement minimal examples rather than importing the
entire corpus into the production workspace.

### Compiler soundness

Treat https://github.com/Speykious/cve-rs as a separate compiler-soundness
exercise. It is not representative of ordinary application code review and can
produce memory corruption from source that contains no conventional unsafe
block.

### Supply chain

Build small excluded fixtures from RustSec advisories. Record vulnerable ranges,
lockfiles, feature combinations, build-script behavior, reachability, and the
upstream patch.
