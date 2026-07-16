// Build script. Compiles the C shim only when the `ffi` feature is enabled, so
// the default build stays std-only with no C toolchain and no cc dependency.
//
// Build scripts do not see `#[cfg(feature = ...)]`; cargo exposes enabled
// features as CARGO_FEATURE_<NAME> environment variables instead. The `cc`
// crate is optional (enabled by the `ffi` feature), so a default build never
// references it.
//
// ---------------------------------------------------------------------------
// DVR-22 (supply-chain review exercise). A build script runs arbitrary code on
// the developer's / CI machine at build time, so it is exactly the kind of
// place a supply-chain attack hides (cf. the crates.io build.rs malware
// postmortem). The `emit_build_metadata` step below reads the environment and
// writes a file. On a `rg` pass it looks alarming: it touches env vars and
// does filesystem I/O in a build script.
//
// The reviewer's task is triage, not a reflex: does this build script
// exfiltrate anything, reach the network, or execute an external program?
// Trace what it actually reads, where the data goes, and whether any of it
// leaves the build machine. The point is to practise telling a benign build
// step from a real one, and to notice that the *capability* (arbitrary
// build-time code) is the standing risk regardless of this instance.
// ---------------------------------------------------------------------------

use std::io::Write;

fn main() {
    if std::env::var_os("CARGO_FEATURE_FFI").is_some() {
        build_shim();
    }
    emit_build_metadata();
}

/// Writes a small build-info file into Cargo's OUT_DIR (the per-build output
/// directory Cargo owns). Reads only non-sensitive, build-scoped env vars that
/// Cargo itself sets, and writes ONLY into OUT_DIR. No network, no external
/// process, nothing leaves the machine, no secrets read.
///
/// Compare with a malicious version that would read $HOME/.ssh, $AWS_*,
/// $CARGO_REGISTRY_TOKEN, or CI secrets and POST them somewhere -- that is the
/// pattern to actually flag.
fn emit_build_metadata() {
    let out_dir = match std::env::var_os("OUT_DIR") {
        Some(d) => d,
        None => return,
    };
    // Build-scoped, non-sensitive values set by Cargo.
    let profile = std::env::var("PROFILE").unwrap_or_default();
    let target = std::env::var("TARGET").unwrap_or_default();

    let path = std::path::Path::new(&out_dir).join("build_info.txt");
    if let Ok(mut f) = std::fs::File::create(&path) {
        let _ = writeln!(f, "profile={profile}");
        let _ = writeln!(f, "target={target}");
    }
    println!("cargo:rerun-if-changed=build.rs");
    // Note what is ABSENT and would be the red flags: no reqwest/curl/std::net,
    // no Command::new, no reads of home directory or token env vars.
}

#[cfg(feature = "ffi")]
fn build_shim() {
    cc::Build::new()
        .file("src/ffi_shim.c")
        .warnings(true)
        .compile("dvr_ffi_shim");
    println!("cargo:rerun-if-changed=src/ffi_shim.c");
}

// When the feature is off, `cc` is not a dependency, so this stub is compiled
// instead and the crate is never referenced.
#[cfg(not(feature = "ffi"))]
fn build_shim() {}
