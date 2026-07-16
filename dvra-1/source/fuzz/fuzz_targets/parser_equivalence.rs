// Differential / invariant fuzz target for the parser-equivalence property.
//
// SCAFFOLD — nightly + cargo-fuzz. Add a [[bin]] for it in fuzz/Cargo.toml.
//
//     cargo +nightly fuzz run parser_equivalence
//
// This does not look for a crash. It asserts the deploy-gate invariant a WAF
// needs: the guard blocks a request IFF the backend would reach the protected
// namespace. On the vulnerable code this fails almost immediately (e.g. a
// double-percent-encoded input the guard allows but the backend resolves to
// /admin). Repointing `parser_equivalence_holds` at the fixed implementation
// makes the target pass — which is what "parser equivalence proven" means as a
// gate.
//
// This mirrors the real invariant:  hard_block  <=>  backend_reaches_protected

#![no_main]

use libfuzzer_sys::fuzz_target;
use dvr::features::proxy;

fuzz_target!(|raw: &str| {
    // Vulnerable: this assertion is violated by double-encoded inputs.
    assert!(
        proxy::parser_equivalence_holds(raw),
        "parser-equivalence bypass: guard and backend disagree on {:?}",
        raw
    );

    // Swap to the fixed implementation to demonstrate the gate passing:
    // assert!(proxy::parser_equivalence_holds_fixed(raw));
});
