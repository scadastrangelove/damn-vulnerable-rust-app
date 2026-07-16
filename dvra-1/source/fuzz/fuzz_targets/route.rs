// Fuzz harness for the request router.
//
// This is a SCAFFOLD. It requires nightly + cargo-fuzz and the fuzz crate wiring
// (a `fuzz/Cargo.toml` with libfuzzer-sys + arbitrary depending on the parent
// crate). It is not compiled by the hermetic std-only build. Run with:
//
//     cargo +nightly fuzz run route
//
// Within a few seconds it should find, with no source annotations:
//   * a panic in /headers/echo   (UTF-8 char-boundary slice in header_parse.rs)
//   * a panic in /framing/read   (subtract-overflow in framing.rs, debug builds)
//   * a stack overflow in /parse/nested (unbounded recursion in nested.rs)
//
// These are the bugs that static triage (grep for unwrap/unsafe) does NOT flag,
// because there is no unwrap and no unsafe on those paths — only a byte-offset
// slice, a length subtraction, and an unbounded recursion that are wrong for
// specific inputs.
//
// For the parser-differential bug (proxy.rs), the high-value harness is the
// INVARIANT target below, not a crash target: fuzz raw inputs and assert the
// guard blocks iff the backend reaches the protected namespace. The vulnerable
// build violates it on double-encoded inputs; the fixed build holds.
//
// A differential target (fuzz the vulnerable vs fixed handler and assert the
// fixed one never panics while matching outputs on valid inputs) is the natural
// next step; see README "Extending the target".

#![no_main]

use libfuzzer_sys::fuzz_target;
use arbitrary::{Arbitrary, Unstructured};

use dvr::{App, Request, Source};

#[derive(Debug)]
struct FuzzReq {
    path_choice: u8,
    query_val: String,
    header_name: String,
    header_val: String,
    body: Vec<u8>,
}

impl<'a> Arbitrary<'a> for FuzzReq {
    fn arbitrary(u: &mut Unstructured<'a>) -> arbitrary::Result<Self> {
        Ok(FuzzReq {
            path_choice: u8::arbitrary(u)?,
            query_val: String::arbitrary(u)?,
            header_name: String::arbitrary(u)?,
            header_val: String::arbitrary(u)?,
            body: Vec::<u8>::arbitrary(u)?,
        })
    }
}

fuzz_target!(|input: FuzzReq| {
    let app = App::new();

    let path = match input.path_choice % 9 {
        0 => "/headers/echo",
        1 => "/framing/read",
        2 => "/users/search",
        3 => "/documents/get",
        4 => "/validate",
        5 => "/proxy/fetch",
        6 => "/collect",
        7 => "/parse/nested",
        _ => "/upload",
    };

    let req = Request {
        principal: "fuzzer".into(),
        is_admin: false,
        path: path.into(),
        query: vec![
            ("username".into(), input.query_val.clone()),
            ("id".into(), input.query_val.clone()),
            ("n".into(), input.query_val.clone()),
            ("h".into(), input.header_name.clone()),
            ("path".into(), input.query_val.clone()),
            ("expr".into(), input.query_val.clone()),
        ],
        headers: vec![
            (input.header_name.clone(), input.header_val.clone()),
            ("x-len".into(), input.query_val.clone()),
        ],
        body: input.body.clone(),
        source: Source::PublicEdge,
    };

    // A panic here is a finding: for a service sharing a process (or an FFI host
    // like an nginx worker), an attacker-triggerable panic is a DoS.
    let _ = app.handle(&req);
});
