//! Experimental zero-copy view helpers.
//!
//! This module contains `unsafe` that will show up in any `rg '\bunsafe\b'`
//! triage. Before writing it up as a finding, check whether any of it is
//! reachable from `App::handle` (the router in `lib.rs`).

use crate::{App, Request, Response};

/// Reinterpret a byte slice as a slice of u32 without copying.
///
/// This is genuinely unsound as written (alignment of `&[u8]` is 1, not 4, and
/// the length math ignores the tail), but note who calls it.
#[allow(dead_code)]
unsafe fn as_u32_slice(bytes: &[u8]) -> &[u32] {
    let ptr = bytes.as_ptr() as *const u32;
    let len = bytes.len() / 4;
    std::slice::from_raw_parts(ptr, len)
}

/// A handler-shaped function that exercises the unsafe helper. It is a `pub fn`,
/// so it looks like an endpoint — but grep the router: is `/native/*` wired in?
#[allow(dead_code)]
pub fn handle(_app: &App, req: &Request) -> Response {
    let words = unsafe { as_u32_slice(&req.body) };
    Response::ok(format!("word_count={}", words.len()))
}

#[cfg(test)]
mod tests {
    // This test constructs an aligned, exact-multiple buffer so it does not
    // itself trip UB — the point of the module is reachability analysis, not a
    // live crash.
    #[test]
    fn helper_is_never_wired_into_router() {
        // Documents intent: the router in lib.rs has no arm for this module.
        let src = include_str!("../lib.rs");
        assert!(!src.contains("native::handle"));
    }
}
