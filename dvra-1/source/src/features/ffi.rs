//! FFI tier — the failure modes at a C ABI boundary (an nginx/Pingora-style
//! host). Compiled only with `--features ffi`, which also builds `ffi_shim.c`.
//!
//! Three planted issues here, all §7:
//!   * DVR-16  a panic unwinding across the C boundary (plain "C" ABI = UB)
//!   * DVR-17  a host request refcount leaked on an early-return path
//!   * DVR-18  a length taken from C and trusted into slice::from_raw_parts
//!
//! Everything is behind `handle_ffi`, which is wired into the router only when
//! the feature is on. Educational only. Not for production.

// The `*_fixed` reference implementations are exercised by tests; in a plain
// (non-test) build with the feature on they are unused by design.
#![allow(dead_code)]

use crate::{App, Request, Response};
use std::os::raw::c_int;

#[repr(C)]
pub struct HostRequest {
    pub count: c_int,
    pub completed: c_int,
}

type RustBodyCb = extern "C" fn(*const u8, usize) -> c_int;

extern "C" {
    fn host_dispatch(cb: RustBodyCb, data: *const u8, len: usize) -> c_int;
    fn host_ref(r: *mut HostRequest);
    fn host_finish(r: *mut HostRequest);
}

// ---------------------------------------------------------------------------
// DVR-16: unwind across the FFI boundary.
//
// This callback is handed to C with the plain "C" ABI. If body validation
// fails it panics. When the panic unwinds back through `host_dispatch` (a C
// frame), behaviour is undefined; in practice it aborts the worker — a
// single crafted request takes down the whole process.
// ---------------------------------------------------------------------------
extern "C" fn body_cb(data: *const u8, len: usize) -> c_int {
    // SAFETY: pointer/len come straight from the host_dispatch call below.
    let bytes = unsafe { std::slice::from_raw_parts(data, len) };
    // A validation failure panics instead of returning an error code.
    assert!(bytes.first() == Some(&b'{'), "body must be JSON object");
    bytes.len() as c_int
}

/// The fix: never let a Rust panic cross into C. Catch it at the boundary and
/// translate to an error code (or declare `extern "C-unwind"` deliberately if
/// the host truly supports unwinding, which nginx does not).
extern "C" fn body_cb_fixed(data: *const u8, len: usize) -> c_int {
    let result = std::panic::catch_unwind(|| {
        let bytes = unsafe { std::slice::from_raw_parts(data, len) };
        if bytes.first() != Some(&b'{') {
            return -1;
        }
        bytes.len() as c_int
    });
    result.unwrap_or(-1)
}

// ---------------------------------------------------------------------------
// DVR-17: host request refcount leaked on an early return.
//
// The host increments the request's refcount before the module runs; the
// module must decrement it on EVERY exit path so the request can complete.
// The error path below returns without decrementing — the request leaks
// (this is the nginx `r->main->count` class bug: a missing decrement on one
// branch keeps the connection alive forever).
// ---------------------------------------------------------------------------
fn handle_request(r: *mut HostRequest, body: &[u8]) -> Response {
    unsafe { host_ref(r) }; // count -> 1, we now owe one decrement

    if body.is_empty() {
        // Early return: forgot to decrement. Refcount stays at 1; the host
        // never sees `count == 0`, so `completed` is never set.
        return Response::err(400, "empty body");
    }

    // Normal path: balance the count.
    unsafe {
        (*r).count -= 1;
        host_finish(r);
    }
    Response::ok(format!("processed {} bytes", body.len()))
}

/// The fix: decrement on every path. A guard type whose `Drop` decrements is
/// the idiomatic way — it fires on early return AND on panic/unwind.
fn handle_request_fixed(r: *mut HostRequest, body: &[u8]) -> Response {
    struct RefGuard(*mut HostRequest);
    impl Drop for RefGuard {
        fn drop(&mut self) {
            unsafe {
                (*self.0).count -= 1;
                host_finish(self.0);
            }
        }
    }

    unsafe { host_ref(r) };
    let _guard = RefGuard(r); // decrements on every exit, including early return

    if body.is_empty() {
        return Response::err(400, "empty body");
    }
    Response::ok(format!("processed {} bytes", body.len()))
}

// ---------------------------------------------------------------------------
// DVR-18: length from C trusted into from_raw_parts.
//
// `declared_len` arrives from the host (here, an `x-c-len` header standing in
// for a value the C side computed). It is fed straight into from_raw_parts
// without checking it against the actual buffer length -> out-of-bounds read.
// ---------------------------------------------------------------------------
fn read_c_buffer(data: *const u8, actual_len: usize, declared_len: usize) -> u64 {
    // Trusts declared_len; a value > actual_len reads out of bounds.
    let view = unsafe { std::slice::from_raw_parts(data, declared_len) };
    let _ = actual_len; // ignored — that is the bug
    view.iter().map(|&b| b as u64).sum()
}

fn read_c_buffer_fixed(data: *const u8, actual_len: usize, declared_len: usize) -> u64 {
    let n = declared_len.min(actual_len); // never trust the C-supplied length
    let view = unsafe { std::slice::from_raw_parts(data, n) };
    view.iter().map(|&b| b as u64).sum()
}

/// Router entry for the FFI tier (wired only under `--features ffi`).
pub fn handle(_app: &App, req: &Request) -> Response {
    // Dispatch the body through the C host, which calls back into `body_cb`.
    let rc = unsafe { host_dispatch(body_cb, req.body.as_ptr(), req.body.len()) };

    // Manage the host request refcount around processing.
    let mut hr = HostRequest { count: 0, completed: 0 };
    let _ = handle_request(&mut hr as *mut _, &req.body);

    // Read a C-declared buffer length.
    let declared: usize = req
        .header("x-c-len")
        .and_then(|s| s.parse().ok())
        .unwrap_or(req.body.len());
    let sum = read_c_buffer(req.body.as_ptr(), req.body.len(), declared);

    Response::ok(format!("rc={} sum={}", rc, sum))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fixed_callback_returns_error_instead_of_unwinding() {
        // Non-JSON body: the fixed callback returns -1 rather than panicking
        // across the boundary.
        let data = b"not json";
        assert_eq!(body_cb_fixed(data.as_ptr(), data.len()), -1);
        let ok = b"{ok}";
        assert_eq!(body_cb_fixed(ok.as_ptr(), ok.len()), 4);
    }

    #[test]
    fn fixed_refcount_balances_on_early_return() {
        // Empty body takes the early-return path; the guarded version still
        // decrements, so the host sees completion.
        let mut hr = HostRequest { count: 0, completed: 0 };
        unsafe { host_ref(&mut hr as *mut _) };
        // Simulate: the guard in handle_request_fixed will bring count to 0.
        let mut hr2 = HostRequest { count: 0, completed: 0 };
        let _ = handle_request_fixed(&mut hr2 as *mut _, b"");
        assert_eq!(hr2.count, 0);
        assert_eq!(hr2.completed, 1);
        // And the vulnerable version leaks on the same input:
        let mut hr3 = HostRequest { count: 0, completed: 0 };
        let _ = handle_request(&mut hr3 as *mut _, b"");
        assert_eq!(hr3.count, 1); // leaked
        assert_eq!(hr3.completed, 0);
        let _ = &mut hr;
    }

    #[test]
    fn fixed_read_clamps_declared_length() {
        let data = [1u8, 2, 3, 4];
        // Declared far larger than actual; fixed clamps and stays in bounds.
        assert_eq!(read_c_buffer_fixed(data.as_ptr(), data.len(), 999), 10);
    }

    // The vulnerable read_c_buffer with declared > actual is an OOB read: UB,
    // caught by Miri/ASan, not a guaranteed panic. Miri does not run the C shim,
    // so exercise this function directly under Miri:
    //     cargo +nightly miri test --features ffi read_c_buffer_ub
    // (Miri intercepts from_raw_parts bounds; the C functions are not called
    // in this test.)
    #[cfg(miri)]
    #[test]
    fn read_c_buffer_ub_caught_by_miri() {
        let data = [1u8, 2, 3, 4];
        let _ = read_c_buffer(data.as_ptr(), data.len(), 64);
    }
}
