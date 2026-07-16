//! Byte collection over a pluggable source.
//!
//! GET /collect  (reads x-len header + body)
//!
//! `ByteSource` is a *safe* trait. `read_all` is a small `unsafe` helper that
//! builds a slice from a source's data pointer and its advertised length. The
//! helper trusts the trait's contract that `advertised_len() <= data().len()`.
//!
//! The review question is the one behind most stdlib soundness CVEs: is the
//! `unsafe` sound for EVERY possible impl of the safe trait, or only for the
//! well-behaved ones? A safe trait method may return anything, including a lie.

use crate::{App, Request, Response};

/// A source of bytes. SAFE trait — anyone may implement it, and impls are not
/// required to be "reasonable" beyond the documented contract.
///
/// Contract (documented, not enforced): `advertised_len() <= data().len()`.
pub trait ByteSource {
    fn data(&self) -> &[u8];
    fn advertised_len(&self) -> usize;
}

/// Sum the advertised bytes of a source.
///
/// SAFETY (as written): assumes `src.advertised_len() <= src.data().len()`,
/// per the `ByteSource` contract, so the constructed slice is in bounds.
///
/// This is the flaw: the safety of an `unsafe` block must not rest on a *safe*
/// trait method behaving. `advertised_len` can return anything.
pub unsafe fn read_all<S: ByteSource>(src: &S) -> u64 {
    let data = src.data();
    let n = src.advertised_len();
    // Trusts `n <= data.len()`. If an impl lies, this is an out-of-bounds read.
    let view = std::slice::from_raw_parts(data.as_ptr(), n);
    view.iter().map(|&b| b as u64).sum()
}

/// A sound wrapper: clamp the advertised length to reality before trusting it.
/// Now `read_all_safe` holds for every impl, honest or not.
pub fn read_all_safe<S: ByteSource>(src: &S) -> u64 {
    let data = src.data();
    let n = src.advertised_len().min(data.len());
    data[..n].iter().map(|&b| b as u64).sum()
}

/// The source used on the request path. Its advertised length comes from the
/// `x-len` header — so an attacker controls whether the contract is honoured.
struct RequestSource<'a> {
    body: &'a [u8],
    advertised: usize,
}

impl<'a> ByteSource for RequestSource<'a> {
    fn data(&self) -> &[u8] {
        self.body
    }
    fn advertised_len(&self) -> usize {
        // Attacker-controlled: may exceed body.len().
        self.advertised
    }
}

pub fn handle(_app: &App, req: &Request) -> Response {
    let advertised = req
        .header("x-len")
        .and_then(|s| s.parse().ok())
        .unwrap_or(req.body.len());

    let src = RequestSource { body: &req.body, advertised };

    // The unsafe helper trusts the (attacker-influenced) advertised length.
    let sum = unsafe { read_all(&src) };
    Response::ok(format!("sum={}", sum))
}

pub fn fixed_handle(_app: &App, req: &Request) -> Response {
    let advertised = req
        .header("x-len")
        .and_then(|s| s.parse().ok())
        .unwrap_or(req.body.len());
    let src = RequestSource { body: &req.body, advertised };
    let sum = read_all_safe(&src);
    Response::ok(format!("sum={}", sum))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(len_header: Option<&str>, body: Vec<u8>) -> Request {
        let headers = match len_header {
            Some(v) => vec![("x-len".to_string(), v.to_string())],
            None => vec![],
        };
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/collect".into(),
            query: vec![],
            headers,
            body,
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn honest_length_is_fine() {
        let app = App::new();
        // No x-len -> advertised defaults to body.len(): contract honoured.
        let r = handle(&app, &req(None, vec![1, 2, 3, 4]));
        assert_eq!(r.body, "sum=10");
    }

    #[test]
    fn fixed_clamps_a_lying_length() {
        let app = App::new();
        // x-len way past the body; the sound version clamps and stays in bounds.
        let r = fixed_handle(&app, &req(Some("1000000"), vec![1, 2, 3, 4]));
        assert_eq!(r.body, "sum=10");
    }

    // The unsound path (x-len > body.len()) is an out-of-bounds read: undefined
    // behaviour, NOT a guaranteed panic. A plain `cargo test` may read garbage
    // or appear to pass, which is exactly why this class needs Miri. This test
    // only compiles under Miri, where the UB is caught deterministically:
    //     cargo +nightly miri test
    #[cfg(miri)]
    #[test]
    fn lying_length_is_ub_caught_by_miri() {
        let app = App::new();
        // Miri aborts with an out-of-bounds error inside read_all.
        let _ = handle(&app, &req(Some("64"), vec![1, 2, 3, 4]));
    }
}
