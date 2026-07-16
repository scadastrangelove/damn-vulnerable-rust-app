//! Batch record builder.
//!
//! POST /records/build  body = newline-separated record payloads
//!
//! Builds a Vec of parsed records. To avoid re-growing, the buffer is sized up
//! front and its length is set before the elements are actually written.

use crate::{App, Request, Response};

/// A record that owns a heap allocation (so an invalid/duplicated drop is a
/// real double-free / use-after-free, not just a logic slip).
#[derive(Debug)]
pub struct Record {
    #[allow(dead_code)]
    payload: String,
}

impl Record {
    /// Parse one line into a record. Returns Err on a line the parser rejects,
    /// which the builder below turns into a panic mid-construction.
    fn parse(line: &str) -> Result<Record, &'static str> {
        if line.starts_with('!') {
            return Err("rejected record");
        }
        Ok(Record { payload: line.to_string() })
    }
}

/// Build all records, pre-sizing the vector and setting its length before the
/// elements exist.
///
/// The flaw: `set_len(n)` makes the Vec believe it owns `n` initialized
/// `Record`s while the slots are still uninitialized. If `parse` panics partway
/// (here via `.expect`), the Vec is dropped during unwinding and runs
/// `Record::drop` over uninitialized memory — reading garbage `String`s and
/// freeing wild pointers. This is a panic-safety hole in an unsafe abstraction
/// (Rudra pattern #1), not a logic bug.
pub fn build(lines: &[&str]) -> Vec<Record> {
    let n = lines.len();
    let mut out: Vec<Record> = Vec::with_capacity(n);
    // Claim the slots as initialized before writing them.
    unsafe {
        out.set_len(n);
    }
    for (i, line) in lines.iter().enumerate() {
        // A panic here unwinds with `out` claiming n initialized elements.
        let rec = Record::parse(line).expect("record parse failed");
        out[i] = rec; // also: this assignment drops the (uninitialized) old slot
    }
    out
}

/// The safe version: never claim length before the element exists. `push` grows
/// the initialized region one element at a time, and `?` propagates the error
/// without leaving a half-built buffer in an unsound state.
pub fn build_fixed(lines: &[&str]) -> Result<Vec<Record>, &'static str> {
    let mut out: Vec<Record> = Vec::with_capacity(lines.len());
    for line in lines {
        out.push(Record::parse(line)?); // only initialized elements are ever in `out`
    }
    Ok(out)
}

pub fn handle(_app: &App, req: &Request) -> Response {
    let text = String::from_utf8_lossy(&req.body);
    let lines: Vec<&str> = text.lines().collect();
    let recs = build(&lines);
    Response::ok(format!("built={}", recs.len()))
}

pub fn fixed_handle(_app: &App, req: &Request) -> Response {
    let text = String::from_utf8_lossy(&req.body);
    let lines: Vec<&str> = text.lines().collect();
    match build_fixed(&lines) {
        Ok(recs) => Response::ok(format!("built={}", recs.len())),
        Err(e) => Response::err(400, e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(body: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/records/build".into(),
            query: vec![],
            headers: vec![],
            body: body.as_bytes().to_vec(),
            source: Source::PublicEdge,
        }
    }

    #[test]
    #[ignore = "vulnerable builder performs UB on ordinary execution; use Miri/heavy review gates"]
    fn all_valid_lines_build() {
        let app = App::new();
        // Even without rejected lines, assignment into slots claimed with
        // set_len drops uninitialized old values. Some allocators let this
        // appear to work; others abort. Keep this out of the default suite.
        assert_eq!(handle(&app, &req("a\nb\nc")).body, "built=3");
    }

    #[test]
    fn fixed_returns_error_without_unsound_state() {
        let app = App::new();
        // A "!"-prefixed line is rejected; the fixed builder returns 400 and
        // never constructs an unsound Vec.
        assert_eq!(fixed_handle(&app, &req("a\n!bad\nc")).status, 400);
        assert_eq!(fixed_handle(&app, &req("a\nb")).body, "built=2");
    }

    // The unsound path: a "!"-line makes `parse` fail, `expect` panics, and the
    // Vec (which claims n initialized Records via set_len) is dropped during
    // unwinding over uninitialized memory -> UB (drop of invalid String).
    //
    // This is NOT reliably a visible crash under plain `cargo test` (it may
    // "work" by luck, or corrupt the heap silently), which is exactly why
    // panic-safety bugs in unsafe need Miri. Gated so it only runs under Miri:
    //     cargo +nightly miri test records
    #[cfg(miri)]
    #[test]
    fn panic_midway_is_ub_caught_by_miri() {
        // catch_unwind so the test process itself survives to let Miri report;
        // Miri flags the invalid drop during unwinding regardless.
        let _ = std::panic::catch_unwind(|| {
            let lines = ["ok", "!reject", "ok2"];
            let _ = build(&lines);
        });
    }
}
