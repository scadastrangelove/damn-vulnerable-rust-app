//! Nested-expression parser.
//!
//! GET /parse/nested?expr=<...>
//!
//! Parses a toy grammar of nested brackets and returns the maximum nesting
//! depth: `[]` -> 1, `[[]]` -> 2, `[a][b]` -> 1, etc. The parser is a plain
//! recursive descent with no depth limit.

use crate::{App, Request, Response};

/// Parse from position `pos`, returning (depth_of_this_level, next_pos).
/// Recurses once per `[`. No depth guard: a deeply nested input recurses as
/// many frames as there are `[`, overflowing the stack.
fn parse_group(bytes: &[u8], pos: usize) -> (usize, usize) {
    let mut i = pos;
    let mut max_child = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => {
                let (child, next) = parse_group(bytes, i + 1); // unbounded recursion
                max_child = max_child.max(child);
                i = next;
            }
            b']' => {
                return (max_child + 1, i + 1);
            }
            _ => {
                i += 1;
            }
        }
    }
    (max_child, i)
}

pub fn handle(_app: &App, req: &Request) -> Response {
    let expr = req.query_get("expr").unwrap_or("");
    let (depth, _) = parse_group(expr.as_bytes(), 0);
    Response::ok(format!("depth={}", depth))
}

const MAX_DEPTH: usize = 128;

/// Same grammar, bounded. Reject once nesting exceeds a limit, before recursing
/// deeper. (An iterative counter would also work and avoids recursion entirely.)
pub fn fixed_handle(_app: &App, req: &Request) -> Response {
    let expr = req.query_get("expr").unwrap_or("");
    match parse_group_bounded(expr.as_bytes(), 0, 0) {
        Some((depth, _)) => Response::ok(format!("depth={}", depth)),
        None => Response::err(400, "nesting too deep"),
    }
}

fn parse_group_bounded(bytes: &[u8], pos: usize, depth: usize) -> Option<(usize, usize)> {
    if depth > MAX_DEPTH {
        return None;
    }
    let mut i = pos;
    let mut max_child = 0usize;
    while i < bytes.len() {
        match bytes[i] {
            b'[' => {
                let (child, next) = parse_group_bounded(bytes, i + 1, depth + 1)?;
                max_child = max_child.max(child);
                i = next;
            }
            b']' => return Some((max_child + 1, i + 1)),
            _ => i += 1,
        }
    }
    Some((max_child, i))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(expr: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/parse/nested".into(),
            query: vec![("expr".into(), expr.into())],
            headers: vec![],
            body: vec![],
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn shallow_nesting_ok() {
        let app = App::new();
        assert_eq!(handle(&app, &req("[[]]")).body, "depth=2");
        assert_eq!(handle(&app, &req("[a][b]")).body, "depth=1");
    }

    #[test]
    fn fixed_rejects_deep_nesting() {
        let app = App::new();
        let deep = "[".repeat(10_000);
        assert_eq!(fixed_handle(&app, &req(&deep)).status, 400);
    }

    // A sufficiently deep input overflows the stack (SIGABRT/SIGSEGV), which is
    // a process abort, not a catchable panic — so it cannot be a #[should_panic]
    // test without killing the test runner. A fuzzer finds it in seconds
    // (category `so` in the rust-fuzz trophy case). The bounded parser has no
    // such input. To observe the crash manually:
    //     cargo run -- (wire a very deep expr through the router)
    // Here we only assert the SHALLOW case matches between vulnerable and fixed.
    #[test]
    fn vulnerable_and_fixed_agree_on_shallow() {
        let app = App::new();
        let v = handle(&app, &req("[[[]]]")).body;
        let f = fixed_handle(&app, &req("[[[]]]")).body;
        assert_eq!(v, f);
    }
}
