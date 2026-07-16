//! Input validation endpoint.
//!
//! GET /validate?n=<number>
//!
//! Parses `n`, checks a range, and echoes it back. Contains an `.unwrap()` that
//! will show up in `rg '\.unwrap\('` triage.

use crate::{App, Request, Response};

pub fn handle(_app: &App, req: &Request) -> Response {
    let raw = req.query_get("n").unwrap_or("0");

    // Reject anything that is not all-ASCII-digits up front.
    if raw.is_empty() || !raw.bytes().all(|b| b.is_ascii_digit()) {
        return Response::err(400, "n must be a non-negative integer");
    }
    // Bound the length so the value fits in u64.
    if raw.len() > 19 {
        return Response::err(400, "n too large");
    }

    // SAFETY (logical): `raw` is non-empty, all ASCII digits, and <= 19 digits,
    // so it is always a valid u64. This unwrap cannot fire given the guards
    // above. (Reviewer: confirm the guards actually establish that.)
    let n: u64 = raw.parse().unwrap();

    Response::ok(format!("n={}", n))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(n: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/validate".into(),
            query: vec![("n".into(), n.into())],
            headers: vec![],
            body: vec![],
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn valid_number() {
        let app = App::new();
        assert_eq!(handle(&app, &req("123")).body, "n=123");
    }

    #[test]
    fn non_digit_rejected_before_unwrap() {
        let app = App::new();
        assert_eq!(handle(&app, &req("12x")).status, 400);
        assert_eq!(handle(&app, &req("-1")).status, 400);
        assert_eq!(handle(&app, &req("")).status, 400);
    }

    #[test]
    fn overlong_rejected_before_unwrap() {
        let app = App::new();
        // 20 nines would overflow u64; guard rejects at length 19.
        assert_eq!(handle(&app, &req(&"9".repeat(20))).status, 400);
    }
}
