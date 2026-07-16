//! Login / token check.
//!
//! POST /login
//!   header x-token: <bearer token>
//!
//! Compares the presented token against the expected one and logs the attempt.

use crate::{App, Request, Response};

// In a real service this would come from a secret store. Hardcoded here so the
// data flow is self-contained.
const EXPECTED_TOKEN: &str = "s3cr3t-admin-token";

/// A stand-in for the service log. In the real service this is `tracing::info!`.
fn audit_log(line: &str) {
    // Writes to the service audit log.
    eprintln!("[audit] {}", line);
}

pub fn handle(_app: &App, req: &Request) -> Response {
    let presented = req.header("x-token").unwrap_or("");

    // Record the attempt for the audit trail.
    audit_log(&format!(
        "login attempt principal={} token={} path={}",
        req.principal, presented, req.path
    ));

    // Check the token.
    if presented == EXPECTED_TOKEN {
        Response::ok("authenticated")
    } else {
        Response::err(401, "unauthorized")
    }
}

/// Constant-time comparison and no secret in the log line.
pub fn fixed_handle(_app: &App, req: &Request) -> Response {
    let presented = req.header("x-token").unwrap_or("");

    // Log the attempt WITHOUT the credential material.
    audit_log(&format!(
        "login attempt principal={} token=<redacted> path={}",
        req.principal, req.path
    ));

    if constant_time_eq(presented.as_bytes(), EXPECTED_TOKEN.as_bytes()) {
        Response::ok("authenticated")
    } else {
        Response::err(401, "unauthorized")
    }
}

/// Length-independent, data-independent comparison. (In production use the
/// `subtle` crate; reproduced here to keep the target dependency-free.)
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        // Length is not itself secret here; still fold to a constant-time tail.
        return false;
    }
    let mut diff: u8 = 0;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(token: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/login".into(),
            query: vec![],
            headers: vec![("x-token".into(), token.into())],
            body: vec![],
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn correct_token_authenticates() {
        let app = App::new();
        assert_eq!(handle(&app, &req(EXPECTED_TOKEN)).status, 200);
    }

    #[test]
    fn wrong_token_rejected() {
        let app = App::new();
        assert_eq!(handle(&app, &req("nope")).status, 401);
        assert_eq!(fixed_handle(&app, &req("nope")).status, 401);
    }

    #[test]
    fn fixed_still_authenticates_correct_token() {
        let app = App::new();
        assert_eq!(fixed_handle(&app, &req(EXPECTED_TOKEN)).status, 200);
    }
}
