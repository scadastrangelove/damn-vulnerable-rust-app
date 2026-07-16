//! Path-based access proxy.
//!
//! GET /proxy/fetch?path=<raw-path>
//!
//! A front guard (the "WAF") decides whether a request may proceed, then the
//! backend resolves the effective path and serves it. The guard blocks any path
//! that resolves under `/admin`.
//!
//! The security-relevant property is *parser equivalence*: the guard and the
//! backend must agree on what a given raw input means. When they normalize
//! differently, an input the guard considers safe can reach a resource the
//! backend considers privileged — a classic filter bypass.

use crate::{App, Request, Response};

/// Percent-decode one pass: `%2f` -> `/`, etc. Unknown/short escapes pass
/// through literally. This is a deliberately small decoder.
fn percent_decode_once(s: &str) -> String {
    let bytes = s.as_bytes();
    let mut out = String::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h * 16 + l) as u8) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

/// The guard's view: decode once, block if the result is under `/admin`.
fn waf_allows(raw: &str) -> bool {
    let decoded = percent_decode_once(raw);
    !normalize(&decoded).starts_with("/admin")
}

/// The backend's view: decode until stable (i.e. twice or more), THEN use.
/// This extra decode pass is the defect — the guard and backend disagree.
fn backend_effective_path(raw: &str) -> String {
    let once = percent_decode_once(raw);
    let twice = percent_decode_once(&once); // second pass: the divergence
    normalize(&twice)
}

/// Collapse `//` and resolve `.`/`..` lexically. Shared by both sides.
fn normalize(p: &str) -> String {
    let mut stack: Vec<&str> = Vec::new();
    for seg in p.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                stack.pop();
            }
            s => stack.push(s),
        }
    }
    format!("/{}", stack.join("/"))
}

pub fn handle(_app: &App, req: &Request) -> Response {
    let raw = req.query_get("path").unwrap_or("/");

    if !waf_allows(raw) {
        return Response::err(403, "blocked by policy");
    }

    // Guard said fine; backend resolves and serves.
    let effective = backend_effective_path(raw);
    Response::ok(format!("served: {}", effective))
}

/// Parser-equivalence fix: the guard and the backend MUST use the identical
/// normalization. Decode to a fixed point exactly once, in one place, and make
/// the policy decision on the same string the backend will use.
pub fn fixed_handle(_app: &App, req: &Request) -> Response {
    let raw = req.query_get("path").unwrap_or("/");

    // Single canonical form used for BOTH the decision and the resolution.
    let canonical = canonicalize(raw);
    if canonical.starts_with("/admin") {
        return Response::err(403, "blocked by policy");
    }
    Response::ok(format!("served: {}", canonical))
}

/// Decode to a fixed point (repeat until stable), then normalize. One function,
/// used everywhere, so no two components can disagree.
fn canonicalize(raw: &str) -> String {
    let mut cur = raw.to_string();
    for _ in 0..8 {
        let next = percent_decode_once(&cur);
        if next == cur {
            break;
        }
        cur = next;
    }
    normalize(&cur)
}

/// The deploy-gate invariant a WAF/edge actually needs: for every input, the
/// guard blocks iff the backend would reach the protected namespace. Any input
/// for which this returns false is a bypass. Exposed for differential fuzzing.
pub fn parser_equivalence_holds(raw: &str) -> bool {
    let guard_blocks = !waf_allows(raw);
    let backend_reaches_admin = backend_effective_path(raw).starts_with("/admin");
    guard_blocks == backend_reaches_admin
}

pub fn parser_equivalence_holds_fixed(raw: &str) -> bool {
    let canonical = canonicalize(raw);
    let guard_blocks = canonical.starts_with("/admin");
    let backend_reaches_admin = canonical.starts_with("/admin");
    guard_blocks == backend_reaches_admin
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(path: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/proxy/fetch".into(),
            query: vec![("path".into(), path.into())],
            headers: vec![],
            body: vec![],
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn direct_admin_is_blocked() {
        let app = App::new();
        assert_eq!(handle(&app, &req("/admin/keys")).status, 403);
    }

    #[test]
    fn double_encoded_admin_bypasses_guard() {
        // %252f -> (once) %2f -> (twice) '/'. Guard decodes once and sees
        // "/%2fadmin"... actually "%2fadmin" which does NOT start with /admin,
        // so it ALLOWS. Backend decodes twice and resolves to /admin/keys.
        let app = App::new();
        let r = handle(&app, &req("%252fadmin%252fkeys"));
        assert_eq!(r.status, 200);
        assert_eq!(r.body, "served: /admin/keys");
    }

    #[test]
    fn parser_equivalence_is_violated_by_that_input() {
        assert!(!parser_equivalence_holds("%252fadmin%252fkeys"));
    }

    #[test]
    fn fixed_blocks_the_bypass_and_preserves_invariant() {
        let app = App::new();
        assert_eq!(fixed_handle(&app, &req("%252fadmin%252fkeys")).status, 403);
        assert!(parser_equivalence_holds_fixed("%252fadmin%252fkeys"));
        assert!(parser_equivalence_holds_fixed("/admin/keys"));
        assert!(parser_equivalence_holds_fixed("/public/x"));
    }
}
