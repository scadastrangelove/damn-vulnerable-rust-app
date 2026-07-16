//! Upload intake.
//!
//! POST /upload
//!   header  x-declared-size: <n>   (client-declared payload size, bytes)
//!   header  x-repeat: <n>          (run-length expansion factor)
//!   body    the payload
//!
//! Two behaviours of interest: the handler pre-allocates a buffer from the
//! client-declared size, and it expands a run-length field by a client factor.

use crate::{App, Request, Response};

// A sane cap. The vulnerable handler ignores it; the fixed one enforces it.
const MAX_SIZE: usize = 1 << 20; // 1 MiB

pub fn handle(_app: &App, req: &Request) -> Response {
    let declared: usize = req
        .header("x-declared-size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);

    // Pre-size the receive buffer to what the client said it will send.
    let mut buf: Vec<u8> = Vec::with_capacity(declared);
    buf.extend_from_slice(&req.body);

    // Expand a small run-length payload by the client-provided factor.
    let repeat: usize = req.header("x-repeat").and_then(|s| s.parse().ok()).unwrap_or(1);
    let expanded = req.body.len().saturating_mul(repeat);

    Response::ok(format!("buffered={} expanded_to={}", buf.len(), expanded))
}

/// Enforce a hard cap on both the declared allocation and the expansion result
/// before touching memory.
pub fn fixed_handle(_app: &App, req: &Request) -> Response {
    let declared: usize = req
        .header("x-declared-size")
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    if declared > MAX_SIZE {
        return Response::err(413, "declared size too large");
    }

    let repeat: usize = req.header("x-repeat").and_then(|s| s.parse().ok()).unwrap_or(1);
    let expanded = req.body.len().saturating_mul(repeat);
    if expanded > MAX_SIZE {
        return Response::err(413, "expansion too large");
    }

    let mut buf: Vec<u8> = Vec::with_capacity(declared.min(req.body.len()));
    buf.extend_from_slice(&req.body);
    Response::ok(format!("buffered={} expanded_to={}", buf.len(), expanded))
}

/// The robust storage path referenced by `file_download`: never uses a
/// client-supplied name; stores under a generated id.
pub fn fixed_store(app: &App, _client_name: &str, seq: u64) -> String {
    // A generated, opaque id — no attacker-controlled path component.
    format!("{}/{:016x}.blob", app.config.upload_dir, seq)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(declared: &str, repeat: &str, body: Vec<u8>) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/upload".into(),
            query: vec![],
            headers: vec![
                ("x-declared-size".into(), declared.into()),
                ("x-repeat".into(), repeat.into()),
            ],
            body,
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn fixed_rejects_huge_declaration() {
        let app = App::new();
        let r = fixed_handle(&app, &req("999999999999", "1", vec![1, 2, 3]));
        assert_eq!(r.status, 413);
    }

    #[test]
    fn fixed_rejects_expansion_bomb() {
        let app = App::new();
        let r = fixed_handle(&app, &req("0", "999999999", vec![0u8; 64]));
        assert_eq!(r.status, 413);
    }
}
