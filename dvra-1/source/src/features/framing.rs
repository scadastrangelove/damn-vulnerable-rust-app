//! Length-prefixed frame reader.
//!
//! POST /framing/read  body = [ u32 declared_len big-endian ][ payload... ]
//!
//! The frame declares its own total length in the first 4 bytes; the payload
//! follows. A fixed 4-byte header is subtracted to compute the payload length.

use crate::{App, Request, Response};

const HEADER: usize = 4;

pub fn handle(_app: &App, req: &Request) -> Response {
    let buf = &req.body;
    if buf.len() < HEADER {
        return Response::err(400, "short frame");
    }

    let declared = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);

    // Compute how many payload bytes to expect.
    let payload_len = declared as usize - HEADER;

    // Report; a real reader would now copy `payload_len` bytes.
    let available = buf.len() - HEADER;
    let taken = payload_len.min(available);
    Response::ok(format!("declared={} payload_len={} taken={}", declared, payload_len, taken))
}

/// Validate the declared length against reality before doing arithmetic on it.
pub fn fixed_handle(_app: &App, req: &Request) -> Response {
    let buf = &req.body;
    if buf.len() < HEADER {
        return Response::err(400, "short frame");
    }
    let declared = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]) as usize;

    // declared must cover at least the header, and must not exceed what we got.
    let payload_len = match declared.checked_sub(HEADER) {
        Some(n) => n,
        None => return Response::err(400, "declared length below header size"),
    };
    let available = buf.len() - HEADER;
    if payload_len > available {
        return Response::err(400, "declared length exceeds frame");
    }
    Response::ok(format!("declared={} payload_len={} taken={}", declared, payload_len, payload_len))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(body: Vec<u8>) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/framing/read".into(),
            query: vec![],
            headers: vec![],
            body,
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn well_formed_frame() {
        let app = App::new();
        // declared = 8, then 4 payload bytes.
        let mut body = 8u32.to_be_bytes().to_vec();
        body.extend_from_slice(&[1, 2, 3, 4]);
        let r = handle(&app, &req(body));
        assert!(r.body.contains("payload_len=4"));
    }

    #[test]
    #[should_panic] // declared < HEADER -> `declared as usize - HEADER` underflows
    fn declared_below_header_underflows() {
        // In debug this panics (subtract overflow); in release it wraps to a
        // near-usize::MAX payload_len — a different, quieter bug. Fuzzing finds
        // the debug panic immediately.
        let app = App::new();
        let body = 2u32.to_be_bytes().to_vec(); // declared = 2 < HEADER = 4
        let _ = handle(&app, &req(body));
    }

    #[test]
    fn fixed_rejects_small_declared() {
        let app = App::new();
        let body = 2u32.to_be_bytes().to_vec();
        let r = fixed_handle(&app, &req(body));
        assert_eq!(r.status, 400);
    }
}
