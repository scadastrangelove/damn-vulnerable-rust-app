//! Echo a truncated preview of a header value.
//!
//! GET /headers/echo?h=<header-name>
//!
//! Returns the first up-to-16 bytes of the named header, for logging previews.

use crate::{App, Request, Response};

const PREVIEW: usize = 16;

pub fn handle(_app: &App, req: &Request) -> Response {
    let name = req.query_get("h").unwrap_or("x-preview");
    let value = req.header(name).unwrap_or("");

    // Take a short preview of the value.
    let end = value.len().min(PREVIEW);
    let preview = &value[..end]; // byte slice into a &str

    Response::ok(format!("preview: {}", preview))
}

/// Slice on a character boundary instead of a raw byte offset.
pub fn fixed_handle(_app: &App, req: &Request) -> Response {
    let name = req.query_get("h").unwrap_or("x-preview");
    let value = req.header(name).unwrap_or("");

    let preview: String = value.chars().take(PREVIEW).collect();
    Response::ok(format!("preview: {}", preview))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req_with_header(value: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/headers/echo".into(),
            query: vec![("h".into(), "x-note".into())],
            headers: vec![("x-note".into(), value.into())],
            body: vec![],
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn ascii_preview_is_fine() {
        let app = App::new();
        let r = handle(&app, &req_with_header("hello world this is long"));
        assert_eq!(r.body, "preview: hello world this");
    }

    #[test]
    #[should_panic] // byte 16 lands inside a multi-byte char
    fn multibyte_preview_panics() {
        // 15 ASCII bytes then a 2-byte 'é' straddling the 16-byte cut.
        let app = App::new();
        let value = format!("{}{}", "a".repeat(15), "é");
        let _ = handle(&app, &req_with_header(&value));
    }

    #[test]
    fn fixed_handles_multibyte() {
        let app = App::new();
        let value = format!("{}{}", "a".repeat(15), "é");
        let r = fixed_handle(&app, &req_with_header(&value));
        assert!(r.body.starts_with("preview: "));
    }
}
