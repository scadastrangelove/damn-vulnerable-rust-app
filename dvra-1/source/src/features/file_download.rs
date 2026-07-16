//! File download from the upload directory.
//!
//! GET /files/download?name=<filename>
//!
//! Returns the resolved on-disk path the service *would* read. (It does not read
//! the file, to keep the target hermetic — the reachable defect is that the
//! resolved path can escape `upload_dir`.)

use crate::{App, Request, Response};
use std::path::{Component, Path, PathBuf};

pub fn handle(app: &App, req: &Request) -> Response {
    let name = req.query_get("name").unwrap_or("");
    let base = Path::new(&app.config.upload_dir);

    // Join the user-supplied name onto the upload directory and serve it.
    let full = base.join(name);

    Response::ok(format!("serving: {}", full.display()))
}

/// A safer resolution: reject any name that is absolute or contains parent
/// (`..`) components, then confirm the lexical result stays within `base`.
///
/// NOTE (see ANSWER_KEY): even this is not fully safe against symlinks or a
/// TOCTOU race between the check and a later open(); the robust fix is to never
/// use the client name for the path at all and store under a generated id
/// (see `features::upload::fixed_store`).
pub fn fixed_handle(app: &App, req: &Request) -> Response {
    let name = req.query_get("name").unwrap_or("");
    let base = Path::new(&app.config.upload_dir);

    let candidate = Path::new(name);
    let rejected = candidate.is_absolute()
        || candidate
            .components()
            .any(|c| matches!(c, Component::ParentDir | Component::RootDir));
    if rejected {
        return Response::err(400, "invalid name");
    }

    let full: PathBuf = base.join(candidate);
    if !full.starts_with(base) {
        return Response::err(400, "invalid name");
    }
    Response::ok(format!("serving: {}", full.display()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(name: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/files/download".into(),
            query: vec![("name".into(), name.into())],
            headers: vec![],
            body: vec![],
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn traversal_escapes_upload_dir() {
        let app = App::new();
        let r = handle(&app, &req("../../etc/passwd"));
        // The resolved path contains parent traversal that an actual open()
        // would follow out of the upload directory. The vulnerable handler does
        // no normalization or containment check, so the `..` survives into the
        // path that would be opened.
        assert!(r.body.contains("../../etc/passwd"));
        // Sanity: the fixed handler would have rejected this exact input.
        assert_eq!(fixed_handle(&app, &req("../../etc/passwd")).status, 400);
    }

    #[test]
    fn fixed_rejects_traversal() {
        let app = App::new();
        let r = fixed_handle(&app, &req("../../etc/passwd"));
        assert_eq!(r.status, 400);
    }
}
