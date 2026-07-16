//! Fetch a document by id.
//!
//! GET /documents/get?id=<n>
//!
//! Every authenticated principal may call this. The intended policy is that a
//! principal may read only documents they own (admins may read any).

use crate::{App, Request, Response};

pub fn handle(app: &App, req: &Request) -> Response {
    let id: u64 = match req.query_get("id").and_then(|s| s.parse().ok()) {
        Some(id) => id,
        None => return Response::err(400, "bad id"),
    };

    // Look up the document.
    let doc = app.db.documents.iter().find(|d| d.id == id);

    match doc {
        Some(d) => Response::ok(d.body.clone()),
        None => Response::err(404, "not found"),
    }
}

/// Enforce ownership at the point of access. Role (`is_admin`) is not the same
/// as per-object rights: a non-admin may read only their own documents.
pub fn fixed_handle(app: &App, req: &Request) -> Response {
    let id: u64 = match req.query_get("id").and_then(|s| s.parse().ok()) {
        Some(id) => id,
        None => return Response::err(400, "bad id"),
    };

    let doc = match app.db.documents.iter().find(|d| d.id == id) {
        Some(d) => d,
        None => return Response::err(404, "not found"),
    };

    // Deny by default unless owner or admin.
    if doc.owner != req.principal && !req.is_admin {
        return Response::err(403, "forbidden");
    }
    Response::ok(doc.body.clone())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(principal: &str, id: &str) -> Request {
        Request {
            principal: principal.into(),
            is_admin: false,
            path: "/documents/get".into(),
            query: vec![("id".into(), id.into())],
            headers: vec![],
            body: vec![],
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn alice_can_read_bobs_doc() {
        // Reachable IDOR: alice reads document 11, owned by bob.
        let app = App::new();
        let r = handle(&app, &req("alice", "11"));
        assert_eq!(r.body, "bob's private notes");
    }

    #[test]
    fn fixed_denies_cross_owner() {
        let app = App::new();
        let r = fixed_handle(&app, &req("alice", "11"));
        assert_eq!(r.status, 403);
    }
}
