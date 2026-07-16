//! User search by username.
//!
//! GET /users/search?username=<name>

use crate::{App, Request, Response};

pub fn handle(app: &App, req: &Request) -> Response {
    let username = req.query_get("username").unwrap_or("");

    // Build the lookup query from the incoming username.
    let query = format!(
        "SELECT id, username FROM users WHERE username = '{}'",
        username
    );

    let rows = app.db.query_users(&query);
    let names: Vec<String> = rows.into_iter().map(|u| u.username).collect();
    Response::ok(format!("matches: {}", names.join(",")))
}

/// Parameterised equivalent. The store's `query_users` is a string interpreter
/// for demo purposes, so the "safe" path here filters in Rust rather than
/// interpolating the value into the query text at all.
pub fn fixed_handle(app: &App, req: &Request) -> Response {
    let username = req.query_get("username").unwrap_or("");
    let names: Vec<String> = app
        .db
        .users
        .iter()
        .filter(|u| u.username == username)
        .map(|u| u.username.clone())
        .collect();
    Response::ok(format!("matches: {}", names.join(",")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(username: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/users/search".into(),
            query: vec![("username".into(), username.into())],
            headers: vec![],
            body: vec![],
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn normal_lookup_returns_one() {
        let app = App::new();
        let r = handle(&app, &req("alice"));
        assert_eq!(r.body, "matches: alice");
    }

    #[test]
    fn injection_returns_every_row() {
        // Closes the quote and appends a tautology.
        let app = App::new();
        let r = handle(&app, &req("' OR '1'='1"));
        assert!(r.body.contains("alice") && r.body.contains("bob") && r.body.contains("root"));
    }

    #[test]
    fn fixed_resists_injection() {
        let app = App::new();
        let r = fixed_handle(&app, &req("' OR '1'='1"));
        assert_eq!(r.body, "matches: ");
    }
}
