//! A tiny in-memory data store with a naive query interpreter.
//!
//! There is no real SQL engine here (the target must compile with no network
//! and no DB). Instead, `query_users` parses a SQL-ish string well enough that
//! classic string-concatenation injection actually changes the result set — so
//! the injection in `features::user_search` is genuinely reachable, not a
//! cosmetic pattern match. The interpreter is intentionally permissive.

#[derive(Clone, Debug)]
pub struct User {
    pub id: u64,
    pub username: String,
    pub is_admin: bool,
    /// A value the app treats as sensitive and never intends to expose.
    pub password_hash: String,
}

#[derive(Clone, Debug)]
pub struct Document {
    pub id: u64,
    pub owner: String,
    pub body: String,
}

pub struct Db {
    pub users: Vec<User>,
    pub documents: Vec<Document>,
}

impl Db {
    pub fn seed() -> Self {
        let users = vec![
            User { id: 1, username: "alice".into(), is_admin: false, password_hash: "argon2:alice".into() },
            User { id: 2, username: "bob".into(), is_admin: false, password_hash: "argon2:bob".into() },
            User { id: 3, username: "root".into(), is_admin: true, password_hash: "argon2:root-secret".into() },
        ];
        let documents = vec![
            Document { id: 10, owner: "alice".into(), body: "alice's private notes".into() },
            Document { id: 11, owner: "bob".into(), body: "bob's private notes".into() },
            Document { id: 12, owner: "root".into(), body: "root's private notes".into() },
        ];
        Db { users, documents }
    }

    /// Run a SQL-ish query and return matching users.
    ///
    /// Supports exactly enough to be injectable:
    ///   SELECT ... FROM users WHERE username = '<...>'
    /// The predicate after `WHERE` is evaluated by `eval_predicate`, which
    /// understands `col = 'literal'` and `OR` / `AND` of such terms, plus the
    /// tautology `'x'='x'`. That means a crafted `username` that closes the
    /// quote and appends `OR '1'='1'` returns every row.
    pub fn query_users(&self, sql: &str) -> Vec<User> {
        let lower = sql.to_ascii_lowercase();
        let where_pos = match lower.find("where ") {
            Some(p) => p + "where ".len(),
            None => return self.users.clone(),
        };
        let predicate = &sql[where_pos..];
        self.users
            .iter()
            .filter(|u| eval_predicate(predicate, u))
            .cloned()
            .collect()
    }
}

/// Evaluate a very small boolean predicate grammar against a user row.
fn eval_predicate(pred: &str, user: &User) -> bool {
    // Split on OR (lowest precedence), then AND, case-insensitively.
    let pred = pred.trim().trim_end_matches(';').trim();
    split_ci(pred, " or ")
        .iter()
        .any(|or_term| split_ci(or_term, " and ").iter().all(|and_term| eval_term(and_term.trim(), user)))
}

/// Case-insensitive split on a keyword, preserving the original-case fragments
/// (so quoted literals keep their case).
fn split_ci(hay: &str, needle_lc: &str) -> Vec<String> {
    let hay_lc = hay.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut start = 0usize;
    let mut search_from = 0usize;
    while let Some(rel) = hay_lc[search_from..].find(needle_lc) {
        let at = search_from + rel;
        out.push(hay[start..at].to_string());
        start = at + needle_lc.len();
        search_from = start;
    }
    out.push(hay[start..].to_string());
    out
}

fn eval_term(term: &str, user: &User) -> bool {
    // Forms handled: `col = 'value'`, `'a'='b'`.
    let mut parts = term.splitn(2, '=');
    let lhs = parts.next().unwrap_or("").trim();
    let rhs = match parts.next() {
        Some(r) => r.trim(),
        None => return false,
    };
    let rhs_val = unquote(rhs);

    match unquote_opt(lhs) {
        // Left side is a quoted literal: literal = literal comparison.
        Some(lhs_val) => lhs_val == rhs_val,
        // Left side is a column name.
        None => match lhs.to_ascii_lowercase().as_str() {
            "username" => user.username == rhs_val,
            "id" => user.id.to_string() == rhs_val,
            "is_admin" => (user.is_admin as u8).to_string() == rhs_val,
            _ => false,
        },
    }
}

fn unquote(s: &str) -> String {
    unquote_opt(s).unwrap_or_else(|| s.to_string())
}

fn unquote_opt(s: &str) -> Option<String> {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('\'') && s.ends_with('\'') {
        Some(s[1..s.len() - 1].to_string())
    } else {
        None
    }
}
