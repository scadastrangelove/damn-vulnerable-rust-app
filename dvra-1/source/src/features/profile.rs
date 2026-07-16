//! Profile update.
//!
//! POST /profile/update  body = flat JSON object of fields to update
//!   e.g. {"display_name":"Alice","bio":"hi"}
//!
//! Applies the submitted fields to the caller's stored profile. Uses a tiny
//! hand-rolled parser for a flat string/bool JSON object (no external crates).

use crate::{App, Request, Response};

#[derive(Debug, Clone, PartialEq)]
pub struct Profile {
    pub display_name: String,
    pub bio: String,
    // Privileged fields the user must NOT be able to set via a profile update.
    pub is_admin: bool,
    pub role: String,
}

impl Default for Profile {
    fn default() -> Self {
        Profile {
            display_name: "alice".into(),
            bio: String::new(),
            is_admin: false,
            role: "user".into(),
        }
    }
}

/// Parse a flat JSON object into (key, value) string pairs. Values are read as
/// strings or the bare words true/false. Deliberately small; no nesting.
fn parse_flat_json(s: &str) -> Vec<(String, String)> {
    let s = s.trim();
    let inner = s
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .unwrap_or(s);
    let mut out = Vec::new();
    for pair in split_top_level(inner) {
        let mut it = pair.splitn(2, ':');
        let k = it.next().unwrap_or("").trim();
        let v = it.next().unwrap_or("").trim();
        let key = unquote(k);
        let val = unquote(v);
        if !key.is_empty() {
            out.push((key, val));
        }
    }
    out
}

fn split_top_level(inner: &str) -> Vec<String> {
    // Split on commas that are not inside quotes.
    let mut parts = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    for c in inner.chars() {
        match c {
            '"' => {
                in_str = !in_str;
                cur.push(c);
            }
            ',' if !in_str => {
                parts.push(std::mem::take(&mut cur));
            }
            _ => cur.push(c),
        }
    }
    if !cur.trim().is_empty() {
        parts.push(cur);
    }
    parts
}

fn unquote(s: &str) -> String {
    let s = s.trim();
    if s.len() >= 2 && s.starts_with('"') && s.ends_with('"') {
        s[1..s.len() - 1].to_string()
    } else {
        s.to_string()
    }
}

/// Apply every submitted field to the profile by name. This is the flaw: the
/// update loop trusts whatever keys the client sends, including `is_admin` and
/// `role`, so a profile update becomes a privilege escalation.
pub fn apply(profile: &mut Profile, body: &str) {
    for (key, val) in parse_flat_json(body) {
        match key.as_str() {
            "display_name" => profile.display_name = val,
            "bio" => profile.bio = val,
            "is_admin" => profile.is_admin = val == "true",
            "role" => profile.role = val,
            _ => {} // unknown fields ignored
        }
    }
}

/// Only the fields a user is allowed to change are read; privileged fields are
/// never sourced from the request. (An allow-list, not a deny-list.)
pub fn apply_fixed(profile: &mut Profile, body: &str) {
    for (key, val) in parse_flat_json(body) {
        match key.as_str() {
            "display_name" => profile.display_name = val,
            "bio" => profile.bio = val,
            // is_admin / role are NOT settable here, by construction.
            _ => {}
        }
    }
}

pub fn handle(_app: &App, req: &Request) -> Response {
    let mut profile = Profile::default();
    let body = String::from_utf8_lossy(&req.body);
    apply(&mut profile, &body);
    Response::ok(format!(
        "updated: name={} role={} admin={}",
        profile.display_name, profile.role, profile.is_admin
    ))
}

pub fn fixed_handle(_app: &App, req: &Request) -> Response {
    let mut profile = Profile::default();
    let body = String::from_utf8_lossy(&req.body);
    apply_fixed(&mut profile, &body);
    Response::ok(format!(
        "updated: name={} role={} admin={}",
        profile.display_name, profile.role, profile.is_admin
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(body: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/profile/update".into(),
            query: vec![],
            headers: vec![],
            body: body.as_bytes().to_vec(),
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn normal_update_changes_allowed_fields() {
        let app = App::new();
        let r = handle(&app, &req(r#"{"display_name":"Alice","bio":"hi"}"#));
        assert!(r.body.contains("name=Alice"));
        assert!(r.body.contains("admin=false"));
    }

    #[test]
    fn mass_assignment_escalates() {
        // Reachable privilege escalation: is_admin/role smuggled in the body.
        let app = App::new();
        let r = handle(&app, &req(r#"{"display_name":"x","is_admin":true,"role":"admin"}"#));
        assert!(r.body.contains("admin=true"));
        assert!(r.body.contains("role=admin"));
    }

    #[test]
    fn fixed_ignores_privileged_fields() {
        let app = App::new();
        let r = fixed_handle(&app, &req(r#"{"display_name":"x","is_admin":true,"role":"admin"}"#));
        assert!(r.body.contains("admin=false"));
        assert!(r.body.contains("role=user"));
    }
}
