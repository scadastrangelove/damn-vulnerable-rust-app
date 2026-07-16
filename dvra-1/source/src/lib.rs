//! Damn Vulnerable Rust — a training target for security code review.
//!
//! This crate models the request-handling surface of a small internal service.
//! It is deliberately insecure in places. Some of the insecure-looking code is
//! genuinely exploitable; some is a decoy that is not reachable by an attacker;
//! some is only triggerable by fuzzing; and some is only a vulnerability under a
//! particular threat model. The reviewer's job is to tell them apart.
//!
//! There are NO "// VULN HERE" markers in the feature code. Read the threat
//! model in `README.md` before reviewing — several verdicts depend on it.
//! Benchmark labels are intentionally kept separate from learner-facing source.
//!
//! SECURITY: do not deploy. Do not expose to a network. Educational use only.

pub mod db;
pub mod features;

/// A parsed, already-authenticated request as it reaches feature handlers.
///
/// `principal` is the caller's identity as established by the (out-of-scope)
/// auth layer. `is_admin` reflects role, not per-object rights. `body` is the
/// raw request body; `query` and `headers` are attacker-controlled key/value
/// data. `source` records where the request entered from — this matters for
/// threat-model-dependent findings (see `features::hooks`).
#[derive(Clone, Debug)]
pub struct Request {
    pub principal: String,
    pub is_admin: bool,
    pub path: String,
    pub query: Vec<(String, String)>,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    pub source: Source,
}

/// Where a request originated. The public edge is fully attacker-controlled;
/// the internal mesh is trusted-by-assumption in the stated threat model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    PublicEdge,
    InternalMesh,
}

impl Request {
    pub fn query_get(&self, key: &str) -> Option<&str> {
        self.query
            .iter()
            .find(|(k, _)| k == key)
            .map(|(_, v)| v.as_str())
    }

    pub fn header(&self, key: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(key))
            .map(|(_, v)| v.as_str())
    }
}

#[derive(Debug)]
pub struct Response {
    pub status: u16,
    pub body: String,
}

impl Response {
    pub fn ok(body: impl Into<String>) -> Self {
        Response { status: 200, body: body.into() }
    }
    pub fn err(status: u16, body: impl Into<String>) -> Self {
        Response { status, body: body.into() }
    }
}

/// The server's runtime configuration. Loaded once at startup from a file the
/// operator controls (see `features::hooks`). It is NOT part of the request and
/// NOT attacker-controlled under the stated threat model.
#[derive(Clone, Debug)]
pub struct Config {
    /// Command run by the post-processing hook. Operator-supplied.
    pub post_hook_command: Option<String>,
    /// Directory uploads are written to.
    pub upload_dir: String,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            post_hook_command: None,
            upload_dir: "/tmp/dvr-uploads".to_string(),
        }
    }
}

/// The application. Holds the in-memory store and config, and dispatches
/// requests to feature handlers by path.
pub struct App {
    pub db: db::Db,
    pub config: Config,
}

impl App {
    pub fn new() -> Self {
        App { db: db::Db::seed(), config: Config::default() }
    }

    pub fn with_config(config: Config) -> Self {
        App { db: db::Db::seed(), config }
    }

    /// Route table. Note which handlers are actually wired in: a handler that
    /// exists but is never dispatched here is not on the attacker path.
    pub fn handle(&self, req: &Request) -> Response {
        match req.path.as_str() {
            "/users/search" => features::user_search::handle(self, req),
            "/files/download" => features::file_download::handle(self, req),
            "/documents/get" => features::documents::handle(self, req),
            "/headers/echo" => features::header_parse::handle(self, req),
            "/framing/read" => features::framing::handle(self, req),
            "/upload" => features::upload::handle(self, req),
            "/hook/run" => features::hooks::handle(self, req),
            "/login" => features::auth::handle(self, req),
            "/validate" => features::validation::handle(self, req),
            "/proxy/fetch" => features::proxy::handle(self, req),
            "/collect" => features::collect::handle(self, req),
            "/parse/nested" => features::nested::handle(self, req),
            "/cache/warm" => features::concurrency::handle(self, req),
            "/dedup" => features::dedup::handle(self, req),
            "/records/build" => features::records::handle(self, req),
            "/profile/update" => features::profile::handle(self, req),
            #[cfg(feature = "ffi")]
            "/ffi/dispatch" => features::ffi::handle(self, req),
            _ => Response::err(404, "not found"),
        }
    }
}

impl Default for App {
    fn default() -> Self {
        Self::new()
    }
}
