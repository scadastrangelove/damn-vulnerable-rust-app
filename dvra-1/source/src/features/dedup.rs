//! Request de-duplication cache.
//!
//! POST /dedup  body = newline-separated keys
//!
//! Counts distinct keys seen in the request using a HashMap. To be "fast", the
//! map is built with a custom hasher instead of the standard SipHash.

use crate::{App, Request, Response};
use std::collections::HashMap;
use std::hash::{BuildHasher, Hasher};

/// A trivial multiplicative hasher (FNV-ish, but no per-process key). It is
/// deterministic and public, so an attacker can precompute keys that all land
/// in the same bucket, degrading the map to O(n) per operation.
#[derive(Default)]
struct WeakHasher {
    state: u64,
}

impl Hasher for WeakHasher {
    fn finish(&self) -> u64 {
        self.state
    }
    fn write(&mut self, bytes: &[u8]) {
        // No random seed. Fully predictable from the input alone.
        let mut h = self.state;
        for &b in bytes {
            h = h.wrapping_mul(0x0100_0000_01b3).wrapping_add(b as u64);
        }
        self.state = h;
    }
}

#[derive(Default, Clone)]
struct WeakBuild;

impl BuildHasher for WeakBuild {
    type Hasher = WeakHasher;
    fn build_hasher(&self) -> WeakHasher {
        WeakHasher::default()
    }
}

pub fn handle(_app: &App, req: &Request) -> Response {
    let text = String::from_utf8_lossy(&req.body);

    // Fast de-dup map keyed by the incoming lines.
    let mut seen: HashMap<&str, u32, WeakBuild> = HashMap::with_hasher(WeakBuild);
    for line in text.lines() {
        *seen.entry(line).or_insert(0) += 1;
    }

    Response::ok(format!("distinct={}", seen.len()))
}

/// The standard-library default hasher (SipHash) is randomized per process and
/// is the correct choice for attacker-controlled keys. Only reach for a faster
/// hasher when keys are trusted (internal, not request-derived).
pub fn fixed_handle(_app: &App, req: &Request) -> Response {
    let text = String::from_utf8_lossy(&req.body);
    let mut seen: HashMap<&str, u32> = HashMap::new(); // SipHash, randomized
    for line in text.lines() {
        *seen.entry(line).or_insert(0) += 1;
    }
    Response::ok(format!("distinct={}", seen.len()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Source;

    fn req(body: &str) -> Request {
        Request {
            principal: "alice".into(),
            is_admin: false,
            path: "/dedup".into(),
            query: vec![],
            headers: vec![],
            body: body.as_bytes().to_vec(),
            source: Source::PublicEdge,
        }
    }

    #[test]
    fn counts_distinct_lines() {
        let app = App::new();
        assert_eq!(handle(&app, &req("a\nb\na\nc")).body, "distinct=3");
        assert_eq!(fixed_handle(&app, &req("a\nb\na\nc")).body, "distinct=3");
    }

    #[test]
    fn weak_hasher_collides_predictably() {
        // Demonstrate that different inputs can be driven to the same hash.
        // The point is not this pair specifically but that, with no random
        // seed and a public algorithm, an attacker can *construct* colliding
        // keys offline. Here we just show the hasher is a pure function of
        // input (no per-process randomness), which is the enabling property.
        fn weak_hash(s: &str) -> u64 {
            let mut h = WeakHasher::default();
            h.write(s.as_bytes());
            h.finish()
        }
        assert_eq!(weak_hash("abc"), weak_hash("abc")); // deterministic
        // Two runs of the same input in the same process AND across processes
        // would match — that determinism is the vulnerability. SipHash would
        // differ across processes due to the random key.
    }
}
