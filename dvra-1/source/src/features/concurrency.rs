//! Shared cache handle passed to worker threads.
//!
//! POST /cache/warm  (spawns workers that touch a shared handle)
//!
//! `Shared<T>` is a thin wrapper used to hand a value to worker threads. It
//! carries a hand-written `unsafe impl Send`. The review question is the bound:
//! is the impl sound for every `T`, or only for `T` that are actually safe to
//! send across threads?

use crate::{App, Request, Response};
use std::sync::Arc;
use std::thread;

/// A wrapper that is sent to worker threads.
pub struct Shared<T> {
    inner: T,
}

impl<T> Shared<T> {
    pub fn new(inner: T) -> Self {
        Shared { inner }
    }
    pub fn get(&self) -> &T {
        &self.inner
    }
}

// SAFETY (as written): "we only ever read `inner` from worker threads, so it is
// fine to send." This reasoning is wrong: an unconditional `Send` for ALL `T`
// lets non-thread-safe interior types (e.g. `Rc`, `Cell`, raw pointers) cross
// thread boundaries, where concurrent access races their non-atomic state.
//
// The bug is the missing bound. `Send` is an unsafe trait; other code (the std
// thread machinery) relies on it being correct.
unsafe impl<T> Send for Shared<T> {}
unsafe impl<T> Sync for Shared<T> {}

/// A sound wrapper: only `Send` when the contained type is. With this bound the
/// compiler rejects sending a `!Send` type, which is the whole point.
pub struct SharedSafe<T: Send + Sync> {
    inner: T,
}

impl<T: Send + Sync> SharedSafe<T> {
    pub fn new(inner: T) -> Self {
        SharedSafe { inner }
    }
    pub fn get(&self) -> &T {
        &self.inner
    }
}
// No hand-written impls needed: the auto-derived Send/Sync are correct because
// the bound guarantees `T: Send + Sync`.

pub fn handle(_app: &App, req: &Request) -> Response {
    // On the request path we wrap a plainly-Send payload (bytes), so nothing
    // races here. The defect is latent in the `unsafe impl`, not in this call.
    let workers: usize = req
        .header("x-workers")
        .and_then(|s| s.parse().ok())
        .unwrap_or(4);

    let shared = Arc::new(Shared::new(req.body.clone()));
    let mut handles = Vec::new();
    for _ in 0..workers.min(16) {
        let s = Arc::clone(&shared);
        handles.push(thread::spawn(move || s.get().len()));
    }
    let total: usize = handles.into_iter().map(|h| h.join().unwrap_or(0)).sum();
    Response::ok(format!("touched={}", total))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_payload_across_threads_is_fine() {
        // Vec<u8> is genuinely Send; this use of Shared does not race.
        let shared = Arc::new(Shared::new(vec![1u8, 2, 3]));
        let mut hs = Vec::new();
        for _ in 0..8 {
            let s = Arc::clone(&shared);
            hs.push(thread::spawn(move || s.get().len()));
        }
        let sum: usize = hs.into_iter().map(|h| h.join().unwrap()).sum();
        assert_eq!(sum, 24);
    }

    // The unsound part: because `Shared<T>: Send` for ALL T, we can send a
    // wrapper around a `!Send` type such as `Rc` across threads and race its
    // non-atomic reference count -> memory corruption / double free.
    //
    // This is a DATA RACE: undefined behaviour, not a guaranteed panic. A plain
    // `cargo test` may pass by luck. It is caught by ThreadSanitizer
    //     RUSTFLAGS="-Zsanitizer=thread" cargo +nightly test --features race-demo
    // or by Miri under multiple seeds. Gated so it is not compiled by default.
    #[cfg(feature = "race-demo")]
    #[test]
    fn rc_across_threads_is_a_data_race() {
        use std::rc::Rc;
        // `SharedSafe` would REJECT this at compile time (Rc: !Send). The
        // vulnerable `Shared` accepts it — that is the bug.
        let shared = Arc::new(Shared::new(Rc::new(0u64)));
        let mut hs = Vec::new();
        for _ in 0..8 {
            let s = Arc::clone(&shared);
            hs.push(thread::spawn(move || {
                // Racing clone/drop of a non-atomic Rc refcount across threads.
                let local = Rc::clone(s.get());
                Rc::strong_count(&local)
            }));
        }
        let _: usize = hs.into_iter().map(|h| h.join().unwrap()).sum();
    }
}
