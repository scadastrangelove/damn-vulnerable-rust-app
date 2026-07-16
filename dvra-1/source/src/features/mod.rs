//! Feature handlers. Each module exposes `handle(&App, &Request) -> Response`
//! and, where useful for training, a `fixed_*` counterpart plus unit tests that
//! demonstrate the trigger. The insecure behaviour is not labelled inline.

pub mod auth;
pub mod collect;
pub mod concurrency;
pub mod dedup;
pub mod documents;
#[cfg(feature = "ffi")]
pub mod ffi;
pub mod file_download;
pub mod framing;
pub mod header_parse;
pub mod hooks;
pub mod native;
pub mod nested;
pub mod profile;
pub mod proxy;
pub mod records;
pub mod upload;
pub mod user_search;
pub mod validation;
