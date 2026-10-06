//! Interop harness for `zincio-http`.
//!
//! Drives real, third-party HTTP clients against the native server over
//! containers. This crate lives outside the main workspace because it pulls in
//! `testcontainers` and container client images that have no place in the
//! published build.

pub mod routes;
pub mod scenario;
pub mod server;
