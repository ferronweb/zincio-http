//! Interop harness for `zincio-http`.
//!
//! Drives real, third-party HTTP clients against the native server over
//! containers. This crate lives outside the main workspace because it pulls in
//! `testcontainers` and container client images that have no place in the
//! published build.
//!
//! # Layout
//!
//! - [`scenario`] -- the declarative scenario matrix, and the single source of
//!   truth for what each scenario expects.
//! - [`routes`] -- the request handler serving exactly those scenarios.
//! - [`server`] -- starts HTTP/1.1, HTTP/2, and HTTP/3 listeners.
//! - [`client`] -- driver abstraction and the normalised observation format
//!   every client reports in.
//! - [`clients`] -- the registry of third-party clients in the matrix.
//! - [`container`] -- `testcontainers`-backed drivers for third-party clients.

pub mod client;
pub mod clients;
pub mod container;
pub mod routes;
pub mod scenario;
pub mod server;
