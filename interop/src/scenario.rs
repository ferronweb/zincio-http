//! The declarative scenario matrix.
//!
//! This module is the single source of truth for *what* the interop suite
//! tests. The scenario server serves exactly these routes, and every client
//! driver -- the in-process reference driver as well as each containerised
//! third-party client -- is measured against the expectations declared here.
//!
//! Keeping the expectations in Rust rather than inside each client script is
//! deliberate: a client driver only reports *what it observed* (status, body
//! length, digest), and this module decides whether that is correct. Otherwise
//! every new client would re-encode the same expectations and drift.

use sha2::{Digest, Sha256};

/// Deterministic response body pattern.
///
/// A repeating 4-byte sequence is used rather than a single repeated byte so
/// that a digest over the body detects truncation, duplication, *and*
/// reordering, while staying trivial to generate for a 64 MiB response.
const PATTERN: [u8; 4] = *b"ABCD";

/// Number of bytes used by the "small" response.
pub const SMALL_LEN: usize = 1024;
/// Number of bytes used by the "large" response.
pub const LARGE_LEN: usize = 1024 * 1024;
/// Number of bytes used by the "huge" response, used for fairness tests.
pub const HUGE_LEN: usize = 64 * 1024 * 1024;

/// The byte at `index` of a deterministic pattern body.
#[inline]
pub fn pattern_byte(index: u64) -> u8 {
    PATTERN[(index % 4) as usize]
}

/// Builds the canonical body for a given length.
///
/// Callers that only need to stream a body of this length should prefer
/// [`pattern_chunk`], which avoids materialising the whole thing.
pub fn pattern_body(len: usize) -> Vec<u8> {
    (0..len as u64).map(pattern_byte).collect()
}

/// A 64 KiB slice of the pattern body starting at `offset`.
///
/// Every offset that is a multiple of 4 keeps this aligned with the
/// surrounding pattern; the tests only ever request aligned offsets.
pub fn pattern_chunk(offset: u64, len: usize) -> Vec<u8> {
    (0..len as u64).map(|i| pattern_byte(offset + i)).collect()
}

/// Lowercase hex SHA-256 of `bytes`.
pub fn digest_hex(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("{:x}", hasher.finalize())
}

/// What a client is expected to observe for a single request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expect {
    /// `200` with a body of exactly `len` pattern bytes.
    Exact { len: usize },
    /// `200` echoing the uploaded body of `len` bytes.
    Echo { len: usize },
    /// `200` with a body of `len` pattern bytes plus a response trailer
    /// carrying `x-echo-trailer`.
    Trailers { len: usize },
    /// A `103` informational response followed by `200` with `len` bytes.
    EarlyHints { len: usize },
    /// The request must be refused, either with a 4xx status or by the
    /// connection/stream being torn down.
    Rejected,
}

impl Expect {
    /// The body length a conforming response carries, if the expectation
    /// describes a successful response.
    pub fn body_len(self) -> Option<usize> {
        match self {
            Expect::Exact { len }
            | Expect::Echo { len }
            | Expect::Trailers { len }
            | Expect::EarlyHints { len } => Some(len),
            Expect::Rejected => None,
        }
    }

    /// The digest a conforming response body must have, if the expectation
    /// describes a successful response. Trailers do not affect the body, so
    /// the digest is the plain pattern digest.
    pub fn body_digest(self) -> Option<String> {
        self.body_len().map(|len| digest_hex(&pattern_body(len)))
    }

    /// Whether a response carrying `trailers` satisfies this expectation.
    pub fn wants_trailers(self) -> bool {
        matches!(self, Expect::Trailers { .. })
    }

    /// Whether an informational `103` must have preceded the final response.
    pub fn wants_early_hints(self) -> bool {
        matches!(self, Expect::EarlyHints { .. })
    }

    /// Human-readable label used in failure messages.
    pub fn label(self) -> &'static str {
        match self {
            Expect::Exact { .. } => "exact body",
            Expect::Echo { .. } => "echoed body",
            Expect::Trailers { .. } => "body + trailers",
            Expect::EarlyHints { .. } => "103 early hints + body",
            Expect::Rejected => "rejected",
        }
    }
}

/// A capability a client driver must implement for a scenario to run.
///
/// Scenarios declare what they need; drivers declare what they can do. The
/// matrix is the intersection, so an unimplemented capability downgrades to a
/// reported skip rather than a spurious failure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Capability {
    /// Send a request body.
    Upload,
    /// Receive response trailers.
    ResponseTrailers,
    /// Send request trailers.
    RequestTrailers,
    /// Drive several streams concurrently on one connection.
    Concurrency,
    /// Reset a stream mid-response.
    Abort,
    /// Send `Expect: 100-continue` and read the interim response.
    ExpectContinue,
    /// Read a `103 Early Hints` before the final response.
    EarlyHints,
    /// Send a header block larger than the server's configured limit.
    BigHeader,
    /// Send an unusually long request target.
    LongUri,
    /// Send many distinct headers on one request.
    ManyHeaders,
    /// Hold a connection idle past the server's timeout, then reuse it.
    IdleReuse,
}

/// One step of a scenario. A scenario is a sequence of steps performed in
/// order against a single server.
#[derive(Clone, Copy, Debug)]
pub enum Step {
    /// A single request/response exchange.
    Request {
        method: &'static str,
        path: &'static str,
        upload_len: usize,
        expect: Expect,
    },
    /// `count` requests issued concurrently on one connection, each of which
    /// must satisfy `expect`.
    Concurrent {
        count: usize,
        path: &'static str,
        expect: Expect,
    },
    /// Begin a response for `path`, read `abort_after` bytes, then reset the
    /// stream. `follow` is then requested on the same connection and must
    /// still succeed -- this is the regression that produced the
    /// "large response starves/aborts the connection" class of bug.
    AbortMidStream {
        path: &'static str,
        abort_after: u64,
        follow: &'static str,
        follow_expect: Expect,
    },
    /// Keep a connection idle for `idle_ms`, then reuse it.
    IdleReuse {
        idle_ms: u64,
        path: &'static str,
        expect: Expect,
    },
}

impl Step {
    /// Capabilities a driver must implement to run this step.
    pub fn requires(&self) -> Vec<Capability> {
        match self {
            Step::Request {
                upload_len, expect, ..
            } => {
                let mut caps = Vec::new();
                if *upload_len > 0 {
                    caps.push(Capability::Upload);
                }
                match expect {
                    Expect::Trailers { .. } => {
                        caps.push(Capability::ResponseTrailers);
                        caps.push(Capability::RequestTrailers);
                    }
                    Expect::EarlyHints { .. } => caps.push(Capability::EarlyHints),
                    _ => {}
                }
                caps
            }
            Step::Concurrent { count, .. } => {
                if *count > 1 {
                    vec![Capability::Concurrency]
                } else {
                    Vec::new()
                }
            }
            Step::AbortMidStream { .. } => vec![Capability::Abort],
            Step::IdleReuse { .. } => vec![Capability::IdleReuse],
        }
    }

    /// Short description used in logs and failure messages.
    pub fn label(&self) -> String {
        match self {
            Step::Request {
                method,
                path,
                upload_len,
                expect,
            } => format!(
                "{method} {path} (upload {upload_len}) -> {}",
                expect.label()
            ),
            Step::Concurrent { count, path, .. } => {
                format!("{count}x concurrent GET {path}")
            }
            Step::AbortMidStream { path, .. } => format!("abort {path} mid-stream"),
            Step::IdleReuse { idle_ms, path, .. } => format!("idle {idle_ms}ms then GET {path}"),
        }
    }
}

/// A named, ordered sequence of steps forming one testable unit.
#[derive(Clone, Copy, Debug)]
pub struct Scenario {
    pub name: &'static str,
    /// Why this scenario exists. Surfaced in test output so a failure is
    /// traceable to the behaviour it protects.
    pub rationale: &'static str,
    pub steps: &'static [Step],
    /// Extra capabilities needed by the scenario as a whole, beyond those
    /// implied by individual steps.
    pub requires: &'static [Capability],
}

impl Scenario {
    /// Every capability a driver needs to run this scenario.
    pub fn required_capabilities(&self) -> Vec<Capability> {
        let mut caps: Vec<Capability> = self.requires.to_vec();
        for step in self.steps {
            caps.extend(step.requires());
        }
        caps.sort_by_key(|c| format!("{c:?}"));
        caps.dedup();
        caps
    }
}

/// Size of the header block that must be rejected. Comfortably above the
/// server's configured `max_header_list_size` (see `server.rs`).
pub const BIG_HEADER_LEN: usize = 32 * 1024;
/// Length of the request target used by the long-URI scenario.
pub const LONG_URI_LEN: usize = 8 * 1024;
/// Number of distinct headers sent by the many-headers scenario.
pub const MANY_HEADERS: usize = 200;
/// Idle period used by the idle-reuse scenario. Exceeds the server's
/// configured HTTP/2 idle timeout so the connection is expected to have been
/// reaped, and the client must transparently reconnect.
pub const IDLE_MS: u64 = 3_000;

/// The full scenario matrix.
///
/// Ordered cheapest-first so that a failure in an early scenario surfaces
/// before the multi-second large-body scenarios run.
pub static SCENARIOS: &[Scenario] = &[
    Scenario {
        name: "small_get",
        rationale: "baseline: a single small response must arrive intact",
        steps: &[Step::Request {
            method: "GET",
            path: "/small",
            upload_len: 0,
            expect: Expect::Exact { len: SMALL_LEN },
        }],
        requires: &[],
    },
    Scenario {
        name: "upload_echo_small",
        rationale: "request bodies must be received intact",
        steps: &[Step::Request {
            method: "POST",
            path: "/echo",
            upload_len: SMALL_LEN,
            expect: Expect::Echo { len: SMALL_LEN },
        }],
        requires: &[],
    },
    Scenario {
        name: "long_uri",
        rationale: "long request targets must not be truncated or rejected",
        steps: &[Step::Request {
            method: "GET",
            path: "/small",
            upload_len: 0,
            expect: Expect::Exact { len: SMALL_LEN },
        }],
        requires: &[Capability::LongUri],
    },
    Scenario {
        name: "many_headers",
        rationale: "many distinct headers must survive HPACK/QPACK coding",
        steps: &[Step::Request {
            method: "GET",
            path: "/small",
            upload_len: 0,
            expect: Expect::Exact { len: SMALL_LEN },
        }],
        requires: &[Capability::ManyHeaders],
    },
    Scenario {
        name: "large_get",
        rationale: "connection-level flow control must not reset a stream on a 1MiB body (0.4.8)",
        steps: &[Step::Request {
            method: "GET",
            path: "/large",
            upload_len: 0,
            expect: Expect::Exact { len: LARGE_LEN },
        }],
        requires: &[],
    },
    Scenario {
        name: "upload_echo_large",
        rationale: "request-side flow control must not stall or reset a 1MiB upload",
        steps: &[Step::Request {
            method: "POST",
            path: "/echo",
            upload_len: LARGE_LEN,
            expect: Expect::Echo { len: LARGE_LEN },
        }],
        requires: &[Capability::Upload],
    },
    Scenario {
        name: "trailers",
        rationale: "request and response trailers must round-trip",
        steps: &[Step::Request {
            method: "POST",
            path: "/trailers",
            upload_len: SMALL_LEN,
            expect: Expect::Trailers { len: SMALL_LEN },
        }],
        requires: &[],
    },
    Scenario {
        name: "expect_continue",
        rationale: "a 100 Continue interim response must precede the final response",
        steps: &[Step::Request {
            method: "POST",
            path: "/echo",
            upload_len: SMALL_LEN,
            expect: Expect::Echo { len: SMALL_LEN },
        }],
        requires: &[Capability::ExpectContinue],
    },
    Scenario {
        name: "early_hints",
        rationale: "103 Early Hints must be delivered before the final response",
        steps: &[Step::Request {
            method: "GET",
            path: "/hint",
            upload_len: 0,
            expect: Expect::EarlyHints { len: SMALL_LEN },
        }],
        requires: &[Capability::EarlyHints],
    },
    Scenario {
        name: "concurrency",
        rationale: "many concurrent streams on one connection must all complete",
        steps: &[Step::Concurrent {
            count: 32,
            path: "/small",
            expect: Expect::Exact { len: SMALL_LEN },
        }],
        requires: &[Capability::Concurrency],
    },
    Scenario {
        name: "abort_midstream",
        rationale:
            "cancelling one large stream must not tear down the connection (0.4.x starvation)",
        steps: &[Step::AbortMidStream {
            path: "/large",
            abort_after: 64 * 1024,
            follow: "/small",
            follow_expect: Expect::Exact { len: SMALL_LEN },
        }],
        requires: &[Capability::Abort],
    },
    Scenario {
        name: "idle_reuse",
        rationale:
            "a connection idle past the server timeout must be reaped cleanly and be reconnectable",
        steps: &[Step::IdleReuse {
            idle_ms: IDLE_MS,
            path: "/small",
            expect: Expect::Exact { len: SMALL_LEN },
        }],
        requires: &[Capability::IdleReuse],
    },
    Scenario {
        name: "big_header_rejected",
        rationale: "an oversized header block must be refused, not silently truncated",
        steps: &[Step::Request {
            method: "GET",
            path: "/small",
            upload_len: 0,
            expect: Expect::Rejected,
        }],
        requires: &[Capability::BigHeader],
    },
];

/// Looks a scenario up by name.
pub fn scenario_by_name(name: &str) -> Option<&'static Scenario> {
    SCENARIOS.iter().find(|s| s.name == name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pattern_body_is_deterministic_and_repeating() {
        let body = pattern_body(16);
        assert_eq!(body, b"ABCDABCDABCDABCD");
        assert_eq!(pattern_body(3), b"ABC");
    }

    #[test]
    fn pattern_chunks_reassemble_into_the_whole_body() {
        let whole = pattern_body(4096);
        for chunk_len in [64usize, 512, 4096] {
            let mut rebuilt = Vec::new();
            let mut offset = 0u64;
            while (rebuilt.len() as u64) < whole.len() as u64 {
                let remaining = whole.len() - rebuilt.len();
                let take = chunk_len.min(remaining);
                rebuilt.extend_from_slice(&pattern_chunk(offset, take));
                offset += take as u64;
            }
            assert_eq!(rebuilt, whole, "chunk_len {chunk_len}");
        }
    }

    #[test]
    fn truncation_and_duplication_change_the_digest() {
        let body = pattern_body(1024);
        let full = digest_hex(&body);
        assert_eq!(full, digest_hex(&pattern_body(1024)));
        assert_ne!(full, digest_hex(&pattern_body(1023)));
        assert_ne!(
            full,
            digest_hex(&[body.as_slice(), body.as_slice()].concat())
        );
    }

    #[test]
    fn every_scenario_name_is_unique() {
        let mut names: Vec<&str> = SCENARIOS.iter().map(|s| s.name).collect();
        names.sort_unstable();
        let count = names.len();
        names.dedup();
        assert_eq!(names.len(), count, "duplicate scenario name");
    }

    #[test]
    fn every_scenario_has_a_rationale() {
        for scenario in SCENARIOS {
            assert!(
                scenario.rationale.len() > 20,
                "{} has a too-thin rationale",
                scenario.name
            );
            assert!(!scenario.steps.is_empty(), "{} has no steps", scenario.name);
        }
    }

    #[test]
    fn capabilities_are_deduplicated() {
        for scenario in SCENARIOS {
            let caps = scenario.required_capabilities();
            let mut deduped = caps.clone();
            deduped.dedup();
            assert_eq!(
                caps, deduped,
                "{} produced duplicate capabilities",
                scenario.name
            );
        }
    }

    #[test]
    fn big_header_scenario_is_the_only_rejection() {
        for scenario in SCENARIOS {
            for step in scenario.steps {
                let rejects = matches!(
                    step,
                    Step::Request {
                        expect: Expect::Rejected,
                        ..
                    }
                );
                assert_eq!(
                    rejects,
                    scenario.name == "big_header_rejected",
                    "unexpected rejection expectation in {}",
                    scenario.name
                );
            }
        }
    }
}
