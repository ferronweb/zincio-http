//! The client driver abstraction and the normalised observation format.
//!
//! Every client implementation -- in-process or containerised, whatever
//! language it is written in -- reports what it observed using the same
//! space-separated `key=value` line. Keeping the format to something a shell
//! can emit is deliberate: `curl` is one of the most valuable clients in the
//! matrix and it has no scripting language beyond the shell.
//!
//! Expectations are *not* part of the format. A client never decides whether
//! its own result was correct; it only reports status, body length, body
//! digest and a few protocol-level facts, and [`crate::scenario`] decides what
//! should have happened.

use crate::scenario::{self, Capability, Expect, Step};

/// What a client observed for one request.
///
/// `status` is `0` when the request never produced a response at all, which is
/// how a stream reset or a refused oversized header block is reported.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Observation {
    /// HTTP status, or `0` if the request failed before a response arrived.
    pub status: u16,
    /// Length of the response body in bytes.
    pub body_len: usize,
    /// Lowercase hex SHA-256 of the response body, or empty if unavailable.
    pub body_sha: String,
    /// Whether an `x-echo-trailer` response trailer was observed.
    pub trailers: bool,
    /// Whether a `103` informational response preceded the final response.
    pub early_hints: bool,
    /// Transport-level failure, if the request could not be completed.
    pub error: Option<String>,
}

impl Observation {
    /// A request that never reached a response.
    pub fn failed(error: impl Into<String>) -> Self {
        Self {
            status: 0,
            body_len: 0,
            body_sha: String::new(),
            trailers: false,
            early_hints: false,
            error: Some(error.into()),
        }
    }

    /// Renders the observation as the line a client program prints.
    pub fn to_line(&self) -> String {
        format!(
            "status={} len={} sha={} trailers={} hints={} err={}",
            self.status,
            self.body_len,
            if self.body_sha.is_empty() {
                "-".to_owned()
            } else {
                self.body_sha.clone()
            },
            u8::from(self.trailers),
            u8::from(self.early_hints),
            // Spaces would break the format; a client should not produce them,
            // but squashing keeps a stray space from failing the parse.
            self.error.clone().unwrap_or_default().replace(' ', "_"),
        )
    }

    /// Parses a line produced by [`Self::to_line`].
    pub fn parse(line: &str) -> Result<Self, String> {
        let mut fields = std::collections::HashMap::new();
        for pair in line.split_whitespace() {
            let (key, value) = pair
                .split_once('=')
                .ok_or_else(|| format!("malformed observation field {pair:?} in {line:?}"))?;
            fields.insert(key.to_owned(), value.to_owned());
        }

        let parse_num = |key: &str| -> Result<usize, String> {
            fields
                .get(key)
                .ok_or_else(|| format!("observation is missing {key:?}: {line:?}"))?
                .parse::<usize>()
                .map_err(|err| format!("bad {key:?}: {err}"))
        };
        let parse_flag = |key: &str| -> bool { fields.get(key).is_some_and(|v| v == "1") };

        let error = fields.get("err").filter(|e| !e.is_empty()).cloned();
        let sha = fields
            .get("sha")
            .filter(|s| *s != "-")
            .cloned()
            .unwrap_or_default();

        Ok(Self {
            status: parse_num("status")? as u16,
            body_len: parse_num("len")?,
            body_sha: sha,
            trailers: parse_flag("trailers"),
            early_hints: parse_flag("hints"),
            error,
        })
    }

    /// Compares the observation against a scenario expectation.
    ///
    /// This is the single place a result becomes pass or fail, which is what
    /// keeps expectations from drifting between client drivers.
    pub fn verify(&self, name: &str, expect: Expect) -> Result<(), String> {
        if let Some(error) = &self.error {
            if expect == Expect::Rejected {
                return Ok(());
            }
            return Err(format!("{name}: request failed: {error}"));
        }

        match expect {
            // Either a 4xx or no response at all is a conforming refusal. A
            // 200 here would mean the limit silently stopped applying.
            Expect::Rejected => {
                let refused = self.status == 0 || (400..500).contains(&self.status);
                if refused {
                    Ok(())
                } else {
                    Err(format!(
                        "{name}: expected the request to be refused, got status {}",
                        self.status
                    ))
                }
            }
            _ => {
                if self.status != 200 {
                    return Err(format!(
                        "{name}: expected 200, got {} ({})",
                        self.status,
                        self.to_line()
                    ));
                }
                let want_len = expect
                    .body_len()
                    .expect("successful expectation has a length");
                if self.body_len != want_len {
                    return Err(format!(
                        "{name}: expected {want_len} body bytes, got {} ({})",
                        self.body_len,
                        self.to_line()
                    ));
                }
                let want_sha = expect
                    .body_digest()
                    .expect("successful expectation has a digest");
                if self.body_sha != want_sha {
                    return Err(format!(
                        "{name}: body digest mismatch\n  want {want_sha}\n  got  {}\n  ({})",
                        self.body_sha,
                        self.to_line()
                    ));
                }
                if expect.wants_trailers() && !self.trailers {
                    return Err(format!(
                        "{name}: expected an x-echo-trailer trailer ({})",
                        self.to_line()
                    ));
                }
                if expect.wants_early_hints() && !self.early_hints {
                    return Err(format!(
                        "{name}: expected 103 Early Hints ({})",
                        self.to_line()
                    ));
                }
                Ok(())
            }
        }
    }
}

/// Which protocol a driver is talking.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Protocol {
    Http1,
    Http2,
    Http3,
}

impl Protocol {
    /// Stable lowercase name, used in driver arguments and test names.
    pub fn name(self) -> &'static str {
        match self {
            Protocol::Http1 => "h1",
            Protocol::Http2 => "h2",
            Protocol::Http3 => "h3",
        }
    }

    /// Every protocol, cheapest first.
    pub fn all() -> [Protocol; 3] {
        [Protocol::Http1, Protocol::Http2, Protocol::Http3]
    }
}

/// A third-party client implementation under test.
#[derive(Clone, Debug)]
pub struct ClientSpec {
    /// Stable identifier, used in test names and in the CI matrix.
    pub id: &'static str,
    /// Human-readable name for logs.
    pub name: &'static str,
    /// Protocols this client can speak.
    pub protocols: &'static [Protocol],
    /// What this client can do. A scenario needing anything absent is skipped.
    pub capabilities: &'static [Capability],
    /// Container image, or `None` for an in-process driver.
    pub image: Option<ImageSpec>,
    /// Where the driver's script lives inside the image, and how to invoke it.
    ///
    /// The driver receives the base URL, protocol, and scenario name as
    /// positional arguments, and prints one [`Observation`] line on stdout.
    pub entrypoint: Option<Entrypoint>,
    /// Whether the image must be built from `clients/` before use.
    pub build_context: Option<&'static str>,
}

/// How to obtain a container image.
#[derive(Clone, Debug)]
pub enum ImageSpec {
    /// Pulled directly from a registry, pinned by digest.
    Registry {
        /// Fully qualified reference including tag or digest.
        image: &'static str,
    },
    /// Built locally from a checked-in Dockerfile.
    Build {
        /// Image name to tag the build result with.
        tag: &'static str,
        /// Directory under `interop/clients/` holding the Dockerfile.
        context: &'static str,
        /// Build stage to stop at. One Dockerfile can serve several images, so
        /// a fast image and a slow one do not force each other to be built.
        target: &'static str,
    },
}

/// The command a driver image exposes.
#[derive(Clone, Copy, Debug)]
pub struct Entrypoint {
    /// Executable to run.
    pub program: &'static str,
    /// Fixed arguments placed before the per-scenario arguments.
    pub args: &'static [&'static str],
}

impl ClientSpec {
    /// Whether this client can run `scenario` over `protocol`.
    ///
    /// A `None` result is a skip, not a failure: it is how an unimplemented
    /// capability stays visible without producing noise.
    pub fn can_run(&self, scenario: &scenario::Scenario, protocol: Protocol) -> Option<String> {
        if !self.protocols.contains(&protocol) {
            return Some(format!("{} does not speak {}", self.name, protocol.name()));
        }
        for capability in scenario.required_capabilities() {
            if !self.capabilities.contains(&capability) {
                return Some(format!("{} lacks {capability:?}", self.name));
            }
        }
        None
    }
}

/// The arguments handed to a driver program for one scenario.
#[derive(Clone, Debug)]
pub struct ScenarioArgs {
    /// Base URL, including scheme, host and port.
    pub base_url: String,
    /// Protocol under test.
    pub protocol: Protocol,
    /// Scenario name.
    pub scenario: &'static str,
    /// The single step to perform. Multi-step scenarios are driven by a
    /// dedicated driver routine rather than the generic path.
    pub step: Step,
}

impl ScenarioArgs {
    /// Formats the positional arguments for a driver program.
    ///
    /// Scenario-specific inputs (upload sizes, header counts) are passed as
    /// `key=value` pairs so a driver written in shell can read them with `for`.
    pub fn to_argv(&self) -> Vec<String> {
        let mut argv = vec![
            self.base_url.clone(),
            self.protocol.name().to_owned(),
            self.scenario.to_owned(),
        ];
        match self.step {
            Step::Request {
                method,
                path,
                upload_len,
                ..
            } => {
                argv.push(format!("method={method}"));
                argv.push(format!("path={path}"));
                argv.push(format!("upload_len={upload_len}"));
            }
            Step::Concurrent { count, path, .. } => {
                argv.push("method=GET".to_owned());
                argv.push(format!("path={path}"));
                argv.push(format!("count={count}"));
            }
            Step::AbortMidStream { path, .. } => {
                argv.push("method=GET".to_owned());
                argv.push(format!("path={path}"));
            }
            Step::IdleReuse { idle_ms, path, .. } => {
                argv.push("method=GET".to_owned());
                argv.push(format!("path={path}"));
                argv.push(format!("idle_ms={idle_ms}"));
            }
        }
        argv
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Observation {
        Observation {
            status: 200,
            body_len: 1024,
            body_sha: scenario::digest_hex(&scenario::pattern_body(1024)),
            trailers: false,
            early_hints: false,
            error: None,
        }
    }

    #[test]
    fn observation_round_trips_through_the_line_format() {
        let original = sample();
        assert_eq!(Observation::parse(&original.to_line()), Ok(original));
    }

    #[test]
    fn observation_round_trips_with_every_field_set() {
        let original = Observation {
            status: 431,
            body_len: 0,
            body_sha: String::new(),
            trailers: true,
            early_hints: true,
            error: Some("refused".to_owned()),
        };
        assert_eq!(Observation::parse(&original.to_line()), Ok(original));
    }

    #[test]
    fn a_missing_body_digest_survives_the_round_trip() {
        let parsed =
            Observation::parse("status=200 len=10 sha=- trailers=0 hints=0 err=").expect("parse");
        assert_eq!(parsed.body_sha, "");
        assert_eq!(parsed.body_len, 10);
    }

    #[test]
    fn errors_with_spaces_do_not_break_the_format() {
        let parsed =
            Observation::parse("status=0 len=0 sha=- trailers=0 hints=0 err=no_route_found")
                .expect("parse");
        assert_eq!(parsed.error.as_deref(), Some("no_route_found"));
    }

    #[test]
    fn malformed_lines_are_rejected_rather_than_silently_accepted() {
        assert!(Observation::parse("").is_err());
        assert!(Observation::parse("garbage").is_err());
        assert!(
            Observation::parse("status=200 len=notanumber sha=- trailers=0 hints=0 err=").is_err()
        );
        // `len` missing entirely must not default to zero.
        assert!(Observation::parse("status=200 sha=- trailers=0 hints=0 err=").is_err());
    }

    #[test]
    fn verification_accepts_a_conforming_response() {
        let expect = Expect::Exact {
            len: scenario::SMALL_LEN,
        };
        assert!(sample().verify("t", expect).is_ok());
    }

    #[test]
    fn verification_rejects_a_truncated_body() {
        let truncated = Observation {
            body_len: 1023,
            ..sample()
        };
        let expect = Expect::Exact {
            len: scenario::SMALL_LEN,
        };
        assert!(truncated.verify("t", expect).is_err());
    }

    #[test]
    fn verification_rejects_a_repeated_body_of_the_right_length() {
        // Same length, different bytes: only the digest catches this.
        let corrupted = Observation {
            body_sha: scenario::digest_hex(b"nonsense"),
            ..sample()
        };
        let expect = Expect::Exact {
            len: scenario::SMALL_LEN,
        };
        assert!(corrupted.verify("t", expect).is_err());
    }

    #[test]
    fn a_refusal_is_accepted_either_as_a_4xx_or_as_no_response() {
        let expect = Expect::Rejected;
        for status in [400u16, 431, 499] {
            assert!(
                Observation { status, ..sample() }
                    .verify("t", expect)
                    .is_ok(),
                "status {status} should count as a refusal"
            );
        }
        assert!(Observation::failed("stream reset")
            .verify("t", expect)
            .is_ok());
        // A 200 is not a refusal.
        assert!(sample().verify("t", expect).is_err());
        // Nor is a 5xx: that is a server fault, not a refusal.
        assert!(Observation {
            status: 500,
            ..sample()
        }
        .verify("t", expect)
        .is_err());
    }

    #[test]
    fn a_transport_failure_fails_every_successful_expectation() {
        let expect = Expect::Exact {
            len: scenario::SMALL_LEN,
        };
        assert!(Observation::failed("broken pipe")
            .verify("t", expect)
            .is_err());
    }

    #[test]
    fn trailing_and_early_hint_expectations_are_enforced() {
        let expect = Expect::Trailers {
            len: scenario::SMALL_LEN,
        };
        assert!(sample().verify("t", expect).is_err());
        let with_trailers = Observation {
            trailers: true,
            ..sample()
        };
        assert!(with_trailers.verify("t", expect).is_ok());

        let expect = Expect::EarlyHints {
            len: scenario::SMALL_LEN,
        };
        assert!(sample().verify("t", expect).is_err());
        let with_hints = Observation {
            early_hints: true,
            ..sample()
        };
        assert!(with_hints.verify("t", expect).is_ok());
    }

    #[test]
    fn unsupported_combinations_report_a_reason_rather_than_failing() {
        let curl = ClientSpec {
            id: "curl",
            name: "curl",
            protocols: &[Protocol::Http1, Protocol::Http2],
            capabilities: &[Capability::Upload],
            image: None,
            entrypoint: None,
            build_context: None,
        };
        let small = scenario::scenario_by_name("small_get").expect("small_get");
        let early_hints = scenario::scenario_by_name("early_hints").expect("early_hints");

        assert_eq!(curl.can_run(small, Protocol::Http1), None);
        assert_eq!(curl.can_run(small, Protocol::Http2), None);
        // Protocol the client cannot speak.
        assert!(curl.can_run(small, Protocol::Http3).is_some());
        // Scenario needing a capability the client lacks.
        assert!(curl.can_run(early_hints, Protocol::Http1).is_some());
    }

    #[test]
    fn argv_carries_the_scenario_parameters() {
        let args = ScenarioArgs {
            base_url: "http://127.0.0.1:8080".to_owned(),
            protocol: Protocol::Http2,
            scenario: "upload_echo_large",
            step: Step::Request {
                method: "POST",
                path: "/echo",
                upload_len: scenario::LARGE_LEN,
                expect: Expect::Echo {
                    len: scenario::LARGE_LEN,
                },
            },
        };
        let argv = args.to_argv();
        assert_eq!(argv[0], "http://127.0.0.1:8080");
        assert_eq!(argv[1], "h2");
        assert_eq!(argv[2], "upload_echo_large");
        assert!(argv.contains(&"method=POST".to_owned()));
        assert!(argv.contains(&"path=/echo".to_owned()));
        assert!(argv.contains(&format!("upload_len={}", scenario::LARGE_LEN)));
    }
}
