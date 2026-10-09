//! The registry of third-party clients in the matrix.
//!
//! Declaring capabilities conservatively is deliberate: a scenario needing
//! something a client genuinely cannot observe should be skipped with a
//! reason, not failed. Guessing in a client's favour turns a tooling
//! limitation into a phantom server bug, which is exactly the failure mode this
//! suite has to avoid.

use crate::client::{ClientSpec, Entrypoint, ImageSpec, Protocol};
use crate::scenario::Capability;

/// Capabilities curl can genuinely observe.
///
/// Notably absent: response trailers and 1xx informational responses, which
/// curl cannot surface, and concurrency, since it makes one request per
/// invocation. Claiming any of these would turn a curl limitation into a
/// phantom server bug.
const CURL_CAPABILITIES: &[Capability] = &[
    Capability::Upload,
    Capability::Abort,
    Capability::BigHeader,
    Capability::LongUri,
    Capability::ManyHeaders,
    // curl opens a connection per invocation, so what this actually verifies
    // is that the server stays usable after a previous connection has idled
    // out and been reaped -- not that curl reuses a pooled connection.
    Capability::IdleReuse,
];

/// curl over HTTP/1.1 and HTTP/2, from the official image plus our driver.
///
/// An HTTP/3-capable curl is not registered yet: building one requires a
/// source build whose CMake configure step is still unresolved. See the
/// recipe left in `clients/curl/Dockerfile`.
///
/// curl is the client that found the 0.4.2 HTTP/3 stream reset, and it is on
/// every CI runner, so it earns its place twice: as an independent
/// HPACK/flow-control implementation and as a reproducibility anchor.
pub static CURL: ClientSpec = ClientSpec {
    id: "curl",
    name: "curl (HTTP/1.1 + HTTP/2)",
    protocols: &[Protocol::Http1, Protocol::Http2],
    capabilities: CURL_CAPABILITIES,
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-curl",
        context: "curl",
        target: "driver",
    }),
    entrypoint: Some(Entrypoint {
        program: "/usr/local/bin/interop-driver",
        args: &[],
    }),
    build_context: Some("clients/curl"),
};

/// aioquic over HTTP/3: an independent Python QUIC + QPACK stack.
///
/// Unlike curl this client can observe response trailers and 103 Early Hints,
/// which is why it carries those scenarios. The pip install needs no C
/// toolchain, so this image builds in under a minute.
pub static AIOQUIC: ClientSpec = ClientSpec {
    id: "aioquic",
    name: "aioquic (HTTP/3)",
    protocols: &[Protocol::Http3],
    capabilities: &[
        Capability::Upload,
        Capability::ResponseTrailers,
        Capability::RequestTrailers,
        Capability::Concurrency,
        Capability::Abort,
        // No ExpectContinue, no EarlyHints: aioquic's H3 HEADERS state machine
        // is INITIAL -> AFTER_HEADERS -> AFTER_TRAILERS with no informational
        // state, so any second HEADERS block is validated as trailers (which
        // allow no pseudo-headers) and the connection is torn down with
        // H3_MESSAGE_ERROR (0x10e, "Pseudo-header ':status' is not valid").
        // A legal 103-then-200 or 100-then-200 therefore kills the connection.
        // The server side is RFC 9114 section 4.1 compliant -- the `h3` crate
        // handles the same exchange correctly -- so this is an aioquic 1.3.0
        // limitation, and these scenarios stay covered by the in-repo
        // fixture-client tests.
        Capability::BigHeader,
        // No LongUri: aioquic encodes headers through pylsqpack, whose C
        // encoder rejects an 8 KiB header value outright. The scenario stays
        // covered by clients whose HPACK encoder accepts it.
        Capability::ManyHeaders,
        Capability::IdleReuse,
    ],
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-aioquic",
        context: "aioquic",
        target: "driver",
    }),
    entrypoint: Some(Entrypoint {
        program: "/usr/local/bin/interop-driver",
        args: &[],
    }),
    build_context: Some("clients/aioquic"),
};

/// curl over HTTP/3, built from source against ngtcp2.
///
/// A separate client rather than extra protocols on [`CURL`] because the image
/// is expensive: keeping it distinct lets the cheap curl image stay in the
/// per-pull-request path while this one is built and cached separately. Shares
/// curl's conservative capability set: it cannot observe trailers or 1xx.
pub static CURL_HTTP3: ClientSpec = ClientSpec {
    id: "curl-http3",
    name: "curl (HTTP/3, ngtcp2)",
    protocols: &[Protocol::Http3],
    capabilities: CURL_CAPABILITIES,
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-curl-http3",
        context: "curl",
        target: "http3",
    }),
    entrypoint: Some(Entrypoint {
        program: "/usr/local/bin/interop-driver",
        args: &[],
    }),
    build_context: Some("clients/curl"),
};

/// Go net/http over HTTP/1.1 and h2c, built from a checked-in program.
///
/// x/net/http2/hpack is the third independent HPACK encoder in the matrix,
/// and goroutines make it the second client (with aioquic) that drives real
/// concurrent streams, so HTTP/2 concurrency is no longer covered by a single
/// implementation.
pub static GO: ClientSpec = ClientSpec {
    id: "go",
    name: "Go net/http",
    protocols: &[Protocol::Http1, Protocol::Http2],
    capabilities: &[
        Capability::Upload,
        Capability::Concurrency,
        // 103 is observed through httptrace.Got1xxResponse, which fires on
        // both HTTP/1.1 and HTTP/2.
        Capability::EarlyHints,
        // The Expect header is sent explicitly; the final Echo verifies the
        // exchange completed.
        Capability::ExpectContinue,
        Capability::BigHeader,
        Capability::LongUri,
        Capability::ManyHeaders,
    ],
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-go",
        context: "go",
        target: "driver",
    }),
    entrypoint: Some(Entrypoint {
        program: "/usr/local/bin/interop-driver",
        args: &[],
    }),
    build_context: Some("clients/go"),
};

/// hyper-h2 over HTTP/2: the popular Python HTTP/2 stack with raw frame control.
///
/// Unlike curl this client can observe 103 Early Hints and response trailers,
/// which is what closes the container-coverage gap curl leaves on those two
/// scenarios. Its HPACK encoder is the fourth independent one in the matrix.
pub static PYTHON_H2: ClientSpec = ClientSpec {
    id: "python-h2",
    name: "Python hyper-h2",
    protocols: &[Protocol::Http2],
    capabilities: &[
        Capability::Upload,
        // Response trailers arrive via the 'trailers' event and are verified
        // working. Request trailers are absent on purpose: Node's
        // ClientHttp2Stream has no addTrailers (server-side only), so they
        // cannot be sent at all.
        Capability::ResponseTrailers,
        Capability::Concurrency,
        Capability::Abort,
        // No EarlyHints: Node swallows 103, emitting only the final response.
        // No ExpectContinue: the driver does not perform the 100-continue
        // dance, so claiming it would exercise nothing.
        Capability::BigHeader,
        Capability::LongUri,
        Capability::ManyHeaders,
        Capability::IdleReuse,
    ],
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-python-h2",
        context: "python-h2",
        target: "driver",
    }),
    entrypoint: Some(Entrypoint {
        program: "/usr/local/bin/interop-driver",
        args: &[],
    }),
    build_context: Some("clients/python-h2"),
};

/// quic-go over HTTP/3: the Go QUIC stack behind Caddy and many CDNs.
///
/// Unlike aioquic it observes 103 Early Hints (its httptrace fires) and
/// trailers, and its QPACK encoder accepts 8 KiB values, so it carries the
/// full H3 matrix including the 1xx scenarios aioquic cannot run. Two
/// independent H3 client stacks handling 103 correctly, against one that
/// cannot, is itself evidence about where that limitation lives.
pub static QUIC_GO: ClientSpec = ClientSpec {
    id: "quic-go",
    name: "quic-go (HTTP/3)",
    protocols: &[Protocol::Http3],
    capabilities: &[
        Capability::Upload,
        Capability::ResponseTrailers,
        Capability::RequestTrailers,
        Capability::Concurrency,
        Capability::Abort,
        Capability::ExpectContinue,
        Capability::EarlyHints,
        Capability::BigHeader,
        Capability::LongUri,
        Capability::ManyHeaders,
        Capability::IdleReuse,
    ],
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-quic-go",
        context: "quic-go",
        target: "driver",
    }),
    entrypoint: Some(Entrypoint {
        program: "/usr/local/bin/interop-driver",
        args: &[],
    }),
    build_context: Some("clients/quic-go"),
};

/// OkHttp over HTTP/1.1 and h2c: the JVM/Android HTTP stack.
///
/// OkHttp only negotiates HTTP/2 over TLS by default, so the driver selects
/// Protocol.H2_PRIOR_KNOWLEDGE for cleartext URLs. Its HPACK encoder is the
/// fifth independent one in the matrix. Response trailers are observed
/// through Response.trailers(); 103 Early Hints are swallowed internally and
/// therefore not claimed.
pub static OKHTTP: ClientSpec = ClientSpec {
    id: "okhttp",
    name: "OkHttp (JVM)",
    protocols: &[Protocol::Http1, Protocol::Http2],
    capabilities: &[
        Capability::Upload,
        Capability::ResponseTrailers,
        Capability::Concurrency,
        Capability::ExpectContinue,
        Capability::BigHeader,
        Capability::LongUri,
        Capability::ManyHeaders,
    ],
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-okhttp",
        context: "okhttp",
        target: "driver",
    }),
    entrypoint: Some(Entrypoint {
        program: "java",
        args: &[
            "-cp",
            "/app:/app/okhttp.jar:/app/okio.jar:/app/kotlin-stdlib.jar:/app/annotations.jar",
            "OkHttpDriver",
        ],
    }),
    build_context: Some("clients/okhttp"),
};

/// Node stdlib http2 over h2c: the JavaScript runtime's HTTP/2 stack.
///
/// Node connects with h2c prior knowledge for http: URLs, so no TLS setup is
/// needed. Its HPACK encoder is the sixth independent one in the matrix.
/// Trailer and 103 observation ride on the standard events; capabilities are
/// declared from what the driver verifies rather than assumed.
pub static NODE: ClientSpec = ClientSpec {
    id: "node",
    name: "Node http2",
    protocols: &[Protocol::Http2],
    capabilities: &[
        Capability::Upload,
        // Response trailers arrive via the 'trailers' event and are verified
        // working. Request trailers are absent on purpose: Node's
        // ClientHttp2Stream has no addTrailers (server-side only), so they
        // cannot be sent at all.
        Capability::ResponseTrailers,
        Capability::Concurrency,
        Capability::Abort,
        // No EarlyHints: Node swallows 103, emitting only the final response.
        // No ExpectContinue: the driver does not perform the 100-continue
        // dance, so claiming it would exercise nothing.
        Capability::BigHeader,
        Capability::LongUri,
        Capability::ManyHeaders,
        Capability::IdleReuse,
    ],
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-node",
        context: "node",
        target: "driver",
    }),
    entrypoint: Some(Entrypoint {
        program: "node",
        args: &["/usr/local/bin/interop-driver"],
    }),
    build_context: Some("clients/node"),
};

/// quiche over HTTP/3: Cloudflare's QUIC stack behind its edge and cloudflared.
///
/// Its QPACK encoder and congestion control differ meaningfully from quic-go,
/// aioquic, and quinn, so it is a second full-matrix H3 opinion alongside
/// quic-go. One quiche-specific detail lives in the driver rather than here:
/// quiche sends HEADERS atomically, and a fresh connection's congestion window
/// cannot fit the 32 KiB `big_header_rejected` block, so the driver primes the
/// window with a sacrificial upload on the same connection first. The scenario
/// still asserts exactly the refusal it should.
pub static QUICHE: ClientSpec = ClientSpec {
    id: "quiche",
    name: "quiche (HTTP/3)",
    protocols: &[Protocol::Http3],
    capabilities: &[
        Capability::Upload,
        Capability::ResponseTrailers,
        Capability::RequestTrailers,
        Capability::Concurrency,
        Capability::Abort,
        Capability::ExpectContinue,
        Capability::EarlyHints,
        Capability::BigHeader,
        Capability::LongUri,
        Capability::ManyHeaders,
        Capability::IdleReuse,
    ],
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-quiche",
        context: "quiche",
        target: "driver",
    }),
    entrypoint: Some(Entrypoint {
        program: "/usr/local/bin/interop-driver",
        args: &[],
    }),
    build_context: Some("clients/quiche"),
};

/// neqo over HTTP/3: Mozilla's QUIC stack used in Firefox.
///
/// Its client is the stable, production-hardened side (the server exists only
/// to test the client), which is exactly the opinion this matrix wants. Notably
/// absent: both trailer directions. neqo's client API has no way to send
/// request trailers, and its source is explicit that received response
/// trailers are ignored (`TODO implement trailers, for now just ignore them`
/// in `recv_message.rs`), so claiming either would turn a tooling limitation
/// into a phantom server bug. The `trailers` scenario therefore stays covered
/// by aioquic, quic-go, and quiche.
pub static NEQO: ClientSpec = ClientSpec {
    id: "neqo",
    name: "neqo (HTTP/3)",
    protocols: &[Protocol::Http3],
    capabilities: &[
        Capability::Upload,
        Capability::Concurrency,
        Capability::Abort,
        Capability::ExpectContinue,
        Capability::EarlyHints,
        Capability::BigHeader,
        Capability::LongUri,
        Capability::ManyHeaders,
        Capability::IdleReuse,
    ],
    image: Some(ImageSpec::Build {
        tag: "zincio-http-interop-neqo",
        context: "neqo",
        target: "driver",
    }),
    entrypoint: Some(Entrypoint {
        program: "/usr/local/bin/interop-driver",
        args: &[],
    }),
    build_context: Some("clients/neqo"),
};

/// Every client currently in the matrix.
pub static ALL_CLIENTS: &[&ClientSpec] = &[
    &CURL,
    &AIOQUIC,
    &CURL_HTTP3,
    &GO,
    &PYTHON_H2,
    &QUIC_GO,
    &OKHTTP,
    &NODE,
    &QUICHE,
    &NEQO,
];

/// The clients to run, honouring `ZINCIO_INTEROP_CLIENTS`.
///
/// Lets a cheap lane run only the fast images while a scheduled lane builds the
/// expensive ones, without maintaining two lists that could drift.
pub fn selected() -> Vec<&'static ClientSpec> {
    let Ok(filter) = std::env::var("ZINCIO_INTEROP_CLIENTS") else {
        return ALL_CLIENTS.to_vec();
    };
    let wanted: Vec<&str> = filter
        .split(',')
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .collect();

    let selected: Vec<&'static ClientSpec> = ALL_CLIENTS
        .iter()
        .copied()
        .filter(|client| wanted.contains(&client.id))
        .collect();

    assert!(
        !selected.is_empty(),
        "ZINCIO_INTEROP_CLIENTS={filter:?} matched no known client; known ids: {:?}",
        ALL_CLIENTS.iter().map(|c| c.id).collect::<Vec<_>>()
    );
    selected
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario;

    #[test]
    fn client_ids_are_unique() {
        let mut ids: Vec<&str> = ALL_CLIENTS.iter().map(|c| c.id).collect();
        ids.sort_unstable();
        let count = ids.len();
        ids.dedup();
        assert_eq!(ids.len(), count, "duplicate client id");
    }

    #[test]
    fn every_client_has_a_runnable_configuration() {
        for client in ALL_CLIENTS {
            assert!(
                client.entrypoint.is_some(),
                "{} has no driver entrypoint",
                client.id
            );
            assert!(
                client.image.is_some(),
                "{} is registered but has no image, so it cannot be started",
                client.id
            );
            assert!(
                !client.protocols.is_empty(),
                "{} speaks no protocols",
                client.id
            );
        }
    }

    #[test]
    fn every_client_image_has_a_dockerfile() {
        let docker_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("clients");
        for client in ALL_CLIENTS {
            let Some(crate::client::ImageSpec::Build { context, .. }) = client.image else {
                continue;
            };
            assert!(
                docker_dir.join(context).join("Dockerfile").exists(),
                "{}: missing clients/{context}/Dockerfile",
                client.id
            );
        }
    }

    /// Protocols with no containerised client yet.
    ///
    /// Listed explicitly rather than merely tolerated, so that *removing* an
    /// entry is what closes the gap. A protocol that becomes uncovered by
    /// accident is not in this list and therefore still fails the test.
    const KNOWN_UNCOVERED_PROTOCOLS: &[Protocol] = &[];

    #[test]
    fn every_protocol_is_covered_or_listed_as_a_known_gap() {
        // A client set that quietly stops covering a protocol would let a whole
        // protocol rot without any test noticing.
        for protocol in Protocol::all() {
            let covered = ALL_CLIENTS.iter().any(|c| c.protocols.contains(&protocol));
            let known_gap = KNOWN_UNCOVERED_PROTOCOLS.contains(&protocol);
            assert!(
                covered || known_gap,
                "no client speaks {}, and it is not listed in \
                 KNOWN_UNCOVERED_PROTOCOLS",
                protocol.name()
            );
            assert!(
                !(covered && known_gap),
                "{} now has a client, so remove it from \
                 KNOWN_UNCOVERED_PROTOCOLS",
                protocol.name()
            );
        }
    }

    #[test]
    fn every_known_uncovered_protocol_really_is_uncovered() {
        // Otherwise a stale entry would let a future regression hide behind it.
        for protocol in KNOWN_UNCOVERED_PROTOCOLS {
            assert!(
                !ALL_CLIENTS.iter().any(|c| c.protocols.contains(protocol)),
                "{} is listed as uncovered but has a client",
                protocol.name()
            );
        }
    }

    #[test]
    fn at_least_one_scenario_is_runnable_by_every_client() {
        // Guards against a client declaring so few capabilities that the
        // matrix silently becomes empty for it.
        for client in ALL_CLIENTS {
            for protocol in client.protocols {
                let runnable = scenario::SCENARIOS
                    .iter()
                    .filter(|s| client.can_run(s, *protocol).is_none())
                    .count();
                assert!(
                    runnable > 0,
                    "{} can run no scenario over {}",
                    client.id,
                    protocol.name()
                );
            }
        }
    }

    #[test]
    fn curl_declares_only_what_it_can_actually_observe() {
        // curl cannot surface response trailers or 1xx informational responses.
        // If these are ever claimed, the matching scenarios would report a
        // server bug that is really a curl limitation.
        assert!(!CURL.capabilities.contains(&Capability::ResponseTrailers));
        assert!(!CURL.capabilities.contains(&Capability::EarlyHints));
        // One request per invocation, so no real concurrency.
        assert!(!CURL.capabilities.contains(&Capability::Concurrency));
    }
}
