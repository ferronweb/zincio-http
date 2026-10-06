//! Smoke test: drives the scenario server with hyper, in process.
//!
//! hyper is the client that found the 0.4.8 large-body flow-control bug, so
//! this file replays that regression directly: hyper's flow-control strategy
//! is independent of both the `h2` crate's (which needs manual
//! `release_capacity`) and curl's, which makes it a third opinion on the same
//! behavior. No containers are involved; this validates the matrix inputs
//! before any containerised client runs them.

use std::time::Duration;

use bytes::Bytes;
use http::{Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::net::TcpStream;
use zincio_http_interop::scenario::{self, Expect};
use zincio_http_interop::server;

/// Spawns the scenario server once for the whole test binary.
fn servers() -> &'static (server::ServerAddrs, server::ServerHandles) {
    use std::sync::OnceLock;
    static SERVERS: OnceLock<(server::ServerAddrs, server::ServerHandles)> = OnceLock::new();
    SERVERS.get_or_init(|| server::spawn().expect("spawn interop servers"))
}

/// Which protocol to speak.
#[derive(Clone, Copy)]
enum Protocol {
    H1,
    H2,
}

impl Protocol {
    fn port(self, addrs: &server::ServerAddrs) -> u16 {
        match self {
            Protocol::H1 => addrs.h1.port(),
            Protocol::H2 => addrs.h2.port(),
        }
    }

    fn name(self) -> &'static str {
        match self {
            Protocol::H1 => "h1",
            Protocol::H2 => "h2",
        }
    }
}

type SendRequestH1 = hyper::client::conn::http1::SendRequest<Full<Bytes>>;
type SendRequestH2 = hyper::client::conn::http2::SendRequest<Full<Bytes>>;

enum Sender {
    H1(SendRequestH1),
    H2(SendRequestH2),
}

struct ConnAny {
    sender: Sender,
    _driver: tokio::task::JoinHandle<()>,
}

impl ConnAny {
    async fn open(protocol: Protocol, addr: std::net::SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("tcp connect");
        let io = TokioIo::new(stream);
        match protocol {
            Protocol::H1 => {
                let (sender, conn) = hyper::client::conn::http1::handshake(io)
                    .await
                    .expect("h1 handshake");
                let driver = tokio::spawn(async move {
                    let _ = conn.await;
                });
                Self {
                    sender: Sender::H1(sender),
                    _driver: driver,
                }
            }
            Protocol::H2 => {
                let (sender, conn) =
                    hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                        .await
                        .expect("h2 handshake");
                let driver = tokio::spawn(async move {
                    let _ = conn.await;
                });
                Self {
                    sender: Sender::H2(sender),
                    _driver: driver,
                }
            }
        }
    }

    async fn request(
        &mut self,
        method: &str,
        url: String,
        upload: Vec<u8>,
        extra: &[(String, String)],
    ) -> Result<(StatusCode, Vec<u8>), String> {
        let mut builder = Request::builder().method(method).uri(&url).header("x-interop", "1");
        for (name, value) in extra {
            builder = builder.header(name.as_str(), value.as_str());
        }
        let request = builder
            .body(Full::new(Bytes::from(upload)))
            .map_err(|err| format!("build request: {err}"))?;

        let response = match &mut self.sender {
            Sender::H1(sender) => sender
                .send_request(request)
                .await
                .map_err(|err| format!("send_request: {err}"))?,
            Sender::H2(sender) => sender
                .send_request(request)
                .await
                .map_err(|err| format!("send_request: {err}"))?,
        };
        let status = response.status();
        let collected = response
            .into_body()
            .collect()
            .await
            .map_err(|err| format!("collect body: {err}"))?;
        Ok((status, collected.to_bytes().to_vec()))
    }
}

/// Resolves the listener address for `protocol` as reachable from this process.
async fn addr_for(protocol: Protocol) -> std::net::SocketAddr {
    let (addrs, _handles) = servers();
    tokio::net::lookup_host(format!("127.0.0.1:{}", protocol.port(addrs)))
        .await
        .expect("resolve listener")
        .next()
        .expect("listener address")
}

/// Checks a response against an expectation, mirroring the container harness
/// so the two stay comparable.
fn check(name: &str, protocol: Protocol, expect: Expect, status: StatusCode, body: &[u8]) {
    let label = format!("{name} over {}", protocol.name());
    match expect {
        Expect::Rejected => {
            assert!(
                status.is_client_error(),
                "{label}: expected refusal, got {status}"
            );
        }
        _ => {
            let want_len = expect.body_len().expect("successful expectation has a length");
            assert_eq!(status, StatusCode::OK, "{label}: expected 200");
            assert_eq!(
                body.len(),
                want_len,
                "{label}: expected {want_len} body bytes"
            );
            let want_sha = expect.body_digest().expect("successful expectation has a digest");
            assert_eq!(
                scenario::digest_hex(body),
                want_sha,
                "{label}: body digest mismatch"
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hyper_matches_the_scenario_matrix() {
    for protocol in [Protocol::H1, Protocol::H2] {
        let addr = addr_for(protocol).await;
        // (scenario, method, path, upload_len, extra headers, expect)
        let cases: Vec<(&str, &str, &str, usize, Vec<(String, String)>, Expect)> = vec![
            (
                "small_get",
                "GET",
                "/small",
                0,
                vec![],
                Expect::Exact {
                    len: scenario::SMALL_LEN,
                },
            ),
            (
                "upload_echo_small",
                "POST",
                "/echo",
                scenario::SMALL_LEN,
                vec![],
                Expect::Echo {
                    len: scenario::SMALL_LEN,
                },
            ),
            (
                "large_get",
                "GET",
                "/large",
                0,
                vec![],
                Expect::Exact {
                    len: scenario::LARGE_LEN,
                },
            ),
            (
                "upload_echo_large",
                "POST",
                "/echo",
                scenario::LARGE_LEN,
                vec![],
                Expect::Echo {
                    len: scenario::LARGE_LEN,
                },
            ),
            (
                "many_headers",
                "GET",
                "/small",
                0,
                server::many_headers_scenario_headers(),
                Expect::Exact {
                    len: scenario::SMALL_LEN,
                },
            ),
        ];

        for (name, method, path, upload_len, extra, expect) in cases {
            let mut conn = ConnAny::open(protocol, addr).await;
            let url = format!("http://localhost{path}");
            let upload = scenario::pattern_body(upload_len);
            let (status, body) = tokio::time::timeout(
                Duration::from_secs(60),
                conn.request(method, url, upload, &extra),
            )
            .await
            .unwrap_or_else(|_| panic!("{name} over {} timed out", protocol.name()))
            .unwrap_or_else(|err| panic!("{name} over {}: {err}", protocol.name()));
            check(name, protocol, expect, status, &body);
        }

        // big_header_rejected: refused either as a 4xx or as a transport error.
        let mut conn = ConnAny::open(protocol, addr).await;
        let big = vec![(
            "x-big".to_owned(),
            "v".repeat(scenario::BIG_HEADER_LEN),
        )];
        let refused = match tokio::time::timeout(
            Duration::from_secs(30),
            conn.request(
                "GET",
                "http://localhost/small".to_owned(),
                vec![],
                &big,
            ),
        )
        .await
        {
            Err(_) => true,
            Ok(Err(_)) => true,
            Ok(Ok((status, _))) => status.is_client_error(),
        };
        assert!(
            refused,
            "big_header_rejected over {}: a {}-byte header block was accepted",
            protocol.name(),
            scenario::BIG_HEADER_LEN
        );
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn hyper_concurrent_streams_all_complete() {
    // Thirty-two concurrent streams on one HTTP/2 connection, each digest
    // checked: the same shape as the container concurrency scenario, driven
    // here by hyper's own multiplexing.
    let addr = addr_for(Protocol::H2).await;
    let mut conn = ConnAny::open(Protocol::H2, addr).await;
    let Sender::H2(sender) = &mut conn.sender else {
        panic!("expected an H2 sender");
    };

    let mut tasks = Vec::new();
    for _ in 0..32 {
        let mut sender = sender.clone();
        tasks.push(tokio::spawn(async move {
            let request = Request::builder()
                .method("GET")
                .uri("http://localhost/small")
                .header("x-interop", "1")
                .body(Full::new(Bytes::new()))
                .expect("build request");
            let response = sender
                .send_request(request)
                .await
                .expect("send_request");
            assert_eq!(response.status(), StatusCode::OK);
            let body = response
                .into_body()
                .collect()
                .await
                .expect("collect")
                .to_bytes();
            assert_eq!(body.len(), scenario::SMALL_LEN);
            assert_eq!(
                scenario::digest_hex(&body),
                scenario::digest_hex(&scenario::pattern_body(scenario::SMALL_LEN))
            );
        }));
    }
    for task in tasks {
        tokio::time::timeout(Duration::from_secs(60), task)
            .await
            .expect("stream timed out")
            .expect("stream panicked");
    }
}
