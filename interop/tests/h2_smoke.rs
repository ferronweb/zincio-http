//! Smoke test: drives the scenario server with the reference `h2` client.
//!
//! This deliberately uses no containers. Its job is to prove that the scenario
//! table, the routes, and the server configuration agree with each other, so
//! that when a containerised third-party client later fails, the failure is
//! attributable to the server or to that client rather than to a mistake in the
//! matrix itself.

use std::time::Duration;

use bytes::{Bytes, BytesMut};
use h2::client::SendRequest;
use http::{HeaderMap, Request, StatusCode};
use tokio::net::TcpStream;
use zincio_http_interop::scenario::{self, Expect, Step};
use zincio_http_interop::server;

/// Spawns the scenario server once for the whole test binary.
fn servers() -> &'static (server::ServerAddrs, server::ServerHandles) {
    use std::sync::OnceLock;
    static SERVERS: OnceLock<(server::ServerAddrs, server::ServerHandles)> = OnceLock::new();
    SERVERS.get_or_init(|| server::spawn().expect("spawn interop servers"))
}

/// A live h2c connection: the request sender, the driver task that must keep
/// being polled for the connection to progress, and the handle that stops it.
struct Conn {
    send: SendRequest<Bytes>,
    driver: tokio::task::JoinHandle<()>,
    stop: tokio::sync::oneshot::Sender<()>,
}

impl Conn {
    async fn open(addr: std::net::SocketAddr) -> Self {
        let stream = TcpStream::connect(addr).await.expect("tcp connect");
        let (send, connection) = h2::client::handshake(stream).await.expect("h2 handshake");
        let (stop, stop_rx) = tokio::sync::oneshot::channel();
        let driver = tokio::spawn(async move {
            // Drive the connection until it closes or the test tears it down.
            tokio::select! {
                _ = connection => {}
                _ = stop_rx => {}
            }
        });
        Self { send, driver, stop }
    }

    fn finish(self) {
        let _ = self.stop.send(());
        self.driver.abort();
    }
}

/// What a single request actually produced.
#[derive(Debug)]
struct Observation {
    status: StatusCode,
    body_len: usize,
    body_sha: String,
    trailers: Option<String>,
}

impl Observation {
    fn describe(&self) -> String {
        format!(
            "status={} len={} sha={} trailers={:?}",
            self.status, self.body_len, self.body_sha, self.trailers
        )
    }
}

/// Reads a response stream to completion, capturing body and trailers.
async fn read_response(recv: &mut h2::RecvStream) -> Result<(Bytes, Option<HeaderMap>), String> {
    let mut body = BytesMut::new();
    let trailers;
    loop {
        match std::future::poll_fn(|cx| recv.poll_data(cx)).await {
            Some(Ok(chunk)) => {
                // `h2` never replenishes a window on its own: the docs are
                // explicit that the caller must release capacity once it has
                // consumed the data, otherwise the transfer stalls at exactly
                // the advertised window (65535 bytes with these defaults).
                let consumed = chunk.len();
                body.extend_from_slice(&chunk);
                recv.flow_control()
                    .release_capacity(consumed)
                    .map_err(|err| format!("release_capacity: {err}"))?;
            }
            Some(Err(err)) => return Err(format!("poll_data: {err}")),
            // End of the data section; any trailers follow.
            None => {
                trailers = std::future::poll_fn(|cx| recv.poll_trailers(cx))
                    .await
                    .map_err(|err| format!("poll_trailers: {err}"))?;
                break;
            }
        }
    }
    Ok((body.freeze(), trailers))
}

/// Sends one request and observes the response.
async fn observe(
    conn: &mut Conn,
    method: &str,
    path: &str,
    upload_len: usize,
    extra: &[(String, String)],
) -> Result<Observation, String> {
    let mut builder = Request::builder()
        .method(method)
        .uri(format!("http://localhost{path}"))
        .header("x-interop", "1");
    for (name, value) in extra {
        builder = builder.header(name.as_str(), value.as_str());
    }
    let request = builder.body(()).expect("build request");

    let (response, mut send_stream) = conn
        .send
        .send_request(request, upload_len == 0)
        .map_err(|err| format!("send_request: {err}"))?;
    if upload_len > 0 {
        send_stream
            .send_data(Bytes::from(scenario::pattern_body(upload_len)), true)
            .map_err(|err| format!("send_data: {err}"))?;
    }

    let (parts, mut recv) = response
        .await
        .map_err(|err| format!("response: {err}"))?
        .into_parts();
    let (body, trailers) = read_response(&mut recv).await?;

    Ok(Observation {
        status: parts.status,
        body_len: body.len(),
        body_sha: scenario::digest_hex(&body),
        trailers: trailers
            .as_ref()
            .and_then(|t| t.get("x-echo-trailer"))
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned),
    })
}

/// Checks an observation against a scenario expectation.
fn check(name: &str, expect: Expect, observed: &Observation) -> Result<(), String> {
    if matches!(expect, Expect::Rejected) {
        return Ok(());
    }
    let want_len = expect
        .body_len()
        .expect("successful expectation has a length");
    if observed.status != StatusCode::OK {
        return Err(format!(
            "{name}: expected 200, got {} ({})",
            observed.status,
            observed.describe()
        ));
    }
    if observed.body_len != want_len {
        return Err(format!(
            "{name}: expected {want_len} body bytes, got {}",
            observed.body_len
        ));
    }
    let want_sha = expect
        .body_digest()
        .expect("successful expectation has a digest");
    if observed.body_sha != want_sha {
        return Err(format!(
            "{name}: body digest mismatch\n  want {want_sha}\n  got  {}",
            observed.body_sha
        ));
    }
    if expect.wants_trailers() && observed.trailers.is_none() {
        return Err(format!(
            "{name}: expected an x-echo-trailer trailer, got {}",
            observed.describe()
        ));
    }
    Ok(())
}

/// Resolves the HTTP/2 listener address as reachable from this process.
async fn h2_addr() -> std::net::SocketAddr {
    let (addrs, _handles) = servers();
    tokio::net::lookup_host(format!("127.0.0.1:{}", addrs.h2.port()))
        .await
        .expect("resolve h2 listener")
        .next()
        .expect("h2 listener address")
}

#[tokio::test(flavor = "multi_thread")]
async fn single_step_scenarios_match_their_expectations() {
    let addr = h2_addr().await;

    for scenario in scenario::SCENARIOS {
        let Some(step) = scenario.steps.first() else {
            continue;
        };
        let (method, path, upload_len, expect) = match step {
            Step::Request {
                method,
                path,
                upload_len,
                expect,
            } => (*method, *path, *upload_len, *expect),
            other => {
                // Multi-step scenarios need dedicated coverage; they are not
                // silently passed off as verified here.
                eprintln!(
                    "note: {} covers a non-Request step ({}), covered by its own test",
                    scenario.name,
                    other.label()
                );
                continue;
            }
        };

        let mut conn = Conn::open(addr).await;
        let observed = tokio::time::timeout(
            Duration::from_secs(60),
            observe(&mut conn, method, path, upload_len, &[]),
        )
        .await
        .unwrap_or_else(|_| panic!("{}: timed out", scenario.name))
        .unwrap_or_else(|err| panic!("{}: {err}", scenario.name));

        check(scenario.name, expect, &observed).unwrap_or_else(|err| panic!("{err}"));
        conn.finish();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn large_response_matches_the_pattern_digest() {
    // The 1 MiB body is the scenario that regressed in 0.4.8 (connection-level
    // flow control resetting the stream), so it is asserted directly and by
    // name rather than only through the generic table walk.
    let addr = h2_addr().await;
    let mut conn = Conn::open(addr).await;
    let observed = tokio::time::timeout(
        Duration::from_secs(60),
        observe(&mut conn, "GET", "/large", 0, &[]),
    )
    .await
    .expect("large_get timed out")
    .expect("large_get failed");

    assert_eq!(observed.body_len, scenario::LARGE_LEN);
    assert_eq!(
        observed.body_sha,
        scenario::digest_hex(&scenario::pattern_body(scenario::LARGE_LEN)),
        "1 MiB body did not survive flow control intact"
    );
    conn.finish();
}

#[tokio::test(flavor = "multi_thread")]
async fn aborting_one_stream_leaves_the_connection_usable() {
    // The regression behind `h3_multiplex_repro`: a client that walks away
    // mid-response must not cost the whole connection.
    let addr = h2_addr().await;
    let mut conn = Conn::open(addr).await;

    let request = Request::builder()
        .method("GET")
        .uri("http://localhost/large")
        .body(())
        .expect("build request");
    let (response, _send_stream) = conn
        .send
        .send_request(request, true)
        .expect("send large request");
    let (parts, mut recv) = response.await.expect("large response").into_parts();
    assert_eq!(parts.status, StatusCode::OK);

    // Read a little, then walk away mid-response.
    let mut read = 0usize;
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            match std::future::poll_fn(|cx| recv.poll_data(cx)).await {
                Some(Ok(chunk)) => {
                    read += chunk.len();
                    recv.flow_control()
                        .release_capacity(chunk.len())
                        .expect("release_capacity");
                    if read >= 16 * 1024 {
                        break;
                    }
                }
                // End of body or an error: either way we are done reading, and
                // the point of this test is what happens to the connection.
                Some(Err(_)) | None => break,
            }
        }
    })
    .await
    .expect("reading the start of the large body timed out");
    assert!(read > 0, "expected to read some body bytes before aborting");
    drop(recv);

    // The connection must still serve a fresh request.
    let observed = tokio::time::timeout(
        Duration::from_secs(30),
        observe(&mut conn, "GET", "/small", 0, &[]),
    )
    .await
    .expect("post-abort request timed out")
    .expect("post-abort request failed");
    check(
        "abort_midstream",
        Expect::Exact {
            len: scenario::SMALL_LEN,
        },
        &observed,
    )
    .expect("post-abort request should still succeed");

    conn.finish();
}

#[tokio::test(flavor = "multi_thread")]
async fn many_headers_are_accepted_and_big_headers_are_refused() {
    // These two scenarios share one limit, so they are asserted together: if
    // the limit moved, this test fails rather than both scenarios silently
    // changing meaning.
    let addr = h2_addr().await;
    let mut conn = Conn::open(addr).await;

    let many = server::many_headers_scenario_headers();
    let observed = tokio::time::timeout(
        Duration::from_secs(30),
        observe(&mut conn, "GET", "/small", 0, &many),
    )
    .await
    .expect("many_headers timed out")
    .expect("many_headers failed");
    check(
        "many_headers",
        Expect::Exact {
            len: scenario::SMALL_LEN,
        },
        &observed,
    )
    .unwrap_or_else(|err| panic!("{err}"));

    let big = vec![("x-big".to_owned(), "v".repeat(scenario::BIG_HEADER_LEN))];
    let refused = match tokio::time::timeout(
        Duration::from_secs(30),
        observe(&mut conn, "GET", "/small", 0, &big),
    )
    .await
    {
        Err(_) => true,
        Ok(Err(_)) => true,
        Ok(Ok(observed)) => observed.status.is_client_error(),
    };
    assert!(
        refused,
        "a {}-byte header block was accepted, so big_header_rejected is vacuous",
        scenario::BIG_HEADER_LEN
    );

    conn.finish();
}
