//! Reproduction for: a large response (e.g. a `.mp4`) streamed on one stream
//! starves other concurrent requests on the same HTTP/3 connection.
//!
//! We stand up the real `Http3` server (zincio runtime) with a handler that,
//! for `/large`, streams a multi-megabyte body in small delayed chunks (so the
//! response stays in flight for several seconds, like a big download), and for
//! `/small` returns a tiny body immediately. A single H3 client connection then
//! issues one `/large` request and, while it is in flight, fires many `/small`
//! requests. If the server multiplexes correctly, every `/small` completes in
//! well under the large-response duration; if it starves them, they only finish
//! once the large response ends (or hang).

#![cfg(feature = "h3-quinn")]

use std::convert::Infallible;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode};
use http_body::Frame;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, StreamBody};
use quinn::Endpoint;
use std::sync::mpsc;
use tokio_util::sync::CancellationToken;
use zincio::RuntimeBuilder;
use zincio_http::{
    quinn::Connection as QuinnConnection, Http3, Http3Options, HttpProtocol, Incoming,
};

const LARGE_TOTAL: usize = 256 * 1024 * 1024;
const LARGE_CHUNK: usize = 64 * 1024;

async fn loopback_pair(tiny: bool) -> (Endpoint, Endpoint, quinn::Connection, quinn::Connection) {
    let cert = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let cert_der: quinn::rustls::pki_types::CertificateDer<'static> = cert.cert.into();

    let server_config = quinn::ServerConfig::with_single_cert(
        vec![cert_der.clone()],
        quinn::rustls::pki_types::PrivateKeyDer::from(cert.signing_key),
    )
    .unwrap();
    let server_endpoint = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
    let server_addr = server_endpoint.local_addr().unwrap();

    let mut client_tc = quinn::TransportConfig::default();
    if tiny {
        // Mimic a constrained client (e.g. Firefox on Windows) that advertises
        // small flow-control windows, so a large response is heavily
        // flow-control-limited and forces many re-polls.
        client_tc.stream_receive_window(quinn::VarInt::from_u32(16384));
        client_tc.receive_window(quinn::VarInt::from_u32(16384));
    }
    let mut roots = quinn::rustls::RootCertStore::empty();
    roots.add(cert_der).unwrap();
    let mut client_config = quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap();
    client_config.transport_config(Arc::new(client_tc));
    let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
    client_endpoint.set_default_client_config(client_config);

    let connecting = client_endpoint
        .connect(server_addr, "localhost")
        .expect("connect");
    let incoming = server_endpoint
        .accept()
        .await
        .expect("accept must eventually yield");
    let (client_conn, server_conn) = tokio::join!(
        async { connecting.await.expect("client handshake") },
        async { incoming.await.expect("server handshake") },
    );
    (server_endpoint, client_endpoint, client_conn, server_conn)
}

fn spawn_native_server<F, Fut>(
    server_conn: quinn::Connection,
    options: Http3Options,
    cancel: CancellationToken,
    handler: F,
) -> (
    std::thread::JoinHandle<()>,
    mpsc::Receiver<Result<(), String>>,
)
where
    F: Fn(Request<Incoming>) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<Response<BoxBody<Bytes, Infallible>>, Infallible>>
        + Send
        + 'static,
{
    let (result_tx, result_rx) = mpsc::channel();
    let thread = std::thread::spawn(move || {
        let rt = RuntimeBuilder::new()
            .enable_timer(true)
            .build()
            .expect("zincio runtime");
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            rt.block_on(async move {
                Http3::new(QuinnConnection::new(server_conn), options)
                    .graceful_shutdown_token(cancel)
                    .handle(handler)
                    .await
            })
        }));
        match &result {
            Ok(Ok(())) => eprintln!("SERVER handle returned Ok"),
            Ok(Err(e)) => eprintln!("SERVER handle returned error: {e:?}"),
            Err(p) => eprintln!(
                "SERVER handle PANICKED: {}",
                if let Some(s) = p.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = p.downcast_ref::<&str>() {
                    s.to_string()
                } else {
                    "<non-string panic>".to_string()
                }
            ),
        }
        let _ = result_tx.send(
            result
                .map(|r| r.map_err(|e| e.to_string()))
                .unwrap_or_else(|_| Err("<panic>".to_string())),
        );
    });
    (thread, result_rx)
}

fn large_body() -> BoxBody<Bytes, Infallible> {
    // A *streaming* large body, chunked like a file being read off disk. This
    // exercises the real `poll_send_data` path (repeated yields) rather than a
    // single buffered `Full`, which is what a `.mp4` served from disk does.
    let chunk = LARGE_CHUNK;
    let chunks = (0..(LARGE_TOTAL / chunk))
        .map(move |_| Ok::<_, Infallible>(Frame::data(Bytes::from(vec![0u8; chunk]))));
    StreamBody::new(futures_util::stream::iter(chunks)).boxed()
}

fn small_body() -> BoxBody<Bytes, Infallible> {
    Full::new(Bytes::from_static(b"ok")).boxed()
}

async fn run_scenario(tiny: bool) {
    run_scenario_inner(tiny, false).await;
}

/// The user's exact clue: "blocking the large `.mp4` makes the hang disappear".
/// This models the client aborting the large response mid-flight (STOP_SENDING)
/// while small requests are in flight. If the server misclassifies that cancel
/// as a connection-scoped error, it tears down the whole connection and the
/// other requests are "ignored". A correct implementation keeps them alive.
async fn run_scenario_cancel_midflight(tiny: bool) {
    run_scenario_inner(tiny, true).await;
}

async fn run_scenario_inner(tiny: bool, cancel_large: bool) {
    tokio::time::timeout(Duration::from_secs(60), async {
        let (_server_ep, _client_ep, client_conn, server_conn) = loopback_pair(tiny).await;
        let cancel = CancellationToken::new();
        let handler = |req: Request<Incoming>| async move {
            let is_large = req.uri().path() == "/large";
            let body: BoxBody<Bytes, Infallible> =
                if is_large { large_body() } else { small_body() };
            Ok::<_, Infallible>(
                Response::builder()
                    .status(StatusCode::OK)
                    .body(body)
                    .expect("response"),
            )
        };
        let (_srv_thread, srv_result) =
            spawn_native_server(server_conn, Http3Options::new(), cancel.clone(), handler);

        let (mut conn, send_request) = h3::client::builder()
            .build(h3_quinn::Connection::new(client_conn))
            .await
            .expect("h3 client");
        let _drive = tokio::spawn(async move {
            let _ = conn.wait_idle().await;
        });

        // Start the large response first, so it is in flight.
        let large_start = Instant::now();
        let large_task = {
            let mut sr: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes> =
                send_request.clone();
            tokio::spawn(async move {
                let req = Request::get("https://localhost/large").body(()).unwrap();
                let mut stream = sr.send_request(req).await.expect("large request");
                stream.finish().await.expect("large finish");
                let resp = stream.recv_response().await.expect("large response");
                assert_eq!(resp.status(), StatusCode::OK);
                let mut got = 0usize;
                while let Some(chunk) = stream.recv_data().await.expect("large data") {
                    got += chunk.remaining();
                    // Abort the download once it is clearly in flight,
                    // simulating the user blocking the large `.mp4`.
                    if cancel_large && got >= 8 * 1024 * 1024 {
                        stream.stop_sending(h3::error::Code::H3_NO_ERROR);
                        break;
                    }
                }
                got
            })
        };

        // Fire small requests in waves across the large response's lifetime so
        // they overlap it on the same connection.
        const WAVES: usize = 4;
        const PER_WAVE: usize = 6;
        let mut all_small: Vec<(usize, tokio::task::JoinHandle<Result<Duration, String>>)> =
            Vec::new();
        for wave in 0..WAVES {
            tokio::time::sleep(Duration::from_millis(200)).await;
            for _ in 0..PER_WAVE {
                let mut sr: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes> =
                    send_request.clone();
                all_small.push((
                    wave,
                    tokio::spawn(async move {
                        let start = Instant::now();
                        let req = Request::get("https://localhost/small").body(()).unwrap();
                        let mut stream =
                            sr.send_request(req).await.map_err(|e| format!("{e:?}"))?;
                        stream.finish().await.map_err(|e| format!("{e:?}"))?;
                        let resp = stream.recv_response().await.map_err(|e| format!("{e:?}"))?;
                        assert_eq!(resp.status(), StatusCode::OK);
                        let mut got = 0usize;
                        while let Some(chunk) =
                            stream.recv_data().await.map_err(|e| format!("{e:?}"))?
                        {
                            got += chunk.remaining();
                        }
                        assert_eq!(got, 2);
                        Ok(start.elapsed())
                    }),
                ));
            }
        }

        let large_got = large_task.await.expect("large task");
        let large_dur = large_start.elapsed();

        let mut by_wave: Vec<(usize, Duration)> = Vec::new();
        for (wave, task) in all_small {
            match task.await {
                Ok(Ok(d)) => by_wave.push((wave, d)),
                Ok(Err(e)) => println!("small task error: {e}"),
                Err(e) => println!("small task join panic: {e:?}"),
            }
        }
        // After any cancel, the connection must still be usable: open one more
        // request to prove it was not torn down.
        let post_probe = async {
            let mut sr: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes> =
                send_request.clone();
            let req = Request::get("https://localhost/small").body(()).unwrap();
            let mut stream = sr.send_request(req).await.map_err(|e| format!("{e:?}"))?;
            stream.finish().await.map_err(|e| format!("{e:?}"))?;
            let resp = stream.recv_response().await.map_err(|e| format!("{e:?}"))?;
            assert_eq!(resp.status(), StatusCode::OK);
            Ok::<_, String>(())
        }
        .await;
        // This is the whole point of the probe, so a failure must fail the
        // test rather than merely print: a connection that cannot serve a
        // fresh request after a large transfer is the regression under test.
        if let Err(e) = post_probe {
            panic!("post-transfer probe failed, connection unusable: {e}");
        }

        let ok_small = by_wave.len();
        let max_small = by_wave.iter().map(|(_, d)| *d).max().unwrap_or_default();
        let mut per_wave_max = String::new();
        for w in 0..WAVES {
            let m = by_wave
                .iter()
                .filter(|(ww, _)| *ww == w)
                .map(|(_, d)| *d)
                .max()
                .unwrap_or_default();
            per_wave_max.push_str(&format!(" w{w}={:?}", m));
        }
        println!(
            "[tiny={}] large: {} bytes in {:?}; small ok={}/{} max={:?};{}",
            tiny,
            large_got,
            large_dur,
            ok_small,
            WAVES * PER_WAVE,
            max_small,
            per_wave_max
        );

        if let Ok(srv) = srv_result.recv_timeout(Duration::from_secs(2)) {
            println!("server handle result: {srv:?}");
        }

        assert!(
            ok_small == WAVES * PER_WAVE,
            "[tiny={}] small requests starved/failed: ok={}/{}; large took {:?}",
            tiny,
            ok_small,
            WAVES * PER_WAVE,
            large_dur
        );
    })
    .await
    .expect("scenario must finish in time");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_response_does_not_starve_concurrent_small_requests() {
    run_scenario(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_response_does_not_starve_concurrent_small_requests_tiny_window() {
    run_scenario(true).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_response_cancelled_midflight_keeps_connection_alive() {
    run_scenario_cancel_midflight(false).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn large_response_cancelled_midflight_keeps_connection_alive_tiny_window() {
    run_scenario_cancel_midflight(true).await;
}
