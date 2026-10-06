//! Starts the native server on all three protocols for the interop matrix.
//!
//! HTTP/1.1 and HTTP/2 are served over cleartext TCP. HTTP/2 is served as h2c
//! (prior-knowledge) rather than over TLS so that clients do not have to be
//! configured with a trust anchor, which keeps the container drivers to a
//! handful of flags. HTTP/3 is served over QUIC with a self-signed certificate,
//! which QUIC requires and which every HTTP/3 client can be told to skip.
//!
//! Listeners bind `0.0.0.0` on ephemeral ports. The ports are reported back so
//! the harness can tell the containers where to connect; `127.0.0.1` would be
//! unreachable from inside a container.

use std::io;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use zincio::net::TcpListener;
use zincio::RuntimeBuilder;
use zincio_http::{Http1, Http1Options, Http2, Http2Options, Http3, Http3Options, HttpProtocol};

use crate::routes;

/// Header-list budget shared by the HTTP/2 and HTTP/3 servers.
///
/// This is deliberately small so the `big_header_rejected` scenario is
/// deterministic rather than dependent on implementation defaults, and
/// deliberately large enough that the `many_headers` scenario still fits.
/// See the unit test `header_list_budget_is_consistent_with_the_header_scenarios`.
pub const MAX_HEADER_LIST_SIZE: u32 = 16 * 1024;

/// Idle timeout for HTTP/2 and HTTP/3 connections.
///
/// Shorter than [`crate::scenario::IDLE_MS`] so the `idle_reuse` scenario
/// observes a reaped connection, but long enough that a normal multi-step
/// scenario is never interrupted.
pub const IDLE_TIMEOUT: Duration = Duration::from_millis(2_000);

/// Header-read timeout for HTTP/1.1 connections.
pub const H1_HEADER_READ_TIMEOUT: Duration = Duration::from_secs(10);

/// Addresses the running servers are listening on.
#[derive(Clone, Copy, Debug)]
pub struct ServerAddrs {
    /// Cleartext HTTP/1.1.
    pub h1: SocketAddr,
    /// Cleartext HTTP/2 (h2c, prior knowledge).
    pub h2: SocketAddr,
    /// QUIC HTTP/3.
    pub h3: SocketAddr,
}

/// Handle to the running servers.
///
/// # Shutdown semantics
///
/// [`shutdown`](Self::shutdown) only raises a flag that the accept loops check
/// before each accept. A thread blocked in `accept()` is not interrupted, so
/// the threads are deliberately *not* joined -- joining would hang until the
/// next connection arrived, and the interop suite is a short-lived test process
/// where the threads die with the process anyway.
pub struct ServerHandles {
    stop: Arc<AtomicBool>,
}

impl ServerHandles {
    /// Signals the accept loops to stop at the next opportunity.
    pub fn shutdown(&self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

/// Binds all three listeners on ephemeral ports, reports the addresses, and
/// starts serving.
///
/// Binding happens before any thread is spawned so that a port conflict is
/// reported to the caller rather than swallowed by a background thread.
pub fn spawn() -> io::Result<(ServerAddrs, ServerHandles)> {
    spawn_on_ports(0, 0, 0)
}

/// Like [`spawn`], but with explicit limits. Used by tests that assert the
/// server's own configuration rather than driving clients.
pub fn spawn_with_limits(
    max_header_list_size: u32,
    idle_timeout: Duration,
) -> io::Result<(ServerAddrs, ServerHandles)> {
    spawn_with_limits_and_ports(max_header_list_size, idle_timeout, 0, 0, 0)
}

/// Like [`spawn`], but on explicit ports rather than ephemeral ones. Used by
/// the `interop-server` binary so a container harness can address the server by
/// a known port.
pub fn spawn_on_ports(h1: u16, h2: u16, h3: u16) -> io::Result<(ServerAddrs, ServerHandles)> {
    spawn_with_limits_and_ports(MAX_HEADER_LIST_SIZE, IDLE_TIMEOUT, h1, h2, h3)
}

/// Like [`spawn_with_limits`], but on explicit ports.
pub fn spawn_with_limits_and_ports(
    max_header_list_size: u32,
    idle_timeout: Duration,
    h1_port: u16,
    h2_port: u16,
    h3_port: u16,
) -> io::Result<(ServerAddrs, ServerHandles)> {
    let stop = Arc::new(AtomicBool::new(false));

    let h1 = spawn_h1(
        &bind_addr(h1_port),
        Http1Options::new()
            .header_read_timeout(Some(H1_HEADER_READ_TIMEOUT))
            .enable_early_hints(true)
            .max_header_count(1024),
        Arc::clone(&stop),
    )?;

    let h2 = spawn_h2(
        &bind_addr(h2_port),
        Http2Options::default()
            .max_header_list_size(max_header_list_size)
            .idle_timeout(Some(idle_timeout))
            .enable_connect_protocol(true),
        Arc::clone(&stop),
    )?;

    // HTTP/3 over QUIC. quinn's `Endpoint` spawns tokio tasks, so it can only
    // be created inside a tokio runtime and it is bound inside the server
    // thread for the same reason the TCP listeners are. Each connection's
    // `Http3` future is then driven by its own zincio runtime -- the same split
    // `examples/h3spec_server.rs` uses.
    let h3 = spawn_h3(h3_port, max_header_list_size, Arc::clone(&stop))?;

    Ok((ServerAddrs { h1, h2, h3 }, ServerHandles { stop }))
}

/// Address every listener binds. `127.0.0.1` would be unreachable from inside
/// a container.
const BIND_HOST: &str = "0.0.0.0";

/// Formats a bind address for `port`.
fn bind_addr(port: u16) -> String {
    format!("{BIND_HOST}:{port}")
}

/// How long [`spawn_h1`]/[`spawn_h2`] wait for their thread to report a bound
/// address before treating it as a failure. Generous, because it only has to
/// cover thread start plus one `bind`.
const BIND_REPORT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

/// Starts the HTTP/1.1 listener and returns its bound address.
///
/// The listener is created *inside* the server thread because
/// `zincio::net::TcpListener` is `!Send`; the address travels back over a
/// channel so the caller still learns the ephemeral port.
fn spawn_h1(bind: &str, options: Http1Options, stop: Arc<AtomicBool>) -> io::Result<SocketAddr> {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let bind = bind.to_owned();
    let options = Arc::new(options);
    let joined = std::thread::Builder::new()
        .name("interop-h1".to_owned())
        .spawn(move || {
            let Ok(runtime) = RuntimeBuilder::new().enable_timer(true).build() else {
                let _ = addr_tx.send(Err(io::Error::other("zincio runtime build failed")));
                return;
            };
            runtime.block_on(async move {
                let listener = match TcpListener::bind(bind.as_str()) {
                    Ok(listener) => listener,
                    Err(err) => {
                        let _ = addr_tx.send(Err(err));
                        return;
                    }
                };
                match listener.local_addr() {
                    Ok(addr) => {
                        let _ = addr_tx.send(Ok(addr));
                    }
                    Err(err) => {
                        let _ = addr_tx.send(Err(err));
                        return;
                    }
                }
                accept_tcp(listener, stop, move |stream| {
                    let options = Arc::clone(&options);
                    async move { serve_h1(stream, options).await }
                })
                .await
            })
        })
        .map_err(io::Error::other)?;
    let _ = joined;
    recv_bound_addr(addr_rx, "h1")
}

/// Starts the HTTP/2 listener. See [`spawn_h1`] for why the bind happens in the
/// server thread.
fn spawn_h2(bind: &str, options: Http2Options, stop: Arc<AtomicBool>) -> io::Result<SocketAddr> {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let bind = bind.to_owned();
    let options = Arc::new(options);
    let joined = std::thread::Builder::new()
        .name("interop-h2".to_owned())
        .spawn(move || {
            let Ok(runtime) = RuntimeBuilder::new().enable_timer(true).build() else {
                let _ = addr_tx.send(Err(io::Error::other("zincio runtime build failed")));
                return;
            };
            runtime.block_on(async move {
                let listener = match TcpListener::bind(bind.as_str()) {
                    Ok(listener) => listener,
                    Err(err) => {
                        let _ = addr_tx.send(Err(err));
                        return;
                    }
                };
                match listener.local_addr() {
                    Ok(addr) => {
                        let _ = addr_tx.send(Ok(addr));
                    }
                    Err(err) => {
                        let _ = addr_tx.send(Err(err));
                        return;
                    }
                }
                accept_tcp(listener, stop, move |stream| {
                    let options = Arc::clone(&options);
                    async move { serve_h2(stream, options).await }
                })
                .await
            })
        })
        .map_err(io::Error::other)?;
    let _ = joined;
    recv_bound_addr(addr_rx, "h2")
}

/// Starts the HTTP/3 listener and returns its bound address.
///
/// The QUIC endpoint is created inside the server thread because `quinn`
/// requires an active tokio runtime to spawn its tasks, and `main` has none.
fn spawn_h3(
    port: u16,
    max_field_section_size: u32,
    stop: Arc<AtomicBool>,
) -> io::Result<SocketAddr> {
    let (addr_tx, addr_rx) = std::sync::mpsc::channel();
    let joined = std::thread::Builder::new()
        .name("interop-h3".to_owned())
        .spawn(move || {
            let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
            else {
                let _ = addr_tx.send(Err(io::Error::other("tokio runtime build failed")));
                return;
            };
            let _ = runtime.block_on(async move {
                let endpoint = match quinn_endpoint(port) {
                    Ok(endpoint) => endpoint,
                    Err(err) => {
                        let _ = addr_tx.send(Err(err));
                        return;
                    }
                };
                match endpoint.local_addr() {
                    Ok(addr) => {
                        let _ = addr_tx.send(Ok(addr));
                    }
                    Err(err) => {
                        let _ = addr_tx.send(Err(err));
                        return;
                    }
                }
                accept_quic(endpoint, stop, max_field_section_size).await
            });
        })
        .map_err(io::Error::other)?;
    let _ = joined;
    recv_bound_addr(addr_rx, "h3")
}

/// Waits for a server thread to report the address it bound.
fn recv_bound_addr(
    addr_rx: std::sync::mpsc::Receiver<io::Result<SocketAddr>>,
    which: &str,
) -> io::Result<SocketAddr> {
    match addr_rx.recv_timeout(BIND_REPORT_TIMEOUT) {
        Ok(result) => result,
        Err(std::sync::mpsc::RecvTimeoutError::Timeout) => Err(io::Error::other(format!(
            "{which} server thread did not report a bound address within {BIND_REPORT_TIMEOUT:?}"
        ))),
        Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Err(io::Error::other(format!(
            "{which} server thread exited before binding"
        ))),
    }
}

/// Serves one HTTP/1.1 connection.
async fn serve_h1(stream: zincio::net::TcpStream, options: Arc<Http1Options>) {
    match stream.into_poll() {
        Ok(polled) => {
            let options = options.as_ref().clone();
            let _ = Http1::new(polled, options).handle(routes::handle).await;
        }
        Err(err) => eprintln!("h1 into_poll failed: {err}"),
    }
}

/// Serves one HTTP/2 connection.
async fn serve_h2(stream: zincio::net::TcpStream, options: Arc<Http2Options>) {
    match stream.into_poll() {
        Ok(polled) => {
            let options = options.as_ref().clone();
            let _ = Http2::new(polled, options).handle(routes::handle).await;
        }
        Err(err) => eprintln!("h2 into_poll failed: {err}"),
    }
}

/// TCP accept loop. Each connection is spawned onto the current runtime.
async fn accept_tcp<F, Fut>(listener: TcpListener, stop: Arc<AtomicBool>, serve: F)
where
    F: Fn(zincio::net::TcpStream) -> Fut,
    Fut: std::future::Future<Output = ()> + 'static,
{
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        match listener.accept().await {
            Ok((stream, _)) => {
                let _ = stream.set_nodelay(true);
                zincio::spawn(serve(stream));
            }
            Err(err) => {
                eprintln!("accept failed: {err}");
                return;
            }
        }
    }
}

/// QUIC accept loop: hands each accepted connection to a dedicated zincio
/// runtime on its own thread.
async fn accept_quic(
    endpoint: quinn::Endpoint,
    stop: Arc<AtomicBool>,
    max_field_section_size: u32,
) {
    loop {
        if stop.load(Ordering::Relaxed) {
            return;
        }
        let connecting = match endpoint.accept().await {
            Some(connecting) => connecting,
            None => return,
        };
        match connecting.await {
            Ok(connection) => {
                std::thread::spawn(move || {
                    let Ok(runtime) = RuntimeBuilder::new().enable_timer(true).build() else {
                        return;
                    };
                    let conn = Http3::new(
                        zincio_http::quinn::Connection::new(connection),
                        Http3Options::new()
                            .max_field_section_size(Some(u64::from(max_field_section_size)))
                            .handshake_timeout(Some(Duration::from_secs(10)))
                            .accept_timeout(Some(Duration::from_secs(30))),
                    );
                    let _ = runtime.block_on(conn.handle(routes::handle));
                });
            }
            Err(err) => eprintln!("quic handshake failed: {err}"),
        }
    }
}

/// Builds a QUIC server endpoint with a freshly generated self-signed
/// certificate for `localhost`.
fn quinn_endpoint(port: u16) -> io::Result<quinn::Endpoint> {
    let cert =
        rcgen::generate_simple_self_signed(vec!["localhost".into()]).map_err(io::Error::other)?;
    let cert_der: quinn::rustls::pki_types::CertificateDer<'static> = cert.cert.into();
    let mut tls = quinn::rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert_der],
            quinn::rustls::pki_types::PrivateKeyDer::from(cert.signing_key),
        )
        .map_err(io::Error::other)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    let quic_crypto =
        quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(io::Error::other)?;
    let config = quinn::ServerConfig::with_crypto(Arc::new(quic_crypto));
    let addr: SocketAddr = bind_addr(port)
        .parse()
        .map_err(|_| io::Error::other("invalid bind address"))?;
    quinn::Endpoint::server(config, addr).map_err(io::Error::other)
}

/// Size a header list occupies under RFC 7541 section 4.1 accounting
/// (`name + value + 32`), which is what `max_header_list_size` measures.
pub fn header_list_size(names_and_values: &[(&str, &str)]) -> u32 {
    names_and_values
        .iter()
        .map(|(name, value)| (name.len() + value.len() + 32) as u32)
        .sum()
}

/// The headers the `many_headers` scenario sends, as they will be counted
/// against the header-list budget.
pub fn many_headers_scenario_headers() -> Vec<(String, String)> {
    (0..crate::scenario::MANY_HEADERS)
        .map(|i| (format!("x-interop-{i:04}"), "v".to_owned()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scenario::{BIG_HEADER_LEN, MANY_HEADERS};

    #[test]
    fn header_list_budget_is_consistent_with_the_header_scenarios() {
        // `many_headers` must be accepted. This is the assertion that keeps the
        // two header scenarios from colliding on the same limit.
        let many = many_headers_scenario_headers();
        assert_eq!(many.len(), MANY_HEADERS);
        let borrowed: Vec<(&str, &str)> = many
            .iter()
            .map(|(name, value)| (name.as_str(), value.as_str()))
            .collect();
        let many_size = header_list_size(&borrowed);
        assert!(
            many_size < MAX_HEADER_LIST_SIZE,
            "many_headers needs {many_size} bytes but the budget is {MAX_HEADER_LIST_SIZE}"
        );

        // `big_header` must be rejected.
        let big = header_list_size(&[("x-big", &"v".repeat(BIG_HEADER_LEN))]);
        assert!(
            big > MAX_HEADER_LIST_SIZE,
            "big_header is only {big} bytes, under the {MAX_HEADER_LIST_SIZE} byte budget"
        );
    }

    #[test]
    fn idle_timeout_is_shorter_than_the_idle_scenario() {
        assert!(
            u64::try_from(IDLE_TIMEOUT.as_millis()).unwrap() < crate::scenario::IDLE_MS,
            "an idle connection would never be reaped, making idle_reuse vacuous"
        );
    }
}
