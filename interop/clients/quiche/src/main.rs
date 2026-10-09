// Interop driver built on Cloudflare quiche (QUIC + HTTP/3).
//
// Usage:
//   interop-driver BASE_URL PROTOCOL SCENARIO [key=value ...]
//   interop-driver --selftest
//   interop-driver                      # idle mode: announce readiness, sleep
//
// Prints one observation line per request on stdout:
//   status=<u16> len=<n> sha=<hex|-> trailers=<0|1> hints=<0|1> err=<text>
//
// quiche is Cloudflare's QUIC + HTTP/3 implementation, fronting a large share
// of the web through cloudflared and Cloudflare's edge. Its QPACK encoder and
// loss recovery differ meaningfully from quic-go, aioquic, and quinn, so it is
// a genuinely independent opinion on the server's HTTP/3 behaviour. It speaks
// only HTTP/3.
//
// The harness (interop/src/client.rs) decides whether an observation is
// acceptable; this driver only reports what it saw. Scenario *inputs* -- which
// headers to send, how many concurrent streams -- are constructed here, because
// only the driver knows its own API. The *thresholds* those inputs are judged
// against live in Rust.

use std::collections::HashMap;
use std::fs::File;
use std::io::Read as _;
use std::net::{SocketAddr, ToSocketAddrs as _, UdpSocket};
use std::time::{Duration, Instant};

use quiche::h3::NameValue as _;
use sha2::{Digest as _, Sha256};

// H3_REQUEST_CANCELLED (RFC 9114 section 8.1.2): the client is no longer
// interested in this stream.
const H3_REQUEST_CANCELLED: u64 = 0x10c;

// Largest UDP payload we send. Matches the quiche examples.
const MAX_DATAGRAM_SIZE: usize = 1350;

// How long one scenario may take overall. The harness has its own (longer)
// timeout around the whole exec.
const SCENARIO_DEADLINE: Duration = Duration::from_secs(100);

// How long the QUIC handshake may take.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);

// Chunk size for request bodies. Small enough that a 1 MiB upload never needs
// a 1 MiB contiguous send buffer reservation.
const SEND_CHUNK: usize = 16 * 1024;

// Abort threshold for the abort_midstream scenario, matching the other H3
// drivers.
const ABORT_AFTER: usize = 64 * 1024;

// Upload size for the sacrificial exchange that grows the congestion window
// before the oversized header block is sent (see run_generic). Large enough
// that slow-start leaves the window above the 32 KiB block afterwards.
const PRIME_UPLOAD_LEN: usize = 128 * 1024;

/// The shared ABCD body pattern, matching the server and the harness.
fn pattern(n: usize) -> Vec<u8> {
    const P: &[u8; 4] = b"ABCD";
    (0..n).map(|i| P[i % 4]).collect()
}

fn sha256_hex(data: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(data);
    format!("{:x}", hasher.finalize())
}

/// Prints one observation line. Mirrors Observation::to_line.
fn emit(status: u16, length: usize, digest: &str, trailers: bool, hints: bool, err: &str) {
    let sha = if digest.is_empty() { "-" } else { digest };
    println!(
        "status={status} len={length} sha={sha} trailers={} hints={} err={err}",
        trailers as u8,
        hints as u8,
    );
}

fn emit_failure(err: &str) {
    emit(0, 0, "", false, false, err);
}

/// Splits a harness base URL (`https://host:port`) into host and socket
/// address. The harness always passes a literal host that resolves.
fn split_base(base_url: &str) -> Result<(String, SocketAddr), String> {
    let without_scheme = base_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(base_url);
    let (host, port) = without_scheme
        .rsplit_once(':')
        .ok_or_else(|| format!("base URL has no port: {base_url}"))?;
    let port: u16 = port
        .parse()
        .map_err(|_| format!("base URL has a bad port: {base_url}"))?;
    let addr = (host, port)
        .to_socket_addrs()
        .map_err(|err| format!("resolve_failed:{err}"))?
        .next()
        .ok_or_else(|| "resolve_failed:empty".to_owned())?;
    Ok((host.to_owned(), addr))
}

/// Fills a source connection ID from the OS RNG. Uniqueness across scenarios
/// is all that is needed; a short read falls back to time-derived bytes.
fn fresh_scid() -> [u8; quiche::MAX_CONN_ID_LEN] {
    let mut scid = [0u8; quiche::MAX_CONN_ID_LEN];
    if let Ok(mut f) = File::open("/dev/urandom") {
        let _ = f.read_exact(&mut scid);
    }
    if scid == [0u8; quiche::MAX_CONN_ID_LEN] {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0x9e3779b9);
        for (i, byte) in scid.iter_mut().enumerate() {
            *byte = ((nanos >> ((i % 16) * 4)) & 0xff) as u8;
        }
    }
    scid
}

fn quic_config() -> Result<quiche::Config, String> {
    let mut config =
        quiche::Config::new(quiche::PROTOCOL_VERSION).map_err(|err| format!("config:{err:?}"))?;
    // *CAUTION*: test-only. The scenario server generates a fresh self-signed
    // certificate per run, so there is nothing stable to pin.
    config.verify_peer(false);
    config
        .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
        .map_err(|err| format!("alpn:{err:?}"))?;
    config.set_max_idle_timeout(30_000);
    config.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
    config.set_initial_max_data(10_000_000);
    config.set_initial_max_stream_data_bidi_local(1_000_000);
    config.set_initial_max_stream_data_bidi_remote(1_000_000);
    config.set_initial_max_stream_data_uni(1_000_000);
    config.set_initial_max_streams_bidi(100);
    config.set_initial_max_streams_uni(100);
    config.set_disable_active_migration(true);
    Ok(config)
}

struct Endpoint {
    socket: UdpSocket,
    conn: quiche::Connection,
    h3: Option<quiche::h3::Connection>,
    local: SocketAddr,
}

impl Endpoint {
    /// Sends every pending QUIC packet on the socket.
    fn flush(&mut self) -> Result<(), String> {
        let mut out = [0u8; 65535];
        loop {
            match self.conn.send(&mut out) {
                Ok((written, info)) => {
                    // A WouldBlock on a blocking socket with no timeout set
                    // cannot happen; any other error is fatal to the exchange.
                    self.socket
                        .send_to(&out[..written], info.to)
                        .map_err(|err| format!("send:{err}"))?;
                }
                Err(quiche::Error::Done) => return Ok(()),
                Err(err) => return Err(format!("quic_send:{err:?}")),
            }
        }
    }

    /// One event-loop iteration: flush sends, drain H3 events into `resps`,
    /// flush again, then wait for the next packet (or timeout).
    ///
    /// Note this deliberately performs a full cycle even when `resps` is
    /// empty or already complete: the `send_request` retry loop calls it
    /// before any stream is tracked, and returning early there would spin
    /// without ever reading the ACKs that unblock the send. Termination on
    /// completed streams is the caller's job (see [`Self::drive`]).
    fn iterate(
        &mut self,
        resps: &mut HashMap<u64, Resp>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.flush()?;
        self.drain_h3(resps)?;
        self.flush()?;

        let now = Instant::now();
        if now >= deadline {
            return Err("scenario_timeout".to_owned());
        }
        // Cap the wait well below any QUIC timer: `send` may report `Done`
        // while packets are pacing-gated rather than absent, and parking in
        // `recv` until the next QUIC timeout (up to the 30 s idle timeout)
        // would stall an exchange that only needs another `flush`. Polling at
        // this granularity costs a few wakeups per scenario and keeps every
        // exchange moving even when no packet arrives to wake it.
        let wait = self
            .conn
            .timeout()
            .unwrap_or(Duration::from_secs(5))
            .min(Duration::from_millis(20))
            .min(deadline.saturating_duration_since(now));
        let _ = self.socket.set_read_timeout(Some(wait));

        let mut buf = [0u8; 65535];
        match self.socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let info = quiche::RecvInfo {
                    to: self.local,
                    from,
                };
                // A stray or coalescing-unfriendly packet is not fatal to the
                // exchange; the loss machinery will recover.
                let _ = self.conn.recv(&mut buf[..len], info);
                Ok(())
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                self.conn.on_timeout();
                Ok(())
            }
            Err(err) => Err(format!("recv:{err}")),
        }
    }

    /// Drains every pending H3 event, collecting bodies and headers for the
    /// tracked streams and discarding anything else.
    fn drain_h3(&mut self, resps: &mut HashMap<u64, Resp>) -> Result<(), String> {
        let mut buf = [0u8; 65535];
        loop {
            let Some(h3) = self.h3.as_mut() else {
                return Ok(());
            };
            match h3.poll(&mut self.conn) {
                Ok((id, quiche::h3::Event::Headers { list, .. })) => {
                    if std::env::var("QUICHE_DEBUG").is_ok() {
                        let names: Vec<String> = list
                            .iter()
                            .map(|h| {
                                format!(
                                    "{}={}",
                                    String::from_utf8_lossy(h.name()),
                                    String::from_utf8_lossy(h.value())
                                )
                            })
                            .collect();
                        eprintln!("DEBUG h3 Headers stream={id} {names:?}");
                    }
                    if let Some(resp) = resps.get_mut(&id) {
                        classify_headers(&list, resp);
                    }
                }
                Ok((id, quiche::h3::Event::Data)) => {
                    // Drain the body so flow control never stalls, even for a
                    // stream nobody is tracking (e.g. the abandoned half of
                    // abort_midstream).
                    loop {
                        let h3 = self.h3.as_mut().expect("checked above");
                        match h3.recv_body(&mut self.conn, id, &mut buf) {
                            Ok(n) => {
                                if let Some(resp) = resps.get_mut(&id) {
                                    resp.body.extend_from_slice(&buf[..n]);
                                }
                            }
                            Err(quiche::h3::Error::Done) => break,
                            Err(err) => return Err(format!("recv_body:{err:?}")),
                        }
                    }
                }
                Ok((id, quiche::h3::Event::Finished)) => {
                    if std::env::var("QUICHE_DEBUG").is_ok() {
                        eprintln!("DEBUG h3 Finished stream={id}");
                    }
                    if let Some(resp) = resps.get_mut(&id) {
                        resp.done = true;
                    }
                }
                Ok((id, quiche::h3::Event::Reset(code))) => {
                    if std::env::var("QUICHE_DEBUG").is_ok() {
                        eprintln!("DEBUG h3 Reset stream={id} code={code:#x}");
                    }
                    if let Some(resp) = resps.get_mut(&id) {
                        resp.reset = true;
                        resp.done = true;
                    }
                }
                Ok((_, quiche::h3::Event::GoAway)) => {}
                Ok((_, quiche::h3::Event::PriorityUpdate)) => {}
                Err(quiche::h3::Error::Done) => return Ok(()),
                Err(err) => return Err(format!("h3_poll:{err:?}")),
            }
        }
    }

    /// Pumps the connection until every tracked stream is done.
    fn drive(&mut self, resps: &mut HashMap<u64, Resp>, deadline: Instant) -> Result<(), String> {
        loop {
            if resps.values().all(|r| r.done) {
                return Ok(());
            }
            if self.conn.is_closed() {
                return Err("connection_closed".to_owned());
            }
            if Instant::now() >= deadline {
                return Err("scenario_timeout".to_owned());
            }
            self.iterate(resps, deadline)?;
        }
    }

    /// Closes the connection politely. Best-effort: the observation is already
    /// collected by the time this runs.
    fn close_gracefully(&mut self) {
        let _ = self.conn.close(true, 0x100, b"kthxbye");
        let _ = self.flush();
    }
}

/// What one request stream produced.
#[derive(Default)]
struct Resp {
    status: u16,
    body: Vec<u8>,
    trailers: bool,
    hints: bool,
    done: bool,
    reset: bool,
}

/// Reduces one HEADERS block to observation fields.
///
/// - A HEADERS block carrying a 103 `:status` sets early-hints. A 100 is part
///   of the normal expect-continue exchange, not an early hint.
/// - A HEADERS block with no `:status` at all is a trailer block.
/// - Anything else is the final status.
fn classify_headers(list: &[quiche::h3::Header], resp: &mut Resp) {
    let mut status: Option<&[u8]> = None;
    for header in list {
        if header.name() == b":status" {
            status = Some(header.value());
            break;
        }
    }
    match status {
        Some(value) if value.starts_with(b"1") && value != b"100" => {
            resp.hints = true;
        }
        Some(value) => {
            if let Ok(text) = std::str::from_utf8(value) {
                if let Ok(code) = text.parse::<u16>() {
                    resp.status = code;
                }
            }
        }
        None => {
            resp.trailers = true;
        }
    }
}

fn connect(base_url: &str) -> Result<Endpoint, String> {
    let (host, peer) = split_base(base_url)?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| format!("bind:{err}"))?;
    let local = socket
        .local_addr()
        .map_err(|err| format!("local_addr:{err}"))?;
    let mut config = quic_config()?;

    let scid = fresh_scid();
    let scid = quiche::ConnectionId::from_ref(&scid);
    let conn = quiche::connect(Some(&host), &scid, local, peer, &mut config)
        .map_err(|err| format!("connect:{err:?}"))?;

    let mut endpoint = Endpoint {
        socket,
        conn,
        h3: None,
        local,
    };

    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    let mut out = [0u8; 65535];
    let mut buf = [0u8; 65535];
    loop {
        // Flush handshake flights.
        loop {
            match endpoint.conn.send(&mut out) {
                Ok((written, info)) => {
                    endpoint
                        .socket
                        .send_to(&out[..written], info.to)
                        .map_err(|err| format!("send:{err}"))?;
                }
                Err(quiche::Error::Done) => break,
                Err(err) => return Err(format!("handshake_send:{err:?}")),
            }
        }
        if endpoint.conn.is_established() {
            break;
        }
        if endpoint.conn.is_closed() {
            return Err("handshake_closed".to_owned());
        }
        let now = Instant::now();
        if now >= deadline {
            return Err("handshake_timeout".to_owned());
        }
        let wait = endpoint
            .conn
            .timeout()
            .unwrap_or(Duration::from_secs(5))
            .min(deadline.saturating_duration_since(now));
        let _ = endpoint.socket.set_read_timeout(Some(wait));
        match endpoint.socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                let info = quiche::RecvInfo {
                    to: local,
                    from,
                };
                let _ = endpoint.conn.recv(&mut buf[..len], info);
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                endpoint.conn.on_timeout();
            }
            Err(err) => return Err(format!("handshake_recv:{err}")),
        }
    }

    let h3_config =
        quiche::h3::Config::new().map_err(|err| format!("h3_config:{err:?}"))?;
    let h3 = quiche::h3::Connection::with_transport(&mut endpoint.conn, &h3_config)
        .map_err(|err| format!("h3_transport:{err:?}"))?;
    endpoint.h3 = Some(h3);
    // Flush the H3 control streams (SETTINGS, QPACK) before requesting.
    endpoint.flush()?;
    Ok(endpoint)
}

/// Sends one request on `endpoint`, including an optional body and optional
/// request trailers, and registers its stream in `resps`.
fn send_request(
    endpoint: &mut Endpoint,
    resps: &mut HashMap<u64, Resp>,
    deadline: Instant,
    method: &str,
    authority: &str,
    path: &str,
    extra: &[(String, String)],
    body: &[u8],
    req_trailers: Option<&[(String, String)]>,
) -> Result<u64, String> {
    let mut headers = vec![
        quiche::h3::Header::new(b":method", method.as_bytes()),
        quiche::h3::Header::new(b":scheme", b"https"),
        quiche::h3::Header::new(b":authority", authority.as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", b"quiche"),
    ];
    for (name, value) in extra {
        headers.push(quiche::h3::Header::new(name.as_bytes(), value.as_bytes()));
    }
    let has_body = !body.is_empty() || req_trailers.is_some();

    // The initial HEADERS may be stream-blocked; pumping the connection
    // between attempts is what unblocks it (ACKs grow the congestion
    // window). A closed connection never unblocks, so fail fast there.
    let id = loop {
        let h3 = endpoint.h3.as_mut().ok_or("no_h3")?;
        match h3.send_request(&mut endpoint.conn, &headers, !has_body) {
            Ok(id) => break id,
            Err(_) => {
                if endpoint.conn.is_closed() {
                    return Err("connection_closed_before_request".to_owned());
                }
                endpoint.iterate(resps, deadline)?;
            }
        }
    };
    resps.insert(id, Resp::default());

    let mut offset = 0;
    while offset < body.len() {
        let end = (offset + SEND_CHUNK).min(body.len());
        let fin = end == body.len() && req_trailers.is_none();
        let h3 = endpoint.h3.as_mut().ok_or("no_h3")?;
        match h3.send_body(&mut endpoint.conn, id, &body[offset..end], fin) {
            Ok(written) => {
                offset += written;
            }
            Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                endpoint.iterate(resps, deadline)?;
            }
            Err(err) => return Err(format!("send_body:{err:?}")),
        }
    }

    if let Some(trailers) = req_trailers {
        let trailer_headers: Vec<quiche::h3::Header> = trailers
            .iter()
            .map(|(name, value)| quiche::h3::Header::new(name.as_bytes(), value.as_bytes()))
            .collect();
        loop {
            let h3 = endpoint.h3.as_mut().ok_or("no_h3")?;
            match h3.send_additional_headers(&mut endpoint.conn, id, &trailer_headers, true, true)
            {
                Ok(()) => break,
                Err(quiche::h3::Error::Done) | Err(quiche::h3::Error::StreamBlocked) => {
                    endpoint.iterate(resps, deadline)?;
                }
                Err(err) => return Err(format!("send_trailers:{err:?}")),
            }
        }
    }

    endpoint.flush()?;
    Ok(id)
}

/// Renders one tracked stream as an observation line.
fn observe(id: u64, resps: &HashMap<u64, Resp>) {
    match resps.get(&id) {
        Some(resp) if resp.reset => emit_failure("request_reset"),
        Some(resp) => {
            let digest = if resp.body.is_empty() {
                String::new()
            } else {
                sha256_hex(&resp.body)
            };
            emit(
                resp.status,
                resp.body.len(),
                &digest,
                resp.trailers,
                resp.hints,
                "",
            );
        }
        None => emit_failure("no_observation"),
    }
}

/// Extra request headers for scenarios that need them.
fn build_headers(scenario: &str) -> Vec<(String, String)> {
    match scenario {
        "many_headers" => (0..200).map(|i| (format!("x-interop-{i:04}"), "v".to_owned())).collect(),
        "big_header_rejected" => vec![("x-big".to_owned(), "v".repeat(32 * 1024))],
        "expect_continue" => vec![("expect".to_owned(), "100-continue".to_owned())],
        _ => Vec::new(),
    }
}

fn build_path(scenario: &str, path: &str) -> String {
    if scenario == "long_uri" {
        format!("{path}?{}", String::from_utf8(pattern(8 * 1024)).unwrap())
    } else {
        path.to_owned()
    }
}

fn authority_of(base_url: &str) -> String {
    // The `:authority` pseudo-header carries host and port, matching what the
    // other H3 drivers send.
    base_url
        .split_once("://")
        .map(|(_, rest)| rest)
        .unwrap_or(base_url)
        .to_owned()
}

fn run_generic(
    base_url: &str,
    scenario: &str,
    method: &str,
    path: &str,
    upload_len: usize,
) -> Result<(), String> {
    let deadline = Instant::now() + SCENARIO_DEADLINE;
    let mut endpoint = connect(base_url)?;
    let mut resps = HashMap::new();
    let authority = authority_of(base_url);

    if scenario == "big_header_rejected" {
        // quiche sends HEADERS atomically, and a fresh connection's
        // congestion window (~13 KiB) cannot fit a 32 KiB header block while
        // nothing is in flight to grow it: `send_request` reports
        // StreamBlocked forever. That is a client-side transport constraint,
        // not the refusal the scenario asserts, so prime the window with a
        // sacrificial upload on the same connection first. The scenario still
        // asserts exactly what it should (refusal of the big block); the
        // extra exchange is invisible to the observation.
        let prime = pattern(PRIME_UPLOAD_LEN);
        let mut prime_resps = HashMap::new();
        let prime_id = send_request(
            &mut endpoint,
            &mut prime_resps,
            deadline,
            "POST",
            &authority,
            "/echo",
            &[],
            &prime,
            None,
        )?;
        endpoint.drive(&mut prime_resps, deadline)?;
        match prime_resps.get(&prime_id) {
            Some(resp) if resp.status == 200 && resp.body.len() == PRIME_UPLOAD_LEN => {}
            _ => return Err("prime_upload_failed".to_owned()),
        }
    }

    let full_path = build_path(scenario, path);
    let extra = build_headers(scenario);
    let upload = pattern(upload_len);
    let trailers: Option<Vec<(String, String)>> = if scenario == "trailers" {
        Some(vec![("x-interop-req".to_owned(), "1".to_owned())])
    } else {
        None
    };

    let id = send_request(
        &mut endpoint,
        &mut resps,
        deadline,
        method,
        &authority,
        &full_path,
        &extra,
        &upload,
        trailers.as_deref(),
    )?;
    match endpoint.drive(&mut resps, deadline) {
        Ok(()) => {
            endpoint.close_gracefully();
            observe(id, &resps);
            Ok(())
        }
        Err(err) => {
            // A transport failure is itself the observation: for
            // big_header_rejected it is a conforming refusal, for everything
            // else the harness reports it as a failure.
            emit_failure(&err.replace(' ', "_"));
            Ok(())
        }
    }
}

fn run_concurrency(base_url: &str, path: &str, count: usize) -> Result<(), String> {
    let deadline = Instant::now() + SCENARIO_DEADLINE;
    let mut endpoint = connect(base_url)?;
    let mut resps = HashMap::new();
    let authority = authority_of(base_url);
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let id = send_request(
            &mut endpoint,
            &mut resps,
            deadline,
            "GET",
            &authority,
            path,
            &[],
            &[],
            None,
        )?;
        ids.push(id);
    }
    // Every stream must produce a line, even on failure: a missing line is a
    // driver bug, while an error line lets the harness attribute the failure.
    match endpoint.drive(&mut resps, deadline) {
        Ok(()) => {
            endpoint.close_gracefully();
        }
        Err(err) => {
            let err = err.replace(' ', "_");
            for _ in &ids {
                emit_failure(&err);
            }
            return Ok(());
        }
    }
    ids.sort_unstable();
    for id in ids {
        observe(id, &resps);
    }
    Ok(())
}

fn run_abort(base_url: &str, path: &str) -> Result<(), String> {
    let deadline = Instant::now() + SCENARIO_DEADLINE;
    let mut endpoint = connect(base_url)?;
    let mut resps = HashMap::new();
    let authority = authority_of(base_url);
    let id = send_request(
        &mut endpoint,
        &mut resps,
        deadline,
        "GET",
        &authority,
        path,
        &[],
        &[],
        None,
    )?;

    // Read a bounded prefix, then cancel the stream: the client is no longer
    // interested in this response.
    loop {
        if endpoint.conn.is_closed() {
            return Err("connection_closed".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("scenario_timeout".to_owned());
        }
        endpoint.iterate(&mut resps, deadline)?;
        let received = resps.get(&id).map(|r| r.body.len()).unwrap_or(0);
        if received >= ABORT_AFTER {
            break;
        }
        if resps.get(&id).is_some_and(|r| r.done) {
            break;
        }
    }
    let _ = endpoint
        .conn
        .stream_shutdown(id, quiche::Shutdown::Read, H3_REQUEST_CANCELLED);
    resps.remove(&id);
    endpoint.flush()?;

    // The connection must still serve a fresh request.
    let follow = send_request(
        &mut endpoint,
        &mut resps,
        deadline,
        "GET",
        &authority,
        "/small",
        &[],
        &[],
        None,
    )?;
    match endpoint.drive(&mut resps, deadline) {
        Ok(()) => {
            endpoint.close_gracefully();
            observe(follow, &resps);
            Ok(())
        }
        Err(err) => {
            emit_failure(&err.replace(' ', "_"));
            Ok(())
        }
    }
}

fn run_idle(base_url: &str, method: &str, path: &str, idle_ms: u64) -> Result<(), String> {
    // quiche manages connection reuse internally; holding one connection idle
    // past the server timeout and then requesting exercises the reaped path,
    // and a transparent reconnect covers the case where the idle connection
    // is already gone -- which is what the scenario asserts.
    let deadline = Instant::now() + SCENARIO_DEADLINE;
    let authority = authority_of(base_url);
    let full_path = build_path("idle_reuse", path);

    match connect(base_url) {
        Ok(mut endpoint) => {
            std::thread::sleep(Duration::from_millis(idle_ms));
            let mut resps = HashMap::new();
            let attempt = send_request(
                &mut endpoint,
                &mut resps,
                deadline,
                method,
                &authority,
                &full_path,
                &[],
                &[],
                None,
            )
            .and_then(|id| {
                endpoint
                    .drive(&mut resps, deadline)
                    .map(|()| {
                        endpoint.close_gracefully();
                        observe(id, &resps);
                    })
            });
            if attempt.is_ok() {
                return Ok(());
            }
            // The idle connection was reaped. Reconnecting is the correct
            // client behaviour, and "reconnectable" is what the scenario
            // asserts.
        }
        Err(_) => std::thread::sleep(Duration::from_millis(idle_ms)),
    }

    let mut endpoint = connect(base_url)?;
    let mut resps = HashMap::new();
    let id = send_request(
        &mut endpoint,
        &mut resps,
        deadline,
        method,
        &authority,
        &full_path,
        &[],
        &[],
        None,
    )?;
    match endpoint.drive(&mut resps, deadline) {
        Ok(()) => {
            endpoint.close_gracefully();
            observe(id, &resps);
            Ok(())
        }
        Err(err) => {
            emit_failure(&err.replace(' ', "_"));
            Ok(())
        }
    }
}

fn main() {
    let argv: Vec<String> = std::env::args().skip(1).collect();

    if argv.first().is_some_and(|arg| arg == "--selftest") {
        return;
    }
    if argv.is_empty() {
        // Idle mode: the container's main process. Announce readiness for the
        // harness, then sleep; scenarios arrive via exec.
        println!("interop-driver ready");
        loop {
            std::thread::sleep(Duration::from_secs(3600));
        }
    }
    if argv.len() < 3 {
        eprintln!("usage: interop-driver BASE_URL PROTOCOL SCENARIO [key=value ...]");
        std::process::exit(2);
    }

    let base_url = argv[0].clone();
    let protocol = argv[1].clone();
    let scenario = argv[2].clone();
    if protocol != "h3" {
        eprintln!("quiche-driver: quiche speaks only HTTP/3, got {protocol}");
        std::process::exit(2);
    }
    let mut params = HashMap::new();
    for item in argv.iter().skip(3) {
        if let Some((key, value)) = item.split_once('=') {
            params.insert(key.to_owned(), value.to_owned());
        }
    }
    let method = params.get("method").cloned().unwrap_or("GET".to_owned());
    let path = params.get("path").cloned().unwrap_or("/small".to_owned());
    let upload_len = params
        .get("upload_len")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(0);

    let result = match scenario.as_str() {
        "concurrency" => {
            let count = params
                .get("count")
                .and_then(|v| v.parse::<usize>().ok())
                .unwrap_or(32);
            run_concurrency(&base_url, &path, count)
        }
        "abort_midstream" => run_abort(&base_url, &path),
        "idle_reuse" => {
            let idle_ms = params
                .get("idle_ms")
                .and_then(|v| v.parse::<u64>().ok())
                .unwrap_or(3000);
            run_idle(&base_url, &method, &path, idle_ms)
        }
        _ => run_generic(&base_url, &scenario, &method, &path, upload_len),
    };
    if let Err(err) = result {
        emit_failure(&err.replace(' ', "_"));
    }
}
