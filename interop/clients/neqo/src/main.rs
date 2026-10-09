// Interop driver built on neqo (Mozilla's QUIC + HTTP/3 stack).
//
// Usage:
//   interop-driver BASE_URL PROTOCOL SCENARIO [key=value ...]
//   interop-driver --selftest
//   interop-driver                      # idle mode: announce readiness, sleep
//
// Prints one observation line per request on stdout:
//   status=<u16> len=<n> sha=<hex|-> trailers=<0|1> hints=<0|1> err=<text>
//
// neqo is the QUIC + HTTP/3 implementation used in Firefox. Its client is the
// stable, production-hardened side (the server side exists only to test the
// client), which is exactly the opinion this matrix wants on the server's
// HTTP/3 behaviour. It speaks only HTTP/3.
//
// The harness (interop/src/client.rs) decides whether an observation is
// acceptable; this driver only reports what it saw. Scenario *inputs* -- which
// headers to send, how many concurrent streams -- are constructed here, because
// only the driver knows its own API. The *thresholds* those inputs are judged
// against live in Rust.
//
// neqo drives no socket of its own: the application pumps UDP datagrams
// through `process_output` / `process_input` and handles `Http3ClientEvent`s.
// That loop lives in `pump` below; everything else is scenario plumbing.

use std::cell::RefCell;
use std::collections::HashMap;
use std::net::{SocketAddr, ToSocketAddrs as _, UdpSocket};
use std::rc::Rc;
use std::time::{Duration, Instant};

use neqo_common::{Datagram, Tos, event::Provider as _};
use neqo_http3::{Header, Http3Client, Http3ClientEvent, Http3Parameters, Http3State, Priority};
use neqo_transport::{EmptyConnectionIdGenerator, Output};
use sha2::{Digest as _, Sha256};

// H3_REQUEST_CANCELLED (RFC 9114 section 8.1.2): the client is no longer
// interested in this stream.
const H3_REQUEST_CANCELLED: u64 = 0x10c;

// How long one scenario may take overall. The harness has its own (longer)
// timeout around the whole exec.
const SCENARIO_DEADLINE: Duration = Duration::from_secs(100);

// How long the QUIC handshake may take.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(15);

// Abort threshold for the abort_midstream scenario, matching the other H3
// drivers.
const ABORT_AFTER: usize = 64 * 1024;

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

/// What one request stream produced.
#[derive(Default)]
struct Resp {
    status: u16,
    body: Vec<u8>,
    trailers: bool,
    hints: bool,
    done: bool,
    failed: bool,
    /// Bytes still to upload, if this stream carries a request body.
    pending_upload: Vec<u8>,
}

/// Reduces one HEADERS block to observation fields.
///
/// - An interim block carrying a 103 `:status` sets early-hints. A 100 is part
///   of the normal expect-continue exchange, not an early hint.
/// - A non-interim block with no `:status` at all is a trailer block.
/// - Anything else is the final status.
fn classify_headers(headers: &[Header], interim: bool, resp: &mut Resp) {
    let mut status: Option<&[u8]> = None;
    for header in headers {
        if header.name() == ":status" {
            status = Some(header.value());
            break;
        }
    }
    match status {
        Some(value) if interim && value.starts_with(b"103") => {
            resp.hints = true;
        }
        Some(value) if interim => {
            // Another interim (e.g. 100 Continue): part of the exchange, not
            // an observation on its own.
            let _ = value;
        }
        Some(value) => {
            if let Ok(text) = std::str::from_utf8(value) {
                if let Ok(code) = text.parse::<u16>() {
                    resp.status = code;
                }
            }
        }
        None if !interim => {
            resp.trailers = true;
        }
        None => {}
    }
}

struct Endpoint {
    socket: UdpSocket,
    client: Http3Client,
    local: SocketAddr,
}

impl Endpoint {
    /// Handles every pending client event, feeding per-stream state.
    fn handle_events(&mut self, resps: &mut HashMap<neqo_transport::StreamId, Resp>) {
        while let Some(event) = self.client.next_event() {
            if std::env::var("NEQO_DEBUG").is_ok() {
                eprintln!("DEBUG event {event:?}");
            }
            match event {
                Http3ClientEvent::AuthenticationNeeded => {
                    // Test-only: the scenario server generates a fresh
                    // self-signed certificate per run, so there is nothing
                    // stable to pin.
                    self.client
                        .authenticated(nss::AuthenticationStatus::Ok, Instant::now());
                }
                Http3ClientEvent::HeaderReady {
                    stream_id,
                    headers,
                    interim,
                    fin,
                } => {
                    if let Some(resp) = resps.get_mut(&stream_id) {
                        classify_headers(&headers, interim, resp);
                        // A trailer block ends the stream; there is no body
                        // after it.
                        if fin && resp.trailers {
                            resp.done = true;
                        }
                    }
                }
                Http3ClientEvent::DataReadable { stream_id } => {
                    // A reset stream may still report readable; a failed
                    // stream stays failed.
                    if resps.get(&stream_id).is_some_and(|r| r.failed) {
                        continue;
                    }
                    let mut buf = [0u8; 65535];
                    loop {
                        match self.client.read_data(Instant::now(), stream_id, &mut buf) {
                            Ok((0, true)) => {
                                if let Some(resp) = resps.get_mut(&stream_id) {
                                    resp.done = true;
                                }
                                break;
                            }
                            Ok((0, false)) => break,
                            Ok((n, fin)) => {
                                if let Some(resp) = resps.get_mut(&stream_id) {
                                    resp.body.extend_from_slice(&buf[..n]);
                                    if fin {
                                        resp.done = true;
                                    }
                                }
                                if fin {
                                    break;
                                }
                            }
                            Err(_) => {
                                if let Some(resp) = resps.get_mut(&stream_id) {
                                    resp.failed = true;
                                    resp.done = true;
                                }
                                break;
                            }
                        }
                    }
                }
                Http3ClientEvent::DataWritable { stream_id } => {
                    // Push pending upload bytes; a partial write leaves the
                    // remainder for the next writable event.
                    let now = Instant::now();
                    if let Some(resp) = resps.get_mut(&stream_id) {
                        while !resp.pending_upload.is_empty() {
                            match self.client.send_data(stream_id, &resp.pending_upload, now) {
                                Ok(0) => break,
                                Ok(n) => {
                                    resp.pending_upload.drain(..n);
                                }
                                Err(_) => break,
                            }
                        }
                        if resp.pending_upload.is_empty() {
                            let _ = self.client.stream_close_send(stream_id, now);
                        }
                    }
                }
                Http3ClientEvent::Reset { stream_id, .. }
                | Http3ClientEvent::StopSending { stream_id, .. } => {
                    if let Some(resp) = resps.get_mut(&stream_id) {
                        resp.failed = true;
                        resp.done = true;
                    }
                }
                Http3ClientEvent::StateChange(_)
                | Http3ClientEvent::RequestsCreatable
                | Http3ClientEvent::GoawayReceived
                | Http3ClientEvent::ResumptionToken(_)
                | Http3ClientEvent::ZeroRttRejected
                | Http3ClientEvent::OutgoingDatagramSpaceAvailable
                | Http3ClientEvent::EchFallbackAuthenticationNeeded { .. }
                | Http3ClientEvent::WebTransport(_)
                | Http3ClientEvent::ConnectUdp(_) => {}
            }
        }
    }

    /// Sends every pending QUIC datagram on the socket. Returns the callback
    /// delay when the client is idle, if any.
    fn flush(&mut self) -> Result<Option<Duration>, String> {
        loop {
            match self.client.process_output(Instant::now()) {
                Output::Datagram(dgram) => {
                    if std::env::var("NEQO_DEBUG").is_ok() {
                        eprintln!("DEBUG tx {} bytes -> {}", dgram.len(), dgram.destination());
                    }
                    self.socket
                        .send_to(&dgram[..], dgram.destination())
                        .map_err(|err| format!("send:{err}"))?;
                }
                Output::Callback(delay) => return Ok(Some(delay)),
                Output::None => return Ok(None),
            }
        }
    }

    /// One event-loop iteration: handle events, flush sends, then wait for the
    /// next packet (or the client's callback delay).
    ///
    /// Note this deliberately performs a full cycle even when `resps` is
    /// empty or already complete: the handshake loop calls it before any
    /// stream is tracked, and returning early there would never send the
    /// Initial flight. Termination on completed streams is the caller's job
    /// (see [`Self::drive`]).
    fn iterate(
        &mut self,
        resps: &mut HashMap<neqo_transport::StreamId, Resp>,
        deadline: Instant,
    ) -> Result<(), String> {
        self.handle_events(resps);
        let callback = self.flush()?;

        let now = Instant::now();
        if now >= deadline {
            return Err("scenario_timeout".to_owned());
        }
        let wait = callback
            .unwrap_or(Duration::from_secs(5))
            .min(deadline.saturating_duration_since(now));
        let _ = self.socket.set_read_timeout(Some(wait));

        let mut buf = vec![0u8; 65535];
        match self.socket.recv_from(&mut buf) {
            Ok((len, from)) => {
                if std::env::var("NEQO_DEBUG").is_ok() {
                    eprintln!("DEBUG rx {len} bytes <- {from}");
                }
                buf.truncate(len);
                let dgram = Datagram::new(from, self.local, Tos::default(), buf);
                self.client.process_input(dgram, Instant::now());
                Ok(())
            }
            Err(err)
                if err.kind() == std::io::ErrorKind::WouldBlock
                    || err.kind() == std::io::ErrorKind::TimedOut =>
            {
                Ok(())
            }
            Err(err) => Err(format!("recv:{err}")),
        }
    }

    /// Pumps the connection until every tracked stream is done.
    fn drive(
        &mut self,
        resps: &mut HashMap<neqo_transport::StreamId, Resp>,
        deadline: Instant,
    ) -> Result<(), String> {
        loop {
            self.handle_events(resps);
            if resps.values().all(|r| r.done) {
                return Ok(());
            }
            if matches!(
                self.client.state(),
                Http3State::Closed(..) | Http3State::Closing(..)
            ) {
                return Err(format!("connection_closed:{:?}", self.client.state()));
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
        let _ = self.flush();
        self.client.close(Instant::now(), 0, "kthxbye");
        let _ = self.flush();
    }
}

fn connect(base_url: &str) -> Result<Endpoint, String> {
    let (host, peer) = split_base(base_url)?;
    let socket = UdpSocket::bind("0.0.0.0:0").map_err(|err| format!("bind:{err}"))?;
    let local = socket
        .local_addr()
        .map_err(|err| format!("local_addr:{err}"))?;

    let cid_gen: Rc<RefCell<dyn neqo_transport::ConnectionIdGenerator>> =
        Rc::new(RefCell::new(EmptyConnectionIdGenerator::default()));
    let client = Http3Client::new(
        host,
        cid_gen,
        local,
        peer,
        Http3Parameters::default(),
        Instant::now(),
    )
    .map_err(|err| format!("client_new:{err:?}"))?;

    let mut endpoint = Endpoint {
        socket,
        client,
        local,
    };

    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    let mut resps = HashMap::new();
    loop {
        endpoint.handle_events(&mut resps);
        if matches!(endpoint.client.state(), Http3State::Connected) {
            break;
        }
        if matches!(
            endpoint.client.state(),
            Http3State::Closed(..) | Http3State::Closing(..)
        ) {
            return Err("handshake_closed".to_owned());
        }
        if Instant::now() >= deadline {
            return Err("handshake_timeout".to_owned());
        }
        endpoint.iterate(&mut resps, deadline)?;
    }
    Ok(endpoint)
}

/// Starts one request: `fetch`, then either half-closes a GET immediately or
/// queues the upload for the writable events to push.
fn start_request(
    endpoint: &mut Endpoint,
    resps: &mut HashMap<neqo_transport::StreamId, Resp>,
    deadline: Instant,
    method: &str,
    base_url: &str,
    path: &str,
    extra: &[(String, String)],
    upload: Vec<u8>,
) -> Result<neqo_transport::StreamId, String> {
    let url: http::Uri = format!("{base_url}{path}")
        .parse()
        .map_err(|_| "bad_url".to_owned())?;
    let headers: Vec<Header> = extra
        .iter()
        .map(|(name, value)| Header::new(name.clone(), value.clone().into_bytes()))
        .collect();

    // A fresh connection may briefly refuse new streams; pumping once is what
    // unblocks it.
    let id = loop {
        match endpoint
            .client
            .fetch(Instant::now(), method, &url, &headers, Priority::default())
        {
            Ok(id) => break id,
            Err(neqo_http3::Error::StreamLimit | neqo_http3::Error::Unavailable) => {
                endpoint.iterate(resps, deadline)?;
            }
            Err(err) => return Err(format!("fetch:{err:?}")),
        }
    };

    let mut resp = Resp::default();
    if method == "GET" || upload.is_empty() {
        let _ = endpoint.client.stream_close_send(id, Instant::now());
    } else {
        resp.pending_upload = upload;
        // Push eagerly: the stream is usually writable already, which saves a
        // round trip on large uploads.
        let now = Instant::now();
        while !resp.pending_upload.is_empty() {
            match endpoint.client.send_data(id, &resp.pending_upload, now) {
                Ok(0) => break,
                Ok(n) => {
                    resp.pending_upload.drain(..n);
                }
                Err(_) => break,
            }
        }
        if resp.pending_upload.is_empty() {
            let _ = endpoint.client.stream_close_send(id, Instant::now());
        }
    }
    resps.insert(id, resp);
    endpoint.flush()?;
    Ok(id)
}

/// Renders one tracked stream as an observation line.
fn observe(id: neqo_transport::StreamId, resps: &HashMap<neqo_transport::StreamId, Resp>) {
    match resps.get(&id) {
        Some(resp) if resp.failed => emit_failure("request_failed"),
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

fn run_generic(
    base_url: &str,
    scenario: &str,
    method: &str,
    path: &str,
    upload_len: usize,
) -> Result<(), String> {
    if scenario == "trailers" {
        // neqo's client API can observe response trailers but cannot send
        // request trailers, and the scenario requires both directions. The
        // capability table reflects this, so the matrix never asks; failing
        // loudly here keeps a silent pass impossible.
        return Err("request_trailers_unsupported".to_owned());
    }
    let deadline = Instant::now() + SCENARIO_DEADLINE;
    let mut endpoint = connect(base_url)?;
    let mut resps = HashMap::new();
    let full_path = build_path(scenario, path);
    let extra = build_headers(scenario);
    let upload = pattern(upload_len);

    let id = start_request(
        &mut endpoint,
        &mut resps,
        deadline,
        method,
        base_url,
        &full_path,
        &extra,
        upload,
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
    let mut ids = Vec::with_capacity(count);
    for _ in 0..count {
        let id = start_request(
            &mut endpoint,
            &mut resps,
            deadline,
            "GET",
            base_url,
            path,
            &[],
            Vec::new(),
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
    let id = start_request(
        &mut endpoint,
        &mut resps,
        deadline,
        "GET",
        base_url,
        path,
        &[],
        Vec::new(),
    )?;

    // Read a bounded prefix, then cancel the stream: the client is no longer
    // interested in this response.
    loop {
        if matches!(
            endpoint.client.state(),
            Http3State::Closed(..) | Http3State::Closing(..)
        ) {
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
    let _ = endpoint.client.cancel_fetch(id, H3_REQUEST_CANCELLED);
    resps.remove(&id);
    endpoint.flush()?;

    // The connection must still serve a fresh request.
    let follow = start_request(
        &mut endpoint,
        &mut resps,
        deadline,
        "GET",
        base_url,
        "/small",
        &[],
        Vec::new(),
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
    // Holding one connection idle past the server timeout and then requesting
    // exercises the reaped path, and a transparent reconnect covers the case
    // where the idle connection is already gone -- which is what the scenario
    // asserts.
    let deadline = Instant::now() + SCENARIO_DEADLINE;
    let full_path = build_path("idle_reuse", path);

    match connect(base_url) {
        Ok(mut endpoint) => {
            std::thread::sleep(Duration::from_millis(idle_ms));
            let mut resps = HashMap::new();
            let attempt = start_request(
                &mut endpoint,
                &mut resps,
                deadline,
                method,
                base_url,
                &full_path,
                &[],
                Vec::new(),
            )
            .and_then(|id| {
                endpoint.drive(&mut resps, deadline).map(|()| {
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
    let id = start_request(
        &mut endpoint,
        &mut resps,
        deadline,
        method,
        base_url,
        &full_path,
        &[],
        Vec::new(),
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

    // NSS backs neqo's TLS. Initialising without a database is enough: the
    // driver approves the scenario server's certificate explicitly per
    // connection (see AuthenticationNeeded above).
    nss::init().expect("NSS initialisation failed");

    let base_url = argv[0].clone();
    let protocol = argv[1].clone();
    let scenario = argv[2].clone();
    if protocol != "h3" {
        eprintln!("neqo-driver: neqo speaks only HTTP/3, got {protocol}");
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
