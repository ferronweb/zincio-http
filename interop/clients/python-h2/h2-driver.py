#!/usr/bin/env python3
"""Interop driver built on hyper-h2 (the popular Python HTTP/2 stack).

Usage:
    h2-driver.py BASE_URL PROTOCOL SCENARIO [key=value ...]
    h2-driver.py --selftest
    h2-driver.py                      # idle mode: announce readiness, sleep

Prints one observation line per request on stdout:
    status=<u16> len=<n> sha=<hex|-> trailers=<0|1> hints=<0|1> err=<text>

hyper-h2 gives raw frame-level control over a single h2c connection, so this
is the only containerised client that can observe 103 Early Hints and
trailers over HTTP/2 -- closing the container-coverage gap curl leaves there.

Flow control is manual, as the library requires: received data must be
acknowledged via acknowledge_received_data, or the transfer stalls at exactly
the advertised window. Uploads are chunked against the local window the same
way.
"""

import hashlib
import socket
import sys
import time
from urllib.parse import urlparse

import h2.connection
import h2.events
import h2.errors
import h2.exceptions

REQUEST_TIMEOUT_S = 60.0
ABORT_AFTER = 64 * 1024
CHUNK = 16 * 1024


def pattern(n):
    """The shared ABCD body pattern, matching the server and the harness."""
    return (b"ABCD" * ((n + 3) // 4))[:n]


def emit(status, length, digest, trailers, hints, err=""):
    """Prints one observation line. Mirrors Observation::to_line."""
    sha = digest if digest else "-"
    print(
        f"status={status} len={length} sha={sha} "
        f"trailers={int(trailers)} hints={int(hints)} err={err}"
    )


class Exchange:
    """Accumulates one request/response exchange from h2 events."""

    def __init__(self):
        self.status = 0
        self.body = bytearray()
        self.trailers = False
        self.hints = False
        self.ended = False
        self.error = None

    def feed(self, event):
        if isinstance(event, h2.events.InformationalResponseReceived):
            for key, value in event.headers:
                if key == b":status" and value.decode() == "103":
                    self.hints = True
        elif isinstance(event, h2.events.ResponseReceived):
            for key, value in event.headers:
                if key == b":status":
                    code = value.decode()
                    if code == "103":
                        self.hints = True
                    elif not code.startswith("1"):
                        self.status = int(code)
                    # A 100 Continue is neither final nor an early hint.
                # Trailers never arrive here; hyper-h2 uses TrailersReceived.
        elif isinstance(event, h2.events.TrailersReceived):
            for key, value in event.headers:
                if key == b"x-echo-trailer":
                    self.trailers = True
        elif isinstance(event, h2.events.DataReceived):
            self.body.extend(event.data)
        elif isinstance(event, h2.events.StreamEnded):
            self.ended = True
        elif isinstance(event, h2.events.StreamReset):
            self.error = f"reset_{event.error_code}"
            self.ended = True
        elif isinstance(event, h2.events.ConnectionTerminated):
            self.error = f"conn_{event.error_code}"
            self.ended = True

    def observation(self):
        if self.error is not None:
            return (0, 0, "", False, False, self.error)
        digest = hashlib.sha256(bytes(self.body)).hexdigest()
        return (self.status, len(self.body), digest, self.trailers, self.hints, "")


def pump(sock, conn, exchanges, deadline):
    """Runs the event loop until every tracked exchange ends or errors.

    Returns True when all exchanges completed, False on timeout.
    """
    sock.settimeout(max(0.1, deadline - time.monotonic()))
    while True:
        pending = [e for e in exchanges.values() if not e.ended]
        if not pending:
            return True
        if time.monotonic() >= deadline:
            return False
        try:
            data = sock.recv(65535)
        except socket.timeout:
            return False
        if not data:
            for exchange in pending:
                if exchange.error is None:
                    exchange.error = "eof"
                exchange.ended = True
            return True
        try:
            events = conn.receive_data(data)
        except h2.exceptions.ProtocolError as exc:
            for exchange in pending:
                exchange.error = type(exc).__name__
                exchange.ended = True
            return True
        for event in events:
            if isinstance(event, h2.events.DataReceived):
                # Manual flow-control acknowledgement: without this the
                # transfer stalls at exactly the advertised window.
                conn.acknowledge_received_data(
                    event.flow_controlled_length, event.stream_id
                )
            stream_id = getattr(event, "stream_id", None)
            if stream_id in exchanges:
                exchanges[stream_id].feed(event)
        out = conn.data_to_send()
        if out:
            sock.sendall(out)


def open_connection(base_url):
    """Opens an h2c connection (prior knowledge, no TLS)."""
    parsed = urlparse(base_url)
    sock = socket.create_connection((parsed.hostname, parsed.port or 80), timeout=10)
    conn = h2.connection.H2Connection()
    conn.initiate_connection()
    sock.sendall(conn.data_to_send())
    return sock, conn, parsed


def request_headers(parsed, method, path, extra):
    headers = [
        (":method", method),
        (":scheme", parsed.scheme),
        (":authority", parsed.netloc),
        (":path", path),
        ("x-interop", "1"),
    ]
    headers.extend(extra)
    return headers


def do_request(sock, conn, parsed, method, path, upload, extra, trailers, deadline):
    """Sends one request, honouring send-side flow control for uploads."""
    stream_id = conn.get_next_available_stream_id()
    exchange = Exchange()
    exchanges = {stream_id: exchange}
    # Paths stay ASCII here by construction (pattern bytes and header names).
    headers = request_headers(parsed, method, path, extra)
    conn.send_headers(stream_id, headers, end_stream=not upload and not trailers)
    sock.sendall(conn.data_to_send())

    offset = 0
    if upload:
        # Drain mode, not pump mode: the server cannot respond until it has
        # the full body, so waiting for stream end here would stall sending
        # long enough for the server's idle timeout to fire. Instead, briefly
        # collect WINDOW_UPDATEs and keep sending.
        while offset < len(upload):
            if time.monotonic() >= deadline:
                exchange.error = "timeout"
                exchange.ended = True
                break
            if exchange.ended:
                break
            window = conn.local_flow_control_window(stream_id)
            if window <= 0:
                sock.settimeout(1.0)
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    continue
                if not data:
                    exchange.error = "eof"
                    exchange.ended = True
                    break
                try:
                    events = conn.receive_data(data)
                except h2.exceptions.ProtocolError as exc:
                    exchange.error = type(exc).__name__
                    exchange.ended = True
                    break
                for event in events:
                    stream_id_event = getattr(event, "stream_id", None)
                    if stream_id_event in exchanges:
                        exchanges[stream_id_event].feed(event)
                out = conn.data_to_send()
                if out:
                    sock.sendall(out)
                continue
            chunk = upload[offset : offset + min(CHUNK, window)]
            last = offset + len(chunk) >= len(upload) and not trailers
            try:
                conn.send_data(stream_id, chunk, end_stream=last)
            except h2.exceptions.ProtocolError as exc:
                exchange.error = type(exc).__name__
                exchange.ended = True
                break
            sock.sendall(conn.data_to_send())
            offset += len(chunk)
        if not exchange.ended and trailers and offset >= len(upload):
            conn.send_headers(stream_id, trailers, end_stream=True)
            sock.sendall(conn.data_to_send())

    if not pump(sock, conn, exchanges, deadline):
        exchange.error = exchange.error or "timeout"
        exchange.ended = True
    return exchange


def build_extra(scenario):
    if scenario == "many_headers":
        return [(f"x-interop-{i:04d}", "v") for i in range(200)]
    if scenario == "big_header_rejected":
        return [("x-big", "v" * (32 * 1024))]
    if scenario == "expect_continue":
        return [("expect", "100-continue")]
    return []


def build_path(scenario, path):
    if scenario == "long_uri":
        return path + "?" + pattern(8 * 1024).decode()
    return path


def run_scenario(base_url, scenario, params):
    method = params.get("method", "GET")
    path = build_path(scenario, params.get("path", "/small"))
    upload_len = int(params.get("upload_len", "0"))
    upload = pattern(upload_len) if upload_len else b""
    deadline = time.monotonic() + REQUEST_TIMEOUT_S

    if scenario == "concurrency":
        count = int(params.get("count", "32"))
        sock, conn, parsed = open_connection(base_url)
        try:
            exchanges = {}
            for _ in range(count):
                stream_id = conn.get_next_available_stream_id()
                exchanges[stream_id] = Exchange()
                conn.send_headers(
                    stream_id,
                    request_headers(parsed, "GET", path, []),
                    end_stream=True,
                )
            sock.sendall(conn.data_to_send())
            if not pump(sock, conn, exchanges, deadline):
                for exchange in exchanges.values():
                    if not exchange.ended:
                        exchange.error = exchange.error or "timeout"
                        exchange.ended = True
            for exchange in exchanges.values():
                emit(*exchange.observation())
        finally:
            sock.close()
        return

    if scenario == "abort_midstream":
        sock, conn, parsed = open_connection(base_url)
        try:
            stream_id = conn.get_next_available_stream_id()
            exchange = Exchange()
            conn.send_headers(
                stream_id, request_headers(parsed, "GET", path, []), end_stream=True
            )
            sock.sendall(conn.data_to_send())
            received = 0
            sock.settimeout(1.0)
            while received < ABORT_AFTER and time.monotonic() < deadline:
                try:
                    data = sock.recv(65535)
                except socket.timeout:
                    continue
                if not data:
                    break
                for event in conn.receive_data(data):
                    if isinstance(event, h2.events.DataReceived):
                        received += len(event.data)
                        conn.acknowledge_received_data(
                            event.flow_controlled_length, event.stream_id
                        )
                    if isinstance(event, (h2.events.StreamEnded, h2.events.StreamReset)):
                        break
                out = conn.data_to_send()
                if out:
                    sock.sendall(out)
            conn.reset_stream(stream_id, error_code=0x8)
            sock.sendall(conn.data_to_send())
            follow = do_request(
                sock, conn, parsed, "GET", "/small", b"", [], [], deadline
            )
            emit(*follow.observation())
        finally:
            sock.close()
        return

    if scenario == "idle_reuse":
        idle_ms = int(params.get("idle_ms", "3000"))
        time.sleep(idle_ms / 1000.0)
        sock, conn, parsed = open_connection(base_url)
        try:
            exchange = do_request(
                sock, conn, parsed, method, path, upload, [], [], deadline
            )
            emit(*exchange.observation())
        finally:
            sock.close()
        return

    # Generic single request.
    sock, conn, parsed = open_connection(base_url)
    try:
        # The parsed URL carries no query; the scenario path (possibly with a
        # long query) is applied by overriding :path below.
        trailers = [("x-interop-req", "1")] if scenario == "trailers" else []
        exchange = do_request(
            sock, conn, parsed, method, path, upload, build_extra(scenario),
            trailers, deadline,
        )
        emit(*exchange.observation())
    finally:
        sock.close()


def main(argv):
    if argv[:1] == ["--selftest"]:
        try:
            import h2.connection  # noqa: F401
        except ImportError:
            return 1
        return 0
    if not argv:
        print("interop-driver ready", flush=True)
        while True:
            time.sleep(3600)
        return 0

    base_url, _protocol, scenario, *rest = argv
    params = dict(item.split("=", 1) for item in rest if "=" in item)
    try:
        run_scenario(base_url, scenario, params)
    except Exception as exc:
        emit(0, 0, "", False, False, err=type(exc).__name__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
