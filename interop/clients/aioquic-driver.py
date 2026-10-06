#!/usr/bin/env python3
"""Interop driver built on aioquic (independent Python HTTP/3 + QPACK stack).

Usage:
    aioquic-driver.py BASE_URL PROTOCOL SCENARIO [key=value ...]
    aioquic-driver.py --selftest
    aioquic-driver.py                      # idle mode: announce readiness, sleep

Prints one observation line per request on stdout:
    status=<u16> len=<n> sha=<hex|-> trailers=<0|1> hints=<0|1> err=<text>

The harness (interop/src/client.rs) decides whether an observation is
acceptable; this script only reports what it saw. Scenario *inputs* -- which
headers to send, how many concurrent streams -- are constructed here, because
only the driver knows its own API. The *thresholds* those inputs are judged
against live in Rust.

Unlike curl this client can observe response trailers and 1xx informational
responses, which is why it carries the trailers and early-hints scenarios.
"""

import asyncio
import hashlib
import ssl
import sys
import time
from collections import deque
from urllib.parse import urlparse

from aioquic.asyncio.client import connect
from aioquic.asyncio.protocol import QuicConnectionProtocol
from aioquic.h3.connection import H3_ALPN, H3Connection
from aioquic.h3.events import DataReceived, H3Event, HeadersReceived
from aioquic.quic.configuration import QuicConfiguration

# H3_REQUEST_CANCELLED (RFC 9114 section 8.1.2): the client is no longer
# interested in this stream. Named constant kept local so the driver does not
# depend on an enum member that may move between aioquic releases.
H3_REQUEST_CANCELLED = 0x10C

# Not a protocol constant: how long one request may take before the driver
# gives up and reports a transport error. The harness has its own (longer)
# timeout around the whole exec.
REQUEST_TIMEOUT_S = 60.0

# How often the abort path polls for newly arrived data while deciding whether
# enough of the response has arrived to cancel.
ABORT_POLL_S = 0.01


def pattern(n: int) -> bytes:
    """The shared ABCD body pattern, matching the server and the harness."""
    return (b"ABCD" * ((n + 3) // 4))[:n]


def emit(status, length, digest, trailers, hints, err=""):
    """Prints one observation line. Mirrors Observation::to_line."""
    sha = digest if digest else "-"
    print(
        f"status={status} len={length} sha={sha} "
        f"trailers={int(trailers)} hints={int(hints)} err={err}"
    )


class Driver(QuicConnectionProtocol):
    """Minimal H3 client: opens streams, collects each stream's events."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._http = H3Connection(self._quic)
        self._request_events = {}
        self._request_waiter = {}

    def quic_event_received(self, event):
        for http_event in self._http.handle_event(event):
            self.http_event_received(http_event)

    def http_event_received(self, event: H3Event):
        stream_id = event.stream_id
        if stream_id in self._request_events:
            self._request_events[stream_id].append(event)
            if event.stream_ended:
                waiter = self._request_waiter.pop(stream_id, None)
                if waiter is not None and not waiter.done():
                    waiter.set_result(self._request_events.pop(stream_id))

    async def request(
        self, method, url, headers=(), data=b"", trailers=(), timeout=REQUEST_TIMEOUT_S
    ):
        """One full request/response exchange. Returns the event deque."""
        parsed = urlparse(url)
        stream_id = self._quic.get_next_available_stream_id()
        request_headers = [
            (b":method", method.encode()),
            (b":scheme", parsed.scheme.encode()),
            (b":authority", parsed.netloc.encode()),
            (b":path", (parsed.path or "/").encode()
            + (("?" + parsed.query).encode() if parsed.query else b"")),
        ] + [(k.encode(), v.encode()) for (k, v) in headers]
        has_body = bool(data) or bool(trailers)

        loop = asyncio.get_running_loop()
        waiter = loop.create_future()
        self._request_events[stream_id] = deque()
        self._request_waiter[stream_id] = waiter

        self._http.send_headers(
            stream_id=stream_id, headers=request_headers, end_stream=not has_body
        )
        if data:
            self._http.send_data(
                stream_id=stream_id, data=data, end_stream=not trailers
            )
        if trailers:
            self._http.send_headers(
                stream_id=stream_id,
                headers=[(k.encode(), v.encode()) for (k, v) in trailers],
                end_stream=True,
            )
        self.transmit()
        return await asyncio.wait_for(asyncio.shield(waiter), timeout)


def classify(events):
    """Reduces an event deque to observation fields.

    - The final status is the :status of the last HEADERS block carrying one.
    - A HEADERS block with a 103 :status sets early-hints.
    - A HEADERS block with no :status at all is a trailer block.
    """
    status = 0
    body = bytearray()
    trailers = False
    hints = False
    for event in events:
        if isinstance(event, HeadersReceived):
            pseudo = {k: v for (k, v) in event.headers if k.startswith(b":")}
            if b":status" in pseudo:
                code = pseudo[b":status"].decode()
                if code.startswith("1") and code != "100":
                    # 103 Early Hints. A 100 Continue is not an early hint: it
                    # is part of the normal expect-continue exchange.
                    hints = True
                else:
                    status = int(code)
            else:
                trailers = True
        elif isinstance(event, DataReceived):
            body.extend(event.data)
    return status, bytes(body), trailers, hints


def observe(events):
    status, body, trailers, hints = classify(events)
    digest = hashlib.sha256(body).hexdigest() if body or status == 200 else ""
    return status, len(body), digest, trailers, hints


def build_headers(scenario, params):
    """Extra request headers for scenarios that need them."""
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


def client_configuration():
    return QuicConfiguration(
        is_client=True, alpn_protocols=H3_ALPN, verify_mode=ssl.CERT_NONE
    )


def split_base(base_url):
    """Splits a base URL into (host, port)."""
    parsed = urlparse(base_url)
    return parsed.hostname, parsed.port or 443


async def run_scenario(base_url, scenario, params):
    """Runs one scenario, printing one observation line per request."""
    method = params.get("method", "GET")
    path = build_path(scenario, params.get("path", "/small"))
    url = base_url + path
    upload_len = int(params.get("upload_len", "0"))

    if scenario == "concurrency":
        count = int(params.get("count", "32"))
        host, port = split_base(base_url)
        try:
            async with connect(
                host, port,
                configuration=client_configuration(),
                create_protocol=Driver,
            ) as client:
                results = await asyncio.gather(
                    *[
                        client.request(
                            "GET",
                            base_url + path,
                            headers=[("x-interop", "1")],
                        )
                        for _ in range(count)
                    ]
                )
                client.close()
        except Exception as exc:
            emit(0, 0, "", False, False, err=type(exc).__name__)
            return
        for events in results:
            status, length, digest, trailers, hints = observe(events)
            emit(status, length, digest, trailers, hints)
        return

    if scenario == "abort_midstream":
        abort_after = 64 * 1024
        host, port = split_base(base_url)
        try:
            async with connect(
                host, port,
                configuration=client_configuration(),
                create_protocol=Driver,
            ) as client:
                stream_id = client._quic.get_next_available_stream_id()
                parsed = urlparse(url)
                headers = [
                    (b":method", b"GET"),
                    (b":scheme", parsed.scheme.encode()),
                    (b":authority", parsed.netloc.encode()),
                    (b":path", (parsed.path or "/").encode()),
                    (b"x-interop", b"1"),
                ]
                loop = asyncio.get_running_loop()
                waiter = loop.create_future()
                client._request_events[stream_id] = deque()
                client._request_waiter[stream_id] = waiter
                client._http.send_headers(
                    stream_id=stream_id, headers=headers, end_stream=True
                )
                client.transmit()
                received = 0
                deadline = time.monotonic() + REQUEST_TIMEOUT_S
                while received < abort_after and time.monotonic() < deadline:
                    await asyncio.sleep(ABORT_POLL_S)
                    queue = client._request_events.get(stream_id, deque())
                    while queue:
                        event = queue.popleft()
                        if isinstance(event, DataReceived):
                            received += len(event.data)
                        if event.stream_ended:
                            break
                client._quic.reset_stream(stream_id, H3_REQUEST_CANCELLED)
                client.transmit()
                waiter.cancel()
                client._request_events.pop(stream_id, None)
                client._request_waiter.pop(stream_id, None)
                events = await client.request("GET", base_url + "/small")
                client.close()
        except Exception as exc:
            emit(0, 0, "", False, False, err=type(exc).__name__)
            return
        status, length, digest, trailers, hints = observe(events)
        emit(status, length, digest, trailers, hints)
        return

    if scenario == "idle_reuse":
        idle_ms = int(params.get("idle_ms", "3000"))
        host, port = split_base(base_url)

        async def idle_request():
            async with connect(
                host, port,
                configuration=client_configuration(),
                create_protocol=Driver,
            ) as client:
                await asyncio.sleep(idle_ms / 1000.0)
                try:
                    events = await client.request(method, url)
                except Exception:
                    # The server reaped the idle connection. Reconnecting is the
                    # correct client behaviour, and "reconnectable" is what the
                    # scenario asserts.
                    client.close()
                    raise
                client.close()
                return events

        try:
            events = await idle_request()
        except Exception:
            # Reconnect on a fresh connection and try once more.
            try:
                async with connect(
                    host, port,
                    configuration=client_configuration(),
                    create_protocol=Driver,
                ) as client:
                    events = await client.request(method, url)
                    client.close()
            except Exception as exc:
                emit(0, 0, "", False, False, err=type(exc).__name__)
                return
        status, length, digest, trailers, hints = observe(events)
        emit(status, length, digest, trailers, hints)
        return

    # Generic single request.
    data = pattern(upload_len) if upload_len else b""
    headers = [("x-interop", "1"), ("content-length", str(len(data)))]
    headers += build_headers(scenario, params)
    trailers = [("x-interop-req", "1")] if scenario == "trailers" else []
    host, port = split_base(base_url)
    try:
        async with connect(
            host, port,
            configuration=client_configuration(),
            create_protocol=Driver,
        ) as client:
            events = await client.request(
                method, url, headers=headers, data=data, trailers=trailers
            )
            client.close()
    except Exception as exc:
        emit(0, 0, "", False, False, err=type(exc).__name__)
        return
    status, length, digest, trailers, hints = observe(events)
    emit(status, length, digest, trailers, hints)


def main(argv):
    if argv[:1] == ["--selftest"]:
        try:
            import aioquic  # noqa: F401
        except ImportError:
            return 1
        return 0
    if not argv:
        # Idle mode: the container's main process. Announce readiness for the
        # harness, then sleep; scenarios arrive via exec.
        print("interop-driver ready", flush=True)
        while True:
            time.sleep(3600)
        return 0

    base_url, _protocol, scenario, *rest = argv
    params = dict(item.split("=", 1) for item in rest if "=" in item)
    try:
        asyncio.run(
            asyncio.wait_for(
                run_scenario(base_url, scenario, params), timeout=120.0
            )
        )
    except Exception as exc:
        emit(0, 0, "", False, False, err=type(exc).__name__)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
