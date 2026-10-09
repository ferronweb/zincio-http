# `zincio-http` interop testing setup

This test setup tests various HTTP clients against a `zincio-http` server to catch interop issues, primarly for HTTP/2 and HTTP/3 implementations.

## Why this exists

Several bugs in `zincio-http`'s changelog were found by running a real-world HTTP client against the server, such as:

| Version | Bug | Found by |
| --- | --- | --- |
| 0.4.2 | max-frame-size `SETTINGS` asymmetry -> frame-size mismatch | libnghttp2 |
| 0.4.2 | `curl: (18) stream 0 reset` on HTTP/3 | curl |
| 0.4.8 | flow-control reset on large response bodies | hyper |
| 0.4.11 | 100 Continue response-related deadlocks | OkHttp |

## Design notes

**The matrix is authoritative.** Each scenario declares the status, body
length, and body digest it expects. A client driver only reports what it
observed; the test matrix decides whether that is correct. Otherwise every new
client would re-encode the same expectations and drift.

**Bodies are a repeating `ABCD` pattern.** A repeating 4-byte sequence rather
than a single byte means a SHA-256 over the body detects truncation,
duplication, and reordering, while remaining cheap to generate for a 64 MiB
response. The digest is computed by the harness from the same pattern bytes,
so it is never duplicated in a client script.

**The two header scenarios share one limit.** `many_headers` must be accepted
and `big_header_rejected` must be refused by the same
`max_header_list_size`. A unit test asserts both directions, so moving the
limit fails a test instead of quietly changing what either scenario means.

**HTTP/2 is served as h2c, not TLS.** QUIC mandates TLS so HTTP/3 needs a
certificate, but serving HTTP/2 in cleartext keeps container drivers down to a
couple of flags with no trust-anchor configuration.

**Capability negotiation, not hard-coded skips.** Scenarios declare the
[`Capability`](src/scenario.rs) they need; drivers declare what they implement.
The matrix is the intersection, so an unimplemented capability becomes a
reported skip rather than a spurious failure.

## Coverage

Registered clients, and what each can actually observe:

| Client | Protocols | Scenarios |
| --- | --- | --- |
| `curl` (nghttp2) | HTTP/1.1, HTTP/2 | 18 scenario runs |
| `curl` (ngtcp2, from source) | HTTP/3 | 9 scenario runs |
| `aioquic` (Python QPACK) | HTTP/3 | 41 scenario runs, incl. 32-way concurrency |
| `Go` (x/net HPACK) | HTTP/1.1, HTTP/2 | 78 scenario runs, incl. 32-way concurrency |
| `OkHttp` (JVM HPACK) | HTTP/1.1, HTTP/2 | 80 scenario runs, incl. 32-way concurrency |
| `Python hyper-h2` | HTTP/2 | 44 scenario runs, incl. H2 103 observation |
| `quic-go` | HTTP/3 | 44 scenario runs, full H3 matrix |
| `quiche` (Cloudflare QUIC) | HTTP/3 | 44 scenario runs, full H3 matrix |
| `neqo` (Firefox QUIC) | HTTP/3 | 43 scenario runs, full H3 matrix except trailers |
| `Node` (stdlib http2) | HTTP/2 | 41 scenario runs, incl. 32-way concurrency |

Not covered (see [LIMITATIONS.md](./LIMITATIONS.md),
which also lists empty matrix cells, thin single-runner cells, and deliberate
scope exclusions):

- **Concurrent streams over HTTP/1.1.** Pipelining aside, HTTP/1.1 has no
  multiplexing, so the concurrency scenario only runs over HTTP/2 and HTTP/3.
- **103 Early Hints and 100 Continue as observed by a containerised client.**
  Over HTTP/3 they are covered by quic-go, quiche, and neqo (aioquic tears
  down the connection on any 1xx-then-final exchange, so its HEADERS state
  machine has no informational state, and curl cannot surface 1xx at all).
  Over HTTP/2 and HTTP/1.1 the only 103 observer is Go, so those two scenarios
  additionally run in `tests/h2_smoke.rs` and the in-repo fixture tests.
- **Trailers as observed by a containerised client.** Over HTTP/3 they are
  covered by aioquic, quic-go, and quiche (curl-http3 cannot surface them, and
  neqo's client ignores response trailers by design). Over HTTP/1.1 and
  HTTP/2 no client both sends request trailers and observes response trailers
  yet, so the scenario runs only in `tests/h2_smoke.rs` and the in-repo
  fixture tests.

## Running

Server plus an in-process consistency check:

```sh
cargo test
```

Drive the server manually (useful for poking at a client interactively):

```sh
cargo run --bin interop-server -- --h1-port 18080 --h2-port 18081 --h3-port 18443
# prints: h1=18080 h2=18081 h3=18443
#         READY

curl -s http://127.0.0.1:18080/small
curl -s --http2-prior-knowledge http://127.0.0.1:18081/large
curl -sk --http3-only https://localhost:18443/large
```

## Why no web browsers

Every major web browser ships a custom HTTP stack that cannot be used in a script client:

| Browser | HTTP/2 | HTTP/3 / QUIC | TLS |
| --- | --- | --- | --- |
| Chrome / Edge | Custom (`Http2Session`, BoringSSL) | Custom (Cronet QUIC) | BoringSSL |
| Firefox | Custom (`nsHttp`, Necko) | neqo (Rust, though this alone is tested in HTTP/3 setup) | NSS |
| Safari | Custom (CFNetwork) | Custom (Network.framework) | SecureTransport |

Concretely, a browser cannot do what this matrix needs:

- **No raw frame control.** A driver must send a specific oversized header
  block, reset a stream mid-response, or observe a 103 separately from the
  final response. Browsers expose navigation-level APIs (fetch, XHR), not
  frames. Headless Chrome via CDP can capture what happened
  (`Network.responseReceivedExtraInfo` shows 103s), but it cannot cause a
  mid-stream reset on demand.
- **No trust-anchor flexibility in automation.** The scenario server uses a
  fresh self-signed certificate per run. Browsers can be told to ignore it
  (`--ignore-certificate-errors`), but that flag also disables the very TLS
  alert paths conformance cares about.
- **Shared fate with the OS resolver and proxy.** Containers give each client
  a reproducible network namespace. Browsers in the other hand inherit the host's.

What might cover the browser-shaped traffic instead:
- curl (the same nghttp2 that ships in many embeddings)
- OkHttp (the Android stack, which is a browser engine's sibling on that platform)
- the `h2spec` strict suite, which encodes the RFC requirements browsers depend on.
 
If browser coverage is ever needed, the possible route is headless Chrome driven over CDP, but this would
belong in another setup, because assertions would be
about page loads rather than the observation lines defined here.

## CI

`.github/workflows/interop.yml` runs the whole matrix on every pull request.
Client images are built in a separate step so a broken Dockerfile fails with a
clear message rather than as a matrix full of container-start failures, and so
docker's layer cache is warm before the tests start.

`ZINCIO_INTEROP_REQUIRE=1` is set in CI: without it the suite skips itself when
Docker is unreachable, which is convenient for contributors but must not hide a
broken runner.

`ZINCIO_INTEROP_CLIENTS=curl cargo test` restricts the run to named clients, which
is how the cheap lane stays separate from the expensive image builds.

## Gotcha worth knowing

The `h2` crate's `RecvStream` never replenishes its flow-control window on
its own. Its documentation is explicit that the caller must call
`flow_control().release_capacity(n)` after consuming data. A driver that
omits this stalls at exactly the advertised window (65535 bytes with the
default settings) and looks like a server-side flow-control bug, which is
very nearly what it looked like before `tests/h2_smoke.rs` existed. See
`read_response` in that file for the correct pattern.
