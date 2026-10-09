# Limitations: what the interop matrix does not cover

This document lists what is **not** covered, so that a green matrix is never
mistaken for a complete one. Each entry says whether the gap is a missing
scenario (nothing drives it), a missing client capability (a scenario exists
but no client can run it over some protocol), or a deliberate scope exclusion.

## 1. Empty matrix cells (scenario exists, zero runners)

| Cell | Why empty | What would close it |
| --- | --- | --- |
| `trailers` over H1 | No H1 client declares `RequestTrailers` + `ResponseTrailers`. curl cannot surface trailers at all; Go could read chunked response trailers via `resp.Trailer` and send request trailers via the `Trailer` map, but the driver does neither. | Teach the Go driver trailer I/O? |
| `trailers` over H2 | Same gate: every H2 client lacks `RequestTrailers`. hyper-h2, Go, and OkHttp can all observe response trailers, but none of the drivers sends request trailers (Node cannot at all, because no `addTrailers` on client streams; curl has no such option). | Teach the hyper-h2 or Go driver to send trailing HEADERS? |

Note the asymmetry this reveals: response-trailer observation is covered on
every protocol (H1: none yet, see above; H2: hyper-h2, OkHttp, Node observe
them but the scenario is gated on sending too; H3: aioquic, quic-go run the
full scenario). Request-trailer sending is the uncovered half everywhere
except H3.

## 2. Thin cells (exactly one runner)

A single runner means no cross-implementation check, the precise failure
mode this suite exists to catch.

| Cell | Only runner | Note |
| --- | --- | --- |
| `early_hints` over H1 | Go (httptrace) | H1 103 has no other observer. |
| `early_hints` over H2 | Go (httptrace) | hyper-h2 also observes 103 but the scenario is not wired to run it there yet. |
| `abort_midstream`, `idle_reuse` over H1 | curl | One request per invocation; connection reuse is not really exercised. |

## 3. Behaviors with no scenario at all

### HTTP/1.x

- **HTTP/1.0 semantics.** Missing-`Host` acceptance, keep-alive-off by
  default, no-chunked responses. In-process tests use HTTP/1.0 request lines
  but assert none of the version-specific semantics; no container scenario
  exists. (A `http09-request` fuzz seed exists, but nothing drives it.)
- **Pipelining through a container.** `tests/h1.rs::test_http_pipelining`
  covers two pipelined requests in-process (strengthened to assert FIFO
  order), but no third-party client pipelines against the server.
- **Chunked request bodies through a container.** All matrix uploads use
  `Content-Length`. The chunked decoder (home of the 0.3.2 DoS fixes) is
  covered only by `tests/h1.rs` and the fuzz target.
- **Upgrade / WebSocket through a container.** `prepare_upgrade` is tested
  in-process against an `Upgrade: echo` stub, but never upgraded to h2c nor
  driven by a real client.
- **Timeouts.** `header_read_timeout` is exercised only by the `slowloris`
  test. No scenario asserts a slow-but-legitimate upload survives, or that a
  legitimate idle keep-alive connection is not reaped.
- **Connection-close semantics.** `Connection: close` echo behavior and
  half-close handling have no container coverage.

### HTTP/2

- **H2 over TLS.** The matrix serves H2 exclusively as h2c (prior knowledge).
  There is no TLS listener, so ALPN negotiation, ALPN mismatch, and every
  TLS-only client behavior are untested. (This is also what keeps OkHttp on
  `H2_PRIOR_KNOWLEDGE` rather than its default path.)
- **Server push.** The server has no push API by design. Push appears only as
  rejection paths (`PUSH_PROMISE` on wrong streams, `MAX_PUSH_ID` ordering).
  No end-to-end push scenario can exist until the API does.
- **Extended CONNECT.** Unit-tested (`stream/tests.rs`), but no interop scenario
  drives `CONNECT` with `:protocol` against the server.
- **h2c upgrade from HTTP/1.** The CHANGELOG for `zincio-http` 0.2.1
  notes upgrade-correctness work, no test performs an `Upgrade: h2c` handshake,
  and it's deprecated in RFC 9113 anyway.
- **Graceful shutdown / GOAWAY through a client.** GOAWAY is covered for H3
  in the main repo, but no matrix scenario observes an H2 GOAWAY.
- **Adversarial frames.** Invalid HPACK, CONTINUATION floods, rapid reset, and
  flow-control violations are covered by unit tests, `h2spec --strict`, and
  fuzzing, but never by a container client speaking the attack.
- **Non-default settings.** `Http2Options` is never customized in any
  integration test; all thirteen tunables run at defaults against real clients.

### HTTP/3

- **0-RTT / session resumption.** No scenario performs a second handshake,
  resumes a session, or sends early data. h3spec self-skips its 0-RTT case
  for the same reason (no session establishment in the harness).
- **Extended CONNECT through a container.** Covered in-repo by
  `fixture_client_connect`; the matrix has no CONNECT scenario on any
  protocol.
- **GOAWAY through a container.** Covered in-repo by
  `h3_client_goaway_graceful_shutdown`; the matrix never observes one.
- **QPACK pressure.** Dynamic-table blocking, eviction under load, and
  blocked-section handling are covered in-repo (fixture tests, tiny-window
  variants); no matrix scenario stresses the encoder/decoder beyond the
  200-header and 8 KiB cases.
- **Connection migration.** Nothing migrates a QUIC connection between paths.
  This exercises quinn more than the H3 layer and is out of scope (see §5).

### Cross-protocol

- **TLS variations.** Every TLS test in both repos uses one self-signed RSA
  certificate with verification skipped. Untested: client certificates
  (mTLS), cipher-suite constraints, TLS version fallback, SNI-based routing,
  verification failure, post-handshake messages. The one exception is h3spec,
  which covers TLS alerts, minus the skipped `missing_extension` case that
  quinn cannot emit.
- **Small flow-control windows through a container.** In-repo H3 tests shrink
  the QUIC window to 16 KiB; the matrix always runs defaults. A client that
  advertises a tiny `INITIAL_WINDOW_SIZE` would exercise a different (and
  historically buggy, see 0.4.8) server path.
- **Malformed traffic through a container.** Only `big_header_rejected`
  exists. Invalid HPACK/QPACK, bad pseudo-headers, and oversized frames over
  the wire are covered in-repo and by h2spec/h3spec, never by matrix clients.
  Over HTTP/3 the refusal is connection-scoped: the oversized section fails
  QPACK decoding against the server's field-section budget, so the server
  closes the connection with `QPACK_DECOMPRESSION_FAILED` (0x200). Every H3
  client therefore observes a transport failure (reset stream, empty stream,
  or closed connection) rather than a 4xx status; all three verify as a
  conforming refusal.
- **IPv6.** Everything binds and dials IPv4 loopback. Dual-stack and
  IPv6-only paths are untested.
- **Proxies.** The server has no proxy support; nothing to cover.

## 4. Capabilities no client implements

From the capability-gating report (a capability with zero implementers is
printed, not failed, so the list stays visible):

- Currently none (every declared `Capability` has at least one implementer).

If a new capability is added without a client, it appears here by
construction. (The closest cases are `RequestTrailers` on H1/H2 and
`EarlyHints`/`ExpectContinue` on H3-for-aioquic, which are per-protocol gaps
documented in sections 1. and 2., not global ones.)

## 5. Deliberate exclusions (not planned)

- **Packet-level network impairment** (latency, loss, reordering, bandwidth
  caps via `tc`/`netem`). Loss recovery and congestion control belong to
  quinn (H3) and the kernel (H1/H2), both tested by their own suites. What
  this crate owns (backpressure, flow-control accounting, idle timeouts)
  is modeled directly instead: shrunken QUIC windows in-repo, trickled
  bodies (`/slow`), and idle-then-reuse scenarios. Simulating packets would
  test someone else's code while adding root privileges and flakiness here.
- **Web browsers.** Documented in `README.md#why-no-web-browsers`: bespoke
  per-browser stacks, no frame-level control, no scriptable trust anchors.
- **Fuzzing.** Covered separately by `fuzz/` (7 targets) on a nightly cron,
  not by the matrix. The corpora intentionally overlap at the seams
  (`H2_DUMP_SEEDS` feeds recorded sessions into `fuzz/seeds/http2/`).

## 6. How to read a green run

A green matrix run means: for every covered cell, at least one independent
client observed the specified status, body length, and body digest.

This does not mean the behaviors in sections 1.-4. were checked. When adding a client,
extend this file's tables; when adding a scenario, check every protocol
column.

The `can_run` gating logic (`interop/src/client.rs`) is the
machine-readable version of sections 1.-2., this document is its human-readable
shadow. If they disagree, the code is right and this file is stale (fix the
file).
