# `zincio-http` change log

## `zincio-http` 0.4.7

**Released in September 11, 2026**

- Performed several optimizations for lower HTTP/2 memory usage and improved performance.

## `zincio-http` 0.4.6

**Released in September 7, 2026**

- Fixed HTTP/1.x requests being rejected with `400 Bad Request` after multiple requests in one connection.

## `zincio-http` 0.4.5

**Released in September 4, 2026**

- Fixed HTTP/2 errors while responses with empty body are sent.

## `zincio-http` 0.4.4

**Released in September 3, 2026**

- Fixed HTTP/1.1 buffering instead of streaming response bodies ([GitHub issue](https://github.com/ferronweb/ferron/issues/899))
- Fixed HTTP/2 buffering instead of streaming response bodies ([GitHub issue](https://github.com/ferronweb/ferron/issues/899))

## `zincio-http` 0.4.3

**Released in August 26, 2026**

- Disabled default `quinn` Cargo features when using HTTP/3.

## `zincio-http` 0.4.2

**Released in August 23, 2026**

- Fixed custom server max frame size setting incorrectly applied into peer defaults (causing frame size mismatch errors for HTTP/2 clients using libnghttp2).
- Fixed `curl: (18) HTTP/3 stream 0 reset by server (error 0x0 unknown)` on `curl` for HTTP/3. ([GitHub issue](https://github.com/ferronweb/ferron/issues/887))
- Optimized HPACK (HTTP/2) and QPACK (HTTP/3) implementations for large dynamic tables (for example for variable headers).
- Optimized Huffman decoding logic (using 8-bit lookup table instead of 4-bit, reducing memory lookups from 2 per byte to just 1 per byte).
- Per-stream client's `WINDOW_UPDATE` frame now drains pending data for one stream instead of all streams.
- Performed several HTTP/3 server logic performance optimizations
- Reduced memory allocations across HTTP/2 and HTTP/3.
- Renamed the project from `vibeio-http` to `zincio-http`.
- Improved HTTP/2 flow-control fairness: added deficit round-robin (DRR) for connection-level `WINDOW_UPDATE` to prevent a single large response from hogging the connection window; changed `complete_blocks` from a simple `Vec` to `VecDeque` for FIFO processing of pipelined `HEADERS` frames.

## `vibeio-http` 0.4.1

**Released in August 16, 2026**

- Improved handling of empty body frame edge cases.
- Mitigated CONTINUATION flood vulnerability in HTTP/2.
- Mitigated Rapid Reset and MadeYouReset vulnerabilities in HTTP/2 and HTTP/3.

## `vibeio-http` 0.4.0

**Released in August 15, 2026**

- Replaced the HTTP/2 protocol implementation (that used `h2` crate) with an in-house one.
- Replaced the experimental HTTP/3 protcol implementation (that used `h3` crate) with an in-house one.

## `vibeio-http` 0.3.5

**Released in August 6, 2026**

- Added support for zerocopy file serving on FreeBSD.
- Reduced spurious errors when HTTP/1.x and HTTP/2 are abruptly closed while idle (accepting or upgraded)

## `vibeio-http` 0.3.4

**Released in June 26, 2026**

- Reduced spurious timeouts when kept-alive HTTP/1.x connection is idle

## `vibeio-http` 0.3.3

**Released in June 14, 2026**

- Improved `Expect: 100-continue` handling

## `vibeio-http` 0.3.2

**Released in June 6, 2026**

- Fixed chunk length parsing range in HTTP/1.x decoder
- Fixed DoS vulnerability in HTTP/1.x chunked encoding parser (triggered by maliciously crafted chunk lengths)
- Fixed off-by-one error in HTTP/1.x trailer header check
- The HTTP/1.x server logic now properly handles write-zero error when writing to the socket instead of infinitely looping

## `vibeio-http` 0.3.1

**Released in April 22, 2026**

- Improved graceful shutdown for HTTP/1.x

## `vibeio-http` 0.3.0

**Released in March 26, 2026**

- Performed some performance optimizations for HTTP/2

## `vibeio-http` 0.2.1

**Released in March 21, 2026**

- Improve HTTP/2 upgrade correctness

## `vibeio-http` 0.2.0

**Released in March 21, 2026**

- Added support for extended CONNECT for HTTP/2 and HTTP/3
- Performed some performance optimizations for HTTP/2

## `vibeio-http` 0.1.2

**Released in March 20, 2026**

- Added an option to disable sending `Date` header for HTTP/2 and HTTP/3
- The default maximum concurrent streams limit for HTTP/2 is now 200
- Fixed TE header being always removed for HTTP/2 and HTTP/3

## `vibeio-http` 0.1.1

**Released in March 19, 2026**

- Performed some performance optimizations for HTTP/1.x and HTTP/2

## `vibeio-http` 0.1.0

**Released in March 19, 2026**

- First release
