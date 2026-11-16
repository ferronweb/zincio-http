# HPACK fixture corpus

Story-format JSON files, used for testing the HPACK decoder and encoder conformance.

## Format

Each `story_XX.json` contains a `cases` array. All cases in a story share one compression context (dynamic table state carries across cases in order).

Each case has:

- **`seqno`**: sequence number within the story
- **`wire`**: the encoded header block as a hex string
- **`headers`**: the decoded header list as an ordered array of single-key objects (pseudo-headers and regular headers, in wire order)
- **`header_table_size`** (optional): `SETTINGS_HEADER_TABLE_SIZE` value to apply before this case

## Source

The corpus was sourced from `http2jp/hpack-test-case` (formerly `nghttp2/hpack-test-case`):

- **URL**: https://github.com/http2jp/hpack-test-case
- **Commit**: `8a1406e7d14bfcb6c046021f13cc15cfb162726d` (2019-06-01)
- **License**: MIT (see `LICENSE` in the source repository).

All files are exact copies from the source repository. The `wire` values were produced by each encoder implementation listed below. `raw-data/` in the source repo contains the unencoded stories.

## Directories

| Directory | Encoder that produced `wire` | Coverage notes |
|---|---|---|
| `nghttp2/` | nghttp2 `deflatehd` (default 4096-octet table) | full story set incl. large-value stories |
| `nghttp2-16384-4096/` | nghttp2 with 16384-octet table | dynamic-table growth across a session |
| `nghttp2-change-table-size/` | nghttp2 with explicit size changes | `SETTINGS_HEADER_TABLE_SIZE` mid-session updates |
| `go-hpack/` | Go `x/net/http2/hpack` encoder | Go implementation output (huffman-heavy) |
| `python-hpack/` | python-hyper/hpack encoder | third independent implementation |

## Trimming

Large-value stories (`story_21/22/27/29/30.json`) are retained only in `nghttp2/` to bound repository size. `nghttp2-16384-4096/` and `nghttp2-change-table-size/` (also produced by nghttp2) do not contain `story_31.json` upstream.
