# QPACK fixture corpus

Story-format JSON files for QPACK decoder/encoder conformance testing, similar to the HPACK corpus in `tests/fixtures/hpack/`.

## Format

Each story JSON has:

- **`description`, `source`**: provenance (where it came from)
- **`table_capacity`**: dynamic table capacity the encoder used (a decoder in tests advertises this as its max)
- **`max_blocked_streams`**: encoder's blocked-stream allowance
- **`delay_encoder_stream` (optional, `nghttp3/` sets it)**: whether tests deliver every field section before any encoder stream bytes, so dynamic references block and are unblocked as the encoder records arrive.
- **`cases`**: records in story order, one shared compression context:
  - **`seqno`**: sequence number within the story
  - **`stream_id`**: 0 for encoder stream bytes, anything else for the encoded field section of that stream (streams are opaque identifiers)
  - **`wire`**: the record as a hex string
  - **`headers` (field sections only)**: the expected decoded header list as an ordered array of `[name, value]` pairs, in wire order

Names and values are opaque bytes, and non-UTF-8 content is stored 1:1 as code points (latin-1 mapping, `\uXXXX`-escaped).

## Directories

| Directory | Source | Coverage notes |
|---|---|---|
| `nghttp3/` | nghttp3 `qpack` example tool encoding ls-qpack `test/qifs/` | real-world Facebook request/response and NetBSD header lists at 256- and 4096-octet tables, plus a long-string exercise; encoder- and section-stream records interleave, exercising blocked streams |
| `spec/` | RFC 9204 Appendix B | hand-transcribed spec examples: literal static name ref, set capacity + inserts + post-Base refs, speculative insert + duplicate + relative refs |

## Regeneration

`scripts/harvest_qpack_fixtures.sh` regenerates `nghttp3/`. Spec stories are hand-maintained from the RFC text.
