#![no_main]
//! Fuzz target for the QPACK encoder/decoder round trip.
//!
//! The encoder must be consistent with itself: any header list it encodes
//! with any capacity and Huffman setting must decode back to the exact same
//! name/value bytes when the encoder stream is replayed first. A mismatch,
//! a blocked section, or a decode error here is an encoder bug; a panic is
//! a memory-safety bug. The input is interpreted as a capacity, a Huffman
//! flag, and a sequence of (name length, value length, name, value)
//! records.

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use zincio_http::qpack::{Decoder, Encoder};

fuzz_target!(|data: &[u8]| {
    if data.len() < 5 {
        return;
    }
    let capacity = u64::from(u16::from_be_bytes([data[0], data[1]])) % 16385;
    let can_block = u64::from(u16::from_be_bytes([data[2], data[3]])) % 16385;
    let huffman = data[4] & 1 == 1;
    let rest = &data[5..];

    let mut headers: Vec<(Bytes, Bytes)> = Vec::new();
    let mut i = 0;
    while i + 2 <= rest.len() {
        let name_len = rest[i] as usize;
        let value_len = rest[i + 1] as usize;
        i += 2;
        if i + name_len + value_len > rest.len() {
            break;
        }
        headers.push((
            Bytes::copy_from_slice(&rest[i..i + name_len]),
            Bytes::copy_from_slice(&rest[i + name_len..i + name_len + value_len]),
        ));
        i += name_len + value_len;
    }

    let mut encoder = Encoder::with_max_blocked(capacity, can_block, huffman);
    let mut decoder = Decoder::new(capacity, 100);
    if let Some(bytes) = encoder.set_capacity(capacity) {
        decoder
            .feed_encoder_stream(&bytes)
            .expect("set-capacity accepted");
    }

    let encoded = encoder.encode_section(0, &headers);
    decoder
        .feed_encoder_stream(&encoded.encoder_stream)
        .expect("our own encoder stream must be accepted");
    let decoded = decoder
        .decode_block(&encoded.block, 1, 0)
        .expect("our own block must decode");
    let decoded = decoded.expect("our own block must not block");
    assert_eq!(decoded, headers, "round trip must preserve headers");
});
