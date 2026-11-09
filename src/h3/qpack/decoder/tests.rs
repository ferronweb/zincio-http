use super::*;
use crate::h3::qpack::encoder::Encoder;

#[inline]
fn hdr(name: &str, value: &str) -> (Bytes, Bytes) {
    (
        Bytes::copy_from_slice(name.as_bytes()),
        Bytes::copy_from_slice(value.as_bytes()),
    )
}

#[inline]
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn vector_b1_static_name_ref() {
    // RFC 9204 B.1, decoded: literal field line with a static name
    // reference. The decoder advertised capacity 0, so the dynamic table
    // is unused and nothing is acknowledged.
    let mut dec = Decoder::new(0, 8);
    let headers = dec
        .decode_block(b"\x00\x00\x51\x0b/index.html", 0, 0)
        .unwrap();
    assert_eq!(headers.as_deref(), Some(&[hdr(":path", "/index.html")][..]));
    assert!(dec.take_decoder_stream().is_empty());
    assert_eq!(dec.known_received(), 0);
}

#[test]
fn chromium_style_capacity_round_trip() {
    // Chromium advertises SETTINGS_QPACK_MAX_TABLE_CAPACITY 65536 and
    // blocked streams 100; the server's encoder is then capped at the
    // peer's value (inheritcapacity 65536, Huffman on, as in production).
    let mut enc = Encoder::new(65536, true);
    let mut dec = Decoder::new(65536, 100);

    let response = [
        hdr(":status", "200"),
        hdr("content-type", "text/html"),
        hdr("x-custom-header", "hello-world"),
        hdr("x-another", "value-2"),
    ];
    let s1 = enc.encode_section(0, &response);
    // Reference-before-data: the section arrives first, blocks, then the
    // encoder stream unblocks it.
    assert!(dec.decode_block(&s1.block, 0, 0).unwrap().is_none());
    let unblocked = dec.feed_encoder_stream(&s1.encoder_stream).unwrap();
    assert_eq!(unblocked.len(), 1);
    assert_eq!(unblocked[0].headers.as_slice(), response.as_slice());

    // A second section referencing the entries from the first.
    let s2 = enc.encode_section(
        0,
        &[hdr(":status", "200"), hdr("x-custom-header", "hello-world")],
    );
    let unblocked2 = dec.feed_encoder_stream(&s2.encoder_stream).unwrap();
    assert!(unblocked2.is_empty());
    let out2 = dec.decode_block(&s2.block, 1, 0).unwrap().expect("decodes");
    assert_eq!(
        out2,
        &[hdr(":status", "200"), hdr("x-custom-header", "hello-world")][..]
    );
}

#[test]
fn vector_b2_round_trip() {
    // RFC 9204 B.2: Set Capacity 220, two inserts, then a section
    // referencing them post-Base (Required Insert Count 2, Sign 1).
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(
        &enc.insert_with_name_ref(b":authority", b"www.example.com")
            .unwrap(),
    );
    es.extend_from_slice(&enc.insert_with_name_ref(b":path", b"/sample/path").unwrap());

    let mut dec = Decoder::new(220, 8);
    assert!(dec.feed_encoder_stream(&es).unwrap().is_empty());
    // Insert Count Increment covering both entries.
    assert_eq!(hex(&dec.take_decoder_stream()), "02");
    assert_eq!(dec.known_received(), 2);

    let headers = dec.decode_block(b"\x03\x81\x10\x11", 5, 0).unwrap();
    assert_eq!(
        headers.as_deref(),
        Some(
            &[
                hdr(":authority", "www.example.com"),
                hdr(":path", "/sample/path")
            ][..]
        )
    );
    // Section Acknowledgment for stream 5.
    assert_eq!(hex(&dec.take_decoder_stream()), "85");
    assert_eq!(dec.known_received(), 2);
}

#[test]
fn vector_b4_round_trip() {
    // RFC 9204 B.4: relative index after a duplicate.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(
        &enc.insert_with_name_ref(b":authority", b"www.example.com")
            .unwrap(),
    );
    es.extend_from_slice(&enc.insert_with_name_ref(b":path", b"/sample/path").unwrap());
    es.extend_from_slice(&enc.insert_literal(b"custom-key", b"custom-value").unwrap());
    es.extend_from_slice(&enc.duplicate(2).unwrap());
    assert_eq!(
        hex(&es[..]),
        concat!(
            "3fbd01c00f7777772e6578616d706c652e636f6d",
            "c10c2f73616d706c652f706174684a637573746f6d2d6b65790c637573746f6d2d76616c756502"
        )
    );

    let mut dec = Decoder::new(220, 8);
    assert!(dec.feed_encoder_stream(&es).unwrap().is_empty());
    let headers = dec.decode_block(b"\x05\x00\x80", 1, 0).unwrap();
    assert_eq!(
        headers.as_deref(),
        Some(&[hdr(":authority", "www.example.com")][..])
    );
    // The feed queues an Insert Count Increment of 4 before the section's
    // acknowledgment (4 inserts arrived with nothing acknowledged yet).
    assert_eq!(hex(&dec.take_decoder_stream()), "0481");
}

#[test]
fn relative_ref_round_trip() {
    // Entries inserted beforehand are referenced with a relative index.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_with_name_ref(b":path", b"/sample/path").unwrap());
    let block = enc.encode_section(0, &[hdr(":path", "/sample/path")]).block;

    let mut dec = Decoder::new(220, 8);
    assert!(dec.feed_encoder_stream(&es).unwrap().is_empty());
    let headers = dec.decode_block(&block, 2, 0).unwrap();
    assert_eq!(
        headers.as_deref(),
        Some(&[hdr(":path", "/sample/path")][..])
    );
}

#[test]
fn huffman_round_trip() {
    // Huffman-encoded strings on both the encoder stream and in field
    // lines decode back to the original values.
    let mut enc = Encoder::new(220, true);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_with_name_ref(b":path", b"/sample/path").unwrap());
    let block = enc
        .encode_section(
            0,
            &[hdr(":path", "www.example.com/aaaaaaaaaaaaaaaaaaaaaaaaa")],
        )
        .block;

    let mut dec = Decoder::new(220, 8);
    assert!(dec.feed_encoder_stream(&es).unwrap().is_empty());
    let headers = dec.decode_block(&block, 2, 0).unwrap();
    assert_eq!(
        headers.as_deref(),
        Some(&[hdr(":path", "www.example.com/aaaaaaaaaaaaaaaaaaaaaaaaa")][..])
    );
}

#[test]
fn fresh_name_inserted_then_referenced() {
    // The encoder inserts a new name mid-section and references it
    // post-Base; the decoder must materialize it from the encoder stream
    // that accompanies the block.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let out = enc.encode_section(0, &[hdr("custom-key", "custom-value")]);

    let mut dec = Decoder::new(220, 8);
    assert!(dec
        .feed_encoder_stream(&out.encoder_stream)
        .unwrap()
        .is_empty());
    let headers = dec.decode_block(&out.block, 4, 0).unwrap();
    assert_eq!(
        headers.as_deref(),
        Some(&[hdr("custom-key", "custom-value")][..])
    );
    assert_eq!(hex(&dec.take_decoder_stream()), "0184");
}

#[test]
fn blocked_then_unblocked() {
    // The decoder receives a section before the encoder stream data that
    // unblocks it; the section is buffered and returned by the feed.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_literal(b"custom-key", b"custom-value").unwrap());
    let block = enc
        .encode_section(0, &[hdr("custom-key", "custom-value")])
        .block;

    let mut dec = Decoder::new(220, 8);
    assert!(dec.decode_block(&block, 7, 100).unwrap().is_none());
    assert_eq!(dec.pending_blocked(), 1);
    assert!(dec.take_decoder_stream().is_empty());

    let sections = dec.feed_encoder_stream(&es).unwrap();
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].stream_id, 7);
    assert_eq!(sections[0].headers, vec![hdr("custom-key", "custom-value")]);
    assert_eq!(dec.pending_blocked(), 0);
    // Section Acknowledgment for stream 7; the increment is subsumed by
    // the acknowledgment (Known Received Count reaches the count).
    assert_eq!(hex(&dec.take_decoder_stream()), "87");
    assert_eq!(dec.known_received(), 1);
}

#[test]
fn blocked_stream_limit() {
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_literal(b"custom-key", b"custom-value").unwrap());
    let block = enc
        .encode_section(0, &[hdr("custom-key", "custom-value")])
        .block;

    let mut dec = Decoder::new(220, 1);
    assert!(dec.decode_block(&block, 1, 0).unwrap().is_none());
    assert_eq!(
        dec.decode_block(&block, 2, 0),
        Err(QpackError::DecompressionFailed),
        "more blocked streams than SETTINGS_QPACK_BLOCKED_STREAMS"
    );
    // The encodings that were not the blocked section are still usable.
    drop(es);
}

#[test]
fn same_stream_sections_stay_ordered() {
    // A second section on a blocked stream is queued behind the first,
    // even when it could be decoded already; both are returned in order
    // by the feed.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(
        &enc.insert_with_name_ref(b":authority", b"www.example.com")
            .unwrap(),
    );
    es.extend_from_slice(&enc.insert_with_name_ref(b":path", b"/sample/path").unwrap());
    let first = enc
        .encode_section(0, &[hdr(":authority", "www.example.com")])
        .block;
    let second = enc.encode_section(0, &[hdr(":method", "GET")]).block;

    let mut dec = Decoder::new(220, 8);
    assert!(dec.decode_block(&first, 3, 0).unwrap().is_none());
    assert!(dec.decode_block(&second, 3, 0).unwrap().is_none());
    assert_eq!(dec.pending_blocked(), 2);

    let sections = dec.feed_encoder_stream(&es).unwrap();
    assert_eq!(sections.len(), 2);
    assert_eq!(
        sections[0].headers,
        vec![hdr(":authority", "www.example.com")]
    );
    assert_eq!(sections[1].headers, vec![hdr(":method", "GET")]);
    // One Section Acknowledgment (the second section has RIC 0), plus an
    // Increment: the ack raised the Known Received Count to 1, but two
    // entries were inserted.
    assert_eq!(hex(&dec.take_decoder_stream()), "8301");
}

#[test]
fn static_only_section_on_populated_table() {
    // A section with no dynamic references announces RIC 0 and decodes
    // immediately even when the decoder has received no inserts yet.
    let mut dec = Decoder::new(220, 8);
    let headers = dec.decode_block(b"\x00\x01\xd1", 0, 0).unwrap();
    assert_eq!(headers.as_deref(), Some(&[hdr(":method", "GET")][..]));
    assert!(dec.take_decoder_stream().is_empty());
}

#[test]
fn literals_with_literal_name() {
    // Literal Field Line with Literal Name, sensistive (N=1) and not.
    let mut dec = Decoder::new(0, 8);
    let headers = dec
        .decode_block(b"\x00\x00\x23foo\x03bar\x33foo\x03baz", 0, 0)
        .unwrap();
    assert_eq!(
        headers.as_deref(),
        Some(&[hdr("foo", "bar"), hdr("foo", "baz")][..])
    );
}

#[test]
fn post_base_literal_name_ref() {
    // Literal Field Line with Post-Base Name Reference (4.5.5): Base 0,
    // post-Base index 0, literal value.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_literal(b"foo", b"bar").unwrap());

    let mut dec = Decoder::new(220, 8);
    assert!(dec.feed_encoder_stream(&es).unwrap().is_empty());
    let headers = dec.decode_block(b"\x02\x80\x00\x03bar", 1, 0).unwrap();
    assert_eq!(headers.as_deref(), Some(&[hdr("foo", "bar")][..]));
}

#[test]
fn empty_section() {
    let mut dec = Decoder::new(220, 8);
    assert_eq!(dec.decode_block(b"\x00\x00", 0, 0).unwrap(), Some(vec![]));
    assert!(dec.take_decoder_stream().is_empty());
}

#[test]
fn field_section_size_capped() {
    // A field section whose decoded size alone exceeds the advertised
    // SETTINGS_MAX_FIELD_SECTION_SIZE is a decompression failure (RFC
    // 9204 Section 4.5). The cap counts the decoded names and values plus
    // the 32-byte per-field overhead of RFC 9114 Section 4.2.2, not the
    // encoded block.
    let mut dec = Decoder::new(220, 8);
    // Name "x" (1) + value of 9 octets + 32 overhead: exactly the cap.
    dec.set_max_field_section_size(42);
    assert_eq!(
        dec.decode_block(b"\x00\x00\x21x\x0ayyyyyyyyyy", 0, 0),
        Err(QpackError::DecompressionFailed)
    );
    // A section of exactly the cap decodes.
    let headers = dec.decode_block(b"\x00\x00\x21x\tyyyyyyyyy", 1, 0).unwrap();
    assert_eq!(headers.as_deref(), Some(&[hdr("x", "yyyyyyyyy")][..]));
    // Static table lines count too: content-length: 0 is 15 octets, plus
    // the 32-byte overhead.
    assert_eq!(
        dec.decode_block(b"\x00\x00\xc4", 2, 0),
        Err(QpackError::DecompressionFailed)
    );
}

#[test]
fn field_section_size_charges_the_per_field_overhead() {
    // RFC 9114 Section 4.2.2: a field list's size is the sum of its
    // fields' name and value lengths "plus an overhead of 32 bytes for
    // each field". Without the overhead, a section of many tiny fields
    // would stay "within" the limit no matter how many it carried.
    let mut dec = Decoder::new(220, 8);
    // Three one-byte-name, empty-value fields: 3 name octets, but
    // 3 * (1 + 0 + 32) = 99 octets of field list.
    dec.set_max_field_section_size(98);
    let mut block = vec![0x00, 0x00];
    for _ in 0..3 {
        block.extend_from_slice(b"\x21a\x00");
    }
    assert_eq!(
        dec.decode_block(&block, 0, 0),
        Err(QpackError::DecompressionFailed)
    );
    // Two of them fit: 2 * 33 = 66.
    let mut dec = Decoder::new(220, 8);
    dec.set_max_field_section_size(66);
    let mut block = vec![0x00, 0x00];
    for _ in 0..2 {
        block.extend_from_slice(b"\x21a\x00");
    }
    let headers = dec.decode_block(&block, 1, 0).unwrap();
    assert_eq!(headers.as_deref(), Some(&[hdr("a", ""), hdr("a", "")][..]));
}

#[test]
fn zero_length_fields_still_charge_the_budget() {
    // A field line with an empty name and an empty value carries no octets
    // of its own; the per-field overhead is what keeps a section of them
    // from bypassing the limit entirely.
    let mut dec = Decoder::new(220, 8);
    dec.set_max_field_section_size(96);
    let mut block = vec![0x00, 0x00];
    for _ in 0..4 {
        // Literal field line with literal name, name length 0, value
        // length 0.
        block.extend_from_slice(b"\x20\x00");
    }
    // 4 * 32 = 128 octets of field list: over the cap.
    assert_eq!(
        dec.decode_block(&block, 0, 0),
        Err(QpackError::DecompressionFailed)
    );
    // Three of them fit: 3 * 32 = 96.
    let mut dec = Decoder::new(220, 8);
    dec.set_max_field_section_size(96);
    let mut block = vec![0x00, 0x00];
    for _ in 0..3 {
        block.extend_from_slice(b"\x20\x00");
    }
    assert!(dec.decode_block(&block, 1, 0).unwrap().is_some());
}

#[test]
fn field_count_is_capped_even_without_a_size_limit() {
    // The number of fields a section may carry is bounded independently of
    // the field-section size limit: with the limit disabled, a section of
    // empty fields would otherwise cost nothing and hold everything.
    let mut dec = Decoder::new(220, 8);
    dec.set_max_field_section_size(usize::MAX);
    let mut block = vec![0x00, 0x00];
    for _ in 0..=MAX_FIELDS_PER_SECTION {
        // Literal field line with literal name, name length 0, value
        // length 0.
        block.extend_from_slice(b"\x20\x00");
    }
    assert_eq!(
        dec.decode_block(&block, 0, 0),
        Err(QpackError::DecompressionFailed)
    );
    // One field fewer is accepted.
    let mut dec = Decoder::new(220, 8);
    dec.set_max_field_section_size(usize::MAX);
    let mut block = vec![0x00, 0x00];
    for _ in 0..MAX_FIELDS_PER_SECTION {
        block.extend_from_slice(b"\x20\x00");
    }
    let headers = dec.decode_block(&block, 1, 0).unwrap().expect("decodes");
    assert_eq!(headers.len(), MAX_FIELDS_PER_SECTION);
}

#[test]
fn field_section_size_budget_is_per_stream() {
    // The SETTINGS_MAX_FIELD_SECTION_SIZE budget accumulates across a
    // stream's field sections (request headers and trailers), like
    // SETTINGS_MAX_HEADER_LIST_SIZE does for HTTP/2, rather than
    // capping each section on its own.
    let mut dec = Decoder::new(220, 8);
    // :method GET (10 + 32) + :authority (10 + 32): exactly the budget.
    dec.set_max_field_section_size(84);
    let headers = dec.decode_block(b"\x00\x01\xd1\xc0", 3, 0).unwrap();
    assert_eq!(
        headers.as_deref(),
        Some(&[hdr(":method", "GET"), hdr(":authority", "")][..])
    );
    // A second section on the same stream, small on its own, pushes the
    // stream over the budget.
    assert_eq!(
        dec.decode_block(b"\x00\x00\x21a\x01b", 3, 0),
        Err(QpackError::DecompressionFailed)
    );
    // Another stream starts with a fresh budget.
    let headers = dec.decode_block(b"\x00\x00\x21a\x01b", 5, 0).unwrap();
    assert_eq!(headers.as_deref(), Some(&[hdr("a", "b")][..]));
}

#[test]
fn stream_finished_releases_budget() {
    let mut dec = Decoder::new(220, 8);
    // :method GET (10 + 32): exactly the budget.
    dec.set_max_field_section_size(42);
    assert!(dec.decode_block(b"\x00\x01\xd1", 2, 0).unwrap().is_some());
    assert_eq!(
        dec.decode_block(b"\x00\x00\x21a\x01b", 2, 0),
        Err(QpackError::DecompressionFailed)
    );
    // The HTTP/3 layer reports the stream finished (peer closed its
    // send side): the budget is released.
    dec.stream_finished(2);
    assert!(dec
        .decode_block(b"\x00\x00\x21a\x01b", 2, 0)
        .unwrap()
        .is_some());
}

#[test]
fn stream_cancelled_releases_budget() {
    let mut dec = Decoder::new(220, 8);
    dec.set_max_field_section_size(42);
    assert!(dec.decode_block(b"\x00\x01\xd1", 4, 0).unwrap().is_some());
    assert_eq!(hex(&dec.stream_cancelled(4)), "44");
    // The reset stream's budget is gone; sections fit again.
    assert!(dec
        .decode_block(b"\x00\x00\x21a\x01b", 4, 0)
        .unwrap()
        .is_some());
}

#[test]
fn blocked_section_size_capped_on_unblock() {
    // The cap is enforced when the section is decoded, so a section
    // buffered as blocked is rejected by the feed once the encoder
    // stream unblocks it.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_literal(b"custom-key", b"custom-value").unwrap());
    let block = enc
        .encode_section(0, &[hdr("custom-key", "custom-value")])
        .block;

    let mut dec = Decoder::new(220, 8);
    // custom-key (10) + custom-value (12) + 32 overhead = 54.
    dec.set_max_field_section_size(53);
    // The section is buffered before its decoded size is known.
    assert!(dec.decode_block(&block, 7, 0).unwrap().is_none());
    assert_eq!(
        dec.feed_encoder_stream(&es),
        Err(QpackError::DecompressionFailed)
    );
}

#[test]
fn blocked_section_charges_the_stream_budget() {
    // A section unblocked later charges the stream's budget: it can
    // push a stream that already used part of its budget over the cap.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_literal(b"custom-key", b"custom-value").unwrap());
    let block = enc
        .encode_section(0, &[hdr("custom-key", "custom-value")])
        .block;

    let mut dec = Decoder::new(220, 8);
    // :method GET (42) on the stream, then a blocked 54-octet section:
    // 96 octets of field list in total.
    dec.set_max_field_section_size(95);
    assert!(dec.decode_block(b"\x00\x01\xd1", 7, 0).unwrap().is_some());
    assert!(dec.decode_block(&block, 7, 0).unwrap().is_none());
    // 42 + 54 > 95: the stream is over its budget once unblocked.
    assert_eq!(
        dec.feed_encoder_stream(&es),
        Err(QpackError::DecompressionFailed)
    );

    // The same 54-octet section alone fits on a fresh stream.
    let mut dec = Decoder::new(220, 8);
    dec.set_max_field_section_size(95);
    assert!(dec.decode_block(&block, 9, 0).unwrap().is_none());
    let sections = dec.feed_encoder_stream(&es).unwrap();
    assert_eq!(sections.len(), 1);
    assert_eq!(sections[0].headers, vec![hdr("custom-key", "custom-value")]);
}

#[test]
fn ric_wrap_round_trip() {
    // 15 inserts at capacity 220 wrap the 8-bit Required Insert Count
    // (2 * MaxEntries = 12): entry 15 encodes as (15 mod 12) + 1 = 4.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es: Vec<Vec<u8>> = Vec::new();
    es.push(enc.set_capacity(220).unwrap().to_vec());
    for i in 0..15 {
        es.push(
            enc.insert_literal(format!("h{i}").as_bytes(), b"v")
                .unwrap()
                .to_vec(),
        );
        // Acknowledge each insert like a peer decoder would, so later
        // inserts can turn the table over.
        enc.feed_decoder_stream(&[1]).unwrap();
    }
    let block = enc.encode_section(0, &[hdr("h14", "v")]).block;
    assert_eq!(&block[..2], &[4, 0], "enc_ric 4, Sign 0 Delta 0");

    let mut dec = Decoder::new(220, 8);
    // Chunked like the wire: the decoder acknowledges each batch, so
    // eviction inside a later batch only reaches acknowledged entries.
    for batch in es.chunks(6) {
        let mut joined = Vec::new();
        for part in batch {
            joined.extend_from_slice(part);
        }
        assert!(dec.feed_encoder_stream(&joined).unwrap().is_empty());
    }
    assert_eq!(dec.inserted(), 15);
    assert_eq!(dec.known_received(), 15);
    let headers = dec.decode_block(&block, 9, 0).unwrap();
    assert_eq!(headers.as_deref(), Some(&[hdr("h14", "v")][..]));
}

#[test]
fn increment_coalesced() {
    // Insert Count Increments cover exactly the new entries per batch.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut set = Vec::new();
    set.extend_from_slice(&enc.set_capacity(220).unwrap());
    let a = enc.insert_literal(b"a", b"a").unwrap();
    let b = enc.insert_literal(b"b", b"b").unwrap();
    let c = enc.insert_literal(b"c", b"c").unwrap();

    let mut dec = Decoder::new(220, 8);
    assert!(dec.feed_encoder_stream(&set).unwrap().is_empty());
    assert!(dec.feed_encoder_stream(&a).unwrap().is_empty());
    assert_eq!(hex(&dec.take_decoder_stream()), "01");
    let mut bc = b.to_vec();
    bc.extend_from_slice(&c);
    assert!(dec.feed_encoder_stream(&bc).unwrap().is_empty());
    assert_eq!(hex(&dec.take_decoder_stream()), "02");
    assert_eq!(dec.known_received(), 3);
}

#[test]
fn stream_cancelled_drops_blocked() {
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_literal(b"custom-key", b"custom-value").unwrap());
    let block = enc
        .encode_section(0, &[hdr("custom-key", "custom-value")])
        .block;

    let mut dec = Decoder::new(220, 8);
    assert!(dec.decode_block(&block, 9, 0).unwrap().is_none());
    assert_eq!(hex(&dec.stream_cancelled(9)), "49");
    assert_eq!(dec.pending_blocked(), 0);
    // The dropped section is gone: no headers surface from the feed.
    assert!(dec.feed_encoder_stream(&es).unwrap().is_empty());
}

#[test]
fn expire_blocked_emits_cancellations() {
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_literal(b"custom-key", b"custom-value").unwrap());
    let block = enc
        .encode_section(0, &[hdr("custom-key", "custom-value")])
        .block;

    let mut dec = Decoder::new(220, 8);
    assert!(dec.decode_block(&block, 4, 1000).unwrap().is_none());
    assert!(dec.decode_block(&block, 6, 1200).unwrap().is_none());
    // Not expired yet: age is exactly the maximum.
    assert!(dec.expire_blocked(1500, 500).is_empty());
    assert_eq!(dec.pending_blocked(), 2);
    // Stream 4 is older (age 600) and expires; stream 6 (age 400) stays.
    assert_eq!(hex(&dec.expire_blocked(1600, 500)), "44");
    assert_eq!(dec.pending_blocked(), 1);
    // Stream 6 now ages past the maximum.
    assert_eq!(hex(&dec.expire_blocked(1701, 500)), "46");
    assert_eq!(dec.pending_blocked(), 0);
    drop(es);
}

#[test]
fn eviction_into_unacknowledged_rejected() {
    // Evicting an entry with an absolute index at or above the Known
    // Received Count is an encoder stream error (RFC 9204 Section 2.1.1).
    // The encoder refuses to emit such an insert, so this feeds a
    // hostile peer's bytes directly.
    let mut dec = Decoder::new(88, 8);
    // Set Dynamic Table Capacity 88, insert (a,a) and (b,b) — the table
    // holds two 34-byte entries — then insert (c,c), which evicts the
    // never-acknowledged first entry.
    let es = [
        0x3f, 0x39, // Set Dynamic Table Capacity 88
        0x41, b'a', 0x01, b'a', // Insert with Literal Name (a,a)
        0x41, b'b', 0x01, b'b', 0x41, b'c', 0x01, b'c',
    ];
    assert_eq!(dec.feed_encoder_stream(&es), Err(QpackError::EncoderStream));
}

#[test]
fn decoder_stream_section_ack_classifies_high_stream_id() {
    // A Section Acknowledgment for stream ID 64 encodes to `0xC0`; the
    // validation parser must accept it as a Section Acknowledgment
    // (high bit set) rather than misreading it as an Insert Count
    // Increment with a forbidden zero value (RFC 9204 Section 4.4.1).
    let mut dec = Decoder::new(0, 8);
    assert!(dec.feed_decoder_stream(&[0xC0]).is_ok());
    // Stream Cancellation (0x44 = Stream ID 4) and a non-zero Insert
    // Count Increment (0x01) validate too.
    assert!(dec.feed_decoder_stream(&[0x44]).is_ok());
    assert!(dec.feed_decoder_stream(&[0x01]).is_ok());
    // A zero Insert Count Increment is rejected.
    assert_eq!(
        dec.feed_decoder_stream(&[0x00]),
        Err(QpackError::DecoderStream)
    );
}

#[test]
fn decoder_stream_batch_larger_than_one_instruction_is_accepted() {
    // A decoder-stream chunk may hold many complete instructions; the
    // validation buffer bound is per instruction, not per chunk.
    let mut dec = Decoder::new(0, 8);
    let mut batch = Vec::new();
    for stream_id in (0..=316u64).step_by(4) {
        integer::encode(&mut batch, stream_id, 7, 0x80);
    }
    assert!(batch.len() > 64, "batch is {} bytes", batch.len());
    assert!(dec.feed_decoder_stream(&batch).is_ok());
}

#[test]
fn endless_decoder_stream_continuation_is_rejected() {
    // A prefixed integer is at most 10 octets (RFC 9204 Section 4.1.1).
    let mut dec = Decoder::new(0, 8);
    let mut runaway = vec![0x3f];
    runaway.extend_from_slice(&[0x80; 10]);
    assert_eq!(
        dec.feed_decoder_stream(&runaway),
        Err(QpackError::DecoderStream)
    );
}

#[test]
fn capacity_eviction_guard() {
    // A capacity reduction in the same batch as the inserts it evicts is
    // rejected while nothing is acknowledged.
    let mut dec = Decoder::new(220, 8);
    let es = [
        0x3f, 0xbd, 0x01, // Set Dynamic Table Capacity 220
        0x41, b'a', 0x01, b'a', // Insert with Literal Name (a,a)
        0x41, b'b', 0x01, b'b', 0x3f, 0x03, // Set Dynamic Table Capacity 34
    ];
    assert_eq!(dec.feed_encoder_stream(&es), Err(QpackError::EncoderStream));

    // The same reduction is fine once the entries are acknowledged.
    let mut dec = Decoder::new(220, 8);
    let first = [
        0x3f, 0xbd, 0x01, 0x41, b'a', 0x01, b'a', 0x41, b'b', 0x01, b'b',
    ];
    assert!(dec.feed_encoder_stream(&first).unwrap().is_empty());
    assert!(dec.feed_encoder_stream(&[0x3f, 0x03]).unwrap().is_empty());
    assert_eq!(dec.dynamic.len(), 1);
    assert_eq!(
        dec.dynamic.get_absolute(1),
        Some((b"b".as_slice(), b"b".as_slice()))
    );
}

#[test]
fn capacity_above_advertised_rejected() {
    let mut dec = Decoder::new(64, 8);
    assert_eq!(
        dec.feed_encoder_stream(&[0x3f, 0x22]),
        Err(QpackError::EncoderStream),
        "Set Dynamic Table Capacity 65 exceeds the advertised maximum"
    );
}

#[test]
fn duplicate_out_of_range() {
    let mut dec = Decoder::new(220, 8);
    assert_eq!(
        dec.feed_encoder_stream(&[0x00]),
        Err(QpackError::EncoderStream)
    );
}

#[test]
fn encoder_stream_refs_evicted_entry() {
    // Insert with Name Reference to an entry evicted by a capacity
    // reduction is an encoder stream error (RFC 9204 Section 3.2.2).
    // The encoder refuses to emit such an insert, so this feeds a
    // hostile peer's bytes directly.
    let mut dec = Decoder::new(220, 8);
    // Set Dynamic Table Capacity 220, insert (a,a), (b,b), (c,c), then
    // reduce the capacity to 34 so only c survives.
    assert!(dec
        .feed_encoder_stream(&[
            0x3f, 0xbd, 0x01, 0x41, b'a', 0x01, b'a', 0x41, b'b', 0x01, b'b', 0x41, b'c', 0x01,
            b'c',
        ])
        .unwrap()
        .is_empty());
    assert!(dec.feed_encoder_stream(&[0x3f, 0x03]).unwrap().is_empty());
    assert_eq!(dec.dynamic.len(), 1);
    assert_eq!(
        dec.dynamic.get_absolute(2),
        Some((b"c".as_slice(), b"c".as_slice()))
    );
    // An Insert with Name Reference to the evicted entry (relative
    // index 1, the second-newest at insert time) is rejected.
    let mut ref_instr = Vec::new();
    integer::encode(&mut ref_instr, 1, 6, INSERT_WITH_NAME_REF);
    ref_instr.push(1);
    ref_instr.push(b'v');
    assert_eq!(
        dec.feed_encoder_stream(&ref_instr),
        Err(QpackError::EncoderStream)
    );
}

#[test]
fn static_index_out_of_range() {
    let mut dec = Decoder::new(0, 8);
    // Indexed Field Line, static table, index 99: 0xff is the 6-bit
    // prefix in "all ones" form, followed by the continuation 36.
    assert_eq!(
        dec.decode_block(b"\x00\x00\xff\x24", 0, 0),
        Err(QpackError::DecompressionFailed)
    );
}

#[test]
fn relative_index_out_of_range() {
    // Base is 0, so no dynamic relative index is valid.
    let mut dec = Decoder::new(220, 8);
    assert_eq!(
        dec.decode_block(b"\x00\x00\x80", 0, 0),
        Err(QpackError::DecompressionFailed)
    );
}

#[test]
fn post_base_beyond_table() {
    // One insert received, but the section references post-Base index 5.
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_literal(b"a", b"a").unwrap());
    let mut dec = Decoder::new(220, 8);
    assert!(dec.feed_encoder_stream(&es).unwrap().is_empty());
    assert_eq!(
        dec.decode_block(b"\x02\x80\x15", 0, 0),
        Err(QpackError::DecompressionFailed)
    );
}

#[test]
fn ric_mismatch_rejected() {
    // Announce a Required Insert Count of 2 for a section that references
    // only one entry (RFC 9204 Section 2.1.2: RIC is one larger than the
    // largest referenced absolute index).
    let mut enc = crate::h3::qpack::encoder::Encoder::new(220, false);
    let mut es = Vec::new();
    es.extend_from_slice(&enc.set_capacity(220).unwrap());
    es.extend_from_slice(&enc.insert_literal(b"a", b"a").unwrap());
    es.extend_from_slice(&enc.insert_literal(b"b", b"b").unwrap());
    let mut dec = Decoder::new(220, 8);
    assert!(dec.feed_encoder_stream(&es).unwrap().is_empty());
    assert_eq!(
        dec.decode_block(b"\x03\x00\x81", 0, 0),
        Err(QpackError::DecompressionFailed)
    );
    // And the reverse: RIC 0 announced for a section that references the
    // newly inserted entry.
    assert_eq!(
        dec.decode_block(b"\x00\x01\x80", 0, 0),
        Err(QpackError::DecompressionFailed)
    );
}

#[test]
fn truncated_inputs_do_not_panic() {
    // A string literal that promises more bytes than the chunk holds:
    // with streaming parsing the truncated chunk is buffered (a chunk
    // boundary is not a stream error), not an immediate error. It must
    // not panic.
    let mut dec = Decoder::new(220, 8);
    assert!(dec.feed_encoder_stream(b"\x4aab").is_ok());

    // A complete instruction that references a missing dynamic entry still
    // errors once fully received (Insert with Name Reference, dynamic
    // relative index 0, against an empty table — RFC 9204 4.3.2).
    let mut dec2 = Decoder::new(220, 8);
    assert_eq!(
        dec2.feed_encoder_stream(b"\x80\x01a"),
        Err(QpackError::EncoderStream)
    );

    // decode_block truncated inputs still error as before.
    let mut dec3 = Decoder::new(220, 8);
    assert_eq!(
        dec3.decode_block(b"\x00\x00\x51\x0aabc", 0, 0),
        Err(QpackError::DecompressionFailed)
    );
    // A section that ends mid-field-line.
    assert_eq!(
        dec3.decode_block(b"\x00\x00\x80", 0, 0),
        Err(QpackError::DecompressionFailed)
    );
    // A half a prefix.
    assert_eq!(
        dec3.decode_block(b"\x00", 0, 0),
        Err(QpackError::DecompressionFailed)
    );
    // Base underflow: Sign 1 with a delta larger than the insert count.
    assert_eq!(
        dec3.decode_block(b"\x02\xff\x00", 0, 0),
        Err(QpackError::DecompressionFailed)
    );
}

#[test]
fn multi_section_round_trip() {
    // Two sections referencing entries inserted by the first, with a
    // static-only section in between.
    let mut enc = Encoder::new(300, false);
    let first = enc.encode_section(
        0,
        &[
            hdr("custom-key", "custom-value"),
            hdr("x-more", "0123456789"),
        ],
    );
    let second = enc.encode_section(0, &[hdr("custom-key", "custom-value")]);
    let third = enc.encode_section(0, &[hdr(":method", "GET")]);

    let mut dec = Decoder::new(300, 8);
    assert!(dec
        .feed_encoder_stream(&first.encoder_stream)
        .unwrap()
        .is_empty());
    let headers = dec.decode_block(&first.block, 1, 0).unwrap();
    assert_eq!(
        headers.as_deref(),
        Some(
            &[
                hdr("custom-key", "custom-value"),
                hdr("x-more", "0123456789")
            ][..]
        )
    );
    assert!(dec
        .feed_encoder_stream(&second.encoder_stream)
        .unwrap()
        .is_empty());
    assert_eq!(
        dec.decode_block(&second.block, 1, 0).unwrap().as_deref(),
        Some(&[hdr("custom-key", "custom-value")][..])
    );
    assert_eq!(
        dec.decode_block(&third.block, 1, 0).unwrap().as_deref(),
        Some(&[hdr(":method", "GET")][..])
    );
    // First section acked: stream 1; second too. The increment merged
    // into the first acknowledgment... plus the second.
    assert_eq!(dec.known_received(), 2);
}

#[test]
fn split_encoder_stream_chunk_repro() {
    use crate::h3::qpack::encoder::Encoder;
    // An Insert With Literal Name whose name length needs a continuation
    // byte (name >= 32 octets) produces a multi-byte instruction. With
    // Huffman on (the production setting) the name-length prefix also
    // carries the Huffman flag at bit 5, so the length must be measured
    // with the flag bit excluded. QUIC `poll_recv` can deliver the
    // instruction split across chunks; the first chunk must be buffered,
    // not treated as a stream error, and the completed insert must land.
    let mut enc = Encoder::new(4096, true);
    // The encoder broadcasts its table capacity on the encoder stream
    // before any insert (RFC 9204 4.3.1). Capture that instruction.
    let cap = enc.set_capacity(4096).unwrap();
    let name = vec![b'x'; 40];
    let instruction = enc.insert_literal(&name, b"v").unwrap();
    assert!(instruction.len() >= 2, "instruction must be multi-byte");

    let mut dec = Decoder::new(4096, 8);
    assert!(dec.feed_encoder_stream(&cap).is_ok());
    // First byte only — must be tolerated (buffered), not a connection
    // error.
    assert!(
        dec.feed_encoder_stream(&instruction[..1]).is_ok(),
        "partial instruction must not raise QPACK_ENCODER_STREAM_ERROR"
    );
    // Remaining bytes complete the instruction and the entry is materialized.
    assert!(dec.feed_encoder_stream(&instruction[1..]).is_ok());
    assert_eq!(dec.inserted(), 1, "split insert must be materialized");
}
