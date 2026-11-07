use super::*;

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
fn decoder_stream_section_ack_classifies_high_stream_id() {
    // A Section Acknowledgment for stream ID 64 encodes to `0xC0`
    // (top bit set, 0x40 bit also set by the 7-bit Stream ID). The
    // instruction is identified by the high bit alone; misclassifying
    // it as an Insert Count Increment (which rejects a zero value)
    // was a latent bug that only surfaced for stream IDs at or above
    // 64 (RFC 9204 Section 4.4.1).
    let mut enc = Encoder::new(256, false);
    enc.encode_section(64, &[hdr("a", "b")]);
    assert!(enc.pending_refs.iter().any(|(id, _)| *id == 64));
    // 0xC0: Section Acknowledgment, Stream ID 64.
    assert!(enc.feed_decoder_stream(&[0xC0]).is_ok());
    assert!(!enc.pending_refs.iter().any(|(id, _)| *id == 64));

    // Stream Cancellation for a low stream ID (0x44 = Stream ID 4)
    // frees its pending reference.
    enc.encode_section(4, &[hdr("a", "b")]);
    assert!(enc.pending_refs.iter().any(|(id, _)| *id == 4));
    assert!(enc.feed_decoder_stream(&[0x44]).is_ok());
    assert!(!enc.pending_refs.iter().any(|(id, _)| *id == 4));

    // Insert Count Increment (0x01 = increment 1) is accepted once the
    // encoder has inserted at least one entry.
    let inserted = enc.dynamic.inserted();
    assert!(inserted >= 1);
    assert!(enc.feed_decoder_stream(&[0x01]).is_ok());
    assert_eq!(enc.known_received, 1);
}

#[test]
fn stray_decoder_stream_instructions_are_benign() {
    // A conformant peer may send a Section Acknowledgment or Stream
    // Cancellation for a field section the encoder has already freed
    // (or never outstanding). RFC 9204 Section 4.4 defines no error for
    // these; treating them as QPACK_DECODER_STREAM_ERROR closed the
    // connection and dropped in-flight requests (the bug this guards).
    let mut enc = Encoder::new(256, false);

    // Section Acknowledgment for a stream with no pending reference.
    assert!(enc.feed_decoder_stream(&[0xC0]).is_ok());
    // Stream Cancellation for a stream with no pending reference.
    assert!(enc.feed_decoder_stream(&[0x44]).is_ok());

    // A duplicate Section Acknowledgment after the only pending
    // reference was already freed is likewise benign.
    enc.encode_section(4, &[hdr("a", "b")]);
    assert!(enc.feed_decoder_stream(&[0x44]).is_ok());
    assert!(enc.feed_decoder_stream(&[0x44]).is_ok());
}

#[test]
fn vector_b1_static_name_ref() {
    // RFC 9204 B.1: literal field line with a static name reference. The
    // decoder advertises capacity 0, so the dynamic table is unused.
    let mut enc = Encoder::new(0, false);
    let out = enc.encode_section(0, &[hdr(":path", "/index.html")]);
    assert_eq!(hex(&out.block), "0000510b2f696e6465782e68746d6c");
    assert!(out.encoder_stream.is_empty());
}

#[test]
fn vector_b2_dynamic_post_base() {
    // RFC 9204 B.2: Set Capacity 220, two inserts with static name
    // references, then a field section referencing them post-Base
    // (Required Insert Count = 2, Sign = 1, Delta Base = 1).
    let mut enc = Encoder::new(220, false);
    assert_eq!(hex(&enc.set_capacity(220).unwrap()), "3fbd01");
    let authority = enc
        .insert_with_name_ref(b":authority", b"www.example.com")
        .unwrap();
    assert_eq!(hex(&authority), "c00f7777772e6578616d706c652e636f6d");
    let path = enc.insert_with_name_ref(b":path", b"/sample/path").unwrap();
    assert_eq!(hex(&path), "c10c2f73616d706c652f70617468");

    // Vector path: Base fixed at 0 (the acknowledged count), so the two
    // entries are referenced post-Base.
    let block = enc.encode_section_with_base(
        0,
        &[
            hdr(":authority", "www.example.com"),
            hdr(":path", "/sample/path"),
        ],
        0,
    );
    assert_eq!(hex(&block.block), "03811011");
}

#[test]
fn vector_b3_insert_literal_name() {
    // RFC 9204 B.3: Insert with Literal Name (custom-key/custom-value).
    let mut enc = Encoder::new(220, false);
    enc.set_capacity(220);
    let ins = enc.insert_literal(b"custom-key", b"custom-value").unwrap();
    assert_eq!(
        hex(&ins),
        "4a637573746f6d2d6b65790c637573746f6d2d76616c7565"
    );
    assert_eq!(enc.dynamic.len(), 1);
    assert_eq!(
        enc.dynamic.get_absolute(0),
        Some((b"custom-key".as_slice(), b"custom-value".as_slice()))
    );
}

#[test]
fn vector_b4_duplicate_and_relative() {
    // RFC 9204 B.4: duplicate entry 2, then an indexed field line
    // relative to Base 4 (Required Insert Count = 4, Sign = 0, Delta
    // Base = 0).
    let mut enc = Encoder::new(220, false);
    enc.set_capacity(220);
    enc.insert_with_name_ref(b":authority", b"www.example.com");
    enc.insert_with_name_ref(b":path", b"/sample/path");
    enc.insert_literal(b"custom-key", b"custom-value");
    assert_eq!(hex(&enc.duplicate(2).unwrap()), "02");
    assert_eq!(enc.dynamic.len(), 4);

    let block = enc.encode_section_with_base(0, &[hdr(":authority", "www.example.com")], 4);
    assert_eq!(hex(&block.block), "050080");
}

#[test]
fn fresh_name_inserted_then_referenced() {
    // A name that matches nothing is inserted with a literal name
    // instruction, then the section references it post-Base.
    let mut enc = Encoder::new(220, false);
    let out = enc.encode_section(0, &[hdr("custom-key", "custom-value")]);
    assert_eq!(
        hex(&out.encoder_stream),
        "3fbd014a637573746f6d2d6b65790c637573746f6d2d76616c7565"
    );
    // Required Insert Count = 1 -> (1 mod 12) + 1 = 2; Base = 0 < Ric ->
    // Sign = 1, Delta = Ric - Base - 1 = 0; post-Base index 0.
    assert_eq!(hex(&out.block), "028010");
    assert_eq!(enc.dynamic.len(), 1);
}

#[test]
fn indexed_static_full_match() {
    let mut enc = Encoder::new(0, false);
    let out = enc.encode_section(0, &[hdr(":method", "GET")]);
    let idx = static_table::find(b":method", b"GET").unwrap() as u8;
    assert_eq!(hex(&out.block), format!("0000{:02x}", 0xc0 | idx));
}

#[test]
fn relative_ref_from_fixed_base() {
    // Entries inserted beforehand are referenced relative to Base = the
    // insert count; nothing new is inserted, so Sign = 0, Delta = 0.
    let mut enc = Encoder::new(220, false);
    enc.set_capacity(220);
    enc.insert_with_name_ref(b":authority", b"www.example.com");
    enc.insert_with_name_ref(b":path", b"/sample/path");
    let out = enc.encode_section(0, &[hdr(":path", "/sample/path")]);
    // Required Insert Count = 2 -> (2 mod 12) + 1 = 3; relative index of
    // absolute 1 from Base 2 is 0.
    assert_eq!(hex(&out.block), "030080");
    assert!(out.encoder_stream.is_empty());
}

/// The production encoder must reference dynamic entries against the
/// decoder's *acknowledged* insert count, not its own (which runs ahead
/// while a client is busy consuming a large response). An unacknowledged
/// entry must be referenced with a Post-Base index (RFC 9204 2.1.2); a
/// relative index above the peer's Largest Reference is a decompression
/// failure that a strict client (Neqo/Firefox) turns into a connection
/// close — which is the reported "concurrent requests ignored while a big
/// download streams" hang.
#[test]
fn ack_base_uses_post_base_for_unacknowledged_entry() {
    let mut enc = Encoder::new(220, false);
    enc.set_capacity(220);
    // Insert two entries but never feed the client's decoder stream, so the
    // encoder's known_received stays 0 (nothing acknowledged yet).
    enc.insert_with_name_ref(b":authority", b"www.example.com");
    enc.insert_with_name_ref(b":path", b"/sample/path");

    // A novel header forces a fresh insert (abs 3) that, with base =
    // known_received = 0, can only be referenced post-Base.
    let section = enc.encode_section_with_ack_base(0, &[hdr("x-novel", "value")]);
    // The single dynamic field line is the only instruction after the
    // 2-byte prefix; a Post-Base Indexed Field Line occupies 0x10..=0x1F.
    let body = &section.block[2..];
    assert_eq!(body.len(), 1, "exactly one field line");
    assert_eq!(
        body[0] & 0xF0,
        0x10,
        "unacknowledged entry must be referenced post-Base, not with a relative index"
    );
    assert!(
        !section.encoder_stream.is_empty(),
        "the newly inserted entry must travel on the encoder stream"
    );
}

#[test]
fn ack_base_uses_relative_for_acknowledged_entry() {
    let mut enc = Encoder::new(220, false);
    enc.set_capacity(220);
    enc.insert_with_name_ref(b":authority", b"www.example.com");
    enc.insert_with_name_ref(b":path", b"/sample/path");
    enc.insert_with_name_ref(b"x-foo", b"bar");
    // Client acknowledges the first two inserts (Insert Count Increment 2),
    // raising known_received to 2. Entry `:authority` (abs 1) is now below
    // the Base, so it may be referenced with a relative index.
    enc.feed_decoder_stream(&[0x02]).unwrap();

    let section = enc.encode_section_with_ack_base(0, &[hdr(":authority", "www.example.com")]);
    let body = &section.block[2..];
    assert_eq!(body.len(), 1, "exactly one field line");
    // A relative Indexed Field Line for the dynamic table occupies 0x80..=0xBF.
    assert_eq!(
        body[0] & 0xC0,
        0x80,
        "acknowledged entry must be referenced with a relative index"
    );
    assert!(
        section.encoder_stream.is_empty(),
        "no new insert needed for an already-present entry"
    );
}

#[test]
fn huffman_used_when_shorter() {
    let mut enc = Encoder::new(0, true);
    let out = enc.encode_section(
        0,
        &[hdr(":path", "www.example.com/aaaaaaaaaaaaaaaaaaaaaaaaa")],
    );
    let block = out.block.as_ref();
    assert_eq!(&block[..2], &[0x00, 0x00]);
    // Literal with Name Reference, static :path (0x51).
    assert_eq!(block[2], 0x51);
    // The value length octet has the H bit set and encodes fewer bytes.
    assert_ne!(block[3] & 0x80, 0);
    assert!(block[3] & 0x7f < 42);
    // The block must decode back to the original value.
    let mut dec = Vec::new();
    huffman::decode(&block[4..], &mut dec).unwrap();
    assert_eq!(dec, b"www.example.com/aaaaaaaaaaaaaaaaaaaaaaaaa");
}

#[test]
fn sensitive_never_indexed() {
    let mut enc = Encoder::new(220, false);
    let out = enc.encode_section(0, &[hdr("authorization", "Bearer xyz")]);
    // No encoder stream instruction: the field is never stored.
    assert!(out.encoder_stream.is_empty());
    // Literal with Literal Name, N=1: the N bit (0x10) is set.
    assert_ne!(out.block.as_ref()[2] & 0x10, 0);
    assert_eq!(enc.dynamic.len(), 0);
}

#[test]
fn insert_skipped_when_it_would_evict_referenced_entry() {
    // A 100-byte table holds exactly one 43-byte entry. The section
    // references it, and the second field (71 bytes) does not fit
    // without evicting it, so the insert is skipped and the field is
    // sent as a literal name.
    let mut enc = Encoder::new(100, false);
    enc.set_capacity(100);
    enc.insert_with_name_ref(b":authority", b"www.example.com");
    let out = enc.encode_section(
        0,
        &[
            hdr(":authority", "www.example.com"),
            hdr("x-custom", "0123456789012345678901234567890123456789"),
        ],
    );
    let block = out.block.as_ref();
    // First field line: Indexed, dynamic, relative index 0 (0x80).
    assert_eq!(block[2], 0x80);
    // Second field line: literal with literal name (starts `001`).
    assert_eq!(block[3] & 0xe0, 0x20);
    // No Insert with Literal Name instruction was queued.
    assert!(out.encoder_stream.is_empty());
    assert_eq!(enc.dynamic.len(), 1);
}

#[test]
fn no_duplicate_set_capacity_instruction() {
    let mut enc = Encoder::new(220, false);
    enc.set_capacity(220);
    let out = enc.encode_section(0, &[hdr(":path", "/sample/path")]);
    assert!(out.encoder_stream.is_empty());
}

#[test]
fn empty_section() {
    let mut enc = Encoder::new(220, false);
    let out = enc.encode_section(0, &[]);
    // Prefix only: Required Insert Count 0, Sign 0, Delta Base 0.
    assert_eq!(hex(&out.block), "0000");
    assert!(out.encoder_stream.is_empty());
}

#[test]
fn static_only_section_announces_zero_ric() {
    // A section that references only static entries must announce a
    // Required Insert Count of 0 even when the dynamic table is
    // non-empty (RFC 9204 Section 2.1.2: it is one larger than the
    // largest referenced absolute index, so 0 when none are referenced).
    let mut enc = Encoder::new(220, false);
    enc.set_capacity(220);
    enc.insert_with_name_ref(b":authority", b"www.example.com");
    let out = enc.encode_section(0, &[hdr(":method", "GET")]);
    // Prefix: RIC 0, Base = insert count 1 (Sign 0, Delta 1); then the
    // static index of ":method GET" (17) as an Indexed Field Line.
    assert_eq!(hex(&out.block), "0001d1");
    assert!(out.encoder_stream.is_empty());
}

/// Strict, independent decoder for a single QPACK "Insert With Literal
/// Name" instruction (RFC 9204 Section 4.3.3). Deliberately does NOT use
/// the project's `push_string`/`read_string`, so it reproduces exactly
/// what a third-party decoder (e.g. Chromium) does: the name length uses
/// a 5-bit prefix with the Huffman flag at bit 5.
fn strict_decode_insert_literal_name(buf: &[u8]) -> Option<(Vec<u8>, Vec<u8>)> {
    let mut off = 0usize;
    let first = *buf.get(off)?;
    // `01` + H + 5-bit name length.
    if first & 0xC0 != 0x40 {
        return None;
    }
    let name_huffman = first & 0x20 != 0;
    let mut name_len = (first & 0x1F) as usize;
    off += 1;
    if name_len == 0x1F {
        let mut shift = 0u32;
        loop {
            let b = *buf.get(off)?;
            off += 1;
            name_len += ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
    }
    let name_raw = buf.get(off..off + name_len)?;
    off += name_len;
    let name = if name_huffman {
        let mut out = Vec::new();
        crate::hpack::huffman::decode(name_raw, &mut out).ok()?;
        out
    } else {
        name_raw.to_vec()
    };

    let first = *buf.get(off)?;
    // 7-bit value length with the Huffman flag at bit 7.
    let value_huffman = first & 0x80 != 0;
    let mut value_len = (first & 0x7f) as usize;
    off += 1;
    if value_len == 0x7f {
        let mut shift = 0u32;
        loop {
            let b = *buf.get(off)?;
            off += 1;
            value_len += ((b & 0x7f) as usize) << shift;
            if b & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
    }
    let value_raw = buf.get(off..off + value_len)?;
    let value = if value_huffman {
        let mut out = Vec::new();
        crate::hpack::huffman::decode(value_raw, &mut out).ok()?;
        out
    } else {
        value_raw.to_vec()
    };
    Some((name, value))
}

#[test]
fn insert_with_literal_name_survives_strict_decode() {
    // Reproduces the hang Chromium reports: the encoder stream carries an
    // "Insert With Literal Name" instruction whose name length must be a
    // 5-bit prefix with the Huffman flag at bit 5. With Huffman enabled
    // (the production setting), a 4-bit prefix misplaces the flag and
    // corrupts the stream, so a strict decoder cannot recover the name.
    let mut enc = Encoder::new(220, true);
    enc.set_capacity(220);
    let ins = enc
        .insert_literal(b"x-custom-header", b"hello-world")
        .unwrap();

    let (name, value) = strict_decode_insert_literal_name(&ins)
        .expect("strict QPACK decoder must parse the insert");
    assert_eq!(name, b"x-custom-header");
    assert_eq!(value, b"hello-world");
}

#[test]
fn neqo_ici_roundtrip_repro() {
    use crate::h3::qpack::decoder::Decoder;
    let mut enc = Encoder::new(4096, false);
    let mut dec = Decoder::new(4096, 16);
    for i in 0..64u64 {
        let name = Bytes::from(format!("x-header-{i}"));
        let value = Bytes::from(format!("value-{i}"));
        let section = enc.encode_section_with_ack_base(2, &[(name, value)]);
        let _ = dec
            .feed_encoder_stream(&section.encoder_stream)
            .expect("client decoder ingests inserts");
        let _ = dec
            .decode_block(&section.block, 2, 0)
            .expect("client decoder decodes section")
            .expect("section not blocked");
        let client_dec = dec.take_decoder_stream();
        enc.feed_decoder_stream(&client_dec)
            .unwrap_or_else(|e| panic!("feed_decoder_stream failed on iter {i}: {e:?}"));
    }
}

#[test]
fn split_decoder_stream_chunk_repro() {
    // A Section Acknowledgment for stream ID 128 needs two bytes
    // (0xFF + 0x01): the 7-bit Stream ID prefix overflows into a
    // continuation byte. QUIC `poll_recv` can deliver these bytes in
    // separate chunks. Feeding the first byte alone must NOT error.
    let mut enc = Encoder::new(256, false);
    enc.encode_section(128, &[hdr("a", "b")]);
    // First byte only — must be tolerated (buffered), not a connection error.
    assert!(
        enc.feed_decoder_stream(&[0xFF]).is_ok(),
        "partial instruction must not raise QPACK_DECODER_STREAM_ERROR"
    );
    // Second byte completes the instruction.
    assert!(enc.feed_decoder_stream(&[0x01]).is_ok());
}

#[test]
fn decoder_stream_batch_larger_than_one_instruction_is_accepted() {
    // One QUIC chunk can carry many complete decoder-stream instructions:
    // under load a peer acknowledges every field section it decodes and the
    // transport may deliver all of those acknowledgments in a single chunk.
    // The buffer bound applies to one instruction (10 octets), not to the
    // chunk, so a valid batch must not raise QPACK_DECODER_STREAM_ERROR.
    let mut enc = Encoder::new(256, false);
    let mut batch = Vec::new();
    for stream_id in (0..=316u64).step_by(4) {
        integer::encode(&mut batch, stream_id, 7, 0x80);
    }
    assert!(batch.len() > 64, "batch is {} bytes", batch.len());
    assert!(enc.feed_decoder_stream(&batch).is_ok());
}

#[test]
fn endless_decoder_stream_continuation_is_rejected() {
    // A prefixed integer is at most 10 octets (RFC 9204 Section 4.1.1).
    // An instruction whose continuation bytes never terminate must be
    // rejected instead of buffered forever.
    let mut enc = Encoder::new(256, false);
    let mut runaway = vec![0x3f]; // `00` + 6-bit increment prefix, all ones
    runaway.extend_from_slice(&[0x80; 10]);
    assert_eq!(
        enc.feed_decoder_stream(&runaway),
        Err(QpackError::DecoderStream)
    );
}

#[test]
fn insert_with_literal_name_huffman_flag_at_bit_five() {
    // Byte-level check: with Huffman on, the H flag of an Insert With
    // Literal Name must sit at bit 5 (0x20), not bit 4 (0x10).
    let mut enc = Encoder::new(220, true);
    enc.set_capacity(220);
    let ins = enc.insert_literal(b"x-custom-header", b"hello").unwrap();
    let pos = ins
        .iter()
        .position(|&b| b & 0xC0 == 0x40)
        .expect("insert instruction present");
    assert_eq!(
        ins[pos] & 0x20,
        0x20,
        "Huffman flag must be at bit 5 for an Insert With Literal Name"
    );
}

/// Decoder-stream integers past their prefix (RFC 9204 Section 4.1.1): an
/// Insert Count Increment of 70 and a Section Acknowledgment for stream 200
/// take two octets each. Reading the first octet twice made the increment
/// 126, more than was inserted, and the instruction a decoder stream error.
#[test]
fn decoder_stream_integers_past_the_prefix_are_read_whole() {
    let mut enc = Encoder::new(4096, false);
    let _ = enc.set_capacity(4096);
    let fields: Vec<_> = (0..70).map(|i| hdr(&format!("x-field-{i}"), "v")).collect();
    let _ = enc.encode_section(200, &fields);
    assert!(enc.dynamic.inserted() >= 70, "{}", enc.dynamic.inserted());
    let had_refs = enc.pending_refs.iter().any(|(id, _)| *id == 200);
    let mut instructions = Vec::new();
    integer::encode(&mut instructions, 200, 7, 0x80);
    integer::encode(&mut instructions, 70, 6, 0x00);
    assert_eq!(hex(&instructions), "ff493f07");
    enc.feed_decoder_stream(&instructions).unwrap();
    assert_eq!(enc.known_received, 70);
    if had_refs {
        assert!(
            enc.pending_refs.iter().all(|(id, _)| *id != 200),
            "the acknowledgment freed nothing"
        );
    }
}
