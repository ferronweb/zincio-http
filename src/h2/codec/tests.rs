use super::*;

#[inline]
fn hex_to_bytes(hex: impl AsRef<str>) -> Vec<u8> {
    hex.as_ref()
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| {
            let hi = (pair[0] as char).to_digit(16).unwrap() as u8;
            let lo = (pair[1] as char).to_digit(16).unwrap() as u8;
            (hi << 4) | lo
        })
        .collect()
}

#[inline]
fn decode_all(wire: &[u8]) -> Result<Vec<Frame>, H2Error> {
    let mut decoder = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
    decoder.extend(wire);
    let mut frames = Vec::new();
    while let Some(frame) = decoder.next_frame()? {
        frames.push(frame);
    }
    Ok(frames)
}

#[inline]
fn decode_one(wire: &[u8]) -> Result<Frame, H2Error> {
    let mut frames = decode_all(wire)?;
    assert_eq!(frames.len(), 1);
    Ok(frames.remove(0))
}

#[test]
fn preface_bytes() {
    assert_eq!(
        CLIENT_PREFACE,
        b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n".as_slice()
    );
}

#[test]
fn writer_data_byte_exact() {
    let mut out = Vec::new();
    FrameWriter::new(16384).write_data(&mut out, 1, true, &[0xab, 0xcd]);
    assert_eq!(out, hex_to_bytes("000002000100000001abcd"));
}

#[test]
fn writer_headers_byte_exact() {
    let mut out = Vec::new();
    FrameWriter::new(16384).write_headers(&mut out, 3, false, true, None, &[0x88, 0x84]);
    assert_eq!(out, hex_to_bytes("0000020104000000038884"));
}

#[test]
fn writer_headers_with_priority_byte_exact() {
    let mut out = Vec::new();
    let priority = Priority {
        exclusive: true,
        dependency: 3,
        weight: 200,
    };
    FrameWriter::new(16384).write_headers(&mut out, 1, false, true, Some(priority), &[0x88]);
    // flags = END_HEADERS | PRIORITY = 0x24; payload = 80 00 00 03 (E, dep 3) c8 88
    assert_eq!(out, hex_to_bytes("00000601240000000180000003c888"));
}

#[test]
fn writer_priority_byte_exact() {
    let mut out = Vec::new();
    let priority = Priority {
        exclusive: false,
        dependency: 4,
        weight: 22,
    };
    FrameWriter::new(16384).write_priority(&mut out, 5, priority);
    assert_eq!(out, hex_to_bytes("0000050200000000050000000416"));
}

#[test]
fn writer_reset_byte_exact() {
    let mut out = Vec::new();
    FrameWriter::new(16384).write_reset(&mut out, 7, 0x06);
    assert_eq!(out, hex_to_bytes("00000403000000000700000006"));
}

#[test]
fn writer_settings_byte_exact() {
    let mut out = Vec::new();
    FrameWriter::new(16384).write_settings(
        &mut out,
        &[
            Setting {
                id: 0x04,
                value: 1024,
            },
            Setting {
                id: 0x01,
                value: 4096,
            },
        ],
    );
    assert_eq!(
        out,
        hex_to_bytes("00000c040000000000000400000400000100001000")
    );
}

#[test]
fn writer_settings_ack_byte_exact() {
    let mut out = Vec::new();
    FrameWriter::new(16384).write_settings_ack(&mut out);
    assert_eq!(out, hex_to_bytes("000000040100000000"));
}

#[test]
fn writer_ping_byte_exact() {
    let mut out = Vec::new();
    FrameWriter::new(16384).write_ping(&mut out, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(out, hex_to_bytes("0000080600000000000102030405060708"));
    let mut ack = Vec::new();
    FrameWriter::new(16384).write_ping_ack(&mut ack, &[1, 2, 3, 4, 5, 6, 7, 8]);
    assert_eq!(ack, hex_to_bytes("0000080601000000000102030405060708"));
}

#[test]
fn writer_goaway_byte_exact() {
    let mut out = Vec::new();
    FrameWriter::new(16384).write_goaway(&mut out, 13, 0, b"bye");
    assert_eq!(
        out,
        hex_to_bytes("00000b0700000000000000000d00000000627965")
    );
}

#[test]
fn writer_window_update_byte_exact() {
    let mut out = Vec::new();
    FrameWriter::new(16384).write_window_update(&mut out, 0, 65_535);
    assert_eq!(out, hex_to_bytes("0000040800000000000000ffff"));
}

#[test]
fn writer_continuation_byte_exact() {
    let mut out = Vec::new();
    FrameWriter::new(16384).write_continuation(&mut out, 3, false, &[0x88]);
    assert_eq!(out, hex_to_bytes("00000109000000000388"));
    let mut end = Vec::new();
    FrameWriter::new(16384).write_continuation(&mut end, 3, true, &[0x88]);
    assert_eq!(end, hex_to_bytes("00000109040000000388"));
}

#[test]
fn writer_field_block_splits_at_frame_limit() {
    let limit = 32;
    let block: Vec<u8> = (0..100).map(|i| i as u8).collect();
    let mut out = Vec::new();
    FrameWriter::new(limit).write_field_block(&mut out, 9, true, &block);

    let frames = decode_all(&out).unwrap();
    assert_eq!(frames.len(), 4);
    match &frames[0] {
        Frame::Headers {
            stream_id,
            end_stream,
            end_headers,
            block: first,
            ..
        } => {
            assert_eq!(*stream_id, 9);
            assert!(*end_stream);
            assert!(!*end_headers);
            assert_eq!(&block[..limit], first);
        }
        other => panic!("unexpected first frame {other:?}"),
    }
    for (i, frame) in frames[1..].iter().enumerate() {
        let (end_headers, cont_block) = match frame {
            Frame::Continuation {
                end_headers, block, ..
            } => (*end_headers, block),
            other => panic!("unexpected continuation {other:?}"),
        };
        assert_eq!(end_headers, i == 2, "only last CONTINUATION ends headers");
        let start = limit + i * limit;
        let end = (start + limit).min(block.len());
        assert_eq!(cont_block, &block[start..end]);
    }
}

#[test]
fn writer_field_block_single_frame_when_small() {
    let mut out = Vec::new();
    FrameWriter::new(16384).write_field_block(&mut out, 1, false, &[0x88]);
    let frames = decode_all(&out).unwrap();
    assert_eq!(frames.len(), 1);
    assert!(matches!(
        frames[0],
        Frame::Headers {
            end_headers: true,
            ..
        }
    ));
}

#[test]
fn decode_settings() {
    let frame = decode_one(&hex_to_bytes("00000c040000000000000400000400000100001000")).unwrap();
    assert_eq!(
        frame,
        Frame::Settings {
            ack: false,
            settings: vec![
                Setting {
                    id: 0x04,
                    value: 1024
                },
                Setting {
                    id: 0x01,
                    value: 4096
                },
            ],
        }
    );
}

#[test]
fn decode_settings_ack() {
    let frame = decode_one(&hex_to_bytes("000000040100000000")).unwrap();
    assert_eq!(
        frame,
        Frame::Settings {
            ack: true,
            settings: vec![],
        }
    );
}

#[test]
fn settings_ack_with_payload_is_frame_size_error() {
    assert_eq!(
        decode_one(&hex_to_bytes("000006040100000000000100000400"))
            .unwrap_err()
            .reason,
        Reason::FrameSizeError
    );
}

#[test]
fn settings_nonzero_stream_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("000000040000000001")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn settings_length_not_multiple_of_six_is_frame_size_error() {
    let err = decode_one(&hex_to_bytes("00000704000000000000010000040000")).unwrap_err();
    assert_eq!(err.reason, Reason::FrameSizeError);
}

#[test]
fn settings_enable_push_out_of_range_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("000006040000000000000200000002")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn settings_initial_window_too_large_is_flow_control_error() {
    let err = decode_one(&hex_to_bytes("000006040000000000000480000000")).unwrap_err();
    assert_eq!(err.reason, Reason::FlowControlError);
}

#[test]
fn settings_initial_window_at_limit_is_accepted() {
    let frame = decode_one(&hex_to_bytes("00000604000000000000047fffffff")).unwrap();
    assert!(matches!(frame, Frame::Settings { .. }));
}

#[test]
fn settings_max_frame_size_out_of_range_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("000006040000000000000500003fff")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
    let ok = decode_one(&hex_to_bytes("000006040000000000000500ffffff")).unwrap();
    assert!(matches!(ok, Frame::Settings { .. }));
}

#[test]
fn unknown_setting_is_accepted_and_parsed() {
    let frame = decode_one(&hex_to_bytes("000006040000000000009900005abc")).unwrap();
    assert_eq!(
        frame,
        Frame::Settings {
            ack: false,
            settings: vec![Setting {
                id: 0x99,
                value: 0x5abc
            }],
        }
    );
}

#[test]
fn decode_ping_with_ack_flag() {
    let frame = decode_one(&hex_to_bytes("0000080601000000000102030405060708")).unwrap();
    assert_eq!(
        frame,
        Frame::Ping {
            ack: true,
            payload: [1, 2, 3, 4, 5, 6, 7, 8],
        }
    );
}

#[test]
fn ping_wrong_length_is_frame_size_error() {
    let err = decode_one(&hex_to_bytes("00000706000000000001020304050607")).unwrap_err();
    assert_eq!(err.reason, Reason::FrameSizeError);
}

#[test]
fn ping_nonzero_stream_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("0000080600000000010102030405060708")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn decode_goaway_with_debug_data() {
    let frame = decode_one(&hex_to_bytes("00000b0700000000000000000d00000000627965")).unwrap();
    assert_eq!(
        frame,
        Frame::GoAway {
            last_stream_id: 13,
            error_code: 0,
            debug: b"bye".as_slice().into(),
        }
    );
}

#[test]
fn goaway_too_short_is_frame_size_error() {
    let err = decode_one(&hex_to_bytes("0000070700000000000000000d00000000")).unwrap_err();
    assert_eq!(err.reason, Reason::FrameSizeError);
}

#[test]
fn goaway_nonzero_stream_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("0000080700000000010000000d00000000")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn goaway_reserved_last_stream_bit_is_masked() {
    let frame = decode_one(&hex_to_bytes("0000080700000000008000000d00000000")).unwrap();
    assert_eq!(
        frame,
        Frame::GoAway {
            last_stream_id: 13,
            error_code: 0,
            debug: Bytes::new(),
        }
    );
}

#[test]
fn decode_window_update() {
    let frame = decode_one(&hex_to_bytes("0000040800000000000000ffff")).unwrap();
    assert_eq!(
        frame,
        Frame::WindowUpdate {
            stream_id: 0,
            increment: 65_535,
        }
    );
}

#[test]
fn window_update_zero_increment_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("00000408000000000000000000")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn window_update_reserved_increment_bit_is_masked() {
    let frame = decode_one(&hex_to_bytes("00000408000000000180000001")).unwrap();
    assert_eq!(
        frame,
        Frame::WindowUpdate {
            stream_id: 1,
            increment: 1,
        }
    );
}

#[test]
fn window_update_wrong_length_is_frame_size_error() {
    let err = decode_one(&hex_to_bytes("000005080000000000000000ffff00")).unwrap_err();
    assert_eq!(err.reason, Reason::FrameSizeError);
}

#[test]
fn rst_stream_wrong_length_is_frame_size_error() {
    let err = decode_one(&hex_to_bytes("000003030000000007000000")).unwrap_err();
    assert_eq!(err.reason, Reason::FrameSizeError);
}

#[test]
fn rst_stream_zero_stream_id_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("00000403000000000000000000")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn data_on_stream_zero_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("00000200000000000000abcd")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn padded_data_is_stripped() {
    let frame = decode_one(&hex_to_bytes("000005000800000001026f6b0000")).unwrap();
    assert_eq!(
        frame,
        Frame::Data {
            stream_id: 1,
            end_stream: false,
            data: b"ok".as_slice().into(),
        }
    );
}

#[test]
fn padding_length_not_less_than_payload_is_protocol_error() {
    // pad_len 5, payload 5 octets: padding not strictly shorter than
    // the payload.
    let err = decode_one(&hex_to_bytes("0000050008000000010500000000")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn padding_of_all_but_one_octet_is_legal() {
    // pad_len 5, payload 6 octets: the strict-lower-bound rule allows
    // the maximum padding with an empty data field.
    let frame = decode_one(&hex_to_bytes("000006000800000001050000000000")).unwrap();
    assert_eq!(
        frame,
        Frame::Data {
            stream_id: 1,
            end_stream: false,
            data: Bytes::new(),
        }
    );
}

#[test]
fn padded_data_without_payload_is_frame_size_error() {
    // PADDED flag but no payload at all.
    let err = decode_one(&hex_to_bytes("000000000800000001")).unwrap_err();
    assert_eq!(err.reason, Reason::FrameSizeError);
}

#[test]
fn padded_headers_with_priority_decode() {
    // payload: 01 (pad len 1) | 80 00 00 03 (E, dep 3) | 88 (weight 136) |
    // 88 (block) | 00 (pad); flags 0x2c = END_HEADERS | PADDED | PRIORITY.
    let frame = decode_one(&hex_to_bytes("000008012c000000010180000003888800")).unwrap();
    assert_eq!(
        frame,
        Frame::Headers {
            stream_id: 1,
            end_stream: false,
            end_headers: true,
            priority: Some(Priority {
                exclusive: true,
                dependency: 3,
                weight: 0x88,
            }),
            block: hex_to_bytes("88").into(),
        }
    );
}

#[test]
fn headers_self_dependency_is_protocol_error() {
    // stream 3, HEADERS with PRIORITY depending on stream 3.
    let err = decode_one(&hex_to_bytes("000006012000000003000000030010")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn priority_frame_wrong_length_is_frame_size_error() {
    let err = decode_one(&hex_to_bytes("0000040200000000050000000310")).unwrap_err();
    assert_eq!(err.reason, Reason::FrameSizeError);
    let err2 = decode_one(&hex_to_bytes("0000060200000000050000000300000010")).unwrap_err();
    assert_eq!(err2.reason, Reason::FrameSizeError);
}

#[test]
fn priority_frame_self_dependency_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("0000050200000000050000000510")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn priority_frame_zero_stream_id_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("0000050200000000000000000310")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn push_promise_promised_stream_zero_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("0000050504000000010000000088")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn push_promise_zero_stream_id_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("0000050504000000000000000288")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn push_promise_too_short_is_frame_size_error() {
    let err = decode_one(&hex_to_bytes("0000020504000000010000")).unwrap_err();
    assert_eq!(err.reason, Reason::FrameSizeError);
}

#[test]
fn push_promise_padded_decode() {
    // payload: 01 (pad len) | 00 00 00 02 (promised) | 88 (block) | 00 (pad)
    let frame = decode_one(&hex_to_bytes("000007050c0000000101000000028800")).unwrap();
    assert_eq!(
        frame,
        Frame::PushPromise {
            stream_id: 1,
            end_headers: true,
            promised_stream_id: 2,
            block: hex_to_bytes("88").into(),
        }
    );
}

#[test]
fn continuation_without_headers_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("00000109040000000388")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn continuation_on_different_stream_is_protocol_error() {
    // HEADERS (no END_HEADERS) on stream 3, then CONTINUATION on stream 5.
    let err = decode_all(&hex_to_bytes(
        "00000101000000000388 00000109000000000588".replace(' ', ""),
    ))
    .unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn non_continuation_while_block_open_is_protocol_error() {
    // HEADERS without END_HEADERS on stream 3, then a DATA frame.
    let err = decode_all(&hex_to_bytes(
        "00000101000000000388 000001000000000003ab".replace(' ', ""),
    ))
    .unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn continuation_closes_block_then_headers_allowed() {
    // HEADERS (no END_HEADERS) + CONTINUATION (END_HEADERS) on stream 3,
    // then a fresh HEADERS (END_HEADERS) on stream 5.
    let frames = decode_all(&hex_to_bytes(
        "00000101000000000388 00000109040000000388 00000101040000000584".replace(' ', ""),
    ))
    .unwrap();
    assert_eq!(frames.len(), 3);
    let Frame::Headers { end_headers, .. } = &frames[0] else {
        panic!();
    };
    assert!(!end_headers);
    let Frame::Continuation { end_headers, .. } = &frames[1] else {
        panic!();
    };
    assert!(*end_headers);
    assert!(matches!(
        &frames[2],
        Frame::Headers {
            end_headers: true,
            ..
        }
    ));
}

#[test]
fn reserved_stream_bit_is_protocol_error() {
    let err = decode_one(&hex_to_bytes("000000040000000081")).unwrap_err();
    assert_eq!(err.reason, Reason::ProtocolError);
}

#[test]
fn oversized_frame_is_frame_size_error() {
    // HEADERS frame claiming 16385 octets of payload: rejected from the
    // header alone, before the payload arrives.
    let mut decoder = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
    decoder.extend(&hex_to_bytes("004001010000000001"));
    let err = decoder.next_frame().unwrap_err();
    assert_eq!(err.reason, Reason::FrameSizeError);
}

#[test]
fn max_frame_size_can_be_increased() {
    let mut decoder = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
    decoder.extend(&hex_to_bytes("004001010000000001"));
    assert_eq!(
        decoder.next_frame().unwrap_err().reason,
        Reason::FrameSizeError
    );

    let mut decoder = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
    decoder.set_max_frame_size(32_768);
    decoder.extend(&hex_to_bytes("004001010000000001"));
    // 16385 octets payload is now legal, but incomplete.
    assert!(decoder.next_frame().unwrap().is_none());
}

#[test]
fn settings_max_frame_size_is_adopted_by_decoder() {
    // SETTINGS announcing SETTINGS_MAX_FRAME_SIZE = 65536, followed by
    // a 20000-octet DATA frame that would violate the default limit.
    let mut session = hex_to_bytes("000006040000000000000500010000");
    let mut data = Vec::new();
    FrameWriter::new(16_384).write_data(&mut data, 1, true, &vec![0x61; 20_000]);
    session.extend_from_slice(&data);

    let frames = decode_all(&session).unwrap();
    assert_eq!(frames.len(), 2);
    assert!(matches!(
        &frames[1],
        Frame::Data { data: body, .. } if body.len() == 20_000
    ));
}

#[test]
fn unknown_frame_type_is_preserved() {
    let frame = decode_one(&hex_to_bytes("0000020a0800000007abcd")).unwrap();
    assert_eq!(
        frame,
        Frame::Unknown {
            typ: 0x0a,
            flags: 0x08,
            stream_id: 7,
            payload: hex_to_bytes("abcd").into(),
        }
    );
}

#[test]
fn incremental_feeding_matches_batch() {
    let mut out = Vec::new();
    let writer = FrameWriter::new(16384);
    writer.write_settings(
        &mut out,
        &[Setting {
            id: 0x01,
            value: 4096,
        }],
    );
    writer.write_headers(&mut out, 1, false, true, None, &[0x82, 0x84, 0x86]);
    writer.write_data(&mut out, 1, true, b"hello, h2!");
    writer.write_window_update(&mut out, 0, 1024);
    writer.write_goaway(&mut out, 1, 0, &[]);

    let batch = decode_all(&out).unwrap();

    let mut decoder = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
    let mut incremental = Vec::new();
    for byte in &out {
        decoder.extend(&[*byte]);
        while let Some(frame) = decoder.next_frame().unwrap() {
            incremental.push(frame);
        }
    }
    assert_eq!(batch, incremental);
}

#[test]
fn round_trip_all_frame_kinds() {
    let mut out = Vec::new();
    let writer = FrameWriter::new(16384);
    writer.write_data(&mut out, 1, true, b"payload");
    writer.write_headers(&mut out, 3, false, true, None, &[0x88]);
    writer.write_headers(
        &mut out,
        5,
        true,
        true,
        Some(Priority {
            exclusive: true,
            dependency: 3,
            weight: 1,
        }),
        &[0x84],
    );
    writer.write_priority(
        &mut out,
        7,
        Priority {
            exclusive: false,
            dependency: 1,
            weight: 255,
        },
    );
    writer.write_reset(&mut out, 9, 0x08);
    writer.write_settings(
        &mut out,
        &[Setting {
            id: 0x05,
            value: 65536,
        }],
    );
    writer.write_settings_ack(&mut out);
    writer.write_push_promise(&mut out, 11, 2, &[0x84]);
    writer.write_ping(&mut out, &[0; 8]);
    writer.write_goaway(&mut out, 13, 0x01, b"debug info");
    writer.write_window_update(&mut out, 0, 1);
    writer.write_window_update(&mut out, 15, 4096);

    let expected: Vec<Frame> = vec![
        Frame::Data {
            stream_id: 1,
            end_stream: true,
            data: b"payload".as_slice().into(),
        },
        Frame::Headers {
            stream_id: 3,
            end_stream: false,
            end_headers: true,
            priority: None,
            block: hex_to_bytes("88").into(),
        },
        Frame::Headers {
            stream_id: 5,
            end_stream: true,
            end_headers: true,
            priority: Some(Priority {
                exclusive: true,
                dependency: 3,
                weight: 1,
            }),
            block: hex_to_bytes("84").into(),
        },
        Frame::Priority {
            stream_id: 7,
            priority: Priority {
                exclusive: false,
                dependency: 1,
                weight: 255,
            },
        },
        Frame::Reset {
            stream_id: 9,
            error_code: 0x08,
        },
        Frame::Settings {
            ack: false,
            settings: vec![Setting {
                id: 0x05,
                value: 65536,
            }],
        },
        Frame::Settings {
            ack: true,
            settings: vec![],
        },
        Frame::PushPromise {
            stream_id: 11,
            end_headers: true,
            promised_stream_id: 2,
            block: hex_to_bytes("84").into(),
        },
        Frame::Ping {
            ack: false,
            payload: [0; 8],
        },
        Frame::GoAway {
            last_stream_id: 13,
            error_code: 0x01,
            debug: b"debug info".as_slice().into(),
        },
        Frame::WindowUpdate {
            stream_id: 0,
            increment: 1,
        },
        Frame::WindowUpdate {
            stream_id: 15,
            increment: 4096,
        },
    ];

    assert_eq!(decode_all(&out).unwrap(), expected);
}
