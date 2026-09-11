use super::*;
use crate::h2::codec::Setting;
use crate::h2::error::Reason;
use crate::h2::hpack::{Encoder, Header as HpackHeader};
use crate::h2::stream::StreamMsg;

/// Runs a connection against a scripted peer over an in-memory
/// duplex stream and collects the server's reply bytes.
///
/// The preface timeout needs the zincio timer, which does not run
/// under a plain tokio test runtime (same pattern as the h1
/// slowloris test), so a zincio runtime is built per call.
#[inline]
fn run_connection(
    preface: &[u8],
    frames: &[u8],
    preface_timeout: Option<Duration>,
    idle_timeout: Option<Duration>,
) -> Vec<u8> {
    run_connection_with(
        preface,
        frames,
        preface_timeout,
        ConnectionOptions {
            idle_timeout,
            ..Default::default()
        },
    )
}

/// Like [`run_connection`], with full control over connection options.
#[inline]
fn run_connection_with(
    preface: &[u8],
    frames: &[u8],
    preface_timeout: Option<Duration>,
    opts: ConnectionOptions,
) -> Vec<u8> {
    let script: Vec<u8> = [preface, frames].concat();
    zincio::RuntimeBuilder::new()
        .enable_timer(true)
        .build()
        .unwrap()
        .block_on(async move {
            let (client_end, server_end) = tokio::io::duplex(1 << 16);
            let script = script;

            let server = zincio::spawn(async move {
                let conn = Connection::new(server_end, preface_timeout);
                let _ = conn
                    .handle(
                        Arc::new(|_| {
                            std::future::pending::<Result<Response<Incoming>, std::io::Error>>()
                        }),
                        opts,
                    )
                    .await;
            });

            let mut client = client_end;
            tokio::io::AsyncWriteExt::write_all(&mut client, &script)
                .await
                .expect("write script");
            zincio::time::sleep(Duration::from_millis(50)).await;

            let mut reply = Vec::new();
            let mut buf = [0u8; 4096];
            loop {
                // The server answers in one burst and then waits for
                // our EOF; give up after a short idle gap instead of
                // blocking on the half-open duplex.
                let read = zincio::time::timeout(
                    Duration::from_millis(100),
                    tokio::io::AsyncReadExt::read(&mut client, &mut buf),
                )
                .await;
                match read {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => break,
                    Ok(Ok(n)) => reply.extend_from_slice(&buf[..n]),
                }
            }
            // Close our half so the server sees EOF and exits.
            drop(client);
            zincio::time::timeout(Duration::from_secs(2), server)
                .await
                .expect("server did not finish");
            reply
        })
}

#[inline]
fn decode_frames(wire: &[u8]) -> Vec<Frame> {
    let mut decoder = FrameDecoder::new(DEFAULT_MAX_FRAME_SIZE);
    decoder.extend(wire);
    let mut frames = Vec::new();
    while let Some(frame) = decoder.next_frame().expect("reply decode") {
        frames.push(frame);
    }
    frames
}

#[inline]
fn client_script(writer: impl FnOnce(&mut FrameWriter, &mut Vec<u8>)) -> Vec<u8> {
    let mut script = Vec::new();
    FrameWriter::new(DEFAULT_MAX_FRAME_SIZE).write_settings(&mut script, &[]);
    writer(&mut FrameWriter::new(DEFAULT_MAX_FRAME_SIZE), &mut script);
    script
}

#[test]
fn valid_preface_completes_handshake() {
    let reply = run_connection(
        CLIENT_PREFACE,
        &client_script(|_, _| {}),
        Some(Duration::from_secs(5)),
        None,
    );
    let decoded = decode_frames(&reply);

    // The server's connection preface: its own SETTINGS.
    assert!(matches!(
        decoded.first(),
        Some(Frame::Settings { ack: false, .. })
    ));
    // The client's SETTINGS is acknowledged.
    assert!(decoded
        .iter()
        .any(|f| matches!(f, Frame::Settings { ack: true, .. })));
}

#[test]
fn invalid_preface_answers_goaway_protocol_error() {
    let reply = run_connection(
        b"INVALID CONNECTION PREFACE!!",
        &[],
        Some(Duration::from_secs(5)),
        None,
    );
    let decoded = decode_frames(&reply);
    assert_eq!(decoded.len(), 1);
    assert!(matches!(
        &decoded[0],
        Frame::GoAway {
            error_code: 0x01,
            ..
        }
    ));
}

#[test]
fn settings_are_applied_and_acked() {
    let reply = run_connection(
        CLIENT_PREFACE,
        &client_script(|writer, script| {
            writer.write_settings(
                script,
                &[
                    Setting {
                        id: 0x01,
                        value: 16_384,
                    },
                    Setting { id: 0x02, value: 0 },
                    Setting {
                        id: 0x04,
                        value: 1_048_576,
                    },
                    Setting {
                        id: 0x05,
                        value: 32_768,
                    },
                    Setting {
                        id: 0x06,
                        value: 65_536,
                    },
                    Setting { id: 0x63, value: 7 }, // unknown: ignored
                ],
            );
        }),
        Some(Duration::from_secs(5)),
        None,
    );
    let decoded = decode_frames(&reply);
    // One ACK per non-ACK SETTINGS frame, in order.
    let acks: Vec<&Frame> = decoded
        .iter()
        .filter(|f| matches!(f, Frame::Settings { ack: true, .. }))
        .collect();
    assert_eq!(acks.len(), 2);
}

#[test]
fn settings_ack_with_payload_is_connection_error() {
    // SETTINGS with the ACK flag and a non-empty payload: the codec
    // rejects it and the connection reports FRAME_SIZE_ERROR.
    // Payload: one Setting { id: 0x04, value: 0 }.
    let bad = [
        0x00, 0x00, 0x06, 0x04, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00,
    ];
    let mut frames = client_script(|_, _| {});
    frames.extend_from_slice(&bad);
    let reply = run_connection(CLIENT_PREFACE, &frames, Some(Duration::from_secs(5)), None);
    let decoded = decode_frames(&reply);
    assert!(matches!(
        decoded.last().and_then(|f| match f {
            Frame::GoAway { error_code, .. } => Some(*error_code),
            _ => None,
        }),
        Some(0x06) // FRAME_SIZE_ERROR
    ));
}

#[test]
fn ping_is_echoed() {
    let reply = run_connection(
        CLIENT_PREFACE,
        &client_script(|writer, script| {
            writer.write_ping(script, &[1, 2, 3, 4, 5, 6, 7, 8]);
        }),
        Some(Duration::from_secs(5)),
        None,
    );
    let decoded = decode_frames(&reply);
    assert!(decoded.iter().any(|f| matches!(
        f,
        Frame::Ping { ack: true, payload } if *payload == [1, 2, 3, 4, 5, 6, 7, 8]
    )));
}

#[test]
fn goaway_from_peer_ends_connection() {
    let mut script = client_script(|_, _| {});
    FrameWriter::new(DEFAULT_MAX_FRAME_SIZE).write_goaway(&mut script, 0, 0x00, b"bye");

    let reply = run_connection(CLIENT_PREFACE, &script, Some(Duration::from_secs(5)), None);
    let decoded = decode_frames(&reply);
    // The peer's GOAWAY draws no reply beyond the SETTINGS
    // exchange; the server closes quietly.
    assert!(!decoded.iter().any(|f| matches!(f, Frame::GoAway { .. })));
}

#[test]
fn idle_timeout_closes_connection() {
    // With an idle timeout set, a peer that completes the handshake and
    // then goes silent must be shut down gracefully with a GOAWAY
    // (RFC 9113 Section 10.5).
    let reply = run_connection(
        CLIENT_PREFACE,
        &client_script(|_, _| {}),
        Some(Duration::from_secs(5)),
        Some(Duration::from_millis(30)),
    );
    let decoded = decode_frames(&reply);
    assert!(decoded.iter().any(|f| matches!(f, Frame::GoAway { .. })));
}

#[test]
fn window_update_overflow_is_connection_error() {
    // A WINDOW_UPDATE that pushes the connection window past 2^31-1
    // is a FLOW_CONTROL_ERROR connection error (RFC 9113 6.9.1).
    let (_client, server) = tokio::io::duplex(1 << 16);
    let mut conn = Connection::new(server, Some(Duration::from_secs(5)));
    conn.handle_window_update(0, 0x7fff_ffff);
    let decoded = decode_frames(&conn.out);
    assert!(decoded.iter().any(|f| matches!(
        f,
        Frame::GoAway { error_code, .. } if *error_code == Reason::FlowControlError.code()
    )));
}

#[test]
fn stream_window_update_overflow_is_stream_error() {
    // A WINDOW_UPDATE that overflows a single stream's window is a
    // RST_STREAM with FLOW_CONTROL_ERROR (RFC 9113 6.9.1).
    let (_client, server) = tokio::io::duplex(1 << 16);
    let mut conn = Connection::new(server, Some(Duration::from_secs(5)));
    // Open a stream so it has a flow-control window.
    let (reset_tx, _) = kanal::bounded_async::<u32>(1);
    let (_, msg_rx) = kanal::bounded_async::<StreamMsg>(1);
    conn.streams.insert(1, StreamEntry::new(reset_tx, msg_rx));
    conn.handle_window_update(1, 0x7fff_ffff);
    let decoded = decode_frames(&conn.out);
    assert!(decoded.iter().any(|f| matches!(
            f,
            Frame::Reset { stream_id, error_code } if *stream_id == 1 && *error_code == Reason::FlowControlError.code()
        )));
}

#[test]
fn graceful_shutdown_queues_goaway() {
    // Cancelling the shutdown token sends GOAWAY (NO_ERROR) and the
    // connection drains in-flight streams before the final GOAWAY.
    zincio::RuntimeBuilder::new()
        .enable_timer(true)
        .build()
        .unwrap()
        .block_on(async {
            let (_client, server) = tokio::io::duplex(1 << 16);
            let mut conn = Connection::new(server, Some(Duration::from_secs(5)));
            conn.begin_graceful_shutdown();
            assert!(conn.graceful);
            conn.finish_graceful_shutdown();
            let decoded = decode_frames(&conn.out);
            let codes: Vec<u32> = decoded
                .iter()
                .filter_map(|f| match f {
                    Frame::GoAway { error_code, .. } => Some(*error_code),
                    _ => None,
                })
                .collect();
            assert_eq!(codes, vec![Reason::NoError.code(), Reason::NoError.code()]);
        });
}

/// A header block carrying only `:method`: decodes fine but fails
/// request parsing, so the server answers with RST_STREAM
/// PROTOCOL_ERROR (RFC 9113 Section 8.1.1).
#[inline]
fn malformed_request_block() -> Vec<u8> {
    let mut encoder = Encoder::new(4096);
    let mut block = Vec::new();
    encoder.encode(&[HpackHeader::new(":method", "GET")], &mut block);
    block
}

#[test]
fn local_reset_budget_closes_with_enhance_your_calm() {
    // A peer whose protocol errors would force more RST_STREAM frames
    // than the budget allows must cost the connection: GOAWAY with
    // ENHANCE_YOUR_CALM (RFC 9113 Section 10.5.2).
    let block = malformed_request_block();
    let script = [client_script(|w, out| {
        for id in [1u32, 3, 5] {
            w.write_headers(out, id, false, true, None, &block);
        }
    })]
    .concat();
    let reply = run_connection_with(
        CLIENT_PREFACE,
        &script,
        Some(Duration::from_secs(5)),
        ConnectionOptions {
            max_local_error_reset_streams: Some(2),
            ..Default::default()
        },
    );
    let decoded = decode_frames(&reply);
    let count = |pred: fn(&Frame) -> bool| decoded.iter().filter(|f| pred(f)).count();
    // Two resets fit the budget; the third error closes the connection.
    assert_eq!(count(|f| matches!(f, Frame::Reset { .. })), 2);
    assert_eq!(
        count(|f| matches!(
            f,
            Frame::GoAway { error_code, .. } if *error_code == Reason::EnhanceYourCalm.code()
        )),
        1,
        "expected ENHANCE_YOUR_CALM GOAWAY, got {decoded:?}"
    );
}

#[test]
fn local_reset_budget_can_be_disabled() {
    // With the budget disabled, protocol errors only ever cost their
    // own streams: one RST_STREAM per error, no GOAWAY.
    let block = malformed_request_block();
    let script = [client_script(|w, out| {
        for id in [1u32, 3, 5, 7] {
            w.write_headers(out, id, false, true, None, &block);
        }
    })]
    .concat();
    let reply = run_connection_with(
        CLIENT_PREFACE,
        &script,
        Some(Duration::from_secs(5)),
        ConnectionOptions {
            max_local_error_reset_streams: None,
            ..Default::default()
        },
    );
    let decoded = decode_frames(&reply);
    assert!(
        decoded.iter().all(|f| !matches!(f, Frame::GoAway { .. })),
        "no GOAWAY expected, got {decoded:?}"
    );
    assert!(matches!(
        decoded.last(),
        Some(Frame::Reset { stream_id: 7, .. })
    ));
}

/// Injects a stream entry that is open but not yet dispatched (the
/// peer's HEADERS arrived but the request was not accepted), the state
/// a pending-accept reset arrives in.
#[inline]
fn inject_pending_stream(conn: &mut Connection<tokio::io::DuplexStream>, id: u32) {
    let (reset_tx, _) = kanal::bounded_async::<u32>(1);
    let (_, msg_rx) = kanal::bounded_async::<StreamMsg>(1);
    conn.streams.insert(id, StreamEntry::new(reset_tx, msg_rx));
}

#[test]
fn pending_accept_reset_budget_closes_with_enhance_your_calm() {
    // A peer that opens streams and resets them before their request
    // was dispatched churns through the pending-accept budget (RFC
    // 9113 Section 10.5.2): on exceeding it the connection closes
    // with ENHANCE_YOUR_CALM.
    let (_client, server) = tokio::io::duplex(1 << 16);
    let mut conn = Connection::new(server, Some(Duration::from_secs(5)));
    conn.opts.max_pending_accept_reset_streams = Some(2);
    for id in [1u32, 3, 5] {
        inject_pending_stream(&mut conn, id);
        conn.handle_reset_frame(id, Reason::Cancel.code());
    }
    let decoded = decode_frames(&conn.out);
    assert!(
        decoded.iter().any(|f| matches!(
            f,
            Frame::GoAway { error_code, .. } if *error_code == Reason::EnhanceYourCalm.code()
        )),
        "expected ENHANCE_YOUR_CALM GOAWAY, got {decoded:?}"
    );
    // The two in-budget resets were handled normally; the third must
    // not have reset anything further.
    assert_eq!(count_resets(&decoded), 0);
}

#[test]
fn pending_accept_reset_budget_can_be_disabled() {
    let (_client, server) = tokio::io::duplex(1 << 16);
    let mut conn = Connection::new(server, Some(Duration::from_secs(5)));
    conn.opts.max_pending_accept_reset_streams = None;
    for id in [1u32, 3, 5, 7, 9] {
        inject_pending_stream(&mut conn, id);
        conn.handle_reset_frame(id, Reason::Cancel.code());
    }
    let decoded = decode_frames(&conn.out);
    assert!(
        decoded.iter().all(|f| !matches!(f, Frame::GoAway { .. })),
        "no GOAWAY expected, got {decoded:?}"
    );
}

#[inline]
fn count_resets(decoded: &[Frame]) -> usize {
    decoded
        .iter()
        .filter(|f| matches!(f, Frame::Reset { .. }))
        .count()
}

#[test]
fn continuation_flood_is_reset_without_closing_connection() {
    // A peer that opens a header field block (HEADERS without END_HEADERS)
    // and never closes it, streaming CONTINUATION frames forever, is a
    // CONTINUATION flood (CVE-2024-27919). Past `max_continuation_frames`
    // the offending stream is reset with PROTOCOL_ERROR and the connection
    // keeps serving other streams (no GOAWAY).
    let limit = 3usize;
    let writer = FrameWriter::new(DEFAULT_MAX_FRAME_SIZE);
    let mut script = Vec::new();
    writer.write_settings(&mut script, &[]);
    // HEADERS opens the block (frame #1 of the flood budget).
    writer.write_headers(&mut script, 1, false, false, None, &[0x82]);
    // Two CONTINUATION frames stay within the budget (frames #2, #3).
    for _ in 0..2 {
        writer.write_continuation(&mut script, 1, false, &[0x82]);
    }
    // The third CONTINUATION exceeds the limit and triggers the reset.
    writer.write_continuation(&mut script, 1, false, &[0x82]);
    let reply = run_connection_with(
        CLIENT_PREFACE,
        &script,
        Some(Duration::from_secs(5)),
        ConnectionOptions {
            max_continuation_frames: limit,
            ..Default::default()
        },
    );
    let decoded = decode_frames(&reply);
    assert!(
        decoded.iter().any(|f| matches!(
            f,
            Frame::Reset {
                stream_id: 1,
                error_code,
            } if *error_code == Reason::ProtocolError.code()
        )),
        "expected RST_STREAM PROTOCOL_ERROR on the flooded stream, got {decoded:?}"
    );
    assert!(
        decoded.iter().all(|f| !matches!(f, Frame::GoAway { .. })),
        "connection must survive a single-stream flood, got {decoded:?}"
    );
}

#[test]
fn complete_field_block_within_limit_is_not_reset() {
    // A normally-packed, bounded header block that spans several
    // CONTINUATION frames but stays under the limit must not be reset.
    let limit = 32usize;
    let mut encoder = Encoder::new(4096);
    let mut block = Vec::new();
    let fields = [
        HpackHeader::new(b":method".to_vec(), b"GET".to_vec()),
        HpackHeader::new(b":scheme".to_vec(), b"https".to_vec()),
        HpackHeader::new(b":authority".to_vec(), b"example.com".to_vec()),
        HpackHeader::new(b":path".to_vec(), b"/".to_vec()),
    ];
    encoder.encode(&fields, &mut block);

    let writer = FrameWriter::new(DEFAULT_MAX_FRAME_SIZE);
    let mut script = Vec::new();
    writer.write_settings(&mut script, &[]);
    let capacity = 3;
    let first = &block[..capacity.min(block.len())];
    writer.write_headers(&mut script, 1, false, false, None, first);
    let mut rest = &block[capacity.min(block.len())..];
    while rest.len() > capacity {
        writer.write_continuation(&mut script, 1, false, &rest[..capacity]);
        rest = &rest[capacity..];
    }
    writer.write_continuation(&mut script, 1, true, rest);
    let reply = run_connection_with(
        CLIENT_PREFACE,
        &script,
        Some(Duration::from_secs(5)),
        ConnectionOptions {
            max_continuation_frames: limit,
            ..Default::default()
        },
    );
    let decoded = decode_frames(&reply);
    assert!(
        decoded
            .iter()
            .all(|f| !matches!(f, Frame::Reset { stream_id: 1, .. })),
        "a bounded field block must not be reset, got {decoded:?}"
    );
}
