#![no_main]

use libfuzzer_sys::fuzz_target;
use zincio_http::codec::{
    Frame, FrameDecoder, FrameWriter, DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT,
};

fuzz_target!(|data: &[u8]| {
    for &max_frame_size in &[DEFAULT_MAX_FRAME_SIZE, MAX_FRAME_SIZE_LIMIT, 1024] {
        let mut decoder = FrameDecoder::new(max_frame_size);
        decoder.extend(data);
        loop {
            let frame = match decoder.next_frame() {
                Ok(Some(frame)) => frame,
                Ok(None) | Err(_) => break,
            };
            round_trip(&frame);
        }
    }
});

fn round_trip(frame: &Frame) {
    let mut out = Vec::new();
    let writer = FrameWriter::new(DEFAULT_MAX_FRAME_SIZE);
    match frame {
        Frame::Data {
            stream_id,
            end_stream,
            data,
        } => writer.write_data(&mut out, *stream_id, *end_stream, data),
        Frame::Headers {
            stream_id,
            end_stream,
            end_headers,
            priority,
            block,
        } => writer.write_headers(
            &mut out,
            *stream_id,
            *end_stream,
            *end_headers,
            *priority,
            block,
        ),
        Frame::Priority {
            stream_id,
            priority,
        } => writer.write_priority(&mut out, *stream_id, *priority),
        Frame::Reset {
            stream_id,
            error_code,
        } => writer.write_reset(&mut out, *stream_id, *error_code),
        Frame::Settings { ack, settings } => {
            if *ack {
                writer.write_settings_ack(&mut out);
            } else {
                writer.write_settings(&mut out, settings);
            }
        }
        Frame::PushPromise {
            stream_id,
            promised_stream_id,
            block,
            ..
        } => writer.write_push_promise(&mut out, *stream_id, *promised_stream_id, block),
        Frame::Ping { ack, payload } => {
            if *ack {
                writer.write_ping_ack(&mut out, payload);
            } else {
                writer.write_ping(&mut out, payload);
            }
        }
        Frame::GoAway {
            last_stream_id,
            error_code,
            debug,
        } => writer.write_goaway(&mut out, *last_stream_id, *error_code, debug),
        Frame::WindowUpdate {
            stream_id,
            increment,
        } => writer.write_window_update(&mut out, *stream_id, *increment),
        Frame::Continuation {
            stream_id,
            end_headers,
            block,
        } => writer.write_continuation(&mut out, *stream_id, *end_headers, block),
        Frame::Unknown { .. } => return,
    }

    // The re-written bytes are not necessarily a valid single stream
    // (e.g. END_HEADERS was clear), so stop at the first error.
    let mut decoder = FrameDecoder::new(MAX_FRAME_SIZE_LIMIT);
    decoder.extend(&out);
    while let Ok(Some(_)) = decoder.next_frame() {}
}
