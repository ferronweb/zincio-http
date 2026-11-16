#![no_main]

use libfuzzer_sys::fuzz_target;
use zincio_http::qpack::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new(16384, 100);
    let split = data.len() / 2;
    let (encoder_stream, section) = data.split_at(split);

    let _ = decoder.feed_encoder_stream(encoder_stream);

    // A second, independent decoder feeds only the section bytes: a section
    // may reference dynamic entries that never arrive (blocks), and must
    // not panic while parked.
    let mut lone = Decoder::new(16384, 100);
    let _ = lone.decode_block(section, 1, 0);

    match decoder.decode_block(section, 1, 0) {
        Ok(Some(_headers)) => {}
        Ok(None) => {
            // Parked: unblocking never arrives, but cancellation and expiry
            // must drain the queue without panicking.
            let _ = decoder.stream_cancelled(1);
            let _ = decoder.expire_blocked(u64::MAX, 0);
        }
        Err(_) => {
            // The expected, safe outcome for malformed input.
        }
    }

    // Decoder stream instructions are never inspected by fuzzing, but must
    // be drainable.
    let _ = decoder.take_decoder_stream();
});
