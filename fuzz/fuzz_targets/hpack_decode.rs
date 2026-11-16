#![no_main]

use libfuzzer_sys::fuzz_target;
use zincio_http::hpack::Decoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = Decoder::new(4096);
    let mut list_size = 0usize;
    match decoder.decode(data, &mut list_size) {
        Ok(headers) => {
            // The dynamic table must stay internally consistent after a
            // successful decode: every referenced entry resolves.
            for h in &headers {
                let _ = h.name().len() + h.value().len();
            }
        }
        Err(_) => {
            // Any error is the expected, safe outcome for malformed input;
            // the decoder must never panic on it.
        }
    }
});
