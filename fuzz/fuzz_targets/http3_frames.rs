#![no_main]

use bytes::Bytes;
use libfuzzer_sys::fuzz_target;
use zincio_http::FrameDecoder;

fuzz_target!(|data: &[u8]| {
    let mut decoder = FrameDecoder::new();
    decoder.extend(Bytes::copy_from_slice(data));
    while let Ok(Some(_)) = decoder.next_frame() {}
});
