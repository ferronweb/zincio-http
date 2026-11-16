//! Prefixed-integer representation (RFC 7541 Section 5.1, RFC 9204
//! Section 4.1.1).

use super::HpackError;

/// Encodes `value` with an `prefix_bits`-bit prefix, appending to `out`.
///
/// The low `prefix_bits` bits of `header` (which carries the representation's
/// other bits) are replaced with the encoded value.
#[inline]
pub(crate) fn encode(out: &mut Vec<u8>, value: u64, prefix_bits: u8, header: u8) {
    let mask = (1u64 << prefix_bits) - 1;
    if value < mask {
        out.push((u64::from(header) & !mask | value) as u8);
        return;
    }
    out.push((u64::from(header) & !mask | mask) as u8);
    let mut v = value - mask;
    while v >= 128 {
        out.push((v & 0x7f) as u8 | 0x80);
        v >>= 7;
    }
    out.push(v as u8);
}

/// Decodes an `prefix_bits`-bit-prefixed integer.
///
/// `header` is the already-consumed first octet; `off` is updated past the
/// consumed continuation octets of `buf`. Values that would overflow 64 bits
/// are treated as a decoding error (RFC 9204 Section 4.1.1 requires support
/// for 62-bit integers).
#[inline]
pub(crate) fn decode(
    buf: &[u8],
    off: &mut usize,
    prefix_bits: u8,
    header: u8,
) -> Result<u64, HpackError> {
    let mask = (1u64 << prefix_bits) - 1;
    let mut value = u64::from(header) & mask;
    if value < mask {
        return Ok(value);
    }

    let mut shift: u32 = 0;
    loop {
        // 7 bits per octet; the ninth octet (shift 56) already covers bit 62,
        // so anything past it overflows the 62-bit QPACK limit.
        if shift > 56 {
            return Err(HpackError::InvalidInteger);
        }
        let b = *buf.get(*off).ok_or(HpackError::InvalidInteger)?;
        *off += 1;
        value = value
            .checked_add((u64::from(b & 0x7f)) << shift)
            .ok_or(HpackError::InvalidInteger)?;
        if b & 0x80 == 0 {
            // RFC 9204 Section 4.1.1: only integers up to 62 bits long are
            // in scope; the shift-56 chunk can carry bit 62, so check the
            // value itself.
            if value >= (1 << 62) {
                return Err(HpackError::InvalidInteger);
            }
            return Ok(value);
        }
        shift += 7;
    }
}

/// Returns the number of bytes a prefixed integer occupies starting at the
/// beginning of `buf`, or `None` when `buf` is too short to hold the full
/// integer (more bytes are required before it can be decoded).
///
/// This lets a streaming parser tell a truncated integer (wait for more
/// bytes) apart from a malformed one (the integer's own continuation bytes
/// are present but invalid) without attempting the decode.
#[allow(dead_code)]
#[inline]
pub(crate) fn encoded_len(buf: &[u8], prefix_bits: u8) -> Option<usize> {
    let mask = (1u64 << prefix_bits) - 1;
    let first = *buf.first()?;
    if (u64::from(first) & mask) < mask {
        return Some(1);
    }
    let mut len = 1;
    loop {
        let b = *buf.get(len)?;
        len += 1;
        if b & 0x80 == 0 {
            return Some(len);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_with_prefix() {
        // RFC 7541 C.1.1: 10 with a 5-bit prefix.
        let mut out = Vec::new();
        encode(&mut out, 10, 5, 0);
        assert_eq!(out, [0x0a]);

        // C.1.2: 1337 with a 5-bit prefix.
        out.clear();
        encode(&mut out, 1337, 5, 0);
        assert_eq!(out, [0x1f, 0x9a, 0x0a]);

        // C.1.3: 42 starting at octet boundary with an 8-bit prefix.
        out.clear();
        encode(&mut out, 42, 8, 0);
        assert_eq!(out, [0x2a]);
    }

    #[test]
    fn preserves_header_bits() {
        // The representation bits (0x80: Huffman flag) survive encoding.
        let mut out = Vec::new();
        encode(&mut out, 5, 7, 0x80);
        assert_eq!(out, [0x85]);
        out.clear();
        encode(&mut out, 0, 7, 0x80);
        assert_eq!(out, [0x80]);
        out.clear();
        encode(&mut out, 127, 7, 0x80);
        assert_eq!(out, [0xff, 0x00]);
    }

    #[test]
    fn round_trip() {
        for &(bits, value) in &[
            (5, 0u64),
            (5, 30),
            (5, 31),
            (5, 1337),
            (5, (1 << 62) - 1),
            (6, 62),
            (6, 63),
            (6, 10_000),
            (7, 127),
            (7, 128),
            (7, 1 << 24),
            (7, 1 << 40),
            (7, (1 << 62) - 1),
            (8, 255),
            (8, 256),
        ] {
            let mut out = Vec::new();
            encode(&mut out, value, bits, 0);
            let mut off = 1;
            assert_eq!(decode(&out, &mut off, bits, out[0]).unwrap(), value);
            assert_eq!(off, out.len(), "value {value}");
        }
    }

    #[test]
    fn rejects_values_beyond_62_bits() {
        // QPACK decoders only need to support up to 62-bit integers
        // (RFC 9204 Section 4.1.1): encoding still works for any u64, but a
        // 64-bit value must be rejected on decode.
        let mut out = Vec::new();
        encode(&mut out, u64::MAX, 5, 0);
        let mut off = 1;
        assert_eq!(
            decode(&out, &mut off, 5, out[0]),
            Err(HpackError::InvalidInteger)
        );
        // Mid-range 63-bit values are also out of scope: 2^62 needs 63 bits.
        out.clear();
        encode(&mut out, 1 << 62, 5, 0);
        let mut off = 1;
        assert_eq!(
            decode(&out, &mut off, 5, out[0]),
            Err(HpackError::InvalidInteger)
        );
    }

    #[test]
    fn round_trip_qpack_prefix_sizes() {
        // QPACK uses 3, 4, 5 and 6-bit prefixes (string literals, indexes).
        for prefix_bits in 2..=8u8 {
            let mut out = Vec::new();
            encode(
                &mut out,
                2u64.pow(u32::from(prefix_bits)) + 123,
                prefix_bits,
                0,
            );
            let mut off = 1;
            assert_eq!(
                decode(&out, &mut off, prefix_bits, out[0]).unwrap(),
                2u64.pow(u32::from(prefix_bits)) + 123
            );
            assert_eq!(off, out.len(), "prefix_bits {prefix_bits}");
        }
    }

    #[test]
    fn rejects_truncated() {
        let mut out = Vec::new();
        encode(&mut out, 1337, 5, 0);
        // Chop the continuation octets.
        let mut off = 1;
        let header = 0x1f;
        assert!(decode(&out[..1], &mut off, 5, header).is_err());
    }

    #[test]
    fn rejects_overflow() {
        // Continuation octets that would overflow u64: all-ones chunks.
        let buf = [
            0x1f, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f,
        ];
        let mut off = 1;
        assert_eq!(
            decode(&buf, &mut off, 5, buf[0]),
            Err(HpackError::InvalidInteger)
        );
    }
}
