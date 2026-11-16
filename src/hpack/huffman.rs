//! HPACK Huffman coding (RFC 7541 Appendix B).
//!
//! Encoding walks the 257-symbol code table; decoding walks a precomputed
//! finite-state machine that consumes one encoded byte per table
//! lookup (vs. one bit per walk in a binary tree).

use super::huffman_table::HUFF_DFA8;
use super::HpackError;

// __HPACK_HUFFMAN_TABLE__

// The code table data below is specified by RFC 7541 Appendix B; the
// literal formatting is taken from the MIT-licensed `h2` crate's generated
// `hpack/huffman/table.rs` (<https://github.com/hyperium/h2>). The 4-bit
// decode DFA in `huffman_table.rs` is ported from ls-hpack
// (<https://github.com/litespeedtech/ls-hpack>), which uses the same RFC
// code table.

/// (bit length, code, most-significant bit first). Entry 256 is EOS.
const CODES: [(u8, u32); 257] = [
    (13, 0x1FF8),
    (23, 0x007FFFD8),
    (28, 0x0FFFFFE2),
    (28, 0x0FFFFFE3),
    (28, 0x0FFFFFE4),
    (28, 0x0FFFFFE5),
    (28, 0x0FFFFFE6),
    (28, 0x0FFFFFE7),
    (28, 0x0FFFFFE8),
    (24, 0x00FFFFEA),
    (30, 0x3FFFFFFC),
    (28, 0x0FFFFFE9),
    (28, 0x0FFFFFEA),
    (30, 0x3FFFFFFD),
    (28, 0x0FFFFFEB),
    (28, 0x0FFFFFEC),
    (28, 0x0FFFFFED),
    (28, 0x0FFFFFEE),
    (28, 0x0FFFFFEF),
    (28, 0x0FFFFFF0),
    (28, 0x0FFFFFF1),
    (28, 0x0FFFFFF2),
    (30, 0x3FFFFFFE),
    (28, 0x0FFFFFF3),
    (28, 0x0FFFFFF4),
    (28, 0x0FFFFFF5),
    (28, 0x0FFFFFF6),
    (28, 0x0FFFFFF7),
    (28, 0x0FFFFFF8),
    (28, 0x0FFFFFF9),
    (28, 0x0FFFFFFA),
    (28, 0x0FFFFFFB),
    (6, 0x14),
    (10, 0x3F8),
    (10, 0x3F9),
    (12, 0xFFA),
    (13, 0x1FF9),
    (6, 0x15),
    (8, 0xF8),
    (11, 0x7FA),
    (10, 0x3FA),
    (10, 0x3FB),
    (8, 0xF9),
    (11, 0x7FB),
    (8, 0xFA),
    (6, 0x16),
    (6, 0x17),
    (6, 0x18),
    (5, 0x0),
    (5, 0x1),
    (5, 0x2),
    (6, 0x19),
    (6, 0x1A),
    (6, 0x1B),
    (6, 0x1C),
    (6, 0x1D),
    (6, 0x1E),
    (6, 0x1F),
    (7, 0x5C),
    (8, 0xFB),
    (15, 0x7FFC),
    (6, 0x20),
    (12, 0xFFB),
    (10, 0x3FC),
    (13, 0x1FFA),
    (6, 0x21),
    (7, 0x5D),
    (7, 0x5E),
    (7, 0x5F),
    (7, 0x60),
    (7, 0x61),
    (7, 0x62),
    (7, 0x63),
    (7, 0x64),
    (7, 0x65),
    (7, 0x66),
    (7, 0x67),
    (7, 0x68),
    (7, 0x69),
    (7, 0x6A),
    (7, 0x6B),
    (7, 0x6C),
    (7, 0x6D),
    (7, 0x6E),
    (7, 0x6F),
    (7, 0x70),
    (7, 0x71),
    (7, 0x72),
    (8, 0xFC),
    (7, 0x73),
    (8, 0xFD),
    (13, 0x1FFB),
    (19, 0x7FFF0),
    (13, 0x1FFC),
    (14, 0x3FFC),
    (6, 0x22),
    (15, 0x7FFD),
    (5, 0x3),
    (6, 0x23),
    (5, 0x4),
    (6, 0x24),
    (5, 0x5),
    (6, 0x25),
    (6, 0x26),
    (6, 0x27),
    (5, 0x6),
    (7, 0x74),
    (7, 0x75),
    (6, 0x28),
    (6, 0x29),
    (6, 0x2A),
    (5, 0x7),
    (6, 0x2B),
    (7, 0x76),
    (6, 0x2C),
    (5, 0x8),
    (5, 0x9),
    (6, 0x2D),
    (7, 0x77),
    (7, 0x78),
    (7, 0x79),
    (7, 0x7A),
    (7, 0x7B),
    (15, 0x7FFE),
    (11, 0x7FC),
    (14, 0x3FFD),
    (13, 0x1FFD),
    (28, 0x0FFFFFFC),
    (20, 0xFFFE6),
    (22, 0x003FFFD2),
    (20, 0xFFFE7),
    (20, 0xFFFE8),
    (22, 0x003FFFD3),
    (22, 0x003FFFD4),
    (22, 0x003FFFD5),
    (23, 0x007FFFD9),
    (22, 0x003FFFD6),
    (23, 0x007FFFDA),
    (23, 0x007FFFDB),
    (23, 0x007FFFDC),
    (23, 0x007FFFDD),
    (23, 0x007FFFDE),
    (24, 0x00FFFFEB),
    (23, 0x007FFFDF),
    (24, 0x00FFFFEC),
    (24, 0x00FFFFED),
    (22, 0x003FFFD7),
    (23, 0x007FFFE0),
    (24, 0x00FFFFEE),
    (23, 0x007FFFE1),
    (23, 0x007FFFE2),
    (23, 0x007FFFE3),
    (23, 0x007FFFE4),
    (21, 0x001FFFDC),
    (22, 0x003FFFD8),
    (23, 0x007FFFE5),
    (22, 0x003FFFD9),
    (23, 0x007FFFE6),
    (23, 0x007FFFE7),
    (24, 0x00FFFFEF),
    (22, 0x003FFFDA),
    (21, 0x001FFFDD),
    (20, 0xFFFE9),
    (22, 0x003FFFDB),
    (22, 0x003FFFDC),
    (23, 0x007FFFE8),
    (23, 0x007FFFE9),
    (21, 0x001FFFDE),
    (23, 0x007FFFEA),
    (22, 0x003FFFDD),
    (22, 0x003FFFDE),
    (24, 0x00FFFFF0),
    (21, 0x001FFFDF),
    (22, 0x003FFFDF),
    (23, 0x007FFFEB),
    (23, 0x007FFFEC),
    (21, 0x001FFFE0),
    (21, 0x001FFFE1),
    (22, 0x003FFFE0),
    (21, 0x001FFFE2),
    (23, 0x007FFFED),
    (22, 0x003FFFE1),
    (23, 0x007FFFEE),
    (23, 0x007FFFEF),
    (20, 0xFFFEA),
    (22, 0x003FFFE2),
    (22, 0x003FFFE3),
    (22, 0x003FFFE4),
    (23, 0x007FFFF0),
    (22, 0x003FFFE5),
    (22, 0x003FFFE6),
    (23, 0x007FFFF1),
    (26, 0x03FFFFE0),
    (26, 0x03FFFFE1),
    (20, 0xFFFEB),
    (19, 0x7FFF1),
    (22, 0x003FFFE7),
    (23, 0x007FFFF2),
    (22, 0x003FFFE8),
    (25, 0x01FFFFEC),
    (26, 0x03FFFFE2),
    (26, 0x03FFFFE3),
    (26, 0x03FFFFE4),
    (27, 0x07FFFFDE),
    (27, 0x07FFFFDF),
    (26, 0x03FFFFE5),
    (24, 0x00FFFFF1),
    (25, 0x01FFFFED),
    (19, 0x7FFF2),
    (21, 0x001FFFE3),
    (26, 0x03FFFFE6),
    (27, 0x07FFFFE0),
    (27, 0x07FFFFE1),
    (26, 0x03FFFFE7),
    (27, 0x07FFFFE2),
    (24, 0x00FFFFF2),
    (21, 0x001FFFE4),
    (21, 0x001FFFE5),
    (26, 0x03FFFFE8),
    (26, 0x03FFFFE9),
    (28, 0x0FFFFFFD),
    (27, 0x07FFFFE3),
    (27, 0x07FFFFE4),
    (27, 0x07FFFFE5),
    (20, 0xFFFEC),
    (24, 0x00FFFFF3),
    (20, 0xFFFED),
    (21, 0x001FFFE6),
    (22, 0x003FFFE9),
    (21, 0x001FFFE7),
    (21, 0x001FFFE8),
    (23, 0x007FFFF3),
    (22, 0x003FFFEA),
    (22, 0x003FFFEB),
    (25, 0x01FFFFEE),
    (25, 0x01FFFFEF),
    (24, 0x00FFFFF4),
    (24, 0x00FFFFF5),
    (26, 0x03FFFFEA),
    (23, 0x007FFFF4),
    (26, 0x03FFFFEB),
    (27, 0x07FFFFE6),
    (26, 0x03FFFFEC),
    (26, 0x03FFFFED),
    (27, 0x07FFFFE7),
    (27, 0x07FFFFE8),
    (27, 0x07FFFFE9),
    (27, 0x07FFFFEA),
    (27, 0x07FFFFEB),
    (28, 0x0FFFFFFE),
    (27, 0x07FFFFEC),
    (27, 0x07FFFFED),
    (27, 0x07FFFFEE),
    (27, 0x07FFFFEF),
    (27, 0x07FFFFF0),
    (26, 0x03FFFFEE),
    (30, 0x3FFFFFFF),
];

/// Encodes `src` using the RFC 7541 Huffman code, appending the encoded
/// bytes (with EOS-prefix padding to the octet boundary) to `dst`.
#[inline]
#[cfg(test)]
pub(crate) fn encode(src: &[u8], dst: &mut Vec<u8>) {
    let encoded_len = encoded_len(src).div_ceil(8);
    dst.reserve(encoded_len);
    encode_with_len(src, dst, encoded_len);
}

/// Encodes `src` when its encoded byte length is already known.
///
/// String-literal encoding calculates this length to choose between raw and
/// Huffman forms, so accepting it here avoids a second pass over the input.
#[inline]
pub(crate) fn encode_with_len(src: &[u8], dst: &mut Vec<u8>, encoded_len: usize) {
    let dst_start = dst.len();
    let mut bits: u64 = 0;
    let mut nbits: u32 = 0;
    for &b in src {
        let (len, code) = CODES[b as usize];
        bits = (bits << len) | u64::from(code);
        nbits += u32::from(len);

        if nbits >= 32 {
            nbits -= 32;
            dst.extend_from_slice(&((bits >> nbits) as u32).to_be_bytes());
            bits &= (1u64 << nbits) - 1;
        }
    }
    if nbits > 0 {
        let byte_len = nbits.div_ceil(8) as usize;
        let padded = (bits << (32 - nbits)) | ((1u64 << (32 - nbits)) - 1);
        let bytes = (padded as u32).to_be_bytes();
        dst.extend_from_slice(&bytes[..byte_len]);
    }
    debug_assert_eq!(dst.len() - dst_start, encoded_len);
}

/// The number of bits needed to Huffman-encode `src`.
#[inline]
pub(crate) fn encoded_len(src: &[u8]) -> usize {
    src.iter().map(|&b| usize::from(CODES[b as usize].0)).sum()
}

/// Decodes a Huffman-encoded string into `dst` (which is cleared first).
///
/// This uses the 8-bit DFA ([`HUFF_DFA8`]), which advances one byte per lookup
/// (built at compile time from the 4-bit DFA), so each encoded byte costs
/// a single table lookup instead of the eight a bit-by-bit walk would need.
#[inline]
pub(crate) fn decode(src: &[u8], dst: &mut Vec<u8>) -> Result<(), HpackError> {
    dst.clear();
    // The shortest HPACK Huffman code is five bits, so this is enough for
    // every valid input while avoiding the repeated growth caused by the old
    // `src.len() / 2` estimate.
    dst.reserve(
        src.len()
            .saturating_add(src.len() / 2)
            .saturating_add(src.len() / 8)
            .saturating_add(1),
    );
    let mut state: usize = 0;
    let mut accepted = true;
    for &byte in src {
        // One lookup for the whole byte (Huffman bits are most-significant first).
        let el = HUFF_DFA8[(state << 8) | byte as usize];
        if el.1 & 0x04 != 0 {
            return Err(HpackError::InvalidHuffman);
        }
        if el.1 & 0x02 != 0 {
            dst.push(el.2[0]);
        }
        if el.1 & 0x01 != 0 {
            dst.push(el.2[1]);
        }
        accepted = el.1 & 0x08 != 0;
        state = el.0 as usize;
    }
    if !accepted {
        return Err(HpackError::InvalidHuffman);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dec(src: &[u8]) -> Result<Vec<u8>, HpackError> {
        let mut out = Vec::new();
        decode(src, &mut out)?;
        Ok(out)
    }

    #[test]
    fn rfc_sanity_vector() {
        // RFC 7541 Appendix B example.
        let mut out = Vec::new();
        encode(b"www.example.com", &mut out);
        assert_eq!(
            out,
            [0xf1, 0xe3, 0xc2, 0xe5, 0xf2, 0x3a, 0x6b, 0xa0, 0xab, 0x90, 0xf4, 0xff]
        );
        assert_eq!(dec(&out).unwrap(), b"www.example.com");
    }

    #[test]
    fn single_byte_symbols() {
        // From the h2 crate's huffman tests.
        assert_eq!(dec(&[0b00111111]).unwrap(), b"o");
        assert_eq!(dec(&[7]).unwrap(), b"0");
        assert_eq!(dec(&[(0x21 << 2) + 3]).unwrap(), b"A");
    }

    #[test]
    fn round_trip_all_bytes() {
        let all: Vec<u8> = (0..=255u8).collect();
        let mut enc = Vec::new();
        encode(&all, &mut enc);
        assert_eq!(dec(&enc).unwrap(), all);
    }

    #[test]
    fn round_trip_common_strings() {
        for s in [
            "",
            "GET",
            "https",
            "example.com",
            "/index.html",
            "application/json; charset=utf-8",
            "xyzzy",
            "The quick brown fox jumps over the lazy dog",
        ] {
            let mut enc = Vec::new();
            encode(s.as_bytes(), &mut enc);
            assert_eq!(dec(&enc).unwrap(), s.as_bytes(), "round trip {s}");
        }
    }

    #[test]
    fn padding_ones_accepted() {
        // 'A' (100001, 6 bits) + 2 padding 1-bits.
        assert_eq!(dec(&[0x87]).unwrap(), b"A");
    }

    #[test]
    fn eos_symbol_rejected() {
        // The full EOS code (30 1-bits).
        assert_eq!(dec(&[0xff; 4]).unwrap_err(), HpackError::InvalidHuffman);
        // EOS inside data.
        assert_eq!(
            dec(&[0xff, 0xff, 0xff, 0xfc, 0x87]).unwrap_err(),
            HpackError::InvalidHuffman
        );
    }

    #[test]
    fn padding_over_7_bits_rejected() {
        // 'A' + 8 padding 1-bits: padding strictly longer than 7 bits.
        assert_eq!(
            dec(&[0x87, 0x87, 0xff]).unwrap_err(),
            HpackError::InvalidHuffman
        );
    }

    #[test]
    fn padding_not_eos_prefix_rejected() {
        // 'A' followed by 0-bits: '0' (00000) decodes, then 3 zero bits are
        // not a prefix of the EOS code.
        assert_eq!(dec(&[0x87, 0x00]).unwrap_err(), HpackError::InvalidHuffman);
    }

    #[test]
    fn truncated_code_rejected() {
        // 11000000: nothing completes and the trailing bits exceed 7.
        assert_eq!(dec(&[0xc0]).unwrap_err(), HpackError::InvalidHuffman);
        // An over-long run of 1-bits never completes.
        assert_eq!(dec(&[0xff, 0xff]).unwrap_err(), HpackError::InvalidHuffman);
    }

    #[test]
    fn empty_input() {
        assert_eq!(dec(&[]).unwrap(), b"");
    }

    #[test]
    fn encoded_len_matches_output() {
        let data = b"www.example.com\x00\xff";
        let mut enc = Vec::new();
        encode(data, &mut enc);
        assert_eq!(encoded_len(data).div_ceil(8), enc.len());
    }
}
