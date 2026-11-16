//! HPACK string literals (RFC 7541 Section 5.2).

use super::{huffman, integer, HpackError};

/// The Huffman-flag bit in the string literal length octet.
const HUFFMAN_FLAG: u8 = 0x80;

/// The length in octets of the Huffman form of `value`.
#[inline]
#[cfg(test)]
pub(crate) fn huffman_encoded_len(value: &[u8]) -> usize {
    huffman::encoded_len(value).div_ceil(8)
}

/// The Huffman byte length when the Huffman bit sequence is shorter than the
/// raw literal. HPACK's selection rule compares the unpadded bit lengths, so
/// a same-size-on-the-wire literal can still use Huffman coding.
#[inline]
pub(crate) fn huffman_encoded_len_if_shorter(value: &[u8]) -> Option<usize> {
    let bit_len = huffman::encoded_len(value);
    (bit_len < value.len().saturating_mul(8)).then(|| bit_len.div_ceil(8))
}

/// Encodes a string literal (raw or Huffman-coded) into `out`.
///
/// When `huffman_len` is present, the literal is Huffman-coded (honoring the
/// flag even for empty values); otherwise it is written as-is.
#[inline]
pub(crate) fn encode(out: &mut Vec<u8>, value: &[u8], huffman_len: Option<usize>) {
    if let Some(huffman_len) = huffman_len {
        // Integer prefix (<=5 octets) plus the exact Huffman body length.
        out.reserve(5usize.saturating_add(huffman_len));
        integer::encode(out, huffman_len as u64, 7, HUFFMAN_FLAG);
        huffman::encode_with_len(value, out, huffman_len);
    } else {
        out.reserve(8 + value.len());
        integer::encode(out, value.len() as u64, 7, 0);
        out.extend_from_slice(value);
    }
}

/// Decodes a string literal from `buf` at `off`, enforcing a maximum
/// decoded length. Returns whether the literal was Huffman-coded.
#[inline]
pub(crate) fn decode(
    buf: &[u8],
    off: &mut usize,
    max_length: usize,
) -> Result<(bool, Vec<u8>), HpackError> {
    let first = *buf.get(*off).ok_or(HpackError::InvalidString)?;
    *off += 1;
    let len = integer::decode(buf, off, 7, first)? as usize;
    if len > max_length {
        return Err(HpackError::InvalidString);
    }
    let end = off.checked_add(len).ok_or(HpackError::InvalidString)?;
    let slice = buf.get(*off..end).ok_or(HpackError::InvalidString)?;
    *off = end;

    if first & HUFFMAN_FLAG != 0 {
        let mut value = Vec::with_capacity(len);
        huffman::decode(slice, &mut value)?;
        if value.len() > max_length {
            return Err(HpackError::InvalidString);
        }
        Ok((true, value))
    } else {
        Ok((false, slice.to_vec()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip() {
        for (value, huffman) in [
            (b"".as_slice(), false),
            (b"", true),
            (b"custom-key", false),
            (b"custom-key", true),
            (b"custom-huffman", true),
            (b"x", true),
            (&[0u8; 3], false),
            (&[0u8; 3], true),
        ] {
            let mut out = Vec::new();
            encode(&mut out, value, huffman.then(|| huffman_encoded_len(value)));
            let mut off = 0;
            let (was_huffman, decoded) = decode(&out, &mut off, 1024).unwrap();
            assert_eq!(was_huffman, huffman);
            assert_eq!(decoded, value);
            assert_eq!(off, out.len());
        }
    }

    #[test]
    fn empty_huffman_flag_keeps_flag() {
        let mut out = Vec::new();
        encode(&mut out, b"", Some(0));
        assert_eq!(out, [0x80]);
        let mut off = 0;
        assert_eq!(decode(&out, &mut off, 16).unwrap(), (true, vec![]));
    }

    #[test]
    fn decode_enforces_max_length() {
        let mut out = Vec::new();
        encode(&mut out, b"toolong", None);
        let mut off = 0;
        assert!(matches!(
            decode(&out, &mut off, 3),
            Err(HpackError::InvalidString)
        ));

        let mut out = Vec::new();
        encode(
            &mut out,
            b"0123456789",
            Some(huffman_encoded_len(b"0123456789")),
        );
        let mut off = 0;
        assert!(decode(&out, &mut off, 9).is_err());
    }
}
