//! HPACK decoder (RFC 7541 Section 6).
//!
//! Decodes a complete header block (HEADERS plus any CONTINUATION frames,
//! already assembled by the caller) into a header list, maintaining the
//! dynamic table across blocks.

use super::{
    integer, string,
    table::{Header, Table},
    HpackError,
};
use bytes::Bytes;

/// The representation prefixes defined in RFC 7541 Section 6.
const INDEXED: u8 = 0b1000_0000;
const LITERAL_WITH_INDEXING: u8 = 0b0100_0000;
const LITERAL_WITHOUT_INDEXING: u8 = 0b1111_0000;
const LITERAL_NEVER_INDEXED: u8 = 0b0001_0000;
const SIZE_UPDATE_MASK: u8 = 0b1110_0000;
const SIZE_UPDATE: u8 = 0b0010_0000;

/// Decodes HPACK header blocks.
#[derive(Debug)]
pub struct Decoder {
    /// Static + dynamic header table.
    table: Table,
    /// The maximum table size allowed by the protocol
    /// (`SETTINGS_HEADER_TABLE_SIZE`). Size updates above this are an
    /// error.
    max_table_size: usize,
    /// A size update queued by the protocol layer (SETTINGS) and applied
    /// at the start of the next decode.
    queued_size_update: Option<usize>,
    /// Cap on the total size of a decoded header list (sum of name and
    /// value octets). Exceeding it is an error.
    max_header_list_size: usize,
}

impl Decoder {
    /// Creates a decoder with the given protocol maximum table size
    /// (RFC 7541 Section 4.2: 4096 by default).
    #[inline]
    pub fn new(max_table_size: usize) -> Self {
        Decoder {
            table: Table::with_max_size_no_maps(max_table_size),
            max_table_size,
            queued_size_update: None,
            max_header_list_size: usize::MAX,
        }
    }

    /// Queues a protocol-level table size update (from SETTINGS) to be
    /// applied at the start of the next header block.
    #[inline]
    pub fn queue_size_update(&mut self, size: usize) {
        self.queued_size_update = Some(match self.queued_size_update {
            Some(current) => current.max(size),
            None => size,
        });
    }

    /// Sets the maximum size of a decoded header list. Headers blocks
    /// whose cumulative name+value octets exceed this are rejected.
    #[inline]
    pub fn set_max_header_list_size(&mut self, size: usize) {
        self.max_header_list_size = size;
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn table(&self) -> &Table {
        &self.table
    }

    /// Decodes a complete header block. The dynamic table is updated
    /// across calls.
    #[inline]
    pub fn decode(&mut self, buf: &[u8], list_size: &mut usize) -> Result<Vec<Header>, HpackError> {
        if let Some(size) = self.queued_size_update.take() {
            self.max_table_size = size;
            // The table capacity itself is driven by size-update
            // representations in the wire; the queued value only raises
            // the protocol cap.
        }

        let mut off = 0usize;
        let mut headers = Vec::with_capacity(buf.len() / 3);
        // Size updates must precede any header field representation
        // (RFC 7541 Section 6.3).
        let mut can_resize = true;

        while off < buf.len() {
            let byte = buf[off];
            // The first octet carries the representation prefix and part
            // of the index/size; `integer::decode` reads on from here.
            off += 1;
            let rep = Representation::load(byte)?;
            match rep {
                Representation::Indexed => {
                    can_resize = false;
                    let index = integer::decode(buf, &mut off, 7, byte)? as usize;
                    let entry = self.table.get(index).ok_or(HpackError::InvalidIndex)?;
                    *list_size += entry.name().len() + entry.value().len();
                    if *list_size > self.max_header_list_size {
                        return Err(HpackError::HeaderListTooLarge);
                    }
                    headers.push(entry);
                }
                Representation::LiteralWithIndexing
                | Representation::LiteralWithoutIndexing
                | Representation::LiteralNeverIndexed => {
                    can_resize = false;
                    let index = integer::decode(
                        buf,
                        &mut off,
                        if rep == Representation::LiteralWithIndexing {
                            6
                        } else {
                            4
                        },
                        byte,
                    )? as usize;

                    // Name: from the table when index > 0, else literal.
                    let name = if index == 0 {
                        let (_, name) = string::decode(buf, &mut off, self.max_header_list_size)?;
                        Bytes::from(name)
                    } else {
                        let entry = self.table.get(index).ok_or(HpackError::InvalidIndex)?;
                        Bytes::copy_from_slice(entry.name())
                    };

                    let (_, value) = string::decode(buf, &mut off, self.max_header_list_size)?;

                    *list_size += name.len() + value.len();
                    if *list_size > self.max_header_list_size {
                        return Err(HpackError::HeaderListTooLarge);
                    }

                    let header = Header::new(name, value);
                    if rep == Representation::LiteralWithIndexing {
                        self.table.add(header.clone());
                    }
                    headers.push(header);
                }
                Representation::SizeUpdate => {
                    if !can_resize {
                        return Err(HpackError::InvalidMaxSize);
                    }
                    let size = integer::decode(buf, &mut off, 5, byte)? as usize;
                    if size > self.max_table_size {
                        return Err(HpackError::InvalidMaxSize);
                    }
                    self.table.set_max_size(size);
                }
            }
        }

        Ok(headers)
    }
}

impl Default for Decoder {
    #[inline]
    fn default() -> Self {
        Decoder::new(4096)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Representation {
    Indexed,
    LiteralWithIndexing,
    LiteralWithoutIndexing,
    LiteralNeverIndexed,
    SizeUpdate,
}

impl Representation {
    #[inline]
    fn load(byte: u8) -> Result<Representation, HpackError> {
        if byte & INDEXED == INDEXED {
            Ok(Representation::Indexed)
        } else if byte & LITERAL_WITH_INDEXING == LITERAL_WITH_INDEXING {
            Ok(Representation::LiteralWithIndexing)
        } else if byte & LITERAL_WITHOUT_INDEXING == 0 {
            Ok(Representation::LiteralWithoutIndexing)
        } else if byte & LITERAL_WITHOUT_INDEXING == LITERAL_NEVER_INDEXED {
            Ok(Representation::LiteralNeverIndexed)
        } else if byte & SIZE_UPDATE_MASK == SIZE_UPDATE {
            Ok(Representation::SizeUpdate)
        } else {
            Err(HpackError::InvalidRepresentation)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    fn decode_one(wire: &[u8]) -> Vec<(String, String)> {
        let mut decoder = Decoder::new(4096);
        decoder
            .decode(wire, &mut 0)
            .unwrap()
            .into_iter()
            .map(|h| {
                (
                    String::from_utf8(h.name().to_vec()).unwrap(),
                    String::from_utf8(h.value().to_vec()).unwrap(),
                )
            })
            .collect()
    }

    /// RFC 7541 C.2.1: literal with incremental indexing, new name.
    #[test]
    fn literal_new_name_indexed() {
        let wire = [
            0x40, 0x0a, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x0d, b'c',
            b'u', b's', b't', b'o', b'm', b'-', b'h', b'e', b'a', b'd', b'e', b'r',
        ];
        assert_eq!(
            decode_one(&wire),
            vec![("custom-key".into(), "custom-header".into())]
        );
    }

    /// RFC 7541 C.2.2: literal without indexing, indexed name.
    #[test]
    fn literal_without_indexing_indexed_name() {
        let wire = [
            0x04, 0x0c, b'/', b's', b'a', b'm', b'p', b'l', b'e', b'/', b'p', b'a', b't', b'h',
        ];
        assert_eq!(
            decode_one(&wire),
            vec![(":path".into(), "/sample/path".into())]
        );
    }

    /// RFC 7541 C.2.3: literal never indexed, new name.
    #[test]
    fn literal_never_indexed() {
        let wire = [
            0x10, 0x08, b'p', b'a', b's', b's', b'w', b'o', b'r', b'd', 0x06, b's', b'e', b'c',
            b'r', b'e', b't',
        ];
        assert_eq!(
            decode_one(&wire),
            vec![("password".into(), "secret".into())]
        );
    }

    /// RFC 7541 C.2.4: indexed header field.
    #[test]
    fn indexed() {
        assert_eq!(decode_one(&[0x82]), vec![(":method".into(), "GET".into())]);
    }

    /// RFC 7541 C.2.4: table state after indexed + literal.
    #[test]
    fn table_state_after_representations() {
        let mut decoder = Decoder::new(4096);
        let _ = decoder.decode(&[0x82], &mut 0).unwrap();
        assert_eq!(decoder.table().dynamic_len(), 0);
        // 0x40 + custom-key + custom-header adds an entry.
        let wire = [
            0x40, 0x0a, b'c', b'u', b's', b't', b'o', b'm', b'-', b'k', b'e', b'y', 0x0d, b'c',
            b'u', b's', b't', b'o', b'm', b'-', b'h', b'e', b'a', b'd', b'e', b'r',
        ];
        let _ = decoder.decode(&wire, &mut 0).unwrap();
        assert_eq!(decoder.table().dynamic_len(), 1);
        assert_eq!(decoder.table().get(62).unwrap().name(), b"custom-key");
    }

    /// RFC 7541 C.3.1: full request block without Huffman.
    #[test]
    fn c3_1_request_without_huffman() {
        // 8286 8441 0f77 7777 2e65 7861 6d70 6c65 2e63 6f6d
        let wire = hex_to_bytes("828684410f7777772e6578616d706c652e636f6d");
        assert_eq!(
            decode_one(&wire),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
    }

    /// RFC 7541 C.4.1: full request block with Huffman.
    #[test]
    fn c4_1_request_with_huffman() {
        let wire = hex_to_bytes("828684418cf1e3c2e5f23a6ba0ab90f4ff");
        assert_eq!(
            decode_one(&wire),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
            ]
        );
    }

    /// RFC 7541 C.3.2/C.3.3: second/third request of the C.3 connection
    /// (no Huffman); C.4.2/C.4.3: the same for the C.4 connection
    /// (Huffman). Each connection starts with its C.x.1 block.
    #[test]
    fn c3_c4_sequential_requests() {
        let block = |d: &mut Decoder, wire: &str| {
            d.decode(&hex_to_bytes(wire), &mut 0)
                .unwrap()
                .into_iter()
                .map(|h| {
                    (
                        String::from_utf8(h.name().to_vec()).unwrap(),
                        String::from_utf8(h.value().to_vec()).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        };

        let mut decoder = Decoder::new(4096);
        let _ = block(&mut decoder, "828684410f7777772e6578616d706c652e636f6d");

        // C.3.2: references :authority: www.example.com at dynamic 62.
        assert_eq!(
            block(&mut decoder, "828684be58086e6f2d6361636865"),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
                ("cache-control".into(), "no-cache".into()),
            ]
        );

        // C.3.3: references cache-control: no-cache at 62, :authority at
        // 63, then a literal new name.
        assert_eq!(
            block(
                &mut decoder,
                "828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565",
            ),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":path".into(), "/index.html".into()),
                (":authority".into(), "www.example.com".into()),
                ("custom-key".into(), "custom-value".into()),
            ]
        );

        let mut decoder = Decoder::new(4096);
        let _ = block(&mut decoder, "828684418cf1e3c2e5f23a6ba0ab90f4ff");

        // C.4.2: references :authority: www.example.com at dynamic 62.
        assert_eq!(
            block(&mut decoder, "828684be5886a8eb10649cbf"),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "http".into()),
                (":path".into(), "/".into()),
                (":authority".into(), "www.example.com".into()),
                ("cache-control".into(), "no-cache".into()),
            ]
        );

        // C.4.3: references :authority at 63, then a literal new name.
        assert_eq!(
            block(
                &mut decoder,
                "828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf"
            ),
            vec![
                (":method".into(), "GET".into()),
                (":scheme".into(), "https".into()),
                (":path".into(), "/index.html".into()),
                (":authority".into(), "www.example.com".into()),
                ("custom-key".into(), "custom-value".into()),
            ]
        );
    }

    /// RFC 7541 C.5: response walkthrough without Huffman, dynamic
    /// table capped at 256 octets so evictions occur.
    #[test]
    fn c5_response_walkthrough() {
        let mut decoder = Decoder::new(256);
        let block = |d: &mut Decoder, wire: &str| {
            d.decode(&hex_to_bytes(wire), &mut 0)
                .unwrap()
                .into_iter()
                .map(|h| {
                    (
                        String::from_utf8(h.name().to_vec()).unwrap(),
                        String::from_utf8(h.value().to_vec()).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        };

        // C.5.1: first response.
        let first = vec![
            (":status".into(), "302".into()),
            ("cache-control".into(), "private".into()),
            ("date".into(), "Mon, 21 Oct 2013 20:13:21 GMT".into()),
            ("location".into(), "https://www.example.com".into()),
        ];
        assert_eq!(
            block(&mut decoder, "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d"),
            first
        );
        assert_eq!(decoder.table().dynamic_len(), 4);

        // C.5.2: second response; :status: 302 evicted to make room.
        let second = vec![
            (":status".into(), "307".into()),
            ("cache-control".into(), "private".into()),
            ("date".into(), "Mon, 21 Oct 2013 20:13:21 GMT".into()),
            ("location".into(), "https://www.example.com".into()),
        ];
        assert_eq!(block(&mut decoder, "4803333037c1c0bf"), second);
        assert_eq!(decoder.table().dynamic_len(), 4);

        // C.5.3: third response; several entries evicted.
        let third = vec![
            (":status".into(), "200".into()),
            ("cache-control".into(), "private".into()),
            ("date".into(), "Mon, 21 Oct 2013 20:13:22 GMT".into()),
            ("location".into(), "https://www.example.com".into()),
            ("content-encoding".into(), "gzip".into()),
            (
                "set-cookie".into(),
                "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1".into(),
            ),
        ];
        assert_eq!(
            block(
                &mut decoder,
                "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31",
            ),
            third
        );
        assert_eq!(decoder.table().dynamic_len(), 3);
    }

    /// RFC 7541 C.6: response walkthrough with Huffman, same table
    /// dynamics as C.5.
    #[test]
    fn c6_response_walkthrough() {
        let mut decoder = Decoder::new(256);
        let block = |d: &mut Decoder, wire: &str| {
            d.decode(&hex_to_bytes(wire), &mut 0)
                .unwrap()
                .into_iter()
                .map(|h| {
                    (
                        String::from_utf8(h.name().to_vec()).unwrap(),
                        String::from_utf8(h.value().to_vec()).unwrap(),
                    )
                })
                .collect::<Vec<_>>()
        };

        let first = vec![
            (":status".into(), "302".into()),
            ("cache-control".into(), "private".into()),
            ("date".into(), "Mon, 21 Oct 2013 20:13:21 GMT".into()),
            ("location".into(), "https://www.example.com".into()),
        ];
        assert_eq!(
            block(&mut decoder, "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"),
            first
        );
        assert_eq!(decoder.table().dynamic_len(), 4);

        let second = vec![
            (":status".into(), "307".into()),
            ("cache-control".into(), "private".into()),
            ("date".into(), "Mon, 21 Oct 2013 20:13:21 GMT".into()),
            ("location".into(), "https://www.example.com".into()),
        ];
        assert_eq!(block(&mut decoder, "4883640effc1c0bf"), second);
        assert_eq!(decoder.table().dynamic_len(), 4);

        let third = vec![
            (":status".into(), "200".into()),
            ("cache-control".into(), "private".into()),
            ("date".into(), "Mon, 21 Oct 2013 20:13:22 GMT".into()),
            ("location".into(), "https://www.example.com".into()),
            ("content-encoding".into(), "gzip".into()),
            (
                "set-cookie".into(),
                "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1".into(),
            ),
        ];
        assert_eq!(
            block(
                &mut decoder,
                "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007",
            ),
            third
        );
        assert_eq!(decoder.table().dynamic_len(), 3);
    }

    #[test]
    fn size_update_at_start() {
        let mut decoder = Decoder::new(4096);
        // 0x3f + continuation: size update to 4096.
        let wire = [0x3f, 0xe1, 0x1f, 0x82];
        let out = decoder.decode(&wire, &mut 0).unwrap();
        assert_eq!(out.len(), 1);
        assert_eq!(decoder.table().max_size(), 4096);
    }

    #[test]
    fn size_update_after_field_rejected() {
        let mut decoder = Decoder::new(4096);
        // Indexed (0x82) then size update (0x20).
        assert!(matches!(
            decoder.decode(&[0x82, 0x20], &mut 0),
            Err(HpackError::InvalidMaxSize)
        ));
    }

    #[test]
    fn size_update_over_protocol_max_rejected() {
        let mut decoder = Decoder::new(128);
        // Size update to 4096 while the protocol allows only 128.
        assert!(matches!(
            decoder.decode(&[0x3f, 0xe1, 0x1f], &mut 0),
            Err(HpackError::InvalidMaxSize)
        ));
    }

    #[test]
    fn invalid_table_index_rejected() {
        // Indexed field with index 0.
        assert!(matches!(decode(&[0x80]), Err(HpackError::InvalidIndex)));
    }

    #[test]
    fn index_out_of_range_rejected() {
        let mut decoder = Decoder::new(4096);
        // Index 200 (0x7f is only 127; use 0xc8 + continuation for 200).
        assert!(matches!(
            decoder.decode(&[0x7f, 0x49], &mut 0),
            Err(HpackError::InvalidIndex)
        ));
    }

    #[test]
    fn header_list_size_capped() {
        let mut decoder = Decoder::new(4096);
        decoder.set_max_header_list_size(10);
        // name "x" (1) + value of 10 octets: each string is within the
        // cap, but the list totals 11.
        let wire = [
            0x40, 0x01, b'x', 0x0a, b'y', b'y', b'y', b'y', b'y', b'y', b'y', b'y', b'y', b'y',
        ];
        assert!(matches!(
            decoder.decode(&wire, &mut 0),
            Err(HpackError::HeaderListTooLarge)
        ));
    }

    #[test]
    fn small_size_update_ok() {
        // 0x30 = size update (001xxxxx) with value 16; every octet value
        // maps to exactly one representation, so there is no invalid
        // byte to test against.
        let mut decoder = Decoder::new(4096);
        decoder.decode(&[0x30], &mut 0).unwrap();
        assert_eq!(decoder.table().max_size(), 16);
    }

    fn decode(wire: &[u8]) -> Result<Vec<Header>, HpackError> {
        let mut decoder = Decoder::new(4096);
        decoder.decode(wire, &mut 0)
    }

    fn hex_to_bytes(hex: &str) -> Vec<u8> {
        hex.as_bytes()
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
}
