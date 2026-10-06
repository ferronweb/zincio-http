//! HPACK encoder (RFC 7541 Section 6).
//!
//! Encodes a header list into a single header block, maintaining the
//! dynamic table across blocks. The encoder's table mirrors the peer's
//! decoder table: it honors the peer's `SETTINGS_HEADER_TABLE_SIZE` via
//! [`Encoder::queue_size_update`].
//!
//! Unlike the API sketch in `CUSTOM_HTTP2_IMPL.md` (`&[(HeaderName,
//! &[u8])]`), [`Encoder::encode`] takes [`Header`] pairs, because
//! `http::HeaderName` rejects HTTP/2 pseudo-headers (`:method`, ...)
//! while they are a first-class part of HPACK header blocks; it also
//! mirrors the [`Decoder`](super::decode::Decoder) API.

use super::{
    integer, string,
    table::{Header, Table},
};

/// The representation prefixes defined in RFC 7541 Section 6.
const INDEXED: u8 = 0b1000_0000;
const LITERAL_WITH_INDEXING: u8 = 0b0100_0000;
const LITERAL_NEVER_INDEXED: u8 = 0b0001_0000;
const SIZE_UPDATE: u8 = 0b0010_0000;

/// Header names that must never be added to the indexed table
/// (RFC 7541 Section 7.1.3).
const NEVER_INDEXED: [&[u8]; 3] = [b"authorization", b"proxy-authorization", b"cookie"];

/// Encodes HPACK header blocks.
#[derive(Debug)]
pub struct Encoder {
    /// Static + dynamic header table, mirroring the peer decoder.
    table: Table,
    /// A size update queued by the protocol layer (SETTINGS) and emitted
    /// at the start of the next header block.
    queued_size_update: Option<usize>,
    /// Whether string literals are Huffman-coded when shorter.
    use_huffman: bool,
}

impl Encoder {
    /// Creates an encoder whose table allows `max_table_size` octets
    /// (RFC 7541 Section 4.2: 4096 by default). This must match the
    /// peer's initial `SETTINGS_HEADER_TABLE_SIZE`.
    #[inline]
    pub fn new(max_table_size: usize) -> Self {
        Encoder {
            table: Table::with_max_size(max_table_size),
            queued_size_update: None,
            use_huffman: true,
        }
    }

    /// Queues a protocol-level table size update (from SETTINGS) to be
    /// applied and emitted at the start of the next header block.
    #[inline]
    pub fn queue_size_update(&mut self, size: usize) {
        self.queued_size_update = Some(match self.queued_size_update {
            Some(current) => current.max(size),
            None => size,
        });
    }

    /// Controls Huffman-coded string literals. Enabled by default, in
    /// which case a literal is Huffman-coded when that is shorter.
    #[inline]
    pub fn set_use_huffman(&mut self, use_huffman: bool) {
        self.use_huffman = use_huffman;
    }

    /// The current table, for inspection by in-crate tests.
    #[cfg(test)]
    #[inline]
    pub(crate) fn table(&self) -> &Table {
        &self.table
    }

    /// Encodes `headers` as a single header block appended to `out`.
    ///
    /// Non-sensitive headers are encoded with incremental indexing
    /// (RFC 7541 Section 6.2.1) and added to the dynamic table; exact
    /// matches use the indexed representation (Section 6.1). Sensitive
    /// headers ([`NEVER_INDEXED`]) are encoded never-indexed (Section
    /// 6.2.3) and never added to the table.
    #[inline]
    pub fn encode(&mut self, headers: &[Header], out: &mut Vec<u8>) {
        if let Some(size) = self.queued_size_update.take() {
            self.table.set_max_size(size);
            integer::encode(out, size as u64, 5, SIZE_UPDATE);
        }

        for header in headers {
            let name = header.name();
            if NEVER_INDEXED.contains(&name) {
                match self.table.find_name(header.name_bytes()) {
                    Some(index) => integer::encode(out, index as u64, 4, LITERAL_NEVER_INDEXED),
                    None => {
                        out.push(LITERAL_NEVER_INDEXED);
                        self.encode_string(out, name);
                    }
                }
                self.encode_string(out, header.value());
                continue;
            }

            match self.table.find(header.name_bytes(), header.value_bytes()) {
                Some(index) => {
                    integer::encode(out, index as u64, 7, INDEXED);
                }
                None => {
                    match self.table.find_name(header.name_bytes()) {
                        Some(index) => integer::encode(out, index as u64, 6, LITERAL_WITH_INDEXING),
                        None => {
                            out.push(LITERAL_WITH_INDEXING);
                            self.encode_string(out, name);
                        }
                    }
                    self.encode_string(out, header.value());
                    // Store the header by cloning its already-owned `Bytes`
                    // (a refcount bump) instead of re-copying the name and
                    // value into fresh heap allocations.
                    self.table.add(header.clone());
                }
            }
        }
    }

    #[inline]
    fn encode_string(&self, out: &mut Vec<u8>, value: &[u8]) {
        let huffman_len = self
            .use_huffman
            .then(|| string::huffman_encoded_len_if_shorter(value))
            .flatten();
        string::encode(out, value, huffman_len);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::h2::hpack::decode::Decoder;

    /// Builds a `Header` list from string tuples.
    #[inline]
    fn headers(list: &[(&str, &str)]) -> Vec<Header> {
        list.iter()
            .map(|(name, value)| Header::new(name.as_bytes().to_vec(), value.as_bytes().to_vec()))
            .collect()
    }

    #[inline]
    fn encode(encoder: &mut Encoder, list: &[(&str, &str)]) -> Vec<u8> {
        let list = headers(list);
        let mut out = Vec::with_capacity(list.len() * 3);
        encoder.encode(&list, &mut out);
        out
    }

    #[inline]
    fn decode(encoder: &Encoder, wire: &[u8]) -> Vec<(String, String)> {
        let mut decoder = Decoder::new(encoder.table().max_size());
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

    #[inline]
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

    /// RFC 7541 C.2.1: literal with incremental indexing, new name.
    #[test]
    fn literal_new_name_indexed() {
        let mut encoder = Encoder::new(4096);
        encoder.set_use_huffman(false);
        let out = encode(&mut encoder, &[("custom-key", "custom-header")]);
        assert_eq!(
            out,
            hex_to_bytes("400a637573746f6d2d6b65790d637573746f6d2d686561646572")
        );
        assert_eq!(encoder.table().dynamic_len(), 1);
    }

    /// RFC 7541 C.3: full request walkthrough without Huffman.
    #[test]
    fn c3_request_walkthrough() {
        let mut encoder = Encoder::new(4096);
        encoder.set_use_huffman(false);

        // C.3.1: first request; :authority added at index 62.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":method", "GET"),
                    (":scheme", "http"),
                    (":path", "/"),
                    (":authority", "www.example.com"),
                ]
            ),
            hex_to_bytes("828684410f7777772e6578616d706c652e636f6d")
        );

        // C.3.2: :authority referenced at dynamic 62; cache-control added.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":method", "GET"),
                    (":scheme", "http"),
                    (":path", "/"),
                    (":authority", "www.example.com"),
                    ("cache-control", "no-cache"),
                ]
            ),
            hex_to_bytes("828684be58086e6f2d6361636865")
        );

        // C.3.3: cache-control at 62, :authority at 63, new literal name.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":path", "/index.html"),
                    (":authority", "www.example.com"),
                    ("custom-key", "custom-value"),
                ]
            ),
            hex_to_bytes("828785bf400a637573746f6d2d6b65790c637573746f6d2d76616c7565")
        );
    }

    /// RFC 7541 C.4: full request walkthrough with Huffman.
    #[test]
    fn c4_request_walkthrough() {
        let mut encoder = Encoder::new(4096);

        // C.4.1.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":method", "GET"),
                    (":scheme", "http"),
                    (":path", "/"),
                    (":authority", "www.example.com"),
                ]
            ),
            hex_to_bytes("828684418cf1e3c2e5f23a6ba0ab90f4ff")
        );

        // C.4.2.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":method", "GET"),
                    (":scheme", "http"),
                    (":path", "/"),
                    (":authority", "www.example.com"),
                    ("cache-control", "no-cache"),
                ]
            ),
            hex_to_bytes("828684be5886a8eb10649cbf")
        );

        // C.4.3.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":method", "GET"),
                    (":scheme", "https"),
                    (":path", "/index.html"),
                    (":authority", "www.example.com"),
                    ("custom-key", "custom-value"),
                ]
            ),
            hex_to_bytes("828785bf408825a849e95ba97d7f8925a849e95bb8e8b4bf")
        );
    }

    /// RFC 7541 C.5: response walkthrough without Huffman, 256-octet
    /// table so evictions occur.
    #[test]
    fn c5_response_walkthrough() {
        let mut encoder = Encoder::new(256);
        encoder.set_use_huffman(false);

        // C.5.1.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":status", "302"),
                    ("cache-control", "private"),
                    ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                    ("location", "https://www.example.com"),
                ]
            ),
            hex_to_bytes(
                "4803333032580770726976617465611d4d6f6e2c203231204f637420323031332032303a31333a323120474d546e1768747470733a2f2f7777772e6578616d706c652e636f6d"
            )
        );
        assert_eq!(encoder.table().dynamic_len(), 4);

        // C.5.2: :status: 302 evicted to make room.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":status", "307"),
                    ("cache-control", "private"),
                    ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                    ("location", "https://www.example.com"),
                ]
            ),
            hex_to_bytes("4803333037c1c0bf")
        );
        assert_eq!(encoder.table().dynamic_len(), 4);

        // C.5.3: several entries evicted.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":status", "200"),
                    ("cache-control", "private"),
                    ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                    ("location", "https://www.example.com"),
                    ("content-encoding", "gzip"),
                    (
                        "set-cookie",
                        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
                    ),
                ]
            ),
            hex_to_bytes(
                "88c1611d4d6f6e2c203231204f637420323031332032303a31333a323220474d54c05a04677a69707738666f6f3d4153444a4b48514b425a584f5157454f50495541585157454f49553b206d61782d6167653d333630303b2076657273696f6e3d31"
            )
        );
        assert_eq!(encoder.table().dynamic_len(), 3);
    }

    /// RFC 7541 C.6: response walkthrough with Huffman, same table
    /// dynamics as C.5.
    #[test]
    fn c6_response_walkthrough() {
        let mut encoder = Encoder::new(256);

        // C.6.1.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":status", "302"),
                    ("cache-control", "private"),
                    ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                    ("location", "https://www.example.com"),
                ]
            ),
            hex_to_bytes(
                "488264025885aec3771a4b6196d07abe941054d444a8200595040b8166e082a62d1bff6e919d29ad171863c78f0b97c8e9ae82ae43d3"
            )
        );
        assert_eq!(encoder.table().dynamic_len(), 4);

        // C.6.2.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":status", "307"),
                    ("cache-control", "private"),
                    ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                    ("location", "https://www.example.com"),
                ]
            ),
            hex_to_bytes("4883640effc1c0bf")
        );
        assert_eq!(encoder.table().dynamic_len(), 4);

        // C.6.3.
        assert_eq!(
            encode(
                &mut encoder,
                &[
                    (":status", "200"),
                    ("cache-control", "private"),
                    ("date", "Mon, 21 Oct 2013 20:13:22 GMT"),
                    ("location", "https://www.example.com"),
                    ("content-encoding", "gzip"),
                    (
                        "set-cookie",
                        "foo=ASDJKHQKBZXOQWEOPIUAXQWEOIU; max-age=3600; version=1",
                    ),
                ]
            ),
            hex_to_bytes(
                "88c16196d07abe941054d444a8200595040b8166e084a62d1bffc05a839bd9ab77ad94e7821dd7f2e6c7b335dfdfcd5b3960d5af27087f3672c1ab270fb5291f9587316065c003ed4ee5b1063d5007"
            )
        );
        assert_eq!(encoder.table().dynamic_len(), 3);
    }

    /// Non-sensitive headers are indexed even when never-indexed would
    /// be a valid choice; only [`NEVER_INDEXED`] names are excluded.
    #[test]
    fn non_sensitive_is_indexed() {
        let mut encoder = Encoder::new(4096);
        encoder.set_use_huffman(false);
        let out = encode(&mut encoder, &[("password", "secret")]);
        // Literal with incremental indexing (0x40), new name.
        assert_eq!(out, hex_to_bytes("400870617373776f726406736563726574"));
        assert_eq!(encoder.table().dynamic_len(), 1);
    }

    /// RFC 7541 Section 7.1.3: sensitive headers are encoded never
    /// indexed and never enter the dynamic table.
    #[test]
    fn sensitive_headers_never_indexed() {
        for name in ["authorization", "proxy-authorization", "cookie"] {
            let mut encoder = Encoder::new(4096);
            encoder.set_use_huffman(false);
            let out = encode(&mut encoder, &[(name, "secret-value")]);

            // Literal never indexed (0x10) with the static-table name
            // index; all three names are static entries above 15, so the
            // index is split across a 0x1f first octet + continuation.
            assert_eq!(out[0], 0x1f, "{name}");
            let decoded = decode(&encoder, &out);
            assert_eq!(
                decoded,
                vec![(name.to_string(), "secret-value".into())],
                "{name}"
            );
            // Sensitive entries never enter the table.
            assert_eq!(encoder.table().dynamic_len(), 0, "{name}");
        }
    }

    /// The static-table name index for a sensitive header is emitted
    /// verbatim: authorization is static index 23 (0x1f 0x08).
    #[test]
    fn sensitive_uses_static_name_index() {
        let mut encoder = Encoder::new(4096);
        encoder.set_use_huffman(false);
        let out = encode(&mut encoder, &[("authorization", "Bearer xyz")]);
        assert_eq!(out, hex_to_bytes("1f080a4265617265722078797a"));
        assert_eq!(encoder.table().dynamic_len(), 0);
    }

    /// A queued table size update is emitted before the first field and
    /// applied to the encoder's table (RFC 7541 Section 6.3).
    #[test]
    fn size_update_emitted_at_block_start() {
        let mut encoder = Encoder::new(4096);
        encoder.set_use_huffman(false);
        encoder.queue_size_update(0);
        let out = encode(&mut encoder, &[(":method", "GET")]);
        assert_eq!(out, hex_to_bytes("2082"));
        assert_eq!(encoder.table().max_size(), 0);

        // Shrinking evicts entries so indices stay in sync with the peer.
        let mut encoder = Encoder::new(4096);
        encoder.set_use_huffman(false);
        let _ = encode(&mut encoder, &[("custom-key", "custom-value")]);
        assert_eq!(encoder.table().dynamic_len(), 1);
        encoder.queue_size_update(32);
        let _ = encode(&mut encoder, &[(":method", "GET")]);
        assert_eq!(encoder.table().dynamic_len(), 0);
    }

    /// Growing the table again restarts indexing at 62.
    #[test]
    fn size_update_grow_reindexes() {
        let mut encoder = Encoder::new(4096);
        encoder.set_use_huffman(false);
        encoder.queue_size_update(0);
        let _ = encode(&mut encoder, &[("a", "1")]);
        encoder.queue_size_update(4096);
        let _ = encode(&mut encoder, &[("b", "2")]);
        assert_eq!(encoder.table().get(62).unwrap().name(), b"b");
        assert_eq!(encoder.table().get(63), None);
    }

    /// Round-trip: encoding then decoding reproduces the original list,
    /// for a range of table sizes and Huffman settings.
    #[test]
    fn round_trip() {
        let lists: [&[(&str, &str)]; 5] = [
            &[(":method", "GET"), (":scheme", "https")],
            &[
                (":status", "302"),
                ("cache-control", "private"),
                ("date", "Mon, 21 Oct 2013 20:13:21 GMT"),
                ("location", "https://www.example.com"),
                ("content-encoding", "gzip"),
                ("authorization", "Bearer sekrit"),
                ("x-empty", ""),
            ],
            &[("x-long", &"v".repeat(300))],
            &[("x-huffman-ok", "custom-value"), ("cookie", "a=b; c=d")],
            &[("accept-encoding", "gzip, deflate"), ("te", "trailers")],
        ];

        for (i, list) in lists.iter().enumerate() {
            for table_size in [0, 16, 256, 4096] {
                for use_huffman in [false, true] {
                    let mut encoder = Encoder::new(table_size);
                    encoder.set_use_huffman(use_huffman);
                    let wire = encode(&mut encoder, list);
                    let decoded = decode(&encoder, &wire);
                    let expected = list
                        .iter()
                        .map(|(name, value)| (name.to_string(), value.to_string()))
                        .collect::<Vec<_>>();
                    assert_eq!(
                        decoded, expected,
                        "list {i}, table {table_size}, huffman {use_huffman}"
                    );
                }
            }
        }
    }

    /// Empty values round-trip with Huffman enabled.
    #[test]
    fn empty_value_round_trip() {
        let mut encoder = Encoder::new(4096);
        let out = encode(&mut encoder, &[("x-empty", "")]);
        assert_eq!(decode(&encoder, &out), vec![("x-empty".into(), "".into())]);
    }
}
