//! QPACK encoder (RFC 9204 Sections 4.3 and 4.5).
//!
//! Consumption: the HTTP/3 layer drives the encoder per connection (it feeds
//! field sections and drains the encoder stream); until that lands, the whole
//! module is dead in non-test builds, which is why `dead_code` is expected
//! here. It errors again once the encoder is used, reminding us to remove the
//! expectation.
//!
//! The encoder owns the shared dynamic table (Section 4.2): it alone adds
//! entries, and it emits an unframed sequence of instructions on the encoder
//! stream (Section 4.3) describing every mutation. Field sections are encoded
//! as a Required Insert Count, a Base, and one or more field line
//! representations (Section 4.5).
//!
//! The encoder fixes the Base at the dynamic table insertion count before
//! encoding a section, so every reference to entries that existed before the
//! section is relative, and entries inserted while encoding the section are
//! referenced with post-Base indexes (Section 4.5.1.2 recommends exactly this:
//! Base equal to the Required Insert Count, which makes the Sign bit and the
//! Delta Base zero whenever nothing new is referenced).
//!
//! Inserts are speculative but bounded: an entry is only inserted when it
//! fits and when the eviction it would cause cannot invalidate an index
//! already referenced by the section being encoded, nor remove an entry the
//! decoder still needs. The decoder's acknowledgments (Section 4.4
//! instructions on its decoder stream) raise a Known Received Count and free
//! the references of acknowledged field sections; an entry is evictable only
//! below the lower of the Known Received Count and the smallest reference
//! still outstanding (RFC 9204 Sections 2.1.1 and 2.1.4). The encoder never
//! evicts above that floor, so the peer's decoder never has to reject an
//! insert as a QPACK_ENCODER_STREAM_ERROR.
//!
//! Huffman encoding follows RFC 9204 Section 4.1.2: a string is Huffman
//! encoded when that is shorter, matching HPACK practice.
#![expect(dead_code)]

use std::collections::VecDeque;

use bytes::Bytes;

use crate::h3::qpack::table::DynamicTable;
use crate::h3::qpack::{static_table, QpackError};
use crate::hpack::{huffman, integer};

/// `001` + 5-bit capacity: Set Dynamic Table Capacity (RFC 9204 4.3.1).
const SET_CAPACITY: u8 = 0b0010_0000;
/// `1 T` + 6-bit name index: Insert with Name Reference (RFC 9204 4.3.2).
const INSERT_WITH_NAME_REF: u8 = 0b1000_0000;
/// `01` + H + 5-bit name length: Insert with Literal Name (RFC 9204 4.3.3).
const INSERT_WITH_LITERAL_NAME: u8 = 0b0100_0000;
/// `000` + 5-bit relative index: Duplicate (RFC 9204 4.3.4).
const DUPLICATE: u8 = 0b0000_0000;

/// `1` + 7-bit stream ID: Section Acknowledgment (RFC 9204 4.4.1).
const SECTION_ACK: u8 = 0x80;
/// `01` + 6-bit stream ID: Stream Cancellation (RFC 9204 4.4.2).
const STREAM_CANCELLATION: u8 = 0x40;
/// `00` + 6-bit increment: Insert Count Increment (RFC 9204 4.4.3).
const INSERT_COUNT_INCREMENT: u8 = 0x00;

/// Upper bound on `decoder_stream_pending`. A complete decoder-stream
/// instruction is a single prefixed integer of at most 10 bytes (a 62-bit
/// integer), so a buffered prefix far larger than this can never become a
/// valid instruction.
const MAX_DECODER_STREAM_PENDING: usize = 64;

/// `1 T` + 6-bit index: Indexed Field Line (RFC 9204 4.5.2).
const INDEXED: u8 = 0b1000_0000;
/// `0001` + 4-bit post-Base index: Indexed Field Line with Post-Base Index
/// (RFC 9204 4.5.3).
const INDEXED_POST_BASE: u8 = 0b0001_0000;
/// `01 N T` + 4-bit name index: Literal Field Line with Name Reference
/// (RFC 9204 4.5.4).
const LITERAL_NAME_REF: u8 = 0b0100_0000;
/// `0000 N` + 3-bit post-Base name index: Literal Field Line with Post-Base
/// Name Reference (RFC 9204 4.5.5).
const LITERAL_POST_BASE_NAME_REF: u8 = 0b0000_0000;
/// `001 N` + H + 3-bit name length: Literal Field Line with Literal Name
/// (RFC 9204 4.5.6).
const LITERAL_LITERAL_NAME: u8 = 0b0010_0000;

/// Field names that must never be added to the dynamic table and must always
/// be sent as literal field lines with the N bit set (RFC 9204 Section 7.1).
const NEVER_INDEXED: [&[u8]; 3] = [b"authorization", b"proxy-authorization", b"cookie"];

/// Result of encoding one field section: the encoded field section carried on
/// the request/response stream, and any encoder stream instructions queued
/// while encoding it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EncodedSection {
    /// Encoded field section prefix plus field lines (RFC 9204 Section 4.5.1).
    pub block: Bytes,
    /// Encoder stream instructions (RFC 9204 Section 4.3).
    pub encoder_stream: Bytes,
}

/// QPACK encoder: dynamic table owner and field section encoder.
#[derive(Debug)]
pub struct Encoder {
    dynamic: DynamicTable,
    /// Upper bound on the dynamic table capacity allowed by the decoder's
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY (RFC 9204 Section 5).
    max_capacity: u64,
    /// Whether string literals are Huffman encoded when that is shorter.
    huffman: bool,
    /// Number of dynamic table insertions and duplications acknowledged by
    /// the decoder (RFC 9204 Section 2.1.4). Absolute indexes below it are
    /// acknowledged and can be evicted.
    known_received: u64,
    /// Smallest absolute index referenced by each unacknowledged field
    /// section that has dynamic references, in send order (RFC 9204
    /// Sections 2.1.1 and 4.4.1). A section is freed by a Section
    /// Acknowledgment for its stream or by a Stream Cancellation.
    pending_refs: VecDeque<(u64, u64)>,
    /// Cached minimum of `pending_refs` second values (`u64::MAX` when empty).
    /// Avoids `O(N_pending)` scan per header insertion in `evictable_floor`.
    cached_min_pending: u64,
    /// Bytes of the peer's decoder stream received so far but not yet forming
    /// a complete instruction. QPACK decoder-stream instructions can span the
    /// arbitrary chunk boundaries of the underlying QUIC stream, so partial
    /// instructions are buffered here until the rest arrives (RFC 9204
    /// Section 4.4) instead of being treated as a stream error.
    decoder_stream_pending: Vec<u8>,
}

impl Encoder {
    /// Creates an encoder bound to a decoder that advertised the given
    /// `max_capacity` in SETTINGS_QPACK_MAX_TABLE_CAPACITY.
    #[inline]
    pub fn new(max_capacity: u64, huffman: bool) -> Self {
        Self {
            dynamic: DynamicTable::new(0),
            max_capacity,
            huffman,
            known_received: 0,
            pending_refs: VecDeque::new(),
            cached_min_pending: u64::MAX,
            decoder_stream_pending: Vec::new(),
        }
    }

    /// The maximum dynamic table capacity permitted by the decoder.
    #[inline]
    pub fn max_capacity(&self) -> u64 {
        self.max_capacity
    }

    /// The lowest absolute index at or above which entries are NOT
    /// evictable: the lower of the Known Received Count and the smallest
    /// reference of any unacknowledged field section (RFC 9204
    /// Sections 2.1.1 and 2.1.4). An insert whose eviction would reach it
    /// is skipped.
    #[inline]
    fn evictable_floor(&self) -> u64 {
        self.known_received.min(self.cached_min_pending)
    }

    #[inline]
    fn recompute_min_pending(&mut self) {
        self.cached_min_pending = self
            .pending_refs
            .iter()
            .map(|(_, min_ref)| *min_ref)
            .min()
            .unwrap_or(u64::MAX);
    }

    /// Encodes `headers` for the field section on `stream_id` into an
    /// encoded field section plus the encoder stream instructions the
    /// decoder needs to process it.
    ///
    /// The dynamic table is used only when the decoder allows a capacity of
    /// at least one entry (RFC 9204 Section 3.2.3): a maximum capacity below
    /// 32 bytes cannot hold any entry and disables the dynamic table.
    #[inline]
    pub fn encode_section(&mut self, stream_id: u64, headers: &[(Bytes, Bytes)]) -> EncodedSection {
        self.encode_section_with_base(stream_id, headers, self.dynamic.inserted())
    }

    /// Encodes `headers` using the decoder's **acknowledged** insert count
    /// (`known_received`) as the QPACK Base.
    ///
    /// RFC 9204 Section 2.1.2 forbids a relative reference to a dynamic entry
    /// whose absolute index exceeds the Largest Reference the decoder has
    /// acknowledged: such an entry must instead be referenced with a Post-Base
    /// index. The shared encoder's own insert count (`dynamic.inserted()`) can
    /// run far ahead of what the peer has acknowledged — for instance when the
    /// client is busy consuming a large response body and lags on its
    /// decoder-stream acknowledgments. Encoding against the insert count there
    /// would emit relative references above the peer's Largest Reference, which
    /// a strict decoder (e.g. Neqo/Firefox) treats as a QPACK decompression
    /// failure, tearing down the whole connection and dropping every other in-
    /// flight request. Encoding against `known_received` keeps every relative
    /// reference within the acknowledged range and uses Post-Base for anything
    /// newer, so the section decodes correctly even if the peer ACKs late.
    #[inline]
    pub(crate) fn encode_section_with_ack_base(
        &mut self,
        stream_id: u64,
        headers: &[(Bytes, Bytes)],
    ) -> EncodedSection {
        self.encode_section_with_base(stream_id, headers, self.known_received)
    }

    /// The insert count a decoder must have reached to process the most
    /// recently encoded section.
    #[inline]
    pub(crate) fn required_insert_count(&self) -> u64 {
        self.dynamic.inserted()
    }

    #[inline]
    fn encode_section_with_base(
        &mut self,
        stream_id: u64,
        headers: &[(Bytes, Bytes)],
        base: u64,
    ) -> EncodedSection {
        let usable = self.max_capacity >= 32;
        let mut encoder_stream = Vec::new();

        let mut block = Vec::new();
        // Smallest absolute index referenced by the section so far; an insert
        // is skipped when its eviction would reach it.
        let mut min_rel_ref: Option<u64> = None;
        // Required Insert Count: one larger than the largest absolute index
        // of all dynamic table entries referenced by the section, and 0 when
        // none are referenced (RFC 9204 Section 2.1.2). It only grows with
        // dynamic references, so a section that happens to reference only
        // static entries does not inflate it.
        let mut ric = 0u64;

        for (name, value) in headers {
            let sensitive = NEVER_INDEXED.contains(&name.as_ref());

            if sensitive {
                self.encode_literal(name, value, true, &mut block);
                continue;
            }

            // Full match, dynamic table first (newest first), then static.
            // Preserve the corresponding name matches so the literal path
            // below does not repeat either table scan.
            let dynamic_match = usable.then(|| self.dynamic.find_full_or_name(name, value));
            if usable {
                if let Some(abs) = dynamic_match.and_then(|(full, _)| full) {
                    self.encode_indexed(abs, base, &mut block, &mut ric, &mut min_rel_ref);
                    continue;
                }
            }
            let static_match = static_table::find_full_or_name(name, value);
            if let Some(idx) = static_match.0 {
                // Indexed Field Line, static table (T=1).
                integer::encode(&mut block, idx as u64, 6, INDEXED | 0x40);
                continue;
            }

            if usable {
                if let Some(abs) = dynamic_match.and_then(|(_, name)| name) {
                    if abs >= base {
                        // Post-Base name reference (4.5.5). Only reachable on
                        // the vector path, which fixes Base below the insert
                        // count.
                        self.encode_literal_post_base_name_ref(
                            abs,
                            base,
                            value,
                            &mut block,
                            &mut ric,
                            &mut min_rel_ref,
                        );
                    } else {
                        // Literal with Name Reference, dynamic table (T=0).
                        self.encode_literal_with_name_ref(
                            abs,
                            base,
                            value,
                            &mut block,
                            &mut ric,
                            &mut min_rel_ref,
                        );
                    }
                    continue;
                }
            }
            if let Some(idx) = static_match.1 {
                // Literal with Name Reference, static table (T=1).
                self.encode_literal_with_static_name_ref(idx, value, &mut block);
                continue;
            }

            // No name match anywhere: emit a literal name, and insert the
            // entry so later sections can reference it (Section 4.4).
            let size = DynamicTable::entry_size(name, value);
            // An insert only evicts the oldest entries, so it is allowed
            // when the first surviving entry sits at or below every entry
            // the section references and everything the decoder still
            // needs (RFC 9204 Section 2.1.1): evicting below that floor is
            // what the decoder's mirror of this table permits.
            let boundary = min_rel_ref.unwrap_or(u64::MAX).min(self.evictable_floor());
            let safe = self.dynamic.inserted() - self.dynamic.len() as u64
                + self.dynamic.would_evict(size)
                <= boundary;
            if usable && size <= self.max_capacity && safe {
                // Set Dynamic Table Capacity (4.3.1), emitted lazily right
                // before the first insert of this section.
                if self.dynamic.capacity() != self.max_capacity {
                    integer::encode(&mut encoder_stream, self.max_capacity, 5, SET_CAPACITY);
                    self.dynamic.set_capacity(self.max_capacity);
                }
                let abs = self.dynamic.next_absolute();
                // Insert with Literal Name (4.3.3): the name length uses a
                // 5-bit prefix, so `push_string` receives 6 (it reserves one
                // bit for the Huffman flag).
                self.push_string(&mut encoder_stream, name, 6, INSERT_WITH_LITERAL_NAME);
                self.push_string(&mut encoder_stream, value, 8, 0);
                let _ = self.dynamic.insert(name.clone(), value.clone());
                // The fresh entry is referenced with a post-Base index.
                self.encode_indexed(abs, base, &mut block, &mut ric, &mut min_rel_ref);
            } else {
                self.encode_literal(name, value, false, &mut block);
            }
        }

        // A section with dynamic references pins the referenced entries
        // until the decoder acknowledges it (Section 4.4.1).
        if ric > 0 {
            let min_ref = min_rel_ref.unwrap_or(0);
            self.pending_refs.push_back((stream_id, min_ref));
            if min_ref < self.cached_min_pending {
                self.cached_min_pending = min_ref;
            }
        }

        // Encoded Field Section Prefix (RFC 9204 4.5.1).
        let mut prefix = Vec::new();
        self.encode_prefix(&mut prefix, ric, base);
        prefix.reserve(block.len());
        prefix.extend_from_slice(&block);

        EncodedSection {
            block: Bytes::from(prefix),
            encoder_stream: Bytes::from(encoder_stream),
        }
    }

    /// Encodes the Required Insert Count and the Base (RFC 9204 4.5.1).
    #[inline]
    fn encode_prefix(&self, out: &mut Vec<u8>, ric: u64, base: u64) {
        // Required Insert Count (4.5.1.1): 0 stays 0, otherwise it is wrapped
        // modulo 2 * MaxEntries, where MaxEntries = floor(MaxCapacity / 32).
        let max_entries = self.max_capacity / 32;
        let enc_ric = if ric == 0 || max_entries == 0 {
            0
        } else {
            (ric % (2 * max_entries)) + 1
        };
        integer::encode(out, enc_ric, 8, 0);
        // Base (4.5.1.2): Sign=0 when Base >= Ric (Delta = Base - Ric);
        // Sign=1 when Base < Ric (Delta = Ric - Base - 1).
        if base >= ric {
            integer::encode(out, base - ric, 7, 0);
        } else {
            integer::encode(out, ric - base - 1, 7, 0x80);
        }
    }

    /// Encodes an indexed reference to a dynamic table entry.
    #[inline]
    fn encode_indexed(
        &self,
        abs: u64,
        base: u64,
        block: &mut Vec<u8>,
        ric: &mut u64,
        min_rel_ref: &mut Option<u64>,
    ) {
        *ric = (*ric).max(abs + 1);
        if abs >= base {
            // Post-Base index (4.5.3).
            integer::encode(block, abs - base, 4, INDEXED_POST_BASE);
        } else {
            // Relative index (4.5.2): Base - Absolute - 1.
            integer::encode(block, base - abs - 1, 6, INDEXED);
        }
        *min_rel_ref = Some(min_rel_ref.map_or(abs, |m| m.min(abs)));
    }

    /// Encodes a literal field line with a dynamic name reference (T=0).
    #[inline]
    fn encode_literal_with_name_ref(
        &self,
        abs: u64,
        base: u64,
        value: &[u8],
        block: &mut Vec<u8>,
        ric: &mut u64,
        min_rel_ref: &mut Option<u64>,
    ) {
        *ric = (*ric).max(abs + 1);
        let rel = base - abs - 1;
        integer::encode(block, rel, 4, LITERAL_NAME_REF);
        *min_rel_ref = Some(min_rel_ref.map_or(abs, |m| m.min(abs)));
        self.push_string(block, value, 8, 0);
    }

    /// Encodes a literal field line with a post-Base name reference (4.5.5).
    #[inline]
    fn encode_literal_post_base_name_ref(
        &self,
        abs: u64,
        base: u64,
        value: &[u8],
        block: &mut Vec<u8>,
        ric: &mut u64,
        min_rel_ref: &mut Option<u64>,
    ) {
        *ric = (*ric).max(abs + 1);
        integer::encode(block, abs - base, 3, LITERAL_POST_BASE_NAME_REF);
        *min_rel_ref = Some(min_rel_ref.map_or(abs, |m| m.min(abs)));
        self.push_string(block, value, 8, 0);
    }

    /// Encodes a literal field line with a static name reference (T=1).
    #[inline]
    fn encode_literal_with_static_name_ref(&self, idx: usize, value: &[u8], block: &mut Vec<u8>) {
        integer::encode(block, idx as u64, 4, LITERAL_NAME_REF | 0x10);
        self.push_string(block, value, 8, 0);
    }

    /// Encodes a literal field line with a literal name (4.5.6), preferring a
    /// static name reference when one exists.
    #[inline]
    fn encode_literal(&self, name: &[u8], value: &[u8], sensitive: bool, block: &mut Vec<u8>) {
        if let Some(idx) = static_table::find_name(name) {
            integer::encode(
                block,
                idx as u64,
                4,
                LITERAL_NAME_REF | 0x10 | (u8::from(sensitive) << 4),
            );
        } else {
            // `001 N` + H + 3-bit name length.
            self.push_string(
                block,
                name,
                4,
                LITERAL_LITERAL_NAME | (u8::from(sensitive) << 4),
            );
        }
        self.push_string(block, value, 8, 0);
    }

    /// Encodes an N-bit prefix string literal (RFC 9204 Section 4.1.2):
    /// `header` carries the bits preceding the string, the Huffman flag is
    /// set when Huffman encoding is shorter, and the length is encoded with
    /// an (N-1)-bit prefix.
    #[inline]
    fn push_string(&self, out: &mut Vec<u8>, value: &[u8], prefix: u8, header: u8) {
        let (huffman, len) = if self.huffman {
            let huffman_bits = huffman::encoded_len(value);
            if huffman_bits < value.len() * 8 {
                (true, huffman_bits.div_ceil(8) as u64)
            } else {
                (false, value.len() as u64)
            }
        } else {
            (false, value.len() as u64)
        };
        integer::encode(
            out,
            len,
            prefix - 1,
            header | (u8::from(huffman) << (prefix - 1)),
        );
        if huffman {
            huffman::encode_with_len(value, out, len as usize);
        } else {
            out.extend_from_slice(value);
        }
    }

    /// Inserts an entry with a literal name on the encoder stream (4.3.3)
    /// and mirrors it in the local table. Returns the instruction, or `None`
    /// when the entry does not fit in the dynamic table.
    #[inline]
    pub(crate) fn insert_literal(&mut self, name: &[u8], value: &[u8]) -> Option<Bytes> {
        let size = DynamicTable::entry_size(name, value);
        if size > self.dynamic.capacity() || self.insert_would_evict_needed(size) {
            return None;
        }
        let mut out = Vec::new();
        // Name length uses a 5-bit prefix (RFC 9204 4.3.3), so `push_string`
        // receives 6 (it reserves one bit for the Huffman flag).
        self.push_string(&mut out, name, 6, INSERT_WITH_LITERAL_NAME);
        self.push_string(&mut out, value, 8, 0);
        let res = self
            .dynamic
            .insert(Bytes::copy_from_slice(name), Bytes::copy_from_slice(value));
        debug_assert!(res.is_ok(), "insert_literal: entry passed the size check");
        res.ok()?;
        Some(Bytes::from(out))
    }

    /// Inserts an entry with a name reference on the encoder stream (4.3.2),
    /// preferring the dynamic table (T=0) then the static table (T=1), and
    /// mirrors it in the local table. Returns the instruction, or `None`
    /// when the name is not indexed anywhere or the entry does not fit.
    #[inline]
    pub(crate) fn insert_with_name_ref(&mut self, name: &[u8], value: &[u8]) -> Option<Bytes> {
        let size = DynamicTable::entry_size(name, value);
        if size > self.dynamic.capacity() || self.insert_would_evict_needed(size) {
            return None;
        }
        let mut out = Vec::new();
        let (name_idx, pattern) = self
            .dynamic
            .find_name(name)
            .map(|abs| (abs, INSERT_WITH_NAME_REF))
            .or_else(|| {
                static_table::find_name(name).map(|idx| (idx as u64, INSERT_WITH_NAME_REF | 0x40))
            })?;
        if pattern == INSERT_WITH_NAME_REF {
            integer::encode(&mut out, self.dynamic.inserted() - name_idx - 1, 6, pattern);
        } else {
            integer::encode(&mut out, name_idx, 6, pattern);
        }
        self.push_string(&mut out, value, 8, 0);
        let res = self
            .dynamic
            .insert(Bytes::copy_from_slice(name), Bytes::copy_from_slice(value));
        debug_assert!(
            res.is_ok(),
            "insert_with_name_ref: entry passed the size check"
        );
        res.ok()?;
        Some(Bytes::from(out))
    }

    /// Duplicates the entry at the given relative index (4.3.4) and mirrors
    /// it in the local table. Returns the instruction, or `None` when the
    /// index is out of range or the copy does not fit.
    #[inline]
    pub(crate) fn duplicate(&mut self, relative: u64) -> Option<Bytes> {
        if relative >= self.dynamic.len() as u64 {
            return None;
        }
        // The relative index is the deque position: 0 is the most recently
        // inserted entry.
        let (name, value) = self.dynamic.entry_at(relative)?;
        let size = DynamicTable::entry_size(name, value);
        if size > self.dynamic.capacity() || self.insert_would_evict_needed(size) {
            return None;
        }
        let mut out = Vec::new();
        integer::encode(&mut out, relative, 5, DUPLICATE);
        let res = self
            .dynamic
            .insert(Bytes::copy_from_slice(name), Bytes::copy_from_slice(value));
        debug_assert!(res.is_ok(), "duplicate: entry passed the size check");
        res.ok()?;
        Some(Bytes::from(out))
    }

    /// Sets the dynamic table capacity (4.3.1), evicting as needed. Returns
    /// the instruction, or `None` when the capacity is unchanged, exceeds
    /// the decoder's maximum, or the reduction would evict entries the
    /// decoder still needs (RFC 9204 Section 2.1.1).
    #[inline]
    pub fn set_capacity(&mut self, capacity: u64) -> Option<Bytes> {
        if capacity > self.max_capacity || capacity == self.dynamic.capacity() {
            return None;
        }
        if capacity < self.dynamic.capacity() {
            let evicted = self.dynamic.evict_for_capacity(capacity);
            if self.dynamic.inserted() - self.dynamic.len() as u64 + evicted
                > self.evictable_floor()
            {
                return None;
            }
        }
        let mut out = Vec::new();
        integer::encode(&mut out, capacity, 5, SET_CAPACITY);
        self.dynamic.set_capacity(capacity);
        Some(Bytes::from(out))
    }

    /// Whether inserting an entry of `size` bytes would evict an entry the
    /// decoder still needs (RFC 9204 Section 2.1.1): one that is not yet
    /// acknowledged or is referenced by an unacknowledged field section.
    #[inline]
    fn insert_would_evict_needed(&self, size: u64) -> bool {
        self.dynamic.inserted() - self.dynamic.len() as u64 + self.dynamic.would_evict(size)
            > self.evictable_floor()
    }

    /// Processes the decoder stream instructions in `buf`. Section
    /// Acknowledgments (4.4.1) free a field section's references, Stream
    /// Cancellations (4.4.2) free every reference of a cancelled stream,
    /// and Insert Count Increments (4.4.3) raise the Known Received Count.
    ///
    /// Only an Insert Count Increment (4.4.3) is a connection error: a zero
    /// increment, or one that advances past the number of inserts sent
    /// (RFC 9204 Section 2.1.4). A Section Acknowledgment or Stream
    /// Cancellation that matches no outstanding field section is benign —
    /// RFC 9204 Section 4.4 defines no error for it and a peer may send one
    /// for a section already acknowledged or cancelled — so it is ignored
    /// rather than closing the connection.
    #[inline]
    pub fn feed_decoder_stream(&mut self, buf: &[u8]) -> Result<(), QpackError> {
        self.decoder_stream_pending.extend_from_slice(buf);
        // A decoder-stream instruction is a single prefixed integer, so its
        // length is known once enough bytes have arrived. Parse only complete
        // instructions, leaving any trailing partial instruction buffered for
        // the next call (RFC 9204 Section 4.4). The QUIC stream beneath can
        // deliver an instruction split across several `poll_recv` chunks.
        // A complete instruction is at most 10 bytes (a 62-bit integer), so a
        // much larger buffered prefix can never become one and is rejected to
        // bound memory against a peer that streams continuation bytes.
        if self.decoder_stream_pending.len() > MAX_DECODER_STREAM_PENDING {
            return Err(QpackError::DecoderStream);
        }
        let data = &self.decoder_stream_pending;
        let mut consumed = 0;
        while consumed < data.len() {
            let header = data[consumed];
            // Every decoder-stream instruction carries one prefixed integer:
            // a Section Acknowledgment (4.4.1) uses a 7-bit prefix, the other
            // two types use 6 bits.
            let prefix_bits: u8 = if header & 0x80 != 0 { 7 } else { 6 };
            let Some(len) = integer::encoded_len(&data[consumed..], prefix_bits) else {
                // Instruction is truncated; wait for more bytes.
                break;
            };
            if consumed + len > data.len() {
                break;
            }
            let instr = &data[consumed..consumed + len];
            // `decode` takes the first octet as `header`; its continuation
            // octets follow it.
            let mut off = 1;
            if header & 0x80 != 0 {
                // `1` + 7-bit stream ID: Section Acknowledgment (4.4.1).
                // A matching field section is freed; a stray
                // acknowledgment (already freed, or never outstanding) is
                // ignored.
                let stream_id = integer::decode(instr, &mut off, 7, header)
                    .map_err(|_| QpackError::DecoderStream)?;
                if let Some(pos) = self
                    .pending_refs
                    .iter()
                    .position(|(id, _)| *id == stream_id)
                {
                    let removed_min = self.pending_refs[pos].1;
                    self.pending_refs.remove(pos);
                    if removed_min == self.cached_min_pending {
                        self.cached_min_pending = self
                            .pending_refs
                            .iter()
                            .map(|(_, min_ref)| *min_ref)
                            .min()
                            .unwrap_or(u64::MAX);
                    }
                }
            } else if header & 0x40 != 0 {
                // `01` + 6-bit stream ID: Stream Cancellation (4.4.2).
                // Every outstanding reference of the stream is dropped; a
                // cancellation for a stream with none is a no-op.
                let stream_id = integer::decode(instr, &mut off, 6, header)
                    .map_err(|_| QpackError::DecoderStream)?;
                let prev_len = self.pending_refs.len();
                self.pending_refs.retain(|(id, _)| *id != stream_id);
                if self.pending_refs.len() != prev_len {
                    self.cached_min_pending = self
                        .pending_refs
                        .iter()
                        .map(|(_, min_ref)| *min_ref)
                        .min()
                        .unwrap_or(u64::MAX);
                }
            } else {
                // `00` + 6-bit increment: Insert Count Increment (4.4.3).
                // A zero increment is forbidden, and the total may not
                // exceed the number of inserts sent.
                let increment = integer::decode(instr, &mut off, 6, header)
                    .map_err(|_| QpackError::DecoderStream)?;
                if increment == 0
                    || self.known_received.saturating_add(increment) > self.dynamic.inserted()
                {
                    return Err(QpackError::DecoderStream);
                }
                self.known_received += increment;
            }
            consumed += len;
        }
        self.decoder_stream_pending.drain(..consumed);
        Ok(())
    }
}

#[cfg(test)]
mod tests;
