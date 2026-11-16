//! QPACK decoder (RFC 9204 Sections 2.2, 4.3 and 4.5).
//!
//! The decoder mirrors the dynamic table from the peer's encoder stream,
//! decodes field sections (buffering blocked ones until their required
//! insertions arrive), and emits the decoder-stream acknowledgements and
//! cancellations described by RFC 9204 Section 4.4.

use std::collections::VecDeque;

use bytes::Bytes;
use rustc_hash::FxHashMap;

use crate::h3::qpack::error::QpackError;
use crate::h3::qpack::static_table;
use crate::h3::qpack::table::DynamicTable;
use crate::hpack::{huffman, integer, HpackError};

/// `1` + 7-bit stream ID: Section Acknowledgment (RFC 9204 4.4.1).
const SECTION_ACK: u8 = 0x80;
/// `01` + 6-bit stream ID: Stream Cancellation (RFC 9204 4.4.2).
#[allow(dead_code)]
const STREAM_CANCELLATION: u8 = 0x40;
/// `00` + 6-bit increment: Insert Count Increment (RFC 9204 4.4.3).
const INSERT_COUNT_INCREMENT: u8 = 0x00;

// Encoder instruction patterns (RFC 9204 4.3), mirrored from the encoder.
/// `001` + 5-bit capacity: Set Dynamic Table Capacity (4.3.1).
#[allow(dead_code)]
const SET_CAPACITY: u8 = 0b0010_0000;
/// `1 T` + 6-bit name index: Insert with Name Reference (4.3.2).
#[allow(dead_code)]
const INSERT_WITH_NAME_REF: u8 = 0b1000_0000;
/// `01` + H + 5-bit name length: Insert with Literal Name (4.3.3).
#[allow(dead_code)]
const INSERT_WITH_LITERAL_NAME: u8 = 0b0100_0000;
/// `000` + 5-bit relative index: Duplicate (4.3.4).
#[allow(dead_code)]
const DUPLICATE: u8 = 0b0000_0000;

// Field line patterns (RFC 9204 4.5), mirrored from the encoder.
/// `1 T` + 6-bit index: Indexed Field Line (4.5.2).
#[allow(dead_code)]
const INDEXED: u8 = 0b1000_0000;
/// `0001` + 4-bit post-Base index: Indexed Field Line with Post-Base Index
/// (4.5.3).
#[allow(dead_code)]
const INDEXED_POST_BASE: u8 = 0b0001_0000;
/// `01 N T` + 4-bit name index: Literal Field Line with Name Reference
/// (4.5.4).
#[allow(dead_code)]
const LITERAL_NAME_REF: u8 = 0b0100_0000;
/// `0000 N` + 3-bit post-Base name index: Literal Field Line with Post-Base
/// Name Reference (4.5.5).
#[allow(dead_code)]
const LITERAL_POST_BASE_NAME_REF: u8 = 0b0000_0000;
/// `001 N` + H + 3-bit name length: Literal Field Line with Literal Name
/// (4.5.6).
#[allow(dead_code)]
const LITERAL_LITERAL_NAME: u8 = 0b0010_0000;

/// Per-field overhead in a field list's size (RFC 9114 Section 4.2.2).
pub const FIELD_OVERHEAD: usize = 32;

/// The maximum number of fields a single field section may carry.
pub const MAX_FIELDS_PER_SECTION: usize = 8192;

/// A field section that was buffered as blocked and has since been decoded
/// after an encoder stream update.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnblockedSection {
    /// The stream the encoded field section was received on.
    pub stream_id: u64,
    /// The decoded header list.
    pub headers: Vec<(Bytes, Bytes)>,
}

/// A field section buffered until its Required Insert Count is reached.
#[derive(Debug)]
struct BlockedSection {
    stream_id: u64,
    buf: Bytes,
    ric: u64,
    #[cfg(feature = "unstable-internals")]
    since: u64,
}

/// QPACK decoder: dynamic table mirror and field section decoder.
#[derive(Debug)]
pub struct Decoder {
    dynamic: DynamicTable,
    /// The dynamic table capacity advertised in SETTINGS (RFC 9204 Section
    /// 3.2.3).
    max_capacity: u64,
    /// Known Received Count (RFC 9204 Section 2.1.4).
    known_received: u64,
    /// Blocked field sections, in arrival order.
    blocked: VecDeque<BlockedSection>,
    /// Number of blocked sections per stream.
    blocked_by_stream: FxHashMap<u64, usize>,
    /// Decoded field-section size per stream, accumulating across headers and
    /// trailers.
    section_size_by_stream: FxHashMap<u64, usize>,
    /// Maximum number of streams that may be blocked at once.
    max_blocked_streams: usize,
    /// Locally advertised `SETTINGS_MAX_FIELD_SECTION_SIZE`; `usize::MAX`
    /// disables it.
    max_field_section_size: usize,
    /// Decoder stream instructions awaiting transmission.
    decoder_stream: Vec<u8>,
    /// Bytes of a partial encoder-stream instruction.
    encoder_stream_pending: Vec<u8>,
    /// Bytes of a partial decoder-stream instruction.
    decoder_stream_pending: Vec<u8>,
}

/// Largest possible decoder-stream instruction: a 6-bit prefix plus nine
/// continuation octets carrying a 62-bit integer (RFC 9204 Section 4.1.1).
const MAX_DECODER_STREAM_INSTRUCTION: usize = 10;

/// Byte length of a string literal at the start of `buf`, including its
/// length integer. Returns `None` when the input is incomplete.
fn string_len(buf: &[u8], prefix_bits: u8) -> Option<usize> {
    let int_prefix = prefix_bits - 1;
    let int_len = integer::encoded_len(buf, int_prefix)?;
    // `decode` consumes `buf[0]` as the header, then continuation octets from
    // `off` onward, so `off` must point past the header byte.
    let mut off = 1;
    let len = integer::decode(buf, &mut off, int_prefix, buf[0]).ok()?;
    let content = usize::try_from(len).ok()?;
    let total = int_len.checked_add(content)?;
    if buf.len() < total {
        return None;
    }
    Some(total)
}

/// Byte length of one encoder-stream instruction (RFC 9204 Section 4.3)
/// starting at the beginning of `buf`, or `None` when `buf` is too short to
/// contain the whole instruction.
fn encoder_instruction_len(buf: &[u8]) -> Option<usize> {
    let header = *buf.first()?;
    match header & 0xC0 {
        // Insert with Name Reference (4.3.2): relative/static index (6-bit
        // prefix) followed by the value string.
        0x80 | 0xC0 => {
            let index_len = integer::encoded_len(buf, 6)?;
            let value_len = string_len(buf.get(index_len..)?, 8)?;
            Some(index_len + value_len)
        }
        // Insert with Literal Name (4.3.3): name string (the instruction's
        // first byte doubles as the name-length prefix, 6-bit prefix) followed
        // by the value string (8-bit prefix).
        0x40 => {
            let name_len = string_len(buf, 6)?;
            let value_len = string_len(buf.get(name_len..)?, 8)?;
            Some(name_len + value_len)
        }
        // `00`: Set Dynamic Table Capacity (4.3.1) or Duplicate (4.3.4), each
        // a 5-bit prefixed integer.
        _ => integer::encoded_len(buf, 5),
    }
}

/// Byte length of one decoder-stream instruction (RFC 9204 Section 4.4)
/// starting at the beginning of `buf`, or `None` when `buf` is too short.
fn decoder_instruction_len(buf: &[u8]) -> Option<usize> {
    let header = *buf.first()?;
    let prefix_bits: u8 = if header & 0x80 != 0 { 7 } else { 6 };
    integer::encoded_len(buf, prefix_bits)
}

impl Decoder {
    /// Creates a decoder that advertised `max_capacity` in
    /// SETTINGS_QPACK_MAX_TABLE_CAPACITY and `max_blocked_streams` in
    /// SETTINGS_QPACK_BLOCKED_STREAMS.
    #[inline]
    pub fn new(max_capacity: u64, max_blocked_streams: usize) -> Self {
        Self {
            dynamic: DynamicTable::without_maps(0),
            max_capacity,
            known_received: 0,
            blocked: VecDeque::new(),
            blocked_by_stream: FxHashMap::default(),
            section_size_by_stream: FxHashMap::default(),
            max_blocked_streams,
            max_field_section_size: usize::MAX,
            decoder_stream: Vec::new(),
            encoder_stream_pending: Vec::new(),
            decoder_stream_pending: Vec::new(),
        }
    }

    /// Sets the locally advertised `SETTINGS_MAX_FIELD_SECTION_SIZE`. The
    /// budget accumulates across a stream's field sections.
    ///
    /// The size of a field list is the sum of its fields' name and value
    /// lengths plus [`FIELD_OVERHEAD`] per field (RFC 9114 Section 4.2.2).
    #[inline]
    pub fn set_max_field_section_size(&mut self, size: usize) {
        self.max_field_section_size = size;
    }

    /// The total number of insertions and duplications materialized from the
    /// encoder stream so far; the decoder's Insert Count (RFC 9204
    /// Section 2.1.1).
    #[cfg(any(test, feature = "unstable-internals"))]
    #[inline]
    pub fn inserted(&self) -> u64 {
        self.dynamic.inserted()
    }

    /// The Known Received Count: insertions and duplications the decoder has
    /// acknowledged or incremented (RFC 9204 Section 2.1.4).
    #[cfg(any(test, feature = "unstable-internals"))]
    #[inline]
    pub fn known_received(&self) -> u64 {
        self.known_received
    }

    /// The number of field sections currently buffered as blocked.
    #[cfg(any(test, feature = "unstable-internals"))]
    #[inline]
    pub fn pending_blocked(&self) -> usize {
        self.blocked.len()
    }

    /// Takes the accumulated decoder stream instructions.
    #[inline]
    pub fn take_decoder_stream(&mut self) -> Bytes {
        Bytes::from(std::mem::take(&mut self.decoder_stream))
    }

    /// Parses the peer's QPACK decoder stream instructions (RFC 9204
    /// Section 4.4). Malformed instructions and zero-value increments are
    /// rejected.
    #[inline]
    pub fn feed_decoder_stream(&mut self, buf: &[u8]) -> Result<(), QpackError> {
        self.decoder_stream_pending.extend_from_slice(buf);
        // Buffer partial instructions: a QUIC chunk can split them or carry
        // several.
        let mut consumed = 0;
        while consumed < self.decoder_stream_pending.len() {
            let Some(len) = decoder_instruction_len(&self.decoder_stream_pending[consumed..])
            else {
                break;
            };
            if consumed + len > self.decoder_stream_pending.len() {
                break;
            }
            let instr = &self.decoder_stream_pending[consumed..consumed + len];
            // Past the header octet, which `decode` takes as `header`.
            let mut off = 1;
            let header = instr[0];
            if header & 0x80 != 0 {
                // `1` + 7-bit stream ID: Section Acknowledgment (4.4.1).
                integer::decode(instr, &mut off, 7, header).map_err(dec_stream_err)?;
            } else if header & 0x40 != 0 {
                // `01` + 6-bit stream ID: Stream Cancellation (4.4.2).
                integer::decode(instr, &mut off, 6, header).map_err(dec_stream_err)?;
            } else {
                // `00` + 6-bit increment: Insert Count Increment (4.4.3). A
                // zero increment is forbidden.
                let increment =
                    integer::decode(instr, &mut off, 6, header).map_err(dec_stream_err)?;
                if increment == 0 {
                    return Err(QpackError::DecoderStream);
                }
            }
            consumed += len;
        }
        self.decoder_stream_pending.drain(..consumed);
        // Only a truncated trailing instruction can remain. A prefixed
        // integer is at most 10 octets, so a longer remainder is an
        // instruction whose continuation bytes never terminate; reject it
        // rather than buffer unbounded input (RFC 9204 Section 4.1.1).
        if self.decoder_stream_pending.len() > MAX_DECODER_STREAM_INSTRUCTION {
            return Err(QpackError::DecoderStream);
        }
        Ok(())
    }

    /// Processes encoder-stream instructions and returns newly decodable
    /// blocked field sections in arrival order.
    #[inline]
    pub fn feed_encoder_stream(&mut self, buf: &[u8]) -> Result<Vec<UnblockedSection>, QpackError> {
        self.encoder_stream_pending.extend_from_slice(buf);
        // Buffer partial instructions. A complete instruction is bounded by
        // the table capacity, so a much larger prefix is abusive.
        let cap = (self.max_capacity as usize).saturating_add(1024);
        if self.encoder_stream_pending.len() > cap {
            return Err(QpackError::EncoderStream);
        }
        let mut consumed = 0;
        while consumed < self.encoder_stream_pending.len() {
            let Some(len) = encoder_instruction_len(&self.encoder_stream_pending[consumed..])
            else {
                break;
            };
            if consumed + len > self.encoder_stream_pending.len() {
                break;
            }
            // Copy the complete instruction to avoid borrowing `self`
            // mutably while inserting.
            let instr = self.encoder_stream_pending[consumed..consumed + len].to_vec();
            self.parse_encoder_instruction(&instr)?;
            consumed += len;
        }
        self.encoder_stream_pending.drain(..consumed);

        // Unblock every field section whose Required Insert Count has been
        // reached, in arrival order.
        let mut sections = Vec::with_capacity(self.blocked.len());
        while let Some(front) = self.blocked.front() {
            if front.ric > self.dynamic.inserted() {
                break;
            }
            let front = self.blocked.pop_front().expect("front just inspected");
            self.remove_blocked_section(front.stream_id);
            let budget = self.remaining_budget(front.stream_id);
            let (headers, size) = self.decode_ready(&front.buf, budget)?;
            self.account_section(front.stream_id, size);
            if front.ric > 0 {
                self.acknowledge(front.ric);
                self.emit_section_ack(front.stream_id);
            }
            sections.push(UnblockedSection {
                stream_id: front.stream_id,
                headers,
            });
        }

        // Coalesced Insert Count Increment (2.2.2.3): the encoder may free
        // references as soon as the received entries are acknowledged.
        if self.dynamic.inserted() > self.known_received {
            integer::encode(
                &mut self.decoder_stream,
                self.dynamic.inserted() - self.known_received,
                6,
                INSERT_COUNT_INCREMENT,
            );
            self.known_received = self.dynamic.inserted();
        }
        Ok(sections)
    }

    /// Parses a single *complete* encoder-stream instruction (RFC 9204
    /// Section 4.3) from `instr` and materializes its dynamic-table update.
    /// `feed_encoder_stream` guarantees `instr` holds a full instruction, so
    /// the parses below cannot run out of bytes.
    #[inline]
    fn parse_encoder_instruction(&mut self, instr: &[u8]) -> Result<(), QpackError> {
        let mut off = 0;
        let header = instr[0];
        off += 1;
        match header & 0xC0 {
            // `1 T` + 6-bit name index: Insert with Name Reference (4.3.2).
            // The T bit being set masks to 0xC0, hence the two-arm pattern.
            0x80 | 0xC0 => {
                let index = integer::decode(instr, &mut off, 6, header).map_err(enc_stream_err)?;
                let value = self
                    .read_value_string(instr, &mut off)
                    .map_err(enc_stream_err)?;
                let name = if header & 0x40 != 0 {
                    // T=1: static table.
                    let idx = usize::try_from(index).map_err(|_| QpackError::EncoderStream)?;
                    let (name, _) = static_table::get(idx).ok_or(QpackError::EncoderStream)?;
                    Bytes::from_static(name)
                } else {
                    // T=0: dynamic table, relative index (index 0 is the most
                    // recently inserted entry).
                    let (name, _) = self
                        .dynamic
                        .get_relative_bytes(index)
                        .ok_or(QpackError::EncoderStream)?;
                    name
                };
                self.insert_entry(name, value)?;
            }
            0x40 => {
                // Insert with Literal Name (4.3.3): the name length uses a
                // 5-bit prefix, so `read_string` receives 6 (it reserves one
                // bit for the Huffman flag).
                let name = self
                    .read_string(instr, &mut off, 6, header)
                    .map_err(enc_stream_err)?;
                let value = self
                    .read_value_string(instr, &mut off)
                    .map_err(enc_stream_err)?;
                self.insert_entry(name, value)?;
            }
            _ => {
                if header & 0x20 != 0 {
                    // Set Dynamic Table Capacity (4.3.1).
                    let capacity =
                        integer::decode(instr, &mut off, 5, header).map_err(enc_stream_err)?;
                    if capacity > self.max_capacity {
                        return Err(QpackError::EncoderStream);
                    }
                    let evicted = self.dynamic.evict_for_capacity(capacity);
                    if evicted > self.known_received {
                        return Err(QpackError::EncoderStream);
                    }
                    self.dynamic.set_capacity(capacity);
                } else {
                    // Duplicate (4.3.4): relative index, 0 being the most
                    // recently inserted entry.
                    let index =
                        integer::decode(instr, &mut off, 5, header).map_err(enc_stream_err)?;
                    let (name, value) = self
                        .dynamic
                        .get_relative_bytes(index)
                        .ok_or(QpackError::EncoderStream)?;
                    self.insert_entry(name, value)?;
                }
            }
        }
        Ok(())
    }

    /// Decodes an encoded field section. Returns `None` when it is buffered
    /// as blocked. Sections on a stream with blocked predecessors are queued
    /// to preserve order (RFC 9204 Section 2.2.1).
    #[inline]
    pub fn decode_block(
        &mut self,
        buf: &[u8],
        stream_id: u64,
        now: u64,
    ) -> Result<Option<Vec<(Bytes, Bytes)>>, QpackError> {
        #[cfg(not(feature = "unstable-internals"))]
        let _ = now;

        let (ric, _, _) = self.read_prefix(buf)?;
        let stream_blocked = self.stream_has_blocked(stream_id);
        if ric > self.dynamic.inserted() || stream_blocked {
            if !stream_blocked && self.blocked_by_stream.len() >= self.max_blocked_streams {
                return Err(QpackError::DecompressionFailed);
            }
            self.blocked.push_back(BlockedSection {
                stream_id,
                buf: Bytes::copy_from_slice(buf),
                ric,
                #[cfg(feature = "unstable-internals")]
                since: now,
            });
            self.add_blocked_section(stream_id);
            return Ok(None);
        }
        let budget = self.remaining_budget(stream_id);
        let (headers, size) = self.decode_ready(buf, budget)?;
        self.account_section(stream_id, size);
        if ric > 0 {
            self.acknowledge(ric);
            self.emit_section_ack(stream_id);
        }
        Ok(Some(headers))
    }

    /// Notifies that a stream finished: its field-section budget is released.
    #[inline]
    pub fn stream_finished(&mut self, stream_id: u64) {
        self.section_size_by_stream.remove(&stream_id);
    }

    /// Notifies that a stream was reset or abandoned: drops its blocked
    /// sections and queues a Stream Cancellation.
    #[cfg(feature = "unstable-internals")]
    #[inline]
    pub fn stream_cancelled(&mut self, stream_id: u64) -> Bytes {
        self.blocked.retain(|b| b.stream_id != stream_id);
        self.blocked_by_stream.remove(&stream_id);
        self.section_size_by_stream.remove(&stream_id);
        let mut out = Vec::new();
        integer::encode(&mut out, stream_id, 6, STREAM_CANCELLATION);
        self.decoder_stream.extend_from_slice(&out);
        Bytes::from_owner(out)
    }

    /// Drops blocked sections older than `max_age` and queues one Stream
    /// Cancellation per affected stream.
    #[cfg(feature = "unstable-internals")]
    #[inline]
    pub fn expire_blocked(&mut self, now: u64, max_age: u64) -> Bytes {
        let mut out = Vec::new();
        let mut cancelled = Vec::with_capacity(self.blocked.len() / 2);
        for blocked in &self.blocked {
            if now.saturating_sub(blocked.since) > max_age
                && !cancelled.contains(&blocked.stream_id)
            {
                cancelled.push(blocked.stream_id);
                integer::encode(&mut out, blocked.stream_id, 6, STREAM_CANCELLATION);
            }
        }
        if !cancelled.is_empty() {
            // Cancelling a stream abandons every queued section on it.
            self.blocked
                .retain(|blocked| !cancelled.contains(&blocked.stream_id));
            for id in &cancelled {
                self.blocked_by_stream.remove(id);
                self.section_size_by_stream.remove(id);
            }
        }
        self.decoder_stream.extend_from_slice(&out);
        Bytes::from(out)
    }

    /// Decodes a field section whose Required Insert Count has been reached,
    /// validating its prefix and size budget (RFC 9204 Section 2.1.2).
    #[inline]
    fn decode_ready(
        &self,
        buf: &[u8],
        budget: Option<usize>,
    ) -> Result<(Vec<(Bytes, Bytes)>, usize), QpackError> {
        let (ric, base, mut off) = self.read_prefix(buf)?;
        let mut headers = Vec::new();
        let mut needed = 0u64;
        let mut size = 0usize;
        while off < buf.len() {
            let header = buf[off];
            off += 1;
            let (name, value) = if header & 0x80 != 0 {
                // Indexed Field Line (4.5.2).
                let index = integer::decode(buf, &mut off, 6, header).map_err(dec_failed)?;
                if header & 0x40 != 0 {
                    // Static table (T=1).
                    let idx =
                        usize::try_from(index).map_err(|_| QpackError::DecompressionFailed)?;
                    let (name, value) =
                        static_table::get(idx).ok_or(QpackError::DecompressionFailed)?;
                    (Bytes::from_static(name), Bytes::from_static(value))
                } else {
                    // Dynamic table (T=0): relative index from the Base.
                    let (name, value) = self
                        .dynamic
                        .get_base_relative_bytes(base, index)
                        .ok_or(QpackError::DecompressionFailed)?;
                    needed = needed.max(base - index);
                    (name, value)
                }
            } else if header & 0x40 != 0 {
                // Literal Field Line with Name Reference (4.5.4).
                let index = integer::decode(buf, &mut off, 4, header).map_err(dec_failed)?;
                let value = self.read_value_string(buf, &mut off).map_err(dec_failed)?;
                if header & 0x10 != 0 {
                    // Static table (T=1).
                    let idx =
                        usize::try_from(index).map_err(|_| QpackError::DecompressionFailed)?;
                    let (name, _) =
                        static_table::get(idx).ok_or(QpackError::DecompressionFailed)?;
                    (Bytes::from_static(name), value)
                } else {
                    // Dynamic table (T=0): relative index from the Base.
                    let (name, _) = self
                        .dynamic
                        .get_base_relative_bytes(base, index)
                        .ok_or(QpackError::DecompressionFailed)?;
                    needed = needed.max(base - index);
                    (name, value)
                }
            } else if header & 0x20 != 0 {
                // Literal Field Line with Literal Name (4.5.6): the N bit is
                // an instruction to peers not to index the line; it does not
                // affect decoding.
                let name = self
                    .read_string(buf, &mut off, 4, header)
                    .map_err(dec_failed)?;
                let value = self.read_value_string(buf, &mut off).map_err(dec_failed)?;
                (name, value)
            } else if header & 0x10 != 0 {
                // Indexed Field Line with Post-Base Index (4.5.3).
                let index = integer::decode(buf, &mut off, 4, header).map_err(dec_failed)?;
                let (name, value) = self
                    .dynamic
                    .get_post_base_bytes(base, index)
                    .ok_or(QpackError::DecompressionFailed)?;
                needed = needed.max(base + index + 1);
                (name, value)
            } else {
                // Literal Field Line with Post-Base Name Reference (4.5.5).
                let index = integer::decode(buf, &mut off, 3, header).map_err(dec_failed)?;
                let (name, _) = self
                    .dynamic
                    .get_post_base_bytes(base, index)
                    .ok_or(QpackError::DecompressionFailed)?;
                needed = needed.max(base + index + 1);
                let value = self.read_value_string(buf, &mut off).map_err(dec_failed)?;
                (name, value)
            };
            // Account the field before retaining it: the budget bounds the
            // memory a single field section can cost, so a section that does
            // not fit is rejected while it is decoded rather than after it
            // has been materialized (RFC 9114 Section 4.2.2).
            size = size.saturating_add(name.len() + value.len() + FIELD_OVERHEAD);
            if budget.is_some_and(|limit| size > limit) {
                return Err(QpackError::DecompressionFailed);
            }
            if headers.len() >= MAX_FIELDS_PER_SECTION {
                return Err(QpackError::DecompressionFailed);
            }
            headers.push((name, value));
        }
        if ric != needed {
            return Err(QpackError::DecompressionFailed);
        }
        Ok((headers, size))
    }

    /// Parses the Encoded Field Section Prefix (RFC 9204 Section 4.5.1):
    /// the Required Insert Count and the Base. Returns both and the number
    /// of octets consumed.
    #[inline]
    fn read_prefix(&self, buf: &[u8]) -> Result<(u64, u64, usize), QpackError> {
        let header = *buf.first().ok_or(QpackError::DecompressionFailed)?;
        let mut off = 1;
        let enc_ric = integer::decode(buf, &mut off, 8, header).map_err(dec_failed)?;
        let max_entries = self.max_capacity / 32;
        let ric = if enc_ric == 0 || max_entries == 0 {
            0
        } else {
            let full_range = 2 * max_entries;
            if enc_ric > full_range {
                return Err(QpackError::DecompressionFailed);
            }
            let max_value = self.dynamic.inserted() + max_entries;
            let max_wrapped = (max_value / full_range) * full_range;
            let mut ric = max_wrapped + enc_ric - 1;
            if ric > max_value {
                if ric <= full_range {
                    return Err(QpackError::DecompressionFailed);
                }
                ric -= full_range;
            }
            if ric == 0 {
                return Err(QpackError::DecompressionFailed);
            }
            ric
        };

        // Base (4.5.1.2): Sign = 0 means Base = Ric + Delta; Sign = 1 means
        // Base = Ric - Delta - 1.
        let header = *buf.get(off).ok_or(QpackError::DecompressionFailed)?;
        off += 1;
        let delta = integer::decode(buf, &mut off, 7, header).map_err(dec_failed)?;
        let base = if header & 0x80 != 0 {
            ric.checked_sub(delta + 1)
                .ok_or(QpackError::DecompressionFailed)?
        } else {
            ric.checked_add(delta)
                .ok_or(QpackError::DecompressionFailed)?
        };
        Ok((ric, base, off))
    }

    /// Reads an N-bit-prefix string literal (RFC 9204 Section 4.1.2) at
    /// `off`, advancing `off` past it. `header` is an already-consumed octet
    /// carrying the Huffman bit (its `prefix_bits - 1` bit) and the length
    /// prefix; for name strings it is the field line's or instruction's
    /// first octet, which pairs with the name length prefix.
    #[inline]
    fn read_string(
        &self,
        buf: &[u8],
        off: &mut usize,
        prefix_bits: u8,
        header: u8,
    ) -> Result<Bytes, HpackError> {
        let huffman = header & (1 << (prefix_bits - 1)) != 0;
        let len = integer::decode(buf, off, prefix_bits - 1, header)?;
        let len = usize::try_from(len).map_err(|_| HpackError::InvalidString)?;
        let end = (*off).checked_add(len).ok_or(HpackError::InvalidString)?;
        let src = buf.get(*off..end).ok_or(HpackError::InvalidString)?;
        *off = end;
        if huffman {
            let mut dst = Vec::with_capacity(len);
            huffman::decode(src, &mut dst)?;
            Ok(Bytes::from(dst))
        } else {
            Ok(Bytes::copy_from_slice(src))
        }
    }

    /// Reads an 8-bit-prefix string literal whose length octet is next in
    /// the buffer, advancing `off` past it. This is the form of every value
    /// string (RFC 9204 Section 4.5).
    #[inline]
    fn read_value_string(&self, buf: &[u8], off: &mut usize) -> Result<Bytes, HpackError> {
        let header = *buf.get(*off).ok_or(HpackError::InvalidString)?;
        *off += 1;
        self.read_string(buf, off, 8, header)
    }

    /// Inserts an entry named `name` with `value`, enforcing the eviction
    /// rules of RFC 9204 Sections 2.1.1 and 3.2.2: entries with an absolute
    /// index at or above the Known Received Count are not evictable, so an
    /// insert that would evict them is an encoder error.
    #[inline]
    fn insert_entry(&mut self, name: Bytes, value: Bytes) -> Result<(), QpackError> {
        let size = DynamicTable::entry_size(&name, &value);
        let evicted = self.dynamic.would_evict(size);
        if evicted > self.known_received {
            return Err(QpackError::EncoderStream);
        }
        self.dynamic
            .insert(name, value)
            .map_err(|_| QpackError::EncoderStream)
    }

    /// Raises the Known Received Count to `ric` (RFC 9204 Section 2.1.4).
    #[inline]
    fn acknowledge(&mut self, ric: u64) {
        self.known_received = self.known_received.max(ric);
    }

    /// Queues a Section Acknowledgment for `stream_id`, unless the maximum
    /// dynamic table capacity is zero (the encoder has no dynamic table
    /// references to free).
    #[inline]
    fn emit_section_ack(&mut self, stream_id: u64) {
        integer::encode(&mut self.decoder_stream, stream_id, 7, SECTION_ACK);
    }

    /// Whether `stream_id` has buffered blocked sections.
    #[inline]
    fn stream_has_blocked(&self, stream_id: u64) -> bool {
        self.blocked_by_stream.contains_key(&stream_id)
    }

    /// Records a newly buffered field section without rescanning the queue.
    #[inline]
    fn add_blocked_section(&mut self, stream_id: u64) {
        *self.blocked_by_stream.entry(stream_id).or_insert(0) += 1;
    }

    /// Charges `size` against `stream_id` and returns the new cumulative
    /// total. `size` is the decoded field-list size, not the encoded size.
    #[inline]
    fn account_section(&mut self, stream_id: u64, size: usize) -> usize {
        let total = self.section_size_by_stream.entry(stream_id).or_insert(0);
        *total = total.saturating_add(size);
        *total
    }

    /// The decoded size still available to `stream_id`, or `None` when the
    /// limit is disabled.
    #[inline]
    fn remaining_budget(&self, stream_id: u64) -> Option<usize> {
        if self.max_field_section_size == usize::MAX {
            return None;
        }
        let used = self
            .section_size_by_stream
            .get(&stream_id)
            .copied()
            .unwrap_or(0);
        Some(self.max_field_section_size.saturating_sub(used))
    }

    /// Removes one decoded blocked section from the per-stream count.
    #[inline]
    fn remove_blocked_section(&mut self, stream_id: u64) {
        let Some(count) = self.blocked_by_stream.get_mut(&stream_id) else {
            debug_assert!(false, "blocked section missing stream accounting");
            return;
        };
        if *count == 1 {
            self.blocked_by_stream.remove(&stream_id);
        } else {
            *count -= 1;
        }
    }
}

/// Maps an `HpackError` from an encoder stream instruction to
/// `QPACK_ENCODER_STREAM_ERROR`.
#[inline]
fn enc_stream_err(_: HpackError) -> QpackError {
    QpackError::EncoderStream
}

/// Maps an `HpackError` from a field section to `QPACK_DECOMPRESSION_FAILED`.
#[inline]
fn dec_failed(_: HpackError) -> QpackError {
    QpackError::DecompressionFailed
}

/// Maps an `HpackError` from a decoder stream instruction to
/// `QPACK_DECODER_STREAM_ERROR`.
#[inline]
fn dec_stream_err(_: HpackError) -> QpackError {
    QpackError::DecoderStream
}
#[cfg(test)]
mod tests;
