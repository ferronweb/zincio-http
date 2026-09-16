//! HTTP/3 frame codec (RFC 9114 Section 7).
//!
//! Frames on HTTP/3 streams have the layout `Type (i), Length (i), Frame
//! Payload (..)` where `Type` and `Length` are QUIC variable-length
//! integers (RFC 9000 Section 16). This module provides:
//!
//! - [`FrameDecoder`]: an incremental, buffer-owning decoder. The driver
//!   feeds received bytes in and pulls completed [`Frame`]s out; `Ok(None)`
//!   means more input is needed. Unknown and reserved (grease) frame types
//!   are skipped without surfacing, per RFC 9114 Section 7.2.8.
//! - [`Frame::encode`]: the corresponding serializer.
//!
//! Parse-level validation follows RFC 9114 Section 7.1: a frame payload
//! must contain exactly the fields identified for its type — extra bytes
//! and truncated fields are `H3_FRAME_ERROR`, as are redundant
//! (non-minimal) variable-length integer encodings (Section 10.8, RFC 9000
//! Section 16). HTTP/2 frame types without an HTTP/3 equivalent
//! (PRIORITY, PING, WINDOW_UPDATE, CONTINUATION) are `H3_FRAME_UNEXPECTED`
//! (Section 7.2.8).
//!
//! What this module deliberately does *not* enforce — it is the driver's
//! (connection-state) job:
//!
//! - stream-type rules (which frame types are legal on which stream, and
//!   that SETTINGS is first on the control stream),
//! - `SETTINGS_MAX_FIELD_SECTION_SIZE` limits on HEADERS/PUSH_PROMISE
//!   payloads,
//! - push ID / stream ID semantics (`H3_ID_ERROR`).
//!
//! A clean end of stream (FIN) with `buffered() != 0` means the last frame
//! was truncated; RFC 9114 Section 7.1 requires that be treated as
//! `H3_FRAME_ERROR` by the driver.

use std::collections::VecDeque;

use bytes::{BufMut, Bytes, BytesMut};
use rustc_hash::FxHashMap;

/// The largest value a QUIC variable-length integer can carry.
pub const MAX_VARINT: u64 = (1 << 62) - 1;

/// Maximum number of setting identifiers accepted in one SETTINGS frame
/// (RFC 9114 Section 7.2.4).
///
/// Fewer than ten identifiers are defined; the implementation sends five.
/// A frame carrying more than this is abusive (CVE-class algorithmic
/// complexity: previously each entry paid a linear duplicate scan, giving
/// O(n^2) work in the entry count) and is rejected with `H3_SETTINGS_ERROR`.
pub const MAX_SETTINGS_ENTRIES: usize = 32;

/// Maximum SETTINGS frame payload in bytes.
///
/// With [`MAX_SETTINGS_ENTRIES`] entries of at most 16 bytes each (two
/// 8-byte varints) no legitimate payload exceeds 512 bytes; this leaves
/// 8x headroom while preventing an attacker from forcing the decoder to
/// buffer megabytes before parsing. Oversized payloads are rejected with
/// `H3_SETTINGS_ERROR` as soon as the length is declared, without waiting
/// for (or buffering) the full payload.
pub const MAX_SETTINGS_PAYLOAD: u64 = 4096;

/// Maximum payload of any single HTTP/3 frame in bytes.
///
/// QUIC varint lengths reach 2^62-1, but buffering an unbounded payload
/// before parsing is a memory-exhaustion vector. This ceiling (parity with
/// HTTP/2's `MAX_FRAME_SIZE_LIMIT`) bounds per-frame buffering; larger
/// declared lengths are rejected with `H3_FRAME_ERROR` immediately.
/// Legitimate traffic (control frames are tiny; request bodies stream as
/// sequences of smaller DATA frames) is unaffected.
pub const MAX_FRAME_PAYLOAD: u64 = 16_777_215;

/// `DATA` frame type (RFC 9114 Section 7.2.1).
pub const FRAME_DATA: u64 = 0x0;
/// `HEADERS` frame type (RFC 9114 Section 7.2.2).
pub const FRAME_HEADERS: u64 = 0x1;
/// `CANCEL_PUSH` frame type (RFC 9114 Section 7.2.3).
pub const FRAME_CANCEL_PUSH: u64 = 0x3;
/// `SETTINGS` frame type (RFC 9114 Section 7.2.4).
pub const FRAME_SETTINGS: u64 = 0x4;
/// `PUSH_PROMISE` frame type (RFC 9114 Section 7.2.5).
pub const FRAME_PUSH_PROMISE: u64 = 0x5;
/// `GOAWAY` frame type (RFC 9114 Section 7.2.6).
pub const FRAME_GOAWAY: u64 = 0x7;
/// `MAX_PUSH_ID` frame type (RFC 9114 Section 7.2.7).
pub const FRAME_MAX_PUSH_ID: u64 = 0xd;

/// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (RFC 9204 Section 5).
///
/// Consumed by the control-stream driver when interpreting peer SETTINGS.
#[allow(dead_code)]
pub const SETTINGS_QPACK_MAX_TABLE_CAPACITY: u64 = 0x1;
/// `SETTINGS_MAX_FIELD_SECTION_SIZE` (RFC 9114 Section 7.2.4.1).
///
/// Consumed by the control-stream driver when interpreting peer SETTINGS.
#[allow(dead_code)]
pub const SETTINGS_MAX_FIELD_SECTION_SIZE: u64 = 0x6;
/// `SETTINGS_QPACK_BLOCKED_STREAMS` (RFC 9204 Section 5).
///
/// Consumed by the control-stream driver when interpreting peer SETTINGS.
#[allow(dead_code)]
pub const SETTINGS_QPACK_BLOCKED_STREAMS: u64 = 0x7;
/// `SETTINGS_ENABLE_CONNECT_PROTOCOL` (RFC 9114 Section 7.2.4.1).
///
/// Consumed by the control-stream driver when interpreting peer SETTINGS.
#[allow(dead_code)]
pub const SETTINGS_ENABLE_CONNECT_PROTOCOL: u64 = 0x8;
/// `SETTINGS_H3_DATAGRAM` (RFC 9297 Section 3.1).
///
/// Consumed by the control-stream driver when interpreting peer SETTINGS.
#[allow(dead_code)]
pub const SETTINGS_H3_DATAGRAM: u64 = 0x33;

/// A single SETTINGS parameter: `(identifier, value)`.
pub type Setting = (u64, u64);

/// A parsed `SETTINGS` frame payload (RFC 9114 Section 7.2.4).
///
/// Settings are kept in wire order. Reserved (grease) identifiers are
/// dropped on decode and may be added for encoding; unknown identifiers
/// are preserved and ignored by the driver.
///
/// Duplicate detection is O(1) per entry via an index map (first value
/// wins, matching the previous linear-scan semantics), so parsing is O(n)
/// overall rather than O(n^2).
#[derive(Debug, Clone, Default)]
pub struct Settings {
    entries: Vec<Setting>,
    /// Index of first-seen value per identifier (insertion order is kept
    /// in `entries`, which may hold wire duplicates for re-encoding).
    lookup: FxHashMap<u64, u64>,
}

impl PartialEq for Settings {
    #[inline]
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}

impl Eq for Settings {}

impl Settings {
    /// An empty SETTINGS payload.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends a `(identifier, value)` parameter in wire order.
    #[inline]
    pub fn insert(&mut self, id: u64, value: u64) {
        self.entries.push((id, value));
        self.lookup.entry(id).or_insert(value);
    }

    /// The value of the first parameter with `id`, if any.
    #[inline]
    pub fn get(&self, id: u64) -> Option<u64> {
        self.lookup.get(&id).copied()
    }

    /// The parameters in wire order.
    #[inline]
    pub fn iter(&self) -> impl Iterator<Item = Setting> + '_ {
        self.entries.iter().copied()
    }

    /// Number of parameters held (wire order, including any duplicates
    /// added via [`Settings::insert`]).
    #[inline]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether the payload holds no parameters.
    #[inline]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// An HTTP/3 frame (RFC 9114 Section 7.2).
///
/// `Data` and `Headers` payloads are opaque byte ranges. `Data` is the
/// streamed body chunk (the driver may hand it to the body reader
/// without copying); `Headers` and `PushPromise` field sections are
/// QPACK-encoded and decoded by the driver.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    /// `DATA`: a chunk of the request or response body.
    Data(Bytes),
    /// `HEADERS`: the QPACK-encoded field section.
    Headers(Bytes),
    /// `SETTINGS`: connection parameters (first frame of a control
    /// stream).
    Settings(Settings),
    /// `CANCEL_PUSH`: push ID whose push the peer should abandon.
    CancelPush(u64),
    /// `PUSH_PROMISE`: push ID plus the promised request's QPACK-encoded
    /// field section.
    PushPromise { push_id: u64, field_section: Bytes },
    /// `GOAWAY`: the highest stream ID (server) or push ID (client) the
    /// sender will process.
    Goaway(u64),
    /// `MAX_PUSH_ID`: the highest push ID the server may use.
    MaxPushId(u64),
}

impl Frame {
    /// Whether this is one of the known HTTP/3 frame types (RFC 9114
    /// Section 7.2).
    ///
    /// The decoder never surfaces unknown or reserved (grease) frame types
    /// — they are consumed and skipped (Section 7.2.8) — so every frame it
    /// returns is by construction a known type. This method documents the
    /// request-stream rule (Section 4.1) that after the trailers only
    /// unknown frames may still appear.
    #[inline]
    pub fn is_known(&self) -> bool {
        matches!(
            self,
            Frame::Data(_)
                | Frame::Headers(_)
                | Frame::Settings(_)
                | Frame::CancelPush(_)
                | Frame::PushPromise { .. }
                | Frame::Goaway(_)
                | Frame::MaxPushId(_)
        )
    }

    /// Serializes this frame (type, length, payload) into `dst`.
    #[inline]
    pub fn encode(&self, dst: &mut BytesMut) {
        match self {
            Frame::Data(payload) => {
                write_varint(FRAME_DATA, dst);
                write_varint(payload.len() as u64, dst);
                dst.extend_from_slice(payload);
            }
            Frame::Headers(payload) => {
                write_varint(FRAME_HEADERS, dst);
                write_varint(payload.len() as u64, dst);
                dst.extend_from_slice(payload);
            }
            Frame::Settings(settings) => {
                write_varint(FRAME_SETTINGS, dst);
                let len: usize = settings
                    .entries
                    .iter()
                    .map(|(id, value)| varint_size(*id) + varint_size(*value))
                    .sum();
                write_varint(len as u64, dst);
                for (id, value) in &settings.entries {
                    write_varint(*id, dst);
                    write_varint(*value, dst);
                }
            }
            Frame::CancelPush(push_id) => {
                write_varint(FRAME_CANCEL_PUSH, dst);
                write_varint(varint_size(*push_id) as u64, dst);
                write_varint(*push_id, dst);
            }
            Frame::PushPromise {
                push_id,
                field_section,
            } => {
                write_varint(FRAME_PUSH_PROMISE, dst);
                write_varint((varint_size(*push_id) + field_section.len()) as u64, dst);
                write_varint(*push_id, dst);
                dst.extend_from_slice(field_section);
            }
            Frame::Goaway(stream_id) => {
                write_varint(FRAME_GOAWAY, dst);
                write_varint(varint_size(*stream_id) as u64, dst);
                write_varint(*stream_id, dst);
            }
            Frame::MaxPushId(push_id) => {
                write_varint(FRAME_MAX_PUSH_ID, dst);
                write_varint(varint_size(*push_id) as u64, dst);
                write_varint(*push_id, dst);
            }
        }
    }
}

/// Errors raised by [`FrameDecoder::next_frame`].
///
/// Each variant corresponds to a distinct RFC 9114 connection error code
/// (see [`FrameError::h3_code`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FrameError {
    /// `H3_FRAME_ERROR` (0x0106): the frame payload does not exactly match
    /// the fields identified for its type, or a variable-length integer is
    /// encoded non-minimally (RFC 9114 Sections 7.1 and 10.8).
    Frame,
    /// `H3_FRAME_UNEXPECTED` (0x0105): an HTTP/2 frame type with no
    /// HTTP/3 equivalent (PRIORITY, PING, WINDOW_UPDATE, CONTINUATION;
    /// RFC 9114 Section 7.2.8).
    Unexpected(u64),
    /// `H3_SETTINGS_ERROR` (0x0109): a reserved setting identifier
    /// (0x02-0x05) or a duplicate identifier in one SETTINGS frame
    /// (RFC 9114 Section 7.2.4).
    Settings,
}

impl FrameError {
    /// The RFC 9114 connection error code for this error.
    pub const fn h3_code(self) -> u64 {
        use crate::h3::H3Error;
        match self {
            FrameError::Frame => H3Error::FrameError.code(),
            FrameError::Unexpected(_) => H3Error::FrameUnexpected.code(),
            FrameError::Settings => H3Error::Settings.code(),
        }
    }
}

/// Incremental HTTP/3 frame decoder.
///
/// The decoder owns its buffer: the driver calls [`FrameDecoder::extend`]
/// with every received chunk and [`FrameDecoder::next_frame`] once per
/// event-loop turn, draining as many complete frames as are buffered.
///
/// The buffer is a `VecDeque<Bytes>` that keeps each QUIC chunk intact.
/// `extend` is zero-copy (push), and `DATA` payloads are returned as
/// refcounted slices when they lie in a single chunk, avoiding the
/// `BytesMut` coalesce on every fragment.
#[derive(Debug, Default)]
pub struct FrameDecoder {
    bufs: VecDeque<Bytes>,
    len: usize,
}

impl FrameDecoder {
    /// A decoder with an empty buffer.
    #[inline]
    pub fn new() -> Self {
        Self::default()
    }

    /// Appends received bytes to the input buffer.
    #[inline]
    pub fn extend(&mut self, data: Bytes) {
        if data.is_empty() {
            return;
        }
        self.len += data.len();
        self.bufs.push_back(data);
    }

    /// Bytes buffered but not yet consumed by a frame.
    #[inline]
    pub fn buffered(&self) -> usize {
        self.len
    }

    /// Pops the next complete frame, if any.
    ///
    /// Returns `Ok(None)` when the buffer does not yet hold a complete
    /// frame; callers must extend the buffer and poll again. Unknown and
    /// reserved frame types are consumed and skipped (RFC 9114 Section
    /// 7.2.8) — a known frame behind them is still returned.
    #[inline]
    pub fn next_frame(&mut self) -> Result<Option<Frame>, FrameError> {
        loop {
            let Some((ty, type_len)) = self.parse_varint_at(0)? else {
                return Ok(None);
            };
            if matches!(ty, 0x02 | 0x06 | 0x08 | 0x09) {
                return Err(FrameError::Unexpected(ty));
            }
            let Some((len, len_len)) = self.parse_varint_at(type_len)? else {
                return Ok(None);
            };
            // Bound per-frame buffering before waiting for (or allocating)
            // the payload: oversized SETTINGS are a settings violation,
            // anything else absurdly large is a frame error. Checking the
            // declared length first means a multi-megabyte abusive frame
            // is rejected from its ~10-byte header without buffering.
            if ty == FRAME_SETTINGS && len > MAX_SETTINGS_PAYLOAD {
                return Err(FrameError::Settings);
            }
            if len > MAX_FRAME_PAYLOAD {
                return Err(FrameError::Frame);
            }
            let header_len = type_len + len_len;
            let Some(total) = header_len.checked_add(len as usize) else {
                return Err(FrameError::Frame);
            };
            if total > self.len {
                return Ok(None);
            }
            if !is_known_frame_type(ty) {
                self.advance(total);
                continue;
            }
            self.advance(header_len);
            let payload = self.take_bytes(len as usize);
            let frame = match ty {
                FRAME_DATA => Frame::Data(payload),
                FRAME_HEADERS => Frame::Headers(payload),
                FRAME_CANCEL_PUSH => Frame::CancelPush(take_varint(&payload)?),
                FRAME_SETTINGS => Frame::Settings(parse_settings(&payload)?),
                FRAME_PUSH_PROMISE => {
                    let Some((push_id, id_len)) = parse_varint(&payload)? else {
                        return Err(FrameError::Frame);
                    };
                    Frame::PushPromise {
                        push_id,
                        field_section: payload.slice(id_len..),
                    }
                }
                FRAME_GOAWAY => Frame::Goaway(take_varint(&payload)?),
                FRAME_MAX_PUSH_ID => Frame::MaxPushId(take_varint(&payload)?),
                _ => unreachable!("unknown types are skipped above"),
            };
            return Ok(Some(frame));
        }
    }

    /// Returns the type of the next frame without consuming it, or `None`
    /// when the type varint is incomplete. Used to pre-reject control-plane
    /// frames on request streams (RFC 9114 Sections 7.2.3-7.2.7) before the
    /// decoder parses (and would otherwise accept or mismatch) them.
    #[inline]
    pub fn peek_frame_type(&self) -> Option<u64> {
        match self.parse_varint_at(0) {
            Ok(Some((ty, _))) => Some(ty),
            _ => None,
        }
    }

    #[inline]
    fn byte_at(&self, offset: usize) -> Option<u8> {
        let mut remaining = offset;
        for buf in &self.bufs {
            if remaining < buf.len() {
                return Some(buf[remaining]);
            }
            remaining -= buf.len();
        }
        None
    }

    #[inline]
    fn parse_varint_at(&self, offset: usize) -> Result<Option<(u64, usize)>, FrameError> {
        if offset >= self.len {
            return Ok(None);
        }
        let first = self.byte_at(offset).expect("offset < len");
        let len = 1usize << (first >> 6);
        if self.len < offset + len {
            return Ok(None);
        }
        let mut value = u64::from(first & 0x3f);
        for i in 1..len {
            let b = self.byte_at(offset + i).expect("offset + offest_len < len");
            value = (value << 8) | u64::from(b);
        }
        if len > 1 && value < MIN_VARINT[usize::from(first >> 6)] {
            return Err(FrameError::Frame);
        }
        Ok(Some((value, len)))
    }

    #[inline]
    fn advance(&mut self, n: usize) {
        debug_assert!(n <= self.len);
        let mut remaining = n;
        while remaining > 0 {
            let front_len = self.bufs.front().expect("advance within len").len();
            if front_len <= remaining {
                self.bufs.pop_front();
                remaining -= front_len;
            } else {
                let mut front = self.bufs.pop_front().expect("advance within len");
                front = front.slice(remaining..);
                self.bufs.push_front(front);
                remaining = 0;
            }
        }
        self.len -= n;
    }

    #[inline]
    fn take_bytes(&mut self, n: usize) -> Bytes {
        if n == 0 {
            return Bytes::new();
        }
        debug_assert!(n <= self.len);
        if let Some(bytes) = self.bufs.pop_front_if(|front| front.len() == n) {
            self.len -= n;
            return bytes;
        }
        if let Some(mut first) = self.bufs.pop_front_if(|front| front.len() > n) {
            let payload = first.split_to(n);
            if !first.is_empty() {
                self.bufs.push_front(first);
            }
            self.len -= n;
            return payload;
        }
        // Fragmented across multiple chunks: coalesce.
        let mut out = BytesMut::with_capacity(n);
        let mut remaining = n;
        while remaining > 0 {
            let mut front = self.bufs.pop_front().expect("take_bytes within len");
            if front.len() <= remaining {
                out.extend_from_slice(&front);
                remaining -= front.len();
            } else {
                let part = front.split_to(remaining);
                out.extend_from_slice(&part);
                self.bufs.push_front(front);
                remaining = 0;
            }
        }
        self.len -= n;
        out.freeze()
    }
}

#[inline]
fn is_known_frame_type(ty: u64) -> bool {
    matches!(
        ty,
        FRAME_DATA
            | FRAME_HEADERS
            | FRAME_CANCEL_PUSH
            | FRAME_SETTINGS
            | FRAME_PUSH_PROMISE
            | FRAME_GOAWAY
            | FRAME_MAX_PUSH_ID
    )
}

/// Reserved grease identifiers: `0x1f * N + 0x21` (RFC 9114 Sections 7.2.8
/// and 7.2.4.1) — must be ignored, never interpreted.
#[inline]
fn is_grease(v: u64) -> bool {
    v >= 0x21 && (v - 0x21).is_multiple_of(0x1f)
}

#[inline]
fn is_reserved_setting(id: u64) -> bool {
    (0x02..=0x05).contains(&id)
}

#[inline]
fn parse_settings(payload: &[u8]) -> Result<Settings, FrameError> {
    if payload.len() as u64 > MAX_SETTINGS_PAYLOAD {
        return Err(FrameError::Settings);
    }
    let mut settings = Settings::new();
    let mut rest = payload;
    // Bound the entry count so a many-entry frame is rejected after
    // bounded work. Duplicate detection below is O(1) per entry via the
    // settings index (previously a linear scan per entry, i.e. O(n^2)
    // in the entry count), so the overall parse is O(n).
    let mut count: usize = 0;
    while !rest.is_empty() {
        let Some((id, id_len)) = parse_varint(rest)? else {
            return Err(FrameError::Frame);
        };
        rest = &rest[id_len..];
        let Some((value, value_len)) = parse_varint(rest)? else {
            return Err(FrameError::Frame);
        };
        rest = &rest[value_len..];
        count += 1;
        if count > MAX_SETTINGS_ENTRIES {
            return Err(FrameError::Settings);
        }
        if is_reserved_setting(id) {
            return Err(FrameError::Settings);
        }
        if settings.get(id).is_some() {
            return Err(FrameError::Settings);
        }
        if !is_grease(id) {
            settings.insert(id, value);
        }
    }
    Ok(settings)
}

/// Parses the single variable-length integer that must fill `buf` exactly
/// (used for CANCEL_PUSH, GOAWAY, MAX_PUSH_ID, and the PUSH_PROMISE push
/// ID). A truncated or non-minimal integer, or trailing bytes, is
/// `H3_FRAME_ERROR` (RFC 9114 Sections 7.1 and 10.8).
#[inline]
fn take_varint(buf: &[u8]) -> Result<u64, FrameError> {
    let Some((value, n)) = parse_varint(buf)? else {
        return Err(FrameError::Frame);
    };
    if n != buf.len() {
        return Err(FrameError::Frame);
    }
    Ok(value)
}

/// The minimum value each variable-length integer encoding width can carry
/// (indexed by the prefix bits `first >> 6`). A value below it in that width
/// is a non-minimal encoding (RFC 9000 Section 16).
const MIN_VARINT: [u64; 4] = [0, 1 << 6, 1 << 14, 1 << 30];

/// Parses a QUIC variable-length integer (RFC 9000 Section 16) from the
/// front of `buf`.
///
/// Returns `Ok(None)` when `buf` is shorter than the encoding; `Err` when
/// the encoding is non-minimal (a protocol violation, per RFC 9000 Section
/// 16, surfaced as `H3_FRAME_ERROR`).
///
/// The control plane uses this to read uni stream type varints before a
/// stream is assigned its role.
#[inline]
pub(crate) fn parse_varint(buf: &[u8]) -> Result<Option<(u64, usize)>, FrameError> {
    let Some(&first) = buf.first() else {
        return Ok(None);
    };
    let len = 1usize << (first >> 6);
    if buf.len() < len {
        return Ok(None);
    }
    let mut value = u64::from(first & 0x3f);
    for &byte in &buf[1..len] {
        value = (value << 8) | u64::from(byte);
    }
    // Minimal encoding: the value must not fit in the next-smaller
    // encoding. 2-byte values must be >= 2^6, 4-byte >= 2^14, 8-byte >=
    // 2^30 (RFC 9000 Section 16).
    if len > 1 && value < MIN_VARINT[usize::from(first >> 6)] {
        return Err(FrameError::Frame);
    }
    Ok(Some((value, len)))
}

/// The encoded length of `value` as a QUIC variable-length integer.
#[inline]
pub fn varint_size(value: u64) -> usize {
    if value < (1 << 6) {
        1
    } else if value < (1 << 14) {
        2
    } else if value < (1 << 30) {
        4
    } else {
        8
    }
}

/// Encodes `value` as a QUIC variable-length integer (RFC 9000 Section
/// 16). Panics in debug builds if `value` does not fit.
#[inline]
pub fn write_varint(value: u64, dst: &mut BytesMut) {
    debug_assert!(value <= MAX_VARINT, "varint out of range: {value:#x}");
    if value < (1 << 6) {
        dst.put_u8(value as u8);
    } else if value < (1 << 14) {
        dst.put_u16((0b01 << 14) | value as u16);
    } else if value < (1 << 30) {
        dst.put_u32((0b10 << 30) | value as u32);
    } else {
        dst.put_u64((0b11 << 62) | value);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    fn decode_all(decoder: &mut FrameDecoder) -> Result<Vec<Frame>, FrameError> {
        let mut frames = Vec::new();
        while let Some(frame) = decoder.next_frame()? {
            frames.push(frame);
        }
        Ok(frames)
    }

    #[inline]
    fn encode_frames(frames: &[Frame]) -> Bytes {
        let mut buf = BytesMut::new();
        for frame in frames {
            frame.encode(&mut buf);
        }
        buf.freeze()
    }

    #[test]
    fn round_trip_all_frame_types() {
        let mut settings = Settings::new();
        settings.insert(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 4096);
        settings.insert(SETTINGS_MAX_FIELD_SECTION_SIZE, 100);
        settings.insert(SETTINGS_QPACK_BLOCKED_STREAMS, 2);
        settings.insert(0x21, 7); // grease: preserved on encode, ignored on decode

        let frames = [
            Frame::Data(Bytes::from_static(b"hello world")),
            Frame::Headers(Bytes::from_static(b"\x3f\xbd\x01")),
            Frame::Settings(settings),
            Frame::CancelPush(7),
            Frame::PushPromise {
                push_id: 1,
                field_section: Bytes::from_static(b"\x05\x00\x80"),
            },
            Frame::Goaway(2),
            Frame::MaxPushId(0),
            Frame::Data(Bytes::new()),
            Frame::Headers(Bytes::new()),
        ];
        let mut decoder = FrameDecoder::new();
        decoder.extend(encode_frames(&frames));
        let got = decode_all(&mut decoder).expect("all frames parse");

        // Reserved grease setting is dropped, everything else round-trips.
        let mut expected = frames.to_vec();
        expected[2] = Frame::Settings(settings_without_grease());
        assert_eq!(got, expected);
    }

    #[inline]
    fn settings_without_grease() -> Settings {
        let mut s = Settings::new();
        s.insert(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 4096);
        s.insert(SETTINGS_MAX_FIELD_SECTION_SIZE, 100);
        s.insert(SETTINGS_QPACK_BLOCKED_STREAMS, 2);
        s
    }

    #[test]
    fn incremental_byte_at_a_time() {
        let wire = encode_frames(&[
            Frame::Headers(Bytes::from_static(b"abc")),
            Frame::Data(Bytes::from_static(b"xy")),
        ]);
        let mut decoder = FrameDecoder::new();
        let mut got = Vec::new();
        for (i, &byte) in wire.iter().enumerate() {
            decoder.extend(Bytes::copy_from_slice(&[byte]));
            while let Some(frame) = decoder.next_frame().unwrap() {
                got.push(frame);
            }
            if i < 4 {
                assert!(got.is_empty(), "frame appeared early at byte {i}");
            }
            if i == 4 {
                // The full HEADERS frame appears exactly when its last
                // byte lands.
                assert_eq!(got, vec![Frame::Headers(Bytes::from_static(b"abc"))]);
            }
        }
        assert_eq!(
            got,
            vec![
                Frame::Headers(Bytes::from_static(b"abc")),
                Frame::Data(Bytes::from_static(b"xy")),
            ]
        );
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn truncated_prefixes_are_incomplete() {
        // Type byte only.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x00]));
        assert_eq!(decoder.next_frame().unwrap(), None);
        // Type + length, no payload yet.
        decoder.extend(Bytes::from_static(&[0x05]));
        assert_eq!(decoder.next_frame().unwrap(), None);
        // Partial payload.
        decoder.extend(Bytes::from_static(b"he"));
        assert_eq!(decoder.next_frame().unwrap(), None);
        // Rest of the payload completes the frame.
        decoder.extend(Bytes::from_static(b"llo"));
        assert_eq!(
            decode_all(&mut decoder).unwrap(),
            vec![Frame::Data(Bytes::from_static(b"hello"))]
        );

        // A frame declaring an absurd length (far beyond
        // MAX_FRAME_PAYLOAD) is rejected from its header without
        // buffering or allocating the payload.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[
            0x01, 0xc0, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        ]));
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Frame);
        assert_eq!(decoder.buffered(), 10);
    }

    #[test]
    fn forbidden_http2_frames() {
        for ty in [0x02u8, 0x06, 0x08, 0x09] {
            let mut decoder = FrameDecoder::new();
            decoder.extend(Bytes::copy_from_slice(&[ty, 0x01, 0x00]));
            let err = decoder.next_frame().unwrap_err();
            assert_eq!(err, FrameError::Unexpected(u64::from(ty)));
            assert_eq!(err.h3_code(), 0x0105);
        }
    }

    #[test]
    fn unknown_and_grease_frames_are_skipped() {
        // Unknown type 0x42 with payload, grease 0x21/0x40/0x5f with
        // arbitrary payload, between two known frames.
        let mut wire = BytesMut::new();
        Frame::Headers(Bytes::from_static(b"first")).encode(&mut wire);
        write_varint(0x42, &mut wire);
        write_varint(3, &mut wire);
        wire.extend_from_slice(b"xyz");
        write_varint(0x21, &mut wire);
        write_varint(2, &mut wire);
        wire.extend_from_slice(&[0xde, 0xad]);
        Frame::Data(Bytes::from_static(b"last")).encode(&mut wire);

        let mut decoder = FrameDecoder::new();
        decoder.extend(wire.freeze());
        let frames = decode_all(&mut decoder).unwrap();
        assert_eq!(
            frames,
            vec![
                Frame::Headers(Bytes::from_static(b"first")),
                Frame::Data(Bytes::from_static(b"last")),
            ]
        );
        assert_eq!(decoder.buffered(), 0);
    }

    #[test]
    fn settings_payload_validation() {
        // Empty SETTINGS is legal.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x04, 0x00]));
        assert_eq!(
            decode_all(&mut decoder).unwrap(),
            vec![Frame::Settings(Settings::new())]
        );

        // Duplicate identifier -> H3_SETTINGS_ERROR.
        let mut wire = BytesMut::new();
        Frame::Settings({
            let mut s = Settings::new();
            s.insert(0x06, 1);
            s.insert(0x06, 2);
            s
        })
        .encode(&mut wire);
        let mut decoder = FrameDecoder::new();
        decoder.extend(wire.freeze());
        let err = decoder.next_frame().unwrap_err();
        assert_eq!(err, FrameError::Settings);
        assert_eq!(err.h3_code(), 0x0109);

        // Reserved identifiers 0x02-0x05 -> H3_SETTINGS_ERROR.
        for id in 0x02..=0x05 {
            let mut wire = BytesMut::new();
            Frame::Settings({
                let mut s = Settings::new();
                s.insert(id, 0);
                s
            })
            .encode(&mut wire);
            let mut decoder = FrameDecoder::new();
            decoder.extend(wire.freeze());
            assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Settings);
        }

        // Unknown identifier is preserved (the driver ignores it), known
        // ones surface.
        let mut s = Settings::new();
        s.insert(0x0100, 5);
        s.insert(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1);
        let mut wire = BytesMut::new();
        Frame::Settings(s.clone()).encode(&mut wire);
        let mut decoder = FrameDecoder::new();
        decoder.extend(wire.freeze());
        match decode_all(&mut decoder).unwrap()[0].clone() {
            Frame::Settings(got) => {
                assert_eq!(got.get(0x0100), Some(5));
                assert_eq!(got.get(SETTINGS_ENABLE_CONNECT_PROTOCOL), Some(1));
            }
            other => panic!("expected Settings, got {other:?}"),
        }

        // Odd-length payload (a lone identifier) -> H3_FRAME_ERROR.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x04, 0x01, 0x06]));
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Frame);
    }

    #[inline]
    fn distinct_test_ids(n: usize) -> Vec<u64> {
        // Distinct, non-reserved, non-grease identifiers for entry-cap
        // tests (grease `0x21 + 0x1f*k` and reserved `0x02-0x05` are
        // skipped so every entry is inserted).
        let mut ids = Vec::new();
        let mut id = 0x1000u64;
        while ids.len() < n {
            if !(0x02..=0x05).contains(&id) && !(id >= 0x21 && (id - 0x21) % 0x1f == 0) {
                ids.push(id);
            }
            id += 1;
        }
        ids
    }

    #[test]
    fn settings_lookup_returns_first_value() {
        // `get` keeps the previous linear-scan semantics (first value
        // wins) while running in O(1).
        let mut s = Settings::new();
        s.insert(0x06, 1);
        s.insert(0x06, 2);
        assert_eq!(s.get(0x06), Some(1));
        assert_eq!(s.len(), 2);
        assert!(!s.is_empty());
        assert!(Settings::new().is_empty());
    }

    #[test]
    fn settings_rejects_too_many_entries() {
        // More than MAX_SETTINGS_ENTRIES distinct identifiers ->
        // H3_SETTINGS_ERROR after bounded work. The wire payload stays
        // under MAX_SETTINGS_PAYLOAD here, so this isolates the entry
        // cap (not the length cap).
        let mut s = Settings::new();
        for id in distinct_test_ids(MAX_SETTINGS_ENTRIES + 1) {
            s.insert(id, 0);
        }
        let mut wire = BytesMut::new();
        Frame::Settings(s).encode(&mut wire);
        assert!((wire.len() as u64) < MAX_SETTINGS_PAYLOAD + 16);
        let mut decoder = FrameDecoder::new();
        decoder.extend(wire.freeze());
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Settings);
    }

    #[test]
    fn settings_at_cap_parses() {
        // Exactly MAX_SETTINGS_ENTRIES distinct identifiers is accepted.
        let mut s = Settings::new();
        for id in distinct_test_ids(MAX_SETTINGS_ENTRIES) {
            s.insert(id, 0);
        }
        let mut wire = BytesMut::new();
        Frame::Settings(s).encode(&mut wire);
        let mut decoder = FrameDecoder::new();
        decoder.extend(wire.freeze());
        match decoder.next_frame().unwrap().unwrap() {
            Frame::Settings(got) => assert_eq!(got.len(), MAX_SETTINGS_ENTRIES),
            other => panic!("expected Settings, got {other:?}"),
        }
    }

    #[test]
    fn settings_rejects_oversized_payload_without_buffering() {
        // A SETTINGS length declaration beyond MAX_SETTINGS_PAYLOAD is
        // rejected from the header alone (H3_SETTINGS_ERROR), without
        // waiting for or buffering the payload.
        let mut wire = BytesMut::new();
        write_varint(FRAME_SETTINGS, &mut wire);
        write_varint(MAX_SETTINGS_PAYLOAD + 1, &mut wire);
        let header_len = wire.len();
        let mut decoder = FrameDecoder::new();
        decoder.extend(wire.freeze());
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Settings);
        assert_eq!(decoder.buffered(), header_len);
    }

    #[test]
    fn oversized_frames_rejected_from_header() {
        // Any frame declaring beyond MAX_FRAME_PAYLOAD is rejected
        // immediately (H3_FRAME_ERROR) instead of buffering unboundedly.
        let mut wire = BytesMut::new();
        write_varint(FRAME_DATA, &mut wire);
        write_varint(MAX_FRAME_PAYLOAD + 1, &mut wire);
        let mut decoder = FrameDecoder::new();
        decoder.extend(wire.freeze());
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Frame);
    }

    #[test]
    fn fixed_value_frames_reject_bad_payloads() {
        // CANCEL_PUSH with no payload -> H3_FRAME_ERROR.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x03, 0x00]));
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Frame);

        // CANCEL_PUSH with trailing bytes -> H3_FRAME_ERROR.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x03, 0x02, 0x01, 0x00]));
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Frame);

        // CANCEL_PUSH with a redundant 2-byte encoding of 5 -> H3_FRAME_ERROR.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x03, 0x02, 0x40, 0x05]));
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Frame);

        // GOAWAY with a minimal 1-byte value parses.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x07, 0x01, 0x05]));
        assert_eq!(decode_all(&mut decoder).unwrap(), vec![Frame::Goaway(5)]);

        // Non-minimal type encoding (0 encoded in 2 bytes) -> error.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x40, 0x00, 0x00]));
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Frame);

        // Non-minimal length encoding -> error.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x00, 0x40, 0x00]));
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Frame);
    }

    #[test]
    fn push_promise_shapes() {
        // push ID plus field section.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x05, 0x04, 0x01, b'a', b'b', b'c']));
        assert_eq!(
            decode_all(&mut decoder).unwrap(),
            vec![Frame::PushPromise {
                push_id: 1,
                field_section: Bytes::from_static(b"abc"),
            }]
        );

        // Empty field section.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x05, 0x01, 0x01]));
        assert_eq!(
            decode_all(&mut decoder).unwrap(),
            vec![Frame::PushPromise {
                push_id: 1,
                field_section: Bytes::new(),
            }]
        );

        // Missing push ID -> H3_FRAME_ERROR.
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x05, 0x00]));
        assert_eq!(decoder.next_frame().unwrap_err(), FrameError::Frame);
    }

    #[test]
    fn varint_edge_encodings() {
        // Boundaries: 2^6-1 (1 byte), 2^6 (2 bytes), 2^14-1, 2^14, 2^30-1,
        // 2^30, 2^62-1 (max).
        for value in [
            (1 << 6) - 1,
            1 << 6,
            (1 << 14) - 1,
            1 << 14,
            (1 << 30) - 1,
            1 << 30,
            MAX_VARINT,
        ] {
            let mut wire = BytesMut::new();
            write_varint(value, &mut wire);
            assert_eq!(wire.len(), varint_size(value));
            let (got, n) = parse_varint(&wire).unwrap().unwrap();
            assert_eq!(got, value);
            assert_eq!(n, wire.len());
        }

        // Non-minimal encodings are rejected.
        assert_eq!(parse_varint(&[0x40, 0x00]), Err(FrameError::Frame)); // 0 in 2 bytes
        assert_eq!(
            parse_varint(&[0x80, 0x00, 0x00, 0x40]),
            Err(FrameError::Frame)
        ); // 64 in 4 bytes
        assert_eq!(parse_varint(&[0x40, 0x40]), Ok(Some((64, 2))));
        // Truncated.
        assert_eq!(parse_varint(&[0x40]), Ok(None));
        assert_eq!(parse_varint(&[]), Ok(None));
    }

    #[test]
    fn clean_eof_with_truncated_frame_is_detectable() {
        let mut decoder = FrameDecoder::new();
        decoder.extend(Bytes::from_static(&[0x01, 0x05, b'a', b'b']));
        assert_eq!(decoder.next_frame().unwrap(), None);
        // Driver's clean-FIN check: buffered() != 0 -> H3_FRAME_ERROR.
        assert_eq!(decoder.buffered(), 4);
    }
}
