//! HTTP/2 frame codec (RFC 9113 Section 6).
//!
//! Parses and writes the 9-octet frame header and every frame type:
//! DATA, HEADERS, PRIORITY, RST_STREAM, SETTINGS, PUSH_PROMISE, PING,
//! GOAWAY, WINDOW_UPDATE and CONTINUATION, including PADDED and
//! PRIORITY flags. Validation covers frame-size limits, stream-id rules,
//! settings values and field-block continuation discipline. Unknown
//! frame types are ignored (RFC 9113 Section 4.1).
//!
//! The decoder is incremental: feed it bytes with [`FrameDecoder::extend`]
//! and call [`FrameDecoder::next_frame`]; it returns `Ok(None)` until a
//! complete frame is buffered.
//!
//! This module is the frame layer of the native HTTP/2 implementation
//! (see CUSTOM_HTTP2_IMPL.md); stream and connection semantics
//! (flow control, settings tracking, lifecycle) live in later steps on
//! top of it.

use super::error::{H2Error, Reason};
use bytes::{Bytes, BytesMut};

/// Length of the fixed frame header (RFC 9113 Section 4.1).
pub const FRAME_HEADER_LEN: usize = 9;
/// The initial maximum frame payload size (RFC 9113 Section 4.2).
pub const DEFAULT_MAX_FRAME_SIZE: usize = 16_384;
/// The largest settable frame payload size (2^24-1).
pub const MAX_FRAME_SIZE_LIMIT: usize = 16_777_215;
/// The initial connection flow-control window (RFC 9113 Section 6.9.1).
/// The connection window is always 65535 octets initially; unlike the
/// per-stream window it cannot be raised via SETTINGS, only via
/// WINDOW_UPDATE.
pub const DEFAULT_CONNECTION_WINDOW_SIZE: u32 = 65_535;
/// The initial per-stream flow-control window this server advertises via
/// SETTINGS (RFC 9113 Section 6.5.2). The protocol default is 65535, but
/// advertising a larger window (1MiB) reduces round-trips for large
/// responses. This is *only* for the window we advertise; the window the
/// peer advertises to us defaults to 65535 per RFC until its SETTINGS
/// says otherwise.
pub const DEFAULT_INITIAL_WINDOW_SIZE: u32 = 1_048_576;
/// The largest legal flow-control window (2^31-1).
pub const MAX_WINDOW_SIZE: u32 = 2_147_483_647;
/// The HTTP/2 connection preface (RFC 9113 Section 3.5).
pub const CLIENT_PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";

const DATA_TYPE: u8 = 0x00;
const HEADERS_TYPE: u8 = 0x01;
const PRIORITY_TYPE: u8 = 0x02;
const RST_STREAM_TYPE: u8 = 0x03;
const SETTINGS_TYPE: u8 = 0x04;
const PUSH_PROMISE_TYPE: u8 = 0x05;
const PING_TYPE: u8 = 0x06;
const GOAWAY_TYPE: u8 = 0x07;
const WINDOW_UPDATE_TYPE: u8 = 0x08;
const CONTINUATION_TYPE: u8 = 0x09;

/// Flag bits shared across frame types (RFC 9113 Section 6).
const FLAG_END_STREAM: u8 = 0x01;
const FLAG_ACK: u8 = 0x01;
const FLAG_END_HEADERS: u8 = 0x04;
const FLAG_PADDED: u8 = 0x08;
const FLAG_PRIORITY: u8 = 0x20;

/// Stream priority (RFC 9113 Section 6.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Priority {
    pub exclusive: bool,
    pub dependency: u32,
    pub weight: u8,
}

/// A SETTINGS parameter (RFC 9113 Section 6.5.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Setting {
    pub id: u16,
    pub value: u32,
}

/// A parsed frame. Payloads are zero-copy views over the decoder's
/// buffer (kept alive by `Bytes` refcounting until the frame is
/// dropped); the connection layer reassembles field blocks from the
/// `block` fragments and applies stream semantics. Padding, when
/// present, is validated and stripped.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Frame {
    Data {
        stream_id: u32,
        end_stream: bool,
        data: Bytes,
    },
    Headers {
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        priority: Option<Priority>,
        block: Bytes,
    },
    Priority {
        stream_id: u32,
        priority: Priority,
    },
    Reset {
        stream_id: u32,
        error_code: u32,
    },
    Settings {
        ack: bool,
        settings: Vec<Setting>,
    },
    PushPromise {
        stream_id: u32,
        end_headers: bool,
        promised_stream_id: u32,
        block: Bytes,
    },
    Ping {
        ack: bool,
        payload: [u8; 8],
    },
    GoAway {
        last_stream_id: u32,
        error_code: u32,
        debug: Bytes,
    },
    WindowUpdate {
        stream_id: u32,
        increment: u32,
    },
    Continuation {
        stream_id: u32,
        end_headers: bool,
        block: Bytes,
    },
    /// A frame type this implementation does not understand; ignored by
    /// the connection (RFC 9113 Section 4.1).
    Unknown {
        typ: u8,
        flags: u8,
        stream_id: u32,
        payload: Bytes,
    },
}

/// Incremental frame decoder over a growing buffer.
#[derive(Debug)]
pub struct FrameDecoder {
    buf: BytesMut,
    max_frame_size: usize,
    /// The stream whose field block is open (HEADERS/PUSH_PROMISE
    /// without END_HEADERS was seen); only CONTINUATION frames for that
    /// stream may follow.
    block_stream: Option<u32>,
}

impl FrameDecoder {
    /// Creates a decoder enforcing the given maximum frame payload
    /// size.
    #[inline]
    pub fn new(max_frame_size: usize) -> FrameDecoder {
        FrameDecoder {
            buf: BytesMut::new(),
            max_frame_size,
            block_stream: None,
        }
    }

    /// Appends bytes to the decode buffer.
    #[inline]
    pub fn extend(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The maximum frame payload size the peer may send.
    #[inline]
    pub fn max_frame_size(&self) -> usize {
        self.max_frame_size
    }

    /// Adjusts the frame-size limit after SETTINGS_MAX_FRAME_SIZE.
    #[inline]
    pub fn set_max_frame_size(&mut self, max_frame_size: usize) {
        self.max_frame_size = max_frame_size;
    }

    /// The stream with an open field block, if any.
    #[inline]
    pub fn block_stream(&self) -> Option<u32> {
        self.block_stream
    }

    /// Forgets any open field block. Used when a stream is reset mid-block
    /// (e.g. a CONTINUATION flood) so subsequent frames are not all treated
    /// as protocol violations for the now-gone stream.
    #[inline]
    pub fn clear_block(&mut self) {
        self.block_stream = None;
    }

    /// Parses the next complete frame. Returns `Ok(None)` when more
    /// bytes are needed.
    #[inline]
    pub fn next_frame(&mut self) -> Result<Option<Frame>, H2Error> {
        if self.buf.len() < FRAME_HEADER_LEN {
            return Ok(None);
        }

        // 24-bit big-endian payload length. The zero padding leads the
        // three length octets.
        let payload_len = u32::from_be_bytes([0, self.buf[0], self.buf[1], self.buf[2]]) as usize;
        let typ = self.buf[3];
        let flags = self.buf[4];
        let raw_stream_id =
            u32::from_be_bytes([self.buf[5], self.buf[6], self.buf[7], self.buf[8]]);
        // RFC 9113 Section 4.1: the high bit of the stream identifier
        // field is reserved and MUST be ignored, not treated as an
        // error.
        let stream_id = raw_stream_id & 0x7fff_ffff;

        if payload_len > self.max_frame_size {
            return Err(H2Error::frame_size(
                "frame payload exceeds SETTINGS_MAX_FRAME_SIZE",
            ));
        }

        let total = FRAME_HEADER_LEN + payload_len;
        if self.buf.len() < total {
            return Ok(None);
        }

        let _header = self.buf.split_to(FRAME_HEADER_LEN);
        let payload = self.buf.split_to(payload_len).freeze();
        let frame = parse_frame(typ, flags, stream_id, payload, self)?;
        Ok(Some(frame))
    }
}

/// Parses one complete frame payload (after the 9-octet header).
#[inline]
fn parse_frame(
    typ: u8,
    flags: u8,
    stream_id: u32,
    payload: Bytes,
    decoder: &mut FrameDecoder,
) -> Result<Frame, H2Error> {
    let mut body = &payload[..];

    // Field-block continuation discipline (RFC 9113 Section 6.10).
    if let Some(open_stream) = decoder.block_stream {
        if typ != CONTINUATION_TYPE {
            return Err(H2Error::protocol(
                "frame received while field block was open",
            ));
        }
        if stream_id != open_stream {
            return Err(H2Error::protocol(
                "CONTINUATION frame on a different stream than the open field block",
            ));
        }
    } else if typ == CONTINUATION_TYPE {
        return Err(H2Error::protocol(
            "CONTINUATION frame without a preceding HEADERS or PUSH_PROMISE",
        ));
    }

    let frame = match typ {
        DATA_TYPE => {
            require_stream(stream_id)?;
            let end_stream = flags & FLAG_END_STREAM != 0;
            let pad_len = take_padding(&mut body, flags & FLAG_PADDED != 0)?;
            Frame::Data {
                stream_id,
                end_stream,
                data: payload_slice(&payload, body, pad_len),
            }
        }
        HEADERS_TYPE => {
            require_stream(stream_id)?;
            let end_stream = flags & FLAG_END_STREAM != 0;
            let end_headers = flags & FLAG_END_HEADERS != 0;
            let pad_len = take_padding(&mut body, flags & FLAG_PADDED != 0)?;
            let priority = if flags & FLAG_PRIORITY != 0 {
                Some(read_priority(&mut body, stream_id)?)
            } else {
                None
            };
            if !end_headers {
                decoder.block_stream = Some(stream_id);
            }
            Frame::Headers {
                stream_id,
                end_stream,
                end_headers,
                priority,
                block: payload_slice(&payload, body, pad_len),
            }
        }
        PRIORITY_TYPE => {
            require_stream(stream_id)?;
            if body.len() != 5 {
                return Err(H2Error::frame_size(
                    "PRIORITY frame payload must be exactly 5 octets",
                ));
            }
            let priority = read_priority(&mut body, stream_id)?;
            Frame::Priority {
                stream_id,
                priority,
            }
        }
        RST_STREAM_TYPE => {
            require_stream(stream_id)?;
            if body.len() != 4 {
                return Err(H2Error::frame_size(
                    "RST_STREAM frame payload must be exactly 4 octets",
                ));
            }
            Frame::Reset {
                stream_id,
                error_code: read_u32(body),
            }
        }
        SETTINGS_TYPE => {
            if stream_id != 0 {
                return Err(H2Error::protocol(
                    "SETTINGS frame must use stream identifier 0",
                ));
            }
            let ack = flags & FLAG_ACK != 0;
            if ack && !body.is_empty() {
                return Err(H2Error::frame_size(
                    "SETTINGS frame with ACK flag must have an empty payload",
                ));
            }
            if !body.len().is_multiple_of(6) {
                return Err(H2Error::frame_size(
                    "SETTINGS frame payload must be a multiple of 6 octets",
                ));
            }
            let mut settings = Vec::with_capacity(body.len() / 6);
            while !body.is_empty() {
                let id = u16::from_be_bytes([body[0], body[1]]);
                let value = u32::from_be_bytes([body[2], body[3], body[4], body[5]]);
                validate_setting(id, value)?;
                settings.push(Setting { id, value });
                body = &body[6..];
            }
            // The peer's announced SETTINGS_MAX_FRAME_SIZE governs what it
            // may send; adopt it immediately so later frames in this
            // buffer are checked against it.
            if !ack {
                for setting in &settings {
                    if setting.id == 0x05 {
                        decoder.set_max_frame_size(setting.value as usize);
                    }
                }
            }
            Frame::Settings { ack, settings }
        }
        PUSH_PROMISE_TYPE => {
            require_stream(stream_id)?;
            let end_headers = flags & FLAG_END_HEADERS != 0;
            let pad_len = take_padding(&mut body, flags & FLAG_PADDED != 0)?;
            if body.len() < 4 {
                return Err(H2Error::frame_size(
                    "PUSH_PROMISE frame payload must be at least 4 octets",
                ));
            }
            let promised_stream_id = read_u32(&body[..4]) & 0x7fff_ffff;
            if promised_stream_id == 0 {
                return Err(H2Error::protocol(
                    "PUSH_PROMISE promised stream identifier is 0",
                ));
            }
            if !end_headers {
                decoder.block_stream = Some(stream_id);
            }
            body = &body[4..];
            Frame::PushPromise {
                stream_id,
                end_headers,
                promised_stream_id,
                block: payload_slice(&payload, body, pad_len),
            }
        }
        PING_TYPE => {
            if stream_id != 0 {
                return Err(H2Error::protocol("PING frame must use stream identifier 0"));
            }
            if body.len() != 8 {
                return Err(H2Error::frame_size(
                    "PING frame payload must be exactly 8 octets",
                ));
            }
            Frame::Ping {
                ack: flags & FLAG_ACK != 0,
                payload: body[..8]
                    .try_into()
                    .expect("PING payload is exactly 8 octets (validated above)"),
            }
        }
        GOAWAY_TYPE => {
            if stream_id != 0 {
                return Err(H2Error::protocol(
                    "GOAWAY frame must use stream identifier 0",
                ));
            }
            if body.len() < 8 {
                return Err(H2Error::frame_size(
                    "GOAWAY frame payload must be at least 8 octets",
                ));
            }
            let last_stream_id = read_u32(&body[..4]) & 0x7fff_ffff;
            let error_code = read_u32(&body[4..8]);
            Frame::GoAway {
                last_stream_id,
                error_code,
                debug: payload.slice(8..),
            }
        }
        WINDOW_UPDATE_TYPE => {
            if body.len() != 4 {
                return Err(H2Error::frame_size(
                    "WINDOW_UPDATE frame payload must be exactly 4 octets",
                ));
            }
            let increment = read_u32(body) & 0x7fff_ffff;
            if increment == 0 {
                return Err(H2Error::protocol("WINDOW_UPDATE frame with zero increment"));
            }
            Frame::WindowUpdate {
                stream_id,
                increment,
            }
        }
        CONTINUATION_TYPE => {
            let end_headers = flags & FLAG_END_HEADERS != 0;
            if end_headers {
                decoder.block_stream = None;
            }
            Frame::Continuation {
                stream_id,
                end_headers,
                block: payload,
            }
        }
        _ => Frame::Unknown {
            typ,
            flags,
            stream_id,
            payload,
        },
    };

    Ok(frame)
}

/// A zero-copy view of `payload` covering exactly the range `body`
/// points at: the leading octets were trimmed by padding/priority
/// fields and `pad_len` trailing octets by padding.
#[inline]
fn payload_slice(payload: &Bytes, body: &[u8], pad_len: usize) -> Bytes {
    let start = payload.len() - pad_len - body.len();
    payload.slice(start..start + body.len())
}

/// Reads the pad-length octet when `padded` is set and strips that many
/// trailing octets from `body`, returning the padding length.
///
/// The padding must be strictly shorter than the payload (RFC 9113
/// Section 6.1).
#[inline]
fn take_padding(body: &mut &[u8], padded: bool) -> Result<usize, H2Error> {
    if !padded {
        return Ok(0);
    }
    let pad_len = *body
        .first()
        .ok_or_else(|| H2Error::frame_size("PADDED frame payload too short for pad length"))?
        as usize;
    if pad_len >= body.len() {
        return Err(H2Error::protocol(
            "padding length is the length of the frame payload or greater",
        ));
    }
    *body = &body[1..body.len() - pad_len];
    Ok(pad_len)
}

/// Reads the 5-octet priority fields (Exclusive + Stream Dependency +
/// Weight).
#[inline]
fn read_priority(body: &mut &[u8], stream_id: u32) -> Result<Priority, H2Error> {
    if body.len() < 5 {
        return Err(H2Error::frame_size(
            "frame payload too short for priority fields",
        ));
    }
    let exclusive = body[0] & 0x80 != 0;
    let dependency = u32::from_be_bytes([body[0], body[1], body[2], body[3]]) & 0x7fff_ffff;
    if dependency == stream_id {
        return Err(H2Error::protocol(
            "stream priority depends on its own stream identifier",
        ));
    }
    let weight = body[4];
    *body = &body[5..];
    Ok(Priority {
        exclusive,
        dependency,
        weight,
    })
}

#[inline]
fn require_stream(stream_id: u32) -> Result<(), H2Error> {
    if stream_id == 0 {
        Err(H2Error::new(
            Reason::ProtocolError,
            "frame must use a non-zero stream identifier",
        ))
    } else {
        Ok(())
    }
}

/// Validates the value of a known SETTINGS parameter (RFC 9113
/// Section 6.5.2). Unknown identifiers are accepted and ignored by the
/// caller.
#[inline]
fn validate_setting(id: u16, value: u32) -> Result<(), H2Error> {
    match id {
        0x02 => {
            // SETTINGS_ENABLE_PUSH.
            if value > 1 {
                return Err(H2Error::protocol("SETTINGS_ENABLE_PUSH must be 0 or 1"));
            }
        }
        0x04 => {
            // SETTINGS_INITIAL_WINDOW_SIZE.
            if value > MAX_WINDOW_SIZE {
                return Err(H2Error::new(
                    Reason::FlowControlError,
                    "SETTINGS_INITIAL_WINDOW_SIZE exceeds 2^31-1",
                ));
            }
        }
        0x05 if !(DEFAULT_MAX_FRAME_SIZE..=MAX_FRAME_SIZE_LIMIT).contains(&(value as usize)) => {
            // SETTINGS_MAX_FRAME_SIZE.
            return Err(H2Error::protocol(
                "SETTINGS_MAX_FRAME_SIZE outside 16384..16777215",
            ));
        }
        _ => {}
    }
    Ok(())
}

#[inline]
fn read_u32(bytes: &[u8]) -> u32 {
    u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

/// Writes frames to an output buffer. The field-block writer
/// ([`FrameWriter::write_field_block`]) splits the block across
/// HEADERS/CONTINUATION frames at the peer's frame-size limit.
#[derive(Debug, Clone, Copy, Default)]
pub struct FrameWriter {
    /// The maximum payload size the peer accepts (the peer's
    /// SETTINGS_MAX_FRAME_SIZE; 16384 by default).
    pub max_frame_size: usize,
}

impl FrameWriter {
    pub const fn new(max_frame_size: usize) -> FrameWriter {
        FrameWriter { max_frame_size }
    }

    #[inline]
    fn header(out: &mut Vec<u8>, payload_len: usize, typ: u8, flags: u8, stream_id: u32) {
        out.push(((payload_len >> 16) & 0xff) as u8);
        out.push(((payload_len >> 8) & 0xff) as u8);
        out.push((payload_len & 0xff) as u8);
        out.push(typ);
        out.push(flags);
        out.push(((stream_id >> 24) & 0x7f) as u8);
        out.push(((stream_id >> 16) & 0xff) as u8);
        out.push(((stream_id >> 8) & 0xff) as u8);
        out.push((stream_id & 0xff) as u8);
    }

    #[inline]
    pub fn write_data(&self, out: &mut Vec<u8>, stream_id: u32, end_stream: bool, data: &[u8]) {
        let flags = if end_stream { FLAG_END_STREAM } else { 0 };
        FrameWriter::header(out, data.len(), DATA_TYPE, flags, stream_id);
        out.extend_from_slice(data);
    }

    /// Writes a HEADERS frame (single frame, no field-block splitting).
    #[inline]
    pub fn write_headers(
        &self,
        out: &mut Vec<u8>,
        stream_id: u32,
        end_stream: bool,
        end_headers: bool,
        priority: Option<Priority>,
        block: &[u8],
    ) {
        let mut flags = 0;
        if end_stream {
            flags |= FLAG_END_STREAM;
        }
        if end_headers {
            flags |= FLAG_END_HEADERS;
        }
        let extra = if priority.is_some() { 5 } else { 0 };
        if extra != 0 {
            flags |= FLAG_PRIORITY;
        }
        FrameWriter::header(out, block.len() + extra, HEADERS_TYPE, flags, stream_id);
        if let Some(p) = priority {
            let dep = p.dependency & 0x7fff_ffff | if p.exclusive { 0x8000_0000 } else { 0 };
            out.extend_from_slice(&dep.to_be_bytes());
            out.push(p.weight);
        }
        out.extend_from_slice(block);
    }

    /// Writes a field block as a HEADERS frame (optionally with
    /// END_STREAM) followed by as many CONTINUATION frames as needed to
    /// stay within the peer's frame-size limit.
    #[inline]
    pub fn write_field_block(
        &self,
        out: &mut Vec<u8>,
        stream_id: u32,
        end_stream: bool,
        block: &[u8],
    ) {
        let capacity = self.max_frame_size;
        if block.len() <= capacity {
            self.write_headers(out, stream_id, end_stream, true, None, block);
            return;
        }
        let first = &block[..capacity];
        self.write_headers(out, stream_id, end_stream, false, None, first);
        let mut rest = &block[capacity..];
        while rest.len() > capacity {
            self.write_continuation(out, stream_id, false, &rest[..capacity]);
            rest = &rest[capacity..];
        }
        self.write_continuation(out, stream_id, true, rest);
    }

    #[inline]
    pub fn write_priority(&self, out: &mut Vec<u8>, stream_id: u32, priority: Priority) {
        let dep =
            priority.dependency & 0x7fff_ffff | if priority.exclusive { 0x8000_0000 } else { 0 };
        FrameWriter::header(out, 5, PRIORITY_TYPE, 0, stream_id);
        out.extend_from_slice(&dep.to_be_bytes());
        out.push(priority.weight);
    }

    #[inline]
    pub fn write_reset(&self, out: &mut Vec<u8>, stream_id: u32, error_code: u32) {
        FrameWriter::header(out, 4, RST_STREAM_TYPE, 0, stream_id);
        out.extend_from_slice(&error_code.to_be_bytes());
    }

    #[inline]
    pub fn write_settings(&self, out: &mut Vec<u8>, settings: &[Setting]) {
        FrameWriter::header(out, settings.len() * 6, SETTINGS_TYPE, 0, 0);
        for setting in settings {
            out.extend_from_slice(&setting.id.to_be_bytes());
            out.extend_from_slice(&setting.value.to_be_bytes());
        }
    }

    #[inline]
    pub fn write_settings_ack(&self, out: &mut Vec<u8>) {
        FrameWriter::header(out, 0, SETTINGS_TYPE, FLAG_ACK, 0);
    }

    #[inline]
    pub fn write_push_promise(
        &self,
        out: &mut Vec<u8>,
        stream_id: u32,
        promised_stream_id: u32,
        block: &[u8],
    ) {
        FrameWriter::header(
            out,
            4 + block.len(),
            PUSH_PROMISE_TYPE,
            FLAG_END_HEADERS,
            stream_id,
        );
        out.extend_from_slice(&(promised_stream_id & 0x7fff_ffff).to_be_bytes());
        out.extend_from_slice(block);
    }

    #[inline]
    pub fn write_ping(&self, out: &mut Vec<u8>, payload: &[u8; 8]) {
        FrameWriter::header(out, 8, PING_TYPE, 0, 0);
        out.extend_from_slice(payload);
    }

    #[inline]
    pub fn write_ping_ack(&self, out: &mut Vec<u8>, payload: &[u8; 8]) {
        FrameWriter::header(out, 8, PING_TYPE, FLAG_ACK, 0);
        out.extend_from_slice(payload);
    }

    #[inline]
    pub fn write_goaway(
        &self,
        out: &mut Vec<u8>,
        last_stream_id: u32,
        error_code: u32,
        debug: &[u8],
    ) {
        FrameWriter::header(out, 8 + debug.len(), GOAWAY_TYPE, 0, 0);
        out.extend_from_slice(&(last_stream_id & 0x7fff_ffff).to_be_bytes());
        out.extend_from_slice(&error_code.to_be_bytes());
        out.extend_from_slice(debug);
    }

    #[inline]
    pub fn write_window_update(&self, out: &mut Vec<u8>, stream_id: u32, increment: u32) {
        FrameWriter::header(out, 4, WINDOW_UPDATE_TYPE, 0, stream_id);
        out.extend_from_slice(&(increment & 0x7fff_ffff).to_be_bytes());
    }

    #[inline]
    pub fn write_continuation(
        &self,
        out: &mut Vec<u8>,
        stream_id: u32,
        end_headers: bool,
        block: &[u8],
    ) {
        let flags = if end_headers { FLAG_END_HEADERS } else { 0 };
        FrameWriter::header(out, block.len(), CONTINUATION_TYPE, flags, stream_id);
        out.extend_from_slice(block);
    }
}

#[cfg(test)]
mod tests;
