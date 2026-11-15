//! HTTP/3 connection settings (RFC 9114 Section 7.2.4).
//!
//! Each endpoint advertises its own limits in the SETTINGS frame that
//! opens its control stream; the driver interprets the peer's values from
//! here. The values that shape our own codecs — the QPACK decoder's
//! capacity and blocked-stream budget ([`LocalSettings`]) and the QPACK
//! encoder's bound on the peer's dynamic table ([`PeerSettings`]) — are
//! the two settings each side understands.
//!
//! Validation of the SETTINGS *frame* (reserved identifiers, duplicates)
//! is the frame codec's job; this module only extracts values and tracks
//! which identifiers the peer sent.
#![allow(dead_code)]

use crate::h3::frame::{
    Settings as FrameSettings, SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_MAX_FIELD_SECTION_SIZE,
    SETTINGS_QPACK_BLOCKED_STREAMS, SETTINGS_QPACK_MAX_TABLE_CAPACITY,
};

/// The peer's settings as negotiated by its SETTINGS frame, with the
/// RFC-default values for everything it did not send.
///
/// The default for `max_field_section_size` is unlimited (RFC 9114
/// Section 7.2.4.1); the QPACK settings default to 0 (RFC 9204 Section 5).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerSettings {
    qpack_max_table_capacity: u64,
    max_field_section_size: Option<u64>,
    qpack_blocked_streams: u64,
    enable_connect_protocol: bool,
}

impl PeerSettings {
    /// The peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`: the dynamic table
    /// capacity our encoder may use on its encoder stream (RFC 9204
    /// Section 5).
    #[inline]
    pub fn qpack_max_table_capacity(&self) -> u64 {
        self.qpack_max_table_capacity
    }

    /// The peer's `SETTINGS_MAX_FIELD_SECTION_SIZE`: the largest field
    /// section it will accept, or `None` when unlimited.
    #[inline]
    pub fn max_field_section_size(&self) -> Option<u64> {
        self.max_field_section_size
    }

    /// The peer's `SETTINGS_QPACK_BLOCKED_STREAMS`: how many of its field
    /// sections may block waiting for dynamic table entries.
    #[inline]
    pub fn qpack_blocked_streams(&self) -> u64 {
        self.qpack_blocked_streams
    }

    /// The peer's `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
    #[inline]
    pub fn enable_connect_protocol(&self) -> bool {
        self.enable_connect_protocol
    }

    /// Overlays the values of a received SETTINGS frame onto these
    /// settings. Unknown identifiers are ignored (their grease handling is
    /// the frame codec's); known ones replace the previous values.
    #[inline]
    pub fn apply(&mut self, settings: &FrameSettings) {
        for (id, value) in settings.iter() {
            match id {
                SETTINGS_QPACK_MAX_TABLE_CAPACITY => self.qpack_max_table_capacity = value,
                SETTINGS_MAX_FIELD_SECTION_SIZE => self.max_field_section_size = Some(value),
                SETTINGS_QPACK_BLOCKED_STREAMS => self.qpack_blocked_streams = value,
                SETTINGS_ENABLE_CONNECT_PROTOCOL => self.enable_connect_protocol = value != 0,
                _ => {}
            }
        }
    }
}

/// The settings this endpoint advertises in its SETTINGS frame.
///
/// The values bound this endpoint's own codecs: the decoder's table
/// capacity and blocked-stream budget come from `qpack_max_table_capacity`
/// and `qpack_blocked_streams`; the peer's encoder is limited by them in
/// turn. `max_field_section_size` bounds how large a field section this
/// endpoint will accept.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSettings {
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY`; must not exceed 2^30 - 1
    /// (RFC 9204 Section 5).
    pub qpack_max_table_capacity: u64,
    /// `SETTINGS_QPACK_BLOCKED_STREAMS`.
    pub qpack_blocked_streams: u64,
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`; `None` means unlimited (the
    /// RFC default).
    pub max_field_section_size: Option<u64>,
    /// `SETTINGS_ENABLE_CONNECT_PROTOCOL`.
    pub enable_connect_protocol: bool,
}

impl Default for LocalSettings {
    #[inline]
    fn default() -> Self {
        LocalSettings {
            qpack_max_table_capacity: 0,
            qpack_blocked_streams: 0,
            max_field_section_size: Some(65_536),
            enable_connect_protocol: false,
        }
    }
}

impl LocalSettings {
    /// The SETTINGS frame payload this endpoint sends as the first frame
    /// of its control stream.
    ///
    /// Includes a reserved (grease) identifier, as RFC 9114 Section
    /// 7.2.4.1 recommends; receivers must ignore it.
    #[inline]
    pub fn to_frame(&self) -> FrameSettings {
        let mut frame = FrameSettings::new();
        frame.insert(
            SETTINGS_QPACK_MAX_TABLE_CAPACITY,
            self.qpack_max_table_capacity,
        );
        frame.insert(SETTINGS_QPACK_BLOCKED_STREAMS, self.qpack_blocked_streams);
        if let Some(size) = self.max_field_section_size {
            frame.insert(SETTINGS_MAX_FIELD_SECTION_SIZE, size);
        }
        if self.enable_connect_protocol {
            frame.insert(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1);
        }
        frame.insert(0x21, 0); // reserved identifier (0x1f * 0 + 0x21)
        frame
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_overlays_received_values() {
        let mut peer = PeerSettings::default();
        let mut frame = FrameSettings::new();
        frame.insert(SETTINGS_QPACK_MAX_TABLE_CAPACITY, 4096);
        frame.insert(SETTINGS_MAX_FIELD_SECTION_SIZE, 16384);
        frame.insert(SETTINGS_QPACK_BLOCKED_STREAMS, 16);
        frame.insert(SETTINGS_ENABLE_CONNECT_PROTOCOL, 1);
        peer.apply(&frame);

        assert_eq!(peer.qpack_max_table_capacity(), 4096);
        assert_eq!(peer.max_field_section_size(), Some(16384));
        assert_eq!(peer.qpack_blocked_streams(), 16);
        assert!(peer.enable_connect_protocol());

        // Partial frames only overlay what they carry.
        let mut partial = FrameSettings::new();
        partial.insert(SETTINGS_MAX_FIELD_SECTION_SIZE, 0);
        peer.apply(&partial);
        assert_eq!(peer.qpack_max_table_capacity(), 4096);
        assert_eq!(peer.max_field_section_size(), Some(0));
        assert_eq!(peer.qpack_blocked_streams(), 16);
    }

    #[test]
    fn local_settings_round_trip_through_frame() {
        let local = LocalSettings {
            qpack_max_table_capacity: 4096,
            qpack_blocked_streams: 16,
            max_field_section_size: Some(100),
            enable_connect_protocol: true,
        };
        let mut peer = PeerSettings::default();
        peer.apply(&local.to_frame());

        assert_eq!(peer.qpack_max_table_capacity(), 4096);
        assert_eq!(peer.qpack_blocked_streams(), 16);
        assert_eq!(peer.max_field_section_size(), Some(100));
        assert!(peer.enable_connect_protocol());
    }

    #[test]
    fn local_settings_frame_always_carries_grease() {
        let frame = LocalSettings::default().to_frame();
        // The reserved identifier must be present; its value is ignored.
        assert_eq!(frame.get(0x21), Some(0));
        // Defaults need not be re-announced, but sending them is legal.
        assert_eq!(frame.get(SETTINGS_QPACK_MAX_TABLE_CAPACITY), Some(0));
    }
}
