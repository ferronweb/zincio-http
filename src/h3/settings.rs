//! HTTP/3 connection settings (RFC 9114 Section 7.2.4).
//!
//! Each endpoint advertises its limits in SETTINGS; this module splits those
//! into our [`LocalSettings`] and the peer's [`PeerSettings`]. Frame-level
//! validation belongs to the frame codec.

use crate::h3::frame::{
    Settings as FrameSettings, SETTINGS_ENABLE_CONNECT_PROTOCOL, SETTINGS_MAX_FIELD_SECTION_SIZE,
    SETTINGS_QPACK_BLOCKED_STREAMS, SETTINGS_QPACK_MAX_TABLE_CAPACITY,
};

/// The peer's settings, with RFC defaults for absent values.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PeerSettings {
    qpack_max_table_capacity: u64,
    max_field_section_size: Option<u64>,
    qpack_blocked_streams: u64,
    enable_connect_protocol: bool,
}

impl PeerSettings {
    /// The peer's `SETTINGS_QPACK_MAX_TABLE_CAPACITY`.
    #[inline]
    pub fn qpack_max_table_capacity(&self) -> u64 {
        self.qpack_max_table_capacity
    }

    /// The peer's `SETTINGS_MAX_FIELD_SECTION_SIZE`; `None` means unlimited.
    #[inline]
    pub fn max_field_section_size(&self) -> Option<u64> {
        self.max_field_section_size
    }

    /// The peer's `SETTINGS_QPACK_BLOCKED_STREAMS`.
    #[inline]
    pub fn qpack_blocked_streams(&self) -> u64 {
        self.qpack_blocked_streams
    }

    /// The peer's `SETTINGS_ENABLE_CONNECT_PROTOCOL` (diagnostics/tests).
    #[cfg(test)]
    #[inline]
    pub fn enable_connect_protocol(&self) -> bool {
        self.enable_connect_protocol
    }

    /// Overlays a received SETTINGS frame; unknown identifiers are ignored.
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
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LocalSettings {
    /// `SETTINGS_QPACK_MAX_TABLE_CAPACITY` (at most 2^30 - 1).
    pub qpack_max_table_capacity: u64,
    /// `SETTINGS_QPACK_BLOCKED_STREAMS`.
    pub qpack_blocked_streams: u64,
    /// `SETTINGS_MAX_FIELD_SECTION_SIZE`; `None` means unlimited.
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
    /// The SETTINGS frame this endpoint sends first on its control stream.
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
