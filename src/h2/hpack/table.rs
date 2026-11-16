//! HPACK header tables (RFC 7541 Sections 2.3 and 4).

use bytes::Bytes;
use rustc_hash::FxHashMap;
use std::collections::VecDeque;

/// Perfect-hash lookup of the static table by exact `(name, value)`. Built once
/// at compile time, so `find` never scans the 61-entry table (RFC 7541
/// Appendix A) on the hot path.
static STATIC_EXACT: phf::Map<(&[u8], &[u8]), usize> = phf::phf_map! {
    (b":authority", b"") => 1,
    (b":method", b"GET") => 2,
    (b":method", b"POST") => 3,
    (b":path", b"/") => 4,
    (b":path", b"/index.html") => 5,
    (b":scheme", b"http") => 6,
    (b":scheme", b"https") => 7,
    (b":status", b"200") => 8,
    (b":status", b"204") => 9,
    (b":status", b"206") => 10,
    (b":status", b"304") => 11,
    (b":status", b"400") => 12,
    (b":status", b"404") => 13,
    (b":status", b"500") => 14,
    (b"accept-charset", b"") => 15,
    (b"accept-encoding", b"gzip, deflate") => 16,
    (b"accept-language", b"") => 17,
    (b"accept-ranges", b"") => 18,
    (b"accept", b"") => 19,
    (b"access-control-allow-origin", b"") => 20,
    (b"age", b"") => 21,
    (b"allow", b"") => 22,
    (b"authorization", b"") => 23,
    (b"cache-control", b"") => 24,
    (b"content-disposition", b"") => 25,
    (b"content-encoding", b"") => 26,
    (b"content-language", b"") => 27,
    (b"content-length", b"") => 28,
    (b"content-location", b"") => 29,
    (b"content-range", b"") => 30,
    (b"content-type", b"") => 31,
    (b"cookie", b"") => 32,
    (b"date", b"") => 33,
    (b"etag", b"") => 34,
    (b"expect", b"") => 35,
    (b"expires", b"") => 36,
    (b"from", b"") => 37,
    (b"host", b"") => 38,
    (b"if-match", b"") => 39,
    (b"if-modified-since", b"") => 40,
    (b"if-none-match", b"") => 41,
    (b"if-range", b"") => 42,
    (b"if-unmodified-since", b"") => 43,
    (b"last-modified", b"") => 44,
    (b"link", b"") => 45,
    (b"location", b"") => 46,
    (b"max-forwards", b"") => 47,
    (b"proxy-authenticate", b"") => 48,
    (b"proxy-authorization", b"") => 49,
    (b"range", b"") => 50,
    (b"referer", b"") => 51,
    (b"refresh", b"") => 52,
    (b"retry-after", b"") => 53,
    (b"server", b"") => 54,
    (b"set-cookie", b"") => 55,
    (b"strict-transport-security", b"") => 56,
    (b"transfer-encoding", b"") => 57,
    (b"user-agent", b"") => 58,
    (b"vary", b"") => 59,
    (b"via", b"") => 60,
    (b"www-authenticate", b"") => 61,
};

/// Perfect-hash lookup of the static table by name alone, mapping each name to
/// its lowest-indexed entry (matching the original left-to-right scan).
static STATIC_NAME: phf::Map<&[u8], usize> = phf::phf_map! {
    b":authority" => 1,
    b":method" => 2,
    b":path" => 4,
    b":scheme" => 6,
    b":status" => 8,
    b"accept-charset" => 15,
    b"accept-encoding" => 16,
    b"accept-language" => 17,
    b"accept-ranges" => 18,
    b"accept" => 19,
    b"access-control-allow-origin" => 20,
    b"age" => 21,
    b"allow" => 22,
    b"authorization" => 23,
    b"cache-control" => 24,
    b"content-disposition" => 25,
    b"content-encoding" => 26,
    b"content-language" => 27,
    b"content-length" => 28,
    b"content-location" => 29,
    b"content-range" => 30,
    b"content-type" => 31,
    b"cookie" => 32,
    b"date" => 33,
    b"etag" => 34,
    b"expect" => 35,
    b"expires" => 36,
    b"from" => 37,
    b"host" => 38,
    b"if-match" => 39,
    b"if-modified-since" => 40,
    b"if-none-match" => 41,
    b"if-range" => 42,
    b"if-unmodified-since" => 43,
    b"last-modified" => 44,
    b"link" => 45,
    b"location" => 46,
    b"max-forwards" => 47,
    b"proxy-authenticate" => 48,
    b"proxy-authorization" => 49,
    b"range" => 50,
    b"referer" => 51,
    b"refresh" => 52,
    b"retry-after" => 53,
    b"server" => 54,
    b"set-cookie" => 55,
    b"strict-transport-security" => 56,
    b"transfer-encoding" => 57,
    b"user-agent" => 58,
    b"vary" => 59,
    b"via" => 60,
    b"www-authenticate" => 61,
};

/// Composite `(name, value)` key for the dynamic exact-match map. `Bytes` are
/// refcount-bumped clones of the stored header, so lookups never allocate.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct NameValue(Bytes, Bytes);

/// The static table (RFC 7541 Appendix A): 61 immutable entries.
/// Index 1 is `:authority`, index 61 is `www-authenticate`.
const STATIC_TABLE: [(&[u8], &[u8]); 61] = [
    (b":authority", b""),
    (b":method", b"GET"),
    (b":method", b"POST"),
    (b":path", b"/"),
    (b":path", b"/index.html"),
    (b":scheme", b"http"),
    (b":scheme", b"https"),
    (b":status", b"200"),
    (b":status", b"204"),
    (b":status", b"206"),
    (b":status", b"304"),
    (b":status", b"400"),
    (b":status", b"404"),
    (b":status", b"500"),
    (b"accept-charset", b""),
    (b"accept-encoding", b"gzip, deflate"),
    (b"accept-language", b""),
    (b"accept-ranges", b""),
    (b"accept", b""),
    (b"access-control-allow-origin", b""),
    (b"age", b""),
    (b"allow", b""),
    (b"authorization", b""),
    (b"cache-control", b""),
    (b"content-disposition", b""),
    (b"content-encoding", b""),
    (b"content-language", b""),
    (b"content-length", b""),
    (b"content-location", b""),
    (b"content-range", b""),
    (b"content-type", b""),
    (b"cookie", b""),
    (b"date", b""),
    (b"etag", b""),
    (b"expect", b""),
    (b"expires", b""),
    (b"from", b""),
    (b"host", b""),
    (b"if-match", b""),
    (b"if-modified-since", b""),
    (b"if-none-match", b""),
    (b"if-range", b""),
    (b"if-unmodified-since", b""),
    (b"last-modified", b""),
    (b"link", b""),
    (b"location", b""),
    (b"max-forwards", b""),
    (b"proxy-authenticate", b""),
    (b"proxy-authorization", b""),
    (b"range", b""),
    (b"referer", b""),
    (b"refresh", b""),
    (b"retry-after", b""),
    (b"server", b""),
    (b"set-cookie", b""),
    (b"strict-transport-security", b""),
    (b"transfer-encoding", b""),
    (b"user-agent", b""),
    (b"vary", b""),
    (b"via", b""),
    (b"www-authenticate", b""),
];

/// Number of entries in the static table.
pub(crate) const STATIC_LEN: usize = 61;

/// Table size below which lookups use a linear scan.
const HYBRID_THRESHOLD: usize = 32;

/// The entry-size overhead (RFC 7541 Section 4.1).
const ENTRY_OVERHEAD: usize = 32;

/// A header field name/value pair stored in or fetched from a table.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    name: Bytes,
    value: Bytes,
    size: usize,
}

impl Header {
    /// Creates a header field from raw name/value bytes. Names are used
    /// without case normalization, which allows HTTP/2 pseudo
    /// headers (`:method`, `:status`, ...).
    #[inline]
    pub fn new(name: impl Into<Bytes>, value: impl Into<Bytes>) -> Self {
        let name = name.into();
        let value = value.into();
        let size = ENTRY_OVERHEAD + name.len() + value.len();
        Header { name, value, size }
    }

    /// Size in octets as defined in RFC 7541 Section 4.1: the sum of the
    /// name and value lengths (without Huffman encoding) plus 32.
    #[inline]
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    #[inline]
    pub fn name(&self) -> &[u8] {
        &self.name
    }

    #[inline]
    pub fn value(&self) -> &[u8] {
        &self.value
    }

    /// Owned `Bytes` view of the name (a refcount bump, no copy).
    #[inline]
    pub(crate) fn name_bytes(&self) -> &Bytes {
        &self.name
    }

    /// Owned `Bytes` view of the value (a refcount bump, no copy).
    #[inline]
    pub(crate) fn value_bytes(&self) -> &Bytes {
        &self.value
    }
}

/// The HPACK header table: the immutable static table followed by a
/// dynamically sized FIFO (RFC 7541 Section 4).
#[derive(Debug)]
pub(crate) struct Table {
    /// Dynamic entries, newest at the front. The entry at index 62 in the
    /// combined addressing scheme is `entries[0]`.
    entries: VecDeque<Header>,
    /// Current combined size of the dynamic entries.
    size: usize,
    /// Maximum combined size the dynamic table may grow to.
    max_size: usize,
    /// Exact `(name, value)` -> combined index for the dynamic entries. Always
    /// holds the newest index of each pair (RFC 7541, newest first).
    exact: FxHashMap<NameValue, usize>,
    /// Name -> combined index for the dynamic entries, holding the newest
    /// index of each name.
    name: FxHashMap<Bytes, usize>,
    /// When false (decoder side), the lookup maps are never built or
    /// consulted: the decoder resolves by index and never calls `find`, so
    /// maintaining them would be pure overhead.
    maintain_maps: bool,
}

impl Table {
    #[inline]
    pub(crate) fn new() -> Self {
        Table::with_max_size(DEFAULT_MAX_SIZE)
    }

    /// The default dynamic-table size when no SETTINGS_HEADER_TABLE_SIZE
    /// has been exchanged (RFC 7541 Section 4.2).
    #[inline]
    pub(crate) fn with_max_size(max_size: usize) -> Self {
        Table {
            entries: VecDeque::new(),
            size: 0,
            max_size,
            exact: FxHashMap::default(),
            name: FxHashMap::default(),
            maintain_maps: true,
        }
    }

    /// Like [`Table::with_max_size`] but without lookup-map maintenance,
    /// for the decoder which resolves entries by index and never queries
    /// the maps.
    #[inline]
    pub(crate) fn with_max_size_no_maps(max_size: usize) -> Self {
        Table {
            entries: VecDeque::new(),
            size: 0,
            max_size,
            exact: FxHashMap::default(),
            name: FxHashMap::default(),
            maintain_maps: false,
        }
    }

    /// Returns the entry at 1-based `index`: 1..=61 addresses the static
    /// table, 62.. the dynamic table (newest first).
    #[inline]
    pub(crate) fn get(&self, index: usize) -> Option<Header> {
        if index == 0 {
            return None;
        }
        if index <= STATIC_LEN {
            let (name, value) = STATIC_TABLE[index - 1];
            // `from_static` is zero-copy.
            return Some(Header::new(
                Bytes::from_static(name),
                Bytes::from_static(value),
            ));
        }
        self.entries.get(index - STATIC_LEN - 1).cloned()
    }

    /// Number of dynamic entries.
    #[cfg(test)]
    #[inline]
    pub(crate) fn dynamic_len(&self) -> usize {
        self.entries.len()
    }

    /// 1-based index of the exact `(name, value)` entry if present:
    /// the static table is searched first, then the dynamic table
    /// (newest first).
    #[inline]
    pub(crate) fn find(&self, name: &Bytes, value: &Bytes) -> Option<usize> {
        if self.maintain_maps && self.entries.len() > HYBRID_THRESHOLD {
            if let Some(&index) = STATIC_EXACT.get(&(name.as_ref(), value.as_ref())) {
                return Some(index);
            }
            return self
                .exact
                .get(&NameValue(name.clone(), value.clone()))
                .copied();
        }
        // Linear fallback: static table first (lowest index), then dynamic
        // (newest first). Matches the original scan for tiny tables.
        let name_ref = name.as_ref();
        let value_ref = value.as_ref();
        for (i, entry) in STATIC_TABLE.iter().enumerate() {
            if entry.0 == name_ref && entry.1 == value_ref {
                return Some(i + 1);
            }
        }
        for (i, header) in self.entries.iter().enumerate() {
            if header.name() == name_ref && header.value() == value_ref {
                return Some(STATIC_LEN + 1 + i);
            }
        }
        None
    }

    /// 1-based index of an entry with the given `name` if present: the
    /// static table is searched first, then the dynamic table (newest
    /// first).
    #[inline]
    pub(crate) fn find_name(&self, name: &Bytes) -> Option<usize> {
        if self.maintain_maps && self.entries.len() > HYBRID_THRESHOLD {
            if let Some(&index) = STATIC_NAME.get(name.as_ref()) {
                return Some(index);
            }
            return self.name.get(name.as_ref()).copied();
        }
        let name_ref = name.as_ref();
        for (i, entry) in STATIC_TABLE.iter().enumerate() {
            if entry.0 == name_ref {
                return Some(i + 1);
            }
        }
        for (i, header) in self.entries.iter().enumerate() {
            if header.name() == name_ref {
                return Some(STATIC_LEN + 1 + i);
            }
        }
        None
    }

    /// Number of static and dynamic entries combined.
    #[cfg(test)]
    #[inline]
    pub(crate) fn len(&self) -> usize {
        STATIC_LEN + self.entries.len()
    }

    /// Current combined size of the dynamic entries.
    #[cfg(test)]
    #[inline]
    pub(crate) fn size(&self) -> usize {
        self.size
    }

    #[cfg(test)]
    #[inline]
    pub(crate) fn max_size(&self) -> usize {
        self.max_size
    }

    /// Changes the maximum table size, evicting entries from the end of
    /// the dynamic table until its size is within the new limit
    /// (RFC 7541 Section 4.3).
    #[inline]
    pub(crate) fn set_max_size(&mut self, max_size: usize) {
        self.max_size = max_size;
        while self.size > self.max_size {
            match self.entries.pop_back() {
                Some(entry) => {
                    self.size -= entry.size();
                    let combined = STATIC_LEN + self.entries.len() + 1;
                    self.evict_entry(&entry, combined);
                }
                None => break,
            }
        }
    }

    /// Drops `entry` from the lookup maps if it is still the stored newest
    /// match for its key.
    #[inline]
    fn evict_entry(&mut self, entry: &Header, combined: usize) {
        if !self.maintain_maps {
            return;
        }
        if self.name.get(entry.name()).copied() == Some(combined) {
            self.name.remove(entry.name());
        }
        let key = NameValue(entry.name_bytes().clone(), entry.value_bytes().clone());
        if self.exact.get(&key).copied() == Some(combined) {
            self.exact.remove(&key);
        }
    }

    /// Adds an entry to the front of the dynamic table, evicting entries
    /// from the end as needed (RFC 7541 Section 4.4). An entry larger
    /// than the maximum size empties the table and is not added.
    #[inline]
    pub(crate) fn add(&mut self, header: Header) {
        if header.size() > self.max_size {
            self.entries.clear();
            self.size = 0;
            if self.maintain_maps {
                self.exact.clear();
                self.name.clear();
            }
            return;
        }
        while self.size + header.size() > self.max_size {
            match self.entries.pop_back() {
                Some(entry) => {
                    self.size -= entry.size();
                    let combined = STATIC_LEN + self.entries.len() + 1;
                    self.evict_entry(&entry, combined);
                }
                None => break,
            }
        }
        if self.maintain_maps {
            // A front insertion shifts every existing dynamic entry's combined
            // index up by one; bump the stored indices to match.
            for v in self.exact.values_mut() {
                *v += 1;
            }
            for v in self.name.values_mut() {
                *v += 1;
            }
        }

        let combined = STATIC_LEN + 1;
        self.size += header.size();
        if self.maintain_maps {
            let name = header.name_bytes().clone();
            let value = header.value_bytes().clone();
            self.entries.push_front(header);
            self.exact.insert(NameValue(name.clone(), value), combined);
            self.name.insert(name, combined);
        } else {
            self.entries.push_front(header);
        }
    }
}

impl Default for Table {
    #[inline]
    fn default() -> Self {
        Self::new()
    }
}

/// RFC 7541 Section 4.2: the initial maximum dynamic table size is 4096
/// octets.
const DEFAULT_MAX_SIZE: usize = 4096;

#[cfg(test)]
mod tests {
    use super::*;

    fn header(name: &str, value: &str) -> Header {
        Header::new(
            Bytes::copy_from_slice(name.as_bytes()),
            Bytes::copy_from_slice(value.as_bytes()),
        )
    }

    /// The hash-map backed `find`/`find_name` must stay correct across the
    /// front-insert index shift and back-eviction, including for duplicate
    /// names and values.
    #[test]
    fn find_tracks_eviction_and_duplicates() {
        let mut table = Table::with_max_size(200);
        table.add(header("a", "1")); // combined 62
        table.add(header("b", "2")); // combined 63
        table.add(header("a", "3")); // combined 62 (newest), `a`/`1` shifts to 64

        assert_eq!(table.find_name(header("a", "").name_bytes()), Some(62));
        assert_eq!(
            table.find(
                header("a", "3").name_bytes(),
                header("a", "3").value_bytes()
            ),
            Some(62)
        );
        assert_eq!(
            table.find(
                header("a", "1").name_bytes(),
                header("a", "1").value_bytes()
            ),
            Some(64)
        );

        // Evict the oldest entry (`a`/`1` at combined 64) by shrinking; the
        // newer `a`/`3` must remain the stored name match.
        table.set_max_size(70); // three 34-octet entries = 102 > 70 -> one evicted
        assert_eq!(
            table.find(
                header("a", "1").name_bytes(),
                header("a", "1").value_bytes()
            ),
            None
        );
        assert_eq!(table.find_name(header("a", "").name_bytes()), Some(62));
        assert_eq!(
            table.find(
                header("a", "3").name_bytes(),
                header("a", "3").value_bytes()
            ),
            Some(62)
        );
        assert_eq!(table.find_name(header("b", "").name_bytes()), Some(63));
    }

    #[test]
    fn static_table_contents() {
        assert_eq!(
            Table::new().get(1),
            Some(Header::new(
                Bytes::from_static(b":authority"),
                Bytes::from_static(b"")
            ))
        );
        assert_eq!(
            Table::new().get(2),
            Some(Header::new(
                Bytes::from_static(b":method"),
                Bytes::from_static(b"GET")
            ))
        );
        assert_eq!(
            Table::new().get(16),
            Some(Header::new(
                Bytes::from_static(b"accept-encoding"),
                Bytes::from_static(b"gzip, deflate")
            ))
        );
        assert_eq!(
            Table::new().get(61),
            Some(Header::new(
                Bytes::from_static(b"www-authenticate"),
                Bytes::from_static(b"")
            ))
        );
        assert_eq!(Table::new().get(0), None);
    }

    #[test]
    fn entry_size_math() {
        // 32 overhead + 4 name + 3 value.
        assert_eq!(header("test", "abc").size(), 39);
        assert_eq!(header("", "").size(), 32);
    }

    #[test]
    fn add_and_fetch_order() {
        let mut table = Table::with_max_size(200);
        table.add(header("a", "1"));
        table.add(header("b", "2"));
        table.add(header("c", "3"));

        // Newest entry is at index 62.
        assert_eq!(table.get(62), Some(header("c", "3")));
        assert_eq!(table.get(63), Some(header("b", "2")));
        assert_eq!(table.get(64), Some(header("a", "1")));
        assert_eq!(table.get(65), None);
        assert_eq!(table.dynamic_len(), 3);
        assert_eq!(table.len(), STATIC_LEN + 3);
        assert_eq!(table.size(), 34 * 3);
    }

    #[test]
    fn eviction_from_end() {
        // Each entry is 34 octets; only two fit in 70.
        let mut table = Table::with_max_size(70);
        table.add(header("a", "1"));
        table.add(header("b", "2"));
        table.add(header("c", "3"));

        assert_eq!(table.dynamic_len(), 2);
        assert_eq!(table.get(62), Some(header("c", "3")));
        assert_eq!(table.get(63), Some(header("b", "2")));
        assert_eq!(table.get(64), None);
        assert_eq!(table.size(), 68);
    }

    #[test]
    fn entry_larger_than_max_empties_table() {
        let mut table = Table::with_max_size(100);
        table.add(header("x", "1"));
        table.add(header("y", "2"));
        assert_eq!(table.dynamic_len(), 2);

        // 101 octets > 100 max.
        let big = header(&"v".repeat(60), &"v".repeat(9));
        assert_eq!(big.size(), 101);
        table.add(big);

        assert_eq!(table.dynamic_len(), 0);
        assert_eq!(table.size(), 0);
    }

    #[test]
    fn entry_exactly_max_size_is_added() {
        let mut table = Table::with_max_size(101);
        let big = header(&"v".repeat(60), &"v".repeat(9));
        assert_eq!(big.size(), 101);
        table.add(big);
        assert_eq!(table.dynamic_len(), 1);
    }

    #[test]
    fn size_update_evicts() {
        let mut table = Table::with_max_size(200);
        table.add(header("a", "1"));
        table.add(header("b", "2"));
        table.add(header("c", "3"));

        table.set_max_size(70);
        assert_eq!(table.dynamic_len(), 2);
        assert_eq!(table.get(62), Some(header("c", "3")));
        assert_eq!(table.size(), 68);

        table.set_max_size(0);
        assert_eq!(table.dynamic_len(), 0);
        assert_eq!(table.size(), 0);

        // Growing back to the original size keeps the table empty; new
        // entries populate it again.
        table.set_max_size(200);
        assert_eq!(table.dynamic_len(), 0);
        table.add(header("d", "4"));
        assert_eq!(table.get(62), Some(header("d", "4")));
    }

    #[test]
    fn max_size_tracks_requests() {
        let mut table = Table::with_max_size(128);
        assert_eq!(table.max_size(), 128);
        table.set_max_size(256);
        assert_eq!(table.max_size(), 256);
    }

    #[test]
    fn default_max_size() {
        assert_eq!(Table::new().max_size(), DEFAULT_MAX_SIZE);
        assert_eq!(Table::default().max_size(), DEFAULT_MAX_SIZE);
    }

    #[test]
    fn grows_and_reuses_slots() {
        // The FIFO must keep working after many evictions (the ring
        // reuses its backing slots).
        let mut table = Table::with_max_size(200);
        for i in 0..100 {
            let entry = header(&format!("k{i}"), "v");
            table.add(entry.clone());
            assert!(table.size() <= table.max_size(), "iteration {i}");
            assert_eq!(table.get(62), Some(entry), "iteration {i}");
        }
        assert_eq!(table.get(62), Some(header("k99", "v")));
        assert_eq!(
            table.size(),
            table.dynamic_len() * table.get(62).unwrap().size()
        );
    }
}
