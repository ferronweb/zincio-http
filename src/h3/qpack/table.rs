//! QPACK dynamic table (RFC 9204 Section 3.2).
//!
//! The dynamic table is a FIFO list of field lines shared between the
//! encoder and the decoder. Entries are added at the insertion point and
//! evicted from the dropping point (oldest first) to keep the table size
//! within its capacity. The size of an entry is the sum of its name length,
//! its value length, and 32 additional bytes (Section 3.2.1).
//!
//! Absolute indices are fixed for the lifetime of an entry; relative and
//! post-base indices are computed from the context (most-recent insertion
//! for encoder-stream instructions, the field section's Base for field line
//! representations). The table itself is context-free: callers translate
//! indices via the lookup helpers.
//!
//! The dynamic table can contain duplicate entries, and entries can have
//! empty values; neither is an error (Section 3.2).
//!
//! Consumption: the encoder adds entries (Section 4.3) and the decoder
//! materializes them from encoder-stream instructions; both use the same
//! structure.

use std::collections::VecDeque;

use bytes::Bytes;
use rustc_hash::FxHashMap;

/// Composite `(name, value)` key for the dynamic exact-match map. `Bytes` are
/// refcount-bumped clones of the stored entry, so lookups never allocate.
#[derive(Clone, Debug, Hash, PartialEq, Eq)]
struct NameValue(Bytes, Bytes);

/// Error returned when an entry cannot be inserted.
///
/// The caller maps this to `QPACK_ENCODER_STREAM_ERROR` on the decoder
/// side; a well-behaved encoder never triggers it (it only inserts entries
/// that fit).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum InsertError {
    /// The entry (name + value + 32) is larger than the table capacity.
    EntryTooLarge,
}

/// FIFO dynamic table. `entries[0]` is the most recently inserted entry.
///
/// Invariants:
/// - `size <= capacity` at all times;
/// - the absolute index of `entries[i]` is `inserted - 1 - i`;
/// - `inserted` counts entries inserted over the table's whole lifetime
///   (absolute indices are never reused).
pub(crate) struct DynamicTable {
    entries: VecDeque<(Bytes, Bytes)>,
    capacity: u64,
    size: u64,
    inserted: u64,
    /// Exact `(name, value)` -> absolute index for the dynamic entries, always
    /// holding the newest absolute index of each pair.
    exact: FxHashMap<NameValue, u64>,
    /// Name -> absolute index for the dynamic entries, holding the newest
    /// absolute index of each name.
    name: FxHashMap<Bytes, u64>,
    /// When false (decoder side), the lookup maps are never built or
    /// consulted: the decoder resolves entries by absolute index and never
    /// calls `find_*`, so maintaining them would be pure overhead.
    maintain_maps: bool,
}

/// Below this many dynamic entries, `find_full_or_name`/`find_name` use a
/// linear scan (cheap early exits); at or above it they use the hash maps.
/// Tiny tables favour the scan; large tables favour the hash map.
pub(crate) const HYBRID_THRESHOLD: usize = 64;

impl std::fmt::Debug for DynamicTable {
    #[inline]
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DynamicTable")
            .field("entries", &self.entries.len())
            .field("capacity", &self.capacity)
            .field("size", &self.size)
            .field("inserted", &self.inserted)
            .finish()
    }
}

impl DynamicTable {
    /// Creates an empty table with the given initial `capacity`.
    #[inline]
    pub(crate) fn new(capacity: u64) -> Self {
        Self::with_maps(capacity, true)
    }

    /// Creates an empty table without lookup-map maintenance, for the decoder
    /// which resolves entries by absolute index and never queries the maps.
    #[inline]
    pub(crate) fn without_maps(capacity: u64) -> Self {
        Self::with_maps(capacity, false)
    }

    #[inline]
    fn with_maps(capacity: u64, maintain_maps: bool) -> Self {
        Self {
            entries: VecDeque::new(),
            capacity,
            size: 0,
            inserted: 0,
            exact: FxHashMap::default(),
            name: FxHashMap::default(),
            maintain_maps,
        }
    }

    /// The current dynamic table capacity.
    #[inline]
    pub(crate) fn capacity(&self) -> u64 {
        self.capacity
    }

    /// The current sum of entry sizes.
    #[cfg(test)]
    #[inline]
    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    /// Number of entries currently in the table.
    #[inline]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    /// Absolute index of the most recently inserted entry, or `0` when the
    /// table is empty.
    #[inline]
    pub(crate) fn last_absolute(&self) -> u64 {
        self.inserted.saturating_sub(1)
    }

    /// The number of entries inserted over the table's lifetime.
    #[inline]
    pub(crate) fn inserted(&self) -> u64 {
        self.inserted
    }

    /// The absolute index a newly inserted entry will receive.
    #[inline]
    pub(crate) fn next_absolute(&self) -> u64 {
        self.inserted
    }

    /// The size contribution of an entry: name + value + 32 (RFC 9204
    /// Section 3.2.1).
    #[inline]
    pub(crate) fn entry_size(name: &[u8], value: &[u8]) -> u64 {
        name.len() as u64 + value.len() as u64 + 32
    }

    /// Changes the table capacity, evicting entries from the dropping point
    /// (oldest first) until the table fits.
    ///
    /// Setting the capacity to 0 clears the table; a later increase restores
    /// normal operation with an empty table (RFC 9204 Section 3.2.2).
    #[inline]
    pub(crate) fn set_capacity(&mut self, capacity: u64) {
        self.capacity = capacity;
        self.evict_to_fit(capacity);
    }

    /// Number of entries that inserting an entry of the given `size` would
    /// evict from the dropping point (oldest first), or 0 if it fits.
    ///
    /// The encoder uses this to decide whether an insert would invalidate
    /// references to older entries made earlier in the same field section:
    /// eviction only removes the oldest entries, so an insert is safe while
    /// every evicted absolute index is below the smallest referenced index.
    #[inline]
    pub(crate) fn would_evict(&self, size: u64) -> u64 {
        let need_freed = size.saturating_sub(self.capacity - self.size);
        if need_freed == 0 {
            return 0;
        }
        let mut freed = 0u64;
        let mut evicted = 0u64;
        for (name, value) in self.entries.iter().rev() {
            freed += Self::entry_size(name, value);
            evicted += 1;
            if freed >= need_freed {
                break;
            }
        }
        evicted
    }

    /// Number of entries that would be evicted from the dropping point if
    /// the capacity were reduced to `target` (0 when nothing would be
    /// evicted).
    ///
    /// The decoder uses this to reject a capacity reduction that would
    /// evict entries with an absolute index at or above its Known Received
    /// Count (RFC 9204 Section 2.1.1).
    #[inline]
    pub(crate) fn evict_for_capacity(&self, target: u64) -> u64 {
        let mut size = 0u64;
        let mut survivors = 0u64;
        for (name, value) in self.entries.iter() {
            let entry_size = Self::entry_size(name, value);
            if size + entry_size > target {
                break;
            }
            size += entry_size;
            survivors += 1;
        }
        self.len() as u64 - survivors
    }

    /// Finds the most recent exact match and the most recent name match.
    /// The encoder uses both results when choosing a field-line
    /// representation, so this avoids scanning a busy dynamic table twice.
    #[inline]
    pub(crate) fn find_full_or_name(
        &self,
        name: &Bytes,
        value: &Bytes,
    ) -> (Option<u64>, Option<u64>) {
        if self.maintain_maps && self.entries.len() > HYBRID_THRESHOLD {
            let exact = self
                .exact
                .get(&NameValue(name.clone(), value.clone()))
                .copied();
            let name_match = self.name.get(name.as_ref()).copied();
            return (exact, name_match);
        }
        // Linear fallback: entries are newest-first, so the first match wins
        // (highest absolute index), matching the hash-map stored value.
        let name_ref = name.as_ref();
        let value_ref = value.as_ref();
        let mut name_match = None;
        for (i, (entry_name, entry_value)) in self.entries.iter().enumerate() {
            if entry_name.as_ref() != name_ref {
                continue;
            }
            let abs = self.inserted - 1 - i as u64;
            name_match.get_or_insert(abs);
            if entry_value.as_ref() == value_ref {
                return (Some(abs), name_match);
            }
        }
        (None, name_match)
    }

    /// Finds the most recently inserted entry whose name matches `name`.
    ///
    /// Returns the entry's absolute index.
    #[inline]
    pub(crate) fn find_name(&self, name: &[u8]) -> Option<u64> {
        if self.maintain_maps && self.entries.len() > HYBRID_THRESHOLD {
            return self.name.get(name).copied();
        }
        for (i, (n, _)) in self.entries.iter().enumerate() {
            if n.as_ref() == name {
                return Some(self.inserted - 1 - i as u64);
            }
        }
        None
    }

    /// Inserts a new entry at the insertion point, evicting oldest entries
    /// as needed.
    ///
    /// Returns [`InsertError::EntryTooLarge`] if the entry does not fit in
    /// the table capacity at all; on success the entry receives absolute
    /// index `inserted()`.
    #[inline]
    pub(crate) fn insert(&mut self, name: Bytes, value: Bytes) -> Result<(), InsertError> {
        let entry_size = Self::entry_size(&name, &value);
        if entry_size > self.capacity {
            return Err(InsertError::EntryTooLarge);
        }
        self.evict_to_fit(self.capacity - entry_size);
        let abs = self.next_absolute();
        self.entries.push_front((name.clone(), value.clone()));
        self.size += entry_size;
        self.inserted += 1;
        if self.maintain_maps {
            self.exact
                .insert(NameValue(name.clone(), value.clone()), abs);
            self.name.insert(name, abs);
        }
        Ok(())
    }

    /// Returns the (name, value) pair at deque position `i` (0 = most
    /// recently inserted).
    #[inline]
    pub(crate) fn entry_at(&self, i: u64) -> Option<(&[u8], &[u8])> {
        let i = usize::try_from(i).ok()?;
        let (name, value) = self.entries.get(i)?;
        Some((name.as_ref(), value.as_ref()))
    }

    /// Clones the reference-counted bytes at a deque position. This is used
    /// by the decoder when materializing a field section: dynamic entries
    /// can be shared with the output instead of copied into new allocations.
    #[inline]
    pub(crate) fn entry_bytes_at(&self, i: u64) -> Option<(Bytes, Bytes)> {
        let i = usize::try_from(i).ok()?;
        let (name, value) = self.entries.get(i)?;
        Some((name.clone(), value.clone()))
    }

    /// Returns a dynamic entry by absolute index as cheap `Bytes` clones.
    #[inline]
    pub(crate) fn get_absolute_bytes(&self, abs: u64) -> Option<(Bytes, Bytes)> {
        let last = self.last_absolute();
        if abs > last {
            return None;
        }
        self.entry_bytes_at(last - abs)
    }

    /// Returns an encoder-stream relative entry as cheap `Bytes` clones.
    #[inline]
    pub(crate) fn get_relative_bytes(&self, index: u64) -> Option<(Bytes, Bytes)> {
        self.entry_bytes_at(index)
    }

    /// Returns a field-section base-relative entry as cheap `Bytes` clones.
    #[inline]
    pub(crate) fn get_base_relative_bytes(&self, base: u64, index: u64) -> Option<(Bytes, Bytes)> {
        if index >= base {
            return None;
        }
        self.get_absolute_bytes(base - 1 - index)
    }

    /// Returns a field-section post-base entry as cheap `Bytes` clones.
    #[inline]
    pub(crate) fn get_post_base_bytes(&self, base: u64, index: u64) -> Option<(Bytes, Bytes)> {
        base.checked_add(index)
            .and_then(|abs| self.get_absolute_bytes(abs))
    }

    /// Evicts entries from the dropping point until `size <= max_size`.
    #[inline]
    fn evict_to_fit(&mut self, max_size: u64) {
        while self.size > max_size {
            let (name, value) = match self.entries.pop_back() {
                Some(entry) => entry,
                None => break,
            };
            self.size -= Self::entry_size(&name, &value);
            // The evicted entry is the oldest (smallest absolute index) of its
            // key, so a map value equals `abs` only when it was the sole
            // occurrence and must be dropped.
            let abs = self.inserted - self.entries.len() as u64 - 1;
            if self.maintain_maps {
                if self.name.get(name.as_ref()).copied() == Some(abs) {
                    self.name.remove(name.as_ref());
                }
                let key = NameValue(name, value);
                if self.exact.get(&key).copied() == Some(abs) {
                    self.exact.remove(&key);
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[inline]
    fn insert(table: &mut DynamicTable, name: &str, value: &str) -> Result<(), InsertError> {
        table.insert(
            Bytes::copy_from_slice(name.as_bytes()),
            Bytes::copy_from_slice(value.as_bytes()),
        )
    }

    /// The hash-map backed lookups must stay correct across insertion (newest
    /// absolute index wins) and eviction (oldest removed), including duplicate
    /// names.
    #[test]
    fn find_tracks_eviction_and_duplicates() {
        let mut table = DynamicTable::new(1000);
        insert(&mut table, "a", "1").unwrap(); // abs 0
        insert(&mut table, "b", "2").unwrap(); // abs 1
        insert(&mut table, "a", "3").unwrap(); // abs 2 (newest `a`)

        assert_eq!(
            table.find_full_or_name(&Bytes::from_static(b"a"), &Bytes::from_static(b"3")),
            (Some(2), Some(2))
        );
        assert_eq!(
            table.find_full_or_name(&Bytes::from_static(b"a"), &Bytes::from_static(b"1")),
            (Some(0), Some(2))
        );
        assert_eq!(table.find_name(&Bytes::from_static(b"a")), Some(2));
        assert_eq!(table.find_name(&Bytes::from_static(b"b")), Some(1));

        // Evict the oldest entry (`a`/`1`, abs 0) by shrinking capacity.
        table.set_capacity(70); // three 34-octet entries = 102 > 70 -> one evicted
        assert_eq!(
            table.find_full_or_name(&Bytes::from_static(b"a"), &Bytes::from_static(b"1")),
            (None, Some(2))
        );
        assert_eq!(table.find_name(&Bytes::from_static(b"a")), Some(2));
        assert_eq!(table.find_name(&Bytes::from_static(b"b")), Some(1));
        assert_eq!(
            table.find_full_or_name(&Bytes::from_static(b"a"), &Bytes::from_static(b"3")),
            (Some(2), Some(2))
        );
    }

    #[test]
    fn entry_size_is_name_plus_value_plus_32() {
        assert_eq!(DynamicTable::entry_size(b"foo", b"bar"), 38);
        assert_eq!(DynamicTable::entry_size(b"", b""), 32);
    }

    #[test]
    fn insert_assigns_increasing_absolute_indices() {
        let mut table = DynamicTable::new(1000);
        assert_eq!(table.len(), 0);
        assert_eq!(table.inserted(), 0);
        assert_eq!(table.next_absolute(), 0);

        insert(&mut table, ":method", "GET").unwrap();
        assert_eq!(table.inserted(), 1);
        assert_eq!(table.last_absolute(), 0);

        insert(&mut table, ":path", "/").unwrap();
        assert_eq!(table.inserted(), 2);
        assert_eq!(table.last_absolute(), 1);
        assert_eq!(
            table.get_absolute_bytes(0),
            Some((Bytes::from_static(b":method"), Bytes::from_static(b"GET")))
        );
        assert_eq!(
            table.get_absolute_bytes(1),
            Some((Bytes::from_static(b":path"), Bytes::from_static(b"/")))
        );
        assert_eq!(table.get_absolute_bytes(2), None);
    }

    #[test]
    fn relative_index_zero_is_most_recent() {
        let mut table = DynamicTable::new(1000);
        insert(&mut table, "a", "1").unwrap();
        insert(&mut table, "b", "2").unwrap();
        insert(&mut table, "c", "3").unwrap();

        assert_eq!(
            table.get_relative_bytes(0),
            Some((Bytes::from_static(b"c"), Bytes::from_static(b"3")))
        );
        assert_eq!(
            table.get_relative_bytes(1),
            Some((Bytes::from_static(b"b"), Bytes::from_static(b"2")))
        );
        assert_eq!(
            table.get_relative_bytes(2),
            Some((Bytes::from_static(b"a"), Bytes::from_static(b"1")))
        );
        assert_eq!(table.get_relative_bytes(3), None);
    }

    #[test]
    fn insert_evicts_oldest_first() {
        // capacity 100: entry size 1+1+32 = 34; three entries = 102 > 100,
        // so inserting the third evicts the first.
        let mut table = DynamicTable::new(100);
        insert(&mut table, "a", "a").unwrap();
        insert(&mut table, "b", "b").unwrap();
        assert_eq!(table.size(), 68);
        assert_eq!(table.len(), 2);

        insert(&mut table, "c", "c").unwrap();
        assert_eq!(table.size(), 68);
        assert_eq!(table.len(), 2);
        assert_eq!(table.get_absolute_bytes(0), None, "oldest entry evicted");
        assert_eq!(
            table.get_absolute_bytes(1),
            Some((Bytes::from_static(b"b"), Bytes::from_static(b"b")))
        );
        assert_eq!(
            table.get_absolute_bytes(2),
            Some((Bytes::from_static(b"c"), Bytes::from_static(b"c")))
        );
        // Absolute indices of evicted entries are never reused.
        assert_eq!(table.inserted(), 3);
    }

    #[test]
    fn insert_rejects_oversized_entry() {
        let mut table = DynamicTable::new(10);
        assert_eq!(
            insert(&mut table, "a", "a"),
            Err(InsertError::EntryTooLarge)
        );
        assert_eq!(table.len(), 0);
        assert_eq!(table.inserted(), 0);
    }

    #[test]
    fn set_capacity_evicts_and_can_clear() {
        let mut table = DynamicTable::new(1000);
        for i in 0..5 {
            insert(&mut table, &format!("h{i}"), "v").unwrap();
        }
        assert_eq!(table.len(), 5);

        // Shrink below the size of the two newest entries.
        table.set_capacity(80);
        assert!(table.size() <= 80);
        assert_eq!(table.len(), 2);

        // Setting 0 clears the table; a later increase works with an empty
        // table.
        table.set_capacity(0);
        assert_eq!(table.len(), 0);
        assert_eq!(table.size(), 0);
        table.set_capacity(1000);
        insert(&mut table, "fresh", "entry").unwrap();
        assert_eq!(table.len(), 1);
        assert_eq!(
            table.get_absolute_bytes(5),
            Some((Bytes::from_static(b"fresh"), Bytes::from_static(b"entry")))
        );
    }

    #[test]
    fn field_section_relative_and_post_base_indexing() {
        // Recreates the RFC 9204 Figure 3/4 scenario: 10 insertions, 3
        // evictions (alive absolute indices 3..=9), Base = 8.
        let mut table = DynamicTable::new(1000);
        for i in 0..10u8 {
            let bytes = Bytes::copy_from_slice(&[b'a' + i]);
            table.insert(bytes.clone(), bytes).unwrap();
        }
        // Evict the three oldest (absolute 0..=2) by shrinking capacity and
        // restoring it: 7 entries x 34 bytes each.
        table.set_capacity(7 * 34);
        table.set_capacity(1000);
        assert_eq!(table.len(), 7);
        assert_eq!(table.last_absolute(), 9);

        let base = 8;
        // Relative: index 0 -> absolute 7, increasing indices go older.
        assert_eq!(
            table.get_base_relative_bytes(base, 0),
            table.get_absolute_bytes(7)
        );
        assert_eq!(
            table.get_base_relative_bytes(base, 3),
            table.get_absolute_bytes(4)
        );
        assert_eq!(
            table.get_base_relative_bytes(base, 5),
            table.get_absolute_bytes(2)
        );
        assert_eq!(
            table.get_base_relative_bytes(base, 5),
            None,
            "evicted entry"
        );
        assert_eq!(
            table.get_base_relative_bytes(base, 8),
            None,
            "index >= base"
        );

        // Post-base: index 0 -> absolute 8, increasing indices go newer.
        assert_eq!(
            table.get_post_base_bytes(base, 0),
            table.get_absolute_bytes(8)
        );
        assert_eq!(
            table.get_post_base_bytes(base, 1),
            table.get_absolute_bytes(9)
        );
        assert_eq!(
            table.get_post_base_bytes(base, 2),
            None,
            "beyond newest entry"
        );
    }

    #[test]
    fn duplicate_entries_are_allowed() {
        let mut table = DynamicTable::new(1000);
        insert(&mut table, "cookie", "a=b").unwrap();
        insert(&mut table, "cookie", "a=b").unwrap();
        assert_eq!(table.len(), 2);
        assert_eq!(
            table.get_absolute_bytes(0),
            Some((Bytes::from_static(b"cookie"), Bytes::from_static(b"a=b")))
        );
        assert_eq!(
            table.get_absolute_bytes(1),
            Some((Bytes::from_static(b"cookie"), Bytes::from_static(b"a=b")))
        );
    }

    #[test]
    fn empty_table_lookups_return_none() {
        let table = DynamicTable::new(1000);
        assert_eq!(table.get_absolute_bytes(0), None);
        assert_eq!(table.get_relative_bytes(0), None);
        assert_eq!(table.get_base_relative_bytes(0, 0), None);
        assert_eq!(table.get_post_base_bytes(0, 0), None);
    }
}
