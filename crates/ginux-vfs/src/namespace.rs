//! Overlay slots and the exact path index kept inside them.
//!
//! Every slot that is not free belongs to one hash chain, chosen by its path.
//! Chain heads and links live in the slots themselves, so the index needs no
//! allocation, grows with the namespace capacity and is charged wherever the
//! namespace is. A slot's `state` and `path` can change only through
//! [`Namespace`], which moves the slot between chains as they change; the rest
//! of the crate reads them through accessors and receives mutable slots only
//! through [`Namespace::entry_mut`], never a mutable slice.

use core::ops::{Deref, DerefMut};

use super::{NodeKind, Path, Slot, Timestamp};

const NONE: u32 = u32::MAX;

#[derive(Clone, Copy)]
pub struct OverlayFile {
    pub(crate) accessed: Timestamp,
    pub(crate) modified: Timestamp,
    state: Slot,
    pub(crate) kind: NodeKind,
    path: Path,
    pub(crate) mode: u32,
    pub(crate) len: usize,
    pub(crate) executions: usize,
    pub(crate) links: u64,
    pub(crate) object: Option<usize>,
    pub(crate) name_pins: usize,
    /// The image record this object replaced, as its inode; zero for an
    /// object created in the instance, whose inode follows from its slot.
    pub(crate) inode: u64,
    /// First member of the chain whose bucket number is this slot's position.
    /// It describes other slots and is unrelated to this slot's own contents.
    chain_head: u32,
    /// The next member of the chain this slot's own path belongs to.
    chain_next: u32,
}

impl OverlayFile {
    pub const fn empty() -> Self {
        Self {
            accessed: Timestamp::ZERO,
            modified: Timestamp::ZERO,
            state: Slot::Free,
            kind: NodeKind::File,
            path: Path::new(),
            mode: 0,
            len: 0,
            executions: 0,
            links: 0,
            object: None,
            name_pins: 0,
            inode: 0,
            chain_head: NONE,
            chain_next: NONE,
        }
    }

    pub(crate) fn state(&self) -> Slot {
        self.state
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// A namespace of overlay slots with its path index.
///
/// Lookups answer exactly as a scan in slot order would: the lowest live slot
/// with the path, otherwise the lowest whiteout with it. Several slots can
/// hold one path (a whiteout left behind by a replaced name, for example), so
/// a lookup examines every member of the path's chain rather than the first.
/// Hash collisions only lengthen a chain; they never change an answer, and a
/// chain never holds more than the named slots, so a lookup is never slower
/// than the scan it replaces.
pub(crate) struct Namespace<N> {
    slots: N,
    /// No slot below this position is free.
    free_hint: usize,
}

impl<N: Deref<Target = [OverlayFile]>> Deref for Namespace<N> {
    type Target = [OverlayFile];
    fn deref(&self) -> &[OverlayFile] {
        &self.slots
    }
}

impl<N: Deref<Target = [OverlayFile]> + DerefMut> Namespace<N> {
    /// Index whatever the supplied slots already hold.
    pub(crate) fn new(slots: N) -> Self {
        assert!(
            slots.len() < NONE as usize,
            "overlay namespace capacity exceeds the index range"
        );
        let mut namespace = Self {
            slots,
            free_hint: 0,
        };
        for slot in namespace.slots.iter_mut() {
            slot.chain_head = NONE;
            slot.chain_next = NONE;
        }
        for slot in 0..namespace.slots.len() {
            if namespace.slots[slot].state != Slot::Free {
                namespace.link(slot);
            }
        }
        namespace.advance_free_hint();
        namespace
    }

    /// Mutable access to one slot. Its name changes only through `occupy`,
    /// `set_state`, `set_path` and `vacate`; never replace the whole slot.
    pub(crate) fn entry_mut(&mut self, slot: usize) -> &mut OverlayFile {
        &mut self.slots[slot]
    }

    /// The lowest live slot named `path`, otherwise its lowest whiteout.
    pub(crate) fn find(&self, path: &[u8]) -> Option<usize> {
        let mut live: Option<usize> = None;
        let mut whiteout: Option<usize> = None;
        for slot in self.chain(path) {
            let entry = &self.slots[slot];
            debug_assert!(entry.state != Slot::Free, "free slot in an index chain");
            if entry.path.as_bytes() != path {
                continue;
            }
            let best = if entry.state == Slot::Whiteout {
                &mut whiteout
            } else {
                &mut live
            };
            *best = Some(best.map_or(slot, |other| other.min(slot)));
        }
        live.or(whiteout)
    }

    /// Whether a slot other than `slot` that is not free holds `slot`'s path.
    pub(crate) fn path_shared(&self, slot: usize) -> bool {
        let path = self.slots[slot].path.as_bytes();
        self.chain(path)
            .any(|other| other != slot && self.slots[other].path.as_bytes() == path)
    }

    /// The lowest free slot.
    pub(crate) fn first_free(&self) -> Option<usize> {
        (self.free_hint..self.slots.len()).find(|slot| self.slots[*slot].state == Slot::Free)
    }

    /// Give `slot` a new name and otherwise empty contents.
    pub(crate) fn occupy(&mut self, slot: usize, state: Slot, path: Path) -> &mut OverlayFile {
        self.replace(slot, state, path);
        &mut self.slots[slot]
    }

    /// Free `slot` and clear its contents.
    pub(crate) fn vacate(&mut self, slot: usize) {
        self.replace(slot, Slot::Free, Path::new());
    }

    /// Free every slot.
    pub(crate) fn vacate_all(&mut self) {
        self.slots.fill(OverlayFile::empty());
        self.free_hint = 0;
    }

    /// Change what `slot` holds while keeping its path and contents.
    pub(crate) fn set_state(&mut self, slot: usize, state: Slot) {
        let path = self.slots[slot].path;
        self.rename_slot(slot, state, path);
    }

    /// Change `slot`'s path while keeping what it holds and its contents.
    pub(crate) fn set_path(&mut self, slot: usize, path: Path) {
        let state = self.slots[slot].state;
        self.rename_slot(slot, state, path);
    }

    fn replace(&mut self, slot: usize, state: Slot, path: Path) {
        self.rename_slot(slot, Slot::Free, Path::new());
        let chain_head = self.slots[slot].chain_head;
        self.slots[slot] = OverlayFile {
            chain_head,
            ..OverlayFile::empty()
        };
        self.rename_slot(slot, state, path);
    }

    /// Every change to one slot's name ends here, which keeps the index exact.
    fn rename_slot(&mut self, slot: usize, state: Slot, path: Path) {
        let entry = &self.slots[slot];
        let indexed = entry.state != Slot::Free;
        if indexed && state != Slot::Free && entry.path.as_bytes() == path.as_bytes() {
            // Same chain: only what the slot holds changes.
            self.slots[slot].state = state;
            return;
        }
        if indexed {
            self.unlink(slot);
        }
        self.slots[slot].state = state;
        self.slots[slot].path = path;
        if state == Slot::Free {
            self.free_hint = self.free_hint.min(slot);
        } else {
            self.link(slot);
            self.advance_free_hint();
        }
    }

    fn advance_free_hint(&mut self) {
        while self
            .slots
            .get(self.free_hint)
            .is_some_and(|entry| entry.state != Slot::Free)
        {
            self.free_hint += 1;
        }
    }

    fn bucket(&self, path: &[u8]) -> usize {
        // Map the full hash range onto the capacity without a division.
        ((u128::from(hash(path)) * self.slots.len() as u128) >> 64) as usize
    }

    fn chain(&self, path: &[u8]) -> Chain<'_> {
        let next = if self.slots.is_empty() {
            NONE
        } else {
            self.slots[self.bucket(path)].chain_head
        };
        Chain {
            slots: &self.slots[..],
            next,
        }
    }

    fn link(&mut self, slot: usize) {
        let bucket = self.bucket(self.slots[slot].path.as_bytes());
        self.slots[slot].chain_next = self.slots[bucket].chain_head;
        self.slots[bucket].chain_head = slot as u32;
    }

    fn unlink(&mut self, slot: usize) {
        let bucket = self.bucket(self.slots[slot].path.as_bytes());
        let next = self.slots[slot].chain_next;
        self.slots[slot].chain_next = NONE;
        if self.slots[bucket].chain_head == slot as u32 {
            self.slots[bucket].chain_head = next;
            return;
        }
        let mut member = self.slots[bucket].chain_head;
        while member != NONE {
            let after = self.slots[member as usize].chain_next;
            if after == slot as u32 {
                self.slots[member as usize].chain_next = next;
                return;
            }
            member = after;
        }
        panic!("overlay slot missing from its index chain");
    }

    /// Check every index invariant against the slots themselves.
    #[cfg(test)]
    pub(crate) fn assert_consistent(&self) {
        extern crate std;
        let len = self.slots.len();
        let mut seen = std::vec![false; len];
        for bucket in 0..len {
            let mut member = self.slots[bucket].chain_head;
            let mut steps = 0;
            while member != NONE {
                let slot = member as usize;
                assert!(slot < len, "chain member out of range");
                assert!(
                    !seen[slot],
                    "slot {slot} is in more than one chain position"
                );
                seen[slot] = true;
                assert!(
                    self.slots[slot].state != Slot::Free,
                    "free slot {slot} indexed"
                );
                assert_eq!(self.bucket(self.slots[slot].path.as_bytes()), bucket);
                steps += 1;
                assert!(steps <= len, "index chain cycle");
                member = self.slots[slot].chain_next;
            }
        }
        for (slot, entry) in self.slots.iter().enumerate() {
            assert_eq!(
                seen[slot],
                entry.state != Slot::Free,
                "slot {slot} index membership"
            );
            if entry.state == Slot::Free {
                assert_eq!(entry.chain_next, NONE);
            }
        }
        assert!(self.free_hint <= len);
        assert!(self.slots[..self.free_hint]
            .iter()
            .all(|entry| entry.state != Slot::Free));
    }
}

struct Chain<'a> {
    slots: &'a [OverlayFile],
    next: u32,
}

impl Iterator for Chain<'_> {
    type Item = usize;
    fn next(&mut self) -> Option<usize> {
        if self.next == NONE {
            return None;
        }
        let slot = self.next as usize;
        self.next = self.slots[slot].chain_next;
        Some(slot)
    }
}

/// FNV-1a with a final avalanche, so every bit of the result depends on the
/// whole path before `bucket` takes the high bits.
fn hash(path: &[u8]) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in path {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    }
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^ (hash >> 33)
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    const STATES: [Slot; 7] = [
        Slot::Free,
        Slot::File,
        Slot::Whiteout,
        Slot::Directory,
        Slot::Symlink,
        Slot::Fifo,
        Slot::Link,
    ];

    fn path(bytes: &[u8]) -> Path {
        let mut path = Path::new();
        path.extend(bytes).unwrap();
        path
    }

    fn namespace(capacity: usize) -> Namespace<Vec<OverlayFile>> {
        Namespace::new(std::vec![OverlayFile::empty(); capacity])
    }

    /// The scan the index replaces: lowest live slot, then lowest whiteout.
    fn linear(slots: &[OverlayFile], path: &[u8]) -> Option<usize> {
        slots
            .iter()
            .position(|entry| {
                !matches!(entry.state, Slot::Free | Slot::Whiteout) && entry.path.as_bytes() == path
            })
            .or_else(|| {
                slots.iter().position(|entry| {
                    entry.state == Slot::Whiteout && entry.path.as_bytes() == path
                })
            })
    }

    fn check(names: &Namespace<Vec<OverlayFile>>, paths: &[Path]) {
        names.assert_consistent();
        for path in paths {
            assert_eq!(names.find(path.as_bytes()), linear(names, path.as_bytes()));
        }
        assert_eq!(
            names.first_free(),
            names.iter().position(|entry| entry.state == Slot::Free)
        );
        for slot in 0..names.len() {
            if names[slot].state != Slot::Free {
                let shared = names.iter().enumerate().any(|(other, entry)| {
                    other != slot
                        && entry.state != Slot::Free
                        && entry.path.as_bytes() == names[slot].path.as_bytes()
                });
                assert_eq!(names.path_shared(slot), shared);
            }
        }
    }

    struct Rng(u64);
    impl Rng {
        fn below(&mut self, bound: usize) -> usize {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            (self.0 % bound as u64) as usize
        }
    }

    #[test]
    fn duplicate_names_resolve_to_the_lowest_live_slot_then_the_lowest_whiteout() {
        let mut names = namespace(6);
        let name = path(b"/name");
        names.occupy(4, Slot::Whiteout, name);
        names.occupy(2, Slot::Whiteout, name);
        assert_eq!(names.find(b"/name"), Some(2));
        names.occupy(5, Slot::File, name);
        names.occupy(3, Slot::Link, name);
        assert_eq!(names.find(b"/name"), Some(3));
        names.set_state(3, Slot::Whiteout);
        assert_eq!(names.find(b"/name"), Some(5));
        names.set_path(5, path(b"/other"));
        assert_eq!(names.find(b"/name"), Some(2));
        assert_eq!(names.find(b"/other"), Some(5));
        names.vacate(2);
        assert_eq!(names.find(b"/name"), Some(3));
        assert_eq!(names.first_free(), Some(0));
        check(&names, &[name, path(b"/other"), path(b"/missing")]);
    }

    #[test]
    fn one_slot_namespace_puts_every_name_in_one_chain() {
        let mut names = namespace(1);
        assert_eq!(names.find(b"/a"), None);
        names.occupy(0, Slot::File, path(b"/a"));
        assert_eq!(names.first_free(), None);
        assert_eq!(names.find(b"/a"), Some(0));
        names.set_path(0, path(b"/b"));
        assert_eq!((names.find(b"/a"), names.find(b"/b")), (None, Some(0)));
        names.occupy(0, Slot::Whiteout, path(b"/c"));
        assert_eq!((names.find(b"/b"), names.find(b"/c")), (None, Some(0)));
        names.vacate(0);
        assert_eq!(names.find(b"/c"), None);
        check(&names, &[path(b"/a"), path(b"/b"), path(b"/c")]);
    }

    #[test]
    fn empty_namespace_finds_nothing() {
        let names = namespace(0);
        assert_eq!(names.find(b"/"), None);
        assert_eq!(names.first_free(), None);
        names.assert_consistent();
    }

    #[test]
    fn chains_survive_changes_to_the_slot_holding_their_head() {
        // Fill a full namespace with names whose chain head lives in slot 0,
        // then rewrite slot 0 itself in every way a slot can change.
        let capacity = 4;
        let mut names = namespace(capacity);
        let mut bucket_zero = (0..)
            .map(|n| path(std::format!("/n{n}").as_bytes()))
            .filter(|name| names.bucket(name.as_bytes()) == 0);
        let held: Vec<Path> = (0..capacity).map(|_| bucket_zero.next().unwrap()).collect();
        for (slot, name) in held.iter().enumerate() {
            names.occupy(slot, Slot::File, *name);
        }
        check(&names, &held);
        names.set_state(0, Slot::Whiteout);
        check(&names, &held);
        names.set_path(0, path(b"/elsewhere"));
        check(&names, &held);
        names.vacate(0);
        check(&names, &held);
        names.occupy(0, Slot::Directory, held[3]);
        check(&names, &held);
        assert_eq!(names.find(held[3].as_bytes()), Some(0));
        names.vacate_all();
        check(&names, &held);
    }

    #[test]
    fn supplied_slots_are_indexed_whatever_their_chain_fields_hold() {
        let mut names = namespace(8);
        let held: Vec<Path> = (0..6)
            .map(|n| path(std::format!("/s{}", n % 4).as_bytes()))
            .collect();
        for (slot, name) in held.iter().enumerate() {
            names.occupy(slot + 1, STATES[1 + slot % 6], *name);
        }
        let mut slots = names.slots.clone();
        for (n, slot) in slots.iter_mut().enumerate() {
            slot.chain_head = n as u32;
            slot.chain_next = (n as u32 + 1) % 8;
        }
        let rebuilt = Namespace::new(slots);
        check(&rebuilt, &held);
        assert_eq!(rebuilt.first_free(), Some(0));
    }

    #[test]
    fn random_changes_keep_every_lookup_equal_to_a_scan() {
        let pool: Vec<Path> = (0..10)
            .map(|n| path(std::format!("/p/{n}").as_bytes()))
            .collect();
        for capacity in [1, 2, 3, 5, 8, 16] {
            for seed in 1..=8u64 {
                let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
                let mut names = namespace(capacity);
                for _ in 0..2_000 {
                    let slot = rng.below(capacity);
                    let name = pool[rng.below(pool.len())];
                    match rng.below(6) {
                        0 | 1 => {
                            let state = STATES[1 + rng.below(6)];
                            names.occupy(slot, state, name);
                        }
                        2 if names[slot].state != Slot::Free => {
                            names.set_state(slot, STATES[1 + rng.below(6)]);
                        }
                        3 if names[slot].state != Slot::Free => names.set_path(slot, name),
                        4 => names.vacate(slot),
                        5 if rng.below(50) == 0 => names.vacate_all(),
                        _ => {}
                    }
                    check(&names, &pool);
                }
            }
        }
    }
}
