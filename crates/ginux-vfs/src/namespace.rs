//! Overlay slots and the exact indexes kept inside them.
//!
//! Every slot that is not free belongs to one name chain, chosen by its path,
//! and every live slot a directory holds belongs to one child chain, chosen by
//! that directory's path. Chain heads and links live in the slots themselves,
//! so the indexes need no allocation, grow with the namespace capacity and are
//! charged wherever the namespace is. A slot's `state` and `path` can change
//! only through [`Namespace`], which moves the slot between chains as they
//! change; the rest of the crate reads them through accessors and receives
//! mutable slots only through [`Namespace::entry_mut`], never a mutable slice.

use core::ops::{Deref, DerefMut};

use super::{beneath, NodeKind, Path, Slot, Timestamp};

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
    /// First member of the child chain whose bucket number is this slot's
    /// position. Like `chain_head`, it describes other slots.
    child_head: u32,
    /// The neighbours in the child chain of the directory holding this slot.
    child_prev: u32,
    child_next: u32,
    /// The listing that last included this slot, and the slot after it there.
    listing: u32,
    listed_next: u32,
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
            child_head: NONE,
            child_prev: NONE,
            child_next: NONE,
            listing: 0,
            listed_next: NONE,
        }
    }

    pub(crate) fn state(&self) -> Slot {
        self.state
    }

    pub(crate) fn path(&self) -> &Path {
        &self.path
    }
}

/// A namespace of overlay slots with its path and child indexes.
///
/// Lookups answer exactly as a scan in slot order would: the lowest live slot
/// with the path, otherwise the lowest whiteout with it. Several slots can
/// hold one path (a whiteout left behind by a replaced name, for example), so
/// a lookup examines every member of the path's chain rather than the first.
/// Hash collisions only lengthen a chain; they never change an answer, and a
/// chain never holds more than the named slots, so a lookup is never slower
/// than the scan it replaces.
///
/// The child index groups live slots (not free, not whiteouts) by the
/// directory that holds them, as [`holder`] decides. Its chains are doubly
/// linked, so a slot leaves a large directory in constant time.
pub(crate) struct Namespace<N> {
    slots: N,
    /// No slot below this position is free.
    free_hint: usize,
    /// The number of the latest listing made by `subtree`.
    listing: u32,
}

/// Live slots threaded through the slots themselves by [`Namespace::subtree`].
/// Valid only until the next listing.
#[derive(Clone, Copy)]
pub(crate) struct Subtree {
    first: u32,
    listing: u32,
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
            listing: 0,
        };
        for slot in namespace.slots.iter_mut() {
            slot.chain_head = NONE;
            slot.chain_next = NONE;
            slot.child_head = NONE;
            slot.child_prev = NONE;
            slot.child_next = NONE;
            slot.listing = 0;
            slot.listed_next = NONE;
        }
        for slot in 0..namespace.slots.len() {
            if namespace.slots[slot].state != Slot::Free {
                namespace.link(slot);
            }
            if held(namespace.slots[slot].state, &namespace.slots[slot].path) {
                namespace.link_child(slot);
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

    /// Whether a live slot is a child of `directory`, as `child_name`
    /// decides.
    pub(crate) fn has_child(&self, directory: &[u8]) -> bool {
        self.children(directory_key(directory)).next().is_some()
    }

    /// List every live slot named `path` or beneath it, as `beneath` decides,
    /// by walking the child index down from `path`.
    ///
    /// The walk descends only through live slots, so a live slot beneath
    /// `path` is listed when the directory holding it is `path` or another
    /// listed slot. The filesystem keeps that true for every directory that
    /// is not in the image: a name is created only inside an existing
    /// directory, a directory is removed only once it holds nothing, and a
    /// rename moves a whole subtree. Every listed slot is live and beneath
    /// `path`, whatever the namespace holds, and each is listed once.
    pub(crate) fn subtree(&mut self, path: &[u8]) -> Subtree {
        self.listing = match self.listing.checked_add(1) {
            Some(listing) => listing,
            None => {
                for slot in self.slots.iter_mut() {
                    slot.listing = 0;
                }
                1
            }
        };
        let mut list = Subtree {
            first: NONE,
            listing: self.listing,
        };
        let mut last = NONE;
        let mut member = self.chain(path).next;
        while member != NONE {
            let slot = member as usize;
            member = self.slots[slot].chain_next;
            if live(self.slots[slot].state) && self.slots[slot].path.as_bytes() == path {
                self.append(&mut list, &mut last, slot);
            }
        }
        let mut cursor = list.first;
        while cursor != NONE {
            let directory = self.slots[cursor as usize].path;
            let directory = directory_key(directory.as_bytes());
            let mut member = self.child_chain(directory);
            while member != NONE {
                let slot = member as usize;
                member = self.slots[slot].child_next;
                let entry = &self.slots[slot];
                if entry.listing != list.listing
                    && holder(entry.path.as_bytes()) == Some(directory)
                    && beneath(entry.path.as_bytes(), path)
                {
                    self.append(&mut list, &mut last, slot);
                }
            }
            cursor = self.slots[cursor as usize].listed_next;
        }
        list
    }

    /// The slots of the latest listing, in the order it found them.
    pub(crate) fn listed(&self, list: Subtree) -> impl Iterator<Item = usize> + '_ {
        let mut next = list.first;
        core::iter::from_fn(move || {
            let slot = self.listed_slot(list, next)?;
            next = self.slots[slot].listed_next;
            Some(slot)
        })
    }

    /// The slot listed after `slot`, which belongs to the latest listing.
    pub(crate) fn listed_after(&self, list: Subtree, slot: usize) -> Option<usize> {
        let slot = self.listed_slot(list, slot as u32)?;
        self.listed_slot(list, self.slots[slot].listed_next)
    }

    fn listed_slot(&self, list: Subtree, slot: u32) -> Option<usize> {
        if slot == NONE {
            return None;
        }
        let slot = slot as usize;
        assert!(
            list.listing == self.listing && self.slots[slot].listing == list.listing,
            "stale overlay subtree listing"
        );
        Some(slot)
    }

    fn append(&mut self, list: &mut Subtree, last: &mut u32, slot: usize) {
        // A second entry would turn the list into a cycle.
        assert!(
            self.slots[slot].listing != list.listing,
            "overlay slot listed twice"
        );
        self.slots[slot].listing = list.listing;
        self.slots[slot].listed_next = NONE;
        if *last == NONE {
            list.first = slot as u32;
        } else {
            self.slots[*last as usize].listed_next = slot as u32;
        }
        *last = slot as u32;
    }

    /// Live slots whose holder is `directory`, which `directory_key` wrote.
    fn children<'a>(&'a self, directory: &'a [u8]) -> impl Iterator<Item = usize> + 'a {
        let mut member = self.child_chain(directory);
        core::iter::from_fn(move || {
            while member != NONE {
                let slot = member as usize;
                member = self.slots[slot].child_next;
                if holder(self.slots[slot].path.as_bytes()) == Some(directory) {
                    return Some(slot);
                }
            }
            None
        })
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
        let entry = &self.slots[slot];
        self.slots[slot] = OverlayFile {
            chain_head: entry.chain_head,
            child_head: entry.child_head,
            listing: entry.listing,
            listed_next: entry.listed_next,
            ..OverlayFile::empty()
        };
        self.rename_slot(slot, state, path);
    }

    /// Every change to one slot's name ends here, which keeps the indexes
    /// exact.
    fn rename_slot(&mut self, slot: usize, state: Slot, path: Path) {
        let entry = &self.slots[slot];
        let named = entry.state != Slot::Free;
        let same_path = entry.path.as_bytes() == path.as_bytes();
        let was_held = held(entry.state, &entry.path);
        let is_held = held(state, &path);
        if was_held && !(is_held && same_path) {
            self.unlink_child(slot);
        }
        if named && state != Slot::Free && same_path {
            // Same name chain: only what the slot holds changes.
            self.slots[slot].state = state;
        } else {
            if named {
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
        if is_held && !(was_held && same_path) {
            self.link_child(slot);
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

    fn child_chain(&self, directory: &[u8]) -> u32 {
        if self.slots.is_empty() {
            NONE
        } else {
            self.slots[self.bucket(directory)].child_head
        }
    }

    fn child_bucket(&self, slot: usize) -> usize {
        let directory = holder(self.slots[slot].path.as_bytes()).expect("held overlay slot");
        self.bucket(directory)
    }

    fn link_child(&mut self, slot: usize) {
        let bucket = self.child_bucket(slot);
        let head = self.slots[bucket].child_head;
        assert!(
            self.slots[slot].child_prev == NONE
                && self.slots[slot].child_next == NONE
                && head != slot as u32,
            "overlay slot already in a child chain"
        );
        self.slots[slot].child_prev = NONE;
        self.slots[slot].child_next = head;
        if head != NONE {
            self.slots[head as usize].child_prev = slot as u32;
        }
        self.slots[bucket].child_head = slot as u32;
    }

    fn unlink_child(&mut self, slot: usize) {
        let prev = self.slots[slot].child_prev;
        let next = self.slots[slot].child_next;
        if prev == NONE {
            let bucket = self.child_bucket(slot);
            assert!(
                self.slots[bucket].child_head == slot as u32,
                "overlay slot missing from its child chain"
            );
            self.slots[bucket].child_head = next;
        } else {
            assert!(
                self.slots[prev as usize].child_next == slot as u32,
                "overlay child chain forward link"
            );
            self.slots[prev as usize].child_next = next;
        }
        if next != NONE {
            assert!(
                self.slots[next as usize].child_prev == slot as u32,
                "overlay child chain back link"
            );
            self.slots[next as usize].child_prev = prev;
        }
        self.slots[slot].child_prev = NONE;
        self.slots[slot].child_next = NONE;
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

        let mut seen = std::vec![false; len];
        for bucket in 0..len {
            let mut member = self.slots[bucket].child_head;
            let mut prev = NONE;
            let mut steps = 0;
            while member != NONE {
                let slot = member as usize;
                assert!(slot < len, "child chain member out of range");
                assert!(
                    !seen[slot],
                    "slot {slot} is in more than one child chain position"
                );
                seen[slot] = true;
                let entry = &self.slots[slot];
                assert!(held(entry.state, &entry.path), "slot {slot} is not held");
                assert_eq!(self.child_bucket(slot), bucket);
                assert_eq!(entry.child_prev, prev, "slot {slot} child chain back link");
                steps += 1;
                assert!(steps <= len, "child chain cycle");
                prev = member;
                member = entry.child_next;
            }
        }
        for (slot, entry) in self.slots.iter().enumerate() {
            assert_eq!(
                seen[slot],
                held(entry.state, &entry.path),
                "slot {slot} child index membership"
            );
            if !seen[slot] {
                assert_eq!((entry.child_prev, entry.child_next), (NONE, NONE));
            }
            assert!(
                entry.listing <= self.listing,
                "slot {slot} listing from the future"
            );
        }
    }
}

/// Whether a slot holding `state` is a directory entry rather than free or a
/// whiteout. Only these count as names beneath or inside a directory.
fn live(state: Slot) -> bool {
    !matches!(state, Slot::Free | Slot::Whiteout)
}

/// Whether a slot belongs to the child index.
fn held(state: Slot, path: &Path) -> bool {
    live(state) && holder(path.as_bytes()).is_some()
}

/// The directory `d` for which `child_name(d, path)` names something, written
/// as [`directory_key`] writes it. No other directory has `path` as a child:
/// the name is everything after the last slash and must not be empty, and the
/// directory is everything before it, except that the root is written `/` and
/// so `//name` belongs to no directory.
fn holder(path: &[u8]) -> Option<&[u8]> {
    let split = path.iter().rposition(|byte| *byte == b'/')?;
    if split + 1 == path.len() {
        return None;
    }
    match &path[..split] {
        b"" => Some(b"/"),
        b"/" => None,
        directory => Some(directory),
    }
}

/// `child_name` treats an empty directory as the root.
fn directory_key(directory: &[u8]) -> &[u8] {
    if directory.is_empty() {
        b"/"
    } else {
        directory
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

    fn check(names: &mut Namespace<Vec<OverlayFile>>, paths: &[Path]) {
        // First, so that a broken chain fails here instead of looping below.
        names.assert_consistent();
        check_children(names, paths);
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

    /// Compare the child index with scans for every path, its holder and the
    /// root, both as directories and as subtrees.
    fn check_children(names: &mut Namespace<Vec<OverlayFile>>, paths: &[Path]) {
        let mut directories: Vec<&[u8]> = std::vec![b"", b"/"];
        for path in paths {
            directories.push(path.as_bytes());
            directories.extend(holder(path.as_bytes()));
        }
        directories.sort_unstable();
        directories.dedup();
        for directory in directories {
            let scanned = names.iter().any(|entry| {
                live(entry.state) && crate::child_name(directory, entry.path.as_bytes()).is_some()
            });
            assert_eq!(
                names.has_child(directory),
                scanned,
                "children of {:?}",
                std::string::String::from_utf8_lossy(directory)
            );
            let list = names.subtree(directory);
            let mut listed: Vec<usize> = names.listed(list).collect();
            let found = listed.len();
            listed.sort_unstable();
            listed.dedup();
            assert_eq!(listed.len(), found, "a slot was listed twice");
            assert_eq!(listed, reachable(names, directory));
            let following: Vec<usize> = (0..found)
                .scan(names.listed(list).next(), |slot, _| {
                    let current = (*slot)?;
                    *slot = names.listed_after(list, current);
                    Some(current)
                })
                .collect();
            assert_eq!(following, names.listed(list).collect::<Vec<_>>());
        }
    }

    /// What `subtree` must list: the live slots named `path`, then every live
    /// slot beneath `path` whose holder is named by a slot already listed.
    /// When every live slot beneath `path` is reached this way, as the
    /// filesystem keeps it, the listing is exactly the scan `rename` replaced.
    fn reachable(names: &Namespace<Vec<OverlayFile>>, path: &[u8]) -> Vec<usize> {
        let scanned: Vec<usize> = (0..names.len())
            .filter(|slot| live(names[*slot].state) && beneath(names[*slot].path.as_bytes(), path))
            .collect();
        let mut listed: Vec<usize> = scanned
            .iter()
            .copied()
            .filter(|slot| names[*slot].path.as_bytes() == path)
            .collect();
        let mut next = 0;
        while let Some(directory) = listed.get(next) {
            let directory = directory_key(names[*directory].path.as_bytes());
            for slot in &scanned {
                if !listed.contains(slot) && holder(names[*slot].path.as_bytes()) == Some(directory)
                {
                    listed.push(*slot);
                }
            }
            next += 1;
        }
        listed.sort_unstable();
        listed
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
        check(&mut names, &[name, path(b"/other"), path(b"/missing")]);
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
        check(&mut names, &[path(b"/a"), path(b"/b"), path(b"/c")]);
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
        check(&mut names, &held);
        names.set_state(0, Slot::Whiteout);
        check(&mut names, &held);
        names.set_path(0, path(b"/elsewhere"));
        check(&mut names, &held);
        names.vacate(0);
        check(&mut names, &held);
        names.occupy(0, Slot::Directory, held[3]);
        check(&mut names, &held);
        assert_eq!(names.find(held[3].as_bytes()), Some(0));
        names.vacate_all();
        check(&mut names, &held);
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
        let mut rebuilt = Namespace::new(slots);
        check(&mut rebuilt, &held);
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
                    check(&mut names, &pool);
                }
            }
        }
    }
    #[test]
    fn holder_is_the_one_directory_child_name_accepts() {
        // Every string of up to five bytes over `/`, `a` and `.`, as a path
        // and as a directory, including the empty string and doubled slashes.
        let mut strings: Vec<Vec<u8>> = std::vec![Vec::new()];
        let mut start = 0;
        for _ in 0..5 {
            let end = strings.len();
            for n in start..end {
                for byte in *b"/a." {
                    let mut longer = strings[n].clone();
                    longer.push(byte);
                    strings.push(longer);
                }
            }
            start = end;
        }
        for path in &strings {
            for directory in &strings {
                assert_eq!(
                    crate::child_name(directory, path).is_some(),
                    holder(path) == Some(directory_key(directory)),
                    "{:?} in {:?}",
                    std::string::String::from_utf8_lossy(path),
                    std::string::String::from_utf8_lossy(directory)
                );
            }
        }
    }

    #[test]
    fn child_index_follows_live_names_but_not_whiteouts() {
        let mut names = namespace(8);
        let all = [
            path(b"/d"),
            path(b"/d/a"),
            path(b"/d/a/b"),
            path(b"/d/c"),
            path(b"/e"),
        ];
        for (slot, name) in all.iter().enumerate() {
            names.occupy(slot, Slot::Directory, *name);
        }
        assert!(names.has_child(b"/d") && names.has_child(b"/d/a") && !names.has_child(b"/e"));
        names.set_state(2, Slot::Whiteout);
        assert!(!names.has_child(b"/d/a"));
        check(&mut names, &all);
        names.set_state(2, Slot::File);
        assert!(names.has_child(b"/d/a"));
        names.set_path(1, path(b"/e/a"));
        assert!(names.has_child(b"/e") && names.has_child(b"/d"));
        check(&mut names, &all);
        names.vacate(3);
        names.vacate(1);
        assert!(!names.has_child(b"/d"));
        // `/d/a/b` is no longer reachable from `/d`, which the filesystem
        // never allows; the listing still names only slots beneath `/d`.
        let list = names.subtree(b"/d");
        assert_eq!(names.listed(list).collect::<Vec<_>>(), std::vec![0]);
        check(&mut names, &all);
    }

    #[test]
    #[should_panic(expected = "stale overlay subtree listing")]
    fn a_listing_is_refused_after_the_next_one() {
        let mut names = namespace(4);
        names.occupy(0, Slot::Directory, path(b"/d"));
        names.occupy(1, Slot::File, path(b"/d/f"));
        let old = names.subtree(b"/d");
        names.subtree(b"/d/f");
        names.listed(old).for_each(drop);
    }

    #[test]
    fn listing_numbers_wrap_without_reviving_old_marks() {
        let mut names = namespace(4);
        names.occupy(0, Slot::Directory, path(b"/d"));
        names.occupy(1, Slot::File, path(b"/d/f"));
        names.occupy(2, Slot::File, path(b"/d/g"));
        // A mark carrying the number the counter restarts at must not make
        // its slot look listed already.
        names.listing = u32::MAX;
        names.slots[1].listing = 1;
        let list = names.subtree(b"/d");
        assert_eq!(names.listing, 1);
        let mut listed: Vec<usize> = names.listed(list).collect();
        listed.sort_unstable();
        assert_eq!(listed, std::vec![0, 1, 2]);
        names.assert_consistent();
        let list = names.subtree(b"/d");
        assert_eq!(names.listing, 2);
        assert_eq!(names.listed(list).count(), 3);
        names.assert_consistent();
    }

    #[test]
    fn random_tree_changes_keep_children_and_subtrees_equal_to_scans() {
        // Nested names, plus spellings the filesystem never stores, so that
        // the index is exact whatever the slots hold.
        let mut pool: Vec<Path> = Vec::new();
        for directory in ["", "/a", "/a/b", "/a/b/c", "/b", "/a/a"] {
            for name in ["a", "b", "c"] {
                pool.push(path(std::format!("{directory}/{name}").as_bytes()));
            }
        }
        for odd in ["/", "", "//a", "/a//b", "/a/", "a", "a/b", "/a/./b"] {
            pool.push(path(odd.as_bytes()));
        }
        for capacity in [1, 2, 4, 9, 24] {
            for seed in 1..=6u64 {
                let mut rng = Rng(seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1);
                let mut names = namespace(capacity);
                for _ in 0..800 {
                    let slot = rng.below(capacity);
                    let name = pool[rng.below(pool.len())];
                    match rng.below(7) {
                        0..=2 => {
                            let state = STATES[1 + rng.below(6)];
                            names.occupy(slot, state, name);
                        }
                        3 if names[slot].state != Slot::Free => {
                            names.set_state(slot, STATES[1 + rng.below(6)]);
                        }
                        4 if names[slot].state != Slot::Free => names.set_path(slot, name),
                        5 => names.vacate(slot),
                        6 if rng.below(80) == 0 => names.vacate_all(),
                        _ => {}
                    }
                    check(&mut names, &pool);
                }
            }
        }
    }
}
