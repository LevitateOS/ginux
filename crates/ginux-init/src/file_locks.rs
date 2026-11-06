//! Bounded POSIX byte-range locks on supervisor-owned inode identities.
//! Owners are virtual processes; forks do not inherit record locks.

const LIMIT: usize = 64;
const END: u64 = i64::MAX as u64 + 1;
#[derive(Clone, Copy)]
pub struct Range {
    pub start: u64,
    pub end: u64,
}
impl Range {
    pub fn new(base: u64, start: i64, length: i64) -> Result<Self, i64> {
        let first = base as i128 + start as i128;
        let (start, end) = if length < 0 {
            (first + length as i128, first)
        } else {
            (
                first,
                if length == 0 {
                    END as i128
                } else {
                    first + length as i128
                },
            )
        };
        if start < 0 || start >= END as i128 || end <= start || end > END as i128 {
            return Err(-22);
        }
        Ok(Self {
            start: start as u64,
            end: end as u64,
        })
    }
    fn overlaps(self, other: Self) -> bool {
        self.start < other.end && other.start < self.end
    }
}
#[derive(Clone, Copy)]
pub struct Lock {
    pub inode: u64,
    pub owner: u32,
    pub range: Range,
    pub write: bool,
}
pub struct Locks {
    entries: [Option<Lock>; LIMIT],
}
impl Locks {
    pub const fn new() -> Self {
        Self {
            entries: [None; LIMIT],
        }
    }
    pub fn conflict(&self, lock: Lock) -> Option<Lock> {
        self.entries.iter().flatten().copied().find(|entry| {
            entry.inode == lock.inode
                && entry.owner != lock.owner
                && (entry.write || lock.write)
                && entry.range.overlaps(lock.range)
        })
    }
    pub fn release(&mut self, owner: u32, inode: Option<u64>) {
        for entry in &mut self.entries {
            if entry.is_some_and(|e| e.owner == owner && inode.is_none_or(|i| e.inode == i)) {
                *entry = None;
            }
        }
    }
    pub fn set(&mut self, lock: Lock, unlock: bool) -> Result<(), i64> {
        if !unlock && self.conflict(lock).is_some() {
            return Err(-11);
        }
        // Build the replacement before committing: splitting a range must not
        // partially unlock the file when the bounded table is exhausted.
        let mut next = Self::new();
        for old in self.entries.iter().flatten().copied() {
            if old.owner != lock.owner || old.inode != lock.inode || !old.range.overlaps(lock.range)
            {
                next.insert(old)?;
            } else {
                if old.range.start < lock.range.start {
                    next.insert(Lock {
                        range: Range {
                            start: old.range.start,
                            end: lock.range.start,
                        },
                        ..old
                    })?;
                }
                if old.range.end > lock.range.end {
                    next.insert(Lock {
                        range: Range {
                            start: lock.range.end,
                            end: old.range.end,
                        },
                        ..old
                    })?;
                }
            }
        }
        if !unlock {
            next.insert(lock)?;
        }
        *self = next;
        Ok(())
    }
    fn insert(&mut self, mut lock: Lock) -> Result<(), i64> {
        // Coalesce adjacent ranges of one kind, including both sides of a hole.
        loop {
            let found = self.entries.iter().position(|entry| {
                entry.is_some_and(|e| {
                    e.owner == lock.owner
                        && e.inode == lock.inode
                        && e.write == lock.write
                        && e.range.start <= lock.range.end
                        && lock.range.start <= e.range.end
                })
            });
            let Some(index) = found else { break };
            let old = self.entries[index].take().unwrap();
            lock.range.start = lock.range.start.min(old.range.start);
            lock.range.end = lock.range.end.max(old.range.end);
        }
        *self
            .entries
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or(-37)? = Some(lock);
        Ok(())
    }
}
