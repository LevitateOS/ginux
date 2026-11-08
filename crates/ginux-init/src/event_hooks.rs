//! Bounded configured event objects. Channels own allocation and IO; descriptor
//! owners supply readiness. No workload pointer or FD is submitted to host epoll.

// Existing owners permit 16 TCP sockets and 16 channel objects together.
// A watch table must cover both without changing either allocation limit.
pub const WATCHES: usize = 32;
pub const EDGE: u32 = 1 << 31;
pub const ONESHOT: u32 = 1 << 30;
pub const ALLOWED_EVENTS: u32 = EDGE | ONESHOT | 0x201d;

#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Key {
    pub handle: u32,
    pub generation: u64,
}

#[derive(Clone, Copy)]
pub struct Watch {
    pub key: Key,
    pub fd: u32,
    pub events: u32,
    pub data: u64,
    pub pending: u32,
    observed: u32,
    armed: bool,
}
impl Watch {
    fn new(key: Key, fd: u32, events: u32, data: u64) -> Self {
        Self {
            key,
            fd,
            events,
            data,
            pending: 0,
            observed: 0,
            armed: true,
        }
    }
    pub fn observe(&mut self, available: u16) {
        let available = u32::from(available);
        let ready = available & (self.events | 8 | 16) & 0x201f;
        if !self.armed {
            self.pending = 0;
        } else if self.events & EDGE != 0 {
            self.pending = (self.pending | (ready & !self.observed)) & ready;
        } else {
            self.pending = ready;
        }
        self.observed = ready;
    }
    fn delivered(&mut self) {
        self.pending = 0;
        if self.events & ONESHOT != 0 {
            self.armed = false;
        }
    }
}

#[derive(Clone, Copy)]
pub struct Epoll {
    pub watches: [Option<Watch>; WATCHES],
    next: usize,
}
impl Epoll {
    pub const fn new() -> Self {
        Self {
            watches: [None; WATCHES],
            next: 0,
        }
    }

    pub fn control(
        &mut self,
        operation: i32,
        key: Key,
        fd: u32,
        events: u32,
        data: u64,
    ) -> Result<(), i64> {
        let existing = self
            .watches
            .iter()
            .position(|watch| watch.is_some_and(|w| w.key == key && w.fd == fd));
        match operation {
            1 => {
                if existing.is_some() {
                    return Err(-17);
                }
                let slot = self.watches.iter().position(Option::is_none).ok_or(-28)?;
                self.watches[slot] = Some(Watch::new(key, fd, events, data));
            }
            2 => {
                self.watches[existing.ok_or(-2)?] = None;
            }
            3 => {
                self.watches[existing.ok_or(-2)?] = Some(Watch::new(key, fd, events, data));
            }
            _ => return Err(-22),
        }
        Ok(())
    }

    pub fn pending(
        &self,
        maximum: usize,
        output: &mut [u8; WATCHES * 12],
        selected: &mut [usize; WATCHES],
    ) -> usize {
        let mut count = 0;
        for offset in 0..WATCHES {
            let index = (self.next + offset) % WATCHES;
            let Some(watch) = self.watches[index].filter(|w| w.pending != 0) else {
                continue;
            };
            output[count * 12..count * 12 + 4].copy_from_slice(&watch.pending.to_ne_bytes());
            output[count * 12 + 4..count * 12 + 12].copy_from_slice(&watch.data.to_ne_bytes());
            selected[count] = index;
            count += 1;
            if count == maximum {
                break;
            }
        }
        count
    }

    pub fn acknowledge(&mut self, selected: &[usize]) {
        for index in selected {
            if let Some(watch) = &mut self.watches[*index] {
                watch.delivered();
            }
            self.next = (index + 1) % WATCHES;
        }
    }
}

#[derive(Clone, Copy)]
pub enum Event {
    None,
    Counter { value: u64, semaphore: bool },
    Epoll,
}
