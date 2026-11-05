//! Supervisor-owned anonymous file backing. Capacity is charged across live
//! overlay objects; no pathname or writable host descriptor is exported.
//! Memfd identity keeps private mappings coherent with mediated writes/truncate.

use crate::supervisor::{syscall1, syscall2, syscall6};
use ginux_vfs::{OverlayStorage, VfsError};

const PAGE: usize = 4096;

#[derive(Clone, Copy)]
struct Mapping {
    address: usize,
    capacity: usize,
    length: usize,
    descriptor: i32,
}
impl Mapping {
    const EMPTY: Self = Self {
        address: 0,
        capacity: 0,
        length: 0,
        descriptor: -1,
    };
}

pub struct MemoryStorage<const FILES: usize> {
    files: [Mapping; FILES],
    limit: usize,
    allocated: usize,
}

impl<const FILES: usize> MemoryStorage<FILES> {
    pub const fn new(limit: usize) -> Self {
        Self {
            files: [Mapping::EMPTY; FILES],
            limit,
            allocated: 0,
        }
    }
    pub fn allocated_bytes(&self) -> usize {
        self.allocated
    }

    fn pages(length: usize) -> Result<usize, VfsError> {
        length
            .checked_add(PAGE - 1)
            .map(|n| n & !(PAGE - 1))
            .ok_or(VfsError::FileTooLarge)
    }

    /// The returned descriptor remains supervisor-owned. Consumers must obtain
    /// their own reference before the overlay object can be released.
    pub fn backing(&mut self, slot: usize) -> Result<i32, VfsError> {
        let file = self
            .files
            .get_mut(slot)
            .ok_or(VfsError::InvalidDescriptor)?;
        if file.descriptor < 0 {
            let fd = unsafe { syscall2(319, c"ginux-storage".as_ptr() as usize, 1) };
            if fd < 0 {
                return Err(VfsError::Io);
            }
            file.descriptor = fd as i32;
        }
        Ok(file.descriptor)
    }
}

impl<const FILES: usize> OverlayStorage for MemoryStorage<FILES> {
    fn resize(&mut self, slot: usize, old_len: usize, new_len: usize) -> Result<(), VfsError> {
        let old = self.files[slot];
        if old_len != old.length {
            return Err(VfsError::Io);
        }
        let needed = Self::pages(new_len)?;
        let available = self.limit - self.allocated + old.capacity;
        if needed > available {
            return Err(VfsError::OverlayLimit);
        }
        if old_len == new_len {
            return Ok(());
        }
        let capacity = if new_len < old_len {
            needed
        } else if needed <= old.capacity {
            old.capacity
        } else {
            needed.max(old.capacity.saturating_mul(2)).min(available) & !(PAGE - 1)
        };
        let fd = self.backing(slot)?;
        let changed = capacity != old.capacity;
        // Establish a replacement address first. A failed map or truncate
        // preserves the old file bytes, address and charged capacity.
        let address = if changed && capacity != 0 {
            let mapped = unsafe { syscall6(9, 0, capacity, 3, 1, fd as usize, 0) };
            if mapped < 0 {
                return Err(VfsError::OverlayLimit);
            }
            mapped as usize
        } else if changed {
            0
        } else {
            old.address
        };
        let result = unsafe { syscall2(77, fd as usize, new_len) };
        if result < 0 {
            if changed && capacity != 0 {
                unsafe {
                    syscall2(11, address, capacity);
                }
            }
            return Err(VfsError::Io);
        }
        if changed && old.capacity != 0 {
            let result = unsafe { syscall2(11, old.address, old.capacity) };
            assert_eq!(result, 0, "overlay replacement unmap failed");
        }
        self.files[slot] = Mapping {
            address,
            capacity,
            length: new_len,
            descriptor: fd,
        };
        self.allocated = self.allocated - old.capacity + capacity;
        Ok(())
    }

    fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<(), VfsError> {
        let file = self.files[slot];
        let end = offset
            .checked_add(output.len())
            .ok_or(VfsError::FileTooLarge)?;
        if end > file.length {
            return Err(VfsError::Io);
        }
        if !output.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    (file.address + offset) as *const u8,
                    output.as_mut_ptr(),
                    output.len(),
                );
            }
        }
        Ok(())
    }

    fn write(&mut self, slot: usize, offset: usize, input: &[u8]) -> Result<(), VfsError> {
        let file = self.files[slot];
        let end = offset
            .checked_add(input.len())
            .ok_or(VfsError::FileTooLarge)?;
        if end > file.length {
            return Err(VfsError::Io);
        }
        if !input.is_empty() {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    input.as_ptr(),
                    (file.address + offset) as *mut u8,
                    input.len(),
                );
            }
        }
        Ok(())
    }

    fn clear(&mut self, slot: usize) {
        let file = core::mem::replace(&mut self.files[slot], Mapping::EMPTY);
        if file.capacity != 0 {
            let result = unsafe { syscall2(11, file.address, file.capacity) };
            assert_eq!(result, 0, "overlay release unmap failed");
            self.allocated -= file.capacity;
        }
        if file.descriptor >= 0 {
            let result = unsafe { syscall1(3, file.descriptor as usize) };
            assert_eq!(result, 0, "overlay backing close failed");
        }
    }
}
