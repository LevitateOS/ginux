//! Supervisor-owned anonymous overlay bytes. No host file or mapping handle is
//! installed in a tracee. Capacity is charged across all live overlay objects.

use crate::supervisor::{syscall2, syscall5, syscall6};
use ginux_vfs::{OverlayStorage, VfsError};

const PAGE: usize = 4096;

#[derive(Clone, Copy)]
struct Mapping {
    address: usize,
    capacity: usize,
}

pub struct MemoryStorage<const FILES: usize> {
    files: [Mapping; FILES],
    limit: usize,
    allocated: usize,
}

impl<const FILES: usize> MemoryStorage<FILES> {
    pub const fn new(limit: usize) -> Self {
        Self {
            files: [Mapping {
                address: 0,
                capacity: 0,
            }; FILES],
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

    fn grow(&mut self, slot: usize, length: usize) -> Result<(), VfsError> {
        let file = self.files[slot];
        if length <= file.capacity {
            return Ok(());
        }
        let needed = Self::pages(length)?;
        let available = self.limit - self.allocated + file.capacity;
        if needed > available {
            return Err(VfsError::OverlayLimit);
        }
        let capacity = needed.max(file.capacity.saturating_mul(2)).min(available) & !(PAGE - 1);
        let address = unsafe {
            if file.capacity == 0 {
                syscall6(9, 0, capacity, 3, 0x22, usize::MAX, 0)
            } else {
                syscall5(25, file.address, file.capacity, capacity, 1, 0) // MREMAP_MAYMOVE
            }
        };
        if address < 0 {
            // A failed anonymous allocation/remap leaves the old object intact.
            return Err(VfsError::OverlayLimit);
        }
        self.files[slot] = Mapping {
            address: address as usize,
            capacity,
        };
        self.allocated += capacity - file.capacity;
        Ok(())
    }
}

impl<const FILES: usize> OverlayStorage for MemoryStorage<FILES> {
    fn resize(&mut self, slot: usize, old_len: usize, new_len: usize) -> Result<(), VfsError> {
        let previous = self.files[slot];
        if old_len > previous.capacity {
            return Err(VfsError::Io);
        }
        if new_len == 0 {
            self.clear(slot);
            return Ok(());
        }
        self.grow(slot, new_len)?;
        let file = self.files[slot];
        if new_len > old_len {
            // New anonymous pages are already zero. Only reused capacity can
            // contain bytes hidden by an earlier truncate; zero that range.
            let end = new_len.min(previous.capacity);
            if end > old_len {
                unsafe {
                    core::ptr::write_bytes((file.address + old_len) as *mut u8, 0, end - old_len);
                }
            }
        } else if new_len < old_len {
            let capacity = Self::pages(new_len)?;
            if capacity < file.capacity {
                let result =
                    unsafe { syscall2(11, file.address + capacity, file.capacity - capacity) };
                assert_eq!(result, 0, "overlay shrink unmap failed");
                self.files[slot].capacity = capacity;
                self.allocated -= file.capacity - capacity;
            }
        }
        Ok(())
    }

    fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<(), VfsError> {
        let file = self.files[slot];
        let end = offset
            .checked_add(output.len())
            .ok_or(VfsError::FileTooLarge)?;
        if end > file.capacity {
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
        if end > file.capacity {
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
        let file = self.files[slot];
        if file.capacity != 0 {
            let result = unsafe { syscall2(11, file.address, file.capacity) };
            assert_eq!(result, 0, "overlay release unmap failed");
            self.allocated -= file.capacity;
            self.files[slot] = Mapping {
                address: 0,
                capacity: 0,
            };
        }
    }
}
