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

/// Supervisor allocation with an explicit capacity and a small stack footprint.
/// Every element is initialized before slices are formed; Drop returns pages.
pub struct MappedArray<T: Copy> {
    address: *mut T,
    length: usize,
    bytes: usize,
}
impl<T: Copy> MappedArray<T> {
    pub fn new(length: usize, initial: T) -> Result<Self, VfsError> {
        let bytes = Self::bytes_for(length)?;
        let address = unsafe { syscall6(9, 0, bytes, 3, 0x22, usize::MAX, 0) };
        if address < 0 {
            return Err(VfsError::OverlayLimit);
        }
        let address = address as *mut T;
        for index in 0..length {
            unsafe {
                address.add(index).write(initial);
            }
        }
        Ok(Self {
            address,
            length,
            bytes,
        })
    }
    pub fn bytes_for(length: usize) -> Result<usize, VfsError> {
        if core::mem::align_of::<T>() > PAGE {
            return Err(VfsError::OverlayLimit);
        }
        length
            .checked_mul(core::mem::size_of::<T>())
            .and_then(|n| n.checked_add(PAGE - 1))
            .map(|n| n & !(PAGE - 1))
            .filter(|n| *n != 0 && *n <= isize::MAX as usize)
            .ok_or(VfsError::OverlayLimit)
    }
}
impl<T: Copy> core::ops::Deref for MappedArray<T> {
    type Target = [T];
    fn deref(&self) -> &[T] {
        unsafe { core::slice::from_raw_parts(self.address, self.length) }
    }
}
impl<T: Copy> core::ops::DerefMut for MappedArray<T> {
    fn deref_mut(&mut self) -> &mut [T] {
        unsafe { core::slice::from_raw_parts_mut(self.address, self.length) }
    }
}
impl<T: Copy> Drop for MappedArray<T> {
    fn drop(&mut self) {
        assert_eq!(
            unsafe { syscall2(11, self.address as usize, self.bytes) },
            0
        );
    }
}

pub struct MemoryStorage {
    files: MappedArray<Mapping>,
    limit: usize,
    allocated: usize,
    close_failed: bool,
}

impl MemoryStorage {
    pub fn metadata_bytes(objects: usize) -> Result<usize, VfsError> {
        MappedArray::<Mapping>::bytes_for(objects)
    }
    pub fn new(limit: usize, objects: usize) -> Result<Self, VfsError> {
        Ok(Self {
            files: MappedArray::new(objects, Mapping::EMPTY)?,
            limit,
            allocated: 0,
            close_failed: false,
        })
    }
    pub fn cleanup_error(&self) -> Option<&'static [u8]> {
        self.close_failed
            .then_some(b"overlay backing close failed".as_slice())
    }

    pub fn allocated_bytes(&self) -> usize {
        self.allocated
    }

    pub fn sync(&mut self, slot: usize, data_only: bool) -> Result<(), VfsError> {
        let descriptor = self.backing(slot)?;
        if unsafe { syscall1(if data_only { 75 } else { 74 }, descriptor as usize) } != 0 {
            return Err(VfsError::Io);
        }
        Ok(())
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

impl OverlayStorage for MemoryStorage {
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
                // A mapped writer in another process may change these bytes.
                for (n, byte) in output.iter_mut().enumerate() {
                    *byte = core::ptr::read_volatile((file.address + offset + n) as *const u8);
                }
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
                for (n, byte) in input.iter().enumerate() {
                    core::ptr::write_volatile((file.address + offset + n) as *mut u8, *byte);
                }
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
            // Linux retires the FD before reporting late close errors. Never
            // retry a numeric FD that may already refer to another resource.
            // The supervisor checks this sticky error before guest resume and
            // after teardown, producing a completion record instead of panic.
            self.close_failed |= result != 0;
        }
    }
}
