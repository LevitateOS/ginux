//! Bounded retained backing for the writable domain overlay.
//!
//! Owner: G-storage (G11). The [`VirtualFs`] overlay is RAM-resident and
//! `teardown` wipes it, which was fine for the demo-sized disposable
//! backing (a handful of small files) but loses every workload write on a
//! normal domain stop. This module stages that overlay into a bounded,
//! self-describing byte image and recovers it on reopen, without changing
//! the existing VFS open/read/write/seek/close shape:
//!
//! * [`VirtualFs::checkpoint_retained`] serializes every live overlay slot
//!   (files, created directories, and tombstones for removed base entries,
//!   so a delete stays deleted after reopen) into caller memory.
//! * [`VirtualFs::restore_retained`] validates a staged image fully before
//!   applying anything, then upserts each record into the overlay.
//!
//! The module performs no host I/O and promises no durability: the caller
//! owns where the staged bytes live. Per-instance isolation is enforced in
//! the format itself — every image carries the caller's `instance` id and
//! [`restore_retained`](VirtualFs::restore_retained) rejects an image
//! staged by another instance with [`RetainedError::WrongInstance`], so two
//! instances can never see each other's files even if their staged bytes
//! are swapped. Bounds are enforced on both paths and every exhaustion
//! reports an explicit error; nothing fails silent and nothing truncates.
//!
//! # G12 flush seam
//!
//! Durable publish and recovery belong to G12, which attaches here without
//! touching the format: G12 takes the staged `out[..summary.bytes]` bytes,
//! writes them to the instance's host backing file, and publishes them
//! durably (fsync plus atomic rename). The image header reserves one word
//! for that publish step (see `reserved` below); until G12 lands it must
//! stay zero and staged bytes must be treated as volatile — only a
//! published image may be handed to restore.
//!
//! Image layout (all integers little-endian):
//!
//! ```text
//! header: magic[8] = b"GINUXRT1", instance u64, count u32, reserved u32
//! record: kind u8 (1 = file, 2 = directory, 3 = tombstone),
//!         path_len u16, mode u32, data_len u64,
//!         path[path_len] bytes, data[data_len] bytes (files only)
//! ```
//!
//! Only absolute, already-normalized domain paths (`/work/...`, `/out/...`)
//! round-trip; anything else in an image fails restore explicitly.

use super::{
    is_canonical_path, read_u16, read_u32, read_u64, BaseReader, VfsError, VirtualFs, MAX_PATH,
};

/// Image magic, version 1.
pub const RETAINED_MAGIC: &[u8; 8] = b"GINUXRT1";
/// Staged-image header length: magic 8 + instance 8 + count 4 + reserved 4.
pub const RETAINED_HEADER_LEN: usize = 24;

/// Overlay record kinds in the staged image.
const KIND_FILE: u8 = 1;
const KIND_DIR: u8 = 2;
const KIND_TOMBSTONE: u8 = 3;

/// Per-record header length: kind 1 + path_len 2 + mode 4 + data_len 8.
const RECORD_HEADER_LEN: usize = 15;

/// Bounds for one staged image. Every bound is enforced on both the stage
/// and the recover path; exceeding one fails explicitly, never silently.
/// `max_file_bytes` must not exceed the [`VirtualFs`] `FILE_SIZE` the image
/// is restored into, and `max_files` must fit its free overlay slots —
/// otherwise restore reports [`RetainedError::TooLarge`] or
/// [`RetainedError::NoSpace`] instead of truncating.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RetainedLimits {
    /// Maximum overlay records (files plus directories plus tombstones).
    pub max_files: usize,
    /// Maximum total file-data bytes across the image.
    pub max_bytes: usize,
    /// Maximum data bytes in one file record.
    pub max_file_bytes: usize,
}

impl RetainedLimits {
    /// Workload-sized bounds: larger than the demo 8 × 4 KiB overlay, still
    /// small enough to stage in memory beside the domain.
    pub const fn defaults() -> Self {
        Self {
            max_files: 64,
            max_bytes: 256 * 1024,
            max_file_bytes: 64 * 1024,
        }
    }

    /// Explicit caller-chosen bounds.
    pub const fn bounded(max_files: usize, max_bytes: usize, max_file_bytes: usize) -> Self {
        Self {
            max_files,
            max_bytes,
            max_file_bytes,
        }
    }
}

/// Why staging or recovery failed. Exhaustion variants (`TooManyFiles`,
/// `NoSpace`, `TooLarge`) are the bounded-storage errors: callers map them
/// to `-ENOSPC`/`-EFBIG`, never to silent truncation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedError {
    /// More records than `max_files`.
    TooManyFiles,
    /// Total data past `max_bytes`, or the caller's staging buffer too
    /// small, or no free overlay slot on restore.
    NoSpace,
    /// One file past `max_file_bytes` or past the overlay `FILE_SIZE`.
    TooLarge,
    /// A record path that is not an absolute normalized domain path.
    InvalidPath,
    /// Bad magic, short reads, unknown kinds, or count/length mismatch.
    InvalidRecord,
    /// Image staged by a different instance id.
    WrongInstance,
    /// Base-reader failure while spilling a writable copy.
    Io,
}

impl From<VfsError> for RetainedError {
    /// Index-decode failures read as corrupt images; only a real
    /// backing-store failure reads as [`RetainedError::Io`].
    fn from(error: VfsError) -> Self {
        match error {
            VfsError::Io => RetainedError::Io,
            _ => RetainedError::InvalidRecord,
        }
    }
}

impl RetainedError {
    /// Stable machine-readable name for logs and error propagation.
    pub const fn as_str(self) -> &'static str {
        match self {
            RetainedError::TooManyFiles => "too-many-files",
            RetainedError::NoSpace => "no-space",
            RetainedError::TooLarge => "too-large",
            RetainedError::InvalidPath => "invalid-path",
            RetainedError::InvalidRecord => "invalid-record",
            RetainedError::WrongInstance => "wrong-instance",
            RetainedError::Io => "io",
        }
    }
}

/// What [`VirtualFs::checkpoint_retained`] staged. `bytes` is the exact
/// staged-image length (`out[..bytes]`); G12 publishes exactly those bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct CheckpointSummary {
    /// Staged image length in bytes.
    pub bytes: usize,
    /// Live file records staged.
    pub files: usize,
    /// Created-directory records staged.
    pub dirs: usize,
    /// Tombstone records staged (removals that must survive reopen).
    pub tombstones: usize,
}

/// What [`VirtualFs::restore_retained`] recovered.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RestoreSummary {
    /// File records applied.
    pub files: usize,
    /// Created-directory records applied.
    pub dirs: usize,
    /// Tombstone records applied.
    pub tombstones: usize,
    /// Total file-data bytes applied.
    pub bytes: usize,
}

impl<'a, R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>
    VirtualFs<'a, R, FILES, FILE_SIZE, FDS>
{
    /// Stage every live overlay slot into `out`, returning the staged
    /// summary. `instance` tags the image for the
    /// [`RetainedError::WrongInstance`] isolation check on restore.
    /// Fails explicitly (writing nothing observable) when the records
    /// exceed `limits` or `out` is too small.
    pub fn checkpoint_retained(
        &self,
        instance: u64,
        limits: &RetainedLimits,
        out: &mut [u8],
    ) -> Result<CheckpointSummary, RetainedError> {
        let mut files = 0usize;
        let mut dirs = 0usize;
        let mut tombstones = 0usize;
        let mut data_total = 0usize;
        let mut needed = RETAINED_HEADER_LEN;
        for slot in &self.overlay {
            match slot.state {
                1 => {
                    if slot.len > limits.max_file_bytes {
                        return Err(RetainedError::TooLarge);
                    }
                    data_total = data_total
                        .checked_add(slot.len)
                        .ok_or(RetainedError::NoSpace)?;
                    if data_total > limits.max_bytes {
                        return Err(RetainedError::NoSpace);
                    }
                    files += 1;
                    needed = needed
                        .checked_add(RECORD_HEADER_LEN + slot.path.len + slot.len)
                        .ok_or(RetainedError::NoSpace)?;
                }
                2 => {
                    tombstones += 1;
                    needed = needed
                        .checked_add(RECORD_HEADER_LEN + slot.path.len)
                        .ok_or(RetainedError::NoSpace)?;
                }
                3 => {
                    dirs += 1;
                    needed = needed
                        .checked_add(RECORD_HEADER_LEN + slot.path.len)
                        .ok_or(RetainedError::NoSpace)?;
                }
                _ => {}
            }
        }
        let count = files + dirs + tombstones;
        if count > limits.max_files {
            return Err(RetainedError::TooManyFiles);
        }
        if needed > out.len() {
            return Err(RetainedError::NoSpace);
        }
        out[..8].copy_from_slice(RETAINED_MAGIC);
        write_u64(out, 8, instance);
        write_u32(out, 16, count as u32);
        // Reserved for the G12 publish generation; must stay zero here.
        write_u32(out, 20, 0);
        let mut cursor = RETAINED_HEADER_LEN;
        for slot in &self.overlay {
            let kind = match slot.state {
                1 => KIND_FILE,
                2 => KIND_TOMBSTONE,
                3 => KIND_DIR,
                _ => continue,
            };
            out[cursor] = kind;
            write_u16(out, cursor + 1, slot.path.len as u16);
            write_u32(
                out,
                cursor + 3,
                if kind == KIND_TOMBSTONE { 0 } else { slot.mode },
            );
            let data_len = if kind == KIND_FILE { slot.len } else { 0 };
            write_u64(out, cursor + 7, data_len as u64);
            cursor += RECORD_HEADER_LEN;
            out[cursor..cursor + slot.path.len].copy_from_slice(slot.path.as_bytes());
            cursor += slot.path.len;
            if kind == KIND_FILE {
                out[cursor..cursor + slot.len].copy_from_slice(&slot.data[..slot.len]);
                cursor += slot.len;
            }
        }
        Ok(CheckpointSummary {
            bytes: needed,
            files,
            dirs,
            tombstones,
        })
    }

    /// Recover a staged image: validate it fully, then upsert every record
    /// into the overlay. `instance` must match the staging call or the
    /// image is rejected before anything is applied. Either the whole
    /// image applies or an explicit error is returned.
    pub fn restore_retained(
        &mut self,
        instance: u64,
        limits: &RetainedLimits,
        image: &[u8],
    ) -> Result<RestoreSummary, RetainedError> {
        let count = self.validate_retained(instance, limits, image)? as usize;
        let mut cursor = RETAINED_HEADER_LEN;
        let mut summary = RestoreSummary {
            files: 0,
            dirs: 0,
            tombstones: 0,
            bytes: 0,
        };
        for _ in 0..count {
            let kind = image[cursor];
            let path_len = read_u16(image, cursor + 1)? as usize;
            let mode = read_u32(image, cursor + 3)?;
            let data_len = read_u64(image, cursor + 7)? as usize;
            cursor += RECORD_HEADER_LEN;
            let path = image
                .get(cursor..cursor + path_len)
                .ok_or(RetainedError::InvalidRecord)?;
            cursor += path_len;
            let data = image
                .get(cursor..cursor + data_len)
                .ok_or(RetainedError::InvalidRecord)?;
            cursor += data_len;
            // Shape, paths, and limits were validated in the pre-pass, so
            // these slices and the slot lookup below cannot fail the checks.
            match kind {
                KIND_FILE => {
                    let slot = self.retained_slot(path)?;
                    let target = &mut self.overlay[slot];
                    set_slot_path(target, path);
                    target.state = 1;
                    target.mode = mode;
                    target.data[..data_len].copy_from_slice(data);
                    target.len = data_len;
                    summary.files += 1;
                    summary.bytes += data_len;
                }
                KIND_DIR => {
                    let slot = self.retained_slot(path)?;
                    let target = &mut self.overlay[slot];
                    set_slot_path(target, path);
                    target.state = 3;
                    target.mode = mode;
                    target.len = 0;
                    summary.dirs += 1;
                }
                KIND_TOMBSTONE => {
                    let slot = self.retained_slot(path)?;
                    let target = &mut self.overlay[slot];
                    set_slot_path(target, path);
                    target.state = 2;
                    target.len = 0;
                    summary.tombstones += 1;
                }
                _ => return Err(RetainedError::InvalidRecord),
            }
        }
        Ok(summary)
    }

    /// Validate `image` end to end without mutating the overlay: header,
    /// instance, per-record shape, paths, and limits. Returns the record
    /// count for the apply pass.
    fn validate_retained(
        &self,
        instance: u64,
        limits: &RetainedLimits,
        image: &[u8],
    ) -> Result<u32, RetainedError> {
        if image.len() < RETAINED_HEADER_LEN || &image[..8] != RETAINED_MAGIC {
            return Err(RetainedError::InvalidRecord);
        }
        if read_u64(image, 8)? != instance {
            return Err(RetainedError::WrongInstance);
        }
        let count = read_u32(image, 16)?;
        if image[20..24] != [0, 0, 0, 0] {
            // The G12 publish generation owns this word; a nonzero value
            // is not a G11 staged image.
            return Err(RetainedError::InvalidRecord);
        }
        if count as usize > limits.max_files {
            return Err(RetainedError::TooManyFiles);
        }
        let mut cursor = RETAINED_HEADER_LEN;
        let mut data_total = 0usize;
        for _ in 0..count {
            let tail = image
                .len()
                .checked_sub(cursor)
                .ok_or(RetainedError::InvalidRecord)?;
            if tail < RECORD_HEADER_LEN {
                return Err(RetainedError::InvalidRecord);
            }
            let kind = image[cursor];
            if kind != KIND_FILE && kind != KIND_DIR && kind != KIND_TOMBSTONE {
                return Err(RetainedError::InvalidRecord);
            }
            let path_len = read_u16(image, cursor + 1)? as usize;
            let data_len = read_u64(image, cursor + 7)? as usize;
            if path_len == 0 || path_len > MAX_PATH {
                return Err(RetainedError::InvalidPath);
            }
            if kind != KIND_FILE && data_len != 0 {
                return Err(RetainedError::InvalidRecord);
            }
            if data_len > limits.max_file_bytes || data_len > FILE_SIZE {
                return Err(RetainedError::TooLarge);
            }
            data_total = data_total
                .checked_add(data_len)
                .ok_or(RetainedError::NoSpace)?;
            if data_total > limits.max_bytes {
                return Err(RetainedError::NoSpace);
            }
            cursor += RECORD_HEADER_LEN;
            let path = image
                .get(cursor..cursor + path_len)
                .ok_or(RetainedError::InvalidRecord)?;
            // Absolute, NUL-free, and already normalized: untrusted images
            // must name exactly the record they mean.
            if !is_canonical_path(path) {
                return Err(RetainedError::InvalidPath);
            }
            cursor += path_len;
            if image
                .len()
                .checked_sub(cursor)
                .ok_or(RetainedError::InvalidRecord)?
                < data_len
            {
                return Err(RetainedError::InvalidRecord);
            }
            cursor += data_len;
        }
        if cursor != image.len() {
            return Err(RetainedError::InvalidRecord);
        }
        Ok(count)
    }

    /// Overlay slot for `path` on restore: reuse the live slot or take a
    /// free one. Exhaustion is explicit; callers size `FILES` for their
    /// retained working set.
    fn retained_slot(&mut self, path: &[u8]) -> Result<usize, RetainedError> {
        if let Some(index) = self.find_overlay(path) {
            return Ok(index);
        }
        self.allocate_overlay().map_err(|_| RetainedError::NoSpace)
    }
}

/// Name an overlay slot during restore. The validation pre-pass already
/// proved `path` fits `MAX_PATH`; the assertion pins that contract.
fn set_slot_path<const FILE_SIZE: usize>(slot: &mut super::OverlayFile<FILE_SIZE>, path: &[u8]) {
    debug_assert!(path.len() <= super::MAX_PATH);
    slot.path.len = path.len();
    slot.path.bytes[..path.len()].copy_from_slice(path);
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
