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
//! * [`VirtualFs::restore_retained`] validates a published image fully before
//!   applying anything, then upserts each record into the overlay.
//!
//! The module performs no host I/O and promises no durability by itself:
//! the caller owns where the staged bytes live and supplies the host
//! behavior through [`DurableStore`]. Per-instance isolation is enforced in
//! the format itself — every image carries the caller's `instance` id and
//! restore rejects an image staged by another instance with
//! [`RetainedError::WrongInstance`], so two instances can never see each
//! other's files even if their staged bytes are swapped. Bounds are enforced
//! on both paths and every exhaustion reports an explicit error; nothing
//! fails silent and nothing truncates.
//!
//! # Durable flush (G12)
//!
//! Staged bytes are volatile until a flush publishes them.
//! [`VirtualFs::flush_retained`] stages the live overlay, stamps the next
//! durable generation into the header word at bytes 20–24 (see `generation`
//! below), writes the staged `out[..summary.bytes]` to the caller-provided
//! temp path, fsyncs the temp file, atomically renames it onto the
//! caller-provided final (per-instance) path, and fsyncs the parent
//! directory — all through the caller-provided [`DurableStore`], so this
//! module claims no host-path authority and invents no host paths. Any host
//! failure before the rename leaves the previous published image untouched,
//! and every phase maps to an explicit [`FlushError`]; a failed flush is
//! never reported as durable.
//!
//! [`VirtualFs::recover_retained`] (like [`restore_retained`](VirtualFs::restore_retained))
//! only ever reads published images: a zero generation (volatile staged
//! bytes that never completed a flush) or a torn image fails validation
//! explicitly and applies nothing.
//!
//! Image layout (all integers little-endian):
//!
//! ```text
//! header: magic[8] = b"GINUXRT1", instance u64, count u32, generation u32
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
/// Staged-image header length: magic 8 + instance 8 + count 4 + generation 4.
pub const RETAINED_HEADER_LEN: usize = 24;
/// Header offset of the durable generation counter (the G11 `reserved` word,
/// claimed by G12: every completed flush stamps the next generation here).
pub const RETAINED_GENERATION_OFFSET: usize = 20;
/// First durable generation. Zero means "staged but never published" and is
/// rejected by restore; a flush with no previous image stamps this.
pub const RETAINED_FIRST_GENERATION: u32 = 1;

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
    /// Bad magic, short reads, unknown kinds, count/length mismatch, or an
    /// unpublished (zero-generation) image handed to restore.
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

/// Why a durable flush or recovery failed. Every phase of the
/// write-temp/fsync/rename/dir-sync sequence reports its own variant, and
/// validation failures carry the underlying [`RetainedError`], so a caller
/// can tell "nothing was published" from "the previous image is untouched"
/// from "the published bytes are torn" without guessing. A failed flush is
/// never reported as durable: the previous published image (if any) is left
/// in place and recovery keeps rejecting torn bytes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FlushError {
    /// Staging the live overlay failed (bounds or shape); nothing reached
    /// the store. Carries the checkpoint failure.
    Stage(RetainedError),
    /// The previously published image has a torn header or belongs to
    /// another instance, so the next generation is unknowable; nothing was
    /// published. Delete the published file to restart at
    /// [`RETAINED_FIRST_GENERATION`].
    Existing(RetainedError),
    /// The temp image could not be written (including a temp path identical
    /// to the final path, which would bypass the atomic rename); the
    /// previous published image is untouched.
    Write,
    /// The temp file could not be fsync'd; its bytes are not durable and the
    /// previous published image is untouched.
    Sync,
    /// The atomic rename failed; the previous published image is untouched.
    Rename,
    /// The containing directory could not be fsync'd after the rename; the
    /// new image is in place but may not survive a crash, so the flush is
    /// reported as not durable and the caller must retry.
    DirSync,
    /// The published image could not be read back (or the store reported a
    /// length past the end of the caller's buffer).
    Read,
    /// Recovery found no published image: nothing ever completed a flush.
    Missing,
    /// The published bytes failed validation (torn write, foreign instance,
    /// or volatile staged bytes that never completed a flush); nothing was
    /// applied. Carries the validation failure.
    Invalid(RetainedError),
    /// The published generation already saturates `u32`; refusing to wrap
    /// back to the reserved zero. Delete the published file to restart at
    /// [`RETAINED_FIRST_GENERATION`].
    GenerationOverflow,
}

impl FlushError {
    /// Stable machine-readable name for logs and error propagation. Wrapper
    /// variants name the flush phase; the inner [`RetainedError::as_str`]
    /// names the validation failure.
    pub const fn as_str(self) -> &'static str {
        match self {
            FlushError::Stage(_) => "stage",
            FlushError::Existing(_) => "existing",
            FlushError::Write => "write",
            FlushError::Sync => "sync",
            FlushError::Rename => "rename",
            FlushError::DirSync => "dir-sync",
            FlushError::Read => "read",
            FlushError::Missing => "missing",
            FlushError::Invalid(_) => "invalid",
            FlushError::GenerationOverflow => "generation-overflow",
        }
    }
}

/// Caller-provided host backing for one per-instance published image: the
/// host-side publish hook the supervisor calls (kept pure — it only moves
/// caller-provided bytes between caller-provided paths).
///
/// The orchestrator ([`VirtualFs::flush_retained`]) passes only these
/// caller-provided paths through and never invents host paths: `temp_path`
/// must sit beside `final_path` on the same filesystem so the rename is
/// atomic. After a crash the final path holds either the previous or the
/// new complete image, never a mix; a torn temp file is simply never
/// renamed. `final_path` names the per-instance image, so two instances
/// never share one.
pub trait DurableStore {
    /// Host failure type. The orchestrator reports the failed phase through
    /// [`FlushError`]; log the value on the host side before returning it.
    type Error;
    /// Replace `temp_path` with exactly `bytes` (create or truncate; a
    /// leftover temp file from a crashed flush is superseded, not resumed).
    fn write_temp(&mut self, temp_path: &[u8], bytes: &[u8]) -> Result<(), Self::Error>;
    /// Persist `temp_path` contents (fsync the file) before the rename.
    fn sync_temp(&mut self, temp_path: &[u8]) -> Result<(), Self::Error>;
    /// Atomically move `temp_path` onto `final_path`.
    fn rename_temp(&mut self, temp_path: &[u8], final_path: &[u8]) -> Result<(), Self::Error>;
    /// Persist the rename (fsync the directory containing `final_path`).
    fn sync_parent(&mut self, final_path: &[u8]) -> Result<(), Self::Error>;
    /// Read the whole published image into `out`, or `Ok(None)` when
    /// nothing was ever published. A real I/O failure — or a length past
    /// the end of `out` (size the buffer from [`RetainedLimits`]) — is
    /// `Err`.
    fn read_published(
        &mut self,
        final_path: &[u8],
        out: &mut [u8],
    ) -> Result<Option<usize>, Self::Error>;
}

/// Durable generation stamped in `image` (header bytes 20–24), without
/// checking which instance staged it. [`RetainedError::InvalidRecord`] when
/// the header is short or the magic mismatches.
pub fn durable_generation(image: &[u8]) -> Result<u32, RetainedError> {
    if image.len() < RETAINED_HEADER_LEN || &image[..8] != RETAINED_MAGIC {
        return Err(RetainedError::InvalidRecord);
    }
    read_u32(image, RETAINED_GENERATION_OFFSET).map_err(|_| RetainedError::InvalidRecord)
}

/// Stamp `generation` into a freshly staged image before publish. The image
/// must carry the volatile zero marker left by
/// [`VirtualFs::checkpoint_retained`] — restamping an already-published
/// image, stamping zero, or a short/bad-magic header fails with
/// [`RetainedError::InvalidRecord`].
pub fn stamp_generation(image: &mut [u8], generation: u32) -> Result<(), RetainedError> {
    if image.len() < RETAINED_HEADER_LEN || &image[..8] != RETAINED_MAGIC {
        return Err(RetainedError::InvalidRecord);
    }
    if generation == 0 || image[RETAINED_GENERATION_OFFSET..RETAINED_HEADER_LEN] != [0, 0, 0, 0] {
        return Err(RetainedError::InvalidRecord);
    }
    write_u32(image, RETAINED_GENERATION_OFFSET, generation);
    Ok(())
}

/// What a completed [`VirtualFs::flush_retained`](VirtualFs::flush_retained)
/// published. `bytes` is the exact published-image length; `generation` is
/// the durable counter stamped into header bytes 20–24.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FlushSummary {
    /// Published image length in bytes.
    pub bytes: usize,
    /// Live file records published.
    pub files: usize,
    /// Created-directory records published.
    pub dirs: usize,
    /// Tombstone records published (removals that survive reopen).
    pub tombstones: usize,
    /// Durable generation stamped by this flush.
    pub generation: u32,
}

/// What [`VirtualFs::recover_retained`](VirtualFs::recover_retained)
/// recovered from the published image.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct RecoverSummary {
    /// File records applied.
    pub files: usize,
    /// Created-directory records applied.
    pub dirs: usize,
    /// Tombstone records applied.
    pub tombstones: usize,
    /// Total file-data bytes applied.
    pub bytes: usize,
    /// Durable generation of the recovered image.
    pub generation: u32,
}

/// What [`VirtualFs::checkpoint_retained`] staged. `bytes` is the exact
/// staged-image length (`out[..bytes]`); a flush publishes exactly those
/// bytes after stamping the durable generation.
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
        // Volatile staging marker: zero until a flush stamps the durable
        // generation (see `stamp_generation`).
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

    /// Flush the live overlay durably: stage it into `scratch`, stamp the
    /// next durable generation (one past the currently published image, or
    /// [`RETAINED_FIRST_GENERATION`] when nothing was ever published), and
    /// publish `scratch[..bytes]` through `store` as write-temp, fsync,
    /// atomic rename onto `final_path`, then parent-dir sync. `temp_path`
    /// and `final_path` are caller-provided (the temp file must sit beside
    /// the final image on the same filesystem); they must differ.
    /// `scratch` doubles as the read-back buffer for the current header, so
    /// it must also fit the largest publishable image (size it from
    /// `limits`). Any host failure before the rename leaves the previous
    /// published image untouched, and every failure — staging, existing
    /// header, or host phase — reports an explicit [`FlushError`], never a
    /// durable claim.
    pub fn flush_retained<S: DurableStore>(
        &self,
        instance: u64,
        limits: &RetainedLimits,
        store: &mut S,
        temp_path: &[u8],
        final_path: &[u8],
        scratch: &mut [u8],
    ) -> Result<FlushSummary, FlushError> {
        if temp_path == final_path {
            return Err(FlushError::Write);
        }
        let next = match store
            .read_published(final_path, scratch)
            .map_err(|_| FlushError::Read)?
        {
            None => RETAINED_FIRST_GENERATION,
            Some(len) => {
                let header = scratch.get(..len).ok_or(FlushError::Read)?;
                let current = published_header(header, instance).map_err(FlushError::Existing)?;
                if current == 0 {
                    // A zero generation at the publish path is volatile
                    // staged bytes that never completed a flush, not a
                    // durable image to advance.
                    return Err(FlushError::Existing(RetainedError::InvalidRecord));
                }
                if current == u32::MAX {
                    return Err(FlushError::GenerationOverflow);
                }
                current + 1
            }
        };
        let summary = self
            .checkpoint_retained(instance, limits, scratch)
            .map_err(FlushError::Stage)?;
        let staged = scratch
            .get_mut(..summary.bytes)
            .ok_or(FlushError::Stage(RetainedError::NoSpace))?;
        stamp_generation(staged, next).map_err(FlushError::Stage)?;
        store
            .write_temp(temp_path, staged)
            .map_err(|_| FlushError::Write)?;
        store.sync_temp(temp_path).map_err(|_| FlushError::Sync)?;
        store
            .rename_temp(temp_path, final_path)
            .map_err(|_| FlushError::Rename)?;
        store
            .sync_parent(final_path)
            .map_err(|_| FlushError::DirSync)?;
        Ok(FlushSummary {
            bytes: summary.bytes,
            files: summary.files,
            dirs: summary.dirs,
            tombstones: summary.tombstones,
            generation: next,
        })
    }

    /// Recover the published image: read it back through `store` into
    /// `scratch`, validate it fully (published generation, instance,
    /// shape, paths, limits), then upsert every record into the overlay.
    /// Only G12-published images restore — a missing image reports
    /// [`FlushError::Missing`], and torn bytes or volatile staged bytes
    /// report [`FlushError::Invalid`] with nothing applied.
    pub fn recover_retained<S: DurableStore>(
        &mut self,
        instance: u64,
        limits: &RetainedLimits,
        store: &mut S,
        final_path: &[u8],
        scratch: &mut [u8],
    ) -> Result<RecoverSummary, FlushError> {
        let len = store
            .read_published(final_path, scratch)
            .map_err(|_| FlushError::Read)?
            .ok_or(FlushError::Missing)?;
        let image = scratch.get(..len).ok_or(FlushError::Read)?;
        let generation = published_header(image, instance).map_err(FlushError::Invalid)?;
        if generation == 0 {
            return Err(FlushError::Invalid(RetainedError::InvalidRecord));
        }
        let summary = self
            .restore_retained(instance, limits, image)
            .map_err(FlushError::Invalid)?;
        Ok(RecoverSummary {
            files: summary.files,
            dirs: summary.dirs,
            tombstones: summary.tombstones,
            bytes: summary.bytes,
            generation,
        })
    }

    /// Recover a published image: validate it fully, then upsert every
    /// record into the overlay. `instance` must match the staging call or
    /// the image is rejected before anything is applied, and the image
    /// must carry a nonzero durable generation — volatile staged bytes
    /// that never completed a flush are rejected. Either the whole image
    /// applies or an explicit error is returned.
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
        if read_u32(image, RETAINED_GENERATION_OFFSET)? == 0 {
            // Only G12-published images restore: zero is the volatile
            // staging marker left by `checkpoint_retained`, never a
            // completed flush.
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

/// Parse a published-image header: magic, the staging `instance`, and the
/// durable generation. Records are not validated here — recovery fully
/// validates before applying, while a flush only needs the header to pick
/// the next generation (a torn body is superseded by the new publish, never
/// reported as durable).
fn published_header(image: &[u8], instance: u64) -> Result<u32, RetainedError> {
    if image.len() < RETAINED_HEADER_LEN || &image[..8] != RETAINED_MAGIC {
        return Err(RetainedError::InvalidRecord);
    }
    if read_u64(image, 8)? != instance {
        return Err(RetainedError::WrongInstance);
    }
    read_u32(image, RETAINED_GENERATION_OFFSET).map_err(|_| RetainedError::InvalidRecord)
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
