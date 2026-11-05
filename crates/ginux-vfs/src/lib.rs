#![no_std]

mod export;
mod retained;

pub use export::{
    ExportError, ExportFailure, ExportFileError, ExportLimits, ExportStore, ExportSummary,
    TOMBSTONE_MARKER_DIR,
};
pub use retained::{
    durable_generation, stamp_generation, CheckpointError, CheckpointSummary, DurableStore,
    FlushError, FlushSummary, GenerationReport, GenerationSummary, QuiesceError, QuiesceGate,
    QuiesceSummary, RecoverSummary, RestoreSummary, RetainedError, RetainedLimits,
    RETAINED_FIRST_GENERATION, RETAINED_GENERATION_OFFSET, RETAINED_HEADER_LEN, RETAINED_MAGIC,
};

pub const INDEX_MAGIC: &[u8; 8] = b"GINUXVFS";
pub const INDEX_VERSION: u32 = 1;
pub const HEADER_SIZE: usize = 64;
pub const RECORD_SIZE: usize = 424;
pub const MAX_PATH: usize = 256;
pub const MAX_LINK: usize = 128;
pub const O_READ: u32 = 1;
pub const O_WRITE: u32 = 2;
pub const O_CREATE: u32 = 4;
pub const O_TRUNC: u32 = 8;
pub const O_CLOEXEC: u32 = 16;
/// Position the offset at end-of-file before every write (G07a data I/O).
pub const O_APPEND: u32 = 32;

/// `lseek` positioning bases (G07a data I/O; Linux `SEEK_SET`/`SEEK_CUR`/
/// `SEEK_END` values). Unknown bases fail [`VfsError::InvalidOffset`].
pub const SEEK_SET: u32 = 0;
pub const SEEK_CUR: u32 = 1;
pub const SEEK_END: u32 = 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum NodeKind {
    File = 1,
    Directory = 2,
    Symlink = 3,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum VfsError {
    InvalidIndex,
    InvalidPath,
    NotFound,
    NotDirectory,
    IsDirectory,
    SymlinkLoop,
    PermissionDenied,
    InvalidDescriptor,
    DescriptorLimit,
    OverlayLimit,
    FileTooLarge,
    AlreadyExists,
    /// Bad `lseek` base or a resulting negative file offset (G07a).
    InvalidOffset,
    Io,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Entry<'a> {
    pub path: &'a [u8],
    pub kind: NodeKind,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub size: u64,
    pub data_offset: u64,
    pub link: &'a [u8],
}

/// One immediate child of a domain directory, as returned by
/// [`VirtualFs::list_dir`]. `name` is the final path component only.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DirEntry<'a> {
    pub name: &'a [u8],
    pub kind: NodeKind,
    pub mode: u32,
}

pub struct Index<'a> {
    bytes: &'a [u8],
    count: usize,
}

impl<'a> Index<'a> {
    pub fn new(bytes: &'a [u8]) -> Result<Self, VfsError> {
        if bytes.len() < HEADER_SIZE || &bytes[..8] != INDEX_MAGIC {
            return Err(VfsError::InvalidIndex);
        }
        if read_u32(bytes, 8)? != INDEX_VERSION || read_u32(bytes, 12)? as usize != RECORD_SIZE {
            return Err(VfsError::InvalidIndex);
        }
        let count = read_u32(bytes, 16)? as usize;
        let expected = count
            .checked_mul(RECORD_SIZE)
            .and_then(|size| size.checked_add(HEADER_SIZE))
            .ok_or(VfsError::InvalidIndex)?;
        if expected != bytes.len() {
            return Err(VfsError::InvalidIndex);
        }
        let index = Self { bytes, count };
        let mut previous: Option<&[u8]> = None;
        for offset in 0..count {
            let entry = index.entry(offset)?;
            if entry.path.is_empty()
                || entry.path[0] != b'/'
                || previous.is_some_and(|value| value >= entry.path)
            {
                return Err(VfsError::InvalidIndex);
            }
            previous = Some(entry.path);
        }
        Ok(index)
    }

    pub const fn len(&self) -> usize {
        self.count
    }

    pub const fn is_empty(&self) -> bool {
        self.count == 0
    }

    pub fn entry(&self, index: usize) -> Result<Entry<'a>, VfsError> {
        if index >= self.count {
            return Err(VfsError::InvalidIndex);
        }
        let start = HEADER_SIZE + index * RECORD_SIZE;
        decode_record(&self.bytes[start..start + RECORD_SIZE])
    }

    pub fn lookup_exact(&self, path: &[u8]) -> Result<Entry<'a>, VfsError> {
        let mut low = 0usize;
        let mut high = self.count;
        while low < high {
            let middle = low + (high - low) / 2;
            let entry = self.entry(middle)?;
            match entry.path.cmp(path) {
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
                core::cmp::Ordering::Equal => return Ok(entry),
            }
        }
        Err(VfsError::NotFound)
    }

    pub fn resolve(&self, path: &[u8]) -> Result<Entry<'a>, VfsError> {
        let mut current = normalize(path)?;
        for _ in 0..16 {
            let mut position = 1usize;
            let mut followed = false;
            while position <= current.len {
                let component_end = current.bytes[position..current.len]
                    .iter()
                    .position(|byte| *byte == b'/')
                    .map_or(current.len, |offset| position + offset);
                let prefix = &current.bytes[..component_end];
                let entry = self.lookup_exact(prefix)?;
                if entry.kind == NodeKind::Symlink {
                    let mut replacement = Path::new();
                    if entry.link.first() == Some(&b'/') {
                        replacement.extend(entry.link)?;
                    } else {
                        let parent_end = prefix.iter().rposition(|byte| *byte == b'/').unwrap_or(0);
                        if parent_end == 0 {
                            replacement.extend(b"/")?;
                        } else {
                            replacement.extend(&prefix[..parent_end])?;
                            replacement.extend(b"/")?;
                        }
                        replacement.extend(entry.link)?;
                    }
                    if component_end < current.len {
                        replacement.extend(&current.bytes[component_end..current.len])?;
                    }
                    current = normalize(replacement.as_bytes())?;
                    followed = true;
                    break;
                }
                if component_end < current.len && entry.kind != NodeKind::Directory {
                    return Err(VfsError::NotDirectory);
                }
                if component_end == current.len {
                    return Ok(entry);
                }
                position = component_end + 1;
            }
            if !followed {
                break;
            }
        }
        Err(VfsError::SymlinkLoop)
    }
}

fn decode_record(bytes: &[u8]) -> Result<Entry<'_>, VfsError> {
    if bytes.len() != RECORD_SIZE {
        return Err(VfsError::InvalidIndex);
    }
    let path_len = read_u16(bytes, 0)? as usize;
    let kind = match bytes[2] {
        1 => NodeKind::File,
        2 => NodeKind::Directory,
        3 => NodeKind::Symlink,
        _ => return Err(VfsError::InvalidIndex),
    };
    let link_len = read_u16(bytes, 32)? as usize;
    if path_len == 0 || path_len > MAX_PATH || link_len > MAX_LINK {
        return Err(VfsError::InvalidIndex);
    }
    Ok(Entry {
        path: &bytes[40..40 + path_len],
        kind,
        mode: read_u32(bytes, 4)?,
        uid: read_u32(bytes, 8)?,
        gid: read_u32(bytes, 12)?,
        size: read_u64(bytes, 16)?,
        data_offset: read_u64(bytes, 24)?,
        link: &bytes[40 + MAX_PATH..40 + MAX_PATH + link_len],
    })
}

pub fn encode_header(count: u32, output: &mut [u8; HEADER_SIZE]) {
    output.fill(0);
    output[..8].copy_from_slice(INDEX_MAGIC);
    output[8..12].copy_from_slice(&INDEX_VERSION.to_le_bytes());
    output[12..16].copy_from_slice(&(RECORD_SIZE as u32).to_le_bytes());
    output[16..20].copy_from_slice(&count.to_le_bytes());
}

pub fn encode_record(entry: Entry<'_>, output: &mut [u8; RECORD_SIZE]) -> Result<(), VfsError> {
    if entry.path.is_empty()
        || entry.path.len() > MAX_PATH
        || entry.link.len() > MAX_LINK
        || entry.path[0] != b'/'
    {
        return Err(VfsError::InvalidPath);
    }
    output.fill(0);
    output[..2].copy_from_slice(&(entry.path.len() as u16).to_le_bytes());
    output[2] = entry.kind as u8;
    output[4..8].copy_from_slice(&entry.mode.to_le_bytes());
    output[8..12].copy_from_slice(&entry.uid.to_le_bytes());
    output[12..16].copy_from_slice(&entry.gid.to_le_bytes());
    output[16..24].copy_from_slice(&entry.size.to_le_bytes());
    output[24..32].copy_from_slice(&entry.data_offset.to_le_bytes());
    output[32..34].copy_from_slice(&(entry.link.len() as u16).to_le_bytes());
    output[40..40 + entry.path.len()].copy_from_slice(entry.path);
    output[40 + MAX_PATH..40 + MAX_PATH + entry.link.len()].copy_from_slice(entry.link);
    Ok(())
}

#[derive(Clone, Copy)]
struct Path {
    bytes: [u8; MAX_PATH],
    len: usize,
}

impl Path {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_PATH],
            len: 0,
        }
    }

    fn extend(&mut self, value: &[u8]) -> Result<(), VfsError> {
        let end = self
            .len
            .checked_add(value.len())
            .ok_or(VfsError::InvalidPath)?;
        if end > MAX_PATH {
            return Err(VfsError::InvalidPath);
        }
        self.bytes[self.len..end].copy_from_slice(value);
        self.len = end;
        Ok(())
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }
}

fn normalize(input: &[u8]) -> Result<Path, VfsError> {
    if input.first() != Some(&b'/') || input.contains(&0) {
        return Err(VfsError::InvalidPath);
    }
    let mut output = Path::new();
    output.extend(b"/")?;
    let mut starts = [0usize; 64];
    let mut components = 0usize;
    for component in input.split(|byte| *byte == b'/') {
        if component.is_empty() || component == b"." {
            continue;
        }
        if component == b".." {
            if components == 0 {
                return Err(VfsError::InvalidPath);
            }
            components -= 1;
            output.len = starts[components];
            continue;
        }
        if components == starts.len() {
            return Err(VfsError::InvalidPath);
        }
        if output.len > 1 {
            output.extend(b"/")?;
        }
        starts[components] = if output.len == 1 { 1 } else { output.len - 1 };
        components += 1;
        output.extend(component)?;
    }
    Ok(output)
}

pub trait BaseReader {
    fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), VfsError>;
}

/// Whether `path` is an absolute, NUL-free, already-normalized domain path.
/// The retained-image validator uses this so untrusted images name exactly
/// the record they mean.
pub(crate) fn is_canonical_path(path: &[u8]) -> bool {
    match normalize(path) {
        Ok(canonical) => canonical.as_bytes() == path,
        Err(_) => false,
    }
}

/// One absolute path classified in the merged domain view, as reported by
/// [`VirtualFs::classify_merged`]. Live overlay entries win over the
/// immutable base; tombstones read as absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergedKind {
    Missing,
    File,
    Directory,
    /// Symlink whose raw target (absolute or relative, uninterpreted) was
    /// copied into the caller's buffer; the value is the target length.
    Symlink(usize),
    /// Symlink target did not fit the caller's buffer.
    TargetTooLong,
}

/// File metadata for one exact merged-view path, as reported by
/// [`VirtualFs::metadata_merged`] and [`VirtualFs::fstat`] (G07b stat
/// family). Paths reaching here are already canonical: callers resolve
/// symlinks first, so this reports the final entry as stored — including
/// a final symlink itself for `lstat`-style queries. `mode` carries the
/// stored permission bits only (the index packs the raw archive mode, so
/// file-type bits are added by the caller from `kind`); `ino` is a
/// deterministic path hash, never host state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    pub kind: NodeKind,
    pub mode: u32,
    pub size: u64,
    pub uid: u32,
    pub gid: u32,
    pub ino: u64,
}

// Overlay slot states: 0 = free, 1 = live file, 2 = tombstone (a removed base
// entry reads as absent and its slot may be reused), 3 = live directory
// created by [`VirtualFs::mkdir`], 4 = live symlink planted by
// [`VirtualFs::rename`] (target bytes in `data[..len]`). Directories reuse
// the file slot; `len` and `data` stay unused while a slot is a directory.
#[derive(Clone, Copy)]
struct OverlayFile<const FILE_SIZE: usize> {
    state: u8,
    path: Path,
    mode: u32,
    len: usize,
    data: [u8; FILE_SIZE],
}

impl<const FILE_SIZE: usize> OverlayFile<FILE_SIZE> {
    const fn empty() -> Self {
        Self {
            state: 0,
            path: Path::new(),
            mode: 0,
            len: 0,
            data: [0; FILE_SIZE],
        }
    }
}

#[derive(Clone, Copy)]
struct Descriptor {
    open: bool,
    overlay: bool,
    object: usize,
    offset: usize,
    readable: bool,
    writable: bool,
    close_on_exec: bool,
    /// Every write starts at end-of-file (G07a `O_APPEND`).
    append: bool,
    /// Pseudo-inode pinned at open from the resolved path (G07b `fstat`),
    /// so an open file reports the same `st_ino` as a path query.
    ino: u64,
}

impl Descriptor {
    const fn empty() -> Self {
        Self {
            open: false,
            overlay: false,
            object: 0,
            offset: 0,
            readable: false,
            writable: false,
            close_on_exec: false,
            append: false,
            ino: 0,
        }
    }
}

pub struct VirtualFs<'a, R, const FILES: usize, const FILE_SIZE: usize, const FDS: usize> {
    index: Index<'a>,
    reader: R,
    overlay: [OverlayFile<FILE_SIZE>; FILES],
    descriptors: [Descriptor; FDS],
}

impl<'a, R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>
    VirtualFs<'a, R, FILES, FILE_SIZE, FDS>
{
    pub fn new(index: Index<'a>, reader: R) -> Self {
        Self {
            index,
            reader,
            overlay: [OverlayFile::empty(); FILES],
            descriptors: [Descriptor::empty(); FDS],
        }
    }

    pub fn open(&mut self, path: &[u8], flags: u32) -> Result<i32, VfsError> {
        let path = normalize(path)?;
        // Expand overlay symlinks (planted by `rename`) before the base
        // lookup below, which only follows base-image links. The renamed
        // path stays canonical: absolute targets restart at `/`, relative
        // targets at the containing directory.
        let mut current = path;
        let mut expansions = 0usize;
        while let Some(index) = self.find_overlay(current.as_bytes()) {
            if self.overlay[index].state != 4 {
                break;
            }
            if expansions >= 16 {
                return Err(VfsError::SymlinkLoop);
            }
            expansions += 1;
            let len = self.overlay[index].len;
            if len > MAX_LINK {
                return Err(VfsError::InvalidIndex);
            }
            current = Self::expand_link(
                current.as_bytes(),
                current.len,
                &current,
                &self.overlay[index].data[..len],
            )?;
        }
        let path = current;
        let writable = flags & O_WRITE != 0;
        let readable = flags & O_READ != 0;
        if !writable && !readable {
            return Err(VfsError::PermissionDenied);
        }
        let overlay_index = self.find_overlay(path.as_bytes());
        let object: usize;
        let overlay: bool;
        // Pseudo-inode for G07b `fstat`: the stored object path, so an
        // open file reports the same `st_ino` as a path query. The base
        // read-only arm below overrides this with the resolved path.
        let mut ino = path_ino(path.as_bytes());
        match overlay_index {
            Some(index) if self.overlay[index].state == 2 => {
                if flags & O_CREATE == 0 {
                    return Err(VfsError::NotFound);
                }
                object = self.create_overlay(path, 0o600)?;
                overlay = true;
            }
            Some(index) if self.overlay[index].state == 3 => {
                return Err(VfsError::IsDirectory);
            }
            Some(index) => {
                // G08a: a writable open honors cleared write bits on overlay
                // files too, matching the base-image rule below. Created
                // files stay `0o600`, so existing writers are unaffected.
                if writable
                    && self.overlay[index].state == 1
                    && self.overlay[index].mode & 0o222 == 0
                {
                    return Err(VfsError::PermissionDenied);
                }
                object = index;
                overlay = true;
            }
            None => match self.index.resolve(path.as_bytes()) {
                Ok(entry) => {
                    if entry.kind == NodeKind::Directory {
                        return Err(VfsError::IsDirectory);
                    }
                    if writable {
                        if entry.mode & 0o222 == 0 {
                            return Err(VfsError::PermissionDenied);
                        }
                        object = self.copy_to_overlay(path, entry)?;
                        overlay = true;
                    } else {
                        object = self
                            .find_base_record(entry.path)
                            .ok_or(VfsError::InvalidIndex)?;
                        overlay = false;
                        ino = path_ino(entry.path);
                    }
                }
                Err(VfsError::NotFound) if flags & O_CREATE != 0 => {
                    self.require_parent(path.as_bytes())?;
                    object = self.create_overlay(path, 0o600)?;
                    overlay = true;
                }
                Err(error) => return Err(error),
            },
        }
        if overlay && flags & O_TRUNC != 0 {
            self.overlay[object].len = 0;
        }
        let slot = self
            .descriptors
            .iter()
            .position(|descriptor| !descriptor.open)
            .ok_or(VfsError::DescriptorLimit)?;
        self.descriptors[slot] = Descriptor {
            open: true,
            overlay,
            object,
            offset: 0,
            readable,
            writable,
            close_on_exec: flags & O_CLOEXEC != 0,
            append: flags & O_APPEND != 0,
            ino,
        };
        Ok(slot as i32 + 3)
    }

    pub fn read(&mut self, descriptor: i32, output: &mut [u8]) -> Result<usize, VfsError> {
        let slot = self.descriptor(descriptor)?;
        if !self.descriptors[slot].readable {
            return Err(VfsError::PermissionDenied);
        }
        let state = self.descriptors[slot];
        if state.overlay && self.overlay[state.object].state == 3 {
            return Err(VfsError::IsDirectory);
        }
        let available = if state.overlay {
            self.overlay[state.object].len.saturating_sub(state.offset)
        } else {
            let entry = self.index.entry(state.object)?;
            usize::try_from(entry.size)
                .map_err(|_| VfsError::FileTooLarge)?
                .saturating_sub(state.offset)
        };
        let length = available.min(output.len());
        // A zero-length read transfers nothing and reports success without
        // touching the backend, matching `pread` with count 0 at any
        // offset (a strict backend must not fail an empty transfer).
        if length > 0 {
            if state.overlay {
                output[..length].copy_from_slice(
                    &self.overlay[state.object].data[state.offset..state.offset + length],
                );
            } else {
                let entry = self.index.entry(state.object)?;
                self.reader.read_at(
                    entry.data_offset + state.offset as u64,
                    &mut output[..length],
                )?;
            }
        }
        self.descriptors[slot].offset += length;
        Ok(length)
    }

    /// Write `input` at the descriptor offset, returning the bytes stored.
    /// `O_APPEND` descriptors start at end-of-file. Transfers are bounded
    /// by overlay capacity: an oversized write stores what fits and returns
    /// that short count instead of failing, so callers observe a bounded
    /// transfer exactly like a short `write(2)` on a nearly full file. Only
    /// a write that can store nothing fails with [`VfsError::FileTooLarge`].
    /// A gap between the previous end and an offset past it reads back as
    /// zeros. Empty input stores nothing and succeeds.
    pub fn write(&mut self, descriptor: i32, input: &[u8]) -> Result<usize, VfsError> {
        let slot = self.descriptor(descriptor)?;
        let state = self.descriptors[slot];
        if !state.writable || !state.overlay {
            return Err(VfsError::PermissionDenied);
        }
        if self.overlay[state.object].state == 3 {
            return Err(VfsError::IsDirectory);
        }
        let mut offset = state.offset;
        if state.append {
            offset = self.overlay[state.object].len;
        }
        if input.is_empty() {
            self.descriptors[slot].offset = offset;
            return Ok(0);
        }
        if offset > FILE_SIZE {
            return Err(VfsError::FileTooLarge);
        }
        let fitting = (FILE_SIZE - offset).min(input.len());
        if fitting == 0 {
            return Err(VfsError::FileTooLarge);
        }
        let previous = self.overlay[state.object].len;
        if offset > previous {
            self.overlay[state.object].data[previous..offset].fill(0);
        }
        let end = offset + fitting;
        self.overlay[state.object].data[offset..end].copy_from_slice(&input[..fitting]);
        self.overlay[state.object].len = previous.max(end);
        self.descriptors[slot].offset = end;
        Ok(fitting)
    }

    /// Reposition a descriptor offset (`SEEK_SET`/`SEEK_CUR`/`SEEK_END`),
    /// returning the new offset. Offsets past end-of-file are allowed; reads
    /// there return short and later writes zero-fill the gap. Unknown bases
    /// and negative results fail with [`VfsError::InvalidOffset`].
    pub fn seek(&mut self, descriptor: i32, offset: i64, whence: u32) -> Result<u64, VfsError> {
        let slot = self.descriptor(descriptor)?;
        let state = self.descriptors[slot];
        if self.overlay[state.object].state == 3 {
            return Err(VfsError::IsDirectory);
        }
        let size: u64 = if state.overlay {
            self.overlay[state.object].len as u64
        } else {
            let entry = self.index.entry(state.object)?;
            entry.size
        };
        let current = i64::try_from(state.offset).map_err(|_| VfsError::InvalidOffset)?;
        let end = i64::try_from(size).map_err(|_| VfsError::FileTooLarge)?;
        let base = match whence {
            SEEK_SET => 0,
            SEEK_CUR => current,
            SEEK_END => end,
            _ => return Err(VfsError::InvalidOffset),
        };
        let position = base
            .checked_add(offset)
            .ok_or(VfsError::InvalidOffset)?;
        if position < 0 {
            return Err(VfsError::InvalidOffset);
        }
        self.descriptors[slot].offset = position as usize;
        Ok(position as u64)
    }

    pub fn duplicate(&mut self, descriptor: i32, close_on_exec: bool) -> Result<i32, VfsError> {
        let source = self.descriptor(descriptor)?;
        let target = self
            .descriptors
            .iter()
            .position(|descriptor| !descriptor.open)
            .ok_or(VfsError::DescriptorLimit)?;
        self.descriptors[target] = self.descriptors[source];
        self.descriptors[target].close_on_exec = close_on_exec;
        Ok(target as i32 + 3)
    }

    pub fn close(&mut self, descriptor: i32) -> Result<(), VfsError> {
        let slot = self.descriptor(descriptor)?;
        self.descriptors[slot] = Descriptor::empty();
        Ok(())
    }

    pub fn close_on_exec(&mut self) {
        for descriptor in &mut self.descriptors {
            if descriptor.open && descriptor.close_on_exec {
                *descriptor = Descriptor::empty();
            }
        }
    }

    /// Create a domain directory. The parent must already exist as a directory
    /// in the merged domain view (base image plus overlay); `..` escapes and
    /// symlink escapes resolve to an explicit denial, never a host effect.
    pub fn mkdir(&mut self, path: &[u8], mode: u32) -> Result<(), VfsError> {
        let path = normalize(path)?;
        if path.as_bytes() == b"/" {
            return Err(VfsError::AlreadyExists);
        }
        // A live entry of any kind (file, directory, or symlink) blocks
        // creation. A tombstone reads as absent, so its slot may be reused.
        if let Some(index) = self.find_overlay(path.as_bytes()) {
            if self.overlay[index].state != 2 {
                return Err(VfsError::AlreadyExists);
            }
        } else if self.index.lookup_exact(path.as_bytes()).is_ok() {
            return Err(VfsError::AlreadyExists);
        }
        let split = path
            .as_bytes()
            .iter()
            .rposition(|byte| *byte == b'/')
            .ok_or(VfsError::InvalidPath)?;
        let parent = if split == 0 {
            b"/".as_slice()
        } else {
            &path.as_bytes()[..split]
        };
        match self.stat_merged(parent)? {
            (NodeKind::Directory, _, _) => {}
            _ => return Err(VfsError::NotDirectory),
        }
        let index = self.allocate_overlay()?;
        self.overlay[index].state = 3;
        self.overlay[index].path = path;
        self.overlay[index].mode = mode & 0o7777;
        self.overlay[index].len = 0;
        Ok(())
    }

    /// List the immediate children of a domain directory in sorted name order.
    /// Returns the total child count; `output` is filled with up to its
    /// capacity, so a return larger than `output.len()` means truncation.
    /// Symlinked directories list under their canonical path.
    pub fn list_dir<'s>(
        &'s self,
        path: &[u8],
        output: &mut [DirEntry<'s>],
    ) -> Result<usize, VfsError> {
        let (kind, _, canonical) = self.stat_merged(path)?;
        if kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let dir = canonical.as_bytes();
        let mut total = 0usize;
        let mut placed = 0usize;
        // Immutable base first (index order is already sorted), skipping
        // anything the overlay shadows with a live entry or hides behind a
        // tombstone. Overlay entries only ever shadow their exact path, so no
        // ancestor check is needed here.
        for record in 0..self.index.len() {
            let entry = self.index.entry(record)?;
            let Some(name) = child_name(dir, entry.path) else {
                continue;
            };
            if self.find_overlay(entry.path).is_some() {
                continue;
            }
            total += 1;
            if placed < output.len() {
                output[placed] = DirEntry {
                    name,
                    kind: entry.kind,
                    mode: entry.mode,
                };
                placed += 1;
            }
        }
        for slot in &self.overlay {
            if slot.state != 1 && slot.state != 3 && slot.state != 4 {
                continue;
            }
            let Some(name) = child_name(dir, slot.path.as_bytes()) else {
                continue;
            };
            total += 1;
            if placed < output.len() {
                output[placed] = DirEntry {
                    name,
                    kind: if slot.state == 3 {
                        NodeKind::Directory
                    } else if slot.state == 4 {
                        NodeKind::Symlink
                    } else {
                        NodeKind::File
                    },
                    mode: slot.mode,
                };
                placed += 1;
            }
        }
        let mut index = 1usize;
        while index < placed {
            let mut cursor = index;
            while cursor > 0 && output[cursor - 1].name > output[cursor].name {
                output.swap(cursor - 1, cursor);
                cursor -= 1;
            }
            index += 1;
        }
        Ok(total)
    }

    /// Remove one domain file or symlink, leaving directories in place.
    /// Resolution never follows the final symlink, so unlinking a link —
    /// including a dangling one or one pointing at a directory — removes
    /// the link itself and leaves the target untouched. The removal reads
    /// as a tombstone: the name goes missing while open descriptors keep
    /// reporting the object they pinned. Directories fail with
    /// [`VfsError::IsDirectory`]; removing one needs `rmdir` support, an
    /// observed follow-up.
    pub fn unlink(&mut self, path: &[u8]) -> Result<(), VfsError> {
        let (kind, _, canon, overlay) = self.resolve_merged(path, false)?;
        if kind == NodeKind::Directory {
            return Err(VfsError::IsDirectory);
        }
        if let Some(index) = overlay {
            self.overlay[index].state = 2;
            self.overlay[index].len = 0;
            return Ok(());
        }
        let index = self.allocate_overlay()?;
        self.overlay[index].state = 2;
        self.overlay[index].path = canon;
        self.overlay[index].len = 0;
        Ok(())
    }

    /// Move `old` to `new` within the domain, replacing any existing file
    /// or symlink at `new` in the same step. The replacement is atomic: all
    /// fallible checks (missing source, directory source or target, overlay
    /// capacity, oversized content, backing-store reads) complete before
    /// any live view changes, so a failure leaves the previous view intact.
    /// Directories never move: an old or new directory fails with
    /// [`VfsError::IsDirectory`], since directory moves need `rmdir`
    /// support, an observed follow-up. Renaming a name onto itself succeeds
    /// once the entry is proven to exist. The target parent must already be
    /// a directory in the merged view; intermediate symlinks on every side
    /// expand, but a final symlink on the source side moves the link
    /// itself, never its target. A moved overlay entry keeps its slot (open
    /// descriptors follow it to the new name); a moved base entry is copied
    /// into the overlay and hidden behind a tombstone, so the immutable
    /// image never changes.
    pub fn rename(&mut self, old: &[u8], new: &[u8]) -> Result<(), VfsError> {
        let old = normalize(old)?;
        let new = normalize(new)?;
        if old.as_bytes() == b"/" || new.as_bytes() == b"/" {
            return Err(VfsError::InvalidPath);
        }
        let (old_kind, old_mode, old_canon, old_overlay) =
            self.resolve_merged(old.as_bytes(), false)?;
        if old_kind == NodeKind::Directory {
            return Err(VfsError::IsDirectory);
        }
        // Canonical target: resolve the parent (through symlinks), then join
        // the final name, so the stored path never hides an unexpanded link.
        let split = new
            .as_bytes()
            .iter()
            .rposition(|byte| *byte == b'/')
            .ok_or(VfsError::InvalidPath)?;
        let parent = if split == 0 {
            b"/".as_slice()
        } else {
            &new.as_bytes()[..split]
        };
        let name = &new.as_bytes()[split + 1..];
        if name.is_empty() || name == b"." || name == b".." {
            return Err(VfsError::InvalidPath);
        }
        let (parent_kind, _, parent_canon, _) = self.resolve_merged(parent, true)?;
        if parent_kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let mut full = parent_canon;
        if full.as_bytes() != b"/" {
            full.extend(b"/")?;
        }
        full.extend(name)?;
        if full.as_bytes() == old_canon.as_bytes() {
            return Ok(());
        }
        // Classify the target exactly: `full` is canonical, so no symlink
        // is left to expand. A base directory always blocks, even under a
        // tombstone; a live overlay entry is replaced below.
        let target_overlay = self.find_overlay(full.as_bytes());
        let victim = match target_overlay {
            Some(index) if self.overlay[index].state == 3 => {
                return Err(VfsError::IsDirectory);
            }
            Some(index) if self.overlay[index].state != 2 => Some(index),
            _ => None,
        };
        let tombstone = match target_overlay {
            Some(index) if self.overlay[index].state == 2 => Some(index),
            _ => None,
        };
        let target_base_live = match self.index.lookup_exact(full.as_bytes()) {
            Ok(entry) => {
                if entry.kind == NodeKind::Directory {
                    return Err(VfsError::IsDirectory);
                }
                true
            }
            Err(VfsError::NotFound) => false,
            Err(error) => return Err(error),
        };
        // Fetch the source content while the view is still untouched. Base
        // files contribute their record span; base symlinks their target.
        // An overlay source moves in its own slot, so nothing is fetched.
        let old_is_base = old_overlay.is_none();
        let mut base_size = 0usize;
        let mut base_offset = 0u64;
        let mut link_buf = [0u8; MAX_LINK];
        let mut link_len = 0usize;
        if old_is_base {
            match self.index.lookup_exact(old_canon.as_bytes()) {
                Ok(entry) if old_kind == NodeKind::File && entry.kind == NodeKind::File => {
                    let size =
                        usize::try_from(entry.size).map_err(|_| VfsError::FileTooLarge)?;
                    if size > FILE_SIZE {
                        return Err(VfsError::FileTooLarge);
                    }
                    base_size = size;
                    base_offset = entry.data_offset;
                }
                Ok(entry)
                    if old_kind == NodeKind::Symlink && entry.kind == NodeKind::Symlink =>
                {
                    if entry.link.len() > FILE_SIZE {
                        return Err(VfsError::FileTooLarge);
                    }
                    link_buf[..entry.link.len()].copy_from_slice(entry.link);
                    link_len = entry.link.len();
                }
                Ok(_) => return Err(VfsError::InvalidIndex),
                Err(error) => return Err(error),
            }
        }
        // Count fresh slots before mutating: recycled tombstones cost none.
        // The source tombstone always needs one; the content needs one
        // unless a dead slot at the target takes it; hiding a live base
        // target needs one more, taking the dead slot when the content did
        // not already claim it.
        let content_in_tomb = old_is_base && victim.is_none() && tombstone.is_some();
        let tomb_new_in_tomb =
            target_base_live && victim.is_none() && tombstone.is_some() && !content_in_tomb;
        let mut need = 1usize;
        if old_is_base && !content_in_tomb {
            need += 1;
        }
        if target_base_live && victim.is_none() && !tomb_new_in_tomb {
            need += 1;
        }
        let free = self.overlay.iter().filter(|entry| entry.state == 0).count();
        if free < need {
            return Err(VfsError::OverlayLimit);
        }
        // Place the content. A base source copies into the recycled target
        // tombstone when one is there, else a fresh slot; a live victim is
        // never reused, so a backing-store failure below cannot clobber live
        // data. The read runs before any view change; a fresh slot rolls
        // back to free on failure.
        let mut tomb_reused = false;
        if old_is_base {
            let index = match tombstone {
                Some(index) if victim.is_none() => {
                    tomb_reused = true;
                    index
                }
                _ => self.allocate_overlay()?,
            };
            if old_kind == NodeKind::File {
                if base_size > 0 {
                    if let Err(error) = self.reader.read_at(
                        base_offset,
                        &mut self.overlay[index].data[..base_size],
                    ) {
                        if !tomb_reused {
                            self.overlay[index].state = 0;
                        }
                        return Err(error);
                    }
                }
                self.overlay[index].state = 1;
                self.overlay[index].path = full;
                self.overlay[index].mode = old_mode;
                self.overlay[index].len = base_size;
            } else {
                self.overlay[index].state = 4;
                self.overlay[index].path = full;
                self.overlay[index].mode = old_mode;
                self.overlay[index].len = link_len;
                self.overlay[index].data[..link_len].copy_from_slice(&link_buf[..link_len]);
            }
        }
        // A replaced live victim becomes a tombstone, keeping the base it
        // may shadow hidden; an overlay source moves in its own slot.
        if let Some(index) = victim {
            self.overlay[index].state = 2;
            self.overlay[index].len = 0;
        }
        if let Some(index) = old_overlay {
            self.overlay[index].path = full;
        }
        // Hide a replaced live base target behind a tombstone, reusing the
        // dead target slot when the content did not already claim it.
        if target_base_live && victim.is_none() {
            let index = match tombstone {
                Some(index) if !tomb_reused => {
                    tomb_reused = true;
                    index
                }
                _ => self.allocate_overlay()?,
            };
            self.overlay[index].state = 2;
            self.overlay[index].path = full;
            self.overlay[index].len = 0;
        }
        // Hide the vacated source name the same way.
        let index = self.allocate_overlay()?;
        self.overlay[index].state = 2;
        self.overlay[index].path = old_canon;
        self.overlay[index].len = 0;
        // A superseded target tombstone that neither the content nor a
        // target tombstone reused is now redundant: free it.
        if let Some(index) = tombstone {
            if !tomb_reused {
                self.overlay[index].state = 0;
            }
        }
        Ok(())
    }

    /// Set permission bits on one domain file or directory, following a
    /// final symlink exactly like Linux `chmod(2)`. Only the plain
    /// permission bits (`0o777`, including the executable bit installers
    /// need) are accepted: setuid/setgid/sticky requests fail with
    /// [`VfsError::PermissionDenied`], and ownership stays root — there is
    /// no privilege model to grant it, so the chown family has no VFS
    /// counterpart. A live overlay entry takes the mode directly; a base
    /// entry is materialized into the overlay first (a directory as a
    /// shadowing directory slot, which keeps its children resolving
    /// through to the base), so the immutable image never changes.
    pub fn chmod(&mut self, path: &[u8], mode: u32) -> Result<(), VfsError> {
        if mode & !0o777 != 0 {
            return Err(VfsError::PermissionDenied);
        }
        let mode = mode & 0o777;
        let (kind, _, canon, overlay) = self.resolve_merged(path, true)?;
        if let Some(index) = overlay {
            match self.overlay[index].state {
                1 | 3 | 4 => {
                    self.overlay[index].mode = mode;
                    return Ok(());
                }
                _ => return Err(VfsError::InvalidIndex),
            }
        }
        match kind {
            NodeKind::File => {
                let entry = self.index.lookup_exact(canon.as_bytes())?;
                let index = self.copy_to_overlay(canon, entry)?;
                self.overlay[index].mode = mode;
                Ok(())
            }
            NodeKind::Directory => {
                let index = self.allocate_overlay()?;
                self.overlay[index].state = 3;
                self.overlay[index].path = canon;
                self.overlay[index].mode = mode;
                self.overlay[index].len = 0;
                Ok(())
            }
            // Following resolution never reports a final symlink.
            NodeKind::Symlink => Err(VfsError::InvalidIndex),
        }
    }

    /// Set permission bits on the object an open descriptor pinned
    /// (`fchmod`). The same bit policy as [`VirtualFs::chmod`] applies. A
    /// base-backed descriptor is materialized into the overlay and repointed
    /// there, so the mode change — like any permitted write — never touches
    /// the immutable image. The pinned path hash is unchanged.
    pub fn chmod_fd(&mut self, descriptor: i32, mode: u32) -> Result<(), VfsError> {
        if mode & !0o777 != 0 {
            return Err(VfsError::PermissionDenied);
        }
        let slot = self.descriptor(descriptor)?;
        let state = self.descriptors[slot];
        if state.overlay {
            if self.overlay[state.object].state != 1 {
                return Err(VfsError::InvalidIndex);
            }
            self.overlay[state.object].mode = mode & 0o777;
            return Ok(());
        }
        let entry = self.index.entry(state.object)?;
        if entry.kind != NodeKind::File {
            return Err(VfsError::InvalidIndex);
        }
        let mut target = Path::new();
        target.extend(entry.path)?;
        let index = self.copy_to_overlay(target, entry)?;
        self.overlay[index].mode = mode & 0o777;
        self.descriptors[slot].overlay = true;
        self.descriptors[slot].object = index;
        Ok(())
    }

    /// Create a hard link: `new` names the same content `old` resolves to.
    /// The source follows a final symlink (like `link(2)`); directories are
    /// refused and the target must be absent — links never replace, so a
    /// live entry of any kind fails with [`VfsError::AlreadyExists`] while a
    /// tombstone reads as absent and takes the new name. Content is copied
    /// into the overlay (the base image never changes); the copy shares no
    /// writes with the source afterward, a stated G08a bound, and both names
    /// report link count 1. At most one overlay slot is consumed, reusing a
    /// dead target slot when one is there, and a failed content read leaves
    /// the previous view intact.
    pub fn link(&mut self, old: &[u8], new: &[u8]) -> Result<(), VfsError> {
        let old = normalize(old)?;
        let new = normalize(new)?;
        if old.as_bytes() == b"/" || new.as_bytes() == b"/" {
            return Err(VfsError::InvalidPath);
        }
        let (old_kind, _, old_canon, old_overlay) = self.resolve_merged(old.as_bytes(), true)?;
        if old_kind == NodeKind::Directory {
            return Err(VfsError::IsDirectory);
        }
        let split = new
            .as_bytes()
            .iter()
            .rposition(|byte| *byte == b'/')
            .ok_or(VfsError::InvalidPath)?;
        let parent = if split == 0 {
            b"/".as_slice()
        } else {
            &new.as_bytes()[..split]
        };
        let name = &new.as_bytes()[split + 1..];
        if name.is_empty() || name == b"." || name == b".." {
            return Err(VfsError::InvalidPath);
        }
        let (parent_kind, _, parent_canon, _) = self.resolve_merged(parent, true)?;
        if parent_kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let mut full = parent_canon;
        if full.as_bytes() != b"/" {
            full.extend(b"/")?;
        }
        full.extend(name)?;
        let tombstone = match self.find_overlay(full.as_bytes()) {
            Some(index) if self.overlay[index].state == 2 => Some(index),
            Some(_) => return Err(VfsError::AlreadyExists),
            None => None,
        };
        match self.index.lookup_exact(full.as_bytes()) {
            Ok(_) => return Err(VfsError::AlreadyExists),
            Err(VfsError::NotFound) => {}
            Err(error) => return Err(error),
        }
        // Fetch the source content while the view is still untouched.
        let mut base_size = 0usize;
        let mut base_offset = 0u64;
        let source_mode;
        let mut source_data = [0u8; FILE_SIZE];
        let mut source_len = 0usize;
        let old_is_base = old_overlay.is_none();
        if old_is_base {
            let entry = self.index.lookup_exact(old_canon.as_bytes())?;
            if entry.kind != NodeKind::File {
                return Err(VfsError::InvalidIndex);
            }
            let size = usize::try_from(entry.size).map_err(|_| VfsError::FileTooLarge)?;
            if size > FILE_SIZE {
                return Err(VfsError::FileTooLarge);
            }
            base_size = size;
            base_offset = entry.data_offset;
            source_mode = entry.mode;
        } else {
            let index = old_overlay.ok_or(VfsError::InvalidIndex)?;
            if self.overlay[index].state != 1 {
                return Err(VfsError::InvalidIndex);
            }
            source_mode = self.overlay[index].mode;
            source_len = self.overlay[index].len;
            source_data = self.overlay[index].data;
        }
        if tombstone.is_none()
            && self.overlay.iter().filter(|entry| entry.state == 0).count() == 0
        {
            return Err(VfsError::OverlayLimit);
        }
        let index = match tombstone {
            Some(index) => index,
            None => self.allocate_overlay()?,
        };
        if old_is_base {
            if base_size > 0 {
                if let Err(error) = self
                    .reader
                    .read_at(base_offset, &mut self.overlay[index].data[..base_size])
                {
                    if tombstone.is_none() {
                        self.overlay[index].state = 0;
                    }
                    return Err(error);
                }
            }
            self.overlay[index].state = 1;
            self.overlay[index].path = full;
            self.overlay[index].mode = source_mode;
            self.overlay[index].len = base_size;
        } else {
            self.overlay[index].state = 1;
            self.overlay[index].path = full;
            self.overlay[index].mode = source_mode;
            self.overlay[index].len = source_len;
            self.overlay[index].data = source_data;
        }
        Ok(())
    }

    /// Plant a symlink: `new` reads as a link whose raw target is `target`
    /// (absolute or relative, uninterpreted — confinement applies when the
    /// link resolves, not when it is created, so dangling and absolute
    /// targets are legal here exactly as on Linux). The target must fit
    /// `MAX_LINK`; the name must be absent (a tombstone takes the name, a
    /// live entry blocks it). Links take mode `0o777`, matching the
    /// conventional `lrwxrwxrwx` report.
    pub fn symlink(&mut self, target: &[u8], new: &[u8]) -> Result<(), VfsError> {
        if target.is_empty() || target.len() > MAX_LINK || target.contains(&0) {
            return Err(VfsError::InvalidPath);
        }
        if target.len() > FILE_SIZE {
            return Err(VfsError::FileTooLarge);
        }
        let new = normalize(new)?;
        if new.as_bytes() == b"/" {
            return Err(VfsError::InvalidPath);
        }
        let split = new
            .as_bytes()
            .iter()
            .rposition(|byte| *byte == b'/')
            .ok_or(VfsError::InvalidPath)?;
        let parent = if split == 0 {
            b"/".as_slice()
        } else {
            &new.as_bytes()[..split]
        };
        let name = &new.as_bytes()[split + 1..];
        if name.is_empty() || name == b"." || name == b".." {
            return Err(VfsError::InvalidPath);
        }
        let (parent_kind, _, parent_canon, _) = self.resolve_merged(parent, true)?;
        if parent_kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let mut full = parent_canon;
        if full.as_bytes() != b"/" {
            full.extend(b"/")?;
        }
        full.extend(name)?;
        let tombstone = match self.find_overlay(full.as_bytes()) {
            Some(index) if self.overlay[index].state == 2 => Some(index),
            Some(_) => return Err(VfsError::AlreadyExists),
            None => None,
        };
        match self.index.lookup_exact(full.as_bytes()) {
            Ok(_) => return Err(VfsError::AlreadyExists),
            Err(VfsError::NotFound) => {}
            Err(error) => return Err(error),
        }
        let index = match tombstone {
            Some(index) => index,
            None => self.allocate_overlay()?,
        };
        self.overlay[index].state = 4;
        self.overlay[index].path = full;
        self.overlay[index].mode = 0o777;
        self.overlay[index].len = target.len();
        self.overlay[index].data[..target.len()].copy_from_slice(target);
        Ok(())
    }

    /// Read a symlink's raw target (`readlink`): the final component never
    /// follows, so this reports the link itself — including a dangling one
    /// or one pointing at a directory — while leaving the target untouched.
    /// Anything but a symlink fails with [`VfsError::InvalidPath`], matching
    /// Linux `EINVAL`. Like Linux, a target longer than `output` truncates
    /// to what fits and the placed count is returned.
    pub fn readlink(&self, path: &[u8], output: &mut [u8]) -> Result<usize, VfsError> {
        let (kind, _, canon, overlay) = self.resolve_merged(path, false)?;
        if kind != NodeKind::Symlink {
            return Err(VfsError::InvalidPath);
        }
        let target: &[u8] = if let Some(index) = overlay {
            if self.overlay[index].state != 4 {
                return Err(VfsError::InvalidIndex);
            }
            &self.overlay[index].data[..self.overlay[index].len]
        } else {
            self.index.lookup_exact(canon.as_bytes())?.link
        };
        let count = target.len().min(output.len());
        output[..count].copy_from_slice(&target[..count]);
        Ok(count)
    }

    pub fn teardown(&mut self) {
        self.overlay.fill(OverlayFile::empty());
        self.descriptors.fill(Descriptor::empty());
    }

    /// Classify one absolute path in the merged domain view (overlay wins
    /// over the base image; tombstones read as absent) without following a
    /// final symlink, so prefix-walking resolvers can expand links
    /// themselves. Symlink targets are copied raw into `link`.
    ///
    /// Callers pass absolute normalized paths (as built by a canonical
    /// prefix walk); anything else simply misses. Base symlinks always fit
    /// the index `MAX_LINK` record, so [`MergedKind::TargetTooLong`] only
    /// guards callers with a smaller buffer.
    pub fn classify_merged(&self, path: &[u8], link: &mut [u8; MAX_LINK]) -> MergedKind {
        if let Some(index) = self.find_overlay(path) {
            let slot = &self.overlay[index];
            if slot.state == 4 {
                if slot.len > link.len() {
                    return MergedKind::TargetTooLong;
                }
                link[..slot.len].copy_from_slice(&slot.data[..slot.len]);
                return MergedKind::Symlink(slot.len);
            }
            return match slot.state {
                1 => MergedKind::File,
                3 => MergedKind::Directory,
                _ => MergedKind::Missing,
            };
        }
        match self.index.lookup_exact(path) {
            Err(_) => MergedKind::Missing,
            Ok(entry) => match entry.kind {
                NodeKind::File => MergedKind::File,
                NodeKind::Directory => MergedKind::Directory,
                NodeKind::Symlink => {
                    if entry.link.len() > link.len() {
                        MergedKind::TargetTooLong
                    } else {
                        link[..entry.link.len()].copy_from_slice(entry.link);
                        MergedKind::Symlink(entry.link.len())
                    }
                }
            },
        }
    }

    /// Report metadata for one exact canonical path in the merged domain
    /// view (G07b `stat`/`lstat`/`newfstatat`): live overlay entries win,
    /// tombstones read as absent. No symlink following — the caller
    /// resolves first and passes the canonical path, so a final symlink
    /// reports itself. Overlay files report root ownership until
    /// permission handling (G08a) lands.
    pub fn metadata_merged(&self, path: &[u8]) -> Result<FileMetadata, VfsError> {
        if let Some(index) = self.find_overlay(path) {
            let slot = &self.overlay[index];
            if slot.state == 2 {
                return Err(VfsError::NotFound);
            }
            if slot.state == 3 {
                return Ok(FileMetadata {
                    kind: NodeKind::Directory,
                    mode: slot.mode,
                    size: 0,
                    uid: 0,
                    gid: 0,
                    ino: path_ino(path),
                });
            }
            if slot.state == 4 {
                return Ok(FileMetadata {
                    kind: NodeKind::Symlink,
                    mode: slot.mode,
                    size: slot.len as u64,
                    uid: 0,
                    gid: 0,
                    ino: path_ino(path),
                });
            }
            return Ok(FileMetadata {
                kind: NodeKind::File,
                mode: slot.mode,
                size: slot.len as u64,
                uid: 0,
                gid: 0,
                ino: path_ino(path),
            });
        }
        base_metadata(self.index.lookup_exact(path)?)
    }

    /// Report metadata for a live descriptor (G07b `fstat`): the object the
    /// open path pinned, so no path lookup runs here. Overlay files report
    /// the live overlay length and root ownership; an unlinked-but-open
    /// file still reports, matching Linux. A directory slot (unreachable
    /// through `open`, which refuses directories) fails explicitly.
    pub fn fstat(&self, descriptor: i32) -> Result<FileMetadata, VfsError> {
        let slot = self.descriptor(descriptor)?;
        let state = self.descriptors[slot];
        if state.overlay {
            let file = &self.overlay[state.object];
            if file.state == 3 {
                return Err(VfsError::IsDirectory);
            }
            if file.state == 0 {
                return Err(VfsError::InvalidIndex);
            }
            return Ok(FileMetadata {
                kind: NodeKind::File,
                mode: file.mode,
                size: file.len as u64,
                uid: 0,
                gid: 0,
                ino: state.ino,
            });
        }
        // `open` pins `ino` from this same record path, so the base
        // mapping below already agrees with path queries.
        base_metadata(self.index.entry(state.object)?)
    }

    pub fn overlay_files(&self) -> usize {
        self.overlay.iter().filter(|entry| entry.state == 1).count()
    }

    fn descriptor(&self, descriptor: i32) -> Result<usize, VfsError> {
        let slot = descriptor
            .checked_sub(3)
            .ok_or(VfsError::InvalidDescriptor)? as usize;
        if slot >= FDS || !self.descriptors[slot].open {
            return Err(VfsError::InvalidDescriptor);
        }
        Ok(slot)
    }

    /// First live slot at `path`, else the first tombstone there. Rename
    /// and recreation can leave a tombstone and a live entry sharing one
    /// path; the live entry always wins so a removed-then-replaced name
    /// resolves to its replacement, never to the deletion marker.
    fn find_overlay(&self, path: &[u8]) -> Option<usize> {
        let mut tombstone = None;
        for (index, entry) in self.overlay.iter().enumerate() {
            if entry.state != 0 && entry.path.as_bytes() == path {
                if entry.state == 2 {
                    if tombstone.is_none() {
                        tombstone = Some(index);
                    }
                } else {
                    return Some(index);
                }
            }
        }
        tombstone
    }

    fn allocate_overlay(&self) -> Result<usize, VfsError> {
        self.overlay
            .iter()
            .position(|entry| entry.state == 0)
            .ok_or(VfsError::OverlayLimit)
    }

    fn create_overlay(&mut self, path: Path, mode: u32) -> Result<usize, VfsError> {
        let index = self.allocate_overlay()?;
        self.overlay[index].state = 1;
        self.overlay[index].path = path;
        self.overlay[index].mode = mode;
        self.overlay[index].len = 0;
        Ok(index)
    }

    fn copy_to_overlay(&mut self, path: Path, entry: Entry<'_>) -> Result<usize, VfsError> {
        let size = usize::try_from(entry.size).map_err(|_| VfsError::FileTooLarge)?;
        if size > FILE_SIZE {
            return Err(VfsError::FileTooLarge);
        }
        let index = self.create_overlay(path, entry.mode)?;
        self.reader
            .read_at(entry.data_offset, &mut self.overlay[index].data[..size])?;
        self.overlay[index].len = size;
        Ok(index)
    }

    fn find_base_record(&self, path: &[u8]) -> Option<usize> {
        let mut low = 0usize;
        let mut high = self.index.count;
        while low < high {
            let middle = low + (high - low) / 2;
            let entry = self.index.entry(middle).ok()?;
            match entry.path.cmp(path) {
                core::cmp::Ordering::Less => low = middle + 1,
                core::cmp::Ordering::Greater => high = middle,
                core::cmp::Ordering::Equal => return Some(middle),
            }
        }
        None
    }

    fn require_parent(&self, path: &[u8]) -> Result<(), VfsError> {
        let split = path
            .iter()
            .rposition(|byte| *byte == b'/')
            .ok_or(VfsError::InvalidPath)?;
        let parent = if split == 0 {
            b"/".as_slice()
        } else {
            &path[..split]
        };
        // Merged view: files may be created under overlay directories too.
        match self.stat_merged(parent)? {
            (NodeKind::Directory, _, _) => Ok(()),
            _ => Err(VfsError::NotDirectory),
        }
    }

    /// Resolve `path` in the merged domain view (overlay wins over base),
    /// returning kind, mode, and the canonical post-symlink path. `..`
    /// escapes past the domain root fail `normalize` with `InvalidPath`, so
    /// traversal can never name anything outside the domain.
    fn stat_merged(&self, path: &[u8]) -> Result<(NodeKind, u32, Path), VfsError> {
        let (kind, mode, canon, _) = self.resolve_merged(path, true)?;
        Ok((kind, mode, canon))
    }

    /// [`stat_merged`] with caller-chosen final-symlink behavior, plus the
    /// overlay index when the final entry is a live overlay entry (`None`
    /// for base entries). With `follow_final = false` a final symlink
    /// reports itself instead of expanding, so rename/unlink operate on the
    /// link itself rather than its target. Overlay symlinks (state 4,
    /// planted by [`VirtualFs::rename`]) expand like base symlinks when
    /// followed: absolute targets restart at `/`, relative targets restart
    /// at the containing directory.
    fn resolve_merged(
        &self,
        path: &[u8],
        follow_final: bool,
    ) -> Result<(NodeKind, u32, Path, Option<usize>), VfsError> {
        let mut current = normalize(path)?;
        for _ in 0..16 {
            let mut position = 1usize;
            let mut followed = false;
            while position <= current.len {
                let component_end = current.bytes[position..current.len]
                    .iter()
                    .position(|byte| *byte == b'/')
                    .map_or(current.len, |offset| position + offset);
                let prefix = &current.bytes[..component_end];
                if let Some(index) = self.find_overlay(prefix) {
                    let slot = &self.overlay[index];
                    if slot.state == 2 {
                        return Err(VfsError::NotFound);
                    }
                    if slot.state == 4 {
                        if slot.len > MAX_LINK {
                            return Err(VfsError::InvalidIndex);
                        }
                        let last = component_end == current.len;
                        if last && !follow_final {
                            return Ok((NodeKind::Symlink, slot.mode, current, Some(index)));
                        }
                        current = Self::expand_link(
                            prefix,
                            component_end,
                            &current,
                            &slot.data[..slot.len],
                        )?;
                        followed = true;
                        break;
                    }
                    let kind = if slot.state == 3 {
                        NodeKind::Directory
                    } else {
                        NodeKind::File
                    };
                    if component_end < current.len && kind != NodeKind::Directory {
                        return Err(VfsError::NotDirectory);
                    }
                    if component_end == current.len {
                        return Ok((kind, slot.mode, current, Some(index)));
                    }
                    position = component_end + 1;
                    continue;
                }
                let base = match self.index.lookup_exact(prefix) {
                    Ok(entry) => entry,
                    Err(_) => return Err(VfsError::NotFound),
                };
                if base.kind == NodeKind::Symlink {
                    if component_end == current.len && !follow_final {
                        return Ok((NodeKind::Symlink, base.mode, current, None));
                    }
                    current = Self::expand_link(prefix, component_end, &current, base.link)?;
                    followed = true;
                    break;
                }
                if component_end < current.len && base.kind != NodeKind::Directory {
                    return Err(VfsError::NotDirectory);
                }
                if component_end == current.len {
                    return Ok((base.kind, base.mode, current, None));
                }
                position = component_end + 1;
            }
            if !followed {
                break;
            }
        }
        Err(VfsError::SymlinkLoop)
    }

    /// Expand one symlink step: absolute `target` restarts at `/`, relative
    /// `target` restarts at the directory containing `prefix`; the
    /// still-unprocessed suffix (`current[component_end..]`) is re-appended
    /// verbatim for the next walk pass, which normalizes and classifies it.
    fn expand_link(
        prefix: &[u8],
        component_end: usize,
        current: &Path,
        target: &[u8],
    ) -> Result<Path, VfsError> {
        if target.is_empty() || target.len() > MAX_LINK || target.contains(&0) {
            return Err(VfsError::InvalidPath);
        }
        let mut replacement = Path::new();
        if target.first() == Some(&b'/') {
            replacement.extend(target)?;
        } else {
            let parent_end = prefix.iter().rposition(|byte| *byte == b'/').unwrap_or(0);
            if parent_end == 0 {
                replacement.extend(b"/")?;
            } else {
                replacement.extend(&prefix[..parent_end])?;
                replacement.extend(b"/")?;
            }
            replacement.extend(target)?;
        }
        if component_end < current.len {
            replacement.extend(&current.bytes[component_end..current.len])?;
        }
        normalize(replacement.as_bytes())
    }
}

/// Map one base-image record onto [`FileMetadata`] (G07b). A symlink
/// reports its stored link-target length as `size`, matching Linux
/// `lstat` (`st_size` counts the link-target bytes); directories report
/// the stored size.
fn base_metadata(entry: Entry<'_>) -> Result<FileMetadata, VfsError> {
    let size = match entry.kind {
        NodeKind::File => entry.size,
        NodeKind::Symlink => entry.link.len() as u64,
        NodeKind::Directory => entry.size,
    };
    Ok(FileMetadata {
        kind: entry.kind,
        mode: entry.mode,
        size,
        uid: entry.uid,
        gid: entry.gid,
        ino: path_ino(entry.path),
    })
}

/// Deterministic pseudo-inode for one canonical path (G07b): FNV-1a over
/// the path bytes, so every view of one entry agrees without host state.
/// Zero maps to 1 (`st_ino` 0 reads as "unknown" to some tools).
fn path_ino(path: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in path {
        hash ^= *byte as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }
    if hash == 0 {
        1
    } else {
        hash
    }
}

/// Immediate child component of `path` under `dir`, or `None` when `path`
/// is not directly inside `dir`.
fn child_name<'x>(dir: &[u8], path: &'x [u8]) -> Option<&'x [u8]> {
    if path == b"/" || path.len() <= dir.len() {
        return None;
    }
    let rest = if dir == b"/" {
        &path[1..]
    } else {
        if !path.starts_with(dir) || path.get(dir.len()) != Some(&b'/') {
            return None;
        }
        &path[dir.len() + 1..]
    };
    if rest.is_empty() || rest.contains(&b'/') {
        return None;
    }
    Some(rest)
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, VfsError> {
    let value = bytes
        .get(offset..offset + 2)
        .ok_or(VfsError::InvalidIndex)?;
    Ok(u16::from_le_bytes(value.try_into().unwrap()))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, VfsError> {
    let value = bytes
        .get(offset..offset + 4)
        .ok_or(VfsError::InvalidIndex)?;
    Ok(u32::from_le_bytes(value.try_into().unwrap()))
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, VfsError> {
    let value = bytes
        .get(offset..offset + 8)
        .ok_or(VfsError::InvalidIndex)?;
    Ok(u64::from_le_bytes(value.try_into().unwrap()))
}
