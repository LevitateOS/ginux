#![no_std]

use core::ops::{Deref, DerefMut};

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
pub const O_APPEND: u32 = 32;
pub const O_EXCLUSIVE: u32 = 64;
pub const O_NONBLOCK: u32 = 128;

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
    DirectoryNotEmpty,
    TextBusy,
    SymlinkLoop,
    PermissionDenied,
    InvalidDescriptor,
    DescriptorLimit,
    OverlayLimit,
    FileTooLarge,
    AlreadyExists,
    /// A value that names no path is out of range or malformed.
    InvalidArgument,
    Io,
}

/// Where `seek` measures its offset from.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Whence {
    Start,
    Current,
    End,
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
                || entry.path.contains(&0)
                || entry.link.contains(&0)
                || previous.is_some_and(|value| value >= entry.path)
                || (entry.kind == NodeKind::File
                    && entry.data_offset.checked_add(entry.size).is_none())
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
        let path = resolve_components(path, true, false, |name, link| {
            let entry = self.lookup_exact(name)?;
            if entry.link.len() > link.len() {
                return Err(VfsError::InvalidPath);
            }
            link[..entry.link.len()].copy_from_slice(entry.link);
            Ok((entry.kind, entry.link.len()))
        })?;
        self.lookup_exact(path.as_bytes())
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
        || entry.path.contains(&0)
        || entry.link.contains(&0)
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

/// Resolve a composed namespace with the same component walker used by the VFS.
pub fn resolve_namespace(
    path: &[u8],
    follow_final: bool,
    missing: bool,
    output: &mut [u8; MAX_PATH],
    lookup: impl FnMut(&[u8], &mut [u8; MAX_PATH]) -> Result<(NodeKind, usize), VfsError>,
) -> Result<usize, VfsError> {
    let path = resolve_components(path, follow_final, missing, lookup)?;
    output[..path.len].copy_from_slice(path.as_bytes());
    Ok(path.len)
}

// Walk original components: collapsing `..` first can skip a link or erase
// a missing/non-directory component before it has been checked.
fn resolve_components(
    input: &[u8],
    follow_final: bool,
    allow_missing: bool,
    mut lookup: impl FnMut(&[u8], &mut [u8; MAX_PATH]) -> Result<(NodeKind, usize), VfsError>,
) -> Result<Path, VfsError> {
    if input.first() != Some(&b'/') || input.contains(&0) {
        return Err(VfsError::InvalidPath);
    }
    let mut pending = Path::new();
    pending.extend(input)?;
    let mut current = Path::new();
    current.extend(b"/")?;
    let mut position = 1;
    let mut followed = 0;
    while position < pending.len {
        let end = pending.bytes[position..pending.len]
            .iter()
            .position(|byte| *byte == b'/')
            .map_or(pending.len, |offset| position + offset);
        let component = &pending.bytes[position..end];
        if component.is_empty() || component == b"." {
            position = end + 1;
            continue;
        }
        if component == b".." {
            if current.len == 1 {
                return Err(VfsError::InvalidPath);
            }
            current.len = current
                .as_bytes()
                .iter()
                .rposition(|byte| *byte == b'/')
                .unwrap()
                .max(1);
            position = end + 1;
            continue;
        }
        let parent_len = current.len;
        if current.len > 1 {
            current.extend(b"/")?;
        }
        current.extend(component)?;
        let last = end == pending.len;
        let mut link = [0u8; MAX_PATH];
        let (kind, length) = match lookup(current.as_bytes(), &mut link) {
            Ok(entry) => entry,
            Err(VfsError::NotFound) if last && allow_missing => return Ok(current),
            Err(error) => return Err(error),
        };
        if kind == NodeKind::Symlink && (follow_final || !last) {
            if followed == 16 {
                return Err(VfsError::SymlinkLoop);
            }
            followed += 1;
            if length == 0 {
                return Err(VfsError::NotFound);
            }
            let target = link.get(..length).ok_or(VfsError::InvalidPath)?;
            if target.contains(&0) {
                return Err(VfsError::InvalidPath);
            }
            current.len = if target[0] == b'/' { 1 } else { parent_len };
            let mut replacement = Path::new();
            replacement.extend(target)?;
            replacement.extend(&pending.bytes[end..pending.len])?;
            pending = replacement;
            position = 0;
            continue;
        }
        if !last && kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        position = end + 1;
    }
    Ok(current)
}

pub trait BaseReader {
    fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), VfsError>;
}

/// Explicit instance inode timestamps, independent of host file identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Timestamp {
    pub seconds: i64,
    pub nanoseconds: u32,
}
impl Timestamp {
    pub const ZERO: Self = Self {
        seconds: 0,
        nanoseconds: 0,
    };
}

/// Image/overlay metadata using only virtual inode identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    pub accessed: Timestamp,
    pub modified: Timestamp,
    pub inode: u64,
    pub kind: NodeKind,
    pub mode: u32,
    pub size: u64,
    pub links: u64,
}

/// A VFS-owned executable reference. Retain/release explicitly when process
/// ownership changes; an unlinked executable cannot be recycled while pinned.
#[derive(Clone, Copy)]
pub struct Executable {
    object: usize,
    entry: usize,
    pub size: usize,
}

pub struct DirectoryEntry<'a> {
    pub name: &'a [u8],
    pub inode: u64,
    pub kind: NodeKind,
    pub next: u64,
}

fn beneath(path: &[u8], parent: &[u8]) -> bool {
    path == parent
        || path
            .strip_prefix(parent)
            .is_some_and(|suffix| suffix.first() == Some(&b'/'))
}

fn dot_entry(path: &[u8]) -> bool {
    path.rsplit(|byte| *byte == b'/')
        .find(|component| !component.is_empty())
        .is_some_and(|component| matches!(component, b"." | b".."))
}

fn child_name<'a>(directory: &[u8], path: &'a [u8]) -> Option<&'a [u8]> {
    let name = if directory == b"/" {
        path.strip_prefix(b"/")?
    } else {
        path.strip_prefix(directory)?.strip_prefix(b"/")?
    };
    (!name.is_empty() && !name.contains(&b'/')).then_some(name)
}

/// What an overlay slot currently holds. A whiteout hides a base entry and
/// keeps an unlinked file's bytes alive until its last descriptor closes; a
/// link is another name for the object a different slot stores.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Slot {
    Free,
    File,
    Whiteout,
    Directory,
    Symlink,
    Link,
}

#[derive(Clone, Copy)]
pub struct OverlayFile {
    accessed: Timestamp,
    modified: Timestamp,
    state: Slot,
    path: Path,
    mode: u32,
    len: usize,
    executions: usize,
    links: u64,
    object: Option<usize>,
    name_pins: usize,
}

impl OverlayFile {
    pub const fn empty() -> Self {
        Self {
            accessed: Timestamp::ZERO,
            modified: Timestamp::ZERO,
            state: Slot::Free,
            path: Path::new(),
            mode: 0,
            len: 0,
            executions: 0,
            links: 0,
            object: None,
            name_pins: 0,
        }
    }
}

#[derive(Clone, Copy)]
struct Descriptor {
    open: bool,
    overlay: bool,
    object: usize,
    entry: usize,
    description: usize,
    readable: bool,
    writable: bool,
    close_on_exec: bool,
    directory: bool,
}

/// State shared by every descriptor duplicated from one open: Linux keeps
/// the offset and the status flags on the open file description.
#[derive(Clone, Copy)]
struct Description {
    offset: usize,
    append: bool,
    nonblocking: bool,
}

impl Description {
    const fn new(flags: u32) -> Self {
        Self {
            offset: 0,
            append: flags & O_APPEND != 0,
            nonblocking: flags & O_NONBLOCK != 0,
        }
    }
}

impl Descriptor {
    const fn empty() -> Self {
        Self {
            open: false,
            overlay: false,
            object: 0,
            entry: 0,
            description: 0,
            readable: false,
            writable: false,
            close_on_exec: false,
            directory: false,
        }
    }
}

/// Overlay bytes are separate from names, metadata and open descriptions.
/// Operations must validate allocation/ranges before publishing bytes. A failed
/// resize preserves the previous readable contents and zeroes newly exposed
/// bytes on success. Reads/writes within that length must not allocate; failed
/// writes leave their range unchanged. Clear is idempotent.
/// Slots are owned by VirtualFs and are below its namespace capacity.
/// A custom namespace and storage must provide matching slot capacities.
pub trait OverlayStorage {
    fn resize(&mut self, slot: usize, old_len: usize, new_len: usize) -> Result<(), VfsError>;
    fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<(), VfsError>;
    fn write(&mut self, slot: usize, offset: usize, input: &[u8]) -> Result<(), VfsError>;
    fn clear(&mut self, slot: usize);
}

/// Allocation-free backing retained for small/freestanding VFS users.
pub struct InlineStorage<const FILES: usize, const FILE_SIZE: usize> {
    data: [[u8; FILE_SIZE]; FILES],
}
impl<const FILES: usize, const FILE_SIZE: usize> Default for InlineStorage<FILES, FILE_SIZE> {
    fn default() -> Self {
        Self {
            data: [[0; FILE_SIZE]; FILES],
        }
    }
}
impl<const FILES: usize, const FILE_SIZE: usize> OverlayStorage
    for InlineStorage<FILES, FILE_SIZE>
{
    fn resize(&mut self, slot: usize, old_len: usize, new_len: usize) -> Result<(), VfsError> {
        if new_len > FILE_SIZE {
            return Err(VfsError::FileTooLarge);
        }
        if new_len > old_len {
            self.data[slot][old_len..new_len].fill(0);
        }
        Ok(())
    }
    fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<(), VfsError> {
        let end = offset
            .checked_add(output.len())
            .ok_or(VfsError::FileTooLarge)?;
        output.copy_from_slice(self.data[slot].get(offset..end).ok_or(VfsError::Io)?);
        Ok(())
    }
    fn write(&mut self, slot: usize, offset: usize, input: &[u8]) -> Result<(), VfsError> {
        let end = offset
            .checked_add(input.len())
            .ok_or(VfsError::FileTooLarge)?;
        self.data[slot]
            .get_mut(offset..end)
            .ok_or(VfsError::Io)?
            .copy_from_slice(input);
        Ok(())
    }
    fn clear(&mut self, _: usize) {
        // Resize zeroes bytes before a later object can expose them again.
    }
}

/// Inline names for freestanding users. Larger adapters may supply a bounded
/// namespace backed by their own allocation instead of a giant stack array.
pub struct InlineNamespace<const FILES: usize>([OverlayFile; FILES]);
impl<const FILES: usize> Deref for InlineNamespace<FILES> {
    type Target = [OverlayFile];
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl<const FILES: usize> DerefMut for InlineNamespace<FILES> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

pub struct VirtualFs<
    'a,
    R,
    const FILES: usize,
    const FILE_SIZE: usize,
    const FDS: usize,
    S = InlineStorage<FILES, FILE_SIZE>,
    N = InlineNamespace<FILES>,
> {
    index: Index<'a>,
    reader: R,
    overlay: N,
    storage: S,
    descriptors: [Descriptor; FDS],
    descriptions: [Description; FDS],
}

impl<'a, R: BaseReader, const FILES: usize, const FILE_SIZE: usize, const FDS: usize>
    VirtualFs<'a, R, FILES, FILE_SIZE, FDS>
{
    pub fn new(index: Index<'a>, reader: R) -> Self {
        Self::with_storage(index, reader, InlineStorage::default())
    }
}

impl<
        'a,
        R: BaseReader,
        const FILES: usize,
        const FILE_SIZE: usize,
        const FDS: usize,
        S: OverlayStorage,
    > VirtualFs<'a, R, FILES, FILE_SIZE, FDS, S>
{
    pub fn with_storage(index: Index<'a>, reader: R, storage: S) -> Self {
        Self {
            index,
            reader,
            storage,
            overlay: InlineNamespace([OverlayFile::empty(); FILES]),
            descriptors: [Descriptor::empty(); FDS],
            descriptions: [Description::new(0); FDS],
        }
    }
}

impl<
        'a,
        R: BaseReader,
        const FILES: usize,
        const FILE_SIZE: usize,
        const FDS: usize,
        S: OverlayStorage,
        N: Deref<Target = [OverlayFile]> + DerefMut,
    > VirtualFs<'a, R, FILES, FILE_SIZE, FDS, S, N>
{
    /// Storage must service every slot in the supplied empty namespace.
    pub fn with_namespace(index: Index<'a>, reader: R, storage: S, namespace: N) -> Self {
        Self {
            index,
            reader,
            storage,
            overlay: namespace,
            descriptors: [Descriptor::empty(); FDS],
            descriptions: [Description::new(0); FDS],
        }
    }
    pub fn namespace_capacity(&self) -> usize {
        self.overlay.len()
    }

    /// Adapter-owned flush/lock operations may use the backing of any open
    /// regular file, including write-only descriptions.
    pub fn descriptor_storage(&mut self, descriptor: i32) -> Result<(&mut S, usize), VfsError> {
        let fd = self.descriptors[self.descriptor(descriptor)?];
        if !fd.overlay || fd.directory {
            return Err(VfsError::InvalidDescriptor);
        }
        Ok((&mut self.storage, fd.object))
    }

    /// Readable regular-file backing for an adapter-owned mapping reference.
    pub fn readable_storage(&mut self, descriptor: i32) -> Result<(&mut S, usize), VfsError> {
        let fd = self.descriptors[self.descriptor(descriptor)?];
        if !fd.overlay || fd.directory || !fd.readable {
            return Err(VfsError::PermissionDenied);
        }
        Ok((&mut self.storage, fd.object))
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn open(&mut self, path: &[u8], flags: u32) -> Result<i32, VfsError> {
        let exclusive = flags & (O_CREATE | O_EXCLUSIVE) == (O_CREATE | O_EXCLUSIVE);
        let path = self.resolved_path(path, !exclusive, flags & O_CREATE != 0)?;
        let writable = flags & O_WRITE != 0;
        let readable = flags & O_READ != 0;
        if !writable && !readable {
            return Err(VfsError::PermissionDenied);
        }
        if flags & O_TRUNC != 0 && !writable {
            return Err(VfsError::PermissionDenied);
        }
        if exclusive {
            match self.metadata_at(path.as_bytes()) {
                Ok(_) => return Err(VfsError::AlreadyExists),
                Err(VfsError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        // Reserve capacity before any operation can create, copy up or truncate.
        let slot = self
            .descriptors
            .iter()
            .position(|descriptor| !descriptor.open)
            .ok_or(VfsError::DescriptorLimit)?;
        // Duplicates share a description until their last close. A free
        // descriptor implies a description no live descriptor references.
        let description = (0..FDS)
            .find(|description| {
                !self
                    .descriptors
                    .iter()
                    .any(|fd| fd.open && fd.description == *description)
            })
            .ok_or(VfsError::DescriptorLimit)?;
        let overlay_index = self.find_overlay(path.as_bytes());
        let object: usize;
        let overlay: bool;
        match overlay_index {
            Some(index) if self.overlay[index].state == Slot::Whiteout => {
                if flags & O_CREATE == 0 {
                    return Err(VfsError::NotFound);
                }
                object = self.create_overlay(path, 0o600)?;
                overlay = true;
            }
            Some(index) if self.overlay[index].state == Slot::Directory => {
                return Err(VfsError::IsDirectory)
            }
            Some(index) if self.overlay[index].state == Slot::Symlink => {
                return Err(VfsError::SymlinkLoop)
            }
            Some(index) => {
                let index = self.object(index);
                if writable && self.overlay[index].executions != 0 {
                    return Err(VfsError::TextBusy);
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
                        object = if flags & O_TRUNC != 0 {
                            // Truncation discards image bytes; copying them first
                            // can incorrectly exhaust a smaller owned backing.
                            self.create_overlay(path, entry.mode)?
                        } else {
                            self.copy_to_overlay(path, entry)?
                        };
                        overlay = true;
                    } else {
                        object = self
                            .find_base_record(entry.path)
                            .ok_or(VfsError::InvalidIndex)?;
                        overlay = false;
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
            self.storage.resize(object, self.overlay[object].len, 0)?;
            self.overlay[object].len = 0;
        }

        let entry = if overlay {
            self.find_overlay(path.as_bytes()).unwrap()
        } else {
            object
        };
        self.descriptions[description] = Description::new(flags);
        self.descriptors[slot] = Descriptor {
            open: true,
            overlay,
            object,
            entry,
            description,
            readable,
            writable,
            close_on_exec: flags & O_CLOEXEC != 0,
            directory: false,
        };
        Ok(slot as i32 + 3)
    }

    /// Reopen the same object with a fresh read offset, including an unlinked
    /// file. This is not dup: status flags and offsets belong to the new open
    /// description. The caller supplies authority through an existing handle.
    pub fn reopen_readonly(&mut self, descriptor: i32, flags: u32) -> Result<i32, VfsError> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(VfsError::InvalidArgument);
        }
        let source = self.descriptors[self.descriptor(descriptor)?];
        if !source.readable {
            return Err(VfsError::PermissionDenied);
        }
        let slot = self
            .descriptors
            .iter()
            .position(|fd| !fd.open)
            .ok_or(VfsError::DescriptorLimit)?;
        let description = (0..FDS)
            .find(|description| {
                !self
                    .descriptors
                    .iter()
                    .any(|fd| fd.open && fd.description == *description)
            })
            .ok_or(VfsError::DescriptorLimit)?;
        self.descriptions[description] = Description::new(flags & O_NONBLOCK);
        self.descriptors[slot] = Descriptor {
            open: true,
            overlay: source.overlay,
            object: source.object,
            entry: source.entry,
            description,
            readable: true,
            writable: false,
            close_on_exec: flags & O_CLOEXEC != 0,
            directory: source.directory,
        };
        Ok(slot as i32 + 3)
    }

    /// Open a directory description. Enumeration cookies share this object
    /// through the launcher's aliases, just like ordinary file offsets.
    pub fn open_directory(&mut self, path: &[u8], flags: u32) -> Result<i32, VfsError> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(VfsError::InvalidArgument);
        }
        let path = self.resolved_path(path, true, false)?;
        let metadata = self.metadata_at(path.as_bytes())?;
        if metadata.kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let slot = self
            .descriptors
            .iter()
            .position(|fd| !fd.open)
            .ok_or(VfsError::DescriptorLimit)?;
        let overlay = self.find_overlay(path.as_bytes());
        let object = match overlay {
            Some(index) => index,
            None => self
                .find_base_record(self.index.resolve(path.as_bytes())?.path)
                .ok_or(VfsError::InvalidIndex)?,
        };
        let description = (0..FDS)
            .find(|description| {
                !self
                    .descriptors
                    .iter()
                    .any(|fd| fd.open && fd.description == *description)
            })
            .ok_or(VfsError::DescriptorLimit)?;
        self.descriptions[description] = Description::new(flags & O_NONBLOCK);
        self.descriptors[slot] = Descriptor {
            open: true,
            overlay: overlay.is_some(),
            object,
            entry: object,
            description,
            readable: true,
            writable: false,
            close_on_exec: flags & O_CLOEXEC != 0,
            directory: true,
        };
        Ok(slot as i32 + 3)
    }

    pub fn directory_path(&self, descriptor: i32) -> Result<&[u8], VfsError> {
        let state = self.descriptors[self.descriptor(descriptor)?];
        if !state.directory {
            return Err(VfsError::NotDirectory);
        }
        if state.overlay {
            let file = &self.overlay[state.object];
            if file.state == Slot::Whiteout {
                return Err(VfsError::NotFound);
            }
            Ok(file.path.as_bytes())
        } else {
            Ok(self.index.entry(state.object)?.path)
        }
    }

    /// A currently named filesystem object held by this descriptor. Unlinked
    /// objects and names now bound to another inode have no path in this view.
    pub fn descriptor_path(&self, descriptor: i32) -> Result<&[u8], VfsError> {
        let state = self.descriptors[self.descriptor(descriptor)?];
        if state.directory {
            return self.directory_path(descriptor);
        }
        let path = if state.overlay {
            let file = &self.overlay[state.object];
            if file.state == Slot::Whiteout {
                return Err(VfsError::NotFound);
            }
            file.path.as_bytes()
        } else {
            self.index.entry(state.object)?.path
        };
        if self.metadata_no_follow(path)?.inode != self.fstat(descriptor)?.inode {
            return Err(VfsError::NotFound);
        }
        Ok(path)
    }

    /// Inspect without consuming a cookie. The ABI adapter commits the next
    /// cookie only after complete directory records reach caller memory.
    pub fn directory_entry(
        &self,
        descriptor: i32,
        cookie: u64,
    ) -> Result<Option<DirectoryEntry<'_>>, VfsError> {
        let state = self.descriptors[self.descriptor(descriptor)?];
        if !state.directory {
            return Err(VfsError::NotDirectory);
        }
        if state.overlay && self.overlay[state.object].state == Slot::Whiteout {
            return Ok(None);
        }
        let path = self.directory_path(descriptor)?;
        if cookie < 2 {
            let inode = if cookie == 0 {
                self.fstat(descriptor)?.inode
            } else {
                let split = path.iter().rposition(|byte| *byte == b'/').unwrap_or(0);
                self.metadata(if split == 0 { b"/" } else { &path[..split] })?
                    .inode
            };
            return Ok(Some(DirectoryEntry {
                name: if cookie == 0 { b"." } else { b".." },
                inode,
                kind: NodeKind::Directory,
                next: cookie + 1,
            }));
        }
        let start = usize::try_from(cookie - 2).map_err(|_| VfsError::InvalidArgument)?;
        for ordinal in start..self.index.len() + self.overlay.len() {
            if ordinal < self.index.len() {
                let entry = self.index.entry(ordinal)?;
                if self.find_overlay(entry.path).is_some() {
                    continue;
                }
                if let Some(name) = child_name(path, entry.path) {
                    return Ok(Some(DirectoryEntry {
                        name,
                        inode: (ordinal + 1) as u64,
                        kind: entry.kind,
                        next: ordinal as u64 + 3,
                    }));
                }
            } else {
                let object = ordinal - self.index.len();
                let entry = &self.overlay[object];
                if !matches!(
                    entry.state,
                    Slot::File | Slot::Directory | Slot::Symlink | Slot::Link
                ) {
                    continue;
                }
                if let Some(name) = child_name(path, entry.path.as_bytes()) {
                    return Ok(Some(DirectoryEntry {
                        name,
                        inode: (self.index.len() + self.object(object) + 1) as u64,
                        kind: match entry.state {
                            Slot::Directory => NodeKind::Directory,
                            Slot::Symlink => NodeKind::Symlink,
                            _ => NodeKind::File,
                        },
                        next: ordinal as u64 + 3,
                    }));
                }
            }
        }
        Ok(None)
    }

    pub fn read(&mut self, descriptor: i32, output: &mut [u8]) -> Result<usize, VfsError> {
        let slot = self.descriptor(descriptor)?;
        if !self.descriptors[slot].readable {
            return Err(VfsError::PermissionDenied);
        }
        let state = self.descriptors[slot];
        if state.directory {
            return Err(VfsError::IsDirectory);
        }
        let offset = self.descriptions[state.description].offset;
        let available = if state.overlay {
            self.overlay[state.object].len.saturating_sub(offset)
        } else {
            let entry = self.index.entry(state.object)?;
            usize::try_from(entry.size)
                .map_err(|_| VfsError::FileTooLarge)?
                .saturating_sub(offset)
        };
        let length = available.min(output.len());
        if length == 0 {
            return Ok(0);
        }
        if state.overlay {
            self.storage
                .read(state.object, offset, &mut output[..length])?;
        } else {
            let entry = self.index.entry(state.object)?;
            self.reader
                .read_at(entry.data_offset + offset as u64, &mut output[..length])?;
        }
        self.descriptions[state.description].offset += length;
        Ok(length)
    }

    pub fn write(&mut self, descriptor: i32, input: &[u8]) -> Result<usize, VfsError> {
        let slot = self.descriptor(descriptor)?;
        let state = self.descriptors[slot];
        if !state.writable || !state.overlay {
            return Err(VfsError::PermissionDenied);
        }
        if self.overlay[state.object].executions != 0 {
            return Err(VfsError::TextBusy);
        }
        if input.is_empty() {
            return Ok(0);
        }
        let offset = if self.descriptions[state.description].append {
            self.overlay[state.object].len
        } else {
            self.descriptions[state.description].offset
        };
        let end = offset
            .checked_add(input.len())
            .ok_or(VfsError::FileTooLarge)?;
        let previous = self.overlay[state.object].len;
        self.storage
            .resize(state.object, previous, previous.max(end))?;
        self.storage.write(state.object, offset, input)?;
        self.overlay[state.object].len = previous.max(end);
        self.descriptions[state.description].offset = end;
        Ok(input.len())
    }

    /// Share the open-file offset while keeping close-on-exec descriptor-local.
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
        let state = self.descriptors[slot];
        self.descriptors[slot] = Descriptor::empty();
        if state.overlay {
            self.release_unlinked(state.entry);
        }
        Ok(())
    }

    pub fn close_on_exec(&mut self) {
        for slot in 0..FDS {
            if self.descriptors[slot].open && self.descriptors[slot].close_on_exec {
                let _ = self.close(slot as i32 + 3);
            }
        }
    }

    fn referenced(&self, object: usize) -> bool {
        self.descriptors
            .iter()
            .any(|fd| fd.open && fd.overlay && (fd.object == object || fd.entry == object))
    }

    fn object(&self, slot: usize) -> usize {
        self.overlay[slot].object.unwrap_or(slot)
    }

    fn link_count(&self, object: usize) -> u64 {
        self.overlay[object].links
    }

    fn remove_name(&mut self, slot: usize) {
        let object = self.object(slot);
        self.overlay[object].links = self.overlay[object]
            .links
            .checked_sub(1)
            .expect("live inode link count");
        self.overlay[slot].state = Slot::Whiteout;
        self.release_unlinked(slot);
    }

    fn release_unlinked(&mut self, slot: usize) {
        let object = self.object(slot);
        if object != slot
            && self.overlay[slot].state == Slot::Whiteout
            && self.overlay[slot].name_pins == 0
            && !self.referenced(slot)
        {
            self.overlay[slot].object = None;
        }
        if self.overlay[object].state == Slot::Whiteout
            && self.overlay[object].links == 0
            && self.overlay[object].executions == 0
            && !self.referenced(object)
        {
            self.storage.clear(object);
            self.overlay[object].len = 0;
        }
    }

    pub fn truncate(&mut self, descriptor: i32, length: u64) -> Result<(), VfsError> {
        let state = self.descriptors[self.descriptor(descriptor)?];
        if !state.overlay || !state.writable {
            return Err(VfsError::PermissionDenied);
        }
        if self.overlay[state.object].executions != 0 {
            return Err(VfsError::TextBusy);
        }
        let length = usize::try_from(length).map_err(|_| VfsError::FileTooLarge)?;
        self.storage
            .resize(state.object, self.overlay[state.object].len, length)?;
        self.overlay[state.object].len = length;
        Ok(())
    }

    pub fn unlink(&mut self, path: &[u8]) -> Result<(), VfsError> {
        let path = self.namespace_path(path, false)?;
        if let Some(index) = self.find_overlay(path.as_bytes()) {
            if self.overlay[index].state == Slot::Whiteout {
                return Err(VfsError::NotFound);
            }
            if self.overlay[index].state == Slot::Directory {
                return Err(VfsError::IsDirectory);
            }
            self.remove_name(index);
            // Open descriptors still own the removed object's bytes.
            return Ok(());
        }
        let entry = self.index.lookup_exact(path.as_bytes())?;
        if entry.kind == NodeKind::Directory {
            return Err(VfsError::IsDirectory);
        }
        let index = self.allocate_overlay()?;
        self.overlay[index] = OverlayFile {
            state: Slot::Whiteout,
            path,
            ..OverlayFile::empty()
        };
        Ok(())
    }

    pub fn pin_executable(&mut self, path: &[u8]) -> Result<Executable, VfsError> {
        let path = self.resolved_path(path, true, false)?;
        let metadata = self.metadata_at(path.as_bytes())?;
        if metadata.kind != NodeKind::File {
            return Err(VfsError::PermissionDenied);
        }
        let object = self
            .find_overlay(path.as_bytes())
            .ok_or(VfsError::PermissionDenied)?;
        self.pin_object(object)
    }

    pub fn pin_executable_fd(&mut self, descriptor: i32) -> Result<Executable, VfsError> {
        let state = self.descriptors[self.descriptor(descriptor)?];
        if !state.overlay || state.directory {
            return Err(VfsError::PermissionDenied);
        }
        self.pin_object(state.entry)
    }

    fn pin_object(&mut self, entry: usize) -> Result<Executable, VfsError> {
        let object = self.object(entry);
        if self.overlay[object].mode & 0o111 == 0 {
            return Err(VfsError::PermissionDenied);
        }
        if self
            .descriptors
            .iter()
            .any(|fd| fd.open && fd.overlay && fd.object == object && fd.writable)
        {
            return Err(VfsError::TextBusy);
        }
        let image = Executable {
            object,
            entry,
            size: self.overlay[object].len,
        };
        let executions = self.overlay[object]
            .executions
            .checked_add(1)
            .ok_or(VfsError::OverlayLimit)?;
        let names = self.overlay[entry]
            .name_pins
            .checked_add(1)
            .ok_or(VfsError::OverlayLimit)?;
        self.overlay[object].executions = executions;
        self.overlay[entry].name_pins = names;
        Ok(image)
    }

    pub fn retain_executable(&mut self, image: Executable) -> Result<(), VfsError> {
        let object = self
            .overlay
            .get(image.object)
            .ok_or(VfsError::InvalidDescriptor)?;
        let entry = self
            .overlay
            .get(image.entry)
            .ok_or(VfsError::InvalidDescriptor)?;
        if object.executions == 0
            || object.len != image.size
            || entry.name_pins == 0
            || self.object(image.entry) != image.object
        {
            return Err(VfsError::InvalidDescriptor);
        }
        let executions = object
            .executions
            .checked_add(1)
            .ok_or(VfsError::OverlayLimit)?;
        let names = entry
            .name_pins
            .checked_add(1)
            .ok_or(VfsError::OverlayLimit)?;
        self.overlay[image.object].executions = executions;
        self.overlay[image.entry].name_pins = names;

        Ok(())
    }

    pub fn release_executable(&mut self, image: Executable) -> Result<(), VfsError> {
        let object = self
            .overlay
            .get(image.object)
            .ok_or(VfsError::InvalidDescriptor)?;
        let entry = self
            .overlay
            .get(image.entry)
            .ok_or(VfsError::InvalidDescriptor)?;
        if object.executions == 0
            || object.len != image.size
            || entry.name_pins == 0
            || self.object(image.entry) != image.object
        {
            return Err(VfsError::InvalidDescriptor);
        }
        let executions = object
            .executions
            .checked_sub(1)
            .ok_or(VfsError::InvalidDescriptor)?;
        let names = entry
            .name_pins
            .checked_sub(1)
            .ok_or(VfsError::InvalidDescriptor)?;
        self.overlay[image.object].executions = executions;
        self.overlay[image.entry].name_pins = names;
        self.release_unlinked(image.entry);
        Ok(())
    }

    pub fn read_executable(
        &self,
        image: Executable,
        offset: usize,
        output: &mut [u8],
    ) -> Result<usize, VfsError> {
        let object = self
            .overlay
            .get(image.object)
            .ok_or(VfsError::InvalidDescriptor)?;
        if object.executions == 0 || object.len != image.size {
            return Err(VfsError::InvalidDescriptor);
        }
        let count = output.len().min(image.size.saturating_sub(offset));
        if count != 0 {
            self.storage
                .read(image.object, offset, &mut output[..count])?;
        }
        Ok(count)
    }

    pub fn executable_name(&self, image: Executable) -> Result<(&[u8], bool), VfsError> {
        let object = self
            .overlay
            .get(image.object)
            .ok_or(VfsError::InvalidDescriptor)?;
        if object.executions == 0 || object.len != image.size {
            return Err(VfsError::InvalidDescriptor);
        }
        let entry = self
            .overlay
            .get(image.entry)
            .ok_or(VfsError::InvalidDescriptor)?;
        if entry.name_pins == 0 || self.object(image.entry) != image.object {
            return Err(VfsError::InvalidDescriptor);
        }
        Ok((entry.path.as_bytes(), entry.state == Slot::Whiteout))
    }

    pub fn executable_pins(&self) -> usize {
        self.overlay.iter().map(|object| object.executions).sum()
    }

    pub fn teardown(&mut self) {
        for slot in 0..self.overlay.len() {
            self.storage.clear(slot);
        }
        self.overlay.fill(OverlayFile::empty());
        self.descriptors.fill(Descriptor::empty());
    }

    /// Exact live namespace identity for archive duplicate detection. This
    /// never follows a symlink or resolves an alternate name for the caller.
    pub fn named_overlay_slot(&self, path: &[u8]) -> Option<usize> {
        self.find_overlay(path)
            .filter(|slot| self.overlay[*slot].state != Slot::Whiteout)
    }

    /// Enumerate live writable entries while the caller has quiesced mutation.
    /// Slots are opaque and stable only until the next filesystem mutation.
    pub fn overlay_entry(&self, slot: usize) -> Option<(&[u8], FileMetadata)> {
        let entry = self.overlay.get(slot)?;
        if !matches!(
            entry.state,
            Slot::File | Slot::Directory | Slot::Symlink | Slot::Link
        ) {
            return None;
        }
        Some((entry.path.as_bytes(), self.overlay_metadata(slot)))
    }

    /// Read a live writable regular file without allocating a guest descriptor.
    pub fn read_overlay(
        &self,
        slot: usize,
        offset: usize,
        output: &mut [u8],
    ) -> Result<(), VfsError> {
        let entry = self.overlay.get(slot).ok_or(VfsError::NotFound)?;
        if !matches!(entry.state, Slot::File | Slot::Symlink | Slot::Link) {
            return Err(VfsError::NotFound);
        }
        let object = self.object(slot);
        if offset
            .checked_add(output.len())
            .filter(|end| *end <= self.overlay[object].len)
            .is_none()
        {
            return Err(VfsError::Io);
        }
        self.storage.read(object, offset, output)
    }

    pub fn overlay_files(&self) -> usize {
        self.overlay
            .iter()
            .filter(|entry| matches!(entry.state, Slot::File | Slot::Link))
            .count()
    }

    pub fn canonical_path(
        &self,
        path: &[u8],
        follow_final: bool,
        allow_missing: bool,
        output: &mut [u8; MAX_PATH],
    ) -> Result<usize, VfsError> {
        let resolved = self.resolved_path(path, follow_final, allow_missing)?;
        output[..resolved.len].copy_from_slice(resolved.as_bytes());
        Ok(resolved.len)
    }

    fn namespace_path(&self, path: &[u8], missing: bool) -> Result<Path, VfsError> {
        let mut end = path.len();
        while end > 1 && path[end - 1] == b'/' {
            end -= 1;
        }
        let resolved = self.resolved_path(&path[..end], false, missing)?;
        if end != path.len() {
            match self.metadata_at(resolved.as_bytes()) {
                Ok(metadata) if metadata.kind == NodeKind::Directory => {}
                Ok(_) => return Err(VfsError::NotDirectory),
                Err(VfsError::NotFound) if missing => {}
                Err(error) => return Err(error),
            }
        }
        Ok(resolved)
    }

    pub fn symlink(&mut self, target: &[u8], name: &[u8]) -> Result<(), VfsError> {
        if target.is_empty() || target.len() > MAX_PATH || target.contains(&0) {
            return Err(VfsError::InvalidPath);
        }
        if name.ends_with(b"/") {
            return Err(VfsError::NotFound);
        }
        let path = self.resolved_path(name, false, true)?;
        match self.metadata_no_follow(path.as_bytes()) {
            Ok(_) => return Err(VfsError::AlreadyExists),
            Err(VfsError::NotFound) => {}
            Err(error) => return Err(error),
        }
        self.require_parent(path.as_bytes())?;
        let slot = self.name_slot(path.as_bytes())?;
        self.storage.clear(slot);
        if let Err(error) = self
            .storage
            .resize(slot, 0, target.len())
            .and_then(|_| self.storage.write(slot, 0, target))
        {
            self.storage.clear(slot);
            return Err(error);
        }
        self.overlay[slot] = OverlayFile {
            accessed: Timestamp::ZERO,
            modified: Timestamp::ZERO,
            state: Slot::Symlink,
            path,
            mode: 0o777,
            len: target.len(),
            executions: 0,
            links: 1,
            object: None,
            name_pins: 0,
        };
        Ok(())
    }

    pub fn read_link(&self, name: &[u8], output: &mut [u8]) -> Result<usize, VfsError> {
        let path = self.resolved_path(name, false, false)?;
        if let Some(slot) = self.find_overlay(path.as_bytes()) {
            let entry = &self.overlay[slot];
            if entry.state == Slot::Whiteout {
                return Err(VfsError::NotFound);
            }
            if entry.state != Slot::Symlink {
                return Err(VfsError::InvalidArgument);
            }
            let count = entry.len.min(output.len());
            self.storage.read(slot, 0, &mut output[..count])?;
            return Ok(count);
        }
        let entry = self.index.lookup_exact(path.as_bytes())?;
        if entry.kind != NodeKind::Symlink {
            return Err(VfsError::InvalidArgument);
        }
        let count = entry.link.len().min(output.len());
        output[..count].copy_from_slice(&entry.link[..count]);
        Ok(count)
    }

    fn overlay_metadata(&self, slot: usize) -> FileMetadata {
        let object = self.object(slot);
        let entry = &self.overlay[object];
        FileMetadata {
            accessed: entry.accessed,
            modified: entry.modified,
            inode: (self.index.len() + object + 1) as u64,
            kind: match self.overlay[slot].state {
                Slot::Directory => NodeKind::Directory,
                Slot::Symlink => NodeKind::Symlink,
                _ => NodeKind::File,
            },
            mode: entry.mode,
            size: entry.len as u64,
            links: self.link_count(object),
        }
    }

    pub fn hard_link(
        &mut self,
        source: &[u8],
        destination: &[u8],
        follow: bool,
    ) -> Result<(), VfsError> {
        let source = self.resolved_path(source, follow, false)?;
        let metadata = self.metadata_no_follow(source.as_bytes())?;
        if metadata.kind != NodeKind::File {
            return Err(VfsError::PermissionDenied);
        }
        let object = self
            .find_overlay(source.as_bytes())
            .map(|slot| self.object(slot))
            .ok_or(VfsError::PermissionDenied)?;
        let directory_destination = destination.ends_with(b"/");
        let destination = self.namespace_path(destination, true)?;
        match self.metadata_no_follow(destination.as_bytes()) {
            Ok(_) => return Err(VfsError::AlreadyExists),
            Err(VfsError::NotFound) if directory_destination => return Err(VfsError::NotFound),
            Err(VfsError::NotFound) => {}
            Err(e) => return Err(e),
        }
        self.require_parent(destination.as_bytes())?;
        let links = self.overlay[object]
            .links
            .checked_add(1)
            .ok_or(VfsError::OverlayLimit)?;
        let slot = self.name_slot(destination.as_bytes())?;
        self.storage.clear(slot);
        self.overlay[object].links = links;
        self.overlay[slot] = OverlayFile {
            state: Slot::Link,
            path: destination,
            object: Some(object),
            ..OverlayFile::empty()
        };
        Ok(())
    }

    pub fn metadata_no_follow(&self, path: &[u8]) -> Result<FileMetadata, VfsError> {
        let path = self.resolved_path(path, false, false)?;
        self.metadata_at(path.as_bytes())
    }

    /// Follow image links in component order and inspect the current namespace.
    pub fn metadata(&self, path: &[u8]) -> Result<FileMetadata, VfsError> {
        let path = self.resolved_path(path, true, false)?;
        self.metadata_at(path.as_bytes())
    }

    fn metadata_at(&self, path: &[u8]) -> Result<FileMetadata, VfsError> {
        if let Some(index) = self.find_overlay(path) {
            let file = &self.overlay[index];
            if file.state == Slot::Whiteout {
                return Err(VfsError::NotFound);
            }
            return Ok(self.overlay_metadata(index));
        }
        let entry = self.index.lookup_exact(path)?;
        Ok(FileMetadata {
            accessed: Timestamp::ZERO,
            modified: Timestamp::ZERO,
            links: 1,
            inode: (self
                .find_base_record(entry.path)
                .ok_or(VfsError::InvalidIndex)?
                + 1) as u64,
            kind: entry.kind,
            mode: entry.mode,
            size: if entry.kind == NodeKind::Symlink {
                entry.link.len() as u64
            } else {
                entry.size
            },
        })
    }

    pub fn fstat(&self, descriptor: i32) -> Result<FileMetadata, VfsError> {
        let state = self.descriptors[self.descriptor(descriptor)?];
        if state.overlay {
            let file = &self.overlay[state.object];
            Ok(FileMetadata {
                accessed: file.accessed,
                modified: file.modified,
                links: self.link_count(state.object),
                inode: (self.index.len() + state.object + 1) as u64,
                kind: if state.directory {
                    NodeKind::Directory
                } else {
                    NodeKind::File
                },
                mode: file.mode,
                size: file.len as u64,
            })
        } else {
            let entry = self.index.entry(state.object)?;
            Ok(FileMetadata {
                accessed: Timestamp::ZERO,
                modified: Timestamp::ZERO,
                links: 1,
                inode: (state.object + 1) as u64,
                kind: entry.kind,
                mode: entry.mode,
                size: entry.size,
            })
        }
    }

    pub fn mkdir(&mut self, path: &[u8], mode: u32) -> Result<(), VfsError> {
        let path = self.namespace_path(path, true)?;
        match self.metadata_at(path.as_bytes()) {
            Ok(_) => return Err(VfsError::AlreadyExists),
            Err(VfsError::NotFound) => {}
            Err(error) => return Err(error),
        }
        self.require_parent(path.as_bytes())?;
        let slot = self.create_overlay(path, mode & 0o777)?;
        self.overlay[slot].state = Slot::Directory;
        Ok(())
    }

    fn has_children(&self, path: &[u8]) -> Result<bool, VfsError> {
        if self.overlay.iter().any(|entry| {
            matches!(
                entry.state,
                Slot::File | Slot::Directory | Slot::Symlink | Slot::Link
            ) && child_name(path, entry.path.as_bytes()).is_some()
        }) {
            return Ok(true);
        }
        for i in 0..self.index.len() {
            let entry = self.index.entry(i)?;
            if child_name(path, entry.path).is_some() && self.find_overlay(entry.path).is_none() {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Mutate overlay-created directories only. Image subtree mutation needs
    /// a unified resolver/whiteout model and must not be approximated here.
    pub fn remove_directory(&mut self, path: &[u8]) -> Result<(), VfsError> {
        if dot_entry(path) {
            return Err(VfsError::InvalidPath);
        }
        let path = self.namespace_path(path, false)?;
        if self.metadata_at(path.as_bytes())?.kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        let slot = self
            .find_overlay(path.as_bytes())
            .ok_or(VfsError::PermissionDenied)?;
        if self.index.lookup_exact(path.as_bytes()).is_ok() {
            return Err(VfsError::PermissionDenied);
        }
        if self.has_children(path.as_bytes())? {
            return Err(VfsError::DirectoryNotEmpty);
        }
        self.remove_name(slot);
        Ok(())
    }

    /// Atomic namespace move of overlay-created objects. Open descriptions
    /// keep their object identity; replacing a name does not replace its OFD.
    pub fn rename(
        &mut self,
        source: &[u8],
        destination: &[u8],
        no_replace: bool,
    ) -> Result<(), VfsError> {
        if dot_entry(source) || dot_entry(destination) {
            return Err(VfsError::InvalidPath);
        }
        let directory_destination = destination.ends_with(b"/");
        let source = self.namespace_path(source, false)?;
        let destination = self.namespace_path(destination, true)?;
        let metadata = self.metadata_at(source.as_bytes())?;
        if directory_destination && metadata.kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        if source.as_bytes() == destination.as_bytes() {
            return if no_replace {
                Err(VfsError::AlreadyExists)
            } else {
                Ok(())
            };
        }
        let source_slot = self
            .find_overlay(source.as_bytes())
            .ok_or(VfsError::PermissionDenied)?;
        if metadata.kind == NodeKind::Directory
            && beneath(destination.as_bytes(), source.as_bytes())
        {
            return Err(VfsError::InvalidPath);
        }
        self.require_parent(destination.as_bytes())?;
        // Do not leave a visible image name behind or expose hidden base
        // descendants when moving a tree. Configured empty memory namespaces
        // have no base entries beneath them and can use the full operation.
        for i in 0..self.index.len() {
            let path = self.index.entry(i)?.path;
            if beneath(path, source.as_bytes()) || beneath(path, destination.as_bytes()) {
                return Err(VfsError::PermissionDenied);
            }
        }
        let target = match self.metadata_at(destination.as_bytes()) {
            Ok(target) => {
                if no_replace {
                    return Err(VfsError::AlreadyExists);
                }
                match (metadata.kind, target.kind) {
                    (NodeKind::Directory, NodeKind::Directory) => {
                        if self.has_children(destination.as_bytes())? {
                            return Err(VfsError::DirectoryNotEmpty);
                        }
                    }
                    (NodeKind::Directory, _) => return Err(VfsError::NotDirectory),
                    (_, NodeKind::Directory) => return Err(VfsError::IsDirectory),
                    _ => {}
                }
                Some(
                    self.find_overlay(destination.as_bytes())
                        .ok_or(VfsError::PermissionDenied)?,
                )
            }
            Err(VfsError::NotFound) => None,
            Err(error) => return Err(error),
        };
        if target.is_some_and(|target| self.object(target) == self.object(source_slot)) {
            return Ok(());
        }
        // Check every new descendant path before changing any namespace entry.
        for entry in self.overlay.iter() {
            if matches!(
                entry.state,
                Slot::File | Slot::Directory | Slot::Symlink | Slot::Link
            ) && beneath(entry.path.as_bytes(), source.as_bytes())
            {
                let suffix = entry.path.len - source.len;
                if destination
                    .len
                    .checked_add(suffix)
                    .is_none_or(|n| n > MAX_PATH)
                {
                    return Err(VfsError::InvalidPath);
                }
            }
        }
        if let Some(target) = target {
            self.remove_name(target);
        }
        for entry in self.overlay.iter_mut() {
            if matches!(
                entry.state,
                Slot::File | Slot::Directory | Slot::Symlink | Slot::Link
            ) && beneath(entry.path.as_bytes(), source.as_bytes())
            {
                let mut path = destination;
                path.extend(&entry.path.as_bytes()[source.len..])?; // Preflight above guarantees capacity.
                entry.path = path;
            }
        }
        debug_assert_eq!(
            self.overlay[source_slot].path.as_bytes(),
            destination.as_bytes()
        );
        Ok(())
    }

    pub fn chmod(&mut self, path: &[u8], mode: u32) -> Result<(), VfsError> {
        // Callers may pass a full st_mode. File-type bits are not permissions;
        // ignore them, while retaining the existing denial of special bits.
        let mode = mode & 0o7777;
        let path = self.resolved_path(path, true, false)?;
        let slot = self
            .find_overlay(path.as_bytes())
            .ok_or(VfsError::PermissionDenied)?;
        if mode & !0o777 != 0 {
            return Err(VfsError::PermissionDenied);
        }
        let object = self.object(slot);
        self.overlay[object].mode = mode;
        Ok(())
    }

    pub fn set_times(
        &mut self,
        path: &[u8],
        follow: bool,
        accessed: Option<Timestamp>,
        modified: Option<Timestamp>,
    ) -> Result<(), VfsError> {
        let path = self.resolved_path(path, follow, false)?;
        let slot = self
            .find_overlay(path.as_bytes())
            .ok_or(VfsError::PermissionDenied)?;
        if self.overlay[slot].state == Slot::Whiteout {
            return Err(VfsError::NotFound);
        }
        self.set_object_times(self.object(slot), accessed, modified)
    }
    pub fn fset_times(
        &mut self,
        fd: i32,
        accessed: Option<Timestamp>,
        modified: Option<Timestamp>,
    ) -> Result<(), VfsError> {
        let descriptor = self.descriptors[self.descriptor(fd)?];
        if !descriptor.overlay {
            return Err(VfsError::PermissionDenied);
        }
        self.set_object_times(descriptor.object, accessed, modified)
    }
    fn set_object_times(
        &mut self,
        object: usize,
        accessed: Option<Timestamp>,
        modified: Option<Timestamp>,
    ) -> Result<(), VfsError> {
        if [accessed, modified]
            .iter()
            .flatten()
            .any(|time| time.nanoseconds >= 1_000_000_000)
        {
            return Err(VfsError::InvalidArgument);
        }
        if let Some(time) = accessed {
            self.overlay[object].accessed = time;
        }
        if let Some(time) = modified {
            self.overlay[object].modified = time;
        }
        Ok(())
    }

    pub fn fchmod(&mut self, descriptor: i32, mode: u32) -> Result<(), VfsError> {
        let mode = mode & 0o7777;
        let state = self.descriptors[self.descriptor(descriptor)?];
        if !state.overlay || mode & !0o777 != 0 {
            return Err(VfsError::PermissionDenied);
        }
        self.overlay[state.object].mode = mode;
        Ok(())
    }

    /// Seek the shared open-file position; seeking past EOF does not grow data.
    /// A position that is negative or does not fit is an invalid argument,
    /// not a file that grew too large.
    pub fn seek(&mut self, descriptor: i32, offset: i64, whence: Whence) -> Result<u64, VfsError> {
        let slot = self.descriptor(descriptor)?;
        let base = match whence {
            Whence::Start => 0,
            Whence::Current => self.descriptions[self.descriptors[slot].description].offset as u64,
            Whence::End => self.fstat(descriptor)?.size,
        };
        let position = i64::try_from(base)
            .ok()
            .and_then(|base| base.checked_add(offset))
            .filter(|position| *position >= 0)
            .and_then(|position| usize::try_from(position).ok())
            .ok_or(VfsError::InvalidArgument)?;
        self.descriptions[self.descriptors[slot].description].offset = position;
        Ok(position as u64)
    }

    /// The open's status flags, as this crate's `O_READ`, `O_WRITE`,
    /// `O_APPEND` and `O_NONBLOCK`. Callers translate them to their own ABI.
    pub fn status_flags(&self, descriptor: i32) -> Result<u32, VfsError> {
        let state = self.descriptors[self.descriptor(descriptor)?];
        let description = self.descriptions[state.description];
        let mut flags = 0;
        if state.readable {
            flags |= O_READ;
        }
        if state.writable {
            flags |= O_WRITE;
        }
        if description.append {
            flags |= O_APPEND;
        }
        if description.nonblocking {
            flags |= O_NONBLOCK;
        }
        Ok(flags)
    }

    /// Changes the open's append mode for every descriptor that shares it.
    pub fn set_append(&mut self, descriptor: i32, append: bool) -> Result<(), VfsError> {
        let state = self.descriptors[self.descriptor(descriptor)?];
        self.descriptions[state.description].append = append;
        Ok(())
    }

    pub fn is_close_on_exec(&self, descriptor: i32) -> Result<bool, VfsError> {
        Ok(self.descriptors[self.descriptor(descriptor)?].close_on_exec)
    }

    pub fn set_close_on_exec(&mut self, descriptor: i32, enabled: bool) -> Result<(), VfsError> {
        let slot = self.descriptor(descriptor)?;
        self.descriptors[slot].close_on_exec = enabled;
        Ok(())
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

    fn find_overlay(&self, path: &[u8]) -> Option<usize> {
        self.overlay
            .iter()
            .position(|entry| {
                matches!(
                    entry.state,
                    Slot::File | Slot::Directory | Slot::Symlink | Slot::Link
                ) && entry.path.as_bytes() == path
            })
            .or_else(|| {
                self.overlay.iter().position(|entry| {
                    entry.state == Slot::Whiteout && entry.path.as_bytes() == path
                })
            })
    }

    fn allocate_overlay(&self) -> Result<usize, VfsError> {
        self.overlay
            .iter()
            .position(|entry| entry.state == Slot::Free)
            .or_else(|| {
                self.overlay.iter().enumerate().position(|(slot, entry)| {
                    entry.state == Slot::Whiteout
                        && entry.executions == 0
                        && entry.name_pins == 0
                        && entry.links == 0
                        && !self.referenced(slot)
                        && (self.index.lookup_exact(entry.path.as_bytes())
                            == Err(VfsError::NotFound)
                            || self.overlay.iter().enumerate().any(|(other, candidate)| {
                                other != slot
                                    && candidate.state != Slot::Free
                                    && candidate.path.as_bytes() == entry.path.as_bytes()
                            }))
                })
            })
            .ok_or(VfsError::OverlayLimit)
    }

    fn name_slot(&self, path: &[u8]) -> Result<usize, VfsError> {
        match self.find_overlay(path) {
            Some(slot)
                if self.overlay[slot].state == Slot::Whiteout
                    && self.overlay[slot].executions == 0
                    && self.overlay[slot].name_pins == 0
                    && self.overlay[slot].links == 0
                    && !self.referenced(slot) =>
            {
                Ok(slot)
            }
            _ => self.allocate_overlay(),
        }
    }

    fn create_overlay(&mut self, path: Path, mode: u32) -> Result<usize, VfsError> {
        let index = self.name_slot(path.as_bytes())?;
        self.storage.clear(index);
        self.overlay[index] = OverlayFile {
            state: Slot::File,
            path,
            mode,
            links: 1,
            ..OverlayFile::empty()
        };
        Ok(index)
    }

    fn copy_to_overlay(&mut self, path: Path, entry: Entry<'_>) -> Result<usize, VfsError> {
        let size = usize::try_from(entry.size).map_err(|_| VfsError::FileTooLarge)?;
        entry
            .data_offset
            .checked_add(entry.size)
            .ok_or(VfsError::InvalidIndex)?;
        let index = self.create_overlay(path, entry.mode)?;
        let copied = (|| {
            self.storage.resize(index, 0, size)?;
            let mut buffer = [0u8; 4096];
            let mut offset = 0;
            while offset < size {
                let count = buffer.len().min(size - offset);
                self.reader
                    .read_at(entry.data_offset + offset as u64, &mut buffer[..count])?;
                self.storage.write(index, offset, &buffer[..count])?;
                offset += count;
            }
            Ok::<(), VfsError>(())
        })();
        if let Err(error) = copied {
            self.storage.clear(index);
            self.overlay[index] = OverlayFile::empty();
            return Err(error);
        }
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

    fn resolved_path(
        &self,
        path: &[u8],
        follow_final: bool,
        allow_missing: bool,
    ) -> Result<Path, VfsError> {
        resolve_components(path, follow_final, allow_missing, |name, target| {
            if let Some(slot) = self.find_overlay(name) {
                let entry = &self.overlay[slot];
                return match entry.state {
                    Slot::Whiteout => Err(VfsError::NotFound),
                    Slot::Directory => Ok((NodeKind::Directory, 0)),
                    Slot::Symlink => {
                        if entry.len > target.len() {
                            return Err(VfsError::InvalidPath);
                        }
                        self.storage.read(slot, 0, &mut target[..entry.len])?;
                        Ok((NodeKind::Symlink, entry.len))
                    }
                    _ => Ok((NodeKind::File, 0)),
                };
            }
            let entry = self.index.lookup_exact(name)?;
            if entry.link.len() > target.len() {
                return Err(VfsError::InvalidPath);
            }
            target[..entry.link.len()].copy_from_slice(entry.link);
            Ok((entry.kind, entry.link.len()))
        })
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
        if self.metadata(parent)?.kind != NodeKind::Directory {
            return Err(VfsError::NotDirectory);
        }
        Ok(())
    }
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

#[cfg(test)]
mod tests {
    extern crate std;
    use super::*;
    use std::vec::Vec;

    fn index_bytes() -> Vec<u8> {
        let records = [
            Entry {
                path: b"/",
                kind: NodeKind::Directory,
                mode: 0o755,
                uid: 0,
                gid: 0,
                size: 0,
                data_offset: 0,
                link: b"",
            },
            Entry {
                path: b"/base",
                kind: NodeKind::File,
                mode: 0o644,
                uid: 0,
                gid: 0,
                size: 4,
                data_offset: 0,
                link: b"",
            },
            Entry {
                path: b"/bin",
                kind: NodeKind::Symlink,
                mode: 0o777,
                uid: 0,
                gid: 0,
                size: 0,
                data_offset: 0,
                link: b"usr/bin",
            },
            Entry {
                path: b"/loop",
                kind: NodeKind::Symlink,
                mode: 0o777,
                uid: 0,
                gid: 0,
                size: 0,
                data_offset: 0,
                link: b"loop",
            },
            Entry {
                path: b"/usr",
                kind: NodeKind::Directory,
                mode: 0o755,
                uid: 0,
                gid: 0,
                size: 0,
                data_offset: 0,
                link: b"",
            },
            Entry {
                path: b"/usr/bin",
                kind: NodeKind::Directory,
                mode: 0o755,
                uid: 0,
                gid: 0,
                size: 0,
                data_offset: 0,
                link: b"",
            },
            Entry {
                path: b"/usr/bin/sh",
                kind: NodeKind::Symlink,
                mode: 0o777,
                uid: 0,
                gid: 0,
                size: 0,
                data_offset: 0,
                link: b"tool",
            },
            Entry {
                path: b"/usr/bin/tool",
                kind: NodeKind::File,
                mode: 0o755,
                uid: 0,
                gid: 0,
                size: 4,
                data_offset: 4,
                link: b"",
            },
        ];
        let mut bytes = Vec::new();
        let mut header = [0u8; HEADER_SIZE];
        encode_header(records.len() as u32, &mut header);
        bytes.extend_from_slice(&header);
        for entry in records {
            let mut record = [0u8; RECORD_SIZE];
            encode_record(entry, &mut record).unwrap();
            bytes.extend_from_slice(&record);
        }
        bytes
    }

    struct Reader([u8; 8]);
    impl BaseReader for Reader {
        fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), VfsError> {
            let offset = offset as usize;
            output.copy_from_slice(&self.0[offset..offset + output.len()]);
            Ok(())
        }
    }

    #[test]
    fn supplied_namespace_controls_capacity_without_changing_inline_defaults() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<
            '_,
            Reader,
            0,
            16,
            4,
            InlineStorage<3, 16>,
            std::vec::Vec<OverlayFile>,
        > = VirtualFs::with_namespace(
            Index::new(&bytes).unwrap(),
            Reader(*b"BASETOOL"),
            InlineStorage::default(),
            std::vec![OverlayFile::empty(); 3],
        );
        assert_eq!(fs.namespace_capacity(), 3);
        for name in [b"/one".as_slice(), b"/two", b"/three"] {
            let fd = fs.open(name, O_CREATE | O_READ | O_WRITE).unwrap();
            fs.write(fd, b"data").unwrap();
            fs.close(fd).unwrap();
        }
        assert_eq!(
            fs.open(b"/four", O_CREATE | O_WRITE),
            Err(VfsError::OverlayLimit)
        );
        let dir = fs.open_directory(b"/", 0).unwrap();
        let mut cookie = 0;
        let mut found = 0;
        while let Some(entry) = fs.directory_entry(dir, cookie).unwrap() {
            if matches!(entry.name, b"one" | b"two" | b"three") {
                found += 1;
            }
            cookie = entry.next;
        }
        assert_eq!(found, 3);
        fs.close(dir).unwrap();

        let fd = fs.open(b"/three", O_READ).unwrap();
        fs.unlink(b"/three").unwrap();
        assert_eq!(
            fs.open(b"/four", O_CREATE | O_WRITE),
            Err(VfsError::OverlayLimit)
        );
        let mut data = [0; 4];
        assert_eq!(fs.read(fd, &mut data), Ok(4));
        assert_eq!(&data, b"data");
        fs.close(fd).unwrap();
        let fd = fs.open(b"/four", O_CREATE | O_WRITE).unwrap();
        fs.close(fd).unwrap();
        fs.teardown();
        assert_eq!(fs.overlay_files(), 0);
    }

    #[test]
    fn resolves_links_before_parent_components_and_checks_each_directory() {
        let bytes = index_bytes();
        let index = Index::new(&bytes).unwrap();
        assert_eq!(index.resolve(b"/bin/..").unwrap().path, b"/usr");
        assert_eq!(index.resolve(b"/bin/../base"), Err(VfsError::NotFound));
        assert_eq!(index.resolve(b"/base/.."), Err(VfsError::NotDirectory));
        assert_eq!(index.resolve(b"/absent/.."), Err(VfsError::NotFound));
        assert_eq!(index.resolve(b"/base/"), Err(VfsError::NotDirectory));
        assert_eq!(index.resolve(b"/bin//./sh").unwrap().path, b"/usr/bin/tool");
        assert_eq!(index.resolve(b"/bin/../..").unwrap().path, b"/");
        assert_eq!(index.resolve(b"/bin/../../.."), Err(VfsError::InvalidPath));
        assert_eq!(index.resolve(b"/base\0"), Err(VfsError::InvalidPath));
        let mut vfs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        assert_eq!(vfs.open(b"/bin/../base", O_READ), Err(VfsError::NotFound));
        assert_eq!(vfs.open(b"/base/..", O_READ), Err(VfsError::NotDirectory));
        let fd = vfs.open(b"/bin/../new", O_WRITE | O_CREATE).unwrap();
        vfs.write(fd, b"new").unwrap();
        vfs.close(fd).unwrap();
        let fd = vfs.open(b"/usr/new", O_READ).unwrap();
        let mut output = [0; 3];
        assert_eq!(vfs.read(fd, &mut output), Ok(3));
        assert_eq!(&output, b"new");
        // Remove the link entry, preserving its target directory and children.
        vfs.unlink(b"/bin").unwrap();
        assert_eq!(vfs.open(b"/bin/sh", O_READ), Err(VfsError::NotFound));
        assert!(vfs.open(b"/usr/bin/tool", O_READ).is_ok());
    }

    #[test]
    fn rejects_embedded_nul_in_image_names_and_links() {
        let mut path = index_bytes();
        let last_path = HEADER_SIZE + 7 * RECORD_SIZE + 40;
        path[last_path + b"/usr/bin/tool".len() - 1] = 0;
        assert!(matches!(Index::new(&path), Err(VfsError::InvalidIndex)));

        let mut link = index_bytes();
        let first_link = HEADER_SIZE + 2 * RECORD_SIZE + 40 + MAX_PATH;
        link[first_link + 3] = 0;
        assert!(matches!(Index::new(&link), Err(VfsError::InvalidIndex)));

        let mut record = [0u8; RECORD_SIZE];
        let valid = index_bytes();
        let entry = Index::new(&valid).unwrap().entry(0).unwrap();
        assert_eq!(
            encode_record(
                Entry {
                    path: b"/bad\0name",
                    ..entry
                },
                &mut record
            ),
            Err(VfsError::InvalidPath)
        );
        assert_eq!(
            encode_record(
                Entry {
                    link: b"bad\0target",
                    ..entry
                },
                &mut record
            ),
            Err(VfsError::InvalidPath)
        );
    }

    #[test]
    fn rejects_image_file_extent_overflow() {
        let mut bytes = index_bytes();
        assert!(Index::new(&bytes).is_ok());
        let offset = HEADER_SIZE + RECORD_SIZE + 24;
        bytes[offset..offset + 8].copy_from_slice(&u64::MAX.to_le_bytes());
        assert!(matches!(Index::new(&bytes), Err(VfsError::InvalidIndex)));
    }

    #[test]
    fn validates_lookup_and_symlink_components() {
        let bytes = index_bytes();
        let index = Index::new(&bytes).unwrap();
        assert_eq!(index.resolve(b"/bin/./sh").unwrap().path, b"/usr/bin/tool");
        assert_eq!(index.resolve(b"/loop"), Err(VfsError::SymlinkLoop));
        assert_eq!(index.resolve(b"/../../base"), Err(VfsError::InvalidPath));
    }

    #[test]
    fn owned_links_resolve_components_and_preserve_namespace_operations() {
        let bytes = index_bytes();
        let index = Index::new(&bytes).unwrap();
        let mut fs: VirtualFs<'_, Reader, 16, 64, 4> = VirtualFs::new(index, Reader(*b"BASETOOL"));
        fs.mkdir(b"/work", 0o755).unwrap();
        fs.mkdir(b"/work/deep", 0o755).unwrap();
        fs.symlink(b"deep", b"/work/link").unwrap();
        fs.symlink(b"../link", b"/work/deep/chain").unwrap();
        fs.symlink(b"/work/loop", b"/work/loop").unwrap();
        let mut path = [0u8; MAX_PATH];
        let n = fs
            .canonical_path(b"/work/deep/chain/../fresh", true, true, &mut path)
            .unwrap();
        assert_eq!(&path[..n], b"/work/fresh");
        assert_eq!(
            fs.canonical_path(b"/work/loop", true, false, &mut path),
            Err(VfsError::SymlinkLoop)
        );
        let n = fs
            .canonical_path(b"/work/link", false, false, &mut path)
            .unwrap();
        assert_eq!(&path[..n], b"/work/link");
        assert_eq!(
            fs.metadata_no_follow(b"/work/link").unwrap().kind,
            NodeKind::Symlink
        );
        assert_eq!(fs.open(b"/work/link", O_READ), Err(VfsError::IsDirectory));
        assert_eq!(fs.read_link(b"/work/link", &mut path[..2]).unwrap(), 2);
        assert_eq!(&path[..2], b"de");
        fs.rename(b"/work/link", b"/work/renamed", false).unwrap();
        assert_eq!(fs.read_link(b"/work/renamed", &mut path).unwrap(), 4);
        fs.unlink(b"/work/renamed").unwrap();
        assert_eq!(
            fs.read_link(b"/work/renamed", &mut path),
            Err(VfsError::NotFound)
        );
        assert_eq!(
            fs.remove_directory(b"/work/deep"),
            Err(VfsError::DirectoryNotEmpty)
        );
        fs.symlink(b"/usr/bin/tool", b"/work/image").unwrap();
        let n = fs
            .canonical_path(b"/work/image", true, false, &mut path)
            .unwrap();
        assert_eq!(&path[..n], b"/usr/bin/tool");
        assert_eq!(
            fs.canonical_path(b"/work/image/..", true, false, &mut path),
            Err(VfsError::NotDirectory)
        );
        // Parent lookup follows the link before consuming .., in the base too.
        assert_eq!(
            fs.index.resolve(b"/bin/../bin/tool").unwrap().path,
            b"/usr/bin/tool"
        );
        fs.teardown();
    }

    #[test]
    fn link_io_follows_targets_but_namespace_changes_do_not() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 16, 16, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        assert_eq!(fs.metadata_no_follow(b"/bin").unwrap().size, 7);
        fs.mkdir(b"/work", 0o755).unwrap();
        fs.mkdir(b"/work/sub", 0o755).unwrap();
        fs.symlink(b"sub", b"/work/dir").unwrap();
        assert_eq!(
            fs.remove_directory(b"/work/dir/"),
            Err(VfsError::NotDirectory)
        );
        assert_eq!(
            fs.rename(b"/work/dir/", b"/work/moved", false),
            Err(VfsError::NotDirectory)
        );
        assert_eq!(fs.metadata(b"/work/sub").unwrap().kind, NodeKind::Directory);
        assert_eq!(
            fs.remove_directory(b"/work/dir/."),
            Err(VfsError::InvalidPath)
        );
        assert_eq!(
            fs.rename(b"/work/dir/.", b"/work/moved", false),
            Err(VfsError::InvalidPath)
        );
        fs.mkdir(b"/work/new/", 0o755).unwrap();
        fs.remove_directory(b"/work/new/").unwrap();

        fs.symlink(b"missing", b"/work/dir/link").unwrap();
        assert_eq!(fs.metadata(b"/work/sub/link"), Err(VfsError::NotFound));
        assert_eq!(
            fs.open(b"/work/sub/link", O_CREATE | O_EXCLUSIVE | O_WRITE),
            Err(VfsError::AlreadyExists)
        );
        assert_eq!(
            fs.mkdir(b"/work/sub/link", 0o755),
            Err(VfsError::AlreadyExists)
        );
        let fd = fs.open(b"/work/dir/link", O_CREATE | O_WRITE).unwrap();
        fs.write(fd, b"content").unwrap();
        fs.close(fd).unwrap();
        assert_eq!(
            fs.metadata(b"/work/sub/link").unwrap(),
            fs.metadata(b"/work/sub/missing").unwrap()
        );
        let fd = fs.open(b"/work/sub/link", O_READ).unwrap();
        fs.unlink(b"/work/sub/link").unwrap();
        let mut data = [0; 7];
        assert_eq!(fs.read(fd, &mut data).unwrap(), 7);
        assert_eq!(&data, b"content");
        fs.close(fd).unwrap();
        fs.symlink(b"missing", b"/work/sub/link").unwrap();
        let fd = fs.open(b"/work/sub/link", O_WRITE | O_TRUNC).unwrap();
        fs.close(fd).unwrap();
        assert_eq!(fs.metadata(b"/work/sub/missing").unwrap().size, 0);
        assert_eq!(
            fs.remove_directory(b"/work/dir"),
            Err(VfsError::NotDirectory)
        );
        assert_eq!(
            fs.symlink(b"target-over-capacity", b"/work/large"),
            Err(VfsError::FileTooLarge)
        );
        assert_eq!(
            fs.metadata_no_follow(b"/work/large"),
            Err(VfsError::NotFound)
        );
        fs.symlink(b"sub/link", b"/work/large").unwrap();
        fs.unlink(b"/bin").unwrap();
        fs.symlink(b"/work/sub", b"/bin").unwrap();
        assert_eq!(fs.metadata(b"/bin/missing").unwrap().size, 0);
        fs.teardown();
    }

    #[test]
    fn dangling_image_link_whiteout_stays_reserved_and_can_be_replaced() {
        let mut bytes = index_bytes();
        let mut entry = Index::new(&bytes).unwrap().entry(2).unwrap();
        entry.link = b"absent";
        let mut record = [0; RECORD_SIZE];
        encode_record(entry, &mut record).unwrap();
        bytes[HEADER_SIZE + 2 * RECORD_SIZE..HEADER_SIZE + 3 * RECORD_SIZE]
            .copy_from_slice(&record);
        let mut fs: VirtualFs<'_, Reader, 1, 16, 2> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        fs.unlink(b"/bin").unwrap();
        assert_eq!(
            fs.open(b"/fresh", O_CREATE | O_WRITE),
            Err(VfsError::OverlayLimit)
        );
        assert_eq!(fs.metadata_no_follow(b"/bin"), Err(VfsError::NotFound));
        assert_eq!(
            fs.symlink(b"target-beyond-backing-capacity", b"/bin"),
            Err(VfsError::FileTooLarge)
        );
        assert_eq!(fs.metadata_no_follow(b"/bin"), Err(VfsError::NotFound));
        fs.symlink(b"base", b"/bin").unwrap();
        let fd = fs.open(b"/bin", O_READ).unwrap();
        let mut output = [0; 4];
        assert_eq!(fs.read(fd, &mut output), Ok(4));
        assert_eq!(&output, b"BASE");
        fs.close(fd).unwrap();
        fs.teardown();
        fs.unlink(b"/bin").unwrap();
        fs.mkdir(b"/bin", 0o755).unwrap();
        assert_eq!(
            fs.metadata_no_follow(b"/bin").unwrap().kind,
            NodeKind::Directory
        );
    }

    #[test]
    fn descriptors_never_equal_base_authority_and_overlay_is_disposable() {
        let bytes = index_bytes();
        let index = Index::new(&bytes).unwrap();
        let mut vfs: VirtualFs<'_, Reader, 4, 32, 4> = VirtualFs::new(index, Reader(*b"BASETOOL"));
        let descriptor = vfs.open(b"/base", O_READ).unwrap();
        assert_eq!(descriptor, 3);
        let mut output = [0u8; 4];
        assert_eq!(vfs.read(descriptor, &mut output).unwrap(), 4);
        assert_eq!(&output, b"BASE");
        vfs.close(descriptor).unwrap();
        let descriptor = vfs.open(b"/base", O_READ | O_WRITE).unwrap();
        vfs.write(descriptor, b"edit").unwrap();
        assert_eq!(vfs.overlay_files(), 1);
        assert_eq!(&vfs.reader.0[..4], b"BASE");
        let duplicate = vfs.duplicate(descriptor, true).unwrap();
        vfs.close_on_exec();
        assert_eq!(vfs.close(duplicate), Err(VfsError::InvalidDescriptor));
        vfs.teardown();
        assert_eq!(vfs.overlay_files(), 0);
    }

    #[test]
    fn descriptor_exhaustion_does_not_create_copy_up_or_truncate() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 4, 32, 1> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let fd = vfs.open(b"/usr/product", O_WRITE | O_CREATE).unwrap();
        vfs.write(fd, b"keep").unwrap();
        vfs.close(fd).unwrap();
        let occupied = vfs.open(b"/base", O_READ).unwrap();
        assert_eq!(
            vfs.open(b"/usr/product", O_WRITE | O_TRUNC),
            Err(VfsError::DescriptorLimit)
        );
        assert_eq!(
            vfs.open(b"/usr/absent", O_WRITE | O_CREATE),
            Err(VfsError::DescriptorLimit)
        );
        assert_eq!(vfs.open(b"/base", O_WRITE), Err(VfsError::DescriptorLimit));
        assert_eq!(vfs.overlay_files(), 1);
        vfs.close(occupied).unwrap();
        assert_eq!(vfs.open(b"/usr/absent", O_READ), Err(VfsError::NotFound));
        let fd = vfs.open(b"/usr/product", O_READ).unwrap();
        let mut bytes = [0; 4];
        assert_eq!(vfs.read(fd, &mut bytes), Ok(4));
        assert_eq!(&bytes, b"keep");
    }

    #[test]
    fn failed_copy_up_preserves_image_contents_and_overlay_capacity() {
        struct FailingReader(bool);
        impl BaseReader for FailingReader {
            fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), VfsError> {
                if self.0 {
                    output.fill(b'x');
                    return Err(VfsError::Io);
                }
                Reader(*b"BASETOOL").read_at(offset, output)
            }
        }
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, FailingReader, 1, 32, 1> =
            VirtualFs::new(Index::new(&bytes).unwrap(), FailingReader(true));
        for _ in 0..3 {
            assert_eq!(vfs.open(b"/base", O_WRITE), Err(VfsError::Io));
            assert_eq!(vfs.overlay_files(), 0);
        }
        vfs.reader.0 = false;
        let fd = vfs.open(b"/base", O_READ).unwrap();
        let mut output = [0; 4];
        assert_eq!(vfs.read(fd, &mut output), Ok(4));
        assert_eq!(&output, b"BASE");
        vfs.close(fd).unwrap();
        let fd = vfs.open(b"/base", O_READ | O_WRITE).unwrap();
        assert_eq!(vfs.read(fd, &mut output), Ok(4));
        assert_eq!(&output, b"BASE");
    }

    #[test]
    fn readonly_truncate_fails_without_changing_contents() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 2, 32, 2> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let fd = vfs.open(b"/base", O_READ | O_WRITE).unwrap();
        vfs.write(fd, b"keep").unwrap();
        vfs.close(fd).unwrap();
        assert_eq!(
            vfs.open(b"/base", O_READ | O_TRUNC),
            Err(VfsError::PermissionDenied)
        );
        let fd = vfs.open(b"/base", O_READ).unwrap();
        let mut output = [0; 4];
        assert_eq!(vfs.read(fd, &mut output), Ok(4));
        assert_eq!(&output, b"keep");
    }

    #[test]
    fn hardlinks_share_identity_and_preserve_pinned_bytes_at_capacity() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 2, 32, 3> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let fd = fs.open(b"/one", O_CREATE | O_READ | O_WRITE).unwrap();
        fs.write(fd, b"shared").unwrap();
        fs.hard_link(b"/one", b"/two", false).unwrap();
        assert_eq!(fs.metadata(b"/one"), fs.metadata(b"/two"));
        assert_eq!(fs.metadata(b"/one").unwrap().links, 2);
        assert_eq!(
            fs.hard_link(b"/two", b"/three", false),
            Err(VfsError::OverlayLimit)
        );
        fs.unlink(b"/one").unwrap();
        assert_eq!(fs.overlay_files(), 1);
        assert_eq!(fs.metadata(b"/two").unwrap().links, 1);
        assert_eq!(
            fs.open(b"/one", O_CREATE | O_WRITE),
            Err(VfsError::OverlayLimit)
        );
        fs.rename(b"/two", b"/moved", false).unwrap();
        let alias = fs.open(b"/moved", O_READ | O_WRITE).unwrap();
        fs.write(alias, b"S").unwrap();
        fs.unlink(b"/moved").unwrap();
        assert_eq!(fs.fstat(fd).unwrap().links, 0);
        let mut output = [0; 6];
        fs.seek(fd, 0, Whence::Start).unwrap();
        assert_eq!(fs.read(fd, &mut output), Ok(6));
        assert_eq!(&output, b"Shared");
        fs.close(alias).unwrap();
        fs.close(fd).unwrap();
        let empty = fs.open(b"/fresh", O_CREATE | O_READ).unwrap();
        assert_eq!(fs.read(empty, &mut output), Ok(0));
    }

    #[test]
    fn hardlink_file_and_exec_references_retain_the_named_entry() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 3, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let writer = fs.open(b"/one", O_CREATE | O_WRITE).unwrap();
        fs.write(writer, b"shared").unwrap();
        fs.fchmod(writer, 0o755).unwrap();
        fs.close(writer).unwrap();
        fs.hard_link(b"/one", b"/two", false).unwrap();
        let fd = fs.open(b"/two", O_READ).unwrap();
        let dup = fs.duplicate(fd, false).unwrap();
        let reopen = fs.reopen_readonly(fd, 0).unwrap();
        let mut bytes = [0; 6];
        fs.read(fd, &mut bytes[..2]).unwrap();
        assert_eq!(&bytes[..2], b"sh");
        fs.read(dup, &mut bytes[..2]).unwrap();
        assert_eq!(&bytes[..2], b"ar");
        fs.read(reopen, &mut bytes[..2]).unwrap();
        assert_eq!(&bytes[..2], b"sh");
        assert_eq!(fs.seek(fd, 0, Whence::Current), Ok(4));
        let old = fs.pin_executable_fd(fd).unwrap();
        assert_eq!(fs.executable_name(old), Ok((b"/two".as_slice(), false)));
        fs.retain_executable(old).unwrap();
        fs.unlink(b"/two").unwrap();
        fs.hard_link(b"/one", b"/two", false).unwrap();
        let new = fs.pin_executable(b"/two").unwrap();
        fs.rename(b"/two", b"/renamed", false).unwrap();
        assert_eq!(fs.executable_name(old), Ok((b"/two".as_slice(), true)));
        assert_eq!(fs.executable_name(new), Ok((b"/renamed".as_slice(), false)));
        assert_eq!(fs.read_executable(old, 0, &mut bytes), Ok(6));
        assert_eq!(&bytes, b"shared");
        assert_eq!(fs.open(b"/one", O_WRITE), Err(VfsError::TextBusy));
        for fd in [fd, dup, reopen] {
            fs.close(fd).unwrap();
        }
        assert_eq!(
            fs.open(b"/fresh", O_CREATE | O_WRITE),
            Err(VfsError::OverlayLimit)
        );
        fs.release_executable(old).unwrap();
        assert_eq!(
            fs.open(b"/fresh", O_CREATE | O_WRITE),
            Err(VfsError::OverlayLimit)
        );
        fs.release_executable(old).unwrap();
        let fresh = fs.open(b"/fresh", O_CREATE | O_WRITE).unwrap();
        fs.close(fresh).unwrap();
        assert_eq!(fs.open(b"/one", O_WRITE), Err(VfsError::TextBusy));
        fs.release_executable(new).unwrap();
        let writer = fs.open(b"/renamed", O_WRITE).unwrap();
        fs.write(writer, b"S").unwrap();
        fs.close(writer).unwrap();
        assert_eq!(fs.metadata(b"/one"), fs.metadata(b"/renamed"));
        assert_eq!(fs.metadata(b"/one").unwrap().links, 2);
        assert_eq!(fs.executable_pins(), 0);
    }

    #[test]
    fn hardlink_creation_preserves_entries_on_failure_and_follows_only_when_requested() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let fd = fs.open(b"/one", O_CREATE | O_WRITE).unwrap();
        fs.write(fd, b"data").unwrap();
        fs.close(fd).unwrap();
        assert_eq!(
            fs.hard_link(b"/one", b"/missing/", false),
            Err(VfsError::NotFound)
        );
        assert_eq!(fs.metadata_no_follow(b"/missing"), Err(VfsError::NotFound));
        fs.symlink(b"one", b"/sym").unwrap();
        assert_eq!(
            fs.hard_link(b"/sym", b"/no-follow", false),
            Err(VfsError::PermissionDenied)
        );
        assert_eq!(fs.metadata(b"/one").unwrap().links, 1);
        fs.hard_link(b"/sym", b"/follow", true).unwrap();
        assert_eq!(fs.metadata(b"/follow"), fs.metadata(b"/one"));
        assert_eq!(fs.metadata_no_follow(b"/sym").unwrap().links, 1);
        assert_eq!(
            fs.hard_link(b"/one", b"/follow", false),
            Err(VfsError::AlreadyExists)
        );
        assert_eq!(fs.metadata(b"/one").unwrap().links, 2);
    }

    #[test]
    fn create_unlink_and_failures_are_deterministic() {
        let bytes = index_bytes();
        let index = Index::new(&bytes).unwrap();
        let mut vfs: VirtualFs<'_, Reader, 4, 8, 4> = VirtualFs::new(index, Reader(*b"BASETOOL"));
        let descriptor = vfs.open(b"/usr/new", O_WRITE | O_CREATE).unwrap();
        vfs.write(descriptor, b"new").unwrap();
        assert_eq!(
            vfs.read(descriptor, &mut [0u8; 1]),
            Err(VfsError::PermissionDenied)
        );
        assert_eq!(vfs.close(99), Err(VfsError::InvalidDescriptor));
        vfs.unlink(b"/base").unwrap();
        assert_eq!(vfs.open(b"/base", O_READ), Err(VfsError::NotFound));
        assert_eq!(
            vfs.open(b"/missing/file", O_WRITE | O_CREATE),
            Err(VfsError::NotFound)
        );
    }

    #[test]
    fn unlink_retains_open_bytes_and_recreated_names_are_independent() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 3, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let writer = vfs.open(b"/usr/new", O_WRITE | O_CREATE).unwrap();
        vfs.write(writer, b"old").unwrap();
        vfs.close(writer).unwrap();
        let old = vfs.open(b"/usr/new", O_READ).unwrap();
        let alias = vfs.duplicate(old, true).unwrap();
        vfs.unlink(b"/usr/new").unwrap();
        assert_eq!(vfs.unlink(b"/usr/new"), Err(VfsError::NotFound));
        assert_eq!(vfs.open(b"/usr/new", O_READ), Err(VfsError::NotFound));
        let fresh = vfs.open(b"/usr/new", O_WRITE | O_CREATE).unwrap();
        vfs.write(fresh, b"new").unwrap();
        vfs.close(fresh).unwrap();
        let fresh = vfs.open(b"/usr/new", O_READ).unwrap();
        let mut output = [0; 3];
        assert_eq!(vfs.read(fresh, &mut output), Ok(3));
        assert_eq!(&output, b"new");
        assert_eq!(vfs.read(old, &mut output[..1]), Ok(1));
        assert_eq!(&output[..1], b"o");
        vfs.close(old).unwrap();
        assert_eq!(vfs.read(alias, &mut output), Ok(2));
        assert_eq!(&output[..2], b"ld");
        assert_eq!(vfs.read(alias, &mut output), Ok(0));
        vfs.close_on_exec();
        assert_eq!(vfs.close(alias), Err(VfsError::InvalidDescriptor));
        vfs.close(fresh).unwrap();
    }

    #[test]
    fn closed_unlinked_slots_are_reusable_without_losing_image_whiteouts() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 2, 32, 2> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        vfs.unlink(b"/base").unwrap();
        for _ in 0..8 {
            let fd = vfs.open(b"/usr/new", O_WRITE | O_CREATE).unwrap();
            vfs.write(fd, b"fresh").unwrap();
            vfs.unlink(b"/usr/new").unwrap();
            // Open references keep the deleted slot occupied.
            assert_eq!(
                vfs.open(b"/usr/other", O_WRITE | O_CREATE),
                Err(VfsError::OverlayLimit)
            );
            vfs.close(fd).unwrap();
            let fd = vfs.open(b"/usr/other", O_WRITE | O_CREATE).unwrap();
            vfs.close(fd).unwrap();
            vfs.unlink(b"/usr/other").unwrap();
            assert_eq!(vfs.open(b"/base", O_READ), Err(VfsError::NotFound));
        }
        assert_eq!(vfs.overlay_files(), 0);
    }

    #[test]
    fn recycling_slots_preserves_whiteouts_below_image_symlinks() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 2, 32, 2> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let fd = vfs.open(b"/bin/tool", O_READ | O_WRITE).unwrap();
        vfs.unlink(b"/bin/tool").unwrap();
        vfs.close(fd).unwrap();
        for path in [b"/usr/one", b"/usr/two", b"/usr/end"] {
            let fd = vfs.open(path, O_CREATE | O_WRITE).unwrap();
            vfs.close(fd).unwrap();
            assert_eq!(vfs.open(b"/bin/tool", O_READ), Err(VfsError::NotFound));
            vfs.unlink(path).unwrap();
        }
    }

    #[test]
    fn replacing_an_open_image_copy_does_not_leak_redundant_whiteouts() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 2, 32, 3> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let old = vfs.open(b"/base", O_READ | O_WRITE).unwrap();
        vfs.write(old, b"old!").unwrap();
        let reader = vfs.open(b"/base", O_READ).unwrap();
        vfs.unlink(b"/base").unwrap();
        let replacement = vfs.open(b"/base", O_WRITE | O_CREATE).unwrap();
        vfs.write(replacement, b"new!").unwrap();
        vfs.close(replacement).unwrap();
        let mut output = [0; 4];
        assert_eq!(vfs.read(reader, &mut output), Ok(4));
        assert_eq!(&output, b"old!");
        vfs.close(reader).unwrap();
        vfs.close(old).unwrap();
        // The old image-name whiteout is redundant while its replacement exists.
        let extra = vfs.open(b"/usr/extra", O_CREATE | O_WRITE).unwrap();
        vfs.close(extra).unwrap();
        vfs.unlink(b"/usr/extra").unwrap();
        vfs.unlink(b"/base").unwrap();
        assert_eq!(vfs.open(b"/base", O_READ), Err(VfsError::NotFound));
        for _ in 0..4 {
            let fd = vfs.open(b"/base", O_CREATE | O_WRITE).unwrap();
            vfs.close(fd).unwrap();
            vfs.unlink(b"/base").unwrap();
        }
        let extra = vfs.open(b"/usr/extra", O_CREATE | O_WRITE).unwrap();
        vfs.close(extra).unwrap();
        assert_eq!(vfs.open(b"/base", O_READ), Err(VfsError::NotFound));
    }

    #[test]
    fn overlays_are_isolated_between_instances() {
        let bytes = index_bytes();
        let mut first: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let mut second: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));

        let first_base = first.open(b"/base", O_READ | O_WRITE).unwrap();
        first.write(first_base, b"edit").unwrap();
        let first_new = first.open(b"/usr/new", O_WRITE | O_CREATE).unwrap();
        first.write(first_new, b"private").unwrap();

        let second_base = second.open(b"/base", O_READ).unwrap();
        let mut output = [0u8; 4];
        assert_eq!(second.read(second_base, &mut output), Ok(4));
        assert_eq!(&output, b"BASE");
        assert_eq!(second.open(b"/usr/new", O_READ), Err(VfsError::NotFound));

        first.teardown();
        assert_eq!(first.overlay_files(), 0);
        assert_eq!(second.overlay_files(), 0);
    }

    #[test]
    fn duplicated_reads_share_offset_while_separate_opens_do_not() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let original = fs.open(b"/base", O_READ).unwrap();
        let alias = fs.duplicate(original, false).unwrap();
        let separate = fs.open(b"/base", O_READ).unwrap();
        let mut byte = [0];
        assert_eq!(fs.read(original, &mut byte), Ok(1));
        assert_eq!(&byte, b"B");
        assert_eq!(fs.read(alias, &mut byte), Ok(1));
        assert_eq!(&byte, b"A");
        assert_eq!(fs.read(separate, &mut byte), Ok(1));
        assert_eq!(&byte, b"B");
        assert_eq!(fs.read(original, &mut byte), Ok(1));
        assert_eq!(&byte, b"S");
    }

    #[test]
    fn duplicated_writes_and_reads_advance_the_same_offset() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let original = fs.open(b"/base", O_READ | O_WRITE).unwrap();
        let alias = fs.duplicate(original, false).unwrap();
        assert_eq!(fs.write(alias, b"X"), Ok(1));
        let mut byte = [0];
        assert_eq!(fs.read(original, &mut byte), Ok(1));
        assert_eq!(&byte, b"A");
        assert_eq!(fs.write(original, b"Y"), Ok(1));
        assert_eq!(fs.read(alias, &mut byte), Ok(1));
        assert_eq!(&byte, b"E");
        let separate = fs.open(b"/base", O_READ).unwrap();
        let mut contents = [0; 4];
        assert_eq!(fs.read(separate, &mut contents), Ok(4));
        assert_eq!(&contents, b"XAYE");
    }

    #[test]
    fn duplicated_offset_survives_close_slot_reuse_and_cloexec() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let original = fs.open(b"/base", O_READ).unwrap();
        let alias = fs.duplicate(original, true).unwrap();
        let mut byte = [0];
        fs.read(original, &mut byte).unwrap();
        fs.close(original).unwrap();
        let reused = fs.open(b"/base", O_READ).unwrap();
        assert_eq!(reused, original);
        fs.read(reused, &mut byte).unwrap();
        assert_eq!(&byte, b"B");
        fs.read(alias, &mut byte).unwrap();
        assert_eq!(&byte, b"A");
        fs.close_on_exec();
        assert_eq!(fs.read(alias, &mut byte), Err(VfsError::InvalidDescriptor));
        fs.read(reused, &mut byte).unwrap();
        assert_eq!(&byte, b"A");
    }

    #[test]
    fn dynamic_directories_metadata_and_sparse_append_io() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        vfs.mkdir(b"/work", 0o755).unwrap();
        vfs.mkdir(b"/work/build", 0o700).unwrap();
        assert_eq!(
            vfs.metadata(b"/work/build").unwrap().kind,
            NodeKind::Directory
        );
        assert_eq!(vfs.open(b"/work/build", O_READ), Err(VfsError::IsDirectory));
        let fd = vfs
            .open(b"/work/build/data", O_READ | O_WRITE | O_CREATE)
            .unwrap();
        vfs.seek(fd, 3, Whence::Start).unwrap();
        vfs.write(fd, b"x").unwrap();
        vfs.fchmod(fd, 0o640).unwrap();
        assert_eq!(vfs.fstat(fd).unwrap().mode, 0o640);
        assert_eq!(vfs.fstat(fd).unwrap().size, 4);
        vfs.seek(fd, 0, Whence::Start).unwrap();
        let mut output = [0xff; 8];
        assert_eq!(vfs.read(fd, &mut output), Ok(4));
        assert_eq!(&output[..4], b"\0\0\0x");
        vfs.seek(fd, 100, Whence::Start).unwrap();
        assert_eq!(vfs.read(fd, &mut output), Ok(0));
        assert_eq!(vfs.write(fd, b""), Ok(0));
        assert_eq!(vfs.fstat(fd).unwrap().size, 4);
        let append = vfs
            .open(b"/work/build/data", O_WRITE | O_APPEND | O_CLOEXEC)
            .unwrap();
        vfs.seek(append, 0, Whence::Start).unwrap();
        vfs.write(append, b"y").unwrap();
        assert_eq!(vfs.seek(append, 0, Whence::Current), Ok(5));
        assert_eq!(vfs.status_flags(append), Ok(O_WRITE | O_APPEND));
        assert_eq!(vfs.is_close_on_exec(append), Ok(true));
        assert_eq!(
            vfs.open(b"/work/build/data", O_READ | O_TRUNC),
            Err(VfsError::PermissionDenied)
        );
        assert_eq!(vfs.fstat(fd).unwrap().size, 5);
    }

    #[test]
    fn unlink_recreate_keeps_open_object_and_reclaims_closed_objects() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 2, 8, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let old = vfs.open(b"/new", O_READ | O_WRITE | O_CREATE).unwrap();
        vfs.write(old, b"old").unwrap();
        vfs.unlink(b"/new").unwrap();
        assert_eq!(vfs.unlink(b"/new"), Err(VfsError::NotFound));
        let new = vfs
            .open(b"/new", O_READ | O_WRITE | O_CREATE | O_EXCLUSIVE)
            .unwrap();
        vfs.write(new, b"new").unwrap();
        let mut output = [0; 3];
        vfs.seek(old, 0, Whence::Start).unwrap();
        vfs.read(old, &mut output).unwrap();
        assert_eq!(&output, b"old");
        assert_eq!(
            vfs.open(b"/new", O_WRITE | O_CREATE | O_EXCLUSIVE),
            Err(VfsError::AlreadyExists)
        );
        vfs.close(old).unwrap();
        vfs.close(new).unwrap();
        for _ in 0..20 {
            vfs.unlink(b"/new").unwrap();
            let fd = vfs.open(b"/new", O_WRITE | O_CREATE).unwrap();
            vfs.close(fd).unwrap();
        }
        assert_eq!(vfs.metadata(b"/new").unwrap().size, 0);
    }

    #[test]
    fn descriptor_exhaustion_does_not_create_or_truncate() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 4, 8, 1> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let fd = vfs.open(b"/new", O_WRITE | O_CREATE).unwrap();
        vfs.write(fd, b"kept").unwrap();
        assert_eq!(
            vfs.open(b"/other", O_WRITE | O_CREATE),
            Err(VfsError::DescriptorLimit)
        );
        assert_eq!(vfs.metadata(b"/other"), Err(VfsError::NotFound));
        assert_eq!(
            vfs.open(b"/new", O_WRITE | O_TRUNC),
            Err(VfsError::DescriptorLimit)
        );
        assert_eq!(vfs.fstat(fd).unwrap().size, 4);
        vfs.close(fd).unwrap();
        let fd = vfs.open(b"/new", O_WRITE | O_TRUNC).unwrap();
        assert_eq!(vfs.fstat(fd).unwrap().size, 0);
    }

    #[test]
    fn owned_paths_check_components_and_preserve_image_link_order() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 8, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        fs.mkdir(b"/work", 0o755).unwrap();
        fs.mkdir(b"/work/dir///", 0o755).unwrap();
        let fd = fs
            .open(b"/work/dir/file", O_READ | O_WRITE | O_CREATE)
            .unwrap();
        fs.write(fd, b"kept").unwrap();
        assert_eq!(
            fs.metadata(b"/work/dir/file/../file"),
            Err(VfsError::NotDirectory)
        );
        assert_eq!(
            fs.metadata(b"/work/dir/file/."),
            Err(VfsError::NotDirectory)
        );
        assert_eq!(
            fs.chmod(b"/work/missing/../dir/file", 0o777),
            Err(VfsError::NotFound)
        );
        assert_eq!(fs.fstat(fd).unwrap().mode, 0o600);
        fs.mkdir(b"/bin/../created", 0o750).unwrap();
        assert_eq!(
            fs.metadata(b"/usr/created").unwrap().kind,
            NodeKind::Directory
        );
        assert_eq!(fs.metadata(b"/created"), Err(VfsError::NotFound));
        assert_eq!(fs.metadata(b"/bin/sh").unwrap().size, 4);
    }

    #[test]
    fn exclusive_create_and_mkdir_do_not_follow_an_existing_final_link() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        assert_eq!(
            fs.open(b"/loop", O_WRITE | O_CREATE | O_EXCLUSIVE),
            Err(VfsError::AlreadyExists)
        );
        assert_eq!(
            fs.open(b"/bin/sh", O_WRITE | O_CREATE | O_EXCLUSIVE),
            Err(VfsError::AlreadyExists)
        );
        assert_eq!(fs.mkdir(b"/loop", 0o755), Err(VfsError::AlreadyExists));
        assert_eq!(fs.overlay_files(), 0);
    }

    #[test]
    fn seek_shares_alias_position_and_errors_leave_it_unchanged() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let fd = fs.open(b"/new", O_READ | O_WRITE | O_CREATE).unwrap();
        fs.write(fd, b"abc").unwrap();
        let alias = fs.duplicate(fd, false).unwrap();
        fs.seek(alias, 0, Whence::Start).unwrap();
        let mut byte = [0];
        assert_eq!(fs.read(fd, &mut byte), Ok(1));
        assert_eq!(&byte, b"a");
        assert_eq!(fs.seek(alias, i64::MAX, Whence::Start), Ok(i64::MAX as u64));
        assert_eq!(
            fs.seek(fd, 1, Whence::Current),
            Err(VfsError::InvalidArgument)
        );
        assert_eq!(
            fs.seek(fd, -1, Whence::Start),
            Err(VfsError::InvalidArgument)
        );
        assert_eq!(
            fs.seek(fd, i64::MIN, Whence::End),
            Err(VfsError::InvalidArgument)
        );
        assert_eq!(fs.seek(fd, 0, Whence::Current), Ok(i64::MAX as u64));
        assert_eq!(fs.read(fd, &mut byte), Ok(0));
        assert_eq!(fs.write(fd, b""), Ok(0));
        assert_eq!(fs.write(alias, b"x"), Err(VfsError::FileTooLarge));
        assert_eq!(fs.fstat(fd).unwrap().size, 3);
        assert_eq!(fs.seek(fd, -2, Whence::End), Ok(1));
        assert_eq!(fs.read(alias, &mut byte), Ok(1));
        assert_eq!(&byte, b"b");
    }

    #[test]
    fn metadata_and_cloexec_flags_follow_their_distinct_owners() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let fd = fs
            .open(b"/new", O_READ | O_WRITE | O_CREATE | O_APPEND | O_CLOEXEC)
            .unwrap();
        let alias = fs.duplicate(fd, false).unwrap();
        fs.chmod(b"/new", 0o750).unwrap();
        assert_eq!(fs.fstat(fd), fs.metadata(b"/new"));
        assert_eq!(fs.fstat(alias).unwrap().mode, 0o750);
        assert_eq!(fs.fchmod(alias, 0o4755), Err(VfsError::PermissionDenied));
        assert_eq!(fs.fstat(fd).unwrap().mode, 0o750);
        assert_eq!(fs.status_flags(fd), Ok(O_READ | O_WRITE | O_APPEND));
        assert_eq!(fs.status_flags(alias), Ok(O_READ | O_WRITE | O_APPEND));
        assert_eq!(fs.is_close_on_exec(fd), Ok(true));
        assert_eq!(fs.is_close_on_exec(alias), Ok(false));
        // Append is a status flag of the open, so the duplicate follows it.
        fs.set_append(alias, false).unwrap();
        assert_eq!(fs.status_flags(fd), Ok(O_READ | O_WRITE));
        fs.set_append(fd, true).unwrap();
        assert_eq!(fs.status_flags(alias), Ok(O_READ | O_WRITE | O_APPEND));
        fs.set_close_on_exec(alias, true).unwrap();
        fs.set_close_on_exec(fd, false).unwrap();
        fs.close_on_exec();
        assert_eq!(fs.fstat(alias), Err(VfsError::InvalidDescriptor));
        assert!(fs.fstat(fd).is_ok());
        let image = fs.open(b"/base", O_READ).unwrap();
        assert_eq!(fs.fchmod(image, 0o600), Err(VfsError::PermissionDenied));
        assert_eq!(fs.chmod(b"/usr", 0o700), Err(VfsError::PermissionDenied));
    }

    #[test]
    fn directory_capacity_failure_and_unlink_preserve_existing_objects() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 2, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let old = fs.open(b"/base", O_READ | O_WRITE).unwrap();
        let old_inode = fs.fstat(old).unwrap().inode;
        fs.unlink(b"/base").unwrap();
        fs.mkdir(b"/base", 0o755).unwrap();
        assert_ne!(fs.metadata(b"/base").unwrap().inode, old_inode);
        assert_eq!(fs.metadata(b"/base").unwrap().kind, NodeKind::Directory);
        assert_eq!(fs.unlink(b"/base"), Err(VfsError::IsDirectory));
        assert_eq!(fs.open(b"/base", O_READ), Err(VfsError::IsDirectory));
        assert_eq!(fs.mkdir(b"/base/child", 0o755), Err(VfsError::OverlayLimit));
        assert_eq!(fs.metadata(b"/base/child"), Err(VfsError::NotFound));
        let mut contents = [0; 4];
        assert_eq!(fs.read(old, &mut contents), Ok(4));
        assert_eq!(&contents, b"BASE");
        fs.close(old).unwrap();
        fs.mkdir(b"/base/child", 0o755).unwrap();
        assert_eq!(
            fs.metadata(b"/base/child").unwrap().kind,
            NodeKind::Directory
        );
    }

    #[test]
    fn sparse_write_after_truncate_never_restores_discarded_bytes() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 2, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let fd = fs.open(b"/new", O_READ | O_WRITE | O_CREATE).unwrap();
        fs.write(fd, b"secret").unwrap();
        let trunc = fs.open(b"/new", O_WRITE | O_TRUNC).unwrap();
        fs.close(trunc).unwrap();
        fs.seek(fd, 3, Whence::Start).unwrap();
        fs.write(fd, b"x").unwrap();
        fs.seek(fd, 0, Whence::Start).unwrap();
        let mut contents = [0xff; 4];
        assert_eq!(fs.read(fd, &mut contents), Ok(4));
        assert_eq!(&contents, b"\0\0\0x");
    }

    #[test]
    fn backing_capacity_and_truncate_preserve_contents_and_open_offset() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 4, 8, 4, InlineStorage<4, 8192>> =
            VirtualFs::with_storage(
                Index::new(&bytes).unwrap(),
                Reader(*b"BASETOOL"),
                InlineStorage::default(),
            );
        let fd = vfs.open(b"/large", O_READ | O_WRITE | O_CREATE).unwrap();
        let payload = [b'x'; 5000];
        assert_eq!(vfs.write(fd, &payload), Ok(5000));
        assert_eq!(vfs.truncate(fd, 9000), Err(VfsError::FileTooLarge));
        assert_eq!(vfs.fstat(fd).unwrap().size, 5000);
        assert_eq!(vfs.seek(fd, 0, Whence::Current), Ok(5000));
        vfs.seek(fd, 0, Whence::Start).unwrap();
        let mut output = [0; 5000];
        assert_eq!(vfs.read(fd, &mut output), Ok(5000));
        assert_eq!(output, payload);
        vfs.truncate(fd, 3).unwrap();
        assert_eq!(vfs.seek(fd, 0, Whence::Current), Ok(5000));
        vfs.truncate(fd, 8192).unwrap();
        assert_eq!(vfs.seek(fd, 0, Whence::Current), Ok(5000));
        vfs.seek(fd, 0, Whence::Start).unwrap();
        output.fill(0xff);
        assert_eq!(vfs.read(fd, &mut output), Ok(5000));
        assert_eq!(&output[..3], b"xxx");
        assert!(output[3..].iter().all(|byte| *byte == 0));
        let readonly = vfs.open(b"/large", O_READ).unwrap();
        assert_eq!(vfs.truncate(readonly, 0), Err(VfsError::PermissionDenied));
        assert_eq!(vfs.fstat(fd).unwrap().size, 8192);
        vfs.close(readonly).unwrap();
        let truncating = vfs.open(b"/large", O_WRITE | O_TRUNC).unwrap();
        assert_eq!(vfs.fstat(fd).unwrap().size, 0);
        assert_eq!(vfs.seek(fd, 0, Whence::Current), Ok(5000));
        vfs.close(truncating).unwrap();
    }

    #[test]
    fn truncate_image_does_not_need_capacity_for_discarded_contents() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 2, 2, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let image = fs.open(b"/base", O_READ).unwrap();
        let owned = fs.open(b"/base", O_READ | O_WRITE | O_TRUNC).unwrap();
        assert_eq!(fs.fstat(owned).unwrap().size, 0);
        assert_eq!(fs.write(owned, b"ok"), Ok(2));
        let mut original = [0; 4];
        assert_eq!(fs.read(image, &mut original), Ok(4));
        assert_eq!(&original, b"BASE");
        fs.seek(owned, 0, Whence::Start).unwrap();
        assert_eq!(fs.read(owned, &mut original), Ok(2));
        assert_eq!(&original[..2], b"ok");
    }

    #[test]
    fn failed_copy_up_preserves_image_and_reuses_storage_slot() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 1, 2, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        assert_eq!(fs.open(b"/base", O_WRITE), Err(VfsError::FileTooLarge));
        assert_eq!(fs.overlay_files(), 0);
        let image = fs.open(b"/base", O_READ).unwrap();
        let mut data = [0; 4];
        assert_eq!(fs.read(image, &mut data), Ok(4));
        assert_eq!(&data, b"BASE");
        let owned = fs.open(b"/new", O_READ | O_WRITE | O_CREATE).unwrap();
        assert_eq!(fs.write(owned, b"ok"), Ok(2));
        let alias = fs.duplicate(owned, true).unwrap();
        fs.unlink(b"/new").unwrap();
        fs.close(owned).unwrap();
        fs.seek(alias, 0, Whence::Start).unwrap();
        assert_eq!(fs.read(alias, &mut data), Ok(2));
        assert_eq!(&data[..2], b"ok");
        fs.close_on_exec();
        let replacement = fs.open(b"/other", O_READ | O_WRITE | O_CREATE).unwrap();
        fs.truncate(replacement, 2).unwrap();
        assert_eq!(fs.read(replacement, &mut data), Ok(2));
        assert_eq!(&data[..2], &[0, 0]);
    }

    #[test]
    fn chunked_copy_up_preserves_all_bytes_and_reclaims_partial_failure() {
        struct ChunkReader {
            fail_second: bool,
        }
        impl BaseReader for ChunkReader {
            fn read_at(&mut self, offset: u64, output: &mut [u8]) -> Result<(), VfsError> {
                if self.fail_second && offset >= 4096 {
                    return Err(VfsError::Io);
                }
                for (i, byte) in output.iter_mut().enumerate() {
                    *byte = ((offset as usize + i) % 251) as u8;
                }
                Ok(())
            }
        }
        let mut bytes = std::vec![0; HEADER_SIZE + 2 * RECORD_SIZE];
        encode_header(2, (&mut bytes[..HEADER_SIZE]).try_into().unwrap());
        for (i, (path, kind, size)) in [
            (b"/".as_slice(), NodeKind::Directory, 0),
            (b"/large".as_slice(), NodeKind::File, 9000),
        ]
        .into_iter()
        .enumerate()
        {
            let start = HEADER_SIZE + i * RECORD_SIZE;
            encode_record(
                Entry {
                    path,
                    kind,
                    mode: 0o777,
                    uid: 0,
                    gid: 0,
                    size,
                    data_offset: 0,
                    link: b"",
                },
                (&mut bytes[start..start + RECORD_SIZE]).try_into().unwrap(),
            )
            .unwrap();
        }
        for fail_second in [false, true] {
            let mut fs: VirtualFs<'_, ChunkReader, 1, 16, 2, InlineStorage<1, 12000>> =
                VirtualFs::with_storage(
                    Index::new(&bytes).unwrap(),
                    ChunkReader { fail_second },
                    InlineStorage::default(),
                );
            let image = fs.open(b"/large", O_READ).unwrap();
            let original = fs.fstat(image).unwrap();
            let mut prefix = [0; 3];
            assert_eq!(fs.read(image, &mut prefix), Ok(3));
            assert_eq!(prefix, [0, 1, 2]);
            let opened = fs.open(b"/large", O_READ | O_WRITE);
            if fail_second {
                assert_eq!(opened, Err(VfsError::Io));
                assert_eq!(fs.overlay_files(), 0);
                assert_eq!(fs.fstat(image), Ok(original));
                assert_eq!(fs.seek(image, 0, Whence::Current), Ok(3));
                let mut untouched = [0; 2];
                assert_eq!(fs.read(image, &mut untouched), Ok(2));
                assert_eq!(untouched, [3, 4]);
                let new = fs.open(b"/new", O_READ | O_WRITE | O_CREATE).unwrap();
                assert_eq!(fs.write(new, b"ok"), Ok(2));
                fs.seek(new, 0, Whence::Start).unwrap();
                let mut output = [0; 2];
                assert_eq!(fs.read(new, &mut output), Ok(2));
                assert_eq!(&output, b"ok");
            } else {
                let fd = opened.unwrap();
                let mut output = [0; 9000];
                assert_eq!(fs.read(fd, &mut output), Ok(9000));
                for (i, byte) in output.into_iter().enumerate() {
                    assert_eq!(byte, (i % 251) as u8);
                }
            }
        }
    }

    #[test]
    fn directory_records_merge_names_and_keep_cookies_explicit() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        vfs.mkdir(b"/work", 0o755).unwrap();
        let file = vfs.open(b"/work/file", O_CREATE | O_WRITE).unwrap();
        vfs.close(file).unwrap();
        vfs.mkdir(b"/work/nested", 0o755).unwrap();
        let leaf = vfs.open(b"/work/nested/leaf", O_CREATE | O_WRITE).unwrap();
        vfs.close(leaf).unwrap();
        let dir = vfs
            .open_directory(b"/work", O_CLOEXEC | O_NONBLOCK)
            .unwrap();
        assert_eq!(vfs.fstat(dir).unwrap().kind, NodeKind::Directory);
        assert_eq!(vfs.status_flags(dir), Ok(O_READ | O_NONBLOCK));
        assert_eq!(vfs.is_close_on_exec(dir), Ok(true));
        assert_eq!(vfs.read(dir, &mut [0; 4]), Err(VfsError::IsDirectory));
        let mut names = Vec::new();
        let mut cookie = 0;
        while let Some(entry) = vfs.directory_entry(dir, cookie).unwrap() {
            assert!(entry.next > cookie);
            names.push(entry.name.to_vec());
            cookie = entry.next;
        }
        assert_eq!(
            names,
            std::vec![
                b".".to_vec(),
                b"..".to_vec(),
                b"file".to_vec(),
                b"nested".to_vec()
            ]
        );
        assert_eq!(vfs.seek(dir, 0, Whence::Current), Ok(0)); // Peeking did not consume anything.
        vfs.seek(dir, cookie as i64, Whence::Start).unwrap();
        assert!(vfs.directory_entry(dir, cookie).unwrap().is_none());
        assert_eq!(vfs.directory_path(dir), Ok(b"/work".as_slice()));
        vfs.close_on_exec();
        assert_eq!(vfs.fstat(dir), Err(VfsError::InvalidDescriptor));
        let root = vfs.open_directory(b"/", 0).unwrap();
        let mut cookie = 2;
        let mut names = Vec::new();
        while let Some(entry) = vfs.directory_entry(root, cookie).unwrap() {
            names.push(entry.name.to_vec());
            cookie = entry.next;
        }
        assert!(names.contains(&b"work".to_vec()));
        assert!(!names.contains(&b"leaf".to_vec()));
    }

    #[test]
    fn rename_and_remove_preserve_open_objects_and_validate_before_mutation() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 16, 32, 8> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        vfs.mkdir(b"/work", 0o755).unwrap();
        let a = vfs.open(b"/work/a", O_READ | O_WRITE | O_CREATE).unwrap();
        vfs.write(a, b"new").unwrap();
        let b = vfs.open(b"/work/b", O_READ | O_WRITE | O_CREATE).unwrap();
        vfs.write(b, b"old").unwrap();
        let inode = vfs.fstat(a).unwrap().inode;
        assert_eq!(
            vfs.rename(b"/work/a", b"/work/b", true),
            Err(VfsError::AlreadyExists)
        );
        vfs.rename(b"/work/a", b"/work/b", false).unwrap();
        assert_eq!(vfs.metadata(b"/work/a"), Err(VfsError::NotFound));
        assert_eq!(vfs.metadata(b"/work/b").unwrap().inode, inode);
        let mut output = [0; 3];
        vfs.seek(b, 0, Whence::Start).unwrap();
        vfs.read(b, &mut output).unwrap();
        assert_eq!(&output, b"old");
        vfs.seek(a, 0, Whence::Start).unwrap();
        vfs.read(a, &mut output).unwrap();
        assert_eq!(&output, b"new");
        vfs.close(a).unwrap();
        vfs.close(b).unwrap();
        vfs.mkdir(b"/work/tree", 0o755).unwrap();
        vfs.mkdir(b"/work/tree/sub", 0o755).unwrap();
        let dir = vfs.open_directory(b"/work/tree", 0).unwrap();
        vfs.rename(b"/work/tree", b"/work/moved", false).unwrap();
        assert_eq!(vfs.directory_path(dir), Ok(b"/work/moved".as_slice()));
        assert!(vfs.metadata(b"/work/moved/sub").is_ok());
        assert_eq!(
            vfs.remove_directory(b"/work/moved"),
            Err(VfsError::DirectoryNotEmpty)
        );
        assert_eq!(
            vfs.rename(b"/work/moved", b"/work/moved/sub/bad", false),
            Err(VfsError::InvalidPath)
        );
        assert!(vfs.metadata(b"/work/moved/sub").is_ok());
        vfs.remove_directory(b"/work/moved/sub").unwrap();
        vfs.remove_directory(b"/work/moved").unwrap();
        assert_eq!(vfs.fstat(dir).unwrap().kind, NodeKind::Directory);
        assert!(vfs.directory_entry(dir, 0).unwrap().is_none());
        assert_eq!(vfs.directory_path(dir), Err(VfsError::NotFound));
        vfs.close(dir).unwrap();
        vfs.mkdir(b"/work/short", 0o755).unwrap();
        let mut long = b"/work/short/".to_vec();
        long.extend_from_slice(&[b'x'; 220]);
        let fd = vfs.open(&long, O_CREATE | O_WRITE).unwrap();
        vfs.close(fd).unwrap();
        let mut dest = b"/work/".to_vec();
        dest.extend_from_slice(&[b'd'; 40]);
        assert_eq!(
            vfs.rename(b"/work/short", &dest, false),
            Err(VfsError::InvalidPath)
        );
        assert!(vfs.metadata(&long).is_ok());
        assert_eq!(vfs.metadata(&dest), Err(VfsError::NotFound));
        let root = vfs.open_directory(b"/", 0).unwrap();
        assert_eq!(vfs.remove_directory(b"/"), Err(VfsError::PermissionDenied));
        assert_eq!(
            vfs.rename(b"/work/short", b"/", false),
            Err(VfsError::PermissionDenied)
        );
        vfs.close(root).unwrap();
    }
    #[test]
    fn directory_alias_cookies_and_image_link_paths_keep_their_owners() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 8, 32, 5> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        fs.mkdir(b"/work", 0o755).unwrap();
        let file = fs.open(b"/work/file", O_READ | O_WRITE | O_CREATE).unwrap();
        fs.write(file, b"data").unwrap();
        let dir = fs.open_directory(b"/work", 0).unwrap();
        let alias = fs.duplicate(dir, false).unwrap();
        fs.seek(alias, 2, Whence::Start).unwrap();
        assert_eq!(fs.seek(dir, 0, Whence::Current), Ok(2));
        assert_eq!(fs.directory_entry(dir, 2).unwrap().unwrap().name, b"file");
        assert_eq!(fs.seek(file, 0, Whence::Current), Ok(4));
        fs.close(dir).unwrap();
        let image = fs.open_directory(b"/bin", 0).unwrap();
        assert_eq!(fs.directory_path(image), Ok(b"/usr/bin".as_slice()));
        let parent = fs.open_directory(b"/bin/..", 0).unwrap();
        assert_eq!(fs.directory_path(parent), Ok(b"/usr".as_slice()));
        fs.close(parent).unwrap();
        fs.seek(image, 1, Whence::Start).unwrap();
        assert_eq!(fs.seek(alias, 0, Whence::Current), Ok(2));
        assert_eq!(fs.seek(file, 0, Whence::Current), Ok(4));
        fs.rename(b"/work", b"/moved", false).unwrap();
        assert_eq!(fs.directory_path(alias), Ok(b"/moved".as_slice()));
        fs.chmod(b"/moved", 0o40750).unwrap();
        fs.fchmod(file, 0o100640).unwrap();
        assert_eq!(fs.fstat(alias).unwrap().mode, 0o750);
        assert_eq!(fs.fstat(file).unwrap().mode, 0o640);
        assert_eq!(fs.fchmod(alias, 0o42755), Err(VfsError::PermissionDenied));
        assert_eq!(fs.fstat(alias).unwrap().mode, 0o750);
    }

    #[test]
    fn namespace_mutations_reject_dot_entries_without_moving_their_parent() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        fs.mkdir(b"/work", 0o755).unwrap();
        fs.mkdir(b"/work/empty", 0o755).unwrap();
        assert_eq!(
            fs.remove_directory(b"/work/empty/."),
            Err(VfsError::InvalidPath)
        );
        assert_eq!(
            fs.rename(b"/work/empty/.", b"/other", false),
            Err(VfsError::InvalidPath)
        );
        assert_eq!(
            fs.rename(b"/work/empty", b"/work/..", false),
            Err(VfsError::InvalidPath)
        );
        assert!(fs.metadata(b"/work/empty").is_ok());
        assert_eq!(fs.metadata(b"/other"), Err(VfsError::NotFound));
        fs.remove_directory(b"/work/empty/").unwrap();
        assert_eq!(fs.metadata(b"/work/empty"), Err(VfsError::NotFound));
    }

    #[test]
    fn readonly_reopen_retains_deleted_objects_with_independent_offsets() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 4, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let original = vfs.open(b"/program", O_CREATE | O_READ | O_WRITE).unwrap();
        vfs.write(original, b"old bytes").unwrap();
        let reopened = vfs
            .reopen_readonly(original, O_CLOEXEC | O_NONBLOCK)
            .unwrap();
        let inode = vfs.fstat(reopened).unwrap().inode;
        assert_eq!(vfs.seek(original, 0, Whence::Current), Ok(9));
        let mut output = [0u8; 9];
        assert_eq!(vfs.read(reopened, &mut output[..3]), Ok(3));
        assert_eq!(&output[..3], b"old");
        assert_eq!(vfs.seek(original, 0, Whence::Current), Ok(9));
        assert_eq!(vfs.write(reopened, b"no"), Err(VfsError::PermissionDenied));
        assert_eq!(vfs.truncate(reopened, 0), Err(VfsError::PermissionDenied));
        vfs.unlink(b"/program").unwrap();
        vfs.close(original).unwrap();
        let replacement = vfs.open(b"/program", O_CREATE | O_WRITE).unwrap();
        vfs.write(replacement, b"new").unwrap();
        assert_ne!(vfs.fstat(replacement).unwrap().inode, inode);
        vfs.close(replacement).unwrap();
        let again = vfs.reopen_readonly(reopened, 0).unwrap();
        vfs.close(reopened).unwrap();
        assert_eq!(vfs.read(again, &mut output), Ok(9));
        assert_eq!(&output, b"old bytes");
        vfs.close(again).unwrap();
        assert_eq!(
            vfs.reopen_readonly(again, 0),
            Err(VfsError::InvalidDescriptor)
        );
        let directory = vfs.open_directory(b"/", 0).unwrap();
        let other = vfs.reopen_readonly(directory, 0).unwrap();
        vfs.seek(directory, 1, Whence::Start).unwrap();
        assert_eq!(vfs.seek(other, 0, Whence::Current), Ok(0));
        vfs.close(directory).unwrap();
        vfs.close(other).unwrap();
    }

    #[test]
    fn executable_pins_exclude_writers_and_retain_unlinked_bytes() {
        let bytes = index_bytes();
        let mut vfs: VirtualFs<'_, Reader, 2, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let writer = vfs.open(b"/program", O_CREATE | O_READ | O_WRITE).unwrap();
        vfs.write(writer, b"executable-bytes").unwrap();
        assert!(matches!(
            vfs.pin_executable(b"/program"),
            Err(VfsError::PermissionDenied)
        ));
        vfs.fchmod(writer, 0o755).unwrap();
        assert!(matches!(
            vfs.pin_executable(b"/program"),
            Err(VfsError::TextBusy)
        ));
        vfs.close(writer).unwrap();
        let reader = vfs.open(b"/program", O_READ).unwrap();
        vfs.seek(reader, 4, Whence::Start).unwrap();
        let image = vfs.pin_executable_fd(reader).unwrap();
        assert_eq!(vfs.executable_pins(), 1);
        assert_eq!(
            vfs.open(b"/program", O_WRITE | O_TRUNC),
            Err(VfsError::TextBusy)
        );
        let mut output = [0u8; 32];
        assert_eq!(vfs.read_executable(image, 0, &mut output), Ok(16));
        assert_eq!(&output[..16], b"executable-bytes");
        assert_eq!(vfs.seek(reader, 0, Whence::Current), Ok(4));
        vfs.retain_executable(image).unwrap(); // A forked process owns another reference.
        vfs.rename(b"/program", b"/moved", false).unwrap();
        vfs.unlink(b"/moved").unwrap();
        vfs.close(reader).unwrap();
        let replacement = vfs.open(b"/moved", O_CREATE | O_WRITE).unwrap();
        vfs.write(replacement, b"new").unwrap();
        vfs.close(replacement).unwrap();
        assert_eq!(
            vfs.open(b"/other", O_CREATE | O_WRITE),
            Err(VfsError::OverlayLimit)
        );
        vfs.release_executable(image).unwrap();
        assert_eq!(vfs.executable_pins(), 1);
        assert_eq!(
            vfs.open(b"/other", O_CREATE | O_WRITE),
            Err(VfsError::OverlayLimit)
        );
        assert_eq!(vfs.read_executable(image, 0, &mut output), Ok(16));
        assert_eq!(&output[..16], b"executable-bytes");
        vfs.release_executable(image).unwrap();
        assert_eq!(vfs.executable_pins(), 0);
        let reused = vfs.open(b"/other", O_CREATE | O_READ | O_WRITE).unwrap();
        assert_eq!(vfs.read(reused, &mut output), Ok(0));
    }
    #[test]
    fn executable_name_follows_namespace_while_pinned_bytes_stay_stable() {
        let bytes = index_bytes();
        let mut fs: VirtualFs<'_, Reader, 2, 32, 4> =
            VirtualFs::new(Index::new(&bytes).unwrap(), Reader(*b"BASETOOL"));
        let writer = fs.open(b"/program", O_READ | O_WRITE | O_CREATE).unwrap();
        fs.write(writer, b"old").unwrap();
        fs.fchmod(writer, 0o755).unwrap();
        fs.close(writer).unwrap();
        let reader = fs.open(b"/program", O_READ).unwrap();
        fs.seek(reader, 1, Whence::Start).unwrap();
        let image = fs.pin_executable_fd(reader).unwrap();
        assert_eq!(
            fs.executable_name(image),
            Ok((b"/program".as_slice(), false))
        );
        fs.rename(b"/program", b"/moved", false).unwrap();
        assert_eq!(fs.executable_name(image), Ok((b"/moved".as_slice(), false)));
        fs.unlink(b"/moved").unwrap();
        assert_eq!(fs.executable_name(image), Ok((b"/moved".as_slice(), true)));
        fs.close(reader).unwrap();
        let replacement = fs.open(b"/moved", O_WRITE | O_CREATE).unwrap();
        fs.write(replacement, b"new").unwrap();
        fs.close(replacement).unwrap();
        let mut output = [0; 3];
        assert_eq!(fs.read_executable(image, 0, &mut output), Ok(3));
        assert_eq!(&output, b"old");
        fs.release_executable(image).unwrap();
        assert_eq!(fs.executable_name(image), Err(VfsError::InvalidDescriptor));
        assert_eq!(fs.executable_pins(), 0);
    }
}
