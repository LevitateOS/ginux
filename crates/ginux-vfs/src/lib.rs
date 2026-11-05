#![no_std]

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

/// Metadata from the domain image/overlay, without host inode identities.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FileMetadata {
    pub inode: u64,
    pub kind: NodeKind,
    pub mode: u32,
    pub size: u64,
}

/// A VFS-owned executable reference. Retain/release explicitly when process
/// ownership changes; an unlinked executable cannot be recycled while pinned.
#[derive(Clone, Copy)]
pub struct Executable {
    object: usize,
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

fn child_name<'a>(directory: &[u8], path: &'a [u8]) -> Option<&'a [u8]> {
    let name = if directory == b"/" {
        path.strip_prefix(b"/")?
    } else {
        path.strip_prefix(directory)?.strip_prefix(b"/")?
    };
    (!name.is_empty() && !name.contains(&b'/')).then_some(name)
}

#[derive(Clone, Copy)]
struct OverlayFile {
    state: u8,
    path: Path,
    mode: u32,
    len: usize,
    executions: usize,
}

impl OverlayFile {
    const fn empty() -> Self {
        Self {
            state: 0,
            path: Path::new(),
            mode: 0,
            len: 0,
            executions: 0,
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
    append: bool,
    directory: bool,
    nonblocking: bool,
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
            directory: false,
            nonblocking: false,
        }
    }
}

/// Overlay bytes are separate from names, metadata and open descriptions.
/// Operations must validate allocation/ranges before publishing bytes. A failed
/// resize preserves the previous readable contents; clear is idempotent.
/// Slots are owned by VirtualFs and are always below its FILES bound.
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
    fn clear(&mut self, _: usize) { /* Future growth explicitly zeroes exposed bytes. */
    }
}

pub struct VirtualFs<
    'a,
    R,
    const FILES: usize,
    const FILE_SIZE: usize,
    const FDS: usize,
    S = InlineStorage<FILES, FILE_SIZE>,
> {
    index: Index<'a>,
    reader: R,
    overlay: [OverlayFile; FILES],
    storage: S,
    descriptors: [Descriptor; FDS],
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
            overlay: [OverlayFile::empty(); FILES],
            descriptors: [Descriptor::empty(); FDS],
        }
    }

    pub fn storage(&self) -> &S {
        &self.storage
    }

    pub fn open(&mut self, path: &[u8], flags: u32) -> Result<i32, VfsError> {
        let path = normalize(path)?;
        // Exhaustion must not create or truncate a file before failing open.
        let slot = self
            .descriptors
            .iter()
            .position(|fd| !fd.open)
            .ok_or(VfsError::DescriptorLimit)?;
        let writable = flags & O_WRITE != 0;
        let readable = flags & O_READ != 0;
        if !writable && !readable {
            return Err(VfsError::PermissionDenied);
        }
        if flags & O_TRUNC != 0 && !writable {
            return Err(VfsError::PermissionDenied);
        }
        if flags & (O_CREATE | O_EXCLUSIVE) == (O_CREATE | O_EXCLUSIVE) {
            match self.metadata(path.as_bytes()) {
                Ok(_) => return Err(VfsError::AlreadyExists),
                Err(VfsError::NotFound) => {}
                Err(error) => return Err(error),
            }
        }
        let overlay_index = self.find_overlay(path.as_bytes());
        let object: usize;
        let overlay: bool;
        match overlay_index {
            Some(index) if self.overlay[index].state == 2 => {
                if flags & O_CREATE == 0 {
                    return Err(VfsError::NotFound);
                }
                object = self.create_overlay(path, 0o600)?;
                overlay = true;
            }
            Some(index) if self.overlay[index].state == 3 => return Err(VfsError::IsDirectory),
            Some(index) => {
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
                        object = self.copy_to_overlay(path, entry)?;
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
        self.descriptors[slot] = Descriptor {
            open: true,
            overlay,
            object,
            offset: 0,
            readable,
            writable,
            close_on_exec: flags & O_CLOEXEC != 0,
            append: flags & O_APPEND != 0,
            directory: false,
            nonblocking: flags & O_NONBLOCK != 0,
        };
        Ok(slot as i32 + 3)
    }

    /// Reopen the same object with a fresh read offset, including an unlinked
    /// file. This is not dup: status flags and offsets belong to the new open
    /// description. The caller supplies authority through an existing handle.
    pub fn reopen_readonly(&mut self, descriptor: i32, flags: u32) -> Result<i32, VfsError> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(VfsError::InvalidPath);
        }
        let source = self.descriptors[self.descriptor(descriptor)?];
        let slot = self
            .descriptors
            .iter()
            .position(|fd| !fd.open)
            .ok_or(VfsError::DescriptorLimit)?;
        self.descriptors[slot] = Descriptor {
            open: true,
            overlay: source.overlay,
            object: source.object,
            offset: 0,
            readable: true,
            writable: false,
            close_on_exec: flags & O_CLOEXEC != 0,
            append: false,
            directory: source.directory,
            nonblocking: flags & O_NONBLOCK != 0,
        };
        Ok(slot as i32 + 3)
    }

    /// Open a directory description. Enumeration cookies share this object
    /// through the launcher's aliases, just like ordinary file offsets.
    pub fn open_directory(&mut self, path: &[u8], flags: u32) -> Result<i32, VfsError> {
        if flags & !(O_CLOEXEC | O_NONBLOCK) != 0 {
            return Err(VfsError::InvalidPath);
        }
        let path = normalize(path)?;
        let metadata = self.metadata(path.as_bytes())?;
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
        self.descriptors[slot] = Descriptor {
            open: true,
            overlay: overlay.is_some(),
            object,
            offset: 0,
            readable: true,
            writable: false,
            close_on_exec: flags & O_CLOEXEC != 0,
            append: false,
            directory: true,
            nonblocking: flags & O_NONBLOCK != 0,
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
            if file.state == 2 {
                return Err(VfsError::NotFound);
            }
            Ok(file.path.as_bytes())
        } else {
            Ok(self.index.entry(state.object)?.path)
        }
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
        if state.overlay && self.overlay[state.object].state == 2 {
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
        let start = usize::try_from(cookie - 2).map_err(|_| VfsError::InvalidPath)?;
        for ordinal in start..self.index.len() + FILES {
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
                if !matches!(entry.state, 1 | 3) {
                    continue;
                }
                if let Some(name) = child_name(path, entry.path.as_bytes()) {
                    return Ok(Some(DirectoryEntry {
                        name,
                        inode: (self.index.len() + object + 1) as u64,
                        kind: if entry.state == 3 {
                            NodeKind::Directory
                        } else {
                            NodeKind::File
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
        let available = if state.overlay {
            self.overlay[state.object].len.saturating_sub(state.offset)
        } else {
            let entry = self.index.entry(state.object)?;
            usize::try_from(entry.size)
                .map_err(|_| VfsError::FileTooLarge)?
                .saturating_sub(state.offset)
        };
        let length = available.min(output.len());
        if length == 0 {
            return Ok(0);
        }
        if state.overlay {
            self.storage
                .read(state.object, state.offset, &mut output[..length])?;
        } else {
            let entry = self.index.entry(state.object)?;
            self.reader.read_at(
                entry.data_offset + state.offset as u64,
                &mut output[..length],
            )?;
        }
        self.descriptors[slot].offset += length;
        Ok(length)
    }

    pub fn write(&mut self, descriptor: i32, input: &[u8]) -> Result<usize, VfsError> {
        let slot = self.descriptor(descriptor)?;
        let mut state = self.descriptors[slot];
        if !state.writable || !state.overlay {
            return Err(VfsError::PermissionDenied);
        }
        if self.overlay[state.object].executions != 0 {
            return Err(VfsError::TextBusy);
        }
        if input.is_empty() {
            return Ok(0);
        }
        if state.append {
            state.offset = self.overlay[state.object].len;
        }
        let end = state
            .offset
            .checked_add(input.len())
            .ok_or(VfsError::FileTooLarge)?;
        let previous = self.overlay[state.object].len;
        self.storage
            .resize(state.object, previous, previous.max(end))?;
        self.storage.write(state.object, state.offset, input)?;
        self.overlay[state.object].len = previous.max(end);
        self.descriptors[slot].offset = end;
        Ok(input.len())
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
        let state = self.descriptors[slot];
        self.descriptors[slot] = Descriptor::empty();
        if state.overlay {
            self.release_unlinked(state.object);
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

    fn release_unlinked(&mut self, object: usize) {
        if self.overlay[object].state == 2
            && self.overlay[object].executions == 0
            && !self
                .descriptors
                .iter()
                .any(|fd| fd.open && fd.overlay && fd.object == object)
        {
            self.storage.clear(object);
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
        let path = normalize(path)?;
        if let Some(index) = self.find_overlay(path.as_bytes()) {
            if self.overlay[index].state == 2 {
                return Err(VfsError::NotFound);
            }
            if self.overlay[index].state == 3 {
                return Err(VfsError::IsDirectory);
            }
            self.overlay[index].state = 2;
            self.release_unlinked(index);
            // Open descriptors still own the removed object's bytes.
            return Ok(());
        }
        let entry = self.index.resolve(path.as_bytes())?;
        if entry.kind == NodeKind::Directory {
            return Err(VfsError::IsDirectory);
        }
        let index = self.allocate_overlay()?;
        self.overlay[index].state = 2;
        self.overlay[index].path = path;
        Ok(())
    }

    pub fn pin_executable(&mut self, path: &[u8]) -> Result<Executable, VfsError> {
        let path = normalize(path)?;
        let metadata = self.metadata(path.as_bytes())?;
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
        self.pin_object(state.object)
    }

    fn pin_object(&mut self, object: usize) -> Result<Executable, VfsError> {
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
            size: self.overlay[object].len,
        };
        self.overlay[object].executions = self.overlay[object]
            .executions
            .checked_add(1)
            .ok_or(VfsError::OverlayLimit)?;
        Ok(image)
    }

    pub fn retain_executable(&mut self, image: Executable) -> Result<(), VfsError> {
        let object = self
            .overlay
            .get_mut(image.object)
            .ok_or(VfsError::InvalidDescriptor)?;
        if object.executions == 0 || object.len != image.size {
            return Err(VfsError::InvalidDescriptor);
        }
        object.executions = object
            .executions
            .checked_add(1)
            .ok_or(VfsError::OverlayLimit)?;
        Ok(())
    }

    pub fn release_executable(&mut self, image: Executable) -> Result<(), VfsError> {
        let object = self
            .overlay
            .get_mut(image.object)
            .ok_or(VfsError::InvalidDescriptor)?;
        object.executions = object
            .executions
            .checked_sub(1)
            .ok_or(VfsError::InvalidDescriptor)?;
        self.release_unlinked(image.object);
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

    pub fn executable_pins(&self) -> usize {
        self.overlay.iter().map(|object| object.executions).sum()
    }

    pub fn teardown(&mut self) {
        for slot in 0..FILES {
            self.storage.clear(slot);
        }
        self.overlay.fill(OverlayFile::empty());
        self.descriptors.fill(Descriptor::empty());
    }

    pub fn overlay_files(&self) -> usize {
        self.overlay.iter().filter(|entry| entry.state == 1).count()
    }

    pub fn metadata(&self, path: &[u8]) -> Result<FileMetadata, VfsError> {
        let path = normalize(path)?;
        if let Some(index) = self.find_overlay(path.as_bytes()) {
            let file = &self.overlay[index];
            if file.state == 2 {
                return Err(VfsError::NotFound);
            }
            return Ok(FileMetadata {
                inode: (self.index.len() + index + 1) as u64,
                kind: if file.state == 3 {
                    NodeKind::Directory
                } else {
                    NodeKind::File
                },
                mode: file.mode,
                size: file.len as u64,
            });
        }
        let entry = self.index.resolve(path.as_bytes())?;
        Ok(FileMetadata {
            inode: (self
                .find_base_record(entry.path)
                .ok_or(VfsError::InvalidIndex)?
                + 1) as u64,
            kind: entry.kind,
            mode: entry.mode,
            size: entry.size,
        })
    }

    pub fn fstat(&self, descriptor: i32) -> Result<FileMetadata, VfsError> {
        let descriptor = self.descriptors[self.descriptor(descriptor)?];
        if descriptor.overlay {
            let file = &self.overlay[descriptor.object];
            Ok(FileMetadata {
                inode: (self.index.len() + descriptor.object + 1) as u64,
                kind: if descriptor.directory {
                    NodeKind::Directory
                } else {
                    NodeKind::File
                },
                mode: file.mode,
                size: file.len as u64,
            })
        } else {
            let entry = self.index.entry(descriptor.object)?;
            Ok(FileMetadata {
                inode: (descriptor.object + 1) as u64,
                kind: entry.kind,
                mode: entry.mode,
                size: entry.size,
            })
        }
    }

    pub fn mkdir(&mut self, path: &[u8], mode: u32) -> Result<(), VfsError> {
        let path = normalize(path)?;
        match self.metadata(path.as_bytes()) {
            Ok(_) => return Err(VfsError::AlreadyExists),
            Err(VfsError::NotFound) => {}
            Err(error) => return Err(error),
        }
        self.require_parent(path.as_bytes())?;
        let slot = self.allocate_overlay()?;
        self.storage.clear(slot);
        self.overlay[slot].state = 3;
        self.overlay[slot].path = path;
        self.overlay[slot].mode = mode & 0o777;
        self.overlay[slot].len = 0;
        Ok(())
    }

    fn has_children(&self, path: &[u8]) -> Result<bool, VfsError> {
        if self.overlay.iter().any(|entry| {
            matches!(entry.state, 1 | 3) && child_name(path, entry.path.as_bytes()).is_some()
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
        let path = normalize(path)?;
        if self.metadata(path.as_bytes())?.kind != NodeKind::Directory {
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
        self.overlay[slot].state = 2;
        self.release_unlinked(slot);
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
        let source = normalize(source)?;
        let destination = normalize(destination)?;
        let metadata = self.metadata(source.as_bytes())?;
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
        let target = match self.metadata(destination.as_bytes()) {
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
        // Check every new descendant path before changing any namespace entry.
        for entry in &self.overlay {
            if matches!(entry.state, 1 | 3) && beneath(entry.path.as_bytes(), source.as_bytes()) {
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
            self.overlay[target].state = 2;
            self.release_unlinked(target);
        }
        for entry in &mut self.overlay {
            if matches!(entry.state, 1 | 3) && beneath(entry.path.as_bytes(), source.as_bytes()) {
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
        let path = normalize(path)?;
        let slot = self
            .find_overlay(path.as_bytes())
            .ok_or(VfsError::PermissionDenied)?;
        if self.overlay[slot].state == 2 {
            return Err(VfsError::NotFound);
        }
        if mode & !0o777 != 0 {
            return Err(VfsError::PermissionDenied);
        }
        self.overlay[slot].mode = mode;
        Ok(())
    }

    pub fn fchmod(&mut self, descriptor: i32, mode: u32) -> Result<(), VfsError> {
        let mode = mode & 0o7777;
        let descriptor = self.descriptors[self.descriptor(descriptor)?];
        if !descriptor.overlay || mode & !0o777 != 0 {
            return Err(VfsError::PermissionDenied);
        }
        self.overlay[descriptor.object].mode = mode;
        Ok(())
    }

    pub fn seek(&mut self, descriptor: i32, offset: i64, whence: u32) -> Result<u64, VfsError> {
        let slot = self.descriptor(descriptor)?;
        let base = match whence {
            0 => 0,
            1 => self.descriptors[slot].offset as i64,
            2 => self.fstat(descriptor)?.size as i64,
            _ => return Err(VfsError::InvalidPath),
        };
        let position = base
            .checked_add(offset)
            .filter(|value| *value >= 0)
            .ok_or(VfsError::InvalidPath)?;
        self.descriptors[slot].offset =
            usize::try_from(position).map_err(|_| VfsError::FileTooLarge)?;
        Ok(position as u64)
    }

    pub fn descriptor_flags(&self, descriptor: i32) -> Result<(u32, bool), VfsError> {
        let state = self.descriptors[self.descriptor(descriptor)?];
        let mode = match (state.readable, state.writable) {
            (true, false) => 0,
            (false, true) => 1,
            _ => 2,
        };
        Ok((
            mode | if state.append { 0o2000 } else { 0 }
                | if state.nonblocking { 0o4000 } else { 0 },
            state.close_on_exec,
        ))
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
            .position(|entry| matches!(entry.state, 1 | 3) && entry.path.as_bytes() == path)
            .or_else(|| {
                self.overlay
                    .iter()
                    .position(|entry| entry.state == 2 && entry.path.as_bytes() == path)
            })
    }

    fn allocate_overlay(&self) -> Result<usize, VfsError> {
        self.overlay
            .iter()
            .position(|entry| entry.state == 0)
            .or_else(|| {
                self.overlay.iter().enumerate().position(|(slot, entry)| {
                    entry.state == 2
                        && entry.executions == 0
                        && self.index.lookup_exact(entry.path.as_bytes()) == Err(VfsError::NotFound)
                        && !self
                            .descriptors
                            .iter()
                            .any(|fd| fd.open && fd.overlay && fd.object == slot)
                })
            })
            .ok_or(VfsError::OverlayLimit)
    }

    fn create_overlay(&mut self, path: Path, mode: u32) -> Result<usize, VfsError> {
        let index = self.allocate_overlay()?;
        self.storage.clear(index);
        self.overlay[index].state = 1;
        self.overlay[index].path = path;
        self.overlay[index].mode = mode;
        self.overlay[index].len = 0;
        Ok(index)
    }

    fn copy_to_overlay(&mut self, path: Path, entry: Entry<'_>) -> Result<usize, VfsError> {
        let size = usize::try_from(entry.size).map_err(|_| VfsError::FileTooLarge)?;
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
    fn validates_lookup_and_symlink_components() {
        let bytes = index_bytes();
        let index = Index::new(&bytes).unwrap();
        assert_eq!(index.resolve(b"/bin/./sh").unwrap().path, b"/usr/bin/tool");
        assert_eq!(index.resolve(b"/loop"), Err(VfsError::SymlinkLoop));
        assert_eq!(index.resolve(b"/../../base"), Err(VfsError::InvalidPath));
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
    fn overlays_are_isolated_between_domain_instances() {
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
        vfs.seek(fd, 3, 0).unwrap();
        vfs.write(fd, b"x").unwrap();
        vfs.fchmod(fd, 0o640).unwrap();
        assert_eq!(vfs.fstat(fd).unwrap().mode, 0o640);
        assert_eq!(vfs.fstat(fd).unwrap().size, 4);
        vfs.seek(fd, 0, 0).unwrap();
        let mut output = [0xff; 8];
        assert_eq!(vfs.read(fd, &mut output), Ok(4));
        assert_eq!(&output[..4], b"\0\0\0x");
        vfs.seek(fd, 100, 0).unwrap();
        assert_eq!(vfs.read(fd, &mut output), Ok(0));
        assert_eq!(vfs.write(fd, b""), Ok(0));
        assert_eq!(vfs.fstat(fd).unwrap().size, 4);
        let append = vfs
            .open(b"/work/build/data", O_WRITE | O_APPEND | O_CLOEXEC)
            .unwrap();
        vfs.seek(append, 0, 0).unwrap();
        vfs.write(append, b"y").unwrap();
        assert_eq!(vfs.seek(append, 0, 1), Ok(5));
        assert_eq!(vfs.descriptor_flags(append), Ok((0o2001, true)));
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
        vfs.seek(old, 0, 0).unwrap();
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
        assert_eq!(vfs.seek(fd, 0, 1), Ok(5000));
        vfs.seek(fd, 0, 0).unwrap();
        let mut output = [0; 5000];
        assert_eq!(vfs.read(fd, &mut output), Ok(5000));
        assert_eq!(output, payload);
        vfs.truncate(fd, 3).unwrap();
        assert_eq!(vfs.seek(fd, 0, 1), Ok(5000));
        vfs.truncate(fd, 8192).unwrap();
        assert_eq!(vfs.seek(fd, 0, 1), Ok(5000));
        vfs.seek(fd, 0, 0).unwrap();
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
        assert_eq!(vfs.seek(fd, 0, 1), Ok(5000));
        vfs.close(truncating).unwrap();
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
        assert_eq!(vfs.descriptor_flags(dir), Ok((0o4000, true)));
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
        assert_eq!(vfs.seek(dir, 0, 1), Ok(0)); // Peeking did not consume anything.
        vfs.seek(dir, cookie as i64, 0).unwrap();
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
        vfs.seek(b, 0, 0).unwrap();
        vfs.read(b, &mut output).unwrap();
        assert_eq!(&output, b"old");
        vfs.seek(a, 0, 0).unwrap();
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
        assert_eq!(vfs.seek(original, 0, 1), Ok(9));
        let mut output = [0u8; 9];
        assert_eq!(vfs.read(reopened, &mut output[..3]), Ok(3));
        assert_eq!(&output[..3], b"old");
        assert_eq!(vfs.seek(original, 0, 1), Ok(9));
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
        vfs.seek(directory, 1, 0).unwrap();
        assert_eq!(vfs.seek(other, 0, 1), Ok(0));
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
        vfs.seek(reader, 4, 0).unwrap();
        let image = vfs.pin_executable_fd(reader).unwrap();
        assert_eq!(vfs.executable_pins(), 1);
        assert_eq!(
            vfs.open(b"/program", O_WRITE | O_TRUNC),
            Err(VfsError::TextBusy)
        );
        let mut output = [0u8; 32];
        assert_eq!(vfs.read_executable(image, 0, &mut output), Ok(16));
        assert_eq!(&output[..16], b"executable-bytes");
        assert_eq!(vfs.seek(reader, 0, 1), Ok(4));
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
}
