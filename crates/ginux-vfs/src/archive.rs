//! Bulk creation of instance objects from one POSIX tar stream.
//!
//! An import is not a second filesystem writer. Each archive member becomes
//! the sequence of ordinary [`VirtualFs`] calls a sequential extractor makes
//! through individual system calls: `mkdir`, `open` with exclusive create,
//! `write`, `fchmod`, `symlink`, `hard_link`, `mkfifo`, `unlink`, `chmod` and
//! timestamp updates. Name, type, capacity, byte and mode policy therefore
//! come from those calls and fail exactly as they would. The importer adds
//! only what an archive needs on top of them:
//!
//! - every member name is relative to a destination directory and may not
//!   be absolute or contain a `..` component;
//! - every existing component between the destination and a member must be a
//!   real directory. Links are never followed while names are created, so no
//!   member can reach outside the destination, including through a link an
//!   earlier member of the same stream created;
//! - a policy callback approves each operation before it runs, so an adapter
//!   can apply the authority the equivalent system call would need.
//!
//! The stream is pushed in arbitrary pieces. State that spans pieces (a
//! partial header, an extended header record, the file being written) lives
//! in [`ArchiveImport`]; nothing is buffered beyond one block and one record.

use super::{
    BaseReader, NodeKind, OverlayFile, OverlayStorage, Timestamp, VfsError, VirtualFs, MAX_PATH,
    O_CREATE, O_EXCLUSIVE, O_WRITE,
};
use core::ops::{Deref, DerefMut};

/// Discard extended attributes the archive carries instead of refusing them.
pub const ARCHIVE_DISCARD_XATTRS: u32 = 1;
/// Clear set-user-ID, set-group-ID and sticky bits instead of refusing them.
pub const ARCHIVE_CLEAR_SPECIAL_MODES: u32 = 2;
const ARCHIVE_FLAGS: u32 = ARCHIVE_DISCARD_XATTRS | ARCHIVE_CLEAR_SPECIAL_MODES;

const BLOCK: usize = 512;
/// The longest extended header record an import buffers.
pub const ARCHIVE_RECORD_LIMIT: usize = 8192;

/// One individual operation an import is about to perform, named after the
/// system call a sequential extractor would use for it.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveOperation {
    /// `openat` with `O_CREAT | O_EXCL` for a regular file.
    CreateFile,
    /// `mkdirat`, for a directory member or a missing parent.
    CreateDirectory,
    /// `symlinkat`.
    CreateSymlink,
    /// `linkat` without following links.
    CreateHardLink,
    /// `mknodat` for a FIFO.
    CreateFifo,
    /// `unlinkat` of an existing non-directory a member replaces.
    Remove,
    /// `fchmodat` of a directory or FIFO member's name to its recorded mode.
    ChangeMode,
    /// `fchmod` of the regular file being written to its recorded mode.
    ChangeFileMode,
    /// `utimensat` or `futimens` to the member's recorded modification time.
    SetTimes,
}

/// Approves each operation before it runs. A refusal stops the import with
/// [`ArchiveError::Denied`] carrying the returned code unchanged.
pub trait ArchivePolicy {
    fn permit(&mut self, operation: ArchiveOperation) -> Result<(), i32>;
}

impl<F: FnMut(ArchiveOperation) -> Result<(), i32>> ArchivePolicy for F {
    fn permit(&mut self, operation: ArchiveOperation) -> Result<(), i32> {
        self(operation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ArchiveError {
    /// The equivalent individual operation failed with this error.
    Fs(VfsError),
    /// A member name or link target, joined to the destination, does not fit
    /// the path bound individual calls accept.
    NameTooLong,
    /// The stream is not a well-formed tar archive.
    Malformed,
    /// A well-formed archive asks for something an import does not represent:
    /// sparse or multivolume members, unknown extended keywords, or extended
    /// attributes without [`ARCHIVE_DISCARD_XATTRS`].
    Unsupported,
    /// A character or block device member. Instance storage never creates them.
    DeviceNode,
    /// The policy refused the equivalent operation with this code.
    Denied(i32),
    /// The stream has not yet reached its end-of-archive marker.
    Truncated,
}

impl From<VfsError> for ArchiveError {
    fn from(error: VfsError) -> Self {
        Self::Fs(error)
    }
}

/// What an import has done so far.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct ArchiveSummary {
    /// Archive members created, replaced or merged.
    pub members: u64,
    /// Missing parent directories created on the way to a member.
    pub directories: u64,
    /// Regular-file bytes written.
    pub bytes: u64,
    /// The end-of-archive marker was reached with every member applied.
    pub complete: bool,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Phase {
    /// Assembling a header block.
    Header,
    /// Consuming the payload of an extended or long-name header.
    Extension {
        kind: u8,
        remaining: u64,
        padding: usize,
    },
    /// Copying member bytes into the file being written.
    Data {
        remaining: u64,
        padding: usize,
    },
    /// Skipping the padding that ends a payload's last block.
    Padding {
        remaining: usize,
    },
    /// One zero block was read; the second must follow.
    EndMarker,
    /// The archive ended. Only zero record padding may follow.
    Done,
    Failed(ArchiveError),
}

#[derive(Clone, Copy)]
struct Name {
    bytes: [u8; MAX_PATH],
    len: usize,
}

impl Name {
    const fn new() -> Self {
        Self {
            bytes: [0; MAX_PATH],
            len: 0,
        }
    }

    fn as_bytes(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    fn set(&mut self, value: &[u8]) -> Result<(), ArchiveError> {
        let target = self
            .bytes
            .get_mut(..value.len())
            .ok_or(ArchiveError::NameTooLong)?;
        target.copy_from_slice(value);
        self.len = value.len();
        Ok(())
    }

    fn push(&mut self, value: &[u8]) -> Result<(), ArchiveError> {
        // Individual calls accept paths shorter than MAX_PATH, leaving room
        // for the terminating NUL their callers carry.
        let end = self
            .len
            .checked_add(value.len())
            .filter(|end| *end < MAX_PATH)
            .ok_or(ArchiveError::NameTooLong)?;
        self.bytes[self.len..end].copy_from_slice(value);
        self.len = end;
        Ok(())
    }
}

/// Values extended and long-name headers supply for the next member.
#[derive(Clone, Copy)]
struct Pending {
    path: Option<Name>,
    link: Option<Name>,
    size: Option<u64>,
    modified: Option<Timestamp>,
    xattrs: bool,
}

impl Pending {
    const EMPTY: Self = Self {
        path: None,
        link: None,
        size: None,
        modified: None,
        xattrs: false,
    };

    fn is_empty(&self) -> bool {
        self.path.is_none()
            && self.link.is_none()
            && self.size.is_none()
            && self.modified.is_none()
            && !self.xattrs
    }
}

#[derive(Clone, Copy)]
struct Writing {
    descriptor: i32,
    mode: u32,
    modified: Timestamp,
}

/// The state of one archive stream. It holds at most one open file
/// descriptor of the filesystem it writes to; pass it to
/// [`VirtualFs::archive_abort`] before discarding it.
#[derive(Clone, Copy)]
pub struct ArchiveImport {
    flags: u32,
    directory_mode: u32,
    phase: Phase,
    block: [u8; BLOCK],
    filled: usize,
    record: [u8; ARCHIVE_RECORD_LIMIT],
    record_fill: usize,
    record_len: usize,
    pending: Pending,
    writing: Option<Writing>,
    summary: ArchiveSummary,
}

impl ArchiveImport {
    /// Begin an import. `flags` combines the `ARCHIVE_*` options and
    /// `directory_mode` is the mode a missing parent directory receives, as
    /// a creation mask leaves it.
    pub fn new(flags: u32, directory_mode: u32) -> Result<Self, VfsError> {
        if flags & !ARCHIVE_FLAGS != 0 || directory_mode & !0o777 != 0 {
            return Err(VfsError::InvalidArgument);
        }
        Ok(Self {
            flags,
            directory_mode,
            phase: Phase::Header,
            block: [0; BLOCK],
            filled: 0,
            record: [0; ARCHIVE_RECORD_LIMIT],
            record_fill: 0,
            record_len: 0,
            pending: Pending::EMPTY,
            writing: None,
            summary: ArchiveSummary {
                members: 0,
                directories: 0,
                bytes: 0,
                complete: false,
            },
        })
    }

    pub fn summary(&self) -> ArchiveSummary {
        self.summary
    }

    /// The error that stopped this import, if any.
    pub fn error(&self) -> Option<ArchiveError> {
        match self.phase {
            Phase::Failed(error) => Some(error),
            _ => None,
        }
    }

    fn special_modes(&self, mode: u32) -> u32 {
        if self.flags & ARCHIVE_CLEAR_SPECIAL_MODES != 0 {
            mode & 0o777
        } else {
            mode & 0o7777
        }
    }

    /// Consume one extended header payload byte range.
    fn extension(&mut self, kind: u8, mut input: &[u8]) -> Result<(), ArchiveError> {
        if matches!(kind, b'L' | b'K') {
            let end = self.record_fill + input.len();
            // Header processing bounded the payload to a path and its NUL.
            self.record[self.record_fill..end].copy_from_slice(input);
            self.record_fill = end;
            return Ok(());
        }
        while !input.is_empty() {
            if self.record_len == 0 {
                // The decimal length and its space, bounded by the record limit.
                let byte = input[0];
                input = &input[1..];
                if byte == b' ' {
                    let length =
                        decimal(&self.record[..self.record_fill]).ok_or(ArchiveError::Malformed)?;
                    let minimum = self.record_fill as u64 + 4;
                    if length < minimum {
                        return Err(ArchiveError::Malformed);
                    }
                    if length > ARCHIVE_RECORD_LIMIT as u64 {
                        return Err(ArchiveError::Unsupported);
                    }
                    self.record_len = length as usize;
                    self.record[self.record_fill] = b' ';
                    self.record_fill += 1;
                    continue;
                }
                if !byte.is_ascii_digit() || self.record_fill == 20 {
                    return Err(ArchiveError::Malformed);
                }
                self.record[self.record_fill] = byte;
                self.record_fill += 1;
                continue;
            }
            let count = (self.record_len - self.record_fill).min(input.len());
            self.record[self.record_fill..self.record_fill + count]
                .copy_from_slice(&input[..count]);
            self.record_fill += count;
            input = &input[count..];
            if self.record_fill == self.record_len {
                let record = self.record;
                self.keyword(kind, &record[..self.record_len])?;
                self.record_fill = 0;
                self.record_len = 0;
            }
        }
        Ok(())
    }

    /// Apply one complete `length keyword=value\n` record.
    fn keyword(&mut self, kind: u8, record: &[u8]) -> Result<(), ArchiveError> {
        let space = record
            .iter()
            .position(|b| *b == b' ')
            .ok_or(ArchiveError::Malformed)?;
        let body = record[space + 1..]
            .strip_suffix(b"\n")
            .ok_or(ArchiveError::Malformed)?;
        let equals = body
            .iter()
            .position(|b| *b == b'=')
            .ok_or(ArchiveError::Malformed)?;
        let (key, value) = (&body[..equals], &body[equals + 1..]);
        if key.is_empty() {
            return Err(ArchiveError::Malformed);
        }
        if xattr_keyword(key) {
            if self.flags & ARCHIVE_DISCARD_XATTRS == 0 {
                return Err(ArchiveError::Unsupported);
            }
            self.pending.xattrs |= kind == b'x';
            return Ok(());
        }
        // Ownership is never restored and access/change times belong to the
        // instance clock; text annotations carry no filesystem meaning.
        if matches!(
            key,
            b"uid"
                | b"gid"
                | b"uname"
                | b"gname"
                | b"atime"
                | b"ctime"
                | b"comment"
                | b"charset"
                | b"hdrcharset"
        ) {
            return Ok(());
        }
        // A global header may only annotate; it cannot rename every member.
        if kind != b'x' {
            return Err(ArchiveError::Unsupported);
        }
        match key {
            b"path" | b"linkpath" => {
                let slot = if key == b"path" {
                    &mut self.pending.path
                } else {
                    &mut self.pending.link
                };
                if value.is_empty() {
                    *slot = None;
                } else {
                    if value.contains(&0) {
                        return Err(ArchiveError::Malformed);
                    }
                    let mut name = Name::new();
                    name.set(value)?;
                    *slot = Some(name);
                }
            }
            b"size" => {
                self.pending.size = if value.is_empty() {
                    None
                } else {
                    Some(decimal(value).ok_or(ArchiveError::Malformed)?)
                };
            }
            b"mtime" => {
                self.pending.modified = if value.is_empty() {
                    None
                } else {
                    Some(decimal_time(value).ok_or(ArchiveError::Malformed)?)
                };
            }
            _ => return Err(ArchiveError::Unsupported),
        }
        Ok(())
    }

    /// The payload of an extended or long-name header is complete.
    fn end_extension(&mut self, kind: u8) -> Result<(), ArchiveError> {
        match kind {
            b'L' | b'K' => {
                let length = self.record_fill;
                self.record_fill = 0;
                let value = self.record[..length]
                    .strip_suffix(b"\0")
                    .ok_or(ArchiveError::Malformed)?;
                let value = &value[..value.iter().position(|b| *b == 0).unwrap_or(value.len())];
                if value.is_empty() {
                    return Err(ArchiveError::Malformed);
                }
                let mut name = Name::new();
                name.set(value)?;
                if kind == b'L' {
                    self.pending.path = Some(name);
                } else {
                    self.pending.link = Some(name);
                }
            }
            _ if self.record_fill != 0 => return Err(ArchiveError::Malformed),
            _ => {}
        }
        Ok(())
    }
}

/// A parsed member header, after extended values have been applied.
struct Member {
    kind: u8,
    name: Name,
    directory_syntax: bool,
    link: Name,
    mode: u32,
    size: u64,
    modified: Timestamp,
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
    /// Push the next piece of an archive stream. Members are created beneath
    /// the directory open as `destination` as soon as their headers and
    /// bytes arrive. `now`, when supplied, stamps created names and their
    /// parents as an individual create would. After an error the import is
    /// stopped: members already applied remain, the member being written
    /// keeps the bytes it received, and every later call returns that error.
    pub fn archive_write(
        &mut self,
        import: &mut ArchiveImport,
        destination: i32,
        input: &[u8],
        now: Option<Timestamp>,
        policy: &mut impl ArchivePolicy,
    ) -> Result<(), ArchiveError> {
        if let Phase::Failed(error) = import.phase {
            return Err(error);
        }
        let result = self.archive_feed(import, destination, input, now, policy);
        if let Err(error) = result {
            self.archive_abort(import);
            import.phase = Phase::Failed(error);
        }
        result
    }

    /// The outcome of a stream that has ended. Incomplete archives report
    /// [`ArchiveError::Truncated`] and may still continue.
    pub fn archive_finish(&self, import: &ArchiveImport) -> Result<ArchiveSummary, ArchiveError> {
        match import.phase {
            Phase::Done => Ok(import.summary),
            Phase::Failed(error) => Err(error),
            _ => Err(ArchiveError::Truncated),
        }
    }

    /// Close the file an unfinished member holds open. Idempotent.
    pub fn archive_abort(&mut self, import: &mut ArchiveImport) {
        if let Some(writing) = import.writing.take() {
            // Only an unknown descriptor fails, and this one is ours.
            let _ = self.close(writing.descriptor);
        }
    }

    fn archive_feed(
        &mut self,
        import: &mut ArchiveImport,
        destination: i32,
        mut input: &[u8],
        now: Option<Timestamp>,
        policy: &mut impl ArchivePolicy,
    ) -> Result<(), ArchiveError> {
        while !input.is_empty() {
            match import.phase {
                Phase::Header | Phase::EndMarker => {
                    let count = (BLOCK - import.filled).min(input.len());
                    import.block[import.filled..import.filled + count]
                        .copy_from_slice(&input[..count]);
                    import.filled += count;
                    input = &input[count..];
                    if import.filled < BLOCK {
                        continue;
                    }
                    import.filled = 0;
                    let block = import.block;
                    let zero = block.iter().all(|b| *b == 0);
                    match (import.phase, zero) {
                        (Phase::Header, true) if import.pending.is_empty() => {
                            import.phase = Phase::EndMarker;
                        }
                        (Phase::EndMarker, true) => {
                            import.summary.complete = true;
                            import.phase = Phase::Done;
                        }
                        (Phase::Header, false) => {
                            self.archive_header(import, &block, destination, now, policy)?;
                        }
                        _ => return Err(ArchiveError::Malformed),
                    }
                }
                Phase::Extension {
                    kind,
                    remaining,
                    padding,
                } => {
                    let count = remaining.min(input.len() as u64) as usize;
                    import.extension(kind, &input[..count])?;
                    input = &input[count..];
                    let remaining = remaining - count as u64;
                    import.phase = Phase::Extension {
                        kind,
                        remaining,
                        padding,
                    };
                    if remaining == 0 {
                        import.end_extension(kind)?;
                        import.phase = after_payload(padding);
                    }
                }
                Phase::Data { remaining, padding } => {
                    let count = remaining.min(input.len() as u64) as usize;
                    let writing = import.writing.ok_or(ArchiveError::Malformed)?;
                    self.write(writing.descriptor, &input[..count])?;
                    import.summary.bytes += count as u64;
                    input = &input[count..];
                    let remaining = remaining - count as u64;
                    import.phase = Phase::Data { remaining, padding };
                    if remaining == 0 {
                        self.archive_complete_file(import, now, policy)?;
                        import.phase = after_payload(padding);
                    }
                }
                Phase::Padding { remaining } => {
                    // Padding content carries nothing; extractors ignore it.
                    let count = remaining.min(input.len());
                    input = &input[count..];
                    import.phase = after_payload(remaining - count);
                }
                Phase::Done => {
                    if input.iter().any(|b| *b != 0) {
                        return Err(ArchiveError::Malformed);
                    }
                    input = &[];
                }
                Phase::Failed(error) => return Err(error),
            }
        }
        Ok(())
    }

    fn archive_header(
        &mut self,
        import: &mut ArchiveImport,
        block: &[u8; BLOCK],
        destination: i32,
        now: Option<Timestamp>,
        policy: &mut impl ArchivePolicy,
    ) -> Result<(), ArchiveError> {
        let recorded = octal(&block[148..156]).ok_or(ArchiveError::Malformed)?;
        let (unsigned, signed) = block.iter().enumerate().fold((0u64, 0i64), |sum, (i, b)| {
            let b = if (148..156).contains(&i) { b' ' } else { *b };
            (sum.0 + b as u64, sum.1 + b as i8 as i64)
        });
        if recorded != unsigned && recorded as i64 != signed {
            return Err(ArchiveError::Malformed);
        }
        let posix = &block[257..263] == b"ustar\0" && &block[263..265] == b"00";
        if !posix && &block[257..265] != b"ustar  \0" {
            return Err(ArchiveError::Malformed);
        }
        let kind = block[156];
        // Ownership fields are validated, never applied.
        numeric(&block[108..116]).ok_or(ArchiveError::Malformed)?;
        numeric(&block[116..124]).ok_or(ArchiveError::Malformed)?;
        let header_size = numeric(&block[124..136]).ok_or(ArchiveError::Malformed)?;
        if matches!(kind, b'x' | b'g' | b'L' | b'K') {
            if matches!(kind, b'L' | b'K') {
                if header_size == 0 {
                    return Err(ArchiveError::Malformed);
                }
                if header_size > MAX_PATH as u64 {
                    return Err(ArchiveError::NameTooLong);
                }
            }
            let padding = padding(header_size);
            import.phase = if header_size == 0 {
                import.end_extension(kind)?;
                after_payload(0)
            } else {
                Phase::Extension {
                    kind,
                    remaining: header_size,
                    padding,
                }
            };
            return Ok(());
        }
        let pending = core::mem::replace(&mut import.pending, Pending::EMPTY);
        let size = pending.size.unwrap_or(header_size);
        let modified = match pending.modified {
            Some(time) => time,
            None => Timestamp {
                seconds: signed_numeric(&block[136..148]).ok_or(ArchiveError::Malformed)?,
                nanoseconds: 0,
            },
        };
        let mode = octal(&block[100..108]).ok_or(ArchiveError::Malformed)?;
        let raw = match &pending.path {
            Some(name) => *name,
            None => {
                let mut name = Name::new();
                let prefix = if posix { field(&block[345..500]) } else { &[] };
                if !prefix.is_empty() {
                    name.set(prefix)?;
                    name.push(b"/")?;
                }
                name.push(field(&block[..100]))?;
                name
            }
        };
        let link = match &pending.link {
            Some(name) => *name,
            None => {
                let mut name = Name::new();
                name.set(field(&block[157..257]))?;
                name
            }
        };
        if raw.len == 0 || u32::try_from(mode).is_err() {
            return Err(ArchiveError::Malformed);
        }
        let member = Member {
            kind,
            name: raw,
            directory_syntax: raw.as_bytes().ends_with(b"/"),
            link,
            mode: import.special_modes(mode as u32),
            size,
            modified,
        };
        match kind {
            b'0' | 0 | b'7' => {}
            b'1' | b'2' | b'5' | b'6' if size != 0 => return Err(ArchiveError::Malformed),
            b'1' | b'2' | b'5' | b'6' => {}
            b'3' | b'4' => return Err(ArchiveError::DeviceNode),
            _ => return Err(ArchiveError::Unsupported),
        }
        if pending.xattrs && import.flags & ARCHIVE_DISCARD_XATTRS == 0 {
            return Err(ArchiveError::Unsupported);
        }
        if member.directory_syntax && kind != b'5'
            || matches!(kind, b'1' | b'2') && member.link.len == 0
        {
            return Err(ArchiveError::Malformed);
        }
        self.archive_member(import, &member, destination, now, policy)
    }

    fn archive_member(
        &mut self,
        import: &mut ArchiveImport,
        member: &Member,
        destination: i32,
        now: Option<Timestamp>,
        policy: &mut impl ArchivePolicy,
    ) -> Result<(), ArchiveError> {
        let mut base = Name::new();
        base.set(self.directory_path(destination)?)?;
        let path = self.archive_parents(
            import,
            &base,
            member.name.as_bytes(),
            Some((import.directory_mode, now)),
            policy,
        )?;
        let path = path.as_bytes();
        let accessed = now;
        match member.kind {
            b'5' => {
                match self.metadata_no_follow(path) {
                    Ok(metadata) if metadata.kind == NodeKind::Directory => {
                        // Merge, as mkdir's EEXIST followed by chmod.
                        policy
                            .permit(ArchiveOperation::ChangeMode)
                            .map_err(ArchiveError::Denied)?;
                        self.chmod(path, member.mode)?;
                    }
                    existing @ (Ok(_) | Err(VfsError::NotFound)) => {
                        if existing.is_ok() {
                            // A directory replaces a non-directory, which is
                            // removed without being followed.
                            self.archive_vacate(path, policy)?;
                        }
                        policy
                            .permit(ArchiveOperation::CreateDirectory)
                            .map_err(ArchiveError::Denied)?;
                        self.mkdir(path, member.mode & 0o777)?;
                        self.archive_created(path, now)?;
                        if member.mode & !0o777 != 0 {
                            // The refusal individual chmod gives special bits.
                            policy
                                .permit(ArchiveOperation::ChangeMode)
                                .map_err(ArchiveError::Denied)?;
                            self.chmod(path, member.mode)?;
                        }
                    }
                    Err(error) => return Err(error.into()),
                }
                policy
                    .permit(ArchiveOperation::SetTimes)
                    .map_err(ArchiveError::Denied)?;
                self.set_times(path, false, accessed, Some(member.modified))?;
            }
            b'1' => {
                if path == base.as_bytes() {
                    return Err(ArchiveError::Fs(VfsError::InvalidPath));
                }
                let target =
                    self.archive_parents(import, &base, member.link.as_bytes(), None, policy)?;
                self.archive_vacate(path, policy)?;
                policy
                    .permit(ArchiveOperation::CreateHardLink)
                    .map_err(ArchiveError::Denied)?;
                self.hard_link(target.as_bytes(), path, false)?;
            }
            _ => {
                if path == base.as_bytes() {
                    return Err(ArchiveError::Fs(VfsError::InvalidPath));
                }
                self.archive_vacate(path, policy)?;
                match member.kind {
                    b'2' => {
                        policy
                            .permit(ArchiveOperation::CreateSymlink)
                            .map_err(ArchiveError::Denied)?;
                        self.symlink(member.link.as_bytes(), path)?;
                        self.archive_created(path, now)?;
                    }
                    b'6' => {
                        policy
                            .permit(ArchiveOperation::CreateFifo)
                            .map_err(ArchiveError::Denied)?;
                        self.mkfifo(path, member.mode & 0o777)?;
                        self.archive_created(path, now)?;
                        if member.mode & !0o777 != 0 {
                            policy
                                .permit(ArchiveOperation::ChangeMode)
                                .map_err(ArchiveError::Denied)?;
                            self.chmod(path, member.mode)?;
                        }
                    }
                    _ => {
                        policy
                            .permit(ArchiveOperation::CreateFile)
                            .map_err(ArchiveError::Denied)?;
                        let descriptor = self.open(path, O_WRITE | O_CREATE | O_EXCLUSIVE)?;
                        import.writing = Some(Writing {
                            descriptor,
                            mode: member.mode,
                            modified: member.modified,
                        });
                        self.archive_created(path, now)?;
                        if member.size == 0 {
                            return self.archive_complete_file(import, now, policy);
                        }
                        import.phase = Phase::Data {
                            remaining: member.size,
                            padding: padding(member.size),
                        };
                        return Ok(());
                    }
                }
                policy
                    .permit(ArchiveOperation::SetTimes)
                    .map_err(ArchiveError::Denied)?;
                self.set_times(path, false, accessed, Some(member.modified))?;
            }
        }
        import.summary.members += 1;
        Ok(())
    }

    /// Give the file being written its recorded mode and time and close it.
    fn archive_complete_file(
        &mut self,
        import: &mut ArchiveImport,
        now: Option<Timestamp>,
        policy: &mut impl ArchivePolicy,
    ) -> Result<(), ArchiveError> {
        let writing = import.writing.take().ok_or(ArchiveError::Malformed)?;
        let applied = (|| {
            policy
                .permit(ArchiveOperation::ChangeFileMode)
                .map_err(ArchiveError::Denied)?;
            self.fchmod(writing.descriptor, writing.mode)?;
            policy
                .permit(ArchiveOperation::SetTimes)
                .map_err(ArchiveError::Denied)?;
            self.fset_times(writing.descriptor, now, Some(writing.modified))?;
            Ok::<(), ArchiveError>(())
        })();
        let closed = self.close(writing.descriptor);
        applied?;
        closed?;
        import.summary.members += 1;
        Ok(())
    }

    /// Join a relative member name to `base`, requiring each existing
    /// component in between to be a real directory. With `create`, missing
    /// components become directories of the given mode; without it they are
    /// an error. Returns the joined path; its last component is unchecked.
    fn archive_parents(
        &mut self,
        import: &mut ArchiveImport,
        base: &Name,
        name: &[u8],
        create: Option<(u32, Option<Timestamp>)>,
        policy: &mut impl ArchivePolicy,
    ) -> Result<Name, ArchiveError> {
        if name.first() == Some(&b'/') || name.contains(&0) {
            return Err(ArchiveError::Fs(VfsError::InvalidPath));
        }
        let mut path = *base;
        let mut components = name
            .split(|b| *b == b'/')
            .filter(|c| !c.is_empty() && *c != b".")
            .peekable();
        while let Some(component) = components.next() {
            if component == b".." {
                return Err(ArchiveError::Fs(VfsError::InvalidPath));
            }
            if path.as_bytes() != b"/" {
                path.push(b"/")?;
            }
            path.push(component)?;
            if components.peek().is_none() {
                break;
            }
            match self.metadata_no_follow(path.as_bytes()) {
                Ok(metadata) if metadata.kind == NodeKind::Directory => {}
                Ok(metadata) if metadata.kind == NodeKind::Symlink => {
                    return Err(ArchiveError::Fs(VfsError::SymlinkLoop));
                }
                Ok(_) => return Err(ArchiveError::Fs(VfsError::NotDirectory)),
                Err(VfsError::NotFound) => {
                    let Some((mode, now)) = create else {
                        return Err(ArchiveError::Fs(VfsError::NotFound));
                    };
                    policy
                        .permit(ArchiveOperation::CreateDirectory)
                        .map_err(ArchiveError::Denied)?;
                    self.mkdir(path.as_bytes(), mode)?;
                    self.archive_created(path.as_bytes(), now)?;
                    import.summary.directories += 1;
                }
                Err(error) => return Err(error.into()),
            }
        }
        Ok(path)
    }

    /// Remove an existing non-directory a member replaces, without following
    /// it. A directory is never replaced.
    fn archive_vacate(
        &mut self,
        path: &[u8],
        policy: &mut impl ArchivePolicy,
    ) -> Result<(), ArchiveError> {
        match self.metadata_no_follow(path) {
            Ok(metadata) if metadata.kind == NodeKind::Directory => {
                Err(ArchiveError::Fs(VfsError::IsDirectory))
            }
            Ok(_) => {
                policy
                    .permit(ArchiveOperation::Remove)
                    .map_err(ArchiveError::Denied)?;
                Ok(self.unlink(path)?)
            }
            Err(VfsError::NotFound) => Ok(()),
            Err(error) => Err(error.into()),
        }
    }

    /// The timestamps an individual create gives a new name and its parent.
    fn archive_created(&mut self, path: &[u8], now: Option<Timestamp>) -> Result<(), VfsError> {
        let Some(now) = now else {
            return Ok(());
        };
        self.set_times(path, false, Some(now), Some(now))?;
        let split = path.iter().rposition(|b| *b == b'/').unwrap_or(0);
        self.set_times(&path[..split.max(1)], false, None, Some(now))
    }
}

fn after_payload(padding: usize) -> Phase {
    if padding == 0 {
        Phase::Header
    } else {
        Phase::Padding { remaining: padding }
    }
}

fn padding(size: u64) -> usize {
    ((BLOCK as u64 - size % BLOCK as u64) % BLOCK as u64) as usize
}

fn field(bytes: &[u8]) -> &[u8] {
    &bytes[..bytes.iter().position(|b| *b == 0).unwrap_or(bytes.len())]
}

/// Keywords that carry extended attributes or access control lists.
fn xattr_keyword(key: &[u8]) -> bool {
    [
        b"SCHILY.xattr.".as_slice(),
        b"LIBARCHIVE.xattr.",
        b"SCHILY.acl.",
        b"RHT.security.",
    ]
    .iter()
    .any(|prefix| key.starts_with(prefix))
}

/// An octal header field: optional leading spaces, digits, then NUL or space.
fn octal(bytes: &[u8]) -> Option<u64> {
    let mut value = 0u64;
    let mut digits = false;
    let mut ended = false;
    for byte in bytes {
        match byte {
            b' ' if !digits => {}
            0 | b' ' => ended = true,
            b'0'..=b'7' if !ended => {
                digits = true;
                value = value.checked_mul(8)?.checked_add((byte - b'0') as u64)?;
            }
            _ => return None,
        }
    }
    Some(value)
}

/// An octal or base-256 unsigned numeric field.
fn numeric(bytes: &[u8]) -> Option<u64> {
    match bytes[0] {
        0x80 => bytes[1..].iter().try_fold(0u64, |value, b| {
            value.checked_mul(256)?.checked_add(*b as u64)
        }),
        0xff => None,
        _ => octal(bytes),
    }
}

/// An octal or two's-complement base-256 signed numeric field.
fn signed_numeric(bytes: &[u8]) -> Option<i64> {
    if bytes[0] == 0xff {
        let magnitude = bytes[1..].iter().try_fold(0u64, |value, b| {
            value.checked_mul(256)?.checked_add(!*b as u64)
        })?;
        return i64::try_from(magnitude).ok()?.checked_neg()?.checked_sub(1);
    }
    i64::try_from(numeric(bytes)?).ok()
}

fn decimal(bytes: &[u8]) -> Option<u64> {
    if bytes.is_empty() {
        return None;
    }
    bytes.iter().try_fold(0u64, |value, b| {
        if !b.is_ascii_digit() {
            return None;
        }
        value.checked_mul(10)?.checked_add((b - b'0') as u64)
    })
}

/// A pax time: optional sign, decimal seconds, optional fraction.
fn decimal_time(bytes: &[u8]) -> Option<Timestamp> {
    let (negative, bytes) = match bytes.strip_prefix(b"-") {
        Some(rest) => (true, rest),
        None => (false, bytes),
    };
    let (whole, fraction) = match bytes.iter().position(|b| *b == b'.') {
        Some(dot) => (&bytes[..dot], &bytes[dot + 1..]),
        None => (bytes, &[][..]),
    };
    let seconds = i64::try_from(decimal(whole)?).ok()?;
    let mut nanoseconds = 0u32;
    for (index, digit) in fraction.iter().enumerate() {
        if !digit.is_ascii_digit() {
            return None;
        }
        if index < 9 {
            nanoseconds = nanoseconds * 10 + (digit - b'0') as u32;
        }
    }
    for _ in fraction.len()..9 {
        nanoseconds *= 10;
    }
    if !negative {
        return Some(Timestamp {
            seconds,
            nanoseconds,
        });
    }
    if nanoseconds == 0 {
        return Some(Timestamp {
            seconds: seconds.checked_neg()?,
            nanoseconds: 0,
        });
    }
    Some(Timestamp {
        seconds: seconds.checked_neg()?.checked_sub(1)?,
        nanoseconds: 1_000_000_000 - nanoseconds,
    })
}

#[cfg(test)]
mod tests {
    extern crate std;
    use super::super::{FileMetadata, Index, O_READ};
    use super::*;
    use std::vec;
    use std::vec::Vec;

    struct NoBase;
    impl BaseReader for NoBase {
        fn read_at(&mut self, _: u64, _: &mut [u8]) -> Result<(), VfsError> {
            Err(VfsError::Io)
        }
    }

    /// Growable backing with a byte quota, like the launch memory storage.
    struct Bytes {
        files: Vec<Vec<u8>>,
        limit: usize,
        used: usize,
    }
    impl OverlayStorage for Bytes {
        fn resize(&mut self, slot: usize, old: usize, new: usize) -> Result<(), VfsError> {
            assert_eq!(self.files[slot].len(), old);
            if self.used - old + new > self.limit {
                return Err(VfsError::OverlayLimit);
            }
            self.used = self.used - old + new;
            self.files[slot].resize(new, 0);
            Ok(())
        }
        fn read(&self, slot: usize, offset: usize, output: &mut [u8]) -> Result<(), VfsError> {
            let bytes = self.files[slot]
                .get(offset..offset + output.len())
                .ok_or(VfsError::Io)?;
            output.copy_from_slice(bytes);
            Ok(())
        }
        fn write(&mut self, slot: usize, offset: usize, input: &[u8]) -> Result<(), VfsError> {
            self.files[slot]
                .get_mut(offset..offset + input.len())
                .ok_or(VfsError::Io)?
                .copy_from_slice(input);
            Ok(())
        }
        fn clear(&mut self, slot: usize) {
            self.used -= self.files[slot].len();
            self.files[slot].clear();
        }
    }

    type Fs = VirtualFs<'static, NoBase, 0, 0, 8, Bytes, Vec<OverlayFile>>;

    const NOW: Timestamp = Timestamp {
        seconds: 1_700_000_000,
        nanoseconds: 5,
    };

    /// An instance filesystem with `/dest` to import into and `/outside`
    /// holding `/outside/secret`, which no member may reach.
    fn instance(objects: usize, limit: usize) -> Fs {
        let mut fs = Fs::with_namespace(
            Index::root_only(),
            NoBase,
            Bytes {
                files: vec![Vec::new(); objects],
                limit,
                used: 0,
            },
            vec![OverlayFile::empty(); objects],
        );
        fs.mkdir(b"/dest", 0o755).unwrap();
        fs.mkdir(b"/outside", 0o755).unwrap();
        let fd = fs.open(b"/outside/secret", O_WRITE | O_CREATE).unwrap();
        fs.write(fd, b"secret").unwrap();
        fs.close(fd).unwrap();
        fs
    }

    fn allow(_: ArchiveOperation) -> Result<(), i32> {
        Ok(())
    }

    /// Every live name with its metadata and bytes, in slot order.
    fn snapshot(fs: &Fs) -> Vec<(Vec<u8>, FileMetadata, Vec<u8>)> {
        (0..fs.namespace_capacity())
            .filter_map(|slot| {
                let (path, metadata) = fs.overlay_entry(slot)?;
                let mut bytes = vec![0; metadata.size as usize];
                if metadata.kind != NodeKind::Directory && metadata.kind != NodeKind::Fifo {
                    fs.read_overlay(slot, 0, &mut bytes).unwrap();
                }
                Some((path.to_vec(), metadata, bytes))
            })
            .collect()
    }

    /// Check the namespace indexes against the scans they replaced: the
    /// name and child chains, then `has_children` and the subtree `rename`
    /// would move, for every live name (each checks itself).
    fn indexes_exact(fs: &mut Fs) {
        fs.overlay.assert_consistent();
        let names: Vec<Vec<u8>> = snapshot(fs).into_iter().map(|(path, _, _)| path).collect();
        fs.has_children(b"/").unwrap();
        for name in names {
            fs.has_children(&name).unwrap();
            fs.subtree(&name);
        }
    }

    fn outside_untouched(fs: &Fs) {
        let names: Vec<Vec<u8>> = snapshot(fs)
            .into_iter()
            .map(|(path, _, _)| path)
            .filter(|path| !path.starts_with(b"/dest"))
            .collect();
        assert_eq!(names, [b"/outside".to_vec(), b"/outside/secret".to_vec()]);
        let secret = fs.metadata_no_follow(b"/outside/secret").unwrap();
        assert_eq!((secret.size, secret.links, secret.mode), (6, 1, 0o600));
    }

    // Archive construction -------------------------------------------------

    fn octal_field(output: &mut [u8], value: u64) {
        let digits = output.len() - 1;
        let text = std::format!("{value:0digits$o}");
        output[..digits].copy_from_slice(text.as_bytes());
        output[digits] = 0;
    }

    fn seal(header: &mut [u8; BLOCK]) {
        header[148..156].fill(b' ');
        let sum: u64 = header.iter().map(|b| *b as u64).sum();
        octal_field(&mut header[148..155], sum);
        header[155] = b' ';
    }

    fn header(kind: u8, name: &[u8], mode: u32, size: u64, link: &[u8]) -> [u8; BLOCK] {
        let mut header = [0u8; BLOCK];
        header[..name.len()].copy_from_slice(name);
        octal_field(&mut header[100..108], mode as u64);
        octal_field(&mut header[108..116], 1000);
        octal_field(&mut header[116..124], 1000);
        octal_field(&mut header[124..136], size);
        octal_field(&mut header[136..148], 1_234_567);
        header[156] = kind;
        header[157..157 + link.len()].copy_from_slice(link);
        header[257..263].copy_from_slice(b"ustar\0");
        header[263..265].copy_from_slice(b"00");
        seal(&mut header);
        header
    }

    fn payload(archive: &mut Vec<u8>, data: &[u8]) {
        archive.extend_from_slice(data);
        archive.resize(archive.len() + padding(data.len() as u64), 0);
    }

    fn pax_records(records: &[(&[u8], &[u8])]) -> Vec<u8> {
        let mut data = Vec::new();
        for (key, value) in records {
            let body = key.len() + value.len() + 3;
            let mut length = body + 1;
            while std::format!("{length}").len() + body != length {
                length += 1;
            }
            data.extend_from_slice(std::format!("{length} ").as_bytes());
            data.extend_from_slice(key);
            data.push(b'=');
            data.extend_from_slice(value);
            data.push(b'\n');
        }
        data
    }

    fn extended(archive: &mut Vec<u8>, kind: u8, records: &[(&[u8], &[u8])]) {
        let data = pax_records(records);
        archive.extend_from_slice(&header(
            kind,
            b"PaxHeaders/x",
            0o644,
            data.len() as u64,
            b"",
        ));
        payload(archive, &data);
    }

    fn end(archive: &mut Vec<u8>) {
        archive.resize(archive.len() + 2 * BLOCK, 0);
    }

    /// A member, also replayable as individual calls.
    #[derive(Clone)]
    enum Spec {
        Dir(&'static [u8], u32),
        File(&'static [u8], u32, Vec<u8>),
        Symlink(&'static [u8], &'static [u8]),
        Link(&'static [u8], &'static [u8]),
        Fifo(&'static [u8], u32),
    }

    fn archive(specs: &[Spec]) -> Vec<u8> {
        let mut archive = Vec::new();
        for spec in specs {
            let block = match spec {
                Spec::Dir(name, mode) => header(b'5', name, *mode, 0, b""),
                Spec::File(name, mode, data) => header(b'0', name, *mode, data.len() as u64, b""),
                Spec::Symlink(name, target) => header(b'2', name, 0o777, 0, target),
                Spec::Link(name, target) => header(b'1', name, 0o644, 0, target),
                Spec::Fifo(name, mode) => header(b'6', name, *mode, 0, b""),
            };
            archive.extend_from_slice(&block);
            if let Spec::File(_, _, data) = spec {
                payload(&mut archive, data);
            }
        }
        end(&mut archive);
        archive
    }

    const MTIME: Timestamp = Timestamp {
        seconds: 1_234_567,
        nanoseconds: 0,
    };

    /// The documented individual-call sequence for valid members beneath
    /// `/dest`, which an import must reproduce exactly.
    fn sequential(fs: &mut Fs, specs: &[Spec], directory_mode: u32) {
        let touch = |fs: &mut Fs, path: &[u8]| {
            fs.set_times(path, false, Some(NOW), Some(NOW)).unwrap();
            let split = path.iter().rposition(|b| *b == b'/').unwrap();
            fs.set_times(&path[..split], false, None, Some(NOW))
                .unwrap();
        };
        for spec in specs {
            let name = match spec {
                Spec::Dir(n, _)
                | Spec::File(n, _, _)
                | Spec::Symlink(n, _)
                | Spec::Link(n, _)
                | Spec::Fifo(n, _) => *n,
            };
            let mut path = b"/dest".to_vec();
            let parts: Vec<&[u8]> = name
                .split(|b| *b == b'/')
                .filter(|p| !p.is_empty() && *p != b".")
                .collect();
            for (i, part) in parts.iter().enumerate() {
                path.push(b'/');
                path.extend_from_slice(part);
                if i + 1 < parts.len() && fs.metadata_no_follow(&path).is_err() {
                    fs.mkdir(&path, directory_mode).unwrap();
                    touch(fs, &path);
                }
            }
            let vacate = |fs: &mut Fs, path: &[u8]| {
                if fs.metadata_no_follow(path).is_ok() {
                    fs.unlink(path).unwrap();
                }
            };
            match spec {
                Spec::Dir(_, mode) => {
                    match fs.metadata_no_follow(&path) {
                        Ok(metadata) if metadata.kind == NodeKind::Directory => {
                            fs.chmod(&path, *mode).unwrap();
                        }
                        existing => {
                            if existing.is_ok() {
                                fs.unlink(&path).unwrap();
                            }
                            fs.mkdir(&path, *mode).unwrap();
                            touch(fs, &path);
                        }
                    }
                    fs.set_times(&path, false, Some(NOW), Some(MTIME)).unwrap();
                }
                Spec::File(_, mode, data) => {
                    vacate(fs, &path);
                    let fd = fs.open(&path, O_WRITE | O_CREATE | O_EXCLUSIVE).unwrap();
                    touch(fs, &path);
                    for chunk in data.chunks(4096) {
                        fs.write(fd, chunk).unwrap();
                    }
                    fs.fchmod(fd, *mode).unwrap();
                    fs.fset_times(fd, Some(NOW), Some(MTIME)).unwrap();
                    fs.close(fd).unwrap();
                }
                Spec::Symlink(_, target) => {
                    vacate(fs, &path);
                    fs.symlink(target, &path).unwrap();
                    touch(fs, &path);
                    fs.set_times(&path, false, Some(NOW), Some(MTIME)).unwrap();
                }
                Spec::Link(_, target) => {
                    let mut source = b"/dest/".to_vec();
                    source.extend_from_slice(target);
                    vacate(fs, &path);
                    fs.hard_link(&source, &path, false).unwrap();
                }
                Spec::Fifo(_, mode) => {
                    vacate(fs, &path);
                    fs.mkfifo(&path, *mode).unwrap();
                    touch(fs, &path);
                    fs.set_times(&path, false, Some(NOW), Some(MTIME)).unwrap();
                }
            }
        }
    }

    /// Push `bytes` in pieces of `chunk` bytes into `/dest`.
    fn import_with(
        fs: &mut Fs,
        bytes: &[u8],
        chunk: usize,
        flags: u32,
        policy: &mut impl ArchivePolicy,
    ) -> (ArchiveImport, Result<ArchiveSummary, ArchiveError>) {
        let destination = fs.open_directory(b"/dest", 0).unwrap();
        let mut import = ArchiveImport::new(flags, 0o755).unwrap();
        let mut result = Ok(());
        for piece in bytes.chunks(chunk.max(1)) {
            result = fs.archive_write(&mut import, destination, piece, Some(NOW), policy);
            if result.is_err() {
                break;
            }
        }
        let outcome = result.and_then(|_| fs.archive_finish(&import));
        fs.archive_abort(&mut import);
        fs.close(destination).unwrap();
        (import, outcome)
    }

    fn import(fs: &mut Fs, bytes: &[u8]) -> Result<ArchiveSummary, ArchiveError> {
        import_with(fs, bytes, bytes.len(), 0, &mut allow).1
    }

    fn sample() -> Vec<Spec> {
        let large: Vec<u8> = (0..10_000u32).map(|n| (n % 251) as u8).collect();
        vec![
            Spec::Dir(b"./", 0o750),
            Spec::Dir(b"./usr/", 0o755),
            Spec::File(b"./usr/bin/tool", 0o755, b"#!/bin/sh\n".to_vec()),
            Spec::File(b"usr/share/data", 0o644, large),
            Spec::File(b"usr/share/empty", 0o600, Vec::new()),
            Spec::Symlink(b"usr/bin/alias", b"tool"),
            Spec::Symlink(b"lib", b"/usr/lib"),
            Spec::Link(b"usr/bin/hard", b"usr/bin/tool"),
            Spec::Fifo(b"run/queue", 0o620),
            Spec::Dir(b"usr/share", 0o700),
        ]
    }

    // Tests -----------------------------------------------------------------

    #[test]
    fn imports_every_member_kind_beneath_the_destination() {
        let mut fs = instance(64, 1 << 20);
        let summary = import(&mut fs, &archive(&sample())).unwrap();
        assert_eq!(
            summary,
            ArchiveSummary {
                members: 10,
                directories: 3,
                bytes: 10_010,
                complete: true,
            }
        );
        let tool = fs.metadata_no_follow(b"/dest/usr/bin/tool").unwrap();
        assert_eq!(
            (tool.kind, tool.mode, tool.links),
            (NodeKind::File, 0o755, 2)
        );
        assert_eq!(tool.modified, MTIME);
        assert_eq!(tool.accessed, NOW);
        let hard = fs.metadata_no_follow(b"/dest/usr/bin/hard").unwrap();
        assert_eq!(hard.inode, tool.inode);
        let fd = fs.open(b"/dest/usr/share/data", O_READ).unwrap();
        let mut data = vec![0; 10_001];
        assert_eq!(fs.read(fd, &mut data), Ok(10_000));
        assert!(data[..10_000]
            .iter()
            .enumerate()
            .all(|(n, b)| *b == (n % 251) as u8));
        fs.close(fd).unwrap();
        let mut link = [0; 16];
        let count = fs.read_link(b"/dest/lib", &mut link).unwrap();
        assert_eq!(&link[..count], b"/usr/lib");
        let queue = fs.metadata_no_follow(b"/dest/run/queue").unwrap();
        assert_eq!((queue.kind, queue.mode), (NodeKind::Fifo, 0o620));
        // The implicit parent was created first; its later member merged.
        let share = fs.metadata_no_follow(b"/dest/usr/share").unwrap();
        assert_eq!((share.kind, share.mode), (NodeKind::Directory, 0o700));
        let run = fs.metadata_no_follow(b"/dest/run").unwrap();
        assert_eq!((run.mode, run.modified), (0o755, NOW));
        // The archive's own root entry applies to the destination.
        assert_eq!(fs.metadata_no_follow(b"/dest").unwrap().mode, 0o750);
        outside_untouched(&fs);
    }

    #[test]
    fn import_equals_the_individual_calls_in_every_chunking() {
        let specs = sample();
        let bytes = archive(&specs);
        let mut expected = instance(64, 1 << 20);
        sequential(&mut expected, &specs, 0o755);
        let expected = snapshot(&expected);
        for chunk in [1, 7, 100, 511, 512, 513, 4096, 10_240, bytes.len()] {
            let mut fs = instance(64, 1 << 20);
            let (_, outcome) = import_with(&mut fs, &bytes, chunk, 0, &mut allow);
            assert!(outcome.unwrap().complete, "chunk {chunk}");
            assert!(snapshot(&fs) == expected, "chunk {chunk}");
        }
    }

    /// The same existing tree in two filesystems: files, a link, a FIFO and
    /// a directory with content, each of which a member replaces or merges.
    fn populated(objects: usize) -> Fs {
        let mut fs = instance(objects, 1 << 20);
        for (name, data) in [
            (b"/dest/file".as_slice(), b"old".as_slice()),
            (b"/dest/a", b"a"),
        ] {
            let fd = fs.open(name, O_WRITE | O_CREATE).unwrap();
            fs.write(fd, data).unwrap();
            fs.close(fd).unwrap();
        }
        fs.symlink(b"/outside", b"/dest/link").unwrap();
        fs.mkfifo(b"/dest/pipe", 0o600).unwrap();
        fs.mkdir(b"/dest/tree", 0o700).unwrap();
        fs.mkdir(b"/dest/tree/kept", 0o700).unwrap();
        fs
    }

    fn leak(name: std::string::String) -> &'static [u8] {
        std::boxed::Box::leak(name.into_bytes().into_boxed_slice())
    }

    #[test]
    fn import_into_a_populated_tree_equals_the_individual_calls() {
        let specs = vec![
            Spec::Symlink(b"file", b"elsewhere"),
            Spec::File(b"link", 0o640, b"was a link".to_vec()),
            Spec::Dir(b"pipe", 0o711),
            Spec::Fifo(b"a", 0o644),
            Spec::Dir(b"tree", 0o755),
            Spec::File(b"tree/kept/new", 0o600, b"inside".to_vec()),
            Spec::File(b"pipe/inner", 0o600, b"x".to_vec()),
            Spec::Link(b"tree/alias", b"link"),
            Spec::Link(b"tree/alias", b"pipe/inner"),
            Spec::Symlink(b"tree/kept/new", b"../../link"),
        ];
        let bytes = archive(&specs);
        let mut expected = populated(64);
        sequential(&mut expected, &specs, 0o755);
        expected.overlay.assert_consistent();
        for chunk in [1, 512, 3000, bytes.len()] {
            let mut fs = populated(64);
            let (_, outcome) = import_with(&mut fs, &bytes, chunk, 0, &mut allow);
            assert!(outcome.unwrap().complete);
            fs.overlay.assert_consistent();
            assert!(snapshot(&fs) == snapshot(&expected), "chunk {chunk}");
            outside_untouched(&fs);
        }
        let alias = expected.metadata_no_follow(b"/dest/tree/alias").unwrap();
        let inner = expected.metadata_no_follow(b"/dest/pipe/inner").unwrap();
        assert_eq!((alias.inode, alias.links), (inner.inode, 2));
        // The link the first hard link pointed at lost one name.
        assert_eq!(expected.metadata_no_follow(b"/dest/link").unwrap().links, 1);
    }

    #[test]
    fn a_large_generated_archive_equals_the_individual_calls() {
        // A fixed linear congruential sequence: directories, files of
        // every size class, links and replacements, deep and shallow.
        let mut state = 0x2545_f491_4f6c_dd1du64;
        let mut next = move |bound: u64| {
            state = state
                .wrapping_mul(6_364_136_223_846_793_005)
                .wrapping_add(1_442_695_040_888_963_407);
            (state >> 33) % bound
        };
        let mut specs = Vec::new();
        let mut files: Vec<&'static [u8]> = Vec::new();
        for index in 0..600u64 {
            let depth = next(4);
            let mut name = std::string::String::new();
            for level in 0..depth {
                name.push_str(&std::format!("d{}{}/", level, next(3)));
            }
            name.push_str(&std::format!("e{index}"));
            let spec = match next(10) {
                0 => Spec::Dir(leak(name), 0o700 + next(0o100) as u32),
                1 => Spec::Symlink(leak(name), b"../somewhere"),
                2 if !files.is_empty() => {
                    Spec::Link(leak(name), files[next(files.len() as u64) as usize])
                }
                3 => Spec::Fifo(leak(name), 0o600),
                _ => {
                    let size = [0, 1, 511, 512, 513, 4096, 9000][next(7) as usize];
                    let data = (0..size).map(|n| (n as u64 ^ index) as u8).collect();
                    let name = leak(name);
                    files.push(name);
                    Spec::File(name, 0o600 + next(0o200) as u32, data)
                }
            };
            specs.push(spec);
        }
        // Rewrite a tenth of the names as other kinds.
        for index in 0..60 {
            let Spec::File(name, _, _) = specs[index * 7] else {
                continue;
            };
            specs.push(Spec::Symlink(name, b"replaced"));
        }
        let bytes = archive(&specs);
        let mut expected = instance(2048, 16 << 20);
        sequential(&mut expected, &specs, 0o755);
        let expected_names = snapshot(&expected);
        for chunk in [509, 65_536] {
            let mut fs = instance(2048, 16 << 20);
            let (import, outcome) = import_with(&mut fs, &bytes, chunk, 0, &mut allow);
            assert!(outcome.unwrap().complete, "chunk {chunk}");
            assert_eq!(import.summary().members, specs.len() as u64);
            indexes_exact(&mut fs);
            assert!(snapshot(&fs) == expected_names, "chunk {chunk}");
        }
    }

    #[test]
    fn corrupted_streams_never_reach_outside_the_destination() {
        // Deterministic corruption of a valid archive that also holds links
        // to the outside: whatever an import makes of it, it stays beneath
        // the destination and leaves the namespace index exact.
        let mut specs = sample();
        specs.push(Spec::Symlink(b"usr/out", b"/outside"));
        specs.push(Spec::Symlink(b"up", b"../outside"));
        let original = archive(&specs);
        // Every header block, whose name and link fields corruption favors.
        let headers: Vec<usize> = (0..original.len() / BLOCK)
            .filter(|n| original[n * BLOCK + 257..n * BLOCK + 262] == *b"ustar")
            .collect();
        let mut state = 0x9e37_79b9_7f4a_7c15u64;
        let mut next = move |bound: usize| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            (state % bound as u64) as usize
        };
        for round in 0..1000 {
            let mut bytes = original.clone();
            for _ in 0..1 + next(8) {
                let at = match next(3) {
                    0 => next(bytes.len()),
                    1 => headers[next(headers.len())] * BLOCK + next(16),
                    _ => headers[next(headers.len())] * BLOCK + 157 + next(16),
                };
                if at >= bytes.len() {
                    continue;
                }
                match next(8) {
                    0 => bytes.truncate(at),
                    1 => bytes[at] = next(256) as u8,
                    2 => bytes[at] ^= 1 << next(8),
                    _ => bytes[at] = b"/./\0x"[next(5)],
                }
            }
            // Recompute checksums so corruption reaches the member logic.
            for block in bytes.chunks_mut(BLOCK) {
                if round % 4 != 0 && block.len() == BLOCK && block[257..262] == *b"ustar" {
                    seal(block.try_into().unwrap());
                }
            }
            let mut fs = instance(64, 1 << 20);
            let flags = (round % 4) as u32;
            let _ = import_with(&mut fs, &bytes, 1 + next(4096), flags, &mut allow);
            indexes_exact(&mut fs);
            outside_untouched(&fs);
        }
    }

    #[test]
    fn missing_parents_take_the_creation_mode() {
        let bytes = archive(&[Spec::File(b"a/b/c", 0o644, Vec::new())]);
        let mut fs = instance(32, 1 << 16);
        let destination = fs.open_directory(b"/dest", 0).unwrap();
        let mut import = ArchiveImport::new(0, 0o750).unwrap();
        fs.archive_write(&mut import, destination, &bytes, None, &mut allow)
            .unwrap();
        assert!(fs.archive_finish(&import).unwrap().complete);
        fs.close(destination).unwrap();
        for path in [b"/dest/a".as_slice(), b"/dest/a/b"] {
            let metadata = fs.metadata_no_follow(path).unwrap();
            assert_eq!((metadata.kind, metadata.mode), (NodeKind::Directory, 0o750));
        }
        // A destination that no longer exists takes no members, as for an
        // openat relative to a removed directory.
        let mut fs = instance(32, 1 << 16);
        fs.mkdir(b"/dest/gone", 0o755).unwrap();
        let destination = fs.open_directory(b"/dest/gone", 0).unwrap();
        fs.remove_directory(b"/dest/gone").unwrap();
        let mut import = ArchiveImport::new(0, 0o755).unwrap();
        assert_eq!(
            fs.archive_write(&mut import, destination, &bytes, None, &mut allow),
            Err(ArchiveError::Fs(VfsError::NotFound))
        );
        fs.close(destination).unwrap();
        assert!(fs.metadata_no_follow(b"/dest/gone").is_err());
    }

    #[test]
    fn refuses_absolute_names_and_parent_components() {
        for name in [
            b"/outside/x".as_slice(),
            b"../outside/x",
            b"a/../../outside/x",
            b"a/b/..",
            b"..",
        ] {
            let mut fs = instance(32, 1 << 16);
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&header(b'0', name, 0o644, 0, b""));
            end(&mut bytes);
            assert_eq!(
                import(&mut fs, &bytes),
                Err(ArchiveError::Fs(VfsError::InvalidPath)),
                "{}",
                std::string::String::from_utf8_lossy(name)
            );
            outside_untouched(&fs);
        }
        // A pax path is checked like a header name.
        let mut fs = instance(32, 1 << 16);
        let mut bytes = Vec::new();
        extended(&mut bytes, b'x', &[(b"path", b"../outside/pax")]);
        bytes.extend_from_slice(&header(b'0', b"harmless", 0o644, 0, b""));
        end(&mut bytes);
        assert_eq!(
            import(&mut fs, &bytes),
            Err(ArchiveError::Fs(VfsError::InvalidPath))
        );
        outside_untouched(&fs);
    }

    #[test]
    fn never_follows_links_while_creating_names() {
        // A link the same stream created, absolute or relative, to the
        // outside or to a directory inside: a later member may not pass it.
        for (target, member) in [
            (b"/outside".as_slice(), b"escape/new".as_slice()),
            (b"../outside", b"escape/new"),
            (b"../outside", b"escape/deeper/new"),
            (b"inside", b"escape/new"),
        ] {
            let mut fs = instance(32, 1 << 16);
            fs.mkdir(b"/dest/inside", 0o755).unwrap();
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&header(b'2', b"escape", 0o777, 0, target));
            bytes.extend_from_slice(&header(b'0', member, 0o644, 4, b""));
            payload(&mut bytes, b"data");
            end(&mut bytes);
            assert_eq!(
                import(&mut fs, &bytes),
                Err(ArchiveError::Fs(VfsError::SymlinkLoop))
            );
            assert!(fs.metadata_no_follow(b"/dest/inside/new").is_err());
            outside_untouched(&fs);
        }
        // A member replaces a final link instead of writing through it.
        let mut fs = instance(32, 1 << 16);
        fs.symlink(b"/outside/secret", b"/dest/secret").unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header(b'0', b"secret", 0o644, 3, b""));
        payload(&mut bytes, b"new");
        end(&mut bytes);
        assert!(import(&mut fs, &bytes).unwrap().complete);
        let replaced = fs.metadata_no_follow(b"/dest/secret").unwrap();
        assert_eq!((replaced.kind, replaced.size), (NodeKind::File, 3));
        outside_untouched(&fs);
        // Nor does a directory member merge into a link's target: it
        // replaces the link with a directory of its own.
        let mut fs = instance(32, 1 << 16);
        fs.symlink(b"/outside", b"/dest/dir").unwrap();
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header(b'5', b"dir", 0o700, 0, b""));
        bytes.extend_from_slice(&header(b'0', b"dir/new", 0o644, 0, b""));
        end(&mut bytes);
        assert!(import(&mut fs, &bytes).unwrap().complete);
        let dir = fs.metadata_no_follow(b"/dest/dir").unwrap();
        assert_eq!((dir.kind, dir.mode), (NodeKind::Directory, 0o700));
        assert!(fs.metadata_no_follow(b"/dest/dir/new").is_ok());
        assert_eq!(fs.metadata_no_follow(b"/outside").unwrap().mode, 0o755);
        outside_untouched(&fs);
    }

    #[test]
    fn hard_links_stay_inside_the_destination() {
        for (target, error) in [
            (b"../outside/secret".as_slice(), VfsError::InvalidPath),
            (b"/outside/secret", VfsError::InvalidPath),
            (b"escape/secret", VfsError::SymlinkLoop),
            (b"escape", VfsError::PermissionDenied),
            (b"missing/secret", VfsError::NotFound),
            (b"", VfsError::InvalidPath),
        ] {
            let mut fs = instance(32, 1 << 16);
            fs.symlink(b"/outside", b"/dest/escape").unwrap();
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&header(b'1', b"alias", 0o644, 0, target));
            end(&mut bytes);
            let expected = if target.is_empty() {
                ArchiveError::Malformed
            } else {
                ArchiveError::Fs(error)
            };
            assert_eq!(import(&mut fs, &bytes), Err(expected));
            assert!(fs.metadata_no_follow(b"/dest/alias").is_err());
            outside_untouched(&fs);
        }
    }

    #[test]
    fn limits_stop_the_stream_and_keep_what_individual_calls_would() {
        // Namespace capacity: /dest, /outside and its file use three slots.
        let specs: Vec<Spec> = [
            b"f0".as_slice(),
            b"f1",
            b"f2",
            b"f3",
            b"f4",
            b"f5",
            b"f6",
            b"f7",
        ]
        .iter()
        .map(|name| {
            Spec::File(
                std::boxed::Box::leak(name.to_vec().into_boxed_slice()),
                0o644,
                b"x".to_vec(),
            )
        })
        .collect();
        let mut fs = instance(8, 1 << 16);
        let bytes = archive(&specs);
        let (import, outcome) = import_with(&mut fs, &bytes, 700, 0, &mut allow);
        assert_eq!(outcome, Err(ArchiveError::Fs(VfsError::OverlayLimit)));
        assert_eq!(import.summary().members, 5);
        let mut expected = instance(8, 1 << 16);
        sequential(&mut expected, &specs[..5], 0o755);
        assert!(snapshot(&fs) == snapshot(&expected));
        outside_untouched(&fs);

        // Byte quota: the file that does not fit keeps the bytes it got.
        let mut fs = instance(32, 6 + 8192 + 4096);
        let specs = vec![
            Spec::File(b"small", 0o644, vec![1; 8192]),
            Spec::File(b"large", 0o644, vec![2; 10_000]),
            Spec::File(b"never", 0o644, vec![3; 1]),
        ];
        let bytes = archive(&specs);
        let destination = fs.open_directory(b"/dest", 0).unwrap();
        let mut import = ArchiveImport::new(0, 0o755).unwrap();
        let mut failure = None;
        for piece in bytes.chunks(4096) {
            if let Err(error) =
                fs.archive_write(&mut import, destination, piece, Some(NOW), &mut allow)
            {
                failure = Some(error);
                break;
            }
        }
        assert_eq!(failure, Some(ArchiveError::Fs(VfsError::OverlayLimit)));
        // Every later write reports the same error and changes nothing.
        let before = snapshot(&fs);
        assert_eq!(
            fs.archive_write(&mut import, destination, &[0; 512], Some(NOW), &mut allow),
            failure.map_or(Ok(()), Err)
        );
        assert_eq!(fs.archive_finish(&import), Err(failure.unwrap()));
        assert!(snapshot(&fs) == before);
        // The 4096-byte piece that held its header also held 3072 of its
        // bytes; the next piece no longer fit.
        let large = fs.metadata_no_follow(b"/dest/large").unwrap();
        assert_eq!((large.size, large.mode), (3072, 0o600));
        assert!(fs.metadata_no_follow(b"/dest/never").is_err());
        fs.archive_abort(&mut import);
        fs.close(destination).unwrap();
        outside_untouched(&fs);
    }

    #[test]
    fn names_longer_than_individual_calls_accept_are_refused() {
        let component = [b'n'; 100];
        // "/dest/" + 249 bytes = 255, the longest path a call accepts.
        let mut longest = Vec::new();
        longest.extend_from_slice(&component);
        longest.push(b'/');
        longest.extend_from_slice(&component);
        longest.push(b'/');
        longest.extend_from_slice(&component[..47]);
        assert_eq!(longest.len() + 6, 255);
        let mut fs = instance(32, 1 << 16);
        let mut bytes = Vec::new();
        extended(&mut bytes, b'x', &[(b"path", &longest)]);
        bytes.extend_from_slice(&header(b'0', b"short", 0o644, 0, b""));
        end(&mut bytes);
        assert!(import(&mut fs, &bytes).unwrap().complete);
        let mut path = b"/dest/".to_vec();
        path.extend_from_slice(&longest);
        assert!(fs.metadata_no_follow(&path).is_ok());

        let mut longer = longest.clone();
        longer.push(b'n');
        let mut fs = instance(32, 1 << 16);
        let mut bytes = Vec::new();
        extended(&mut bytes, b'x', &[(b"path", &longer)]);
        bytes.extend_from_slice(&header(b'0', b"short", 0o644, 0, b""));
        end(&mut bytes);
        assert_eq!(import(&mut fs, &bytes), Err(ArchiveError::NameTooLong));

        // GNU long names and long link targets are bounded the same way.
        let mut fs = instance(32, 1 << 16);
        let mut bytes = Vec::new();
        let name = [b'g'; 300];
        bytes.extend_from_slice(&gnu_header(b'L', b"././@LongLink", 301, b""));
        let mut data = name.to_vec();
        data.push(0);
        payload(&mut bytes, &data);
        bytes.extend_from_slice(&gnu_header(b'0', b"short", 0, b""));
        end(&mut bytes);
        assert_eq!(import(&mut fs, &bytes), Err(ArchiveError::NameTooLong));
        let mut fs = instance(32, 1 << 16);
        let mut bytes = Vec::new();
        extended(&mut bytes, b'x', &[(b"linkpath", &[b'l'; 257])]);
        bytes.extend_from_slice(&header(b'2', b"link", 0o777, 0, b"x"));
        end(&mut bytes);
        assert_eq!(import(&mut fs, &bytes), Err(ArchiveError::NameTooLong));
        outside_untouched(&fs);
    }

    fn gnu_header(kind: u8, name: &[u8], size: u64, link: &[u8]) -> [u8; BLOCK] {
        let mut block = header(kind, name, 0o644, size, link);
        block[257..265].copy_from_slice(b"ustar  \0");
        seal(&mut block);
        block
    }

    #[test]
    fn gnu_long_names_and_links() {
        let mut fs = instance(32, 1 << 16);
        let name = [b'a'; 180];
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&gnu_header(b'L', b"././@LongLink", 181, b""));
        let mut data = name.to_vec();
        data.push(0);
        payload(&mut bytes, &data);
        bytes.extend_from_slice(&gnu_header(b'0', b"truncated", 2, b""));
        payload(&mut bytes, b"ok");
        bytes.extend_from_slice(&gnu_header(b'K', b"././@LongLink", 181, b""));
        payload(&mut bytes, &data);
        bytes.extend_from_slice(&gnu_header(b'1', b"alias", 0, b"truncated"));
        end(&mut bytes);
        assert!(import(&mut fs, &bytes).unwrap().complete);
        let mut path = b"/dest/".to_vec();
        path.extend_from_slice(&name);
        let original = fs.metadata_no_follow(&path).unwrap();
        let alias = fs.metadata_no_follow(b"/dest/alias").unwrap();
        assert_eq!(
            (original.inode, original.links, original.size),
            (alias.inode, 2, 2)
        );
    }

    #[test]
    fn replaces_non_directories_and_merges_directories() {
        let mut fs = instance(32, 1 << 16);
        fs.mkdir(b"/dest/dir", 0o700).unwrap();
        let keep = fs.open(b"/dest/dir/keep", O_WRITE | O_CREATE).unwrap();
        fs.close(keep).unwrap();
        let old = fs.open(b"/dest/file", O_WRITE | O_CREATE | O_READ).unwrap();
        fs.write(old, b"old").unwrap();
        let old_inode = fs.fstat(old).unwrap().inode;
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header(b'5', b"dir", 0o755, 0, b""));
        bytes.extend_from_slice(&header(b'0', b"file", 0o640, 3, b""));
        payload(&mut bytes, b"new");
        end(&mut bytes);
        assert!(import(&mut fs, &bytes).unwrap().complete);
        assert_eq!(fs.metadata_no_follow(b"/dest/dir").unwrap().mode, 0o755);
        assert!(fs.metadata_no_follow(b"/dest/dir/keep").is_ok());
        let new = fs.metadata_no_follow(b"/dest/file").unwrap();
        assert_ne!(new.inode, old_inode);
        // An open description keeps the replaced object, as after unlink.
        let mut data = [0; 3];
        assert_eq!(fs.pread(old, 0, &mut data), Ok(3));
        assert_eq!(&data, b"old");
        fs.close(old).unwrap();

        // A non-directory never replaces a directory, whether or not it is
        // empty.
        for name in [b"dir".as_slice(), b"dir/empty"] {
            if name == b"dir/empty" {
                fs.mkdir(b"/dest/dir/empty", 0o755).unwrap();
            }
            let mut bytes = Vec::new();
            bytes.extend_from_slice(&header(b'2', name, 0o777, 0, b"/outside"));
            end(&mut bytes);
            assert_eq!(
                import(&mut fs, &bytes),
                Err(ArchiveError::Fs(VfsError::IsDirectory))
            );
        }
        assert!(fs.metadata_no_follow(b"/dest/dir/keep").is_ok());
        // A directory replaces a non-directory, as unlink and mkdir.
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&header(b'5', b"file", 0o755, 0, b""));
        end(&mut bytes);
        assert!(import(&mut fs, &bytes).unwrap().complete);
        let file = fs.metadata_no_follow(b"/dest/file").unwrap();
        assert_eq!((file.kind, file.mode), (NodeKind::Directory, 0o755));
        outside_untouched(&fs);
    }

    fn assert_rejected(bytes: &[u8], expected: ArchiveError) {
        let mut fs = instance(32, 1 << 16);
        let before = snapshot(&fs);
        assert_eq!(import(&mut fs, bytes), Err(expected));
        assert!(snapshot(&fs) == before, "a rejected header created a name");
    }

    #[test]
    fn malformed_streams_stop_before_their_member() {
        let good = header(b'0', b"file", 0o644, 0, b"");
        let mut checksum = good;
        checksum[0] = b'g';
        assert_rejected(
            &[&checksum[..], &[0; 1024]].concat(),
            ArchiveError::Malformed,
        );
        let mut magic = good;
        magic[257..263].copy_from_slice(b"ustaR\0");
        seal(&mut magic);
        assert_rejected(&[&magic[..], &[0; 1024]].concat(), ArchiveError::Malformed);
        let mut digits = good;
        digits[124..136].copy_from_slice(b"0000000009x\0");
        seal(&mut digits);
        assert_rejected(&[&digits[..], &[0; 1024]].concat(), ArchiveError::Malformed);
        // A lone zero block followed by more members.
        assert_rejected(
            &[&[0; 512][..], &good, &[0; 1024]].concat(),
            ArchiveError::Malformed,
        );
        // Directories, links and FIFOs carry no bytes.
        assert_rejected(
            &[&header(b'5', b"dir", 0o755, 1, b"")[..], &[0; 1536]].concat(),
            ArchiveError::Malformed,
        );
        // Extended headers must precede a member.
        let mut dangling = Vec::new();
        extended(&mut dangling, b'x', &[(b"path", b"x")]);
        end(&mut dangling);
        assert_rejected(&dangling, ArchiveError::Malformed);
        // Pax records must be well formed and bounded.
        for payload_bytes in [
            b"5 a=b\n".as_slice(),
            b"7 a=b\n".as_slice(),
            b"6 =bb\n".as_slice(),
            b"x6 a=b\n".as_slice(),
            b"6 ab\n\n".as_slice(),
            b"06 a=b".as_slice(),
        ] {
            let mut bytes = header(b'x', b"pax", 0o644, payload_bytes.len() as u64, b"").to_vec();
            payload(&mut bytes, payload_bytes);
            bytes.extend_from_slice(&good);
            end(&mut bytes);
            assert_rejected(&bytes, ArchiveError::Malformed);
        }
        let mut huge = Vec::new();
        extended(
            &mut huge,
            b'x',
            &[(b"comment", &[b'c'; ARCHIVE_RECORD_LIMIT])],
        );
        huge.extend_from_slice(&good);
        end(&mut huge);
        assert_rejected(&huge, ArchiveError::Unsupported);
        // Device, sparse and unknown members, and unknown keywords.
        assert_rejected(
            &[&header(b'3', b"tty", 0o600, 0, b"")[..], &[0; 1024]].concat(),
            ArchiveError::DeviceNode,
        );
        for kind in *b"SDMVZ" {
            assert_rejected(
                &[&header(kind, b"odd", 0o600, 0, b"")[..], &[0; 1024]].concat(),
                ArchiveError::Unsupported,
            );
        }
        for (kind, key) in [
            (b'x', b"GNU.sparse.map".as_slice()),
            (b'x', b"SCHILY.dev"),
            (b'g', b"path"),
            (b'g', b"mtime"),
        ] {
            let mut bytes = Vec::new();
            extended(&mut bytes, kind, &[(key, b"1")]);
            bytes.extend_from_slice(&good);
            end(&mut bytes);
            assert_rejected(&bytes, ArchiveError::Unsupported);
        }
        // Data after the end-of-archive marker.
        let mut trailing = archive(&[]);
        trailing.extend_from_slice(&[0; 9216]);
        let mut fs = instance(32, 1 << 16);
        assert!(import(&mut fs, &trailing).unwrap().complete);
        trailing.push(1);
        assert_rejected(&trailing, ArchiveError::Malformed);
    }

    #[test]
    fn an_unfinished_stream_reports_truncation_and_keeps_its_members() {
        let specs = vec![
            Spec::File(b"whole", 0o644, b"done".to_vec()),
            Spec::File(b"partial", 0o644, vec![7; 2000]),
        ];
        let bytes = archive(&specs);
        let mut fs = instance(32, 1 << 16);
        let destination = fs.open_directory(b"/dest", 0).unwrap();
        let mut import = ArchiveImport::new(0, 0o755).unwrap();
        fs.archive_write(
            &mut import,
            destination,
            &bytes[..1536 + 1000],
            None,
            &mut allow,
        )
        .unwrap();
        assert_eq!(fs.archive_finish(&import), Err(ArchiveError::Truncated));
        // The stream may still continue after an early query.
        fs.archive_write(
            &mut import,
            destination,
            &bytes[2536..2600],
            None,
            &mut allow,
        )
        .unwrap();
        fs.archive_abort(&mut import);
        fs.close(destination).unwrap();
        assert_eq!(fs.metadata_no_follow(b"/dest/whole").unwrap().size, 4);
        let partial = fs.metadata_no_follow(b"/dest/partial").unwrap();
        assert_eq!((partial.size, partial.mode), (1064, 0o600));
        // Abort released the member's descriptor: all eight are free again.
        let opened: Vec<i32> = (0..8)
            .map(|_| fs.open(b"/dest/whole", O_READ).unwrap())
            .collect();
        for fd in opened {
            fs.close(fd).unwrap();
        }
    }

    #[test]
    fn pax_values_and_extended_attributes() {
        let capability: &[u8] = b"\x01\x00\x00\x02\x00\x20\x00\x00";
        let mut bytes = Vec::new();
        extended(
            &mut bytes,
            b'g',
            &[
                (b"comment", b"generated"),
                (b"charset", b"ISO-IR 10646 2000 UTF-8"),
            ],
        );
        extended(
            &mut bytes,
            b'x',
            &[
                (b"path", b"usr/bin/ping"),
                (b"mtime", b"1700000000.25"),
                (b"uid", b"999999"),
                (b"uname", b"nobody"),
                (b"SCHILY.xattr.security.capability", capability),
            ],
        );
        bytes.extend_from_slice(&header(b'0', b"truncated-name", 0o755, 4, b""));
        payload(&mut bytes, b"ping");
        extended(&mut bytes, b'x', &[(b"mtime", b"-1.5"), (b"size", b"3")]);
        bytes.extend_from_slice(&header(b'0', b"old", 0o644, 0, b""));
        payload(&mut bytes, b"old");
        end(&mut bytes);

        // Extended attributes cannot be stored, so they are refused by default
        // before the member exists.
        let mut fs = instance(32, 1 << 16);
        assert_eq!(import(&mut fs, &bytes), Err(ArchiveError::Unsupported));
        assert!(fs.metadata_no_follow(b"/dest/usr").is_err());

        let mut fs = instance(32, 1 << 16);
        let (_, outcome) = import_with(&mut fs, &bytes, 333, ARCHIVE_DISCARD_XATTRS, &mut allow);
        assert!(outcome.unwrap().complete);
        let ping = fs.metadata_no_follow(b"/dest/usr/bin/ping").unwrap();
        assert_eq!((ping.mode, ping.size), (0o755, 4));
        assert_eq!(
            ping.modified,
            Timestamp {
                seconds: 1_700_000_000,
                nanoseconds: 250_000_000
            }
        );
        let old = fs.metadata_no_follow(b"/dest/old").unwrap();
        assert_eq!(old.size, 3);
        assert_eq!(
            old.modified,
            Timestamp {
                seconds: -2,
                nanoseconds: 500_000_000
            }
        );
        assert!(fs.metadata_no_follow(b"/dest/truncated-name").is_err());
    }

    #[test]
    fn special_modes_follow_chmod_unless_cleared() {
        let specs = vec![Spec::File(b"setuid", 0o4755, b"bin".to_vec())];
        let bytes = archive(&specs);
        let mut fs = instance(32, 1 << 16);
        assert_eq!(
            import(&mut fs, &bytes),
            Err(ArchiveError::Fs(VfsError::PermissionDenied))
        );
        // As after open, write and a refused fchmod.
        let left = fs.metadata_no_follow(b"/dest/setuid").unwrap();
        assert_eq!((left.mode, left.size), (0o600, 3));
        let mut fs = instance(32, 1 << 16);
        let (_, outcome) = import_with(
            &mut fs,
            &bytes,
            512,
            ARCHIVE_CLEAR_SPECIAL_MODES,
            &mut allow,
        );
        assert!(outcome.unwrap().complete);
        assert_eq!(fs.metadata_no_follow(b"/dest/setuid").unwrap().mode, 0o755);
        let mut sticky = Vec::new();
        sticky.extend_from_slice(&header(b'5', b"tmp", 0o1777, 0, b""));
        end(&mut sticky);
        let mut fs = instance(32, 1 << 16);
        assert_eq!(
            import(&mut fs, &sticky),
            Err(ArchiveError::Fs(VfsError::PermissionDenied))
        );
        assert_eq!(fs.metadata_no_follow(b"/dest/tmp").unwrap().mode, 0o777);
    }

    #[test]
    fn the_policy_approves_each_operation_in_order() {
        let specs = sample();
        let bytes = archive(&specs);
        let mut seen = Vec::new();
        let mut fs = instance(64, 1 << 20);
        let mut record = |operation| {
            seen.push(operation);
            Ok(())
        };
        assert!(
            import_with(&mut fs, &bytes, 512, 0, &mut record)
                .1
                .unwrap()
                .complete
        );
        use ArchiveOperation::*;
        assert_eq!(
            seen,
            [
                ChangeMode,
                SetTimes,
                CreateDirectory,
                SetTimes,
                CreateDirectory,
                CreateFile,
                ChangeFileMode,
                SetTimes,
                CreateDirectory,
                CreateFile,
                ChangeFileMode,
                SetTimes,
                CreateFile,
                ChangeFileMode,
                SetTimes,
                CreateSymlink,
                SetTimes,
                CreateSymlink,
                SetTimes,
                CreateHardLink,
                CreateDirectory,
                CreateFifo,
                SetTimes,
                ChangeMode,
                SetTimes,
            ]
        );
        // A refusal stops the stream with the policy's own code; members
        // before it remain.
        let mut fs = instance(64, 1 << 20);
        let mut deny_links = |operation| {
            if operation == CreateSymlink {
                Err(-1)
            } else {
                Ok(())
            }
        };
        let (import, outcome) = import_with(&mut fs, &bytes, 4096, 0, &mut deny_links);
        assert_eq!(outcome, Err(ArchiveError::Denied(-1)));
        assert_eq!(import.summary().members, 5);
        assert!(fs.metadata_no_follow(b"/dest/usr/share/empty").is_ok());
        assert!(fs.metadata_no_follow(b"/dest/usr/bin/alias").is_err());
    }

    #[test]
    fn numeric_fields_accept_base_256_and_reject_garbage() {
        let mut block = header(b'0', b"big", 0o644, 0, b"");
        block[124..136].copy_from_slice(&[0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 3]);
        seal(&mut block);
        let mut bytes = block.to_vec();
        payload(&mut bytes, b"abc");
        end(&mut bytes);
        let mut fs = instance(32, 1 << 16);
        assert!(import(&mut fs, &bytes).unwrap().complete);
        assert_eq!(fs.metadata_no_follow(b"/dest/big").unwrap().size, 3);
        assert_eq!(signed_numeric(&[0xff; 12]), Some(-1));
        assert_eq!(numeric(&[0xff; 12]), None);
        assert_eq!(octal(b"  0755 \0"), Some(0o755));
        assert_eq!(octal(b"07 55\0"), None);
        assert_eq!(
            decimal_time(b"12.000000001999"),
            Some(Timestamp {
                seconds: 12,
                nanoseconds: 1
            })
        );
        assert_eq!(
            decimal_time(b"-0.5"),
            Some(Timestamp {
                seconds: -1,
                nanoseconds: 500_000_000
            })
        );
        assert_eq!(decimal_time(b"1e3"), None);
        assert!(ArchiveImport::new(4, 0o755).is_err());
        assert!(ArchiveImport::new(0, 0o1755).is_err());
    }
}
