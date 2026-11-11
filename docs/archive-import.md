# Bulk archive import

Every managed syscall that touches owned storage is a supervisor round trip.
Unpacking a tree file by file costs about five of them per member: `openat`,
`write`, `fchmod`, `futimens` and `close`, plus `mkdirat`, `symlinkat` or
`linkat` for other kinds. A build that moves whole trees between steps as tar
archives pays that for every file it unpacks, although the archive already
holds everything the supervisor needs.

An archive import lets the workload hand configured launch one tar stream and
a destination directory. The supervisor applies each member itself, through
the same storage calls and contract decisions as the individual creates it
replaces, and the workload pays one mediated `write` per MiB of archive. It is
an optimization, not a new authority: an import can create exactly what the
same workload could create one call at a time, beneath one directory, and
never through a link.

The parser and member logic live in `crates/ginux-vfs/src/archive.rs`; the
launch adapter (descriptor, contract decisions, audit) lives in
`crates/ginux-init/src/launch_storage.rs` and `descriptors.rs`.

## Enabling and detecting it

Imports are off by default. An instance recipe enables them for its owned
storage:

```toml
[storage]
assignments = ["memory:/work"]
archive_import = true
```

The normalized configuration echoes `archive_import = true` only when it is
set; `storage.archive_import` is accepted as an override key. A Ginux that
predates the field rejects the recipe, because unknown fields fail closed.

A workload detects the feature by asking for it. Where imports are not
offered, the request answers `ENOTTY`, as Linux does for an ioctl a descriptor
does not implement: when the field is off, on an image or other non-owned
descriptor, on a non-directory, on an older Ginux, or on a plain Linux host. A
consumer should treat `ENOTTY` as "extract member by member instead". A
stream closed before any byte is written creates nothing.

## Interface

```c
#define GINUX_ARCHIVE_IMPORT 0x40104701 /* _IOW('G', 1, struct ginux_archive_import) */
#define GINUX_ARCHIVE_DISCARD_XATTRS      1u
#define GINUX_ARCHIVE_CLEAR_SPECIAL_MODES 2u

struct ginux_archive_import {
    uint32_t flags;       /* GINUX_ARCHIVE_* */
    uint32_t reserved[3]; /* must be zero */
};

int stream = ioctl(directory_fd, GINUX_ARCHIVE_IMPORT, &request);
/* write(2) the tar stream to `stream`, then: */
fsync(stream); /* 0 once the end-of-archive marker has been applied */
close(stream);
```

`directory_fd` must be a directory descriptor in owned storage, opened without
`O_PATH`. The result is a new descriptor, always close-on-exec, that accepts
the archive bytes in order. Members are applied as soon as their headers and
bytes arrive; nothing is buffered beyond one header block and one extended
header record.

Why this shape:

- **No new syscall number.** `ioctl` already exists in every contract and in
  the catalog. The request is classified as a filesystem write (below), so a
  contract that denies writes denies imports with no new selector.
- **Relative to a descriptor the workload already holds.** The destination is
  named the way `openat` names one: by an owned directory descriptor, after
  all of its path policy. A pseudo-path would add a name to every instance's
  namespace and need its own path rules; a configured endpoint would let the
  operator choose a destination the workload cannot see.
- **A stream, not a buffer.** Any tar writer can produce it with plain
  `write(2)`, archives of any size need no supervisor allocation, and an
  archive can be piped from a decompressor without an intermediate file.

### The stream descriptor

| Call | Result |
|---|---|
| `write` | Applies up to 1 MiB per call; returns the count consumed. A short count is a normal partial write; callers continue with the rest. |
| `writev` | Applies up to 16 KiB per call. |
| `fsync`, `fdatasync` | `0` once the end-of-archive marker has been applied; the error that stopped the import; otherwise `EIO` (not yet complete). |
| `close` | Always succeeds. The last close releases the member being written and records the import. |
| `fstat`, `statx` with `AT_EMPTY_PATH` | A write-only FIFO (`S_IFIFO`, mode `0200`, size 0). |
| `fcntl(F_GETFL)` | `O_WRONLY`. Descriptor flags, `dup`, fork and exec follow the public descriptor table. |
| `poll`, `epoll` | Always writable, never readable. |
| `read`, `pread`, `readv` | `EBADF` |
| `lseek`, `pwrite` | `ESPIPE` |
| `getdents64`, `fchdir`, a relative path from it | `ENOTDIR` |
| A further import request | `ENOTTY` |
| `mmap` | `ENODEV` |
| Reopen through `/proc/self/fd` | `EOPNOTSUPP`; `readlink` of it answers `ENOENT` |
| Anything else | `EINVAL` |

The stream holds its own private description of the destination directory.
It never acts as that directory, never shares its offset or status flags, and
never takes part in its `fcntl` locks.

The request itself fails with `EBADF` (unknown or `O_PATH` descriptor),
`ENOTTY` (not offered, see above), `EFAULT` (unreadable request), `EINVAL`
(unknown flags or non-zero reserved words), or `EMFILE` (no public descriptor,
or eight streams already open in this launch).

## The contract

The request is decided twice at syscall entry, like every configured call: as
`syscall.ioctl`, and as the semantic operation `filesystem.path.write`, whose
explicit denial wins. Stream writes are `write(2)` calls and are decided as
`syscall.write` and `filesystem.path.write`.

Each operation an import performs is then decided as the individual calls a
sequential extractor would make for it:

| Operation | Individual calls |
|---|---|
| Create a regular file | `openat(O_CREAT \| O_EXCL)` and `write` |
| Create a directory (member or missing parent) | `mkdirat` |
| Create a symbolic link | `symlinkat` |
| Create a hard link | `linkat` |
| Create a FIFO | `mknodat` |
| Remove a non-directory a member replaces | `unlinkat` |
| Set a directory's or FIFO's mode | `fchmodat` |
| Set the mode of the file being written | `fchmod` |
| Set the recorded modification time | `utimensat` |

The effective contract is immutable for a launch, so each row is resolved
once, when the launch starts, with the same `runtime_rule` lookup syscall
entry uses. A denied row stops the import at the first member that needs it,
with that rule's errno, exactly where the individual call would have failed.
An instance that denies `syscall.symlinkat`, for example, imports regular
files and stops at the first link member with `EPERM`.

## Accepted format

- **Headers:** POSIX ustar (`ustar\0` `00`, with the 155-byte name prefix) and
  GNU (`ustar  \0`). The checksum may be unsigned or signed. Numeric fields are
  octal or base-256. Old V7 headers without a magic are refused.
- **Member types:** regular files (`0`, NUL, `7`), hard links (`1`), symbolic
  links (`2`), directories (`5`) and FIFOs (`6`). Character and block devices
  (`3`, `4`) are refused with `EPERM`, as `mknod` refuses them in owned storage.
  Sparse, multivolume, directory-dump and all other types are refused with
  `EOPNOTSUPP`. Links, directories and FIFOs must not carry data.
- **pax extended headers (`x`):** `path`, `linkpath`, `size` and `mtime`
  (fractional and negative values) apply to the next member. `uid`, `gid`,
  `uname`, `gname`, `atime`, `ctime`, `comment`, `charset` and `hdrcharset`
  are accepted and ignored. Any other keyword is refused with `EOPNOTSUPP`.
- **Extended attributes:** `SCHILY.xattr.*` (and `LIBARCHIVE.xattr.*`,
  `SCHILY.acl.*`, `RHT.security.*`) cannot be stored by instance storage, just
  as `setxattr` cannot. They are refused with `EOPNOTSUPP` before their member
  exists, unless the request sets `GINUX_ARCHIVE_DISCARD_XATTRS`, in which case
  they are parsed and dropped.
- **Global headers (`g`):** may only carry the ignored keywords and extended
  attributes above; one that would rename or resize every member is refused.
- **GNU long names (`L`, `K`):** accepted up to the 256-byte path bound.
- **Records:** one extended header record is at most 8192 bytes.
- **End:** two zero blocks end the archive. Only zero bytes (record padding)
  may follow; anything else is `EBADMSG`. A lone zero block followed by a
  header is malformed.
- **Ownership** is never applied. Instance objects are owned by the virtual
  root, as after a `chown` that preserves it.

## Per-member rules

Every member becomes the sequence of ordinary `VirtualFs` calls below, the
same calls the configured `openat`, `mkdirat`, `symlinkat`, `linkat`,
`mknodat`, `unlinkat`, `fchmod(at)` and `utimensat` handlers make. Name
validation, file types, namespace capacity, byte quota, descriptor limits,
special-mode refusal and the overlay name index (`namespace.rs`) therefore
come from those calls and fail exactly as they do. The import adds only the
rules an archive needs on top of them.

### Names stay beneath the destination

- Member names and hard-link targets are relative to the destination. An
  absolute name or a `..` component is refused with `EINVAL` before anything
  is created; a pax name containing NUL is malformed. Empty and `.` components are dropped, so `./`
  names the destination itself.
- The destination's current path is joined with the member name. The result
  must fit the 255-byte path bound individual calls accept, or the member is
  refused with `ENAMETOOLONG`.
- The destination is re-resolved for every member through its descriptor and
  must still be owned storage. A removed destination takes no members
  (`ENOENT`), as for `openat` relative to a removed directory.

### Links are never followed

Every existing component between the destination and a member must be a real
directory. A symbolic link there stops the import with `ELOOP`, whether it was
in the tree before or an earlier member of the same stream made it; a regular
file stops it with `ENOTDIR`. The final component is never followed either: a
member replaces a link instead of writing through it. A hard-link target
follows the same rule, must already exist, and names the object itself, so a
target that is a link or directory is refused as `linkat` refuses it in owned
storage (`EACCES`).

This is stricter than GNU tar, which follows a directory link that already
exists in the tree. An archive written for an import must use real paths: a
member `lib/x` fails where `lib` is a link to `usr/lib`.

### Replace and merge

- A directory member merges into an existing directory: its contents stay and
  it takes the member's mode and time.
- A directory member replaces any other existing object (`unlinkat`, then
  `mkdirat`).
- A non-directory member replaces an existing non-directory (`unlinkat`
  without following it, then the create) and never replaces a directory
  (`EISDIR`), empty or not.
- Missing parents are created with `mkdirat(0777)` under the calling process's
  creation mask at the time of the request. A later directory member for the
  same name merges into it.

### Modes and times

The reference sequence is an extractor that restores recorded permissions
(`tar -xp`):

| Member | Individual calls |
|---|---|
| directory | `mkdirat(mode & 0777)`, `fchmodat(mode)` when special bits are set, `utimensat(mtime)` |
| regular file | `openat(O_CREAT \| O_EXCL, 0600)`, `write`..., `fchmod(mode)`, `futimens(mtime)`, `close` |
| symbolic link | `symlinkat`, `utimensat(AT_SYMLINK_NOFOLLOW, mtime)` |
| hard link | `linkat` |
| FIFO | `mknodat(mode & 0777)`, `fchmodat(mode)` when special bits are set, `utimensat(mtime)` |

- The recorded mode, all twelve bits, is applied as `chmod` applies it. Owned
  storage refuses set-user-ID, set-group-ID and sticky bits with `EACCES`; so
  does the import, unless the request sets `GINUX_ARCHIVE_CLEAR_SPECIAL_MODES`
  to clear them instead.
- A file keeps mode `0600` while its bytes arrive and takes its recorded mode
  when it is complete.
- Created names get the time of the `write` call as their access and
  modification time, and their parent's modification time, as individual
  creates do. Each member then takes its recorded modification time.
- Because creating a name updates its parent, a directory whose member comes
  before its contents ends with the time its last child was created, exactly
  as with individual calls. A writer that needs exact directory times emits
  each directory member after its contents: the directory exists by then and
  the later member merges into it.

### Limits

Namespace objects, file bytes and descriptors are charged as individual
creates charge them, and their exhaustion stops the import with the same
`ENOSPC` or `EMFILE`. One open stream holds one VFS descriptor for its
destination and, while a file member is incomplete, one more for that file.
A launch has at most eight open streams.

## Errors mid-stream

An import is not a transaction; it leaves what the same sequence of
individual calls would have left.

- A header or record that is malformed or unsupported is refused before its
  member's first effect.
- The first failing operation stops the import. The `write` that delivered it
  returns its error (any bytes consumed earlier in that call are not
  reported). Members completed before it remain. The failing member keeps
  what its calls had already done: a file keeps the bytes it received and
  mode `0600`, a replaced name stays removed, a created directory stays.
- Every later `write` and `fsync` returns the same error and changes nothing.
- A stream closed before its end-of-archive marker keeps every member already
  applied, including a partly written file. `fsync` reports `EIO` until the
  marker arrives.

| Cause | Error |
|---|---|
| Failed storage call | that call's errno (`EEXIST`, `EISDIR`, `ENOTDIR`, `ENOENT`, `ELOOP`, `ENOSPC`, `EMFILE`, `EACCES`, ...) |
| Absolute name or `..` | `EINVAL` |
| Name beyond the path bound | `ENAMETOOLONG` |
| Malformed archive | `EBADMSG` |
| Unsupported type, keyword or attribute | `EOPNOTSUPP` |
| Device member | `EPERM` |
| Contract denial | the denying rule's errno |
| Incomplete (from `fsync`) | `EIO` |

## Audit

The ioctl, every stream `write`, `fsync` and `close` produce ordinary
per-syscall audit records. The last close of a stream adds one record for the
whole import:

```text
ginux: audit archive-import process=1 members=9 directories=1 bytes=20012 outcome=complete result=0
```

`members` counts archive members applied, `directories` the missing parents
created for them, `bytes` the file data written. `outcome` is `complete`,
`incomplete` (closed before the end-of-archive marker, `result=-5`) or
`failed` (with the stopping errno). The record is charged to the same 64 KiB
audit budget as syscall records; after truncation, or with audit disabled, it
is not written.

## Limitations

- Extended attributes, ACLs, device nodes, sparse files and ownership are not
  represented in instance storage and are not imported.
- Directory links inside the destination are never followed (see above).
- The feature applies to configured launch with owned storage. Image paths and
  the demonstration backends do not offer it.
- An import is not atomic; a failed stream is not rolled back.

## Evidence

```sh
RUSTFLAGS='' cargo test -p ginux-vfs archive   # format, confinement, equivalence
RUSTFLAGS='' cargo test -p ginux-instance archive_import
RUSTFLAGS='' cargo test -p ginux-contract syscall_semantic_operations_are_catalogued
make build build-launch-storage-fixture
sudo make test-launch-storage                  # archive-import, -disabled, -denied
```

The VFS tests check every member kind, absolute and `..` names, links made
earlier in the same stream, hard links to the outside, limits reached
mid-stream, oversized names, replacement and merging, malformed and corrupted
streams, pax values and extended attributes, and that an import leaves the
same namespace, metadata and bytes as the reference sequence of individual
calls, in every chunking. The launch scenarios exercise the descriptor, the
contract decisions and the audit record through a real supervised workload.
