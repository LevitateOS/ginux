# Ginux

**Ginux is a configurable userspace kernel for isolated Linux compatibility
domains.** It runs as an ordinary Linux process and places an explicit,
versioned contract between managed workloads and the host kernel.

> [!IMPORTANT]
> Ginux began as an independent Rust kernel that booted directly through UEFI
> and ran a Rocky Linux 10 userspace. That research phase is complete. Its
> final source is permanently preserved on the
> [`bootable-kernel`](https://github.com/gmkurtzer/ginux/tree/bootable-kernel)
> branch and at the
> [`bootable-kernel-final`](https://github.com/gmkurtzer/ginux/tree/bootable-kernel-final)
> tag. Active development now continues here as a userspace kernel.

## Why the project changed direction

The standalone-kernel experiment proved that an AI coding agent, directed by
an experienced human through architecture, gates, and executable tests, could
construct a new kernel capable of running meaningful Linux userspace. It also
made the limits of that result obvious.

Linux is much more than source code. It is a stable interface, a development
process, a global community, vendor and hardware alignment, and decades of
compatibility and operational experience. Reimplementing kernel mechanisms
does not reproduce that ecosystem, and competing with Linux was never the
goal.

The more useful result is the boundary the experiment exposed. Linux must
preserve a broad userspace ABI; as Linus Torvalds put it, **“And we simply do
not break user space.”** The
[kernel regression documentation](https://docs.kernel.org/process/handling-regressions.html)
records that rule. Ginux can sit above Linux and deliberately offer a smaller
contract to each managed domain. Before a managed syscall has a host effect,
Ginux decides whether to emulate it, perform a validated mediated operation,
or deny it.

Put bluntly: **Linux must not break userspace; Ginux is designed to break the
full Linux ABI guarantee deliberately and selectively.** A domain receives
only the capabilities and interface behavior its approved workload requires.
Every departure is intended to be explicit, versioned, reviewable, and tested,
rather than accidental incompatibility.

This pivot is also a result of the development method. AI made it practical to
build disposable but executable prototype code, test an architectural idea,
learn from the running system, and carry the valuable parts into a better
design. The prototype was evidence, not an obligation to turn every experiment
into a product.

## What Ginux is now

```text
Host Linux kernel
  `- host systemd (real PID 1)
       `- ginux (ordinary trusted host process)
            `- domain contract
                 |- virtual processes and identities
                 |- virtual descriptors and kernel views
                 |- assigned devices and resources
                 `- managed Rocky Linux userspace
                      `- domain systemd (virtual PID 1, planned Gate 9)
```

Ginux supervises native x86-64 programs and intercepts managed syscalls before
their host effect. Its central dispatcher resolves the domain contract and
chooses one of three outcomes:

- **Emulate:** answer entirely from Ginux-owned state.
- **Mediate:** validate and translate the request, then perform a narrow
  Ginux-owned host operation.
- **Deny:** return a configured Linux-compatible error or terminate the task.

The current implementation includes:

- a security-focused x86-64 interpreter and a balanced native ptrace backend;
- strict, versioned domain configuration and lifecycle;
- a digest-pinned OCI root, immutable filesystem index, and bounded overlay;
- Ginux-owned process, credential, signal, synchronization, timer, and event
  models;
- virtual devices with explicit assignment, ownership, and revocation; and
- bounded virtual `/proc`, `/sys`, cgroup v2, mount, namespace, machine, and
  boot-identity views.

Gate 8 is complete. Booting Rocky Linux systemd as virtual PID 1 is the next
planned compatibility gate; it is not yet a current claim.

## Relationship to other systems

The userspace-kernel idea is established research and engineering territory.
Ginux explores a particular point in that design space:

| Approach | Primary boundary | Difference in emphasis |
|---|---|---|
| Linux [seccomp](https://docs.kernel.org/userspace-api/seccomp_filter.html) | Filters host syscalls | Restricts the existing ABI rather than defining a complete virtual contract |
| [User-Mode Linux](https://kernel.org/doc/html/latest/virt/uml/user_mode_linux.html) | Runs Linux as a host process | Reuses a complete Linux kernel over virtual hardware |
| [gVisor](https://gvisor.dev/docs/) | Implements an application kernel in userspace | Closely related model with different compatibility and performance goals |
| [Gramine](https://gramine.readthedocs.io/en/stable/) | Packages applications with a library OS | Uses manifests and a library-OS boundary |
| [Proxos](https://www.usenix.org/legacy/events/osdi06/tech/ta-min.html) | Routes calls between private and commodity OSes | Makes trust placement configurable across the syscall interface |
| **Ginux** | Gives each domain a versioned kernel contract | Treats the declared contract, virtual state, devices, resources, and lifecycle as one reviewable boundary |

Ginux does **not** promise the complete Linux ABI. Compatibility claims apply
only to named contracts, workloads, and executable evidence.

## Development and testing

The reference development environment is macOS arm64. QEMU TCG boots a pinned
Rocky Linux 10 x86-64 host where Ginux runs as an ordinary unprivileged
process. The host systemd remains real PID 1.

Check prerequisites:

```sh
make doctor
```

Prepare the pinned assets with explicit network operations:

```sh
make host-image-fetch
make image-helper-fetch
make domain-image-fetch
```

Build and run the deterministic suite offline after the caches are populated:

```sh
make build
make check
make test
```

Inspect the latest completed capability directly:

```sh
make demo-gate-8
```

Individual component and gate targets are documented in the `Makefile` and the
corresponding files under [`docs/`](docs/) and [`hdae/`](hdae/).

## Security model and limitations

The primary adversary controls a process inside a domain. The host kernel,
hardware, Ginux executable and approved configuration, boot chain, and
operator are currently trusted. The balanced native backend still relies on
the host for ELF loading, address spaces, page faults, signals, scheduling,
and ptrace; those remain host-kernel attack surface.

Ginux is research software. It has not received independent security
certification, does not provide complete Linux compatibility, and is not ready
for production workloads. Unknown contract operations fail closed, but current
coverage and guarantees are limited to the tested gates.

The full intent, threat model, invariants, and gate plan live in:

- [`hdae/PROJECT.md`](hdae/PROJECT.md)
- [`hdae/ARCHITECTURE.md`](hdae/ARCHITECTURE.md)
- [`hdae/PLAN.md`](hdae/PLAN.md)
- [`hdae/STATUS.md`](hdae/STATUS.md)

## Development method

Ginux is developed with
[Human-Directed Agentic Engineering (HDAE)](https://github.com/gmkurtzer/hdae):
human-owned product intent, architecture, constraints, and acceptance
boundaries combined with agent-executed implementation, diagnosis, and test
loops. Each approved gate records its scope, non-goals, acceptance criteria,
verification, evidence, and stopping point in `hdae/`.

## Historical standalone kernel

The independent bootable kernel remains available for research and historical
reference:

- [final branch: `bootable-kernel`](https://github.com/gmkurtzer/ginux/tree/bootable-kernel)
- [final tag: `bootable-kernel-final`](https://github.com/gmkurtzer/ginux/tree/bootable-kernel-final)
- [technical report and DOI](https://doi.org/10.5281/zenodo.23682548)

It is no longer the active development line. The code remains available under
the repository's existing terms for anyone who independently chooses to study
or fork it.

The name remains a joke in the same family as Linux: **Ginux** combines Linux,
GPT, and Greg. To keep the author's ego within its configured resource limit,
the `G` officially stands for GPT.

## License

Ginux is available under the Apache License 2.0. See [`LICENSE`](LICENSE) and
[`NOTICE`](NOTICE).

## Configured native launch

Running `ginux` without arguments selects the interception demonstration.
Unknown or incomplete commands exit 2 with diagnostics on stderr and no workload
output; they do not select the demonstration.

On x86-64 Linux, `ginux launch <config> <root> [--result-file <fresh host path>]`
executes `[domain].init` with the configured arguments and environment inside
the supplied host root directory. The bootstrap requires chroot and credential
change privileges, and a kernel with `close_range` (Linux 5.9 or later).
It drops to UID/GID 1000 before executing the workload. The configuration must
select `profile = "balanced"` and `backend = "ptrace-native"`. Only the `null`
device assignment and memory-storage backend described below are supported.

`[domain].workdir` is optional and defaults to `/work`; `/` is also supported.
The bootstrap creates the working directory if its parent exists, then enters
it after dropping privileges. Init and working-directory paths are limited to
128 bytes and must be absolute without `..` path components. Up to seven
arguments of 128 bytes each and eight `NAME=value` environment entries of
256 bytes each are accepted. Invalid or oversized input fails before launch.

Workload stdout stays separate from supervisor diagnostics on stderr. Only
stdin, stdout, and stderr are inherited by the workload. The launcher returns
the workload exit code, or `128 + signal` for signal termination. Startup
failure returns 2; supervision or result-writing failure returns 1. Non-x86-64
syscall ABIs and job-control
group stops fail explicitly. Audit output is capped at 64 KiB plus a truncation
notice. Process resource quotas remain unfinished; anonymous writable backing
has the allocation bound described below.

Configured `poll` resolves at most 16 public descriptors through their owning
table. Pipes, assigned memory files/directories, null, and console aliases may
share a query; negative descriptors are ignored and closed/unknown descriptors
report `POLLNVAL`. Pipe readiness includes buffered input, available output
space, peer-close `POLLHUP` and missing-reader `POLLERR`. Error/hangup events are
reported even with an empty requested mask. Timeouts from 0 through 300000 ms
and negative (infinite) waits are supported; unreadable or unwritable arrays
return `EFAULT`. Parked queries retry on object changes; finite and console
waits also use a 1 ms supervisor tick, keeping deadlines while other tasks run.
Infinite owned-object waits need no periodic retry. Console queries use only
the supervisor's explicitly shared stdio OFDs; image-file polling returns
`EOPNOTSUPP`, never a query on a coincidentally numbered host descriptor.
General nonfatal signal interruption/restart of parked queries remains
unfinished; SIGKILL death is consumed and reaped through the task owner.

Optional `[storage].assignments` entries of the form `"memory:/absolute/path"`
declare empty, ephemeral writable namespaces. For example:

```toml
[storage]
assignments = ["memory:/work", "memory:/work/build", "memory:/out"]
```

Each assignment creates its directory and parents in supervisor-owned memory.
Overlapping assignments can precreate nested directories. Image files beneath
an assigned path are hidden; missing files there never fall through to native
storage. Paths must be canonical, unique, and cannot cover init, `/`, `/proc`,
`/sys`, or `/dev`. Up to eight assignments fit the existing 64-byte entry bound.
Without assignments, native image access remains read-only.

This backend supports regular-file open/create/exclusive-create/truncate/append,
read/write/pread, ftruncate, seek, close, basic descriptor flags, mkdir, unlink,
chmod and stat/fstat/fstatat/statx metadata. Owned directory descriptions support
getdents64, rewind/cookies and relative openat/mkdirat/fstatat/unlinkat/chmodat.
Aliases and fork share directory offsets; failed directory copyout does not
consume records. Enumeration returns only direct children and domain inode IDs.
Rename/renameat and renameat2 (zero flags or NOREPLACE) move overlay files/trees,
preserving open objects across replacement. Nonempty directory removal and
invalid replacements fail before mutation. Empty directories can be removed
while open; their handles retain metadata but cannot create new children.
Minimal assignment roots remain busy; overlapping assignments merely seed
ordinary nested directories. Normal fchmod/chmod accept full st_mode values
while special permission bits remain unsupported.
Relative paths without a directory fd use the calling process's current directory.
Owned chdir/fchdir retain directory identity across rename and exec; fork copies
the reference and threads share cwd. Removed cwd returns ENOENT rather than
entering the immutable image directory underneath it.
Owned symlink/symlinkat, readlink/readlinkat and nofollow metadata are supported.
Resolution expands links before processing parent components, bounds link chains,
and rechecks storage assignment boundaries. Unlink and rename act on the final
link itself; exclusive create and O_NOFOLLOW retain their distinct semantics.
Cross-image/owned traversal, native-image relative directory-fd access, image
subtree mutation remain unsupported.
Owned regular-file link/linkat names share inode, bytes, permissions and link
counts. Unlink removes a name; remaining links, open handles and executable
pins keep its data alive. Capacity failure leaves existing names unchanged.
Owned execution and private file mappings are described below.
This is not a complete unified image/overlay filesystem. IO is bounded to 4096 bytes per call. Metadata supports
a configurable namespace and 64 independently opened file handles.
`[storage].max_objects` defaults to 16384, accepts 1–1000000 and includes seeded
directories and live or pinned namespace slots. Namespace and backing metadata
use bounded supervisor allocations rather than stack arrays. Their page-rounded
size is charged before file bytes. Optional `[storage].max_bytes` sets a positive
file-data budget; data plus metadata must fit `[resources].memory_mib`. If
omitted, file bytes use the remaining memory budget. File bytes grow on demand in anonymous supervisor mappings rather than
fixed per-file arrays. Their total mapped capacity, including page rounding and
growth reserve, cannot exceed `[resources].memory_mib`; files share that bound
instead of a 64 KiB per-file ceiling. This accounts for overlay backing, not
total supervisor/tracee RAM. Allocation exhaustion returns `ENOSPC` without
changing the file's length, bytes or open offset. Shrinking/truncating returns
unused mapped pages; regrowth and sparse gaps read as zero. Unlinked bytes remain
until the last open reference closes, and teardown releases all mappings.
Aliases use the common descriptor table. Metadata and handle exhaustion return
`ENOSPC` and `EMFILE` respectively.

Configured launch gives each process a table of up to 256 public descriptors for bootstrap
stdio, immutable-image files, writable files, devices and pipes. Allocation uses
the lowest free number; native opens reserve a slot before running. Backend
handles stay private, including when the kernel reuses an underlying fd number.
Dup/dup2/dup3 and fcntl duplication share an open description across owners;
close-on-exec flags belong to each public descriptor. Owned backends close only
after their last alias across all processes. Syscall arguments are translated for native IO/metadata/
mmap and restored at exit. Native locks, leases and signal ownership are denied.

Bootstrap constrains the real descriptor soft/hard limits to 256 while keeping
lower operator limits. Allocation respects that lower soft limit; runtime
NOFILE-limit changes are currently denied. Reported limits are not inflated to
accommodate backend handle ranges. Libc spawn preflight now accepts the public
numbers. Relative operations on owned directory handles stay within assigned
storage; attempts to use a private handle or mutate an unassigned tree fail.
Guest-memory copies respect page protections, including partial read copyout.
No writable host descriptor is exposed. Data disappears at domain teardown;
there is no retention, export or storage generation.

The configured `/dev` view is an immutable virtual directory, empty by default;
image entries beneath it are hidden. `[devices].assignments = ["null"]` exposes
`/dev/null` through the existing device registry: reads return EOF and writes
discard up to 4096 bytes per call. Stat/fstat/fstatat/statx report a character
device with domain-owned identity and major/minor 1:3. Open access modes,
close-on-exec descriptor flags, seek, close and basic access queries are
supported; device metadata cannot be changed. There are 64 open-device slots.
Unknown and duplicate assignments fail before launch. Device aliases share the
common descriptor table and handle lifetime. No host device node or descriptor
is used. Null is immediately readable/writable for polling. Additional device
types are not implemented by configured launch yet.

Anonymous `pipe`/`pipe2` are emulated with supervisor-owned memory and virtual
handles. Up to sixteen channel buffers hold 65536 bytes each; aliases use the common table.
A local `AF_UNIX` / `SOCK_SEQPACKET` pair consumes two buffers and supports
messages up to 4096 bytes, duplex read/write, nonblocking IO, polling and
close-on-exec. Local socket names and descriptor transfer are unsupported.
Configured TCP connections have a separate bounded owner described below.
`pipe2` accepts only `O_CLOEXEC|O_NONBLOCK`. IO is bounded to 4096 bytes per call;
writes of up to 4096 bytes are atomic. Reads consume only bytes successfully
copied out, so invalid/partially inaccessible destinations do not lose data.
Read/write direction, EOF, SIGPIPE, metadata, seek rejection, descriptor/status
flags, `FIONBIO`, pipe-size queries and aliases across owners are supported.
Alias status flags and endpoint lifetimes are shared; close-on-exec flags are
per descriptor. No native pipe or host descriptor is given to the workload.

Nonblocking empty/full operations return `EAGAIN`. Blocking operations stay
stopped at entry until a peer changes readiness or exits. No native pipe fd is
passed through. Byte-flow checks alone do not prove ordinary child commands work.

Configured launch supervises up to 16 native tasks through the existing process
owner. Fork and vfork are supported, as are clone flags `SIGCHLD`,
`CLONE_VM | CLONE_VFORK | SIGCHLD`, libc fork's
`CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID | SIGCHLD` (`0x1200011`), and the
x86-64 pthread shape `0x3d0f00`. Libc fork suppresses native child-TID copyout
and publishes virtual identity into the child's private address space before it
runs. Invalid/readonly child-TID addresses do not force writes or fail the fork;
kernel clear-TID registration remains intact.
Pthread tasks share their process's descriptor table, retain independent syscall
transactions, and use distinct virtual TIDs with a common virtual process ID.
Kernel parent-TID copyout is suppressed; the supervisor publishes the virtual TID
at birth, and native clear-TID/futex wakeup supports joins. Other clone shapes,
clone3, cross-process shared tables and namespace creation remain unsupported. Each
child is registered at its ptrace birth stop before it can execute. Public
process IDs start at 1. Fork returns the virtual child ID; getpid/gettid/getppid/
getpgrp and SIGCHLD sender identities use domain IDs. Native descriptor tables
inherit the kernel's shared file offsets; owned files/devices/pipes share backend
references until their last alias or pending IO reference is released. A blocked
owned read/write pins its original object when another thread closes/reuses the
public number. Native descriptor mutations settle before a fork snapshot; peers
cannot change the table until the kernel confirms the child birth. Thread exit
leaves peer handles intact, including after the process leader exits. Getcwd
reports the owned or immutable-image cwd selected by chdir/fchdir.

Wait4 supports a positive virtual child ID or -1, with options 0 or WNOHANG and
no rusage buffer. An invalid status pointer does not consume the child. Orphans
are adopted by the virtual init, while the supervisor acts as the native
subreaper. Kill supports positive domain IDs with signals 0 or SIGKILL; other
signal forms are rejected. SIGCHLD auto-reap dispositions are rejected; bootstrap
resets an inherited ignored SIGCHLD to its default disposition.
Native rt_sigreturn restores the kernel signal frame, allowing handlers to
return to the interrupted program. A real SIGCHLD handler case checks virtual
sender identity, a handler syscall, and continued execution after return.
Job control, interruption/restart of parked calls and SIGCHLD notification for adopted
children and robust-futex owner-death behavior remain incomplete. Supported
futex operations are wait/wake/requeue and their ordinary variants; PI futexes
are denied before the kernel can publish native owner TIDs. Final root-process
exit or supervision failure kills and reaps all remaining
descendants and releases owned descriptors before reporting completion.
Image execve and execveat are supervised, including relative paths from the
configured workdir, absolute execveat paths, and AT_EMPTY_PATH on image
file descriptors. Relative native-image directory-fd execution remains
unsupported. Virtual devices cannot execute; assigned file paths use the owned
loader described below.
Before exec, controlled fcntl syscalls synchronize each native handle's CLOEXEC
bit: any surviving public alias keeps its native handle. The supervisor replays
the original verified x86-64 syscall instruction; no executable bytes change.
Only PTRACE_EVENT_EXEC retires public CLOEXEC descriptors and owned references.
Failed exec preserves every public descriptor and its flags. Successful exec
keeps task identity and advances the existing process owner's exec state. Exec
currently requires the sole remaining task to be its process leader; other
threaded exec transitions return EOPNOTSUPP.
Owned ELF64 x86-64 files support execve and execveat, including owned directory
descriptors and AT_EMPTY_PATH on an open, possibly unlinked file. VFS checks
executable permissions and rejects writable open descriptions with ETXTBSY.
Executable references survive fork and keep unlinked objects alive; replacing
the last executing process releases write exclusion without changing file
offsets or names.

The exec transaction creates a private CLOEXEC memfd in the stopped tracee.
The supervisor opens only that registered task's fresh kernel fd through procfs,
copies pinned VFS bytes into it, applies mandatory write/grow/shrink/seal locks,
sets mode 0500 and closes its own descriptor. The tracee then executes that
sealed ELF through execveat. The private fd never enters the public table: the
kernel closes it on success, and the transaction closes it before returning a
failed exec. No named host output file is created. Supervisor access to the
tracee's procfs fd view is required; failure propagates without fallback.
Named owned shebang scripts support up to four consecutive owned interpreters,
followed by an owned ELF or the kernel's image interpreter loader. Resolution
pins every owned script until exec commits, enforces executable permissions and
write exclusion, and rejects cycles/excessive nesting with ELOOP. Each shebang's
single optional argument and any recursive image interpreter prefix are retained. The new
exec stack restores the original script pathname in argv and AT_EXECFN before
user code runs. Arguments and environment survive unchanged; the replaced
argv[0] follows kernel shebang behavior. The script backing survives kernel
exec, then a private close/replay retires it before the interpreter's first
syscall. It never enters the public descriptor table. Script pins release on
interpreter commit; ELF pins retain their process lifetime.

Absolute execve/execveat names and cwd-relative execve names are supported.
Owned scripts also support execveat on an open/unlinked file and relative to an
owned directory descriptor, including a renamed directory. The interpreter sees
the public /dev/fd/N[/path] name. Readonly open/openat resolves that name through
the public table and creates a fresh owned description with offset zero; it can
retain an unlinked object independently of its source description. It rejects
writes, native/device/pipe descriptors and directory escapes rather than passing
an integer to the native kernel. General /dev/fd metadata and procfs semantics
are not provided. Up to four consecutive owned shebang scripts may lead to an
owned ELF or native image interpreter chain. Every owned script stays pinned
until exec commits or fails; cycles and excessive depth return ELOOP. A script
whose required source/relative directory descriptor is CLOEXEC returns ENOENT.
Script argv/environment arrays are bounded to 4096 entries each. Only the new
exec address space receives stack writes, including after vfork/CLONE_VM. A
failure restoring that committed stack stops the domain rather than pretending
the old program can resume. Other invalid formats return ENOEXEC. Executable
snapshots add memory beyond the VFS
mapping budget; total process/kernel memory accounting is unfinished.

Signals interrupting descriptor synchronization or private-fd preparation fail the domain explicitly;
restart/deferred delivery for that preparation remains incomplete. Path checking
resolves owned links within assigned storage; traversal across the separate
image and owned namespaces remains unsupported.
Image-file polling, links, shared writable file mappings and a full
image/overlay resolver remain incomplete. Compiler compatibility remains bounded
by these and the configured task, descriptor and storage limits.

When requested, the result file is reserved exclusively before launch, with
mode 0600 and a maximum path length of 512 bytes. Existing files are never
overwritten. After completion, it contains one synced JSON object:

```json
{"version":1,"outcome":"exited","code":0,"signal":null,"generation":null}
```

`outcome` is `exited`, `signaled`, or `supervisor-error`; only the relevant
`code` or `signal` is populated. Storage generations are not implemented, so
`generation` is null. A missing, empty, or malformed result is a protocol failure.
A failure to write, sync, or close the result returns 1 even if the workload
succeeded. Consumers should wait for launcher completion before reading it.

The focused Linux integration scenario consumes existing binaries:

```sh
make build
make build-launch-fixture
make build-gate1-fixture
sudo make test-gate1-setup
sudo make test-launch
make build-launch-storage-fixture
sudo make test-launch-storage
make build-launch-device-fixture
sudo make test-launch-devices
make build-launch-pipe-fixture
sudo make test-launch-pipes
make build-launch-fd-fixture
sudo make test-launch-fds
make build-launch-task-fixture
sudo make test-launch-tasks
make build-launch-exec-fixture
sudo make test-launch-exec
make build-launch-thread-fixture
sudo make test-launch-threads
make build-launch-poll-fixture
sudo make test-launch-poll
make build-launch-directory-fixture
sudo make test-launch-directories
make build-launch-owned-exec-fixture
sudo make test-launch-owned-exec
make build-launch-script-fixture
sudo make test-launch-scripts
sudo make test-native-supervision
```

## Configured TCP grants

Networking is disabled with `[network].backend = "none"`. A configured launch
may select `backend = "mediated"` with up to eight numeric `endpoints`, such as
`["192.0.2.10:443", "[2001:db8::1]:443"]`, `max_connections` between 1 and 16,
and a positive `max_bytes` aggregate sent/received budget. Hostname resolution
and TLS verification belong to the caller and workload respectively; Ginux
never expands the endpoint grant. IP/port grants do not isolate HTTP paths or
hostnames sharing an address. Connect outside the set fails before a host
connection is created. Datagram, listening and arbitrary socket operations
remain denied.

TCP descriptors share the existing public descriptor, alias and fork owners.
Their private nonblocking host sockets remain in the supervisor. Blocking and
nonblocking connect/read/write, vectored IO, poll/ppoll, SO_ERROR, socket names,
TCP_NODELAY, receive/send timeouts and shutdown use the bounded backend and task
scheduler. Transfer accounting counts successful bytes once across all aliases;
exhaustion is EDQUOT, socket capacity exhaustion is EMFILE, and teardown closes
connecting and connected sockets. Live sockets are never exported or restored.
The focused scenario is `make build-launch-network-fixture` followed by
`sudo make test-launch-network`.

## Native process scenarios

The separate `process-native <config> <executable>` command exercises native
fork, clone, vfork, exec, threads, waits, termination signals, and pipes. It
executes a trusted host fixture as the caller, without chroot; it does not
require root on a host that permits tracing child processes. Configured
`launch` remains a separate entry point and does not yet use this process loop.

Process creation returns virtual identities, including clone TID cells.
Untraced, reparenting, namespace, and unsupported clone flags are denied.
Thread slots are reclaimed on exit. `CLONE_FILES` shares one descriptor table;
ordinary fork copies it, and exec unshares it before closing CLOEXEC entries.
Worker-thread exec preserves the group's process identity. Inherited host
files above stderr are closed before execution. PI futex operations and queries
for another task's robust list are unsupported.

Build the fixtures explicitly, then run their independent scenarios:

```sh
make build build-process-fixtures
make test-process-native
make test-process-native SCENARIO=shared_pipe
make test-process-native SCENARIO=thread_exec
```

The scenarios consume existing binaries under `.artifacts/process`, including
checks for syscall ABI dispatch, clone restrictions, descriptor inheritance,
thread reuse, successful and failed worker exec, signals, wait-status writes,
nonblocking waits, and vfork. The existing native fork fixture also runs. These
checks do not claim complete libc, job-control, or systemd compatibility.

Configured owned files support private mappings and read-only shared mappings.
Mediated writes and truncation affect the same anonymous backing; private writes
remain copy-on-write, and unlinking preserves existing mappings. Writable shared
mappings and shared protection upgrades are rejected. Mapping uses a temporary
readonly descriptor transfer through a private local socket, requiring host
`pidfd_open`/`pidfd_getfd` support and ptrace access. Temporary descriptors and
scratch bytes are retired before the workload resumes. Fixed mappings cannot
replace the transaction's syscall instruction or scratch stack region. Failure
or a signal during descriptor transfer stops the domain instead of resuming a
partially transformed syscall. This adds no retained-storage guarantee.

Configured launch accepts `--export-file <fresh tar path>` to retrieve its owned
writable files after a successful workload exit. The supervisor first terminates
and reaps remaining tasks, then writes regular files, directories and symlinks to
the caller-selected archive, preserving file modes, long paths and link targets. Deleted names and
immutable image contents are excluded. Guest paths are archive data and never
select host destinations. The output path is reserved exclusively before launch;
write, sync or close failures fail the launch. Failed or interrupted workloads do
not produce a valid successful export. Consumers must require both a successful
completion result and a validated archive before publishing selected files.
Final export does not capture live process state; coordinated filesystem snapshots
and startup restore are described below.

A coordinator can additionally pass `--control-fd <inherited Unix stream socket>`
for mid-run filesystem snapshots. The socket stays private to the supervisor.
A bounded request is `GXS1`, a little-endian u64 sequence (strictly increasing),
a little-endian u16 pathname length (1–512), and the non-NUL pathname bytes.
The destination must be fresh. After writing, syncing and closing its archive,
the supervisor replies `GXA1`, the matching little-endian u64 sequence, and a
little-endian u64 zero status. Malformed requests, peer loss, and capture failure
stop the domain. Partial requests are buffered within the fixed frame bound.
The coordinator owns request deadlines, directory durability, matching runtime
state, and workload acknowledgement. Snapshot capture serializes with all owned
filesystem mutations. Regular hardlinks are encoded once as payload and then
as zero-size tar hardlink entries referring to an earlier name; inode identity
survives restore. Writable shared mappings/native backing descriptors are
not exposed. This captures filesystem contents, not process memory or live
handles. Complete coordinator state pairing and recovery are separate capabilities.

`--restore-file <snapshot tar>` imports a snapshot into the newly prepared owned
filesystem before starting the workload. Import is bounded by the configured namespace capacity
and the configured file-data budget. Archive bytes are bounded by that budget
plus 3072 bytes per namespace slot and a 1024-byte terminator; at most three
headers per slot cover GNU long names and link targets. There is no fixed 2 GiB
ceiling. File payloads use ustar octal size fields (below 8 GiB per file).
It restores regular files, directories, symlinks and permission bits, including
long names and link targets emitted by Ginux. Absolute link targets are retained
as data, never followed during import. Hardlinks require a previously imported
regular-file name with matching mode; aliases share its storage. Import rejects
forward, absolute or traversing hardlink targets, directory/symlink hardlink
targets, symlink parents, traversal, duplicate entries,
invalid metadata/checksums/terminators, truncated archives, and names outside the
configured storage assignments. The source must be a regular file opened without
following a symlink; import never changes it. Failure discards the new memory
view and starts no workload. The coordinator remains responsible for verifying
the selected snapshot's identity/content and matching runtime state; a supplied
archive alone is not evidence of a recoverable checkpoint.
