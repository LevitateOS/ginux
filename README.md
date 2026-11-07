# Ginux

**Ginux is a configurable userspace kernel for isolated Linux compatibility
instances.** It runs as an ordinary Linux process and places an explicit,
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
contract to each managed instance. Before a managed syscall has a host effect,
Ginux decides whether to emulate it, perform a validated mediated operation,
or deny it.

Put bluntly: **Linux must not break userspace; Ginux is designed to break the
full Linux ABI guarantee deliberately and selectively.** A instance receives
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
            `- instance contract
                 |- virtual processes and identities
                 |- virtual descriptors and kernel views
                 |- assigned devices and resources
                 `- managed Rocky Linux userspace
                      `- instance systemd (virtual PID 1)
```

Ginux supervises native x86-64 programs and intercepts managed syscalls before
their host effect. Its central dispatcher resolves the instance contract and
chooses one of three outcomes:

- **Emulate:** answer entirely from Ginux-owned state.
- **Mediate:** validate and translate the request, then perform a narrow
  Ginux-owned host operation.
- **Deny:** return a configured Linux-compatible error or terminate the task.

The current implementation includes:

- a security-focused x86-64 interpreter and a balanced native ptrace backend;
- strict, versioned instance configuration and lifecycle;
- a digest-pinned OCI root, immutable filesystem index, and bounded overlay;
- Ginux-owned process, credential, signal, synchronization, timer, and event
  models;
- virtual devices with explicit assignment, ownership, and revocation; and
- bounded virtual `/proc`, `/sys`, cgroup v2, mount, namespace, machine, and
  boot-identity views;
- a host-shared network backend that remains syscall-mediated; and
- a pinned Rocky Linux 10 systemd baseline that reaches `multi-user.target`,
  authenticates a managed console login, updates through Rocky's enabled
  repositories, and shuts the instance down cleanly.

This is a named compatibility baseline, not a claim of complete Linux or
systemd compatibility. Its exact image, readiness marker, tests, evidence, and
limitations are recorded in
[`hdae/gates-todo/9-systemd-baseline.md`](hdae/gates-todo/9-systemd-baseline.md).

### Agent containment research

Ginux is also being tested as a containment boundary for AI agents and other
automated software that can execute commands, modify files, open network
connections, and start additional processes. Instead of giving an agent the
host's complete Linux ABI, an operator can place its process tree inside a
instance whose kernel contract exposes only the operations and virtual resources
required for the task.

The research goal is a reviewable boundary spanning syscalls, ioctls,
filesystems, devices, networking, process authority, and virtual `/proc` and
`/sys` state. For example, a contract may allow an agent to read time, inspect
its own processes, and modify one assigned workspace while denying clock
changes, host filesystem access, unapproved network listeners, and unrelated
devices. Ginux can then audit the contract decisions made while the agent and
its child processes run.

This is an active verification target, not a claim that Ginux is currently a
production-grade agent sandbox. The contract inventory, configurable policy,
adversarial tests, performance costs, and escape boundaries are tracked through
the HDAE gates and must be demonstrated before stronger containment claims are
made.

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
| **Ginux** | Gives each instance a versioned kernel contract | Treats the declared contract, virtual state, devices, resources, and lifecycle as one reviewable boundary |

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
make instance-image-fetch
make systemd-image-fetch
```

Build and run the deterministic suite offline after the caches are populated:

```sh
make build
make check
make test
```

Inspect the latest completed capability directly:

```sh
make test-systemd       # cached image, external networking disabled
make bench              # systemd timing and resource observations
make test-systemd-live  # shared network plus real upstream dnf -y update
make run-host           # general interactive Rocky host with Ginux installed
make demo-gate-9        # Gate 9 checkpoint through the same host workflow
```

`make run-host` boots the QEMU Rocky host and logs you into its ordinary shell.
Ginux is installed in `PATH`. The first `instance create` downloads and verifies
the pinned Rocky OCI image with live per-layer progress; later creates reuse the
cache. The writable Rocky host overlay persists across `make run-host` sessions,
so cached images, instance definitions, roots, and stopped status remain available.
A complete first session is:

```sh
ginux instance create rocky --config /etc/ginux/examples/rocky-systemd.toml
ginux instance list
ginux instance status rocky
ginux instance start rocky --attach
```

The instance specification also supports typed CLI overrides, network
interface/source selection, ingress and egress port policy, translated ports,
volumes, virtual identity, and ordered pre-boot hooks. Hooks run only as
mediated instance processes; Ginux does not support arbitrary host-context hooks.
See [Gate 9.75 instance specification](docs/gate-9.75-instance-specification.md)
for the schema, precedence rules, examples, and verification targets.

The attached terminal becomes the Ginux instance console. Log in as `root` with
password `ginux`, explore normally, press `Ctrl-]` to detach while leaving the
instance running, and run `kill -RTMIN+4 1` as instance root to
shut down systemd and return to the host. Detached operation uses
`ginux instance start rocky`, `ginux instance status rocky`, and
`ginux instance stop rocky`. Exit the Rocky host shell to stop QEMU cleanly.
This stops the VM without deleting its persistent overlay; `make clean` resets
that host state. `make demo-gate-9` uses the same operator workflow;
`make run-systemd` remains as a compatibility alias, and
`make test-systemd-interactive` is the automated regression.

The live test and interactive demonstration enable shared external networking.
An upstream DNF update can take many minutes under QEMU TCG because every
managed syscall is intercepted and audited. The offline systemd test uses only
the prepared, digest-pinned cache.

Individual component and gate targets are documented in the `Makefile` and the
corresponding files under [`docs/`](docs/) and [`hdae/`](hdae/).

## Security model and limitations

The primary adversary controls a process inside an instance. The host kernel,
hardware, Ginux executable and approved configuration, boot chain, and
operator are currently trusted. The balanced native backend still relies on
the host for ELF loading, address spaces, page faults, signals, scheduling,
and ptrace; those remain host-kernel attack surface.

Ginux is research software. It has not received independent security
certification, does not provide complete Linux compatibility, and is not ready
for production workloads. Unknown contract operations fail closed, but current
coverage and guarantees are limited to the tested gates.

For agent containment, the protected object is the host and any authority not
explicitly assigned to the instance. Ginux constrains the Linux processes in
which an agent and its tools execute; it does not inspect model reasoning,
secure an external model provider, or make untrusted code safe outside the
enforced instance boundary.

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

On x86-64 Linux, `ginux launch <config> <root> [--result-file <fresh host path>]`
executes `[instance].init` with the configured arguments and environment inside
the supplied host root directory. The bootstrap requires chroot and credential
change privileges, and a kernel with `close_range` (Linux 5.9 or later).
It drops to UID/GID 1000 before executing the workload. The configuration must
select `profile = "balanced"` and `backend = "ptrace-native"`. Only the `null`
device assignment and memory-storage backend described below are supported.

`[instance].workdir` is optional and defaults to `/work`; `/` is also supported.
The bootstrap creates the working directory if its parent exists, then enters
it after dropping privileges. Init and working-directory paths are limited to
128 bytes and must be absolute without `..` path components. Up to seven
arguments of 128 bytes each and eight `NAME=value` environment entries of
256 bytes each are accepted. Invalid or oversized input fails before launch.

Workload stdout stays separate from supervisor diagnostics on stderr. Only
stdin, stdout, and stderr are inherited by the workload. The launcher returns
the workload exit code, or `128 + signal` for signal termination. Startup
failure returns 2; supervision or result-writing failure returns 1. Native
fork/vfork, bounded process-only clone, image exec and child wait are supervised
by a configured-launch task loop. Non-x86-64 syscall ABIs and job-control
group stops fail explicitly. Audit output is capped at 64 KiB plus a truncation
notice. `[resources].memory_mib` caps each tracee process's virtual address space
with hard/soft `RLIMIT_AS`, preserving lower operator limits. This includes
anonymous and image mappings; it is not an aggregate domain RSS limit.
`[resources].vcpus` restricts the child to at most that many logical CPUs selected
from the launcher's allowed affinity mask. This bounds eligible CPUs, not CPU
time. Limits are installed only in the child before exec; no host-global cgroup
policy is changed. Kernel inheritance preserves them for supported descendants.
Self affinity queries (zero, current virtual PID or thread-group ID) report the
actual eligible CPU subset through a buffer of at most 1024 bytes. Affinity mutation and address-space limit mutation
are denied; unrelated virtual PIDs are not native scheduler targets.

Configured `uname` returns `Linux`, the domain id as nodename, the kernel-views
package version with `-ginux` as its virtual release, version `ginux`, machine
`x86_64`, and an empty domainname. This identifies the virtual implementation;
it does not report host kernel/hostname data or promise the host kernel's ABI.
The shared native syscall contract and `sysinfo` behavior are unchanged.

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
read/write/pread/pwrite, ftruncate, seek, close, descriptor flags, mkdir/unlink/rmdir,
owned directory descriptions/getdents64, rename/renameat/renameat2 with NOREPLACE,
chmod and stat/fstat/fstatat/statx metadata. Positioned writes preserve the
shared open-description offset; append descriptions retain Linux append semantics. Access and readlink probes stay in
the owned namespace; regular files accept O_NOCTTY. Directory cookies and inode
identity follow open descriptions across aliases, fork, rename and removal.
Namespace changes validate types, capacity and replacement before mutation.
Relative AT_FDCWD paths follow the calling process's cwd; owned directory
FDs resolve relative operations through their current VFS identity. Image chdir,
getcwd and relative image exec retain native per-process cwd semantics.
Relative image-directory FD paths join the same namespace. Owned chdir/fchdir/
getcwd keep a private VFS directory reference per process. Fork copies that
reference; exec keeps it; successful image chdir/fchdir
releases it. Rename updates the reported path, and a removed cwd reports ENOENT
for getcwd and relative operations until an absolute directory change. Private
cwd references consume the existing 64-entry VFS open-description capacity.
Relative owned scripts/interpreters and explicit image paths use that cwd.
Native kernel-selected relative interpreters from owned cwd remain unsupported.
Supported configured-launch threads share the process cwd reference.
Owned regular-file link/linkat names share inode, bytes, permissions and link
counts. Removing one name preserves data through other names, file descriptions
and executable references. Descriptions and executable pins retain the name
through which they were obtained, including rename and deletion state. Hardlinks
consume namespace entries without duplicating file capacity. Only owned regular
files are linkable; linkat supports flags zero or AT_SYMLINK_FOLLOW. Symlink inode
links, image-file imports, descriptor-only AT_EMPTY_PATH linking and directory
hardlinks remain unsupported. Failed creation preserves names and link counts.
Owned symlink/symlinkat and readlink/readlinkat support bounded targets and
nofollow metadata. Link expansion precedes later parent components; mutations
name the final link itself, including directory requirements on trailing slashes.
Exclusive create and O_NOFOLLOW keep their separate failure behavior. Owned links
may lead to readonly image paths or assigned virtual devices; image links may lead
into owned storage. Directory descriptors and cwd use the same assignment
precedence. Image mutations remain unsupported; hidden device paths retain absent
semantics. Owned script
interpreter aliases are canonicalized only in the sealed execution copy; original
script bytes and interpreter names in argv remain unchanged. Kernel-selected
nested native interpreters must still match the image namespace. Canonical script
interpreter targets containing shebang separators are unsupported.
Link target bytes consume the same owned storage capacity as regular data.
Component-wise image-link traversal preserves assignment
precedence, missing components and non-directory errors. Native image operations
use a temporary canonical path below the stopped workload's stack; an unavailable
scratch area or overlapping output buffer returns EFAULT. This is a bounded
storage adapter, not a complete unified image/overlay filesystem. Regular writes
and pwrites process at most 1 MiB per call in 4 KiB scratch chunks, returning
only committed bytes after a short transfer or error. Reads and readv/writev
remain bounded to 4096 bytes per call; callers must handle short transfers.
Owned files and pipes accept at most 16 iovecs, including empty entries, with a
combined length no greater than the signed transfer-result range. Pipe writes
use the combined vector length for atomicity and retain their existing bounds.
Native image/console transfer policy is unchanged. Metadata defaults to 32 objects (including seeded directories) and 64 independently
opened files. `[storage].max_objects` permits 1–1000000 namespace slots. Bounded
supervisor allocations hold namespace and backing metadata. Before workload
startup, assigned storage reserves `max_objects + 128` private descriptors by raising
only the supervisor soft limit within its existing hard limit; insufficient hard
capacity rejects launch. The public descriptor capacity is captured beforehand
and applied to the tracee. Page-rounded metadata bytes are charged before file data. Optional positive `[storage].max_bytes` caps
file-data capacity. Data plus metadata must fit `[resources].memory_mib`; without
max_bytes, data uses the remainder. Removed names with live descriptions retain
their slots until final close. Bytes grow on demand in supervisor-owned memfd mappings. Total mapped capacity, including page rounding and growth
reserve, is bounded by `[resources].memory_mib`, shared across files instead of
a 64 KiB per-file ceiling. This accounts for writable backing, not total process
RAM. Exhaustion returns `ENOSPC` without changing file bytes, size or offset.
Truncation returns unused pages; sparse gaps and regrowth read as zero. Unlinked
bytes survive until the last open reference closes; teardown releases mappings.
Aliases use the common public descriptor table. Handle exhaustion returns `EMFILE`.

Configured launch uses one table of up to 256 public descriptors for bootstrap
stdio, immutable-image files, writable files, devices and pipes. Allocation uses
the lowest free number; native opens reserve a slot before running. Backend
handles stay private, including when the kernel reuses an underlying fd number.
Dup/dup2/dup3 and fcntl duplication share an open description across owners;
close-on-exec flags belong to each public descriptor. The backend closes only
after its last alias. Syscall arguments are translated for native IO/metadata/
mmap and restored at exit. Owned regular files support POSIX byte-range locks
(`F_GETLK`, `F_SETLK`, `F_SETLKW`) with virtual process ownership. Fork does not
inherit record locks; closing any descriptor for the inode releases that
process's record locks. Owned file/directory `flock` locks follow the open
description across dup/fork and release on its final close. Each table holds at
most 64 ranges; exhaustion returns `ENOLCK` without a partial update. Conflicting
blocking calls wait in the supervisor; threads share their process lock owner.
Deadlock detection, native image locks, leases and signal ownership stay denied.

Bootstrap constrains the real descriptor soft/hard limits to 256 while keeping
lower operator limits. Allocation respects that lower soft limit; runtime
NOFILE-limit changes are currently denied. Reported limits are not inflated to
accommodate backend handle ranges. Fork copies public descriptor tables while
sharing open descriptions and owned-object lifetimes. Successful exec closes
CLOEXEC entries; failed exec preserves the table. Owned directory-fd operations
are supported; configured readiness is described below.
Guest-memory copies respect page protections, including partial read copyout.
No writable host descriptor is exposed. Data disappears at domain teardown;
explicit export and restore are described below. There is no retained storage generation.

Owned executable files with an execute bit and no open writers may be replaced
through execve or execveat, including an owned directory FD or an unlinked read
FD with AT_EMPTY_PATH. The VFS pins the bytes; a private sealed memfd supplies
them to the native kernel ELF loader. Paths and ELF interpreter metadata use the
same assignment checks as image execution.
No writable host pathname is used for generated program bytes. Writable opens
and truncation report ETXTBSY while the program is pinned; unlink/rename retain
identity until the last process releases it. Fork retains the executable pin;
exit or successful replacement releases it. Failed exec closes its temporary
backing, releases its proposed pin and preserves public descriptors. CLOEXEC
retirement still commits only after successful exec. Threads retain their
process executable pin until the last thread exits.
Readlink of /proc/self/exe and /proc/thread-self/exe returns the current domain
executable name, with a deleted suffix for an unlinked owned executable; native
memfd names and supervisor prefixes are not part of that interface.

Owned shebang programs support up to four consecutive owned scripts followed
by an owned ELF or an image interpreter chain. Each shebang has one optional
argument, including spaces. Owned script bytes stay pinned until exec commits;
the final owned ELF retains the running executable pin. The new exec stack
restores the virtual script name in argv and AT_EXECFN; existing arguments and
environment are preserved, with argv[0] replaced as for kernel shebang execution.
Image interpreters use a transient non-CLOEXEC script backing, retired before
the interpreter's first syscall. Stack reconstruction is bounded to 4096 caller
arguments, 4096 environment entries and 64 auxiliary pairs. Unsupported stack
layouts fail the domain after exec rather than resuming a replaced address space.
Descriptor-based scripts require a non-CLOEXEC public file or directory descriptor;
otherwise execveat fails with ENOENT. The interpreter can reopen /dev/fd/<public>
(or an owned directory suffix) read-only through the virtual descriptor owner,
with a fresh offset, including after unlink/rename. This never imports native
or private descriptors. Other /dev/fd operations remain unsupported. Threads,
owned ELF dynamic loaders remain unsupported.

Owned regular files support private mappings and read-only shared mappings.
Mediated writes/truncation use the same anonymous file backing; private writes
remain copy-on-write, and unlink/recreation preserves existing mapping identity.
Writable shared mappings are unsupported. A temporary read-only descriptor
transfer requires host pidfd_open/pidfd_getfd and ptrace access. Temporary native
descriptors and stack scratch retire before the original mmap returns. Fixed
maps cannot replace the replay instruction or scratch region. Transfer failure,
signal interruption or death stops the domain if cleanup cannot complete safely.
Threads remain unsupported in configured launch; nonleader mapping integration
is not provided here. File capacity charging remains unchanged, but guest mappings,
private COW pages and mappings retained after unlink are not aggregate RAM-accounted.
No retention, mapping budget or wider Linux compatibility is promised.

The configured `/dev` view is an immutable virtual directory, empty by default;
image entries beneath it are hidden. The script descriptor reopen operation
described above is separate from directory enumeration. `[devices].assignments = ["null"]` exposes
`/dev/null` through the existing device registry: reads return EOF and writes
discard up to 4096 bytes per call. Stat/fstat/fstatat/statx report a character
device with domain-owned identity and major/minor 1:3. Open access modes,
close-on-exec descriptor flags, seek, close and basic access queries are
supported; device metadata cannot be changed. There are 64 open-device slots.
Unknown and duplicate assignments fail before launch. Device aliases share the
common descriptor table and handle lifetime. No host device node or descriptor
is used. Assigned null descriptors are always ready for configured polling. Additional
device types are not implemented by configured launch yet.

Anonymous `pipe`/`pipe2` are emulated with supervisor-owned memory and virtual
handles. Up to sixteen channel buffers hold 65536 bytes each; aliases use the common table.
`pipe2` accepts only `O_CLOEXEC|O_NONBLOCK`. IO is bounded to 4096 bytes per call;
writes of up to 4096 bytes are atomic. Reads consume only bytes successfully
copied out, so invalid/partially inaccessible destinations do not lose data.
Read/write direction, EOF, SIGPIPE, metadata, seek rejection, descriptor/status
flags, pipe-size queries and aliases across owners are supported.
Alias status flags and endpoint lifetimes are shared; close-on-exec flags are
per descriptor. No native pipe or host descriptor is given to the workload.

Nonblocking empty/full operations return `EAGAIN`. Blocking operations stay
stopped at entry until another task changes pipe state. Forked peers can exchange
data and wake blocked reads/writes; a self-pipe without a runnable peer still
waits indefinitely. SIGKILL termination and reaping are supported. Signal-driven restart of emulated blocking operations remains unsupported;
configured descriptor readiness is described below.

Configured launch owns at most 16 task slots, including unreaped children.
Process creation accepts fork, vfork, and clone with `SIGCHLD`,
`CLONE_VM|CLONE_VFORK|SIGCHLD`, or the libc-fork
`CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|SIGCHLD` flags. Native threads accept
the libc `0x3d0f00` flag set (VM, FS, FILES, SIGHAND, THREAD, SYSVSEM, SETTLS,
PARENT_SETTID and CHILD_CLEARTID); other clone forms remain unsupported. Threads
share the process descriptor table, cwd and executable pin. Pending syscall
results and readiness snapshots remain per task. A blocked owned IO call keeps
its original handle until completion, even if another thread replaces its fd. New children remain stopped until their virtual identity
and descriptor snapshot are installed. Init is PID 1; PID/TID/parent queries,
child-TID writes and forwarded signal senders use virtual identities. Actual
credentials remain UID/GID 1000. `wait4` supports a positive child PID or -1,
optional `WNOHANG`, and a null rusage pointer. A faulty status destination still
reaps the child and leaves the status word unchanged. Kill supports only signal
0 and SIGKILL directed at a positive virtual PID. Ignoring SIGCHLD and
`SA_NOCLDWAIT` are unsupported. A leader exiting alone keeps its remaining threads and resources alive. The
last thread publishes the leader's status. Process completion kills and reaps all
remaining descendants before the launcher reports completion. Exec requires the
single remaining task to be the process leader; other thread exec returns
EOPNOTSUPP.

Subsequent exec supports image paths and native image descriptors with
`execveat(AT_EMPTY_PATH)`. Descriptor synchronization precedes native exec;
CLOEXEC retirement commits at the observed successful exec event. Failed exec
restores public arguments and descriptor state. Owned ELF/script execution uses
the separate pinned-byte transaction described above. Native script and ELF
interpreter paths must resolve to the same permitted image object in both the
configured and native namespaces; hidden assignments
cannot be bypassed through a kernel-selected interpreter. Interpreter metadata
is bounded to x86-64 ELF headers, 256-byte paths and 16 script-chain inspections;
unsupported or ambiguous chains fail explicitly. The initial executable has the
same interpreter ownership check before its first instruction runs.

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
sudo make test-native-supervision
make build-launch-storage-fixture
sudo make test-launch-storage
make build-launch-device-fixture
sudo make test-launch-devices
make build-launch-pipe-fixture build-launch-fd-fixture
sudo make test-launch-pipes test-launch-fds
make build-launch-task-fixture build-launch-exec-fixture
sudo make test-launch-tasks test-launch-exec
make build-launch-thread-fixture
sudo make test-launch-threads
```

## Native process scenarios

The separate `process-native <config> <executable>` command exercises native
fork, clone, vfork, exec, threads, waits, termination signals, and pipes. It
executes a trusted host fixture as the caller, without chroot; it does not
require root on a host that permits tracing child processes. Configured
`launch` uses its own bounded task loop that joins configured storage, device
and descriptor ownership; it does not use this native-only fixture loop.

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

Configured `poll` resolves at most 16 public descriptors through their existing
owners: pipes, local packets, TCP, assigned memory files/null and inherited console aliases. Negative
descriptors are ignored; closed descriptors report POLLNVAL. Image files remain
unsupported for this operation. Error/hangup bits are reported independently of
the requested mask. Zero through 300000 ms and negative infinite waits are
supported. Queries park and wake on object progress; finite/console waits also
use a 1 ms supervisor tick. Internal monotonic time does not enable guest clocks.
General nonfatal signal interruption/restart remains unfinished. The shared
native syscall contract is unchanged; this is configured-launch readiness.

Configured local `AF_UNIX` / `SOCK_SEQPACKET` pairs consume two channel buffers
and support duplex messages up to4096 bytes, aliases, nonblocking IO and poll.
Messages preserve boundaries; a short receive discards the remaining message.
Local socket names, descriptor transfer and socket shutdown are unsupported.
FIONBIO changes the shared open status of owned pipe and packet endpoints,
preserving other status flags and each public descriptor's CLOEXEC flag.

Configured launch accepts `--export-file <fresh tar path>` to retrieve owned
regular files and directories after a successful workload exit. Remaining tasks
are terminated and reaped before capture. Deleted names and immutable image files
are excluded; file modes and long paths are preserved. Guest names are archive
data and never select host destinations. The supervisor stages mode0600 output
beside the destination, then publishes without overwrite only after complete
write, sync and close. Failed workloads cancel staging. Export failures fail the
launch; an existing destination is preserved. Abrupt supervisor death can leave a
private staging file, which is never a published archive. Consumers must require
both successful completion and a valid archive. This is final export, without
retained storage.
Owned regular files support fsync/fdatasync against their supervisor backing;
these calls do not imply persistence after the in-memory domain ends.

A host coordinator may pass `--control-fd <inherited Unix stream socket>` for
mid-run filesystem snapshots. The supervisor keeps the socket private. Requests
are GXS1, a little-endian u64 strictly increasing sequence, a little-endian u16
pathname length1–512, and non-NUL pathname bytes. Destinations must be fresh.
Only after complete archive write/sync/close and no-overwrite publication does
it reply GXA1, the matching little-endian u64 sequence and u64 zero status.
Valid partial frames are buffered within the fixed bound. Invalid requests,
peer loss and capture failure stop the domain. The host owns request deadlines,
directory durability, paired state and workload acknowledgment. Capture serializes
with mediated owned filesystem mutation; it does not save process memory or live
handles. Private signal/control readiness wakes the supervisor without a periodic
control tick; wait4 remains the sole task-status owner. Finite guest readiness waits
also use a bounded timer tick; shared-thread capture remains a separate capability.

`--restore-file <snapshot tar>` reconstructs the owned filesystem before workload
startup. Regular files, directories, symlinks, modes and GNU long names/targets
are supported. Regular hardlinks export one payload followed by zero-size aliases
to an earlier name; restore preserves shared bytes and inode identity. Symbolic
link targets are stored as data and are never followed during import. Their
permission mode is fixed at 0777; imports with another symlink mode are rejected.

Import uses the configured namespace and data budgets, including prepared
assignment parents. Archive bytes are bounded by the data budget plus 3072 bytes
per namespace slot and a 1024-byte terminator. There is no fixed 2 GiB payload
ceiling; ustar octal size fields limit each file to below 8 GiB. Hardlink aliases
consume namespace capacity and share the original data charge. Invalid paths,
forward hardlinks, conflicting alias modes, symlink parents, duplicate entries,
metadata, checksums, truncation or trailing data fail launch. The source must be
a bounded regular file opened without following a symlink; it remains unchanged.
Failure discards the new memory view. The host must verify the chosen snapshot
and matching runtime state: process memory and live handles are not restored,
and no checkpoint control socket is required.

Owned inode access and modification timestamps can be set explicitly through
`utimensat` and descriptor `futimens`, including no-follow, nanoseconds and
`UTIME_OMIT`/`UTIME_NOW`. Aliases share times; stat/statx return them. New owned objects
and VFS index metadata start at zero; reads/writes do not update times automatically.
`UTIME_NOW` uses the supervisor's native realtime clock, without allowing new
workload clock syscalls. These operations require existing owned objects.
Archives retain only whole-second nonnegative USTAR mtime. Access time and runtime
nanoseconds are not persisted; unrepresentable mtimes fail export explicitly.

### Supervisor-owned TCP backend

`ginux-devices` exposes `BoundedTcp` with a fixed numeric IPv4/IPv6 endpoint set,
a concurrent socket-slot limit and a cumulative sent-plus-received byte budget.
Connections use a supervisor-supplied `TcpBackend`; the Linux x86-64 adapter uses
private nonblocking, close-on-exec TCP sockets. Each transfer is at most 4096
bytes and only transferred bytes consume budget. Empty transfers consume none.
Endpoint metadata, TCP_NODELAY, readiness, connect error and half-close are
available through the same owner. Connect may remain in progress; callers check
readiness and socket error before treating it as complete. Readiness reports the
transport state; read/write also enforce the byte budget. Final close, drop and
revocation release private handles. Callers own public descriptor alias counts.

This library capability performs no DNS, accepts no connections and does not
change configured-launch networking or the default-denied guest socket contract.
Callers must grant endpoints explicitly before use. It is not a general network
namespace or firewall implementation. Linux device tests exercise real local
peers; the portable static/unit job remains unchanged.

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
connecting and connected sockets. Receive bytes that cannot be copied out remain
with the shared socket until delivered or closed. SO_ERROR consumption does not
turn a failed connection into a successful one. Socket names require a started
connection; ppoll accepts a null signal mask and rounds positive timeouts up to
milliseconds without modifying the supplied timespec. General signal interruption
and restart behavior is not implemented. Live sockets are never exported or restored.
The focused scenario is `make build-launch-network-fixture` followed by
`sudo make test-launch-network`.

Owned storage inode uid/gid are virtual root. `chown`, `fchown`, `lchown` and
`fchownat` can preserve 0 or unchanged (-1) on existing assigned storage objects,
including symlinks and empty-path descriptor operations. Other identities remain
unsupported; these operations never change host ownership.
