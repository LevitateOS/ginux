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
notice. This path does not implement resource quotas from the domain metadata.

Bootstrap-console readiness supports `poll` queries with at most 16
slots containing descriptors 0, 1, 2 or ignored negative descriptors. The native
supervisor validates the descriptor array before continuation. Timeouts from
0 through 300000 ms are supported; infinite or larger waits, other descriptors,
unreadable arrays, and oversized queries are denied. Closed
descriptors retain the kernel's `POLLNVAL` result.

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
read/write/pread, seek, close, basic descriptor flags, mkdir, file unlink, chmod,
and stat/fstat/fstatat/statx metadata. Relative paths use the configured workdir;
directory descriptors, directory enumeration/removal, symlinks, hardlinks,
rename, file mappings and execution of generated files
are unsupported. Path normalization is lexical; this is not a complete unified
image/overlay filesystem. IO is bounded to 4096 bytes per call. Capacity is
32 objects (including seeded directories), 65536 bytes per file and 64
independently opened file handles. Aliases use the common descriptor table. Exhaustion returns `ENOSPC`, `EFBIG`, or `EMFILE` as appropriate.

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
numbers. Relative directory-fd access, poll on remapped stdio or non-bootstrap
descriptors remain unfinished.
Guest-memory copies respect page protections, including partial read copyout.
No writable host descriptor is exposed. Data disappears at domain teardown;
there is no retention, export, storage generation or configured storage quota.

The configured `/dev` view is an immutable virtual directory, empty by default;
image entries beneath it are hidden. `[devices].assignments = ["null"]` exposes
`/dev/null` through the existing device registry: reads return EOF and writes
discard up to 4096 bytes per call. Stat/fstat/fstatat/statx report a character
device with domain-owned identity and major/minor 1:3. Open access modes,
close-on-exec descriptor flags, seek, close and basic access queries are
supported; device metadata cannot be changed. There are 64 open-device slots.
Unknown and duplicate assignments fail before launch. Device aliases share the
common descriptor table and handle lifetime. No host device node or descriptor
is used. Device polling and additional device types are not implemented by
configured launch yet.

Anonymous `pipe`/`pipe2` are emulated with supervisor-owned memory and virtual
handles. Up to eight pipes hold 65536 bytes each; aliases use the common table.
`pipe2` accepts only `O_CLOEXEC|O_NONBLOCK`. IO is bounded to 4096 bytes per call;
writes of up to 4096 bytes are atomic. Reads consume only bytes successfully
copied out, so invalid/partially inaccessible destinations do not lose data.
Read/write direction, EOF, SIGPIPE, metadata, seek rejection, descriptor/status
flags, pipe-size queries and aliases across owners are supported.
Alias status flags and endpoint lifetimes are shared; close-on-exec flags are
per descriptor. No native pipe or host descriptor is given to the workload.

Nonblocking empty/full operations return `EAGAIN`. Blocking operations stay
stopped at entry until a peer changes readiness or exits. No native pipe fd is
passed through. Byte-flow checks alone do not prove ordinary child commands work.

Configured launch supervises up to 16 native tasks through the existing process
owner. Fork and vfork are supported, as are clone flags `SIGCHLD`,
`CLONE_VM | CLONE_VFORK | SIGCHLD`, and the x86-64 pthread shape `0x3d0f00`.
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
leaves peer handles intact, including after the process leader exits. Getcwd is
mediated against the bootstrapped chroot workdir; runtime chdir is unsupported.

Wait4 supports a positive virtual child ID or -1, with options 0 or WNOHANG and
no rusage buffer. An invalid status pointer does not consume the child. Orphans
are adopted by the virtual init, while the supervisor acts as the native
subreaper. Kill supports positive domain IDs with signals 0 or SIGKILL; other
signal forms are rejected. SIGCHLD auto-reap dispositions are rejected; bootstrap
resets an inherited ignored SIGCHLD to its default disposition. Job control,
interruption/restart of parked calls and SIGCHLD notification for adopted
children and robust-futex owner-death behavior remain incomplete. Supported
futex operations are wait/wake/requeue and their ordinary variants; PI futexes
are denied before the kernel can publish native owner TIDs. Final root-process
exit or supervision failure kills and reaps all remaining
descendants and releases owned descriptors before reporting completion.
Image execve and execveat are supervised, including relative paths from the
configured workdir, absolute execveat paths, and AT_EMPTY_PATH on image
file descriptors. Relative directory-fd execution remains unsupported. Generated
files and virtual devices cannot execute through the native image path.
Before exec, controlled fcntl syscalls synchronize each native handle's CLOEXEC
bit: any surviving public alias keeps its native handle. The supervisor replays
the original verified x86-64 syscall instruction; no executable bytes change.
Only PTRACE_EVENT_EXEC retires public CLOEXEC descriptors and owned references.
Failed exec preserves every public descriptor and its flags. Successful exec
keeps task identity and advances the existing process owner's exec state. Exec
currently requires the sole remaining task to be its process leader; other
threaded exec transitions return EOPNOTSUPP.
Signals interrupting descriptor synchronization fail the domain explicitly;
restart/deferred delivery for that preparation remains incomplete. Path checking
uses the current lexical view rather than a unified image/overlay resolver.
Readiness beyond bootstrap consoles, compiler-sized writable storage and
execution of generated files remain incomplete. This is not compiler support.

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
```
