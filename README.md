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
full Linux ABI guarantee deliberately and selectively.** An instance receives
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

### How execution works today

Ginux is not running another Linux kernel. In the balanced backend, host Linux
loads each x86-64 ELF, creates its address space and tasks, and schedules its
instructions on the host CPU. Ginux remains attached as the trusted supervisor.
A mandatory seccomp filter sends managed syscalls to ptrace stops before their
host implementation, where Ginux can inspect registers and memory and then
emulate, mediate, or deny the operation.

The current selective optimization has one deliberately narrow exception:
contract-approved `sched_yield` may execute directly in host Linux. Paranoid
mode sends that operation through a seccomp user-notification broker as well,
so every managed syscall receives a Ginux userspace decision. The host kernel,
ptrace, seccomp, ELF loader, memory manager, scheduler, and CPU execution remain
trusted in both modes. This is therefore not a VM or microVM security boundary.

### What Ginux is not

- It is **not User-Mode Linux**: UML runs a complete Linux kernel as a host
  process over paravirtual hardware; Ginux implements a deliberately incomplete
  contract and uses host Linux for native execution services.
- It is **not a mature gVisor alternative**: gVisor is the closest established
  architectural relative, but it has a broad Linux System API and years of
  production engineering. Ginux is a much narrower research prototype.
- It is **not just namespaces or seccomp policy**: those mechanisms partition
  or filter host-kernel behavior. Ginux additionally supplies contract-specific
  results and virtual kernel objects such as process identities, `/proc`,
  `/sys`, devices, and lifecycle state.
- It is **not VM-equivalent isolation**: there is no guest kernel or
  hardware-enforced guest boundary, and current trusted host surface is
  substantial.

See [How Ginux differs from UML, gVisor, namespaces, and
VMs](docs/how-ginux-differs.md) for the complete comparison.

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
[`hdae/gates-done/9-systemd-baseline.md`](hdae/gates-done/9-systemd-baseline.md).

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

The userspace-kernel idea is established research and engineering territory;
Ginux does not claim to have invented it. Its closest established comparison is
gVisor, not UML. The specific experiment is whether one self-contained,
versioned instance contract can define a deliberately reduced ABI together
with virtual kernel state, filesystems, devices, networking, resources,
lifecycle, and audit evidence.

| System | What runs for the workload | Compatibility goal | Main distinction from Ginux |
|---|---|---|---|
| Linux namespaces and seccomp | The workload talks to host Linux through partitioned objects and filtered syscalls | Host Linux ABI | They constrain the existing host API; Ginux also implements contract-specific virtual results and objects |
| [User-Mode Linux](https://docs.kernel.org/virt/uml/user_mode_linux_howto_v2.html) | A complete Linux kernel runs as a host process over paravirtual devices | Linux kernel behavior | Ginux does not boot or reuse a guest Linux kernel and intentionally exposes less than Linux |
| [gVisor](https://gvisor.dev/docs/architecture_guide/intro/) | A mature application kernel implements a broad Linux System API | Broad application/container compatibility | It is the closest relative; Ginux is narrower, contract-first, and currently a research prototype |
| VM or microVM | A guest kernel runs behind a hardware virtualization boundary | Guest-kernel compatibility | Ginux has no guest kernel or hardware-enforced guest boundary and trusts more host Linux surface |
| **Ginux** | Native tasks run under a userspace contract supervisor | Named workloads and contracts only | The portable recipe intentionally grants only the ABI and virtual resources that a workload is meant to receive |

Ginux does **not** promise the complete Linux ABI, VM-grade isolation, or
production readiness. Compatibility claims apply only to named contracts,
workloads, and executable evidence.

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
make test-multi-instance # two concurrent Rocky systemd instances and isolation
make bench-prepare      # one-time networked setup for the pinned benchmark image
make bench              # matched native/Ginux matrix plus mandatory budget checks
make bench-modes-prepare # one-time setup for the three-way dispatch comparison
make bench-modes        # native/selective/paranoid tables and graphs
make demo-gate-15       # bounded reproducible three-way comparison
make bench-launch       # launch-mode per-syscall and workload overhead against native
make bench-launch-compare # launch-mode run against its baseline, or two binaries (A/B)
make demo-gate-17       # operator-readable concurrent-instance isolation check
make test-systemd-live  # shared network plus real upstream dnf -y update
make host-run           # general interactive Rocky host with Ginux installed
make host-reset         # discard that host's cache, instances, and writable state
make demo-gate-9        # Gate 9 checkpoint through the same host workflow
```

Instance recipes select syscall control under `[contract.syscalls]`:

```toml
[contract.syscalls]
control = "selective" # default; use "paranoid" for all-syscall mediation
default = "deny"
allow = ["*"]
deny = []
```

`selective` is the default and permits direct host execution only
when the instance contract allows the operation and Ginux's versioned catalog
independently classifies it as direct-safe. Denials, virtual state, inspection,
translation, emulation, pointer or descriptor validation, and modified results
remain Ginux-dispatched in both modes. `paranoid` is an explicit opt-in that
sends every syscall through the Ginux userspace dispatcher before completion.

`make bench-compare` checks every row against the 4% native budget and, after an
accepted baseline is published under `benchmarks/gate11/`, against that Ginux
baseline as well. Environment mismatches are reported separately from
performance regressions. `make demo-gate-11` runs a bounded human-inspectable
comparison and returns nonzero when a mandatory row misses its budget.

Those benchmarks are compute loops that barely make syscalls. For
`ginux launch` workloads, which are syscall-bound, `make bench-launch` measures
per-syscall-class and build-shaped rows against a native chroot of the same
root, with supervisor stop and ptrace counts, and `make bench-launch-compare`
checks a run against an accepted baseline or compares two binaries; see
[docs/launch-performance.md](docs/launch-performance.md).

Gate 15 provides a separate characterization workflow across native Rocky,
selective Ginux, and paranoid Ginux. Native is the no-mediation control, not a
Ginux instance mode. The checked-in templates under
[`benchmarks/gate15/`](benchmarks/gate15/) fix the complete test protocol and
may be copied without editing scripts. `make bench-modes` produces paired raw
samples, metadata, a Markdown table, and an SVG graph under `build/gate15/`.
See [Reproducible performance measurement](docs/performance.md) for the exact
protocol, customization workflow, output schema, and interpretation limits.

`make host-run` boots the QEMU Rocky host and logs you into its ordinary shell.
Ginux is installed in `PATH`. The first `create` or `import` downloads and verifies
the pinned Rocky OCI image with live per-layer progress; later operations reuse the
cache. The writable Rocky host overlay persists across `make host-run`, ordinary
cleanup, builds, and tests, so cached images, instance definitions, roots, and
stopped status remain available. `make host-reset` is the explicit destructive
operation that stops the host and removes that overlay; the next `make host-run`
starts from the pinned clean Rocky image.
A complete first session is:

```sh
ginux create rocky
ginux list
ginux status rocky
ginux start rocky --attach
```

`create` starts from the documented default recipe. Use
`ginux import NAME FILE` to create or atomically replace an instance from a
self-contained recipe, `ginux export NAME` to print that recipe, and
`ginux edit NAME` to validate and atomically apply an editor session.

Instances are contract-locked by default. For an explicit maintenance window,
stop the instance, run `ginux unlock NAME`, perform the required maintenance,
stop it again, and run `ginux lock NAME`. `ginux list` and `ginux status NAME`
show the current state, and starting an unlocked instance prints a warning.
Unlocking relaxes configurable recipe restrictions only; Ginux still owns the
virtual kernel boundary, rejects unsupported authority, reduces host identity,
and applies `NoNewPrivs`. Lock state is host deployment state and is never
written into an exported portable recipe.

Syscall auditing is disabled by default with `[audit] enabled = false`. Add
`--audit` to `ginux start` to enable it for that run, or set `enabled = true`
to enable it for every start. Enabled audit records always go to the instance's
`audit.log`; they are kept separate from the attached console.
Existing recipes using `mode = "stderr"` or `mode = "disabled"` remain
read-compatible and normalize to the new boolean form when rewritten.

The instance specification supports typed recipe overrides, ingress and egress
contract policy, volumes, virtual identity, and ordered pre-boot hooks. Host
network attachment and translated ports are deployment settings, supplied as
repeatable flags when the instance is created or changed:

```sh
ginux import web /etc/ginux/examples/rocky-systemd.toml \
    --network eth0:1 \
    --forward protocol=tcp,external_port=8080,instance_port=80 \
    --forward protocol=tcp,external_port=8443,instance_port=443
ginux set web \
    --network default \
    --forward none
```

Omitting `--network` uses the host's default network. Multiple flags are
validated and persisted atomically; an invalid combination changes nothing.
Hooks run only as
mediated instance processes; Ginux does not support arbitrary host-context hooks.
Longer hooks may use self-contained triple-quoted scripts, while short hooks
remain ordinary quoted array entries. The readable Rocky reference recipe and
minimal Rocky, constrained-agent, Ubuntu CMS, paranoid, and Alpine native-init
examples are indexed in [`config/examples/`](config/examples/README.md). Each
example uses the distribution's normal boot process; systemd is not a Ginux
requirement.
See [Gate 9.75 instance specification](docs/gate-9.75-instance-specification.md)
for the schema, precedence rules, examples, and verification targets.

The same instance file contains a self-contained hierarchical contract under
`[contract]` and its `syscalls`, `filesystem`, `network`, `devices`,
`privileges`, `process`, and `kernel` subsections. Syscall names accept bounded
globs compiled against the pinned catalog; explicit denies always win. The
contract is part of the instance rather than a separate operator object.
Validate and inspect the complete instance recipe before launch:

```sh
ginux validate /etc/ginux/examples/rocky-systemd.toml
ginux inspect /etc/ginux/examples/rocky-systemd.toml
ginux explain /etc/ginux/examples/rocky-systemd.toml filesystem.path.write
```

See [Self-contained userspace contract](docs/configurable-contract.md) for the
syntax, precedence, migration behavior, and complete CLI workflow.

The attached terminal becomes the Ginux instance console. Log in as `root` with
password `ginux`, explore normally, press `Ctrl-]` to detach while leaving the
instance running, and run `kill -RTMIN+4 1` as instance root to
shut down systemd and return to the host. Detached operation uses
`ginux start rocky`, `ginux status rocky`, and
`ginux stop rocky`. Exit the Rocky host shell to stop QEMU cleanly.
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

The precise supported claims, retained supervisor authority, trusted
components, exclusions, compatibility gaps, performance limitation, and
reproducible boundary tests are documented in
[Security boundary and limitations](docs/security-boundary.md).
The tested concurrent lifecycle, virtual-state, root, contract, audit, and
shared-network semantics are documented in
[Concurrent instances and isolation](docs/multi-instance-isolation.md).

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

AI assistance is the means used to build and revise the experiment, not a claim
that the output is correct, secure, maintainable, or novel. Human direction
sets the architecture and boundaries; executable gates supply the evidence;
review determines what can actually be claimed.

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

Configured Linux FD syscall arguments use the low 32 bits of the register.
Lookup and policy classification use that same public descriptor identity;
a high-bit alias has the same grant or denial as its low-bit value. Private
backend handles are not public descriptors, and no 64-bit canonical-FD rejection
is promised. Ordinary file read/readv operations require filesystem read authority,
while console and TCP aliases retain their respective semantic policy families.

Memory assignment prefixes are checked against the supplied image before restore
or workload execution. Every existing image component above the assigned name
must be a real directory: image symlink and file prefixes fail startup. Missing
parents may be synthesized; a link or file at the assigned name itself is hidden
by the empty memory directory. This matches the configured-storage foundation.

A private storage close error stops execution before the next guest resume.
Teardown attempts the remaining releases and reports a structured supervisor
failure; it never substitutes a successful workload result or retries a closed
numeric FD. Successful unlink/final-close and mapping references keep their
existing lifetime rules.

The configured supervisor retains only standard streams and an explicitly
supplied coordinator control socket from its caller. Other inherited FDs are
closed before private storage reservation. Its own result/export descriptors
remain private. The workload's public descriptor capacity is captured from the
original soft limit and is never enlarged by the supervisor's private reserve.


On x86-64 Linux, `ginux launch <config> <root> [--result-file <fresh host path>]`
executes `[instance].init` with the configured arguments and environment inside
the supplied host root directory. It needs a kernel with `close_range` (Linux
5.9 or later). A root caller chroots directly and drops to UID/GID 65534 before
executing the workload. Any other caller needs unprivileged user namespaces:
the workload enters a private one that maps only the caller's UID and GID, to
0, chroots there, and then gives up every capability (securebits locked, all
capability sets and the bounding set empty), so it runs with the caller's host
identity and no capabilities. A host that refuses the namespace fails the
launch with exit code 2 and a message naming the sysctl to change. The configuration must
select `profile = "balanced"` and `backend = "ptrace-native"`. Only the `null`
device assignment and memory-storage backend described below are supported.

Launch resolves the configured contract and checks it before every workload
syscall's clock, task, descriptor, storage or network handler. Explicit denials
return EPERM; absent grants return ENOSYS. A grant only permits the existing
implementation to handle the call; assignments, endpoint/byte limits and
argument checks still apply. Denials take precedence over grants. An explicit
syscall denial also wins over an ungranted semantic family.

`config/instance-configured.toml` selects `[contract] version = 1` and
`catalog = 1002`, using the upstream hierarchical format.
It adds `lstat`, `readv`, `pipe`, `nanosleep`, `link`, `sched_getaffinity`,
`clock_getres`, `faccessat`, `renameat2`, `execveat`, `tkill`, `tgkill`,
`preadv`, `preadv2`, `readahead`, `fadvise64`, `sendfile`, `copy_file_range`,
`getxattr`, `lgetxattr`, `listxattr`, `llistxattr`, `setxattr`, `lsetxattr`,
`removexattr` and `lremovexattr` to upstream catalog 2; `tkill` and `tgkill`
are also `signal.virtual.deliver`. `preadv`, `preadv2`, `readahead`,
`fadvise64` and the xattr reads and lists (with catalog 2's `fgetxattr` and
`flistxattr`) are also `filesystem.path.read`, and the xattr changes (with
`fsetxattr` and `fremovexattr`) `filesystem.path.write`, as their plain
counterparts are. `sendfile` and `copy_file_range` are decided by their output
as a `write` and by their input as a `read`; both must be granted.
Gate 11 advances the upstream catalog from 1 to 2 and adds direct-safe
`sched_yield`. Our former local catalog number 2 is retired to avoid assigning
upstream's number a different meaning. Self-contained configured contracts must
select `catalog = 1002`. Validation/inspection report the selected catalog and
digest; contract diffs include operations added or removed by a catalog change.
Gate 11 selective/paranoid dispatch applies to the native backend; configured
launch retains its existing mediated handlers and bounded audit contract.

Entry audit records name the deciding operation, policy source and rule index.
Console and TCP classification follows tracked descriptors through aliases,
fork and reuse. Self-contained contract rules carry their actual zero-based
index. Disabled audit suppresses decision records, while configuration, completion and failure
diagnostics remain available. Audit records remain bounded to 64 KiB.

The host vDSO can answer clock reads without a syscall. Launch therefore rejects
explicit clock/vDSO denials before starting a workload. It likewise rejects
explicit `/proc`, `/sys` and cgroup semantic denials, filesystem `write_deny`
rules and pre-boot hooks that this backend cannot enforce. Leaving those
semantic operations ungranted does not withhold their non-syscall effects.
This is not a claim of complete deny-by-default mediation of those surfaces.

`[instance].workdir` is optional and defaults to `/work`; `/` is also supported.
The bootstrap creates the working directory if its parent exists, then enters
it after dropping privileges. Init and working-directory paths are limited to
128 bytes and must be absolute without `..` path components. Up to seven
arguments of 128 bytes each and eight `NAME=value` environment entries of
256 bytes each are accepted. Invalid or oversized input fails before launch.

Workload stdout stays separate from supervisor diagnostics on stderr. Only
stdin, stdout, and stderr are inherited by the workload, and launch refuses to
start when any of them is a directory or cannot be checked: a directory there
would anchor `openat` and other `*at` calls outside the root. `ginux native`
applies the same check and closes every other inherited descriptor with
`close_range`, so it also needs Linux 5.9 or later. The launcher returns the
workload exit code, or `128 + signal` for signal termination. Startup
failure returns 2; supervision or result-writing failure returns 1. Native
fork/vfork, bounded process-only clone, image exec and child wait are supervised
by a configured-launch task loop. Non-x86-64 syscall ABIs and job-control
group stops fail explicitly. Audit output is capped at 64 KiB plus a truncation
notice. `[resources].memory_mib` caps each tracee process's virtual address space
with hard/soft `RLIMIT_AS`, preserving lower operator limits. This includes
anonymous and image mappings; it is not an aggregate instance RSS limit.
`[resources].vcpus` restricts the child to at most that many logical CPUs selected
from the launcher's allowed affinity mask. This bounds eligible CPUs, not CPU
time. Limits are installed only in the child before exec; no host-global cgroup
policy is changed. Kernel inheritance preserves them for supported descendants.
Self affinity queries (zero, current virtual PID or thread-group ID) report the
actual eligible CPU subset through a buffer of at most 1024 bytes. Affinity mutation and address-space limit mutation
are denied; unrelated virtual PIDs are not native scheduler targets.

Configured `uname` returns `Linux`, the instance id as nodename, the kernel-views
package version with `-ginux` as its virtual release, version `ginux`, machine
`x86_64`, and an empty final UTS field. This identifies the virtual implementation;
it does not report host kernel/hostname data or promise the host kernel's ABI.
The shared native syscall contract is unchanged. Configured `sysinfo` writes
the same deterministic structure as native supervision (Gate 22): every field
zero except `mem_unit = 1`, with no host counters. A `getrandom` request above
the balanced 256-byte bound returns a 256-byte short read (Gate 20); the
caller's length register is restored at the syscall exit. Configured image
reads keep their own 64 MiB request bound described below rather than the
balanced 1 MiB short read, and console writes over 4096 bytes return a
partial count.

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
only committed bytes after a short transfer or error. Scalar reads and preads
fill the available requested range up to Linux's 2,147,479,552-byte transfer limit,
using 4096-byte internal buffers; EOF or copy faults can return a shorter count.
Readv/writev remain bounded to 4096 bytes per call.
Owned files and pipes accept at most 16 iovecs, including empty entries, with a
combined length no greater than the signed transfer-result range. Pipe writes
use the combined vector length for atomicity and retain their existing bounds.
Image descriptors read natively: read, pread64, readv and preadv share a 64 MiB
request bound, readv and preadv summing their vectors. `preadv` and `preadv2`
are the `preadv` or `readv` they name (offset -1 is the current position) on
every descriptor, with that form's bounds and errors; any `preadv2` flag is
EOPNOTSUPP. `readahead` and `fadvise64` answer as Linux does for the
descriptor (EBADF, EINVAL for `readahead` on anything but a readable regular
file, ESPIPE for `fadvise64` on a pipe or FIFO) and otherwise return 0 with no
host effect. `sendfile` and `copy_file_range` read a regular owned or image
file as `pread64` and write an owned file (and, for `sendfile`, an assigned
device or the inherited console) as `write`/`pwrite64`, at most 1 MiB per call
(4096 bytes into the console or a device); owned channels and TCP sockets are
EINVAL outputs, without consuming input. Configured scalar console writes
return a partial count for requests over 4096 bytes, retaining that host transfer
bound while allowing callers to write the remainder. Metadata defaults to 32 objects (including seeded directories) and 64 independently
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

Optional `[storage].archive_import = true` lets a workload unpack one POSIX
tar stream into an owned directory with a single mediated write per MiB instead
of several mediated calls per member. `ioctl(dirfd, 0x40104701, &request)`
returns a write-only stream descriptor; each member is applied through the same
storage calls, contract decisions, limits and audit budget as individual
creates, and never through a link. It is off by default and answers `ENOTTY`
when disabled. See [docs/archive-import.md](docs/archive-import.md).

Configured launch uses one table of up to 256 public descriptors for bootstrap
stdio, immutable-image files, writable files, devices and pipes. Allocation uses
the lowest free number; native opens reserve a slot before running. Backend
handles stay private, including when the kernel reuses an underlying fd number.
Dup/dup2/dup3 and fcntl duplication share an open description across owners;
close-on-exec flags belong to each public descriptor. The backend closes only
after its last alias. A native image descriptor's host number is its public
number wherever the table can arrange it, so its calls run with the workload's
own registers: before a native open, free host numbers below the reserved one
are filled with inert close-on-exec placeholders (a placeholder at the reserved
number is closed), and duplicating a native image descriptor duplicates it in
the kernel onto the public target. A plain close of an owned descriptor closes
its placeholder in the same call. Placeholders are never reachable by a
workload call, which is translated or answered by the table first. Where the
numbers still differ (console aliases, or a host number another public
descriptor holds), syscall arguments are translated for native IO/metadata/
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
No writable host descriptor is exposed. Data disappears at instance teardown;
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
Readlink of /proc/self/exe and /proc/thread-self/exe returns the current instance
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
layouts fail the instance after exec rather than resuming a replaced address space.
Descriptor-based scripts require a non-CLOEXEC public file or directory descriptor;
otherwise execveat fails with ENOENT. The interpreter can reopen /dev/fd/<public>
(or an owned directory suffix) read-only through the virtual descriptor owner,
with a fresh offset, including after unlink/rename. This never imports native
or private descriptors. Other /dev/fd operations and owned ELF dynamic loaders remain unsupported.

Owned regular files support private and shared mappings. Shared write access
requires a readable/writable public file description; executable pins reject it.
Mediated writes/truncation and mapped writes use the same anonymous file backing;
private writes remain copy-on-write, and unlink/recreation preserves existing
mapping identity. Exec refuses an owned file while any registered task retains a
shared mapping of it, including a read-only protection that could regain write
access. Coordinated snapshots stop all tracees before reading owned bytes.
Preallocation on owned files returns EOPNOTSUPP. A temporary backing descriptor
transfer requires host pidfd_open/pidfd_getfd and ptrace access. Temporary native
descriptors and stack scratch retire before the original mmap returns. Fixed
maps cannot replace the replay instruction or scratch region. Signals stay
blocked in the calling task while supervisor-chosen syscalls replace its own, for
this transaction and for exec descriptor setup; they are delivered when the
original call returns. Transfer failure or death stops the instance if cleanup
cannot complete safely.
Configured launch admits bounded glibc, musl and Go thread clone forms; private
mapping transfers can address a registered nonleader task. File capacity charging
remains unchanged, but guest mappings,
private COW pages and mappings retained after unlink are not aggregate RAM-accounted.
No retention, mapping budget or wider Linux compatibility is promised.

The configured `/dev` view is an immutable virtual directory, empty by default;
image entries beneath it are hidden. The script descriptor reopen operation
described above is separate from directory enumeration. `[devices].assignments`
accepts `null`, `random` and `urandom`; each assigned name appears as
`/dev/<name>` through the existing device registry, and every other `/dev`
entry stays absent. Null reads return EOF and writes discard up to 4096 bytes
per call without reading the buffer. Random and urandom reads (`read`,
`pread64`, `readv`) return up to 4096 bytes per call from the host
`getrandom(2)` without blocking, which a workload can already call directly;
like Linux since 5.18, `/dev/random` does not block once the host generator is
ready. Bytes leave through the strict copy path, so an inaccessible buffer
gives EFAULT or a short read. Writes are read from the caller and discarded,
as Linux does for a caller that may not credit entropy; an instance never
feeds the host pool. `RNDGETENTCNT` reports 256 (a ready generator), the
privileged random ioctls return EPERM and other requests EINVAL; null ioctls
return ENOTTY. Stat/fstat/fstatat/statx report a character device, mode 0666,
with instance-owned identity and major/minor 1:3, 1:8 or 1:9. Open access
modes, close-on-exec descriptor flags, seek, close and basic access queries are
supported; device metadata cannot be changed. There are 64 open-device slots.
Unknown and duplicate assignments fail before launch. Device aliases share the
common descriptor table and handle lifetime. No host device node or descriptor
is used. Assigned device descriptors are always ready for configured polling.
Reads, writes and opens are decided and audited as `filesystem.path.read` and
`filesystem.path.write`, exactly as for null. `instance-validate` lists the
names this launcher serves as `configured-devices=null,random,urandom`; a
launcher without that field serves only `null`, and like any launcher rejects
an unsupported name when the launch starts, before the workload runs.

Anonymous `pipe`/`pipe2` are emulated with supervisor-owned memory and virtual
handles. Up to sixteen channel buffers hold 65536 bytes each; aliases use the common table.
`pipe2` accepts only `O_CLOEXEC|O_NONBLOCK`. Copies use bounded 4096-byte chunks;
writes of up to 4096 bytes are atomic. Blocking pipe writes retain task-owned
progress across full-buffer waits until the requested bytes are written. Other
tasks can drain the fixed buffer while that syscall remains stopped. Nonblocking
writes and packet operations retain their bounded short-transfer behavior. Reads consume only bytes successfully
copied out, so invalid/partially inaccessible destinations do not lose data.
Read/write direction, EOF, SIGPIPE, metadata, seek rejection, descriptor/status
flags, pipe-size queries and aliases across owners are supported.
Alias status flags and endpoint lifetimes are shared; close-on-exec flags are
per descriptor. No native pipe or host descriptor is given to the workload.

Named FIFOs in assigned writable storage use the same channel buffers.
`mknod`/`mknodat` accept FIFO creation, apply umask, and retain ordinary inode
permissions and namespace operations. Blocking opens wait for the opposite
endpoint; `O_NONBLOCK` and Linux `O_RDWR` behavior are supported. Separate opens
have separate status flags. Unlinking a FIFO preserves existing endpoints;
recreating its name creates a distinct channel. Export/restore preserves FIFO
metadata and hardlinks, with no buffered data or open endpoints.

Nonblocking empty/full operations return `EAGAIN`. Blocking operations stay
stopped at entry until another task changes pipe state. Forked peers can exchange
data and wake blocked reads/writes; a self-pipe without a runnable peer still
waits indefinitely. SIGKILL termination and reaping are supported. A blocked
owned read, write, lock, wait, poll or epoll wait ends early for a signal that
runs a handler or terminates the task. The call is handed back to the kernel,
which applies the handler's own flags: EINTR, or a restart of the same call with
SA_RESTART; poll and epoll waits always report EINTR. A partly completed
blocking write returns its count. Ignored signals leave the call blocked. The
supervisor looks for such signals when it reaps a task, which is when a child's
SIGCHLD is queued; a signal sent from outside the instance is not noticed while
a call stays blocked. Configured descriptor readiness is described below.

Configured processes start with a creation mask of `022`. `umask` updates the
process group's mask used by owned file and directory creation; fork copies it,
exec preserves it, and threads share it. This does not change the native lane.

Configured launch owns at most 32 task slots, including unreaped children.
Process creation accepts fork, vfork, and clone with `SIGCHLD`,
`CLONE_VM|CLONE_VFORK|SIGCHLD`, or the libc-fork
`CLONE_CHILD_SETTID|CLONE_CHILD_CLEARTID|SIGCHLD` flags. Native threads accept
the glibc `0x3d0f00` and musl `0x7d0f00` flag sets (VM, FS, FILES,
SIGHAND, THREAD, SYSVSEM, SETTLS, PARENT_SETTID and CHILD_CLEARTID; musl also
sets the ignored DETACHED bit); other clone forms remain unsupported. Threads
share the process descriptor table, cwd and executable pin. Pending syscall
results and readiness snapshots remain per task. A blocked owned IO call keeps
its original handle until completion, even if another thread replaces its fd. New children remain stopped until their virtual identity
and descriptor snapshot are installed. A creation is a reservation until the
parent's birth event publishes the child: a failed clone, or a parent that dies
first, withdraws the reserved identity and descriptor snapshot together, and a
native child that parent can no longer claim is killed without ever running.
Init is PID 1; PID/TID/parent queries,
child-TID writes and forwarded signal senders use virtual identities. Actual
credentials remain UID/GID 1000. `wait4` supports a positive child PID or -1,
optional `WNOHANG`, and a null rusage pointer. A faulty status destination still
reaps the child and leaves the status word unchanged. Kill supports only signal
0 and SIGKILL directed at a positive virtual PID. `tkill` and `tgkill` name
virtual thread IDs, as `raise`, `abort` and `pthread_kill` use them: any signal
for a thread of the caller's own process is queued by the kernel, with the
sender projected to its virtual PID on delivery. The caller runs `tgkill` with
its own host thread group, so the kernel itself refuses any thread outside it.
A handler runs in the named thread, also when it is parked in an owned wait,
and a default fatal action such as `abort`'s SIGABRT ends the process with that
signal. SIGSTOP, and SIGTSTP/SIGTTIN/SIGTTOU at their default action, return
EOPNOTSUPP because a group stop is not supported. Another process of the
instance gets the `kill` subset (signal 0 and SIGKILL, otherwise EOPNOTSUPP);
any other ID is ESRCH and never names a host task. Ignoring SIGCHLD and
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
sudo make test-tracee-kill
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

The source-build check uses an existing compiler rootfs and local ncurses/htop
release archives. It runs configure, parallel make and make install in assigned
storage, then executes the installed htop. It downloads nothing; the rootfs must
contain the C toolchain, development headers and standard shell build tools.

```sh
sudo python3 scripts/test-launch-build.py \
  target/x86_64-unknown-linux-gnu/release/ginux \
  compiler-rootfs.tar ncurses.tar.gz htop.tar.xz .artifacts/htop-build
```

Use a fresh output directory. It retains build logs, source/binary checksums,
the completion result and an archive of the source, build and installed files.

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
owners: pipes, local socket pairs, TCP, assigned memory files/null and inherited console aliases. Negative
descriptors are ignored; closed descriptors report POLLNVAL. Image files remain
unsupported for this operation. Error/hangup bits are reported independently of
the requested mask. Zero through 300000 ms and negative infinite waits are
supported. Queries park and wake on object progress; finite/console waits also
use a 1 ms supervisor tick.
A handled signal ends a parked query with EINTR as described for blocked pipe
operations. The shared native syscall contract is unchanged; this is
configured-launch readiness.

Configured launch permits `clock_gettime` and `clock_getres` for host
`CLOCK_REALTIME` and `CLOCK_MONOTONIC` only. These are global host clocks,
not virtual instance time; CPU clocks and dynamic/fd clocks return EPERM.
`nanosleep` and `clock_nanosleep` accept relative waits and absolute deadlines
on those two clocks, at most 300 seconds into the future. Requests are copied
once. Scalar kernel poll waits of at most 100 ms preserve peer progress and
recheck absolute realtime deadlines. Millisecond rounding can delay completion.
Relative waits use monotonic time; a wait interrupted by a signal handler
returns EINTR even with SA_RESTART, with remaining time for relative requests
only. Ignored signals and the supervisor's own stops do not end it. A realtime clock
adjustment cannot extend a request beyond 300 seconds of monotonic time;
that limit returns ETIMEDOUT. Invalid times or unsupported flags return EINVAL.
This does not change native execution's clock policy or virtualize vDSO time.

Configured `socketpair(AF_UNIX, SOCK_STREAM | SOCK_SEQPACKET, 0)`, with
optional `SOCK_CLOEXEC` and `SOCK_NONBLOCK`, returns two connected endpoints
owned by the supervisor. Each pair consumes two channel buffers, one per
direction, from the pipe pool, so pipe bounds, quotas and lower operator
limits apply; no host socket, name or descriptor transfer is involved, and
creation needs no network grant. Other families and types, including
`SOCK_DGRAM`, return EOPNOTSUPP.

Read, write and their vector forms, `send`/`recv` (`sendto`/`recvfrom` with a
null address and only `MSG_DONTWAIT`/`MSG_NOSIGNAL`), aliases, fork, exec with
close-on-exec, poll, select and epoll behave as for pipes in both directions.
Stream blocking writes complete across full-buffer waits; stream reads ignore
write boundaries. Sequenced packets carry up to 4096 bytes, preserve
boundaries, and a short receive discards the rest of the record. After the
peer closes everywhere, reads return buffered bytes then end-of-file and
writes return EPIPE with SIGPIPE unless `MSG_NOSIGNAL` is given. `shutdown`
closes directions for both endpoints as Linux does: the peer of a closed send
side drains then reads end-of-file with POLLRDHUP, writes into a closed
direction return EPIPE, and POLLHUP needs both directions closed. FIONREAD
reports queued bytes (summed payloads for packets), fstat reports a socket,
and F_GETFL reports `O_RDWR` with the shared `O_NONBLOCK`.

`getsockname`/`getpeername` report an unnamed `AF_UNIX` address. `getsockopt`
answers `SO_TYPE`, the socket family option (`AF_UNIX`), `SO_PROTOCOL`, `SO_ERROR`,
`SO_ACCEPTCONN` and the fixed 65536-byte `SO_SNDBUF`/`SO_RCVBUF`; peer
credentials and other options return ENOPROTOOPT. `setsockopt` accepts buffer
size requests without changing the bound and returns ENOPROTOOPT otherwise.
`connect` returns EISCONN without reading the address. Every socket call is
still decided by the contract first: a contract that denies `shutdown`,
`getsockname` or `*sockopt` denies them on these endpoints too. Pipes, FIFOs
and event objects return ENOTSOCK for socket calls.
FIONBIO changes the shared open status of owned pipe and socket endpoints,
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
these calls do not imply persistence after the in-memory instance ends.

A host coordinator may pass `--control-fd <inherited Unix stream socket>` for
mid-run filesystem snapshots. The supervisor keeps the socket private. Requests
are GXS1, a little-endian u64 strictly increasing sequence, a little-endian u16
pathname length1–512, and non-NUL pathname bytes. Destinations must be fresh.
Only after complete archive write/sync/close and no-overwrite publication does
it reply GXA1, the matching little-endian u64 sequence and u64 zero status.
Valid partial frames are buffered within the fixed bound. Invalid requests,
peer loss and capture failure stop the instance. The host owns request deadlines,
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
`UTIME_OMIT`/`UTIME_NOW`. Aliases share times; stat/statx return them. VFS index
metadata starts at zero. Configured-launch file creation, directory
creation and symlink creation stamp access and modification times from realtime;
nonempty writes, positional writes, vectored writes and truncation update the
modified time. Reads leave access times unchanged. Explicit timestamp updates and
archive restoration retain their supplied times until a later write or truncation.
`UTIME_NOW` uses the supervisor's native realtime clock.
These operations require existing owned objects.
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
milliseconds without modifying the supplied timespec. Blocked socket calls
follow the signal rule described for blocked pipe operations. Live sockets are
never exported or restored.
The focused scenario is `make build-launch-network-fixture` followed by
`sudo make test-launch-network`.

Owned storage inode uid/gid are virtual root. `chown`, `fchown`, `lchown` and
`fchownat` can preserve 0 or unchanged (-1) on existing assigned storage objects,
including symlinks and empty-path descriptor operations. Other identities remain
unsupported; these operations never change host ownership.
Native configured clone3 captures the Linux 6.12 argument structure before
execution and gives the host a private read-only snapshot. Caller structures
may be read-only; Ginux does not rewrite them and restores syscall argument
registers. Normal kernel-declared outputs, such as the pidfd output, still apply.
The existing virtual-cgroup adaptation accepts only an owned virtual cgroup
directory and starts the child in the parent's host cgroup; it does not
implement host cgroup placement. Unknown nonzero extension bytes fail closed.

The native runtime reserves `0x600000000000` through `0x600000080000` for
transient clone snapshots (one 4 KiB page per active task slot, within existing
memory and task limits). Workloads cannot map, discard, move or change
permissions in this range. Parent and child remove their snapshots before
returning to workload code. A pre-existing mapping is never overwritten;
allocation errors propagate. Death during the private protocol fails the
instance closed so a shared address space cannot retain a stale snapshot.
Snapshot capture requires host `process_vm_readv`; it fails closed if the host
cannot provide it.

Configured native waitid supports a null siginfo pointer without retaining
reaped child slots. Ginux pins each waitable host child with a private pidfd
before it runs and uses final-reap readiness (POLLHUP) to reconcile its
process table. The host waitid call, selectors, options, rusage and errno
semantics remain in force, including WNOHANG, WNOWAIT and copy-out failures.
Exited zombies and stopped/continued children are not treated as reaped.
Private pins close when waitid or wait4 reclaims the child; they do not change
the instance-visible descriptor budget. The native host must support pidfd
final-reap readiness, as in the Linux 6.12 ABI used for this contract.
