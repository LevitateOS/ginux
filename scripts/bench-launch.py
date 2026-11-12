#!/usr/bin/env python3
"""Launch-mode performance and overhead harness (make bench-launch).

Measures `ginux launch <instance.toml> <root>` against the same fixture run
natively in a chroot of the same root, per syscall class and per build-shaped
workload, and counts the supervisor work behind every row.

  bench-launch.py run     [--ginux LABEL=PATH[@DESCRIBE]]... [--reps N] [--scale F]
  bench-launch.py compare RUN_DIR [--baseline FILE] [--budgets FILE] [--subject LABEL]
  bench-launch.py ab      --a LABEL=PATH --b LABEL=PATH [run options]
  bench-launch.py accept  RUN_DIR [--subject LABEL] [--force]
  bench-launch.py selftest

See docs/launch-performance.md. Needs passwordless `sudo -n` (launch and the
native chroot both need root), `strace`, `taskset`, `unshare`, `gcc`.
"""
import argparse
import datetime
import hashlib
import io
import json
import os
import re
import shutil
import statistics
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
FIXTURE_SOURCE = REPO / 'benchmarks/launch/launch-bench-fixture.c'
CONFIG_TEMPLATE = REPO / 'config/instance-configured.toml'
DEFAULT_BUDGETS = REPO / 'benchmarks/launch/budgets.conf'
DEFAULT_BASELINE = REPO / 'benchmarks/launch/baseline.json'
ROOT_LAYOUT = 'tree16x16x12-v1'  # bump when the image tree or archive shape changes
TREE_FANOUT = (16, 16, 12)
PATH_ENV = 'PATH=/usr/local/bin:/usr/bin:/usr/sbin:/bin:/sbin'
HELLO = b'#include <stdio.h>\nint main(void) { puts("hello"); return 0; }\n'

# name, class, kind, passes at --scale 1, unit of one op, description
ROWS = [
    ('stat_image', 'stat_image', 'micro', 20000, 'call', 'newfstatat of one image file'),
    ('statx_image', 'statx_image', 'micro', 20000, 'call', 'statx of one image file'),
    ('openread_image', 'openread_image', 'micro', 10000, 'open+read+close', 'open, read 4 KiB, close of an image file'),
    ('getdents_image', 'getdents_image', 'micro', 5000, 'listing', 'open + getdents64 to the end + close of a 64-entry image directory'),
    ('stat_owned', 'stat_owned', 'micro', 20000, 'call', 'newfstatat of one owned (memory storage) file'),
    ('statx_owned', 'statx_owned', 'micro', 20000, 'call', 'statx of one owned file'),
    ('openread_owned', 'openread_owned', 'micro', 10000, 'open+read+close', 'open, read 4 KiB, close of an owned file'),
    ('getdents_owned', 'getdents_owned', 'micro', 5000, 'listing', 'getdents64 listing of a 64-entry owned directory'),
    ('create_owned', 'create_owned', 'micro', 4000, 'create+write+close', 'create a new owned file, write 64 bytes, close (unlink untimed)'),
    ('seekread_image', 'seekread_image', 'micro', 20000, 'lseek+pread', 'lseek and pread64 on an open image fd'),
    ('seekread_owned', 'seekread_owned', 'micro', 20000, 'lseek+pread', 'lseek and pread64 on an open owned fd'),
    ('fork_exec_wait', 'fork_exec_wait', 'micro', 300, 'fork+exec+wait', 'fork, execve of a tiny static image binary, wait4'),
    ('mmap_munmap', 'mmap_munmap', 'micro', 20000, 'mmap+munmap', 'anonymous mmap and munmap of one page'),
    ('clock_gettime', 'clock_gettime', 'micro', 20000, 'call', 'clock_gettime(CLOCK_MONOTONIC) through the syscall instruction'),
    ('getpid', 'getpid', 'micro', 20000, 'call', 'getpid (virtual identity under launch)'),
    ('futex_pair', 'futex_pair', 'micro', 5000, 'round trip', 'futex wake/wait handoff between two threads, one round trip'),
    ('pipe_pingpong', 'pipe_pingpong', 'micro', 5000, 'round trip', 'one byte through two pipes between a parent and a forked child'),
    ('walk_lstat', 'walk_lstat', 'workload', 20, 'entry', 'find-style recursive walk, getdents64 + lstat of every entry of the image tree'),
    ('tar_unpack', 'tar_unpack', 'workload', 2, 'entry', 'unpack a ustar archive from the image into owned storage'),
    ('hash_walk', 'hash_walk', 'workload', 5, 'entry', 'walk the image tree and read and hash every file'),
    ('cc_hello', None, 'workload', 1, 'compile+link', 'gcc compile+link of a tiny C file, compiler from the host root (skipped if absent)'),
]
ROW_NAMES = [r[0] for r in ROWS]


def sh(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def sha256(path):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def loadavg():
    return [float(x) for x in Path('/proc/loadavg').read_text().split()[:3]]


def median(values):
    return statistics.median(values)


def spread(values):
    """(max - min) / median; 0 for a single sample."""
    m = median(values)
    return (max(values) - min(values)) / m if m and len(values) > 1 else 0.0


# --------------------------------------------------------------------------
# run: prepare the root, run native and launch samples, count the supervisor
# --------------------------------------------------------------------------

def build_root(root, fixture):
    (root / 'bin').mkdir(parents=True)
    (root / 'work').mkdir()
    shutil.copyfile(fixture, root / 'bin/fixture')
    (root / 'bin/fixture').chmod(0o755)
    img = root / 'img'
    img.mkdir()
    (img / 'one').write_bytes(bytes((i * 7) & 0xff for i in range(4096)))
    (img / 'dir').mkdir()
    for i in range(64):
        (img / 'dir' / f'f{i}').write_bytes(b'x' * 64)
    a, b, c = TREE_FANOUT
    for i in range(a):
        for j in range(b):
            d = img / 'tree' / f'd{i:02d}' / f's{j:02d}'
            d.mkdir(parents=True)
            for k in range(c):
                size = 512 + ((i * 131 + j * 17 + k * 29) % 12) * 700
                (d / f'f{k:02d}').write_bytes(bytes(((i + j + k + n) & 0xff) for n in range(size)))
    # A quarter of the tree as a ustar archive, with fixed metadata.
    with tarfile.open(img / 'archive.tar', 'w', format=tarfile.USTAR_FORMAT) as tar:
        for path in sorted((img / 'tree').rglob('*')):
            rel = path.relative_to(img / 'tree')
            if not rel.parts[0] in ('d00', 'd01', 'd02', 'd03'):
                continue
            info = tar.gettarinfo(str(path), arcname=str(rel))
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = 0
            info.mode = 0o755 if path.is_dir() else 0o644
            if path.is_dir():
                tar.addfile(info)
            else:
                with open(path, 'rb') as f:
                    tar.addfile(info, f)


def config_text(args, storage=True, init='/bin/fixture', memory=256, extra_env=None):
    text = CONFIG_TEMPLATE.read_text()
    text = text.replace('init = "/bin/bash"', f'init = "{init}"')
    text = text.replace('args = []', 'args = ' + json.dumps(args))
    if storage:
        text = text.replace('[storage]\nassignments = []',
                            '[storage]\nassignments = ["memory:/work"]\nmax_objects = 16384')
    text = text.replace('memory_mib = 256', f'memory_mib = {memory}')
    if extra_env:
        text = text.replace('environment = ["container=ginux"]',
                            'environment = ' + json.dumps(['container=ginux'] + extra_env))
    return text


class Bench:
    def __init__(self, work, root, fixture, cpu, cc_available):
        self.work, self.root, self.fixture, self.cpu = work, root, fixture, cpu
        self.cc_available = cc_available
        self.counter = 0

    def passes(self, row, scale):
        base = row[3]
        return max(1, int(round(base * scale)))

    def config_for(self, row, passes):
        self.counter += 1
        path = self.work / f'instance-{self.counter}.toml'
        if row[0] == 'cc_hello':
            text = config_text(['-pipe', '-O0', '-x', 'c', '-', '-o', '/tmp/hello'], storage=False,
                               init='/usr/bin/gcc', memory=1024, extra_env=[PATH_ENV])
            text = text.replace('[storage]\nassignments = []',
                                '[storage]\nassignments = ["memory:/tmp"]\nmax_objects = 4096')
        else:
            text = config_text([row[1], str(passes)])
        path.write_text(text)
        return path

    def native_command(self, row, passes):
        if row[0] == 'cc_hello':
            inner = ('mount -t tmpfs -o mode=1777 tmpfs /tmp && exec chroot --userspec=1000:1000 / '
                     f'env -i {PATH_ENV} gcc -pipe -O0 -x c - -o /tmp/hello')
        else:
            inner = (f'mount -t tmpfs -o mode=1777 tmpfs {self.root}/work && '
                     f'exec chroot --userspec=1000:1000 {self.root} /bin/fixture {row[1]} {passes}')
        return ['sudo', '-n', 'taskset', '-c', str(self.cpu), 'unshare', '-m', 'sh', '-c', inner]

    def launch_command(self, ginux, row, passes, prefix=()):
        cfg = self.config_for(row, passes)
        root = '/' if row[0] == 'cc_hello' else str(self.root)
        return ['sudo', '-n', *prefix, str(ginux), 'launch', str(cfg), root]

    def run_once(self, command, row, timeout=900):
        stdin = HELLO if row[0] == 'cc_hello' else b''
        start = time.monotonic()
        proc = subprocess.run(command, input=stdin, capture_output=True, timeout=timeout)
        wall = time.monotonic() - start
        return proc, wall

    def sample(self, subject, ginux, row, passes):
        command = (self.native_command(row, passes) if ginux is None
                   else self.launch_command(ginux, row, passes))
        load = loadavg()[0]
        try:
            proc, wall = self.run_once(command, row)
        except subprocess.TimeoutExpired:
            return {'error': 'timeout', 'load1': load, 'wall_s': None}
        out = {'wall_s': wall, 'load1': load, 'exit': proc.returncode}
        if row[0] == 'cc_hello':
            if proc.returncode != 0:
                out['error'] = f'exit {proc.returncode}: {proc.stderr[-200:].decode(errors="replace")}'
            else:
                out.update(ns=int(wall * 1e9), ops=1)
            return out
        match = re.search(rb'RESULT class=(\S+) passes=(\d+) ns=(\d+) ops=(\d+)', proc.stdout)
        if proc.returncode != 0 or not match:
            tail = (proc.stdout + proc.stderr)[-200:].decode(errors='replace')
            out['error'] = f'exit {proc.returncode}: {tail}'
            return out
        out.update(ns=int(match.group(3)), ops=int(match.group(4)))
        return out

    # ---- supervisor cost ------------------------------------------------
    def supervisor_run(self, ginux, row, passes):
        """One strace of the supervisor: filtered log and a -c summary."""
        log = self.work / 'trace.log'
        summary = self.work / 'summary.txt'
        res = {}
        command = self.launch_command(ginux, row, passes,
                                      prefix=('strace', '-o', str(log), '-e', 'trace=wait4,ptrace',
                                              '-e', 'signal=none'))
        proc, _ = self.run_once(command, row)
        match = re.search(rb'RESULT class=\S+ passes=\d+ ns=\d+ ops=(\d+)', proc.stdout)
        if not match:
            return None
        res['ops'] = int(match.group(1))
        text = log.read_text(errors='replace')
        res['stops'] = len(re.findall(r'^wait4\(-1, \[\{WIFSTOPPED', text, re.M))
        res['entries'] = len(re.findall(r'op=PTRACE_SYSCALL_INFO_(?:ENTRY|SECCOMP)', text))
        res['ptrace_calls'] = len(re.findall(r'^ptrace\(', text, re.M))
        command = self.launch_command(ginux, row, passes,
                                      prefix=('strace', '-c', '-o', str(summary), '-e', 'signal=none'))
        self.run_once(command, row)
        for line in summary.read_text(errors='replace').splitlines():
            parts = line.split()
            if parts and parts[-1] == 'total':
                res['supervisor_syscalls'] = int(parts[3])
        return res

    def supervisor_cost(self, ginux, row, scale):
        """Cost per workload call from two runs (P and 2P passes) so that
        startup and setup cancel out of the difference."""
        if row[0] == 'cc_hello':
            return {'note': 'single-shot row, not counted'}
        p = max(2, self.passes(row, scale) // 2)
        a = self.supervisor_run(ginux, row, p)
        b = self.supervisor_run(ginux, row, 2 * p)
        if not a or not b or 'supervisor_syscalls' not in a or 'supervisor_syscalls' not in b:
            return {'note': 'supervisor counting failed'}
        delta = {k: b[k] - a[k] for k in a}
        if delta['entries'] <= 0 or delta['ops'] <= 0:
            return {'note': 'no supervised calls counted'}
        return {
            'supervised_syscalls_per_op': delta['entries'] / delta['ops'],
            'stops_per_syscall': delta['stops'] / delta['entries'],
            'ptrace_calls_per_syscall': delta['ptrace_calls'] / delta['entries'],
            'supervisor_syscalls_per_syscall': delta['supervisor_syscalls'] / delta['entries'],
            'counted_passes': p,
        }


def parse_ginux(spec):
    describe = None
    if '@' in spec:
        spec, describe = spec.rsplit('@', 1)
    label, _, path = spec.partition('=')
    if not path:
        label, path = Path(spec).parent.name or 'ginux', spec
    return label, Path(path).resolve(), describe


def describe_binary(path, override):
    if override:
        return override
    for parent in [path.parent, *path.parents]:
        if (parent / '.git').exists():
            r = sh(['git', '-C', str(parent), 'describe', '--always', '--dirty', '--tags'])
            if r.returncode == 0:
                return r.stdout.strip() + ' (repository of the binary)'
    return 'unknown (binary is outside a git work tree; pass LABEL=PATH@DESCRIBE)'


def cpu_model():
    for line in Path('/proc/cpuinfo').read_text().splitlines():
        if line.startswith('model name'):
            return line.split(':', 1)[1].strip()
    return 'unknown'


def pick_cpu():
    allowed = sorted(os.sched_getaffinity(0))
    return allowed[-1]


def cmd_run(args):
    ginuxes = [parse_ginux(s) for s in (args.ginux or [])]
    if not ginuxes:
        default = REPO / 'target/x86_64-unknown-linux-gnu/release/ginux'
        ginuxes = [('current', default, None)]
    for label, path, _ in ginuxes:
        if not path.is_file():
            sys.exit(f'bench-launch: ginux binary not found: {path} (run make build, or pass --ginux LABEL=PATH)')
    if len({g[0] for g in ginuxes}) != len(ginuxes):
        sys.exit('bench-launch: labels must be unique')
    fixture = Path(args.fixture)
    if not fixture.is_file():
        sys.exit(f'bench-launch: fixture not built: {fixture} (make build-bench-launch-fixture)')
    wanted = args.rows.split(',') if args.rows else ROW_NAMES
    for name in wanted:
        if name not in ROW_NAMES:
            sys.exit(f'bench-launch: unknown row {name}; rows: {" ".join(ROW_NAMES)}')
    rows = [r for r in ROWS if r[0] in wanted]
    if sh(['sudo', '-n', 'true']).returncode != 0:
        sys.exit('bench-launch: passwordless sudo is required')

    stamp = datetime.datetime.now().strftime('%Y%m%dT%H%M%S')
    out = Path(args.out or REPO / 'build/bench-launch' / stamp)
    out.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix='ginux-bench-launch-', dir=out))
    root = work / 'root'
    build_root(root, fixture)
    os.chmod(work, 0o755)
    cc_available = Path('/usr/bin/gcc').exists()
    bench = Bench(work, root, fixture, pick_cpu(), cc_available)
    nproc = os.cpu_count()
    load_start = loadavg()
    meta = {
        'run_id': stamp,
        'host_kernel': os.uname().release,
        'host_arch': os.uname().machine,
        'cpu_model': cpu_model(),
        'host_cpus': nproc,
        'native_cpu': bench.cpu,
        'load_start': load_start,
        'reps': args.reps,
        'scale': args.scale,
        'root_layout': ROOT_LAYOUT,
        'fixture_sha256': sha256(fixture),
        'config_template_sha256': hashlib.sha256(CONFIG_TEMPLATE.read_bytes()).hexdigest(),
        'config_profile': 'balanced',
        'storage': 'memory:/work, max_objects=16384',
        'native_comparison': 'chroot of the same root, tmpfs at /work, same uid 1000, one pinned CPU',
        'subjects': {label: {'path': str(path), 'sha256': sha256(path),
                             'describe': describe_binary(path, describe)}
                     for label, path, describe in ginuxes},
        'rows': [r[0] for r in rows],
    }
    subjects = ['native'] + [g[0] for g in ginuxes]
    binaries = {g[0]: g[1] for g in ginuxes}
    samples_path = out / 'samples.jsonl'
    notes = []
    skipped = set()
    with samples_path.open('w') as samples:
        for rep in range(args.reps):
            for row in rows:
                if row[0] in skipped:
                    continue
                passes = bench.passes(row, args.scale)
                order = subjects[rep % len(subjects):] + subjects[:rep % len(subjects)]
                for subject in order:
                    s = bench.sample(subject, binaries.get(subject), row, passes)
                    s.update(type='sample', rep=rep, row=row[0], subject=subject, passes=passes)
                    if 'ns' in s:
                        s['ns_per_op'] = s['ns'] / s['ops']
                    samples.write(json.dumps(s) + '\n')
                    samples.flush()
                    if 'error' in s:
                        msg = f'{row[0]} [{subject}] {s["error"]}'
                        print('bench-launch: ' + msg, file=sys.stderr)
                        if row[0] == 'cc_hello' and subject == 'native':
                            notes.append('cc_hello skipped: no usable compiler in the host root')
                            skipped.add('cc_hello')
                            break
                print(f'bench-launch: rep {rep + 1}/{args.reps} {row[0]} done (load {loadavg()[0]:.1f})',
                      file=sys.stderr)
        if not args.no_supervisor:
            for row in rows:
                if row[0] in skipped:
                    continue
                for label, path, _ in ginuxes:
                    cost = bench.supervisor_cost(path, row, args.scale)
                    cost.update(type='supervisor', row=row[0], subject=label)
                    samples.write(json.dumps(cost) + '\n')
                    samples.flush()
                    print(f'bench-launch: supervisor cost {row[0]} [{label}] done', file=sys.stderr)
    meta['load_end'] = loadavg()
    limit = nproc / 2
    meta['load_limit'] = limit
    meta['reliable'] = max(meta['load_start'][0], meta['load_end'][0]) <= limit
    meta['notes'] = notes
    (out / 'metadata.json').write_text(json.dumps(meta, indent=2) + '\n')
    shutil.rmtree(work, ignore_errors=True)
    results = summarize(out)
    (out / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    (out / 'report.md').write_text(render_markdown(results))
    link = REPO / 'build/bench-launch/latest'
    if out.parent == REPO / 'build/bench-launch':
        try:
            if link.is_symlink():
                link.unlink()
            link.symlink_to(out.name)
        except OSError:
            pass
    print((out / 'report.md').read_text())
    print(f'bench-launch: wrote {out}')
    args.run_dir = out
    return 0


# --------------------------------------------------------------------------
# results, report
# --------------------------------------------------------------------------

def summarize(run_dir):
    run_dir = Path(run_dir)
    meta = json.loads((run_dir / 'metadata.json').read_text())
    samples = [json.loads(l) for l in (run_dir / 'samples.jsonl').read_text().splitlines() if l]
    rows = {}
    for r in ROWS:
        if r[0] in meta['rows']:
            rows[r[0]] = {'kind': r[2], 'unit': r[4], 'description': r[5], 'subjects': {}}
    for s in samples:
        row = rows.get(s['row'])
        if row is None:
            continue
        entry = row['subjects'].setdefault(s['subject'], {'values': [], 'errors': [], 'supervisor': None})
        if s['type'] == 'sample':
            if 'ns_per_op' in s:
                entry['values'].append(s['ns_per_op'])
            else:
                entry['errors'].append(s.get('error', 'failed'))
        elif s['type'] == 'supervisor':
            entry['supervisor'] = {k: v for k, v in s.items() if k not in ('type', 'row', 'subject')}
    for name, row in list(rows.items()):
        for subject, e in row['subjects'].items():
            v = e.pop('values')
            if v:
                e.update(median_ns_per_op=median(v), min_ns_per_op=min(v), max_ns_per_op=max(v),
                         spread=spread(v), samples=len(v))
        native = row['subjects'].get('native', {}).get('median_ns_per_op')
        for subject, e in row['subjects'].items():
            if subject != 'native' and native and 'median_ns_per_op' in e:
                e['ratio_to_native'] = e['median_ns_per_op'] / native
    return {'metadata': meta, 'rows': rows}


def fmt_ns(ns):
    if ns is None:
        return 'n/a'
    if ns >= 1e9:
        return f'{ns / 1e9:.2f} s'
    if ns >= 1e6:
        return f'{ns / 1e6:.2f} ms'
    if ns >= 1e3:
        return f'{ns / 1e3:.2f} us'
    return f'{ns:.0f} ns'


def cell(e):
    if not e or 'median_ns_per_op' not in e:
        return 'FAILED'
    return f'{fmt_ns(e["median_ns_per_op"])} (+/-{e["spread"] * 100:.0f}%)'


def render_markdown(results):
    meta, rows = results['metadata'], results['rows']
    ginux = list(meta['subjects'])
    out = ['# Launch-mode benchmark', '']
    if not meta['reliable']:
        out += [f'**UNRELIABLE RUN: load average {meta["load_start"][0]:.1f} at start and '
                f'{meta["load_end"][0]:.1f} at end exceeded the limit {meta["load_limit"]:.1f} '
                f'(nproc/2). Numbers are indicative only and must not be accepted as a baseline.**', '']
    for note in meta.get('notes', []):
        out += [f'Note: {note}.', '']
    out += [f'Kernel {meta["host_kernel"]}, {meta["cpu_model"]}, {meta["host_cpus"]} CPUs. '
            f'Repetitions {meta["reps"]}, scale {meta["scale"]}. Load average at start '
            f'{" ".join(f"{x:.2f}" for x in meta["load_start"])}, at end '
            f'{" ".join(f"{x:.2f}" for x in meta["load_end"])}.', '',
            'Each cell is the median ns (or us/ms) per operation over the repetitions with the relative '
            'spread (max-min)/median. Native is the same fixture in a chroot of the same root; ratio is '
            'ginux median / native median.', '']
    header = '| Row | Operation | Native |'
    sep = '|---|---|---|'
    for g in ginux:
        header += f' {g} | {g} / native |'
        sep += '---|---|'
    if len(ginux) == 2:
        header += f' {ginux[1]} vs {ginux[0]} |'
        sep += '---|'
    out += [header, sep]
    for name, row in rows.items():
        line = f'| {name} | {row["unit"]} | {cell(row["subjects"].get("native"))} |'
        for g in ginux:
            e = row['subjects'].get(g)
            ratio = f'{e["ratio_to_native"]:.1f}x' if e and 'ratio_to_native' in e else 'n/a'
            line += f' {cell(e)} | {ratio} |'
        if len(ginux) == 2:
            a, b = (row['subjects'].get(g) for g in ginux)
            if a and b and 'median_ns_per_op' in a and 'median_ns_per_op' in b:
                line += f' {(b["median_ns_per_op"] / a["median_ns_per_op"] - 1) * 100:+.1f}% |'
            else:
                line += ' n/a |'
        out.append(line)
    out += ['', '## Supervisor cost per supervised workload syscall', '',
            'Counted with strace on the supervisor (difference of two runs, so startup cancels). '
            'Stops and ptrace calls per supervised syscall come from the `wait4`/`ptrace` trace; '
            'supervisor syscalls are the `strace -c` total of the supervisor process.', '']
    header = '| Row | Subject | Supervised syscalls/op | Stops/syscall | ptrace calls/syscall | Supervisor syscalls/syscall |'
    out += [header, '|---|---|---|---|---|---|']
    for name, row in rows.items():
        for g in ginux:
            sup = (row['subjects'].get(g) or {}).get('supervisor') or {}
            if 'stops_per_syscall' in sup:
                out.append(f'| {name} | {g} | {sup["supervised_syscalls_per_op"]:.2f} | '
                           f'{sup["stops_per_syscall"]:.2f} | {sup["ptrace_calls_per_syscall"]:.2f} | '
                           f'{sup["supervisor_syscalls_per_syscall"]:.2f} |')
            else:
                out.append(f'| {name} | {g} | {sup.get("note", "n/a")} | | | |')
    out += ['', 'Notes: the 4% native budget of Gate 11 applies to compute-bound rows only; every supervised '
            'syscall costs microseconds under ptrace, so ratios above 1 are expected here and the rows are '
            'regression guards, not parity claims. See docs/launch-performance.md.', '']
    return '\n'.join(out)


# --------------------------------------------------------------------------
# compare, A/B, accept
# --------------------------------------------------------------------------

def load_budgets(path):
    budgets = {'default': {'regression_pct': 10.0}}
    if not Path(path).exists():
        return budgets
    for line in Path(path).read_text().splitlines():
        line = line.split('#', 1)[0].strip()
        if not line:
            continue
        name, *pairs = line.split()
        entry = budgets.setdefault(name, {})
        for pair in pairs:
            key, _, value = pair.partition('=')
            if key not in ('regression_pct', 'max_ns_per_op', 'max_ratio_to_native'):
                sys.exit(f'bench-launch: bad budget key {key!r} in {path}')
            entry[key] = float(value)
    return budgets


def budget_for(budgets, row):
    merged = dict(budgets['default'])
    merged.update(budgets.get(row, {}))
    return merged


ENV_KEYS = ['host_kernel', 'host_arch', 'cpu_model', 'host_cpus', 'root_layout', 'fixture_sha256',
            'config_template_sha256', 'config_profile', 'storage', 'native_comparison', 'scale']


def pick_subject(results, wanted):
    subjects = list(results['metadata']['subjects'])
    if wanted:
        if wanted not in subjects:
            sys.exit(f'bench-launch: no subject {wanted}; run has {subjects}')
        return wanted
    return subjects[0]


def compare_baseline(results, baseline, budgets, subject):
    """Returns (lines, status). status: 0 ok, 1 regression, 2 environment mismatch."""
    meta = results['metadata']
    lines = []
    mismatch = [(k, baseline['metadata'].get(k), meta.get(k)) for k in ENV_KEYS
                if baseline['metadata'].get(k) != meta.get(k)]
    if mismatch:
        for k, a, c in mismatch:
            lines.append(f'LAUNCH_ENVIRONMENT: INCOMPATIBLE key={k} accepted={a} current={c}')
        lines.append('No regression verdict: the run is not comparable with the accepted baseline '
                     '(accept a new baseline on this environment, see docs/launch-performance.md).')
        return lines, 2
    failures = 0
    lines += [f'Subject {subject} against the accepted baseline '
              f'({baseline.get("accepted_from", "?")}, binary {baseline.get("subject_describe", "?")}).', '',
              '| Row | Baseline | Current | Change | Allowed | Absolute target | Verdict |',
              '|---|---|---|---|---|---|---|']
    for name, row in results['rows'].items():
        cur = row['subjects'].get(subject, {})
        base = baseline['rows'].get(name)
        b = budget_for(budgets, name)
        if 'median_ns_per_op' not in cur:
            lines.append(f'| {name} | | FAILED | | | | FAIL |')
            failures += 1
            continue
        verdicts, target = [], ''
        if 'max_ns_per_op' in b:
            target += f'<= {fmt_ns(b["max_ns_per_op"])}'
            if cur['median_ns_per_op'] > b['max_ns_per_op']:
                verdicts.append('TARGET-MISS')
        if 'max_ratio_to_native' in b:
            target += f' ratio <= {b["max_ratio_to_native"]:g}x'
            if cur.get('ratio_to_native', 0) > b['max_ratio_to_native']:
                verdicts.append('TARGET-MISS')
        if base is None:
            change, allowed = 'no baseline row', ''
        else:
            delta = (cur['median_ns_per_op'] / base['median_ns_per_op'] - 1) * 100
            change, allowed = f'{delta:+.1f}%', f'+{b["regression_pct"]:g}%'
            if delta > b['regression_pct']:
                verdicts.append('REGRESSION')
        failures += bool(verdicts)
        lines.append(f'| {name} | {fmt_ns(base["median_ns_per_op"]) if base else "n/a"} | '
                     f'{cell(cur)} | {change} | {allowed} | {target or "-"} | {" ".join(verdicts) or "ok"} |')
    return lines, 1 if failures else 0


def compare_ab(results, budgets, labels):
    a, b = labels[:2]
    lines = [f'A/B: {a} (A) against {b} (B), alternating runs, {results["metadata"]["reps"]} repetitions.', '',
             '| Row | A | B | B vs A | Noise | Allowed | Verdict |', '|---|---|---|---|---|---|---|']
    failures = 0
    for name, row in results['rows'].items():
        ea, eb = row['subjects'].get(a, {}), row['subjects'].get(b, {})
        if 'median_ns_per_op' not in ea or 'median_ns_per_op' not in eb:
            lines.append(f'| {name} | {cell(ea)} | {cell(eb)} | | | | FAIL |')
            failures += 1
            continue
        delta = (eb['median_ns_per_op'] / ea['median_ns_per_op'] - 1) * 100
        noise = max(ea['spread'], eb['spread']) * 100
        allowed = budget_for(budgets, name)['regression_pct']
        if abs(delta) <= noise:
            verdict = 'within noise'
        elif delta < 0:
            verdict = 'faster'
        elif delta > allowed:
            verdict = 'REGRESSION'
            failures += 1
        else:
            verdict = 'slower, within budget'
        lines.append(f'| {name} | {cell(ea)} | {cell(eb)} | {delta:+.1f}% | +/-{noise:.0f}% | '
                     f'+{allowed:g}% | {verdict} |')
    supervisor = ['', '| Row | Stops/syscall A | B | ptrace/syscall A | B | Supervisor syscalls/syscall A | B |',
                  '|---|---|---|---|---|---|---|']
    for name, row in results['rows'].items():
        sa = (row['subjects'].get(a) or {}).get('supervisor') or {}
        sb = (row['subjects'].get(b) or {}).get('supervisor') or {}
        if 'stops_per_syscall' in sa and 'stops_per_syscall' in sb:
            supervisor.append(f'| {name} | {sa["stops_per_syscall"]:.2f} | {sb["stops_per_syscall"]:.2f} | '
                              f'{sa["ptrace_calls_per_syscall"]:.2f} | {sb["ptrace_calls_per_syscall"]:.2f} | '
                              f'{sa["supervisor_syscalls_per_syscall"]:.2f} | '
                              f'{sb["supervisor_syscalls_per_syscall"]:.2f} |')
    return lines + supervisor, 1 if failures else 0


def cmd_compare(args):
    run_dir = Path(args.run) if args.run else REPO / 'build/bench-launch/latest'
    results = summarize(run_dir.resolve())
    meta = results['metadata']
    budgets = load_budgets(args.budgets)
    subjects = list(meta['subjects'])
    out = [f'# Launch-mode comparison of {run_dir.resolve().name}', '']
    unreliable = not meta['reliable']
    if unreliable:
        out += [f'UNRELIABLE: load average {meta["load_start"][0]:.1f} (start) / {meta["load_end"][0]:.1f} '
                f'(end) exceeded {meta["load_limit"]:.1f} (nproc/2). Verdicts are reported but not enforced.', '']
    status = 0
    if len(subjects) >= 2 and not args.baseline_only:
        lines, status = compare_ab(results, budgets, subjects)
        out += lines + ['']
    baseline_path = Path(args.baseline)
    if baseline_path.exists() and (len(subjects) < 2 or args.baseline_only):
        subject = pick_subject(results, args.subject)
        lines, status = compare_baseline(results, json.loads(baseline_path.read_text()), budgets, subject)
        out += lines + ['']
    elif len(subjects) < 2 or args.baseline_only:
        out += [f'No accepted baseline at {baseline_path}: nothing to compare against '
                '(accept one with make bench-launch-accept, see docs/launch-performance.md).', '']
    print('\n'.join(out))
    if unreliable and status == 1:
        print('LAUNCH_COMPARE: UNRELIABLE (regressions above are not enforced on a loaded host)')
        return 0
    print({0: 'LAUNCH_COMPARE: PASS', 1: 'LAUNCH_COMPARE: FAIL',
           2: 'LAUNCH_COMPARE: SKIP (environment mismatch)'}[status])
    return status


def cmd_ab(args):
    args.ginux = [args.a, args.b]
    if cmd_run(args):
        return 1
    args.run, args.baseline_only = str(args.run_dir), False
    args.baseline = str(DEFAULT_BASELINE)
    args.subject = None
    text_status = cmd_compare(args)
    return text_status


def cmd_accept(args):
    run_dir = Path(args.run) if args.run else REPO / 'build/bench-launch/latest'
    results = summarize(run_dir.resolve())
    meta = results['metadata']
    if not meta['reliable'] and not args.force:
        sys.exit('bench-launch: refusing to accept an unreliable (loaded) run; rerun on an idle host or pass --force')
    subject = pick_subject(results, args.subject)
    failed = [n for n, r in results['rows'].items() if 'median_ns_per_op' not in r['subjects'].get(subject, {})]
    if failed and not args.force:
        sys.exit(f'bench-launch: rows failed in this run: {" ".join(failed)} (fix, or pass --force)')
    baseline = {
        'accepted_from': run_dir.resolve().name,
        'accepted_at': datetime.datetime.now().isoformat(timespec='seconds'),
        'subject': subject,
        'subject_describe': meta['subjects'][subject]['describe'],
        'subject_sha256': meta['subjects'][subject]['sha256'],
        'metadata': {k: meta[k] for k in ENV_KEYS},
        'rows': {n: {'median_ns_per_op': r['subjects'][subject]['median_ns_per_op'],
                     'spread': r['subjects'][subject]['spread']}
                 for n, r in results['rows'].items() if 'median_ns_per_op' in r['subjects'].get(subject, {})},
    }
    Path(args.baseline).write_text(json.dumps(baseline, indent=2) + '\n')
    print(f'bench-launch: wrote {args.baseline}; review it and commit it deliberately')
    return 0


# --------------------------------------------------------------------------
# selftest: compare logic on synthetic runs, no root needed
# --------------------------------------------------------------------------

def synthetic(base, reliable=True, kernel='k', **ginux):
    rows = {n: {'kind': 'micro', 'unit': 'call', 'description': '', 'subjects': {
        'native': {'median_ns_per_op': 100.0, 'spread': 0.01, 'errors': [], 'supervisor': None}}} for n in base}
    for label, factor in ginux.items():
        for n in rows:
            rows[n]['subjects'][label] = {'median_ns_per_op': base[n] * factor, 'spread': 0.02, 'errors': [],
                                          'supervisor': None, 'ratio_to_native': base[n] * factor / 100}
    meta = {k: 'x' for k in ENV_KEYS}
    meta.update(host_kernel=kernel, subjects={g: {'describe': 'd', 'sha256': 's'} for g in ginux},
                reliable=reliable, load_start=[1, 1, 1], load_end=[1, 1, 1], load_limit=4, reps=3)
    return {'metadata': meta, 'rows': rows}


def cmd_selftest(_):
    base = {'a': 1000.0, 'b': 2000.0}
    budgets = {'default': {'regression_pct': 10.0}, 'b': {'regression_pct': 30.0, 'max_ns_per_op': 2500.0}}
    baseline = {'metadata': synthetic(base, g=1.0)['metadata'],
                'rows': {n: {'median_ns_per_op': v * 1.0} for n, v in base.items()}}
    baseline['metadata'] = {k: baseline['metadata'][k] for k in ENV_KEYS}
    assert compare_baseline(synthetic(base, g=1.05), baseline, budgets, 'g')[1] == 0
    assert compare_baseline(synthetic(base, g=1.15), baseline, budgets, 'g')[1] == 1, 'row a over 10%'
    assert compare_baseline(synthetic(base, g=1.27), baseline, budgets, 'g')[1] == 1
    assert compare_baseline(synthetic({'a': 1000.0, 'b': 2000.0}, g=1.0, kernel='other'), baseline, budgets, 'g')[1] == 2
    assert compare_ab(synthetic(base, g=1.0, h=1.0), budgets, ['g', 'h'])[1] == 0
    results = synthetic(base, g=1.0)
    for n in base:
        results['rows'][n]['subjects']['h'] = dict(results['rows'][n]['subjects']['g'],
                                                   median_ns_per_op=base[n] * 1.5)
    assert compare_ab(results, budgets, ['g', 'h'])[1] == 1
    assert median([3, 1, 2]) == 2 and abs(spread([1.0, 1.1, 1.2]) - 0.2 / 1.1) < 1e-9
    with tempfile.TemporaryDirectory() as d:
        (Path(d) / 'b.conf').write_text('default regression_pct=12\nx max_ratio_to_native=30 # c\n')
        got = load_budgets(Path(d) / 'b.conf')
        assert got['default']['regression_pct'] == 12 and got['x']['max_ratio_to_native'] == 30
    print('bench-launch selftest: PASS')
    return 0


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)

    def run_options(p):
        p.add_argument('--reps', type=int, default=5, help='repetitions per row and subject (default 5)')
        p.add_argument('--scale', type=float, default=1.0, help='multiply every row\'s pass count (default 1)')
        p.add_argument('--rows', help='comma-separated row names (default all)')
        p.add_argument('--out', help='output directory (default build/bench-launch/<timestamp>)')
        p.add_argument('--fixture', default=str(REPO / 'build/bench-launch/launch-bench-fixture'))
        p.add_argument('--no-supervisor', action='store_true', help='skip the strace supervisor counting')

    p = sub.add_parser('run')
    run_options(p)
    p.add_argument('--ginux', action='append', help='LABEL=PATH[@DESCRIBE]; repeat for several binaries')
    p.set_defaults(func=cmd_run)

    p = sub.add_parser('compare')
    p.add_argument('run', nargs='?')
    p.add_argument('--baseline', default=str(DEFAULT_BASELINE))
    p.add_argument('--budgets', default=str(DEFAULT_BUDGETS))
    p.add_argument('--subject')
    p.add_argument('--baseline-only', action='store_true', help='compare to the baseline even when the run has two binaries')
    p.set_defaults(func=cmd_compare)

    p = sub.add_parser('ab')
    run_options(p)
    p.add_argument('--a', required=True)
    p.add_argument('--b', required=True)
    p.add_argument('--budgets', default=str(DEFAULT_BUDGETS))
    p.set_defaults(func=cmd_ab)

    p = sub.add_parser('accept')
    p.add_argument('run', nargs='?')
    p.add_argument('--subject')
    p.add_argument('--baseline', default=str(DEFAULT_BASELINE))
    p.add_argument('--force', action='store_true')
    p.set_defaults(func=cmd_accept)

    p = sub.add_parser('selftest')
    p.set_defaults(func=cmd_selftest)

    args = parser.parse_args()
    sys.exit(args.func(args))


if __name__ == '__main__':
    main()
