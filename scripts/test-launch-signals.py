#!/usr/bin/env python3
"""Check signals against supervisor-held syscalls and creation racing death."""
import json
import os
from pathlib import Path
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time

PARKED = {
    'park-read': b'park surface=lane-channel',
    'park-read-restart': b'park surface=lane-channel',
    'park-poll': b'park surface=owned-poll',
    'park-pselect': b'park surface=owned-poll',
    'park-pselect-timed': b'park surface=owned-poll',
    'park-epoll': b'park surface=owned-poll',
    'park-wait': b'park surface=owned-child-wait',
    'park-ignored': b'park surface=owned-poll',
}
# The syscall whose entry the supervisor replaces, and the signal queued there.
INJECTED = {'map-signal': (b'9 ', signal.SIGUSR1), 'exec-signal': (b'59 ', signal.SIGCHLD)}
SLEEPS = ('sleep-peer', 'sleep-ignored', 'sleep-handled')
PSELECT = ('pending-pselect', 'pending-zero-pselect', 'ready-pselect')
CREATION = ('birth-orphan',)
RACES = ('race-thread-exit', 'race-fork-kill')
INTERRUPTED = b'park interrupted surface=pending-signal'


def children(pid):
    return [int(p) for p in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]


def wait_for(condition, proc, audit_path, reason):
    deadline = time.monotonic() + 10
    while not condition():
        assert proc.poll() is None, (reason, audit_path.read_text())
        assert time.monotonic() < deadline, (reason, audit_path.read_text())
        time.sleep(.01)


def stop(pid):
    os.kill(pid, signal.SIGSTOP)
    deadline = time.monotonic() + 10
    while Path(f'/proc/{pid}/stat').read_text().split(') ')[1][0] != 'T':
        assert time.monotonic() < deadline, 'supervisor did not stop'
        time.sleep(.0005)


def orphan_newborn(proc, audit_path):
    """Kill a forking parent while its kernel-created child is unpublished.

    The supervisor is stepped with SIGCONT/SIGSTOP until the kernel shows the
    parent's new child. A child still in its birth stop has not been
    published: the parent is killed there. An attempt the supervisor already
    published is discarded and repeated.
    """
    for _ in range(40):
        assert select.select([proc.stdout], [], [], 10)[0], audit_path.read_text()
        assert proc.stdout.readline() == b'orphan-ready\n', audit_path.read_text()
        init = children(proc.pid)
        assert len(init) == 1, init
        parent = children(init[0])
        assert len(parent) == 1, parent
        stop(proc.pid)
        proc.stdin.write(b'g')
        proc.stdin.flush()
        deadline = time.monotonic() + 10
        stepped = time.monotonic()
        while not children(parent[0]):
            assert time.monotonic() < deadline, ('fork never started', audit_path.read_text()[-2000:])
            if time.monotonic() - stepped > .005:
                os.kill(proc.pid, signal.SIGCONT)
                time.sleep(.00005)
                stop(proc.pid)
                stepped = time.monotonic()
            time.sleep(.0002)
        newborn = children(parent[0])[0]
        # A newborn the supervisor has not resumed still reports the clone.
        unpublished = Path(f'/proc/{newborn}/syscall').read_bytes().startswith(b'56 ')
        if unpublished:
            os.kill(parent[0], signal.SIGKILL)
        os.kill(proc.pid, signal.SIGCONT)
        assert select.select([proc.stdout], [], [], 10)[0], audit_path.read_text()[-2000:]
        line = proc.stdout.readline()
        if not unpublished:
            assert line == b'orphan-published\n', (line, audit_path.read_text()[-2000:])
            proc.stdin.write(b'N')
            proc.stdin.flush()
            continue
        assert line == b'orphan-killed\n', (line, audit_path.read_text()[-2000:])
        # The newborn never ran and nothing names it: it must be gone, not
        # left stopped under the supervisor.
        deadline = time.monotonic() + 5
        while children(proc.pid) != init:
            assert time.monotonic() < deadline, ('unpublished newborn survived', children(proc.pid), init)
            time.sleep(.01)
        return b'D'
    raise AssertionError('supervisor never stopped inside a creation')


def main():
    if len(sys.argv) < 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-signals.py <ginux> <signal-fixture> [scenario ...]')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    scenarios = (*PARKED, *PSELECT, *SLEEPS, *INJECTED, *CREATION, *RACES)
    selected = sys.argv[3:] or scenarios
    if any(mode not in scenarios for mode in selected):
        sys.exit('unknown signal scenario')
    template = (Path(__file__).resolve().parent.parent / 'config/instance-configured.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-signals-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
        for mode in selected:
            path, result, audit_path = work / f'{mode}.toml', work / f'{mode}.json', work / f'{mode}.audit'
            # Creation races need tasks that really run at the same time.
            case = config.replace('vcpus = 1', 'vcpus = 2') if mode in RACES else config
            path.write_text(case.replace('args = []', 'args = ' + json.dumps([mode])))
            with audit_path.open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
                try:
                    sent = None
                    if mode in PARKED:
                        # The child exits only after its parent is parked.
                        wait_for(lambda: PARKED[mode] in audit_path.read_bytes(), proc, audit_path, 'parent did not park')
                        sent = b'G'
                    if mode in INJECTED:
                        entry, queued = INJECTED[mode]
                        assert select.select([proc.stdout], [], [], 10)[0], audit_path.read_text()
                        assert proc.stdout.readline() == b'inject-ready\n', audit_path.read_text()
                        # Stop the supervisor while the task still computes in
                        # user mode, let the task reach the entry stop of the
                        # call, and queue the signal before it is seen.
                        stop(proc.pid)
                        try:
                            tracee = children(proc.pid)
                            assert len(tracee) == 1, tracee
                            state = Path(f'/proc/{tracee[0]}/syscall')
                            # The handshake write may still await its exit stop.
                            deadline = time.monotonic() + 10
                            while state.read_bytes() != b'running\n':
                                assert time.monotonic() < deadline, ('task did not resume', audit_path.read_text()[-2000:])
                                os.kill(proc.pid, signal.SIGCONT)
                                time.sleep(.00005)
                                stop(proc.pid)
                            wait_for(lambda: state.read_bytes().startswith(entry),
                                     proc, audit_path, 'task did not reach the replaced call')
                            os.kill(tracee[0], queued)
                        finally:
                            os.kill(proc.pid, signal.SIGCONT)
                    if mode in CREATION:
                        sent = orphan_newborn(proc, audit_path)
                    stdout, _ = proc.communicate(sent, timeout=180 if mode in RACES else 20)
                    audit_bytes = audit_path.read_bytes()
                    assert proc.returncode == 0 and stdout.endswith(b'held-signals: PASS\n'), \
                        (mode, proc.returncode, stdout, audit_bytes[-4000:])
                    record = json.loads(result.read_text())
                    assert record == {'version': 1, 'outcome': 'exited', 'code': 0, 'signal': None, 'generation': None}, record
                    assert b'teardown tasks=0 owned-handles=0' in audit_bytes
                    if mode in PARKED:
                        # Only a handler hands the parked call back to the kernel.
                        marker = b'mediate surface=pselect-signal-mask' if mode.startswith('park-pselect') else INTERRUPTED
                        assert (marker in audit_bytes) == (mode != 'park-ignored'), (mode, audit_bytes[-4000:])
                    if mode == 'map-signal':
                        assert b'mediate surface=owned-file-mapping' in audit_bytes, audit_bytes[-4000:]
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
            print(f'PASS launch signals: {mode}', flush=True)
    print('test-launch-signals: PASS')


if __name__ == '__main__':
    main()
