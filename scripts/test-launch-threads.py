#!/usr/bin/env python3
"""Exercise actual native threads through configured task and descriptor owners."""
import json
import os
import resource
from pathlib import Path
import select
import signal
import shutil
import subprocess
import sys
import tempfile
import time


def main():
    if len(sys.argv) < 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-threads.py <ginux> <thread-fixture> [scenario ...]')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    scenarios = ('basic', 'musl', 'umask', 'pin', 'limit', 'stress', 'x-path', 'y-mapping', 'k-scratch', 'v-private', 'n-mapping', 'j-leader-map', 'q-fixed', 'w-rollback', 'a-pair-fail', 'fork', 'early', 'rollback', 'tiny', 'teardown')
    selected = sys.argv[3:] or scenarios
    if any(mode not in scenarios for mode in selected):
        sys.exit('unknown thread scenario')
    template = (Path(__file__).resolve().parent.parent / 'config/instance-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-threads-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        (root / 'input').write_bytes(b'abcdef')
        (root / 'allowed').write_bytes(b'A')
        (root / 'work/hh').write_bytes(b'S')
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
        config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ["null"]')
        for mode in (mode for mode in selected if mode != 'teardown'):
            path, result, audit_path = work / f'{mode}.toml', work / f'{mode}.json', work / f'{mode}.audit'
            result.unlink(missing_ok=True)
            path.write_text(config.replace('args = []', 'args = ' + json.dumps([mode])))
            with audit_path.open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
                try:
                    if mode == 'a-pair-fail':
                        assert select.select([proc.stdout], [], [], 5)[0], 'pair fixture did not reach first handshake'
                        assert proc.stdout.readline() == b'pair-ready\n', audit_path.read_text()
                        roots = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                        assert len(roots) == 1, roots
                        tracee = int(roots[0])
                        tracee_fds = Path(f'/proc/{tracee}/fd')
                        before = sorted(int(item.name) for item in tracee_fds.iterdir())
                        previous_limit = resource.prlimit(tracee, resource.RLIMIT_NOFILE)
                        assert max(before) < 5, before
                        resource.prlimit(tracee, resource.RLIMIT_NOFILE, (5, previous_limit[1]))
                        proc.stdin.write(b'A')
                        proc.stdin.flush()
                        assert select.select([proc.stdout], [], [], 5)[0], 'pair fixture did not reach second handshake'
                        assert proc.stdout.readline() == b'pair-failed\n', audit_path.read_text()
                        after = sorted(int(item.name) for item in tracee_fds.iterdir())
                        assert after == before, ('socketpair failure leaked native fds', before, after, audit_path.read_text())
                        resource.prlimit(tracee, resource.RLIMIT_NOFILE, previous_limit)
                        print(f'PAIR failure native fds: {before} -> {after}')
                        assert b'mediate surface=owned-file-mapping' in audit_path.read_bytes(), audit_path.read_text()
                    if mode == 'w-rollback':
                        assert select.select([proc.stdout], [], [], 5)[0], 'rollback fixture did not reach first handshake'
                        assert proc.stdout.readline() == b'before-map\n', audit_path.read_text()
                        roots = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                        assert len(roots) == 1, roots
                        tracee_fds = Path('/proc') / roots[0] / 'fd'
                        before = sorted(int(item.name) for item in tracee_fds.iterdir())
                        proc.stdin.write(b'A')
                        proc.stdin.flush()
                        assert select.select([proc.stdout], [], [], 5)[0], 'rollback fixture did not reach second handshake'
                        assert proc.stdout.readline() == b'after-map\n', audit_path.read_text()
                        after = sorted(int(item.name) for item in tracee_fds.iterdir())
                        assert after == before, ('mapping failure leaked native fds', before, after, audit_path.read_text())
                        print(f'ROLLBACK native fds: {before} -> {after}')
                        assert b'mediate surface=owned-file-mapping' in audit_path.read_bytes(), audit_path.read_text()
                    if mode == 'pin':
                        assert select.select([proc.stdout], [], [], 5)[0], 'thread fixture did not reach handshake'
                        assert proc.stdout.readline() == b'pin-ready\n', audit_path.read_text()
                        deadline = time.monotonic() + 5
                        while b'ginux: park surface=lane-channel fd=5' not in audit_path.read_bytes():
                            assert proc.poll() is None, audit_path.read_text()
                            assert time.monotonic() < deadline, 'read did not acquire its pinned handle'
                            time.sleep(.01)
                    if mode in ('early', 'j-leader-map'):
                        assert select.select([proc.stdout], [], [], 5)[0]
                        assert proc.stdout.readline() == b'leader-ready\n', audit_path.read_text()
                        tasks = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                        assert len(tasks) == 1, tasks
                        leader = Path('/proc') / tasks[0]
                        deadline = time.monotonic() + 5
                        while leader.joinpath('stat').read_text().split(') ')[1][0] != 'Z':
                            assert proc.poll() is None, audit_path.read_text()
                            assert time.monotonic() < deadline, 'leader did not exit while thread remained alive'
                            time.sleep(.01)
                        assert proc.poll() is None, 'instance ended before its remaining thread'
                    stdout, _ = proc.communicate(b'G' if mode in ('pin', 'early', 'j-leader-map', 'w-rollback', 'a-pair-fail') else None, timeout=10)
                    assert proc.returncode == 0 and stdout == b'owned-threads: PASS\n', (mode, proc.returncode, stdout, audit_path.read_text())
                    record = json.loads(result.read_text())
                    assert record == {'version': 1, 'outcome': 'exited', 'code': 0, 'signal': None, 'generation': None}, record
                    assert b'teardown tasks=0 owned-handles=0' in audit_path.read_bytes()
                    if mode in ('limit', 'rollback'):
                        assert audit_path.read_bytes().count(b'creation returns EAGAIN') + audit_path.read_bytes().count(b'creation returned EAGAIN') == 1, audit_path.read_text()
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
            print(f'PASS launch threads: {mode}')
        for failure in ((False, True) if 'teardown' in selected else ()):
            path, result, audit_path = work / f'hold-{failure}.toml', work / f'hold-{failure}.json', work / f'hold-{failure}.audit'
            path.write_text(config.replace('args = []', 'args = ["hold"]'))
            with audit_path.open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                        stdout=subprocess.PIPE, stderr=audit)
                try:
                    assert select.select([proc.stdout], [], [], 5)[0]
                    assert proc.stdout.readline() == b'hold-ready\n', audit_path.read_text()
                    roots = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                    assert len(roots) == 1, roots
                    leader = int(roots[0])
                    deadline = time.monotonic() + 5
                    while b'ginux: park surface=lane-channel fd=5' not in audit_path.read_bytes():
                        assert proc.poll() is None, audit_path.read_text()
                        assert time.monotonic() < deadline
                        time.sleep(.01)
                    tids = [int(p.name) for p in Path(f'/proc/{leader}/task').iterdir()]
                    assert len(tids) == 2, tids
                    os.kill(leader, signal.SIGSTOP if failure else signal.SIGKILL)
                    stdout, _ = proc.communicate(timeout=5)
                    assert not stdout
                    assert proc.returncode == (1 if failure else 137), audit_path.read_text()
                    record = json.loads(result.read_text())
                    assert record['outcome'] == ('supervisor-error' if failure else 'signaled'), record
                    assert all(not Path(f'/proc/{tid}').exists() for tid in tids), tids
                    assert b'teardown tasks=0 owned-handles=0' in audit_path.read_bytes()
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
            print(f'PASS thread group teardown: {"failure" if failure else "signal"}')
    print('test-launch-threads: PASS')


if __name__ == '__main__':
    main()
