#!/usr/bin/env python3
"""Consume built launch/payload artifacts to check owned ELF replacement."""
import json
import fcntl
import os
from pathlib import Path
import select
import shutil
import subprocess
import sys
import tempfile


def children(pid):
    return [int(p) for p in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]


def main():
    if len(sys.argv) < 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-owned-exec.py <ginux> <owned-exec-fixture> [scenario ...]')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    template = (Path(__file__).resolve().parent.parent / 'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-owned-exec-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        for name in ('fixture', 'payload'):
            shutil.copyfile(fixture, root / 'bin' / name)
            (root / 'bin' / name).chmod(0o755)
        (root / 'input').write_bytes(b'Q')
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
        ordinary = ('ordinary-path', 'ordinary-fd', 'ordinary-unlinked', 'ordinary-relative', 'ordinary-child', 'ordinary-reexec', 'ordinary-hardlinked', 'ordinary-fd-hardlinked')
        full = ('success', 'descriptor', 'unlinked', 'relative', 'child', 'vfork', 'mixed-clone')
        for mode in (sys.argv[3:] or (*full, *ordinary)):
            if mode not in (*full, *ordinary):
                sys.exit('unknown owned exec scenario')
            path, result, audit_path = [work / (mode + suffix) for suffix in ('.toml', '.json', '.audit')]
            path.write_text(config.replace('args = []', 'args = ' + json.dumps([mode])))
            if mode in ordinary:
                proc = subprocess.run([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                      capture_output=True, timeout=15)
                audit_path.write_bytes(proc.stderr)
                expected = b'owned-ordinary: PASS\n' * (2 if mode == 'ordinary-child' else 1)
                assert proc.returncode == 0 and proc.stdout == expected, (mode, proc.returncode, proc.stdout, proc.stderr)
                assert json.loads(result.read_text()) == dict(version=1, outcome='exited', code=0, signal=None, generation=None)
                assert b'teardown tasks=0 owned-handles=0' in proc.stderr
                assert list((root / 'work').iterdir()) == []
                assert (root / 'input').read_bytes() == b'Q'
                print('PASS owned exec ' + mode, flush=True)
                continue
            with audit_path.open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
                try:
                    assert select.select([proc.stdout], [], [], 10)[0], ('failed-exec checks stalled', mode, audit_path.read_text())
                    ready = proc.stdout.readline()
                    assert ready == b'failed-ready\n', (mode, ready, audit_path.read_text())
                    roots = children(proc.pid)
                    assert len(roots) == 1, roots
                    initial = roots[0]
                    fds = sorted(int(p.name) for p in Path(f'/proc/{initial}/fd').iterdir())
                    assert fds == [0, 1, 2, 3], ('failed exec leaked private descriptors', mode, fds)
                    proc.stdin.write(b'G'); proc.stdin.flush()
                    assert select.select([proc.stdout], [], [], 10)[0], ('owned exec stalled', mode, audit_path.read_text())
                    ready = proc.stdout.readline()
                    assert ready == b'owned-ready\n', (mode, ready, audit_path.read_text())
                    target = initial
                    if mode in ('child', 'vfork', 'mixed-clone'):
                        descendants = children(initial)
                        assert len(descendants) == 1, descendants
                        target = descendants[0]
                    fds = sorted(int(p.name) for p in Path(f'/proc/{target}/fd').iterdir())
                    assert fds == [0, 1, 2, 3], ('successful exec leaked private descriptors', mode, fds)
                    with open(f'/proc/{target}/exe', 'rb') as executable:
                        assert executable.read() == Path(fixture).read_bytes(), 'executed bytes differ from the owned ELF'
                        seals = fcntl.fcntl(executable.fileno(), 1034)
                        assert seals & 0xf == 0xf, ('execution backing is not sealed', seals)
                        assert os.fstat(executable.fileno()).st_mode & 0o777 == 0o500
                    stdout, _ = proc.communicate(b'G', timeout=10)
                    expected = b'owned-exec: PASS\n' + (b'owned-parent: PASS\n' if mode in ('child', 'vfork', 'mixed-clone') else b'')
                    assert proc.returncode == 0 and stdout == expected, (mode, proc.returncode, stdout, audit_path.read_text())
                    record = json.loads(result.read_text())
                    assert record == dict(version=1, outcome='exited', code=0, signal=None, generation=None), record
                    assert b'teardown tasks=0 owned-handles=0' in audit_path.read_bytes()
                    assert not Path(f'/proc/{target}').exists() and not Path(f'/proc/{initial}').exists()
                    assert list((root / 'work').iterdir()) == [], 'owned bytes reached the host tree'
                    assert (root / 'input').read_bytes() == b'Q'
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
            print('PASS owned exec ' + mode, flush=True)
        for mode in (() if sys.argv[3:] else ('interpreter', 'joined-interpreters', 'kernel-interpreter', 'limit-interpreters')):
            path = work / f'{mode}.toml'
            path.write_text(config.replace('args = []', 'args = ' + json.dumps([mode])))
            with (work / f'{mode}.audit').open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(path), str(root)],
                    stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
                try:
                    assert select.select([proc.stdout], [], [], 10)[0], mode
                    assert proc.stdout.readline() == b'script-ready\n', (mode, (work / f'{mode}.audit').read_text())
                    target, = children(proc.pid)
                    assert sorted(int(p.name) for p in Path(f'/proc/{target}/fd').iterdir()) == [0, 1, 2]
                    stdout, _ = proc.communicate(b'G', timeout=10)
                    assert proc.returncode == 0 and stdout == b'script-chain: PASS\n', (mode, proc.returncode, stdout)
                    assert b'teardown tasks=0 owned-handles=0' in (work / f'{mode}.audit').read_bytes()
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
            print('PASS script chain ' + mode, flush=True)
        print('test-launch-owned-exec: PASS (' + (', '.join(sys.argv[3:]) if sys.argv[3:] else 'full scenarios') + ')')


if __name__ == '__main__':
    main()
