#!/usr/bin/env python3
"""Check real exec replacement and CLOEXEC across descriptor owners and fork."""
import json
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
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-exec.py <ginux> <exec-fixture>')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / 'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-exec-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        for path in ('bin/fixture', 'bin/second', 'noexec', 'work/hidden'):
            shutil.copyfile(fixture, root / path)
            (root / path).chmod(0o644 if path == 'noexec' else 0o755)
        (root / 'bin/link').symlink_to('/bin/second')
        (root / 'malformed').write_bytes(b'not an executable\n')
        (root / 'malformed').chmod(0o755)
        (root / 'input').write_bytes(b'abcdef')
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
        config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ["null"]')
        for mode in ('success', 'bad', 'child', 'descriptor', 'path', 'relative', 'link'):
            path, result, audit_path = work / f'{mode}.toml', work / f'{mode}.json', work / f'{mode}.audit'
            path.write_text(config.replace('args = []', 'args = ' + json.dumps([mode])))
            with audit_path.open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
                try:
                    assert select.select([proc.stdout], [], [], 5)[0], 'exec did not reach ready handshake'
                    ready = proc.stdout.readline()
                    assert ready == b'after-ready\n', (mode, ready, audit_path.read_text())
                    tasks = children(proc.pid)
                    assert len(tasks) == 1, tasks
                    target = tasks[0]
                    if mode == 'child':
                        descendants = children(target)
                        assert len(descendants) == 1, descendants
                        target = descendants[0]
                    # The all-CLOEXEC image fd is gone in the kernel. A mixed
                    # alias keeps only its single native handle, number 3.
                    native_fds = sorted(int(p.name) for p in Path(f'/proc/{target}/fd').iterdir())
                    assert native_fds == [0, 1, 2, 3], (mode, native_fds)
                    stdout, _ = proc.communicate(b'G', timeout=5)
                    expected = b'exec: PASS\n' + (b'parent: PASS\n' if mode == 'child' else b'')
                    assert proc.returncode == 0 and stdout == expected, (mode, proc.returncode, stdout, audit_path.read_text())
                    record = json.loads(result.read_text())
                    assert record == {'version': 1, 'outcome': 'exited', 'code': 0, 'signal': None, 'generation': None}, record
                    diagnostics = audit_path.read_bytes()
                    assert diagnostics.count(b'ginux: task exec virtual-pid=') == 2, diagnostics
                    assert b'teardown tasks=0 owned-handles=0' in diagnostics
                    assert not Path(f'/proc/{target}').exists(), 'executed task was not reaped'
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
            print(f'PASS launch exec: {mode}')
    print('test-launch-exec: PASS')


if __name__ == '__main__':
    main()
