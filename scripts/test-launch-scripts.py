#!/usr/bin/env python3
"""Consume built artifacts to verify named owned scripts and exec rollback."""
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
    if len(sys.argv) < 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-scripts.py <ginux> <script-fixture> [scenario ...]')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    template = (Path(__file__).resolve().parent.parent / 'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-scripts-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        for name in ('fixture', 'interpreter'):
            shutil.copyfile(fixture, root / 'bin' / name)
            (root / 'bin' / name).chmod(0o755)
        (root / 'bin/wrapper').write_text('#!/bin/interpreter nested option\n')
        (root / 'bin/wrapper').chmod(0o755)
        (root / 'input').write_bytes(b'Q')
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"\nworkdir = "/"')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
        fork_modes = ('fork', 'vfork', 'clone', 'fd-fork', 'fd-vfork')
        full_modes = ('plain', 'optional', 'nested', 'relative', 'at', 'fork', 'vfork', 'clone', 'many',
                     'descriptor', 'unlinked', 'dir-relative', 'dir-renamed', 'fd-fork', 'fd-vfork')
        ordinary_modes = ('ordinary-plain', 'ordinary-option', 'ordinary-nested', 'ordinary-relative',
                          'ordinary-at', 'ordinary-fd', 'ordinary-unlinked', 'ordinary-dir',
                          'ordinary-renamed', 'ordinary-fork', 'ordinary-vfork', 'ordinary-owned', 'ordinary-chain', 'ordinary-joined', 'ordinary-script-link', 'ordinary-interpreter-link', 'ordinary-cross', 'ordinary-cross-nested', 'ordinary-cross-relative', 'ordinary-cross-cwd', 'ordinary-cross-plain')
        modes = sys.argv[3:] or (*full_modes, *ordinary_modes)
        assert set(modes) <= set(full_modes + ordinary_modes), modes
        for mode in modes:
            path, result, audit_path = [work / (mode + suffix) for suffix in ('.toml', '.json', '.audit')]
            path.write_text(config.replace('args = []', 'args = ' + json.dumps([mode])))
            if mode in ordinary_modes:
                with audit_path.open('wb') as audit:
                    proc = subprocess.run([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                          input=b'', stdout=subprocess.PIPE, stderr=audit, timeout=15)
                expected = b'script: PASS\n' + (b'parent: PASS\n' if mode in ('ordinary-fork', 'ordinary-vfork') else b'')
                assert proc.returncode == 0 and proc.stdout == expected, (mode, proc.returncode, proc.stdout, audit_path.read_text())
                assert json.loads(result.read_text()) == dict(version=1, outcome='exited', code=0, signal=None, generation=None)
                assert b'teardown tasks=0 owned-handles=0' in audit_path.read_bytes()
                assert list((root / 'work').iterdir()) == [] and (root / 'input').read_bytes() == b'Q'
                print('PASS owned script ' + mode, flush=True)
                continue
            with audit_path.open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
                try:
                    assert select.select([proc.stdout], [], [], 10)[0], (mode, 'rollback stalled', audit_path.read_text())
                    assert proc.stdout.readline() == b'failed-ready\n', (mode, audit_path.read_text())
                    roots = children(proc.pid)
                    assert len(roots) == 1, roots
                    initial = roots[0]
                    assert sorted(int(p.name) for p in Path(f'/proc/{initial}/fd').iterdir()) == [0, 1, 2, 3]
                    proc.stdin.write(b'G'); proc.stdin.flush()
                    assert select.select([proc.stdout], [], [], 10)[0], (mode, 'script exec stalled', audit_path.read_text())
                    assert proc.stdout.readline() == b'script-ready\n', (mode, audit_path.read_text())
                    target = initial
                    if mode in fork_modes:
                        descendants = children(initial)
                        assert len(descendants) == 1, descendants
                        target = descendants[0]
                    assert sorted(int(p.name) for p in Path(f'/proc/{target}/fd').iterdir()) == [0, 1, 2], ('private fd leaked', mode)
                    assert Path(f'/proc/{target}/exe').read_bytes() == Path(fixture).read_bytes()
                    stdout, _ = proc.communicate(b'G', timeout=10)
                    expected = b'script: PASS\n' + (b'parent: PASS\n' if mode in fork_modes else b'')
                    assert proc.returncode == 0 and stdout == expected, (mode, proc.returncode, stdout, audit_path.read_text())
                    record = json.loads(result.read_text())
                    assert record == dict(version=1, outcome='exited', code=0, signal=None, generation=None), record
                    assert b'teardown tasks=0 owned-handles=0' in audit_path.read_bytes()
                    assert not Path(f'/proc/{target}').exists() and not Path(f'/proc/{initial}').exists()
                    assert list((root / 'work').iterdir()) == []
                    assert (root / 'input').read_bytes() == b'Q'
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
            print('PASS owned script ' + mode, flush=True)
        print('test-launch-scripts: PASS (' + ', '.join(modes) + ')')


if __name__ == '__main__':
    main()
