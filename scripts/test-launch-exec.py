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
    if len(sys.argv) != 5 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-exec.py <ginux> <exec-fixture> <interpreter-fixture> <allowed-interpreter-fixture>')
    binary, fixture, interpreter, allowed_interpreter = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / 'config/instance-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-exec-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        for path in ('bin/fixture', 'bin/second', 'noexec', 'work/hidden'):
            shutil.copyfile(fixture, root / path)
            (root / path).chmod(0o644 if path == 'noexec' else 0o755)
        (root / 'bin/link').symlink_to('/bin/second')
        (root / 'owned-link').symlink_to('/work/hidden')
        (root / 'work/nested').mkdir()
        (root / 'virtual').symlink_to('/work/nested')
        shutil.copyfile(fixture, root / 'hidden')
        (root / 'hidden').chmod(0o755)
        shutil.copyfile(interpreter, root / 'image-elf')
        (root / 'image-elf').chmod(0o755)
        shutil.copyfile(allowed_interpreter, root / 'allowed-elf')
        (root / 'allowed-elf').chmod(0o755)
        for name, target in [('image-script', '/work/hidden'), ('allowed-script', '/bin/second'),
                             ('link-script', '/owned-link'), ('mixed-script', '/virtual/../hidden')]:
            (root / name).write_text('#!' + target + '\n')
            (root / name).chmod(0o755)
        (root / 'malformed').write_bytes(b'not an executable\n')
        (root / 'malformed').chmod(0o755)
        (root / 'input').write_bytes(b'abcdef')
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work", "memory:/virtual"]')
        config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ["null"]')
        for initial, mode, expected in [('/bin/fixture', 'u-guards', 0),
                                        ('/image-script', '', 1), ('/image-elf', '', 1),
                                        ('/allowed-script', '', 77), ('/allowed-elf', '/allowed-elf', 77)]:
            label=initial.strip('/').replace('/', '-') + '-' + (mode or 'initial').replace('/', '-')
            path, result = work / (label+'.toml'), work / (label+'.json')
            text=config.replace('init = "/bin/fixture"', 'init = '+json.dumps(initial))
            text=text.replace('args = []', 'args = '+json.dumps([mode] if mode else []))
            path.write_text(text)
            proc=subprocess.run([binary,'launch',str(path),str(root),'--result-file',str(result)],capture_output=True,timeout=20)
            record=json.loads(result.read_text())
            assert proc.returncode==expected, (label,proc.returncode,proc.stderr,record)
            assert record['outcome']==('supervisor-error' if expected==1 else 'exited'),record
            assert proc.stdout==(b'interpreter-guards: PASS\n' if mode=='u-guards' else b''),proc.stdout
            if expected!=1: assert record['code']==expected,record
            print('PASS interpreter ownership:',label)
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
        # A forked writer shares the pathname page but has a separate thread group.
        # The image path under memory:/work must not become a kernel exec target.
        (root / 'work/hidden').write_text('#!/bin/fixture X\n')
        (root / 'work/hidden').chmod(0o755)
        path, result = work / 'shared-path.toml', work / 'shared-path.json'
        path.write_text(config.replace('args = []', 'args = ["S"]'))
        proc = subprocess.run([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                              capture_output=True, timeout=20)
        record = json.loads(result.read_text())
        assert proc.returncode == 0 and proc.stdout == b'shared-exec: PASS\n', (proc.returncode, proc.stdout, proc.stderr[-4096:], record)
        assert record == dict(version=1, outcome='exited', code=0, signal=None, generation=None), record
        assert b'teardown tasks=0 owned-handles=0' in proc.stderr, proc.stderr
        print('PASS launch exec: shared-path')
    print('test-launch-exec: PASS')


if __name__ == '__main__':
    main()
