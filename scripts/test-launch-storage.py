#!/usr/bin/env python3
"""Real configured-launch storage checks against explicit existing binaries."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-storage.py <ginux> <storage-fixture>')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / 'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-storage-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        (root / 'work/existing').write_bytes(b'hidden immutable work file')
        (root / 'image').write_bytes(b'immutable image')
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)

        def invoke(assignments, args, expected=0):
            config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
            config = config.replace('args = []', 'args = ' + json.dumps(args))
            config = config.replace('assignments = []', 'assignments = ' + json.dumps(assignments), 1)
            config = config.replace('id = "gate5-demo"', 'id = "storage-fixture"\nworkdir = "/work"')
            path = work / 'launch.toml'
            path.write_text(config)
            result = work / 'result.json'
            result.unlink(missing_ok=True)
            proc = subprocess.run([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                  capture_output=True, timeout=20)
            record = json.loads(result.read_text())
            if proc.returncode != expected:
                sys.exit(f'launch failed: {proc.returncode}\n{proc.stderr.decode()}\n{record}')
            assert record['outcome'] == ('exited' if expected == 0 else 'supervisor-error'), record
            if expected == 0:
                assert record['code'] == 0 and record['generation'] is None, record
                assert proc.stdout == (b'' if args else b'memory-storage: PASS\n'), proc.stdout
            assert (root / 'image').read_bytes() == b'immutable image'
            assert (root / 'work/existing').read_bytes() == b'hidden immutable work file'
            assert sorted(p.name for p in (root / 'work').iterdir()) == ['existing']
            assert not (root / 'out').exists()

        for _ in range(2):
            invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], [])
        invoke(['memory:/work', 'memory:/work/build', 'memory:/out'], ['quota'])
        invoke([], ['no-storage'])
        for assignment in ['disk0', 'memory:/', 'memory:/proc', 'memory:/sys/x', 'memory:/dev',
                           'memory:/bin', 'memory:/work/../out', 'memory:/work/', 'memory:work']:
            invoke([assignment], [], 2)
        invoke(['memory:/work', 'memory:/work'], [], 2)
        print('test-launch-storage: PASS (isolation, data, metadata, copy protections, bounds, fresh launch)')


if __name__ == '__main__':
    main()
