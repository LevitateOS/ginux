#!/usr/bin/env python3
"""Real configured-launch device ownership checks using explicit built artifacts."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-devices.py <ginux> <device-fixture>')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / 'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-devices-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        (root / 'dev').mkdir()
        (root / 'alias-null').symlink_to('/dev/null')
        (root / 'alias-dev').symlink_to('/dev')
        for name in ['null', 'image-device']:
            (root / 'dev' / name).write_bytes(b'image device bytes must stay untouched')
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        counter = 0

        def invoke(devices, storage=False, expected=0):
            nonlocal counter
            counter += 1
            config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
            config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ' + json.dumps(devices))
            if not devices:
                config = config.replace('args = []', 'args = ["none"]')
            if storage:
                config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
            path = work / f'{counter}.toml'
            path.write_text(config)
            result = work / f'{counter}.json'
            proc = subprocess.run([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                  capture_output=True, timeout=20)
            record = json.loads(result.read_text())
            assert proc.returncode == expected, (proc.returncode, proc.stderr, record)
            assert record['outcome'] == ('exited' if expected == 0 else 'supervisor-error'), record
            if expected == 0:
                assert record['code'] == 0 and record['generation'] is None, record
                assert proc.stdout == (b'null-device: PASS\n' if devices else b''), proc.stdout
            for name in ['null', 'image-device']:
                assert (root / 'dev' / name).read_bytes() == b'image device bytes must stay untouched'

        invoke([])
        invoke(['null'])
        invoke(['null'], storage=True)
        invoke(['null'])  # No descriptors survive a fresh supervisor.
        for devices in [['zero'], ['null', 'null'], ['null', 'console'], ['disk0']]:
            invoke(devices, expected=2)
        print('test-launch-devices: PASS (assignment, IO, metadata, bounds, isolation)')


if __name__ == '__main__':
    main()
