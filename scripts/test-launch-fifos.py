#!/usr/bin/env python3
"""Check real named FIFOs, blocking opens, and namespace snapshot roundtrips."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tarfile
import tempfile
import time


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-fifos.py <ginux> <fifo-fixture>')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / 'config/instance-configured.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-fifos-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        for mode in ['metadata', 'blocking']:
            native = work / ('native-' + mode)
            native.mkdir()
            result = subprocess.run([fixture, str(native), mode], capture_output=True, timeout=20)
            assert result.returncode == 0, ('native', mode, result.returncode, result.stderr)
        snapshot = work / 'snapshot.tar'
        for mode in ['metadata', 'restore', 'blocking', 'shared', 'interrupt', 'pr', 'pw']:
            config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
            config = config.replace('args = []', 'args = ' + json.dumps(['/work', mode]))
            config = config.replace('[storage]\nassignments = []',
                                    '[storage]\nassignments = ["memory:/work"]')
            path, record = work / (mode + '.toml'), work / (mode + '.json')
            path.write_text(config)
            command = [binary, 'launch', str(path), str(root), '--result-file', str(record)]
            if mode == 'metadata':
                command += ['--export-file', str(snapshot)]
            if mode == 'restore':
                command += ['--restore-file', str(snapshot)]
            if mode.startswith('p') or mode in ['shared', 'interrupt']:
                audit_path = work / (mode + '.log')
                with audit_path.open('wb') as audit:
                    process = subprocess.Popen(command, stdin=subprocess.PIPE,
                                               stdout=subprocess.PIPE, stderr=audit)
                    try:
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            if b'park surface=lane-channel' in audit_path.read_bytes():
                                children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
                                assert len(children) == 1, children
                                if mode in ['shared', 'interrupt']:
                                    process.stdin.write(b'x')
                                    process.stdin.flush()
                                else:
                                    os.kill(int(children[0]), signal.SIGKILL)
                                break
                            assert process.poll() is None, (mode, audit_path.read_text())
                            time.sleep(0.01)
                        else:
                            raise AssertionError('FIFO open did not block')
                        stdout, _ = process.communicate(timeout=5)
                        expected = 128 + signal.SIGKILL if mode.startswith('p') else 0
                        assert process.returncode == expected, (mode, process.returncode, audit_path.read_text()[-10000:])
                        if not mode.startswith('p'):
                            assert stdout == b'owned-fifos: PASS\n', stdout
                    finally:
                        if process.poll() is None:
                            process.kill()
                            process.communicate(timeout=5)
                completion = json.loads(record.read_text())
                if not mode.startswith('p'):
                    assert completion['outcome'] == 'exited' and completion['code'] == 0, completion
                else:
                    assert completion['outcome'] == 'signaled' and completion['signal'] == signal.SIGKILL
            else:
                result = subprocess.run(command, capture_output=True, timeout=30)
                assert result.returncode == 0, (mode, result.returncode, result.stderr[-10000:])
                assert result.stdout == b'owned-fifos: PASS\n', result.stdout
                completion = json.loads(record.read_text())
                assert completion['outcome'] == 'exited' and completion['code'] == 0, completion
            if mode == 'metadata':
                with tarfile.open(snapshot) as archive:
                    members = [archive.getmember('work/' + name) for name in ['fifo', 'snapshot-link']]
                    assert sum(member.isfifo() for member in members) == 1, members
                    assert sum(member.islnk() for member in members) == 1, members
        print('test-launch-fifos: PASS (native oracle, metadata, aliases, rendezvous, cancellation, snapshots)')


if __name__ == '__main__':
    main()
