#!/usr/bin/env python3
"""Run real configured-launch anonymous pipe checks against existing artifacts."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile
import time


def main():
    if len(sys.argv) < 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-pipes.py <ginux> <pipe-fixture> [modes...]')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    template = (Path(__file__).resolve().parent.parent / 'config/instance-configured.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-pipes-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        counter = 0

        def invoke(args=(), *, assigned=False, sig=None, park=False):
            nonlocal counter
            counter += 1
            config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
            config = config.replace('args = []', 'args = ' + json.dumps(list(args)))
            if assigned:
                config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
                config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ["null"]')
            path, result = work / f'{counter}.toml', work / f'{counter}.json'
            path.write_text(config)
            command = [binary, 'launch', str(path), str(root), '--result-file', str(result)]
            if park:
                audit_path = work / f'{counter}.audit'
                with audit_path.open('wb') as audit:
                    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=audit)
                    child = None
                    try:
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            # Read through a separate open file description;
                            # seeking the inherited stderr would move its writer.
                            if b'ginux: park surface=lane-channel' in audit_path.read_bytes():
                                children = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                                assert len(children) == 1, children
                                child = int(children[0])
                                break
                            assert proc.poll() is None, f'blocking call returned early: {proc.returncode}'
                            time.sleep(0.01)
                        assert child is not None, 'blocking pipe operation did not park'
                        os.kill(child, signal.SIGKILL)
                        stdout, _ = proc.communicate(timeout=5)
                        assert not Path(f'/proc/{child}').exists(), 'terminated workload was not reaped'
                    finally:
                        if proc.poll() is None:
                            proc.kill()
                            proc.communicate(timeout=5)
            else:
                proc = subprocess.run(command, capture_output=True, timeout=20)
                stdout = proc.stdout
                assert proc.returncode == (128 + sig if sig else 0), (proc.returncode, proc.stderr)
            record = json.loads(result.read_text())
            if sig:
                assert proc.returncode == 128 + sig, (proc.returncode, record)
                assert record['outcome'] == 'signaled' and record['signal'] == sig, record
            else:
                assert record['outcome'] == 'exited' and record['code'] == 0, record
                assert stdout == b'owned-pipes: PASS\n', stdout
            assert record['generation'] is None

        if sys.argv[3:]:
            modes=('ordinary-packet','ordinary-fionbio','ordinary-streams','ordinary-vectors','ordinary-blocking-large')
            for mode in sys.argv[3:]:
                if mode not in modes:sys.exit('unknown ordinary pipe mode')
                invoke(['vectors'] if mode=='ordinary-vectors' else [mode],assigned=True)
            print('test-launch-pipes: PASS ('+', '.join(sys.argv[3:])+')')
            return
        invoke(['ordinary-blocking-large'], assigned=True)
        invoke(['vectors'])
        invoke()
        invoke(assigned=True)
        invoke(["packet"], assigned=True)
        invoke(['sigpipe'], sig=signal.SIGPIPE)
        invoke(['blocked-read'], sig=signal.SIGKILL, park=True)
        invoke(['write-full'], sig=signal.SIGKILL, park=True)
        invoke()  # Fresh launch: no live pipe state or buffered bytes.
        print('test-launch-pipes: PASS (data, atomicity, copyout, aliases, EOF, bounds, blocking, SIGPIPE)')


if __name__ == '__main__':
    main()
