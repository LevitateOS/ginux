#!/usr/bin/env python3
"""Consume a built launcher/fixture to exercise public-descriptor readiness."""
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
        sys.exit('usage (as root): test-launch-poll.py <ginux> <poll-fixture>')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    template = (Path(__file__).resolve().parent.parent / 'config/instance-configured.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-poll-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        selected = sys.argv[3:]
        if selected and any(mode not in ('ordinary', 'read', 'write', 'hup', 'ordinary-timer', 'select', 'Splice', 'Denied', 'LargeConsole', 'ConsoleDenied') for mode in selected):
            sys.exit('unknown selected poll scenario')
        for mode in selected or ('all', 'read', 'write', 'hup', 'deadline', 'timer', 'console', 'kill', 'infinite-kill', 'all-again', 'ordinary', 'ordinary-timer', 'select', 'Splice', 'Denied', 'LargeConsole', 'ConsoleDenied'):
            config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
            config = config.replace('args = []', 'args = ' + json.dumps([mode]))
            config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
            config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ["null"]')
            if mode == 'Denied':
                config = config.replace('deny = ["device.mmio.direct"', 'deny = ["syscall.pselect6", "syscall.splice", "device.mmio.direct"', 1)
            if mode == 'ConsoleDenied':
                config = config.replace('deny = ["device.mmio.direct"', 'deny = ["device.console.write", "device.mmio.direct"', 1)
            path, result, audit_path = [work / (mode + suffix) for suffix in ('.toml', '.json', '.audit')]
            path.write_text(config)
            start = time.monotonic()
            child = None
            with audit_path.open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
                try:
                    if mode in ('console', 'kill', 'infinite-kill'):
                        deadline = time.monotonic() + 5
                        while time.monotonic() < deadline:
                            if b'park surface=owned-poll' in audit_path.read_bytes():
                                children = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                                assert len(children) == 1, children
                                child = int(children[0])
                                break
                            assert proc.poll() is None, (proc.returncode, audit_path.read_bytes())
                            time.sleep(0.005)
                        assert child is not None, 'readiness query did not park'
                        if mode.endswith('kill'):
                            os.kill(child, signal.SIGKILL)
                        else:
                            proc.stdin.write(b'C')
                            proc.stdin.flush()
                    stdout, _ = proc.communicate(timeout=10)
                finally:
                    if proc.poll() is None:
                        # Kill the actual workload first so the supervisor
                        # observes its death and performs normal instance teardown.
                        for pid in Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split():
                            os.kill(int(pid), signal.SIGKILL)
                        proc.communicate(timeout=5)
            elapsed = time.monotonic() - start
            record = json.loads(result.read_text())
            audit = audit_path.read_bytes()
            assert b'ginux: teardown tasks=0 owned-handles=0' in audit, audit
            if mode.endswith('kill'):
                assert proc.returncode == 137 and record['outcome'] == 'signaled' and record['signal'] == 9, (proc.returncode, record, audit)
                assert not Path(f'/proc/{child}').exists(), 'parked task survived teardown'
                assert stdout == b'', stdout
            else:
                assert proc.returncode == 0 and record['outcome'] == 'exited' and record['code'] == 0, (mode, proc.returncode, record, audit)
                expected = b'owned-poll: PASS\n'
                if mode == 'LargeConsole':
                    expected = bytes(65 + i % 26 for i in range(10003)) + expected
                elif mode == 'ConsoleDenied':
                    expected = b''
                assert stdout == expected, stdout
            if mode in ('timer', 'ordinary-timer', 'select'):
                assert elapsed >= 0.055, ('finite wait returned early', elapsed)
            assert elapsed < 5, ('readiness/deadline stalled', mode, elapsed)
            assert record['generation'] is None, record
            assert not (root / 'work/data').exists(), 'owned data escaped into host tree'
            print('PASS poll ' + mode, flush=True)
        print('test-launch-poll: PASS (selected ordinary scenarios)' if selected else
              'test-launch-poll: PASS (masks, aliases, mixed console, faults, EOF, peer wakeups, timers, teardown)')


if __name__ == '__main__':
    main()
