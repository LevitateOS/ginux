#!/usr/bin/env python3
"""Exercise actual configured children, owned FD inheritance and complete teardown."""
import json
import os
from pathlib import Path
import shutil
import signal
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-tasks.py <ginux> <task-fixture>')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent / 'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-tasks-') as directory:
        work = Path(directory)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        (root / 'input').write_bytes(b'abcdef')
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
        config = config.replace('[devices]\nassignments = []', '[devices]\nassignments = ["null"]')
        for mode in ('fork', 'vfork', 'clone', 'shared-vfork', 'libc-fork', 'junk-child-tid', 'protected-child-tid', 'handler-return',
                     'inherit', 'kill', 'bound', 'orphan', 'rollback', 'inherit'):
            path, result = work / f'{mode}.toml', work / f'{mode}.json'
            path.write_text(config.replace('args = []', 'args = ' + json.dumps([mode])))
            result.unlink(missing_ok=True)
            def inherit_ignored_child_signal():
                signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            proc = subprocess.run([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                  capture_output=True, timeout=20,
                                  preexec_fn=inherit_ignored_child_signal if mode == 'fork' else None)
            record = json.loads(result.read_text())
            assert proc.returncode == 0, (mode, proc.returncode, proc.stderr.decode(), record)
            assert proc.stdout == b'owned-tasks: PASS\n', (mode, proc.stdout)
            assert record == {'version': 1, 'outcome': 'exited', 'code': 0, 'signal': None, 'generation': None}, record
            assert b'teardown tasks=0 owned-handles=0' in proc.stderr, proc.stderr
            assert not (root / 'work/data').exists()
            print(f'PASS launch tasks: {mode}')
        # No descendant may survive root death or a supervisor failure.
        for failure in (False, True):
            path, result = work / f'teardown-{failure}.toml', work / f'teardown-{failure}.json'
            path.write_text(config.replace('args = []', 'args = ["teardown"]'))
            # Use a file so audit backpressure cannot prevent the ready handshake.
            with (work / f'teardown-{failure}.audit').open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                        stdout=subprocess.PIPE, stderr=audit)
                observed = []
                try:
                    import select
                    assert select.select([proc.stdout], [], [], 5)[0], 'descendants did not start'
                    assert proc.stdout.readline() == b'ready\n'
                    def children(pid):
                        return [int(p) for p in Path(f'/proc/{pid}/task/{pid}/children').read_text().split()]
                    observed = children(proc.pid)
                    assert len(observed) == 1, observed
                    root_pid = observed[0]
                    observed += children(root_pid)
                    assert len(observed) == 2, observed
                    observed += children(observed[1])
                    assert len(observed) == 3, observed
                    os.kill(root_pid, signal.SIGSTOP if failure else signal.SIGKILL)
                    stdout, _ = proc.communicate(timeout=5)
                    assert not stdout
                    assert proc.returncode == (1 if failure else 137), proc.returncode
                    assert json.loads(result.read_text())['outcome'] == ('supervisor-error' if failure else 'signaled')
                    assert all(not Path(f'/proc/{pid}').exists() for pid in observed), observed
                finally:
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
            print(f'PASS full descendant teardown: {"failure" if failure else "root signal"}')
    print('test-launch-tasks: PASS')


if __name__ == '__main__':
    main()
