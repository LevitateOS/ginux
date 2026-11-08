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
import select
import time


def main():
    if len(sys.argv) < 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-tasks.py <ginux> <task-fixture> [scenario ...]')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    template = (Path(__file__).resolve().parent.parent / 'config/instance-gate5.toml').read_text()
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
        def resource_cases():
            original_affinity = os.sched_getaffinity(0)
            allowed = sorted(original_affinity)[:2]
            assert allowed
            scenarios = [(1, allowed[:1])]
            scenarios.append((3, allowed))
            for vcpus, expected_cpus in scenarios:
                path, result = work / f'resources-{vcpus}.toml', work / f'resources-{vcpus}.json'
                current = config.replace('memory_mib = 256', 'memory_mib = 32')
                current = current.replace('vcpus = 1', f'vcpus = {vcpus}')
                current = current.replace('args = []', 'args = ' + json.dumps(
                    ['Resources', ','.join(str(cpu) for cpu in expected_cpus)]))
                path.write_text(current)
                def restrict_operator_cpus():
                    os.sched_setaffinity(0, allowed)
                proc = subprocess.run([binary, 'launch', str(path), str(root), '--result-file', str(result)],
                                      capture_output=True, timeout=20, preexec_fn=restrict_operator_cpus)
                assert proc.returncode == 0, (proc.returncode, proc.stderr.decode())
                assert proc.stdout == b'owned-tasks: PASS\n', proc.stdout
                assert json.loads(result.read_text()) == {'version': 1, 'outcome': 'exited',
                    'code': 0, 'signal': None, 'generation': None}
                assert b'teardown tasks=0 owned-handles=0' in proc.stderr
                assert os.sched_getaffinity(0) == original_affinity
                print(f'PASS launch resources: vcpus={vcpus}, operator={allowed}, actual={expected_cpus}; fork/exec')
        if not sys.argv[3:] or 'ordinary-resources' in sys.argv[3:]:
            resource_cases()
        modes = ('Z-clocks', 'Umask', 'Locks', 'OrdinaryLocks', 'ExecLocks', 'BoundedTasks', 'qfault', 'fork', 'vfork', 'clone', 'shared-vfork', 'libc-fork', 'junk-child-tid', 'protected-child-tid', 'x-child-tid', 'handler-return', 'inherit', 'kill', 'bound', 'orphan', 'adopted-zombie', 'rollback', 'inherit')
        if sys.argv[3:]:
            allowed=set(modes) | {'OrdinaryLocks', 'ordinary-resources'}
            if any(mode not in allowed for mode in sys.argv[3:]): sys.exit('unknown task selection')
            modes = [mode for mode in sys.argv[3:] if mode != 'ordinary-resources']
        for mode in modes:
            path, result = work / f'{mode}.toml', work / f'{mode}.json'
            path.write_text(config.replace('args = []', 'args = ' + json.dumps([mode])))
            result.unlink(missing_ok=True)
            def inherit_ignored_child_signal():
                signal.signal(signal.SIGCHLD, signal.SIG_IGN)
            command=[binary, 'launch', str(path), str(root), '--result-file', str(result)]
            if mode == 'OrdinaryLocks':
                audit=work/'ordinary-locks.audit'
                with audit.open('wb') as errors:
                    proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors)
                    try:
                        for syscall, owner, ready in ((72,2,b'record-release-ready\n'),(73,3,b'flock-release-ready\n'),(72,4,b'cancel-ready\n')):
                            assert select.select([proc.stdout],[],[],5)[0], 'lock readiness missing'
                            assert proc.stdout.readline()==ready
                            deadline=time.monotonic()+5
                            while not any(f'syscall={syscall} virtual-pid={owner} '.encode() in line and b'action=park' in line for line in audit.read_bytes().splitlines()):
                                assert proc.poll() is None and time.monotonic()<deadline, audit.read_text()
                                time.sleep(.01)
                            proc.stdin.write(b'G'); proc.stdin.flush()
                        stdout,_=proc.communicate(timeout=5)
                    finally:
                        if proc.poll() is None: proc.kill(); proc.communicate(timeout=5)
                proc.stdout,proc.stderr=stdout,audit.read_bytes()
            elif mode == 'adopted-zombie':
                audit=work/'adopted-zombie.audit'
                with audit.open('wb') as errors:
                    proc=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors)
                    try:
                        assert select.select([proc.stdout],[],[],5)[0], 'orphan handshake timed out'
                        assert proc.stdout.readline()==b'zombie-ready\n'
                        deadline=time.monotonic()+5
                        while b'ginux: task exited virtual-pid=3' not in audit.read_bytes():
                            assert proc.poll() is None and time.monotonic()<deadline, audit.read_text()
                            time.sleep(.01)
                        stdout,_=proc.communicate(b'G',timeout=5)
                    finally:
                        if proc.poll() is None:
                            proc.kill();proc.communicate(timeout=5)
                proc.stdout=stdout
                proc.stderr=audit.read_bytes()
            else:
                proc = subprocess.run(command, capture_output=True, timeout=20,
                                      preexec_fn=inherit_ignored_child_signal if mode == 'fork' else None)
            record = json.loads(result.read_text())
            assert proc.returncode == 0, (mode, proc.returncode, proc.stderr.decode(), record)
            assert proc.stdout == b'owned-tasks: PASS\n', (mode, proc.stdout)
            assert record == {'version': 1, 'outcome': 'exited', 'code': 0, 'signal': None, 'generation': None}, record
            assert b'teardown tasks=0 owned-handles=0' in proc.stderr, proc.stderr
            assert not (root / 'work/data').exists()
            print(f'PASS launch tasks: {mode}')
        if sys.argv[3:]: return
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
