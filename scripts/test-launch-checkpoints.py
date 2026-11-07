#!/usr/bin/env python3
"""Exercise private snapshot control against a real configured workload."""
import json
import os
from pathlib import Path
import select
import shutil
import signal
import time
import socket
import struct
import subprocess
import sys
import tarfile
import tempfile


def receive(sock, count):
    data = bytearray()
    while len(data) < count:
        chunk = sock.recv(count - len(data))
        assert chunk, 'control socket closed before acknowledgement'
        data.extend(chunk)
    return bytes(data)


def main():
    if len(sys.argv) not in (3,4) or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-checkpoints.py <ginux> <storage-fixture> [ordinary]')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:3]]
    ordinary = len(sys.argv)==4
    if ordinary and sys.argv[3]!='ordinary': sys.exit('unknown checkpoint selection')
    template = (Path(__file__).resolve().parent.parent / 'config/instance-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-checkpoints-') as folder:
        work = Path(folder)
        root = work / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
        config = config.replace('args = []', 'args = ["checkpoint"]')
        config = config.replace('[storage]\nassignments = []', '[storage]\nassignments = ["memory:/work"]')
        config_path = work / 'config.toml'
        config_path.write_text(config)
        for failure in ((None,) if ordinary else (None, 'replay', 'existing')):
            client, server = socket.socketpair()
            client.settimeout(5)
            result = work / f'result-{failure}.json'
            final = work / f'final-{failure}.tar'
            with (work / f'audit-{failure}').open('wb') as audit:
                proc = subprocess.Popen([binary, 'launch', str(config_path), str(root),
                    '--result-file', str(result), '--export-file', str(final), '--control-fd', str(server.fileno())],
                    pass_fds=(server.fileno(),), stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=audit)
                server.close()
                try:
                    for sequence, expected in ((1, b'first'), (2, b'second')):
                        assert select.select([proc.stdout], [], [], 5)[0]
                        assert proc.stdout.readline() == b'checkpoint-ready\n'
                        if not ordinary:
                            children = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                            assert len(children) == 1
                            assert sorted(p.name for p in Path(f'/proc/{children[0]}/fd').iterdir()) == ['0', '1', '2']
                        archive = work / f'snapshot-{failure}-{sequence}.tar'
                        if sequence == 2 and failure == 'existing':
                            archive.write_bytes(b'preserve')
                        request_id = 1 if sequence == 2 and failure == 'replay' else sequence
                        path = os.fsencode(archive)
                        frame = b'GXS1' + struct.pack('<QH', request_id, len(path)) + path
                        client.sendall(frame[:5])
                        assert not select.select([client], [], [], .02)[0], 'partial request acknowledged'
                        client.sendall(frame[5:])
                        if sequence == 2 and failure:
                            stdout, _ = proc.communicate(timeout=5)
                            assert proc.returncode == 1 and not stdout
                            assert json.loads(result.read_text())['outcome'] == 'supervisor-error'
                            if failure == 'existing': assert archive.read_bytes() == b'preserve'
                            else: assert not archive.exists()
                            assert not final.exists()
                            break
                        assert receive(client, 20) == b'GXA1' + struct.pack('<QQ', sequence, 0)
                        with tarfile.open(archive) as tar:
                            assert tar.extractfile('work/checkpoint').read() == expected
                            assert tar.extractfile('work/child').read() == b'child'
                        proc.stdin.write(b'G')
                        proc.stdin.flush()
                    if failure is None:
                        stdout, _ = proc.communicate(timeout=5)
                        assert proc.returncode == 0 and not stdout
                        with tarfile.open(work / 'snapshot-None-1.tar') as tar:
                            assert tar.extractfile('work/checkpoint').read() == b'first'
                        assert json.loads(result.read_text())['code'] == 0
                        with tarfile.open(final) as tar:
                            assert tar.extractfile('work/checkpoint').read() == b'second'
                        assert not list(work.glob('.ginux-export-*'))
                finally:
                    client.close()
                    if proc.poll() is None:
                        proc.kill()
                        proc.communicate(timeout=5)
        # A normally disconnected coordinator cancels a blocked workload.
        client, server = socket.socketpair()
        result, final = work/'closed.json', work/'closed.tar'
        with (work/'closed.audit').open('wb') as audit:
            proc = subprocess.Popen([binary,'launch',str(config_path),str(root),'--result-file',str(result),'--export-file',str(final),'--control-fd',str(server.fileno())],
                pass_fds=(server.fileno(),),stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=audit)
            server.close()
            try:
                assert select.select([proc.stdout],[],[],5)[0]
                assert proc.stdout.readline()==b'checkpoint-ready\n'
                client.close()
                assert proc.wait(timeout=5)==1
                stdout,_=proc.communicate(timeout=5)
                assert not stdout and json.loads(result.read_text())['outcome']=='supervisor-error'
                assert not final.exists() and not list(work.glob('.ginux-export-*'))
            finally:
                client.close()
                if proc.poll() is None: proc.kill(); proc.communicate(timeout=5)
        # Idle control must not force a polling tick per syscall. An inherited
        # ignored SIGCHLD must not prevent the supervisor's private task wait.
        config_path.write_text(config.replace('args = ["checkpoint"]','args = ["events"]'))
        for controlled in (False,True):
            client, server = socket.socketpair()
            try:
                command=[binary,'launch',str(config_path),str(root)]
                if controlled: command+=['--control-fd',str(server.fileno())]
                start=time.monotonic()
                proc=subprocess.run(command,pass_fds=(server.fileno(),) if controlled else (),
                    preexec_fn=lambda: signal.signal(signal.SIGCHLD,signal.SIG_IGN),capture_output=True,timeout=10)
                assert proc.returncode==0,proc.stderr.decode()
                assert proc.stdout==b'events: PASS\n',proc.stdout
                print(f'10000 syscalls, control={controlled}: {time.monotonic()-start:.3f}s')
            finally:
                client.close(); server.close()
        print('test-launch-checkpoints: PASS (' + ('ordinary snapshots, fragmented valid frames, final export, cancellation and task events' if ordinary else 'snapshots, private fds, partial frames, replay, freshness, cancellation and task events') + ')')


if __name__ == '__main__':
    main()
