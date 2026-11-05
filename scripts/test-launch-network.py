#!/usr/bin/env python3
"""Real configured numeric TCP grants, ownership, readiness and quota checks."""
import json
import os
from pathlib import Path
import shutil
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time


def main():
    if len(sys.argv) != 3 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-network.py <ginux> <network-fixture>')
    binary, fixture = [str(Path(p).resolve()) for p in sys.argv[1:]]
    template = (Path(__file__).resolve().parent.parent/'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-network-') as directory:
        work = Path(directory)
        root = work/'root'
        (root/'bin').mkdir(parents=True)
        (root/'work').mkdir()
        shutil.copyfile(fixture, root/'bin/fixture')
        (root/'bin/fixture').chmod(0o755)
        for mode in ('io', 'nonblock', 'deny', 'quota', 'timeout', 'hold', 'hold-kill', 'slots', 'off'):
            with socket.socket() as server, socket.socket() as forbidden:
                server.bind(('127.0.0.1', 0))
                forbidden.bind(('127.0.0.1', 0))
                server.listen()
                forbidden.listen()
                port = server.getsockname()[1]
                observed = []
                failure = []
                def echo():
                    try:
                        server.settimeout(5)
                        stream, _ = server.accept()
                        with stream:
                            observed.append('connect')
                            if mode == 'timeout':
                                time.sleep(.15)
                                return
                            while True:
                                data = stream.recv(4096)
                                if not data:
                                    break
                                observed.append(data)
                                if mode == 'nonblock':
                                    time.sleep(.08)
                                stream.sendall(data)
                    except Exception as error:
                        failure.append(repr(error))
                thread = None
                if mode in ('io', 'nonblock', 'quota', 'timeout', 'hold', 'hold-kill'):
                    thread = threading.Thread(target=echo, daemon=True)
                    thread.start()
                config = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
                connect_port = forbidden.getsockname()[1] if mode == 'deny' else port
                config = config.replace('args = []', 'args = '+json.dumps([mode, str(connect_port)]))
                if mode != 'off':
                    network = (f'backend = "mediated"\nendpoints = ["127.0.0.1:{port}"]\n'
                               f'max_connections = 2\nmax_bytes = {8 if mode == "quota" else 1048576}')
                    config = config.replace('backend = "none"', network)
                path, result = work/'domain.toml', work/'result.json'
                path.write_text(config)
                result.unlink(missing_ok=True)
                command = [binary, 'launch', str(path), str(root), '--result-file', str(result)]
                if mode.startswith('hold'):
                    audit = work/(mode+'.audit')
                    with audit.open('wb') as errors:
                        proc = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errors)
                        try:
                            assert select.select([proc.stdout], [], [], 5)[0], 'network readiness handshake timed out'
                            assert proc.stdout.readline() == b'network-ready\n'
                            children = Path(f'/proc/{proc.pid}/task/{proc.pid}/children').read_text().split()
                            assert len(children) == 1, children
                            assert sorted(p.name for p in Path(f'/proc/{children[0]}/fd').iterdir()) == ['0', '1', '2']
                            if mode == 'hold-kill':
                                proc.kill()
                                proc.communicate(timeout=5)
                            else:
                                proc.communicate(b'G', timeout=5)
                                assert proc.returncode == 0, audit.read_text()
                        finally:
                            if proc.poll() is None:
                                proc.kill()
                                proc.communicate(timeout=5)
                    if mode == 'hold':
                        assert json.loads(result.read_text())['code'] == 0
                        assert b'teardown tasks=0 owned-handles=0' in audit.read_bytes()
                else:
                    before = time.monotonic()
                    proc = subprocess.run(command, capture_output=True, timeout=10)
                    assert proc.returncode == 0, (mode, proc.returncode, proc.stdout, proc.stderr.decode(), result.read_text())
                    if mode == 'timeout':
                        assert .03 < time.monotonic() - before < 2
                    assert json.loads(result.read_text())['code'] == 0
                    assert b'teardown tasks=0 owned-handles=0' in proc.stderr
                if thread:
                    thread.join(6)
                    assert not thread.is_alive() and not failure, (mode, failure)
                    assert observed[0] == 'connect'
                forbidden.setblocking(False)
                try:
                    unallowed, _ = forbidden.accept()
                except BlockingIOError:
                    pass
                else:
                    unallowed.close()
                    raise AssertionError('denied endpoint received a connection')
                print(f'PASS configured TCP: {mode}')
    print('test-launch-network: PASS')

if __name__ == '__main__':
    main()
