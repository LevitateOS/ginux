#!/usr/bin/env python3
"""Real allowed/denied configured-launch calls, with contract audit checks."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv) < 4 or os.geteuid() != 0:
        sys.exit('usage (as root): test-launch-contract.py <ginux> <fixture> <evidence-dir>')
    binary, fixture, evidence = [Path(p).resolve() for p in sys.argv[1:4]]
    evidence.mkdir(parents=True, exist_ok=True)
    template = (Path(__file__).resolve().parent.parent / 'config/instance-gate5.toml').read_text()
    template = template.replace('init = "/bin/bash"', 'init = "/bin/fixture"')
    template = template.replace('assignments = []', 'assignments = ["memory:/work"]', 1)
    def policy(catalog=2, allow=('*',), deny=(), syscall_allow=(), syscall_deny=()):
        text = (f'[contract]\nversion = 1\ncatalog = {catalog}\ndefault = "deny"\n'
                f'allow = {json.dumps(allow)}\ndeny = {json.dumps(deny)}\n')
        if syscall_allow or syscall_deny:
            text += ('[contract.syscalls]\ncontrol = "paranoid"\ndefault = "deny"\n'
                     f'allow = {json.dumps(syscall_allow)}\ndeny = {json.dumps(syscall_deny)}\n')
        return text
    legacy = policy()
    recipe = policy()
    receipts = []
    with tempfile.TemporaryDirectory(prefix='ginux-contract-') as tmp:
        root = Path(tmp) / 'root'
        (root / 'bin').mkdir(parents=True)
        (root / 'work').mkdir()
        shutil.copyfile(fixture, root / 'bin/fixture')
        (root / 'bin/fixture').chmod(0o755)
        (root / 'input').write_bytes(b'input')

        def check(name, op='r', expected=0, contract=legacy, startup=False,
                  audit=True, operation=None, source=None, extra='', stdout=b''):
            if sys.argv[4:] and name not in sys.argv[4:]:
                return
            config = template.split('[contract]')[0] + contract + '[storage]' + template.split('[storage]', 1)[1]
            config = config.replace('args = []', 'args = ' + json.dumps([op, str(expected)]))
            if not audit:
                config = config.replace('mode = "stderr"', 'mode = "disabled"')
            config += extra
            path, result = evidence / (name + '.toml'), evidence / (name + '.json')
            path.write_text(config)
            result.unlink(missing_ok=True)
            command = [str(binary), 'launch', str(path), str(root), '--result-file', str(result)]
            proc = subprocess.run(command, input=b'x', capture_output=True, timeout=20)
            (evidence / (name + '.stderr')).write_bytes(proc.stderr)
            (evidence / (name + '.stdout')).write_bytes(proc.stdout)
            record = json.loads(result.read_text())
            wanted = 2 if startup else 0
            assert proc.returncode == wanted, (name, proc.returncode, proc.stderr.decode())
            assert record['outcome'] == ('supervisor-error' if startup else 'exited'), (name, record)
            assert proc.stdout == stdout, (name, proc.stdout)
            if not audit:
                assert b'ginux: audit ' not in proc.stderr, (name, proc.stderr.decode())
            elif not startup:
                assert b'ginux: launch contract instance=' in proc.stderr, name
                assert b'teardown tasks=0 owned-handles=0' in proc.stderr, name
            if operation:
                lines = proc.stderr.decode().splitlines()
                assert any('operation=' + operation + ' ' in line
                           and ('policy-source=' + source + ' ') in line
                           and 'action=deny result=-' + str(-expected) in line
                           for line in lines), (name, proc.stderr.decode())
            receipts.append({'name': name, 'command': command, 'exit': proc.returncode,
                             'result': record})
            (evidence / 'receipts.json').write_text(json.dumps(receipts, indent=2) + '\n')
            print('PASS contract ' + name, flush=True)

        # Every failure control has an allowed workload counterpart.
        configured = policy(1002)
        for op in ['r', 'w', 'c', 'm', 'g', 'i', 'f', 'b']:
            check('allow-' + op, op)
        for op in ['s', 'p']:
            check('configured-allow-' + op, op, contract=configured)
            check('v1-refuses-' + op, op, -38, contract=legacy)
        check('allow-console-alias', 'a', stdout=b'alias\n')
        for selector, op in [('syscall.open', 'r'), ('syscall.fork', 'f'),
                             ('syscall.nanosleep', 's'), ('syscall.pipe', 'p'),
                             ('filesystem.path.write', 'w'), ('memory.virtual.manage', 'm'),
                             ('credential.virtual.set', 'g'), ('signal.virtual.deliver', 'i'),
                             ('device.console.write', 'a'), ('device.console.read', 'b')]:
            check('deny-' + selector, op, -1, policy(1002 if op in ['s', 'p'] else 2, deny=(selector,)),
                  operation=selector, source='exact-deny')
        check('recipe-deny', 'r', -1, policy(deny=('syscall.open',)),
              operation='syscall.open', source='exact-deny')
        check('exact-deny', 'r', -1, policy(syscall_deny=('open',)),
              operation='syscall.open', source='exact-deny')
        check('deny-beats-exact-allow', 'r', -1,
              policy(deny=('syscall.open',), syscall_allow=('open',)),
              operation='syscall.open', source='exact-deny')
        check('default-deny', 'r', -38, policy(allow=('syscall.getpid','syscall.getppid','syscall.gettid','syscall.write','syscall.exit','syscall.exit_group')),
              operation='filesystem.path.read', source='default-deny')
        check('explicit-beats-family-default', 'a', -1,
              policy(allow=('syscall.dup','syscall.exit','syscall.exit_group'), deny=('syscall.write',)),
              operation='syscall.write', source='exact-deny')
        check('no-network', 'n', -13)
        check('network-family-deny', 'n', -1,
              policy(deny=('network.inet.tcp.connect',)),
              operation='network.inet.tcp.connect', source='exact-deny')
        check('unknown-syscall', 'u', -38)
        check('disabled-audit', audit=False)
        check('disabled-audit-denial', 'r', -1, policy(deny=('syscall.open',)), audit=False)
        for selector in ['time.clock.read', 'syscall.clock_gettime', 'proc.process.read', 'proc.system.read',
                         'sys.device.read', 'cgroup.virtual.manage']:
            check('refuse-' + selector, contract=policy(deny=(selector,)), startup=True)
        check('refuse-path-policy', startup=True,
              extra='\n[contract.filesystem]\ndeny = ["/work"]\n')
        check('refuse-hooks', startup=True, extra='\n[hooks]\npre_boot = ["/bin/fixture"]\n')
        for name, fields in [
            ('filesystem-read', '[contract.filesystem]\nread = ["/"]'),
            ('filesystem-write', '[contract.filesystem]\nwrite = ["/"]'),
            ('filesystem-create', '[contract.filesystem]\ncreate = ["/"]'),
            ('privileges', '[contract.privileges]\nsetuid = ["/"]'),
            ('devices', '[contract.devices]\nread = ["/dev/null"]'),
            ('process-limit', '[contract.process]\nmax_processes = 8'),
            ('thread-limit', '[contract.process]\nmax_threads = 8'),
            ('signals', '[contract.process]\nsignals = ["*"]'),
            ('ptrace', '[contract.process]\nptrace = "allow"'),
            ('namespace', '[contract.process]\nnamespace_create = ["user"]'),
            ('proc', '[contract.kernel]\nproc_read = ["/"]'),
            ('sys', '[contract.kernel]\nsys_read = ["/"]'),
        ]:
            check('refuse-native-' + name, startup=True, extra='\n' + fields + '\n')

        configured_recipe = recipe.replace('catalog = 2', 'catalog = 1002')
        check('recipe-v2-allows-sleep', 's', contract=configured_recipe)
        check('recipe-v2-denies-sleep', 's', -1, policy(1002, syscall_deny=('nanosleep',)), operation='syscall.nanosleep', source='exact-deny')
        check('unknown-catalog-refused', contract=recipe.replace('catalog = 2', 'catalog = 99'), startup=True)
        check('zero-match-refused', contract=policy(deny=('unknown.operation',)), startup=True)
        check('refuse-v2-clock-resolution-deny', contract=policy(1002, deny=('syscall.clock_getres',)), startup=True)
        check('allowed-after-denials')
    print('test-launch-contract: PASS (' + str(len(receipts)) + ' cases)')


if __name__ == '__main__':
    main()
