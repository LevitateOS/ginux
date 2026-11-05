#!/usr/bin/env python3
"""Exercise a shared public descriptor table through actual configured launch."""
import json
import os
from pathlib import Path
import shutil
import resource
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv)!=3 or os.geteuid()!=0:
        sys.exit('usage (as root): test-launch-fds.py <ginux> <fd-fixture>')
    binary,fixture=[str(Path(p).resolve()) for p in sys.argv[1:]]
    template=(Path(__file__).resolve().parent.parent/'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-fds-') as directory:
        work=Path(directory)
        root=work/'root'
        (root/'bin').mkdir(parents=True)
        (root/'work').mkdir()
        shutil.copyfile(fixture,root/'bin/fixture')
        (root/'bin/fixture').chmod(0o755)
        config=template.replace('init = "/bin/bash"','init = "/bin/fixture"')
        config=config.replace('[storage]\nassignments = []','[storage]\nassignments = ["memory:/work"]')
        config=config.replace('[devices]\nassignments = []','[devices]\nassignments = ["null"]')
        (work/'launch.toml').write_text(config)
        for i in range(2):
            result=work/f'{i}.json'
            proc=subprocess.run([binary,'launch',str(work/'launch.toml'),str(root),'--result-file',str(result)],capture_output=True,timeout=20)
            record=json.loads(result.read_text())
            assert proc.returncode==0,(proc.returncode,proc.stderr,record)
            assert record['outcome']=='exited' and record['code']==0 and record['generation'] is None,record
            assert proc.stdout==b'shared-fds: PASS\n',proc.stdout
            assert not (root/'work/data').exists()
        # A lower operator limit remains effective for both native and public FDs.
        (work/'low.toml').write_text(config.replace('args = []','args = ["low"]'))
        def lower_limit():
            resource.setrlimit(resource.RLIMIT_NOFILE,(8,8))
        result=work/'low.json'
        proc=subprocess.run([binary,'launch',str(work/'low.toml'),str(root),'--result-file',str(result)],capture_output=True,timeout=20,preexec_fn=lower_limit)
        assert proc.returncode==0,(proc.returncode,proc.stderr)
        assert proc.stdout==b'lower-limit: PASS\n',proc.stdout
        assert json.loads(result.read_text())['code']==0
        print('test-launch-fds: PASS (small numbers, cross-owner aliases, native reuse/mmap, limits, registers)')


if __name__=='__main__':
    main()
