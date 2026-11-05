#!/usr/bin/env python3
"""Exercise owned directory descriptions through actual configured launch."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile


def main():
    if len(sys.argv)!=3 or os.geteuid()!=0:
        sys.exit('usage (as root): test-launch-directories.py <ginux> <directory-fixture>')
    binary,fixture=[str(Path(p).resolve()) for p in sys.argv[1:]]
    template=(Path(__file__).resolve().parent.parent/'config/domain-gate5.toml').read_text()
    with tempfile.TemporaryDirectory(prefix='ginux-directories-') as directory:
        work=Path(directory)
        root=work/'root'
        (root/'bin').mkdir(parents=True)
        (root/'work').mkdir()
        shutil.copyfile(fixture,root/'bin/fixture')
        (root/'bin/fixture').chmod(0o755)
        (root/'image').write_bytes(b'immutable image')
        config=template.replace('init = "/bin/bash"','init = "/bin/fixture"')
        config=config.replace('[storage]\nassignments = []','[storage]\nassignments = ["memory:/work", "memory:/work/seed"]')
        config=config.replace('[devices]\nassignments = []','[devices]\nassignments = ["null"]')
        (work/'launch.toml').write_text(config)
        for i in range(2):
            result=work/f'{i}.json'
            proc=subprocess.run([binary,'launch',str(work/'launch.toml'),str(root),'--result-file',str(result)],capture_output=True,timeout=20)
            record=json.loads(result.read_text())
            assert proc.returncode==0,(proc.returncode,proc.stderr,record)
            assert record['outcome']=='exited' and record['code']==0 and record['generation'] is None,record
            assert proc.stdout==b'owned-directories: PASS\n',proc.stdout
            assert b'ginux: teardown tasks=0 owned-handles=0' in proc.stderr,proc.stderr
            assert list((root/'work').iterdir())==[]
            assert (root/'image').read_bytes()==b'immutable image'
        print('test-launch-directories: PASS (records, cursors, faults, aliases/fork, rename, removal, relative operations, isolation)')


if __name__=='__main__':
    main()
