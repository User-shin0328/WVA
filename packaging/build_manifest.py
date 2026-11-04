"""Bind the executable to normalized source files; validation is separate from building."""
import argparse
from datetime import datetime, timezone, timedelta
import hashlib
import json
from pathlib import Path
import subprocess

ROOT=Path(__file__).resolve().parents[1]
MANIFEST=ROOT/'docs/BUILD_INFO.json'


def sources():
    files=[]
    for folder in ['agents','core','dashboard','surface','reporting']:
        files.extend(p for p in (ROOT/folder).rglob('*') if p.is_file() and '__pycache__' not in p.parts and p.suffix in ('.py','.js','.css','.html','.svg','.ttf'))
    files += [ROOT/name for name in ['launcher.py','mock_target.py','requirements-lock.txt','packaging/build.ps1','packaging/build_manifest.py']]
    return {p.relative_to(ROOT).as_posix():hashlib.sha256(p.read_bytes() if p.suffix=='.ttf' else p.read_bytes().replace(b'\r\n',b'\n')).hexdigest() for p in sorted(files)}


def verify(data=None):
    data=data or json.loads(MANIFEST.read_text(encoding='utf-8'))
    exe=ROOT/'WVA.exe'
    return (exe.stat().st_size==data['bytes'] and hashlib.sha256(exe.read_bytes()).hexdigest()==data['sha256']
            and sources()==data.get('source_files'))


def create():
    from dashboard.server import VERSION
    exe=ROOT/'WVA.exe'
    data={'product':'WVA','version':VERSION,'date':datetime.now(timezone(timedelta(hours=9))).date().isoformat(),
          'platform':'Windows x64','file':'WVA.exe','bytes':exe.stat().st_size,'sha256':hashlib.sha256(exe.read_bytes()).hexdigest(),
          'source_base_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),
          'source_worktree_dirty':bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT)),
          'source_files':sources(),'validation_status':'NOT_RUN','default_port':9030,
          'test_guide':'tests/TEST_GUIDE.md','implementation_report':'docs/RELIABILITY_UPGRADE_2.6.md',
          'browser_runtime':'Playwright 1.64.1 bundled; installed Edge/Chrome or Playwright Chromium required'}
    MANIFEST.write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    return data


if __name__=='__main__':
    import sys
    sys.path.insert(0,str(ROOT))
    parser=argparse.ArgumentParser();parser.add_argument('--verify',action='store_true');args=parser.parse_args()
    if args.verify:
        valid=verify();print('VALID' if valid else 'MISMATCH');raise SystemExit(0 if valid else 1)
    data=create();print(json.dumps({'version':data['version'],'sha256':data['sha256'],'validation_status':data['validation_status']}))
