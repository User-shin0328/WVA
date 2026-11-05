"""Own temporary UI/lab processes for a bounded browser check, then stop both."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import time
import httpx

ROOT=Path(__file__).resolve().parents[1]


def port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));return sock.getsockname()[1]


def main():
    parser=argparse.ArgumentParser();parser.add_argument('--exe',action='store_true');parser.add_argument('--workflow',action='store_true');args=parser.parse_args()
    dashboard_port,lab_port=port(),port()
    data=ROOT/'tests/artifacts/upgrade-2.7/ui-data';data.mkdir(parents=True,exist_ok=True)
    node=Path(os.environ['USERPROFILE'])/'.cache/codex-runtimes/codex-primary-runtime/dependencies/node/bin/node.exe'
    if os.environ.get('WVA_NODE'):node=Path(os.environ['WVA_NODE'])
    base=f'http://127.0.0.1:{dashboard_port}'
    command=[str(ROOT/'WVA.exe')] if args.exe else [sys.executable,str(ROOT/'launcher.py')]
    hidden={'creationflags':subprocess.CREATE_NO_WINDOW} if os.name=='nt' else {}
    service=subprocess.Popen(command+['--no-browser','--port',str(dashboard_port),'--data-dir',str(data)],cwd=ROOT,**hidden)
    lab=subprocess.Popen([sys.executable,'-m','tests.lab.workflow_target' if args.workflow else 'tests.lab.target','--port',str(lab_port)],cwd=ROOT,**hidden)
    try:
        with httpx.Client(trust_env=False,timeout=2) as client:
            for _ in range(200):
                try:
                    if client.get(base+'/api/health').status_code==200 and client.get(f'http://127.0.0.1:{lab_port}').status_code==200:break
                except httpx.HTTPError:pass
                time.sleep(.1)
            else:raise RuntimeError('Temporary UI/lab services did not start')
        env={**os.environ,'WVA_TEST_URL':base,'WVA_LAB_URL':f'http://127.0.0.1:{lab_port}'}
        completed=subprocess.run([str(node),str(ROOT/('tests/ui_workflow.cjs' if args.workflow else 'tests/ui_check.cjs'))],cwd=ROOT,env=env,timeout=240,**hidden)
        output=ROOT/('tests/artifacts/upgrade-2.7/browser/result.json' if args.workflow else 'tests/artifacts/browser/result.json')
        if output.exists():
            result=json.loads(output.read_text(encoding='utf-8'))
            result['runner_mode']='executable' if args.exe else 'source'
            result['exe_sha256']=hashlib.sha256((ROOT/'WVA.exe').read_bytes()).hexdigest() if args.exe else None
            output.write_text(json.dumps(result,ensure_ascii=False,indent=2),encoding='utf-8')
        return completed.returncode
    finally:
        try:
            with httpx.Client(trust_env=False,timeout=5) as client:client.post(base+'/api/app/shutdown',json={})
            service.wait(timeout=15)
        except (httpx.HTTPError,subprocess.TimeoutExpired):pass
        for process in [service,lab]:
            if process.poll() is None:
                if os.name=='nt':subprocess.run(['taskkill','/PID',str(process.pid),'/T','/F'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,**hidden)
                else:process.terminate()
                process.wait(timeout=10)


if __name__=='__main__':raise SystemExit(main())
