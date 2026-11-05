"""Compare source/frozen server rules against owned real-I/O positive/negative pairs."""
import asyncio
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import time
import httpx
from agents.engine import VulnerabilityAnalysisEngine
from dashboard.testbed import LocalTestbed
from reporting.report_generator import SecurityReportGenerator
from tests.lab.system_target import create_app

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'tests/artifacts/reliability-2.6'


def cases(base):
    items=[]
    for kind,modes in [('file',['vulnerable','safe']),('command',['vulnerable','reflection']),('ssrf',['vulnerable','reflection']),('upload',['vulnerable','reject'])]:
        for mode in modes:
            item={'kind':kind,'url':base+f'/{kind}/{mode}'}
            if kind=='file':item.update(control_value='guide.txt',probe_value='../canary.txt',expected_marker='WVA_BENIGN_FILE_CANARY_6e6de08c')
            if kind=='command':item['shell']='windows' if os.name=='nt' else 'posix'
            if kind=='ssrf':item.update(callback_url=base+'/callback/{marker}',receipt_url=base+'/receipt/{marker}')
            if kind=='upload':item.update(read_url=base+'/files/{filename}',cleanup_url=base+'/cleanup/ok')
            items.append(item)
    return items


def executable(base,options):
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    data=OUT/'server-exe-data';data.mkdir(parents=True,exist_ok=True)
    hidden={'creationflags':subprocess.CREATE_NO_WINDOW} if os.name=='nt' else {}
    process=subprocess.Popen([str(ROOT/'WVA.exe'),'--no-browser','--port',str(port),'--data-dir',str(data)],cwd=ROOT,**hidden)
    with httpx.Client(base_url=f'http://127.0.0.1:{port}',trust_env=False,timeout=15) as client:
        try:
            for _ in range(200):
                try:
                    if client.get('/api/health').json().get('version')=='2.7.0':break
                except httpx.HTTPError:pass
                time.sleep(.1)
            else:raise RuntimeError('Frozen service did not start')
            response=client.post('/api/scan/start',json={'target_url':base,'scope_mode':'origin','mode':'deep','consent':True,'options':options})
            assert response.status_code==200,response.text
            for _ in range(1800):
                state=client.get('/api/scan/status').json()
                if state['status']!='running':break
                time.sleep(.1)
            assert state['status']=='completed',state
            assert state['assessment_complete'],state
            return client.get('/api/scan/report/json').json()
        finally:
            try:client.post('/api/app/shutdown',json={})
            except httpx.HTTPError:pass
            try:process.wait(timeout=15)
            except subprocess.TimeoutExpired:process.terminate();process.wait(timeout=10)


async def main():
    OUT.mkdir(parents=True,exist_ok=True)
    data={'at':datetime.now().astimezone().isoformat(),'status':'FAIL','checks':[],'exe_sha256':hashlib.sha256((ROOT/'WVA.exe').read_bytes()).hexdigest()}
    try:
        with tempfile.TemporaryDirectory() as directory:
            app=create_app(directory);lab=LocalTestbed(app);base=await lab.start()
            options={'mode':'deep','sql':False,'xss':False,'browser':False,'concurrency_check':False,'system_cases':cases(base)}
            try:
                source=SecurityReportGenerator(await VulnerabilityAnalysisEngine(base,options=options).execute_audit()).generate_json_report()
                binary=await asyncio.to_thread(executable,base,options)
                for name,report in [('source',source),('exe',binary)]:
                    paths={f['endpoint'] for f in report['findings']}
                    for case in options['system_cases']:
                        path=case['url'].removeprefix(base)
                        expected=path.endswith('/vulnerable')
                        assert (path in paths)==expected,(name,path,paths)
                        data['checks'].append({'name':name+':'+path,'status':'PASS','expected_finding':expected})
                    assert not app.state.files
                    assert all(not f['yielded_postconditions'] for f in report['findings'])
                    assert all(not c['errors'] and not c['inconclusive'] for c in report['scan_scope']['checks'])
                    assert next(c for c in report['scan_scope']['checks'] if c['rule_id']=='R14')['status']=='PASS'
                    data['checks'].append({'name':name+':verified_cleanup_and_no_fabricated_privilege','status':'PASS'})
                    (OUT/(name+'-server-report.json')).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
                assert [(f['vuln_type'],f['endpoint']) for f in source['findings']]==[(f['vuln_type'],f['endpoint']) for f in binary['findings']]
                data['checks'].append({'name':'source_exe_agree','status':'PASS'})
                manifest=json.loads((ROOT/'docs/BUILD_INFO.json').read_text(encoding='utf-8'))
                assert data['exe_sha256']==manifest['sha256']
                data['checks'].append({'name':'manifest_matches_exe','status':'PASS'})
                data['status']='PASS'
            finally:await lab.stop()
    except Exception as exc:data['error']=str(exc);raise
    finally:
        (OUT/'acceptance.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'status':data['status'],'checks':len(data['checks']),'error':data.get('error')},ensure_ascii=True))


if __name__=='__main__':asyncio.run(main())
