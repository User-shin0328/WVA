"""Source + frozen executable acceptance for declared local policies and cleanup."""
import asyncio
from collections import Counter
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import socket
import subprocess
import time
import httpx
from agents.engine import VulnerabilityAnalysisEngine
from dashboard.testbed import LocalTestbed
from reporting.report_generator import SecurityReportGenerator
from tests.lab.advanced_target import create_app

ROOT=Path(__file__).resolve().parents[2]
OUT=ROOT/'tests/artifacts/benchmark'


def options(base):
    return {'sql':False,'xss':False,'browser':True,'primary_session':'A',
        'sessions':[{'alias':alias,'login_url':base+'/login','login_fields':{'username':alias,'password':'local-only-'+alias}} for alias in ['A','B','admin']],
        'access_cases':[{'url':base+f'/{kind}/{mode}','owner':'A' if kind=='object' else 'admin','denied':['B','anonymous'],'protected_fields':['private_record'],'kind':kind} for kind in ['object','role'] for mode in ['vulnerable','safe']],
        'stored_cases':[{'write_url':base+'/stored/write','read_url':base+'/stored/read?record_id=wva-probe','cleanup_url':base+'/stored/cleanup','field':'message','fields':{'record_id':'wva-probe'}}],
        'timing_cases':[{'url':base+'/timing?id=1','parameter':'id','true_value':'(CASE WHEN 1=1 THEN wva_delay(0.3) ELSE 0 END)+1','false_value':'(CASE WHEN 1=2 THEN wva_delay(0.3) ELSE 0 END)+1','delay':.3}]}


def verify(report):
    checks={r['rule_id']:r for r in report['scan_scope']['checks']}
    for key in ['R09','R10','R11-T','R12-S']:assert checks[key]['status']=='FINDING',checks[key]
    counts=Counter(f['vuln_type'] for f in report['findings'])
    for key in ['BOLA_IDOR','AUTH_BYPASS','SQL_INJECTION','XSS']:assert counts[key]==1,(key,counts)
    text=json.dumps(report)
    assert 'local-only-' not in text and 'wva-session-' not in text
    return dict(counts)


def executable(base,config):
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    data=OUT/'extended-exe-data';data.mkdir(parents=True,exist_ok=True)
    proc=subprocess.Popen([str(ROOT/'WVA.exe'),'--no-browser','--port',str(port),'--data-dir',str(data)],cwd=ROOT,
                          creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    with httpx.Client(base_url=f'http://127.0.0.1:{port}',trust_env=False,timeout=15) as client:
        try:
            for _ in range(200):
                try:
                    if client.get('/api/health').json().get('version')=='2.5.0':break
                except httpx.HTTPError:pass
                assert proc.poll() is None
                time.sleep(.1)
            else:raise TimeoutError('Executable did not start')
            assert client.post('/api/scan/start',json={'target_url':base,'scope_mode':'origin','consent':True,'options':config}).status_code==200
            for _ in range(1800):
                status=client.get('/api/scan/status').json()
                if status['status']!='running':break
                time.sleep(.1)
            assert status['status']=='completed',status
            return client.get('/api/scan/report/json').json()
        finally:
            try:client.post('/api/app/shutdown',json={})
            except httpx.HTTPError:pass
            try:proc.wait(timeout=15)
            except subprocess.TimeoutExpired:proc.terminate();proc.wait(timeout=5)


async def main():
    OUT.mkdir(parents=True,exist_ok=True)
    app=create_app();lab=LocalTestbed(app);base=await lab.start()
    data={'at':datetime.now().astimezone().isoformat(timespec='seconds'),'status':'FAIL','checks':[]}
    try:
        config=options(base)
        bb=await VulnerabilityAnalysisEngine(base,scope_mode='origin',options=config).execute_audit()
        source=SecurityReportGenerator(bb).generate_json_report();source_counts=verify(source)
        assert not app.state.stored
        binary=await asyncio.to_thread(executable,base,config);binary_counts=verify(binary)
        assert source_counts==binary_counts and not app.state.stored
        data.update(status='PASS',source_findings=source_counts,executable_findings=binary_counts,
                    exe_sha256=hashlib.sha256((ROOT/'WVA.exe').read_bytes()).hexdigest())
        data['checks']=[{'name':name,'status':'PASS'} for name in ['source_account_policy','source_role_policy','source_timing_sql','source_stored_xss_cleanup','exe_account_policy','exe_role_policy','exe_timing_sql','exe_stored_xss_cleanup','source_exe_agree','credentials_redacted']]
        for name,report in [('extended-source.json',source),('extended-exe.json',binary)]:
            (OUT/name).write_text(json.dumps(report,ensure_ascii=False,indent=2),encoding='utf-8')
    except Exception as exc:data['error']=str(exc);raise
    finally:
        await lab.stop()
        (OUT/'extended-result.json').write_text(json.dumps(data,ensure_ascii=False,indent=2),encoding='utf-8')
        print(json.dumps({'status':data['status'],'checks':len(data['checks']),'error':data.get('error')},ensure_ascii=False))


if __name__=='__main__':asyncio.run(main())
