"""Verify third-party ground truth, then measure the unchanged WVA source and exe.

This is an acceptance benchmark, not a claim that SQLi/XSS rules are implemented.
Only the hard-coded loopback lab services may be targeted by this runner.
"""
import asyncio
from collections import Counter
from datetime import datetime
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import time
import httpx
from bs4 import BeautifulSoup
from agents.engine import VulnerabilityAnalysisEngine
from core.graph.blackboard import SecurityBlackboard
from core.safety.governance import SafetyGovernance
from reporting.report_generator import SecurityReportGenerator
from surface.reflection import ReflectionCanaryAuditor

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / 'tests/artifacts/benchmark'
LOW = 'http://127.0.0.1:18910'
SAFE = 'http://127.0.0.1:18911'
JUICE = 'http://127.0.0.1:18912'


def write(name, data):
    (OUT / name).write_text(json.dumps(data, ensure_ascii=False, indent=2)+'\n', encoding='utf-8')


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def token(response):
    item = BeautifulSoup(response.text, 'html.parser').find('input', attrs={'name': 'user_token'})
    require(item and item.get('value'), 'DVWA CSRF token not found')
    return item['value']


def user_rows(response):
    # Compare returned DB fields, excluding the echoed input printed before them.
    return [node.get_text(' ', strip=True).split('First name:', 1)[1] for node in BeautifulSoup(response.text, 'html.parser').find_all('pre') if 'First name:' in node.get_text()]


def setup_and_ground_truth():
    # Reset only the dedicated compose database; never accepts an arbitrary host/database.
    with httpx.Client(base_url=LOW, trust_env=False, follow_redirects=True, timeout=15) as client:
        result = client.post('/setup.php', data={'create_db': 'Create / Reset Database', 'user_token': token(client.get('/setup.php'))})
        (OUT/'dvwa-setup.html').write_text(result.text, encoding='utf-8')
        require('setup successful' in result.text.lower(), 'Dedicated DVWA database setup failed')
    checks=[]
    for name, base, vulnerable in [('dvwa-low', LOW, True), ('dvwa-safe', SAFE, False)]:
        with httpx.Client(base_url=base, trust_env=False, follow_redirects=True, timeout=15) as client:
            rows={}
            for label, value in [('baseline','1'), ('true',"1' AND '1'='1"), ('false',"1' AND '1'='2"), ('true-repeat',"1' AND '1'='1"), ('false-repeat',"1' AND '1'='2")]:
                params={'id':value,'Submit':'Submit'}
                if not vulnerable:
                    params['user_token']=token(client.get('/vulnerabilities/sqli/'))
                response=client.get('/vulnerabilities/sqli/', params=params)
                require(response.status_code==200, name+' SQL request failed')
                (OUT/(name+'-sql-'+label+'.html')).write_text(response.text, encoding='utf-8')
                rows[label]=user_rows(response)
            require(len(rows['baseline'])==1, name+' must return exactly one fixture row for id=1')
            require(rows['true']==rows['baseline'] if vulnerable else not rows['true'], name+' true condition disagrees with expected mode')
            require(not rows['false'], name+' false condition must return no fixture row')
            require(rows['true-repeat']==rows['true'] and rows['false-repeat']==rows['false'],name+' repeated conditions changed results')
            checks.append({'name':name+'_sql_ground_truth','status':'PASS','condition_changes_result':vulnerable,'baseline_rows':len(rows['baseline']),'true_rows':len(rows['true']),'false_rows':len(rows['false']),'condition_pair_repeats':2})
    # Only the public apple search subset is read; no user/credential extraction.
    with httpx.Client(base_url=JUICE, trust_env=False, timeout=15) as client:
        baseline=client.get('/rest/products/search', params={'q':'apple'})
        true=client.get('/rest/products/search', params={'q':"apple%') AND 1=1)-- "})
        false=client.get('/rest/products/search', params={'q':"apple%') AND 1=2)-- "})
        require(baseline.status_code==200 and isinstance(baseline.json().get('data'),list), 'Juice Shop baseline failed')
        require(true.status_code==false.status_code==200,'Juice Shop boolean requests failed')
        ids=lambda response: sorted(p['id'] for p in response.json()['data'])
        require(ids(baseline) and ids(true)==ids(baseline) and not ids(false),'Juice Shop boolean differential missing')
        require(ids(client.get('/rest/products/search',params={'q':"apple%') AND 1=1)-- "}))==ids(true),'Juice Shop true repeat changed')
        require(not ids(client.get('/rest/products/search',params={'q':"apple%') AND 1=2)-- "})),'Juice Shop false repeat changed')
        evidence={'baseline_ids':ids(baseline),'true_ids':ids(true),'false_ids':ids(false),'condition_pair_repeats':2,'assessment':'Repeatable SQL condition changes public product results; no credential extraction'}
        write('juice-sql-ground-truth.json',evidence)
        checks.append({'name':'juice_shop_sql_ground_truth','status':'PASS',**evidence})
    node=shutil.which('node')
    require(node, 'Node is required for independent browser ground truth')
    completed=subprocess.run([node,str(ROOT/'tests/benchmarks/browser_check.cjs')],cwd=ROOT,capture_output=True,text=True,encoding='utf-8',timeout=90)
    (OUT/'browser-output.txt').write_text(completed.stdout+completed.stderr,encoding='utf-8')
    require(completed.returncode==0,'Browser ground truth failed; see browser-output.txt')
    browser=json.loads((OUT/'browser-ground-truth.json').read_text(encoding='utf-8'))
    require(browser['status']=='PASS','Browser truth result is not PASS')
    return checks+browser['checks']


TARGETS=[
    ('dvwa-low-sql',LOW+'/vulnerabilities/sqli/?id=1&Submit=Submit','SQL_INJECTION','KNOWN_VULNERABLE'),
    ('dvwa-safe-sql',SAFE+'/vulnerabilities/sqli/?id=1&Submit=Submit','SQL_INJECTION','DEFENDED_CONTROL'),
    ('dvwa-low-xss',LOW+'/vulnerabilities/xss_r/?name=WVA_baseline','XSS','KNOWN_VULNERABLE'),
    ('dvwa-safe-xss',SAFE+'/vulnerabilities/xss_r/?name=WVA_baseline','XSS','DEFENDED_CONTROL'),
    ('juice-shop-search',JUICE+'/rest/products/search?q=apple','SQL_INJECTION','KNOWN_VULNERABLE'),
    ('juice-shop-root',JUICE+'/','XSS','KNOWN_VULNERABLE'),
]


def measure(name, expected_type, truth, report, runner):
    counts=Counter(f['vuln_type'] for f in report['findings'])
    expected = truth=='KNOWN_VULNERABLE'
    detected=counts.get(expected_type,0)
    require(bool(detected)==expected,name+' expected detection/negative control failed')
    checks=report['scan_scope'].get('checks',[])
    rule='R11' if expected_type=='SQL_INJECTION' else 'R12'
    check=next((r for r in checks if r['rule_id']==rule),None)
    require(check and check['status']==('FINDING' if expected else 'PASS'),name+' rule did not complete')
    return {'name':name,'runner':runner,'ground_truth':truth,'rule':expected_type,
            'outcome':'TRUE_POSITIVE' if expected else 'TRUE_NEGATIVE','detected':detected,'findings':dict(counts),
            'endpoints':len(report['endpoints']),'scope':report['scan_scope'],
            'interpretation':'Independent ground truth and actual rule result agree'}



async def source_benchmark():
    results=[]
    for name,url,kind,truth in TARGETS:
        engine=VulnerabilityAnalysisEngine(url)
        bb=await asyncio.wait_for(engine.execute_audit(),timeout=180)
        report=SecurityReportGenerator(bb).generate_json_report()
        write('source-'+name+'.json',report)
        results.append(measure(name,kind,truth,report,'source'))
    # Exercise the existing helper separately; it is deliberately not enabled in production.
    reflection=[]
    for name,base in [('dvwa-low',LOW),('dvwa-safe',SAFE)]:
        bb=SecurityBlackboard(base)
        auditor=ReflectionCanaryAuditor(bb,SafetyGovernance(base))
        async with httpx.AsyncClient(trust_env=False,follow_redirects=False) as client:
            await auditor.audit_endpoint_parameters(client,'/vulnerabilities/xss_r/',['name'])
        items=[f.model_dump(mode='json') for f in bb.get_findings_list()]
        reflection.append({'name':name,'findings':items,'assessment':'Standalone input reflection only; not XSS execution proof or engine integration'})
    write('standalone-reflection.json',reflection)
    return results


def exe_benchmark():
    executable=ROOT/'WVA.exe'
    sha=hashlib.sha256(executable.read_bytes()).hexdigest()
    build=json.loads((ROOT/'docs/BUILD_INFO.json').read_text(encoding='utf-8'))
    require(sha==build['sha256'],'Executable differs from BUILD_INFO.json')
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    data=OUT/'executable-data';data.mkdir(exist_ok=True)
    env=os.environ.copy();env['WVA_DATA_DIR']=str(data)
    proc=subprocess.Popen([str(executable),'--no-browser','--port',str(port),'--data-dir',str(data)],cwd=ROOT,env=env,
                          creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
    results=[]
    with httpx.Client(base_url=f'http://127.0.0.1:{port}',trust_env=False,timeout=15) as client:
        try:
            for _ in range(200):
                try:
                    health=client.get('/api/health').json()
                    if health.get('product')=='WVA':break
                except httpx.HTTPError:pass
                require(proc.poll() is None,'Benchmark executable exited before health')
                time.sleep(.1)
            else:raise TimeoutError('Executable did not become ready')
            require(health['version']==build['version'],'Wrong executable version')
            for name,url,kind,truth in TARGETS:
                started=client.post('/api/scan/start',json={'target_url':url,'scope_mode':'path','consent':True})
                require(started.status_code==200,'Executable scan start failed')
                for _ in range(1800):
                    status=client.get('/api/scan/status').json()
                    if status['status']!='running':break
                    time.sleep(.1)
                require(status['status']=='completed',name+' executable scan failed: '+str(status.get('error')))
                report=client.get('/api/scan/report/json').json()
                write('exe-'+name+'.json',report)
                result=measure(name,kind,truth,report,'exe')
                result['scan_id']=status['scan_id'];result['score']=status['score'];result['grade']=status['grade']
                results.append(result)
        finally:
            try:client.post('/api/app/shutdown',json={})
            except httpx.HTTPError:pass
            try:proc.wait(timeout=15)
            except subprocess.TimeoutExpired:
                proc.terminate();proc.wait(timeout=5)
    return sha,results


def report(data):
    rows=['# WVA 2.5 독립 취약 웹앱 검증 결과','',
          f"검증 시각: {data['at']} · 소스 기준 HEAD: `{data.get('source_commit','unknown')}`",'',
          f"결과: **{data['status']}**. 아래에 명시한 대상·입력·규칙의 결과이며 전체 웹 보안 인증은 아니다.",'',
          '## 이전 결과와 구현 변경','',
          '[2.4 실측 기록](BASELINE_2.4.md)은 미지원으로 4개 양성을 놓치고 97/A를 표시했던 당시 결과다. 2.5는 SQL 조건 반복 대조와 브라우저 실행 표식 확인을 실제 엔진에 연결했다. 쿠키·CSRF 토큰을 갱신하며 모든 HTTP와 브라우저 자원에 출처·경로·메서드·요청 수·응답 크기 제한을 적용한다.','',
          'JavaScript 라우트는 #/ 형식 입력과 렌더링된 링크·검색 제어에서 수집한다. 검사 상태와 미실행 사유를 UI·자동 보고서·선택 내보내기에 남긴다. SQLi/XSS 검사가 미실행·오류이면 A~D 등급을 보류한다. 참고 점수는 발견 기반으로만 계산한다.','',
          '## 독립 기준 확인','', '| 항목 | 상태 | 실제 관찰 |','| --- | --- | --- |']
    for item in data['ground_truth']:
        detail=(f"기준 {item['baseline_rows']} / 참 {item['true_rows']} / 거짓 {item['false_rows']}, 조건 쌍 2회" if 'baseline_rows' in item else
                f"기준/참 {item['baseline_ids']} / 거짓 {item['false_ids']}, 조건 쌍 2회" if 'baseline_ids' in item else f"표식 실행 예상 {item['expected_execution']} / 실제 {item['executed']}")
        rows.append(f"| {item['name']} | {item['status']} | {detail} |")
    rows+=['','## 소스 및 실행파일 진단','', '| 대상 | 실행 | SQLi/XSS 발견 | 판정 | 참고 점수·등급 |','| --- | --- | ---: | --- | --- |']
    for item in data['measurements']:
        rows.append(f"| {item['name']} | {item['runner']} | {item['detected']} | {item['outcome']} | {str(item.get('score',''))+' / '+str(item.get('grade') or '보류') if item['runner']=='exe' else 'API 별도'} |")
    rows+=['','알려진 양성 4개와 방어 대조 2개를 각각 소스·실행파일로 검사했다. 관련 규칙이 실제 실행된 결과를 비교하며 CSP 누락을 SQLi/XSS 탐지로 집계하지 않는다. 이 표본으로 전체 탐지 정확도를 일반화하지 않는다.','',
           '## 추가 기능의 별도 검증','',
           'tests/test_active_rules.py는 실제 SQLite의 취약/매개변수화 쿼리, 불안정·WAF·DB 오류 응답, 출력 인코딩·CSP·DOM, 브라우저의 외부/다른 경로/POST/WebSocket 차단, 요청·응답 한도, CSRF 세션, 계정·역할 정책, 저장형 XSS·정리·취소 정리, 로컬 시간 기반 조건 대조를 검사한다. 별도 로컬 실습 앱 tests/lab/advanced_target.py를 사용하며 제3자 앱 결과와 구분한다. 최신 수와 실제 PASS/FAIL은 ../TEST_RESULTS.md의 기능 검사 목록을 따른다.','',
           '## 산출물','',
           f"- WVA.exe SHA-256: `{data.get('exe_sha256','NOT_RUN')}`.",
           '- 원본 result.json: 독립 기준 6건, 소스/실행파일 12건, 이미지 digest, 소스 파일 해시.',
           '- source-*.json, exe-*.json: 실제 발견 항목과 검사 상태.',
           '- browser-ground-truth.json 및 XSS PNG 3장: 브라우저 표식과 요청 기록.',
           '- dvwa-*-sql-*.html, juice-sql-ground-truth.json: 실제 DB 조건 응답.',
           '- 설치 원문 installed-*.php 및 별도 레거시 반사 도우미 standalone-reflection.json.',
           '- 재실행·환경 종료 절차: [README.md](README.md).','',
           '## 남은 한계와 검사 전제','',
           '1. SQLi 기본 규칙은 안정적인 읽기 응답의 조건 차이를 확인한다. DB 오류만 있으면 SIGNAL이며 WAF·인증·통신 실패는 오류 또는 미실행으로 구분한다. 모든 DB 문법·인코딩·애플리케이션 문맥을 포괄하지 않는다.',
           '2. 브라우저 XSS는 실제 실행 표식으로 판정하며 인코딩·CSP 차단을 구분한다. 쿠키 읽기·외부 전송·실사용 계정 작업은 하지 않는다. 브라우저 미설치·범위 제한·후보 없음은 미실행이다.',
           '3. 저장형과 시간 기반 검사는 명시한 로컬 시나리오에서만 실행한다. 저장·조회·정리 계약 및 시간 입력이 필요하며, 전제가 없으면 NOT_RUN이다. 별도 실습 앱에서 검증했으며 이 표의 제3자 앱 6개 결과와 합치지 않는다.',
           '4. 로그인·계정 간·역할별 대조는 제공한 세션과 명시적인 비공개 필드·권한 정책이 있어야 한다. MFA·CAPTCHA·SSO 자동 로그인과 임의 사이트의 권한 정책 추론은 지원하지 않는다.',
           '5. Windows 10 + Docker Linux + Edge에서 검증했다. 운영 사이트·운영 DB·다른 OS/백신 조합의 검증은 별개다. bridge 네트워크의 완전한 외부 통신 차단을 주장하지 않는다.',
           '6. R01~R13 설계 문서의 모든 세부 항목을 구현한 것은 아니다. 이번 범위는 직전 검증 보고서의 SQLi·XSS·세션·계정·브라우저 경계·판정 상태 보완이다. 현재 지원 범위와 전제는 docs/ACTIVE_RULES.md에 기록한다.','']
    if data.get('error'):rows+=['## 실패 원인','',data['error']]
    (ROOT/'tests/benchmarks/RESULTS.md').write_text('\n'.join(rows),encoding='utf-8')


def main():
    OUT.mkdir(parents=True,exist_ok=True)
    data={'at':datetime.now().astimezone().isoformat(timespec='seconds'),'status':'FAIL','ground_truth':[],'measurements':[]}
    try:
        data['source_commit']=subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip()
        data['source_worktree_dirty']=bool(subprocess.check_output(['git','status','--porcelain'],cwd=ROOT))
        data['source_files']={file:hashlib.sha256((ROOT/file).read_bytes()).hexdigest() for file in ['agents/engine.py','agents/injection_auditor.py','agents/browser_auditor.py','agents/policy_auditor.py','core/http/requester.py','core/rules/contracts.py','core/rules/redaction.py','core/models/vulnerability.py','reporting/report_generator.py','dashboard/server.py','dashboard/static/app.js','dashboard/static/app.css','dashboard/static/index.html','surface/reflection.py','docs/RULE_DESIGN.md']}
        image_ids=subprocess.check_output(['docker','compose','-f',str(ROOT/'tests/benchmarks/compose.yaml'),'images','-q','dvwa-low','juice-shop','db'],text=True).split()
        require(len(image_ids)==3,'Three installed service images are required')
        data['images']=json.loads(subprocess.check_output(['docker','image','inspect',*image_ids],text=True))
        for file in ['sqli/source/low.php','sqli/source/impossible.php','xss_r/source/low.php','xss_r/source/impossible.php']:
            content=subprocess.check_output(['docker','compose','-f',str(ROOT/'tests/benchmarks/compose.yaml'),'exec','-T','dvwa-low','cat','/var/www/html/vulnerabilities/'+file])
            (OUT/('installed-'+file.replace('/','-'))).write_bytes(content)
        data['ground_truth']=setup_and_ground_truth()
        data['measurements']=asyncio.run(source_benchmark())
        data['exe_sha256'],exe=exe_benchmark()
        data['measurements']+=exe
        require(len(data['measurements'])==12,'Expected 6 targets each in source and exe')
        for source,exe in zip(data['measurements'][:6],data['measurements'][6:]):
            require(source['findings']==exe['findings'],source['name']+' source/exe findings differ')
        data['status']='PASS'
    except Exception as exc:
        data['error']=str(exc)
        raise
    finally:
        write('result.json',data)
        report(data)
        print(json.dumps({'status':data['status'],'ground_truth_checks':len(data['ground_truth']),'measurements':len(data['measurements']),'error':data.get('error')},ensure_ascii=False))


if __name__=='__main__':main()
