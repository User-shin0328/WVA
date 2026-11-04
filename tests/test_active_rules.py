import asyncio
import json
import pytest
from fastapi import FastAPI
from agents.engine import VulnerabilityAnalysisEngine
from core.http.requester import RequestBudget, ResourceLimit, ProbeSession
from core.rules.contracts import ScanOptions
from core.safety.governance import SafetyGovernance
from dashboard.testbed import LocalTestbed
from tests.lab.advanced_target import create_app
from reporting.report_generator import SecurityReportGenerator
import dashboard.server as dashboard


@pytest.fixture
def lab_app():return create_app()


@pytest.mark.parametrize('path,expected,status', [('sql',True,'FINDING'),('safe-sql',False,'PASS'),('unstable',False,'SIGNAL'),('waf',False,'ERROR'),('db-error',False,'SIGNAL')])
@pytest.mark.asyncio
async def test_sql_actual_sqlite_and_negative_conditions(path,expected,status,lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        bb=await VulnerabilityAnalysisEngine(base+'/'+path+'?id=1',options={'browser':False,'xss':False,'parameters':['id']}).execute_audit()
        assert any(f.vuln_type.value=='SQL_INJECTION' for f in bb.findings.values())==expected
        assert next(r for r in bb.asset.metadata['checks'] if r['rule_id']=='R11')['status']==status
    finally:await lab.stop()


@pytest.mark.parametrize('path,expected', [('reflected',True),('safe-reflected',False),('csp-reflected',False),('spa/#/search?q=baseline',True)])
@pytest.mark.asyncio
async def test_browser_execution_encoding_csp_and_dom(path,expected,lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        url=base+'/'+path+('' if '#' in path else '?name=baseline')
        bb=await VulnerabilityAnalysisEngine(url,options={'sql':False}).execute_audit()
        assert any(f.vuln_type.value=='XSS' for f in bb.findings.values())==expected
        result=next(r for r in bb.asset.metadata['checks'] if r['rule_id']=='R12')
        assert result['status']==('FINDING' if expected else 'PASS'),result
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_browser_enforces_external_path_post_and_websocket_boundaries():
    sink=FastAPI();hits=[]
    @sink.get('/sink')
    async def external():hits.append(True);return {}
    external_lab=LocalTestbed(sink);outside=await external_lab.start()
    app=create_app(outside+'/sink');lab=LocalTestbed(app);base=await lab.start()
    try:
        bb=await VulnerabilityAnalysisEngine(base+'/boundary/?name=baseline',options={'sql':False}).execute_audit()
        assert any(f.vuln_type.value=='XSS' for f in bb.findings.values())
        assert hits==[]
        assert not any(path=='/outside' or method in ('POST','WS') for method,path in app.state.hits)
    finally:await lab.stop();await external_lab.stop()


@pytest.mark.asyncio
async def test_response_and_request_caps_are_actual_boundaries(lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        budget=RequestBudget(SafetyGovernance(base),ScanOptions(max_requests=40,max_response_bytes=64000))
        async with budget.client() as client:
            with pytest.raises(ResourceLimit):await client.get(base+'/oversize')
            budget.count=40
            with pytest.raises(ResourceLimit):await client.get(base+'/')
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_csrf_get_refresh_preserves_unrelated_repeated_query(lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        budget=RequestBudget(SafetyGovernance(base),ScanOptions())
        async with budget.client() as client:
            url=await ProbeSession(client).prepare(base+'/reflected?name=old&tag=a&tag=b&lang=ko',{'name':'new'})
            from urllib.parse import parse_qs,urlsplit
            assert parse_qs(urlsplit(url).query)=={'name':['new'],'tag':['a','b'],'lang':['ko']}
    finally:await lab.stop()


def profiles(base):
    return [{'alias':alias,'login_url':base+'/login','login_fields':{'username':alias,'password':'local-only-'+alias}} for alias in ['A','B','admin']]


@pytest.mark.asyncio
async def test_real_login_csrf_and_private_object_role_policy(lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        cases=[{'url':base+f'/{kind}/{mode}','owner':'A' if kind=='object' else 'admin','denied':['B','anonymous'],'protected_fields':['private_record'],'kind':kind} for kind in ['object','role'] for mode in ['vulnerable','safe']]
        bb=await VulnerabilityAnalysisEngine(base,options={'sql':False,'xss':False,'browser':False,'sessions':profiles(base),'access_cases':cases}).execute_audit()
        assert sum('계정 간 비공개' in f.title for f in bb.findings.values())==1
        assert sum('역할별 보호' in f.title for f in bb.findings.values())==1
        serialized=json.dumps(SecurityReportGenerator(bb).generate_json_report())+SecurityReportGenerator(bb).generate_markdown_report()
        assert 'local-only-' not in serialized and 'wva-session-' not in serialized
        assert sum(method=='POST' and path=='/login' for method,path in lab_app.state.hits)==3
    finally:await lab.stop()


@pytest.mark.parametrize('safe', [False,True])
@pytest.mark.asyncio
async def test_stored_xss_separate_read_and_verified_cleanup(safe,lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        case={'write_url':base+'/stored/write','read_url':base+'/stored/read?record_id=wva-probe&safe='+str(safe).lower(),'cleanup_url':base+'/stored/cleanup','field':'message','fields':{'record_id':'wva-probe'}}
        bb=await VulnerabilityAnalysisEngine(base,options={'sql':False,'xss':False,'stored_cases':[case]}).execute_audit()
        assert any('저장형' in f.title for f in bb.findings.values()) is (not safe)
        assert lab_app.state.stored=={}
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_timing_uses_real_sqlite_conditional_delay(lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        case={'url':base+'/timing?id=1','parameter':'id','true_value':'(CASE WHEN 1=1 THEN wva_delay(0.3) ELSE 0 END)+1','false_value':'(CASE WHEN 1=2 THEN wva_delay(0.3) ELSE 0 END)+1','delay':.3}
        bb=await VulnerabilityAnalysisEngine(base,options={'sql':False,'xss':False,'browser':False,'timing_cases':[case]}).execute_audit()
        assert any('시간 기반' in f.title for f in bb.findings.values())
    finally:await lab.stop()


@pytest.mark.parametrize('rule,status',[('R11','NOT_RUN'),('R09','ERROR')])
@pytest.mark.asyncio
async def test_partial_check_does_not_receive_a_grade(client,rule,status):
    from core.graph.blackboard import SecurityBlackboard
    dashboard.state.status='completed';dashboard.state.blackboard=SecurityBlackboard('http://localhost')
    dashboard.state.blackboard.asset.metadata['checks']=[{'rule_id':rule,'title':'SQL or account policy','status':status}]
    result=(await client.get('/api/scan/status')).json()
    assert result['score']==100 and result['grade'] is None and not result['assessment_complete']


@pytest.mark.asyncio
async def test_extended_probes_reject_external_targets_without_post(lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        bb=await VulnerabilityAnalysisEngine(base,options={'sql':False,'xss':False,'browser':False,'timing_cases':[{'url':'http://example.com/timing','parameter':'id','true_value':'1','false_value':'2'}]}).execute_audit()
        assert next(r for r in bb.asset.metadata['checks'] if r['rule_id']=='R11-T')['status']=='ERROR'
        assert not any(method=='POST' for method,path in lab_app.state.hits)
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_missing_browser_is_not_run_instead_of_a_pass(monkeypatch,lab_app):
    import agents.browser_auditor as module
    monkeypatch.setattr(module,'browser_executable',lambda:'/missing/wva-browser.exe')
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        bb=await VulnerabilityAnalysisEngine(base+'/reflected?name=baseline',options={'sql':False}).execute_audit()
        assert next(r for r in bb.asset.metadata['checks'] if r['rule_id']=='R12')['status']=='NOT_RUN'
        assert not any(f.vuln_type.value=='XSS' for f in bb.findings.values())
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_cancel_stored_check_still_removes_owned_record(lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    case={'write_url':base+'/stored/write','read_url':base+'/stored/read?record_id=cancel-test','cleanup_url':base+'/stored/cleanup','field':'message','fields':{'record_id':'cancel-test'}}
    task=asyncio.create_task(VulnerabilityAnalysisEngine(base,options={'sql':False,'xss':False,'stored_cases':[case]}).execute_audit())
    try:
        for _ in range(600):
            if lab_app.state.stored:break
            if task.done():await task;pytest.fail('Check ended before cancellation')
            await asyncio.sleep(.01)
        assert lab_app.state.stored
        task.cancel()
        with pytest.raises(asyncio.CancelledError):await task
        assert lab_app.state.stored=={}
    finally:
        if not task.done():task.cancel()
        await lab.stop()


@pytest.mark.asyncio
async def test_primary_session_is_used_for_normal_scan(lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        engine=VulnerabilityAnalysisEngine(base+'/object/safe',scope_mode='origin',options={'sql':False,'browser':False,'sessions':profiles(base),'primary_session':'A'})
        bb=await engine.execute_audit()
        entry=next(e for e in bb.asset.endpoints if e.path=='/object/safe')
        assert entry.status_code==200
        assert not any(f.id.startswith('VULN-CSP') for f in bb.findings.values()),'JSON API alone is not an HTML CSP finding'
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_validation_does_not_echo_profile_secrets(client):
    response=await client.post('/api/scan/start',json={'options':{'sessions':[{'alias':'A','headers':{'X-Unsupported':'DO_NOT_ECHO_PRIVATE_VALUE'}}]}})
    assert response.status_code==422
    assert 'DO_NOT_ECHO_PRIVATE_VALUE' not in response.text


@pytest.mark.asyncio
async def test_session_rescan_uses_the_same_redacted_comparison_profile(client,lab_app):
    lab=LocalTestbed(lab_app);base=await lab.start()
    try:
        options={'sql':False,'xss':False,'browser':False,'sessions':[profiles(base)[2]]}
        for _ in range(2):
            assert (await client.post('/api/scan/start',json={'consent': True, 'target_url':base,'scope_mode':'origin','options':options})).status_code==200
            for _ in range(400):
                status=(await client.get('/api/scan/status')).json()
                if status['status']!='running':break
                await asyncio.sleep(.025)
            assert status['status']=='completed'
        diff=(await client.get('/api/scan/diff')).json()
        assert diff['has_previous'] and diff['new_count']==diff['fixed_count']==0
        assert diff['current_grade']==diff['previous_grade']=='A'
        assert not any(c['required'] for c in status['checks'] if c['rule_id'] in ('R11','R12'))
    finally:await lab.stop()
