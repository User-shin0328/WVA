import json
import os
import httpx
import pytest
from agents.engine import VulnerabilityAnalysisEngine
from agents.exposure_auditor import ExposureAuditor
from agents.injection_auditor import InjectionAuditor
from core.graph.blackboard import SecurityBlackboard
from core.http.requester import RequestBudget
from core.models.asset import HttpEndpoint
from core.models.vulnerability import VulnerabilityFinding,VulnerabilityType,Severity
from core.rules.contracts import ScanOptions
from core.rules.retest import verify
from core.safety.governance import SafetyGovernance
from dashboard.testbed import LocalTestbed
from reporting.report_generator import SecurityReportGenerator
from tests.lab.workflow_target import create_app
import dashboard.server as dashboard


@pytest.mark.asyncio
async def test_common_parameter_reaches_actual_sqlite_without_declared_input():
    app=create_app();lab=LocalTestbed(app);base=await lab.start()
    try:
        bb=await VulnerabilityAnalysisEngine(base,options={'browser':False,'xss':False,'exposure':False}).execute_audit()
        sql=next(f for f in bb.findings.values() if f.vuln_type==VulnerabilityType.SQL_INJECTION)
        assert sql.verification_context['parameter']=='id'
        assert bb.asset.metadata['sql_candidates']['tested']>=1
        assert all(path=='/' or path.startswith('/') for _,path,_ in app.state.hits)
        assert len(app.state.hits)<450
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_guessed_but_ignored_parameters_are_not_pass():
    bb=SecurityBlackboard('http://127.0.0.1/');bb.add_endpoint(HttpEndpoint(url=bb.target_url,path='/',method='GET'))
    opts=ScanOptions(browser=False,xss=False)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda request:httpx.Response(200,text='static page'))) as client:
        await InjectionAuditor(bb,SafetyGovernance(bb.target_url),opts).audit(client)
    check=bb.asset.metadata['checks'][0]
    assert check['status']=='NOT_RUN' and check['tested']==0 and not bb.findings
    assert len(bb.asset.metadata['sql_candidates']['preflight'])==6


@pytest.mark.parametrize('fixed',[False,True])
@pytest.mark.asyncio
async def test_exposure_positive_defended_and_values_not_exported(fixed):
    app=create_app();app.state.fixed=fixed;lab=LocalTestbed(app);base=await lab.start()
    try:
        bb=SecurityBlackboard(base);gov=SafetyGovernance(base);budget=RequestBudget(gov,ScanOptions())
        async with budget.client() as client:await ExposureAuditor(bb,gov).audit(client)
        assert len(bb.findings)==(0 if fixed else 3)
        text=json.dumps(SecurityReportGenerator(bb).generate_json_report())
        assert 'owned-private-password' not in text and 'owned-private-api-key' not in text
        assert all(c['status']==('PASS' if fixed else 'FINDING') for c in bb.asset.metadata['checks'])
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_html_fallback_does_not_become_exposure():
    bb=SecurityBlackboard('http://127.0.0.1');gov=SafetyGovernance(bb.target_url)
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r:httpx.Response(200,text='<h1>SECRET_KEY=not-a-real-secret</h1>',headers={'content-type':'text/html'}))) as client:await ExposureAuditor(bb,gov).audit(client)
    assert not bb.findings


@pytest.mark.asyncio
async def test_sql_retest_repeats_original_rule_and_does_not_claim_fixed():
    app=create_app();lab=LocalTestbed(app);base=await lab.start()
    try:
        engine=VulnerabilityAnalysisEngine(base,options={'browser':False,'xss':False,'exposure':False});bb=await engine.execute_audit()
        finding=next(f for f in bb.findings.values() if f.vuln_type==VulnerabilityType.SQL_INJECTION)
        budget=RequestBudget(engine.governance,engine.options)
        async with budget.client() as client:
            assert (await verify(finding,client,engine.governance,engine.options))[0]=='STILL_VULNERABLE'
            app.state.fixed=True
            assert (await verify(finding,client,engine.governance,engine.options))[0]=='NOT_REPRODUCED'
            app.state.code=403
            with pytest.raises(ValueError):await verify(finding,client,engine.governance,engine.options)
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_header_retest_requires_exact_header_not_hsts_for_csp():
    app=create_app();lab=LocalTestbed(app);base=await lab.start();gov=SafetyGovernance(base);options=ScanOptions()
    finding=VulnerabilityFinding(id='VULN-CSP-1',vuln_type=VulnerabilityType.MISSING_SECURITY_HEADER,severity=Severity.LOW,title='Missing CSP',endpoint='/',request_url=base,description='test',evidence='test')
    try:
        async with RequestBudget(gov,options).client() as client:
            assert (await verify(finding,client,gov,options))[0]=='STILL_VULNERABLE'
            app.state.csp=True
            assert (await verify(finding,client,gov,options))[0]=='NOT_REPRODUCED'
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_completed_reference_grade_visible_with_pending_assessment(client):
    bb=SecurityBlackboard('http://127.0.0.1');bb.asset.metadata['checks']=[{'rule_id':'R11','title':'SQL','status':'NOT_RUN','tested':0,'required':True}]
    dashboard.state.blackboard=bb;dashboard.state.status='completed'
    data=(await client.get('/api/scan/status')).json()
    assert data['finding_grade']=='A' and data['grade'] is None and not data['assessment_complete']
    assert data['pending_checks']==['SQL']


@pytest.mark.asyncio
async def test_account_context_is_stable_private_and_sensitive_to_changes(client):
    def profile(token):
        engine=VulnerabilityAnalysisEngine('http://127.0.0.1',options={'sessions':[{'alias':'A','headers':{'Authorization':'Bearer '+token}}]})
        return dashboard.comparison_profile(engine)
    first=profile('owned-first-secret')
    assert first==profile('owned-first-secret')
    assert first!=profile('owned-second-secret')
    assert 'owned-first-secret' not in json.dumps(first)


def test_previous_report_uses_completed_time_not_copy_time(tmp_path,monkeypatch):
    monkeypatch.setenv('WVA_DATA_DIR',str(tmp_path));folder=tmp_path/'reports';folder.mkdir();profile={'ruleset':'2.7.0'}
    for index,stamp in enumerate(['2026-11-01T00:00:00+00:00','2026-11-02T00:00:00+00:00']):
        data={'schema':'wva-report-2','target_url':'http://127.0.0.1','scan_metadata':{'scan_id':str(index),'completed':True,'completed_at':stamp,'profile':profile}}
        path=folder/f'report_{index}.json';path.write_text(json.dumps(data),encoding='utf-8');os.utime(path,(100-index,100-index))
    assert dashboard.get_previous_scan_report('http://127.0.0.1','new',profile)['scan_metadata']['scan_id']=='1'
