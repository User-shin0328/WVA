"""Regression contracts for reviewed false positives and real owned I/O evidence."""
import asyncio
import os
import httpx
import pytest
from agents.system_auditor import SystemAuditor
from agents.injection_auditor import InjectionAuditor
from agents.idor_auditor import IdorAndBolaAuditor
from agents.policy_auditor import PolicyAuditor
from core.graph.blackboard import SecurityBlackboard
from core.graph.attack_graph import AttackGraphEngine
from core.models.asset import HttpEndpoint
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.rules.contracts import ScanOptions, record
from core.http.requester import RequestBudget
from core.safety.governance import SafetyGovernance
from dashboard.testbed import LocalTestbed
from tests.lab.system_target import create_app
import dashboard.server as dashboard


def setup(options=None,url='http://127.0.0.1'):
    bb=SecurityBlackboard(url);gov=SafetyGovernance(url);opts=ScanOptions(**(options or {}));budget=RequestBudget(gov,opts)
    return bb,gov,opts,budget


@pytest.mark.parametrize('content',['SQL Injection Vulnerability Detected','SQL_INJECTION_PWNED','Normal documentation'])
@pytest.mark.asyncio
async def test_constant_sql_documentation_never_confirms(content):
    bb,gov,opts,budget=setup()
    bb.add_endpoint(HttpEndpoint(url=bb.target_url+'/search?q=one',path='/search',method='GET'))
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req:httpx.Response(200,text=content))) as client:
        await InjectionAuditor(bb,gov,opts).audit(client)
    assert not bb.findings
    assert bb.asset.metadata['checks'][0]['status'] in ('SIGNAL','PASS')


@pytest.mark.asyncio
async def test_default_system_checks_do_not_write_or_claim_safe():
    bb,gov,opts,budget=setup();hits=[]
    bb.add_endpoint(HttpEndpoint(url=bb.target_url+'/upload',path='/upload',method='POST'))
    def respond(req):hits.append(req);return httpx.Response(200,text='Rejected shell.php Cloud Metadata Service')
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond),event_hooks={'request':[budget.enforce]}) as client:
        await SystemAuditor(bb,gov,opts,budget).audit(client)
    assert not hits and not bb.findings
    assert all(c['status']=='NOT_RUN' and c['tested']==0 for c in bb.asset.metadata['checks'])


@pytest.mark.parametrize('kind,mode,expected',[
    ('file','vulnerable',True),('file','safe',False),
    ('command','vulnerable',True),('command','reflection',False),
    ('ssrf','vulnerable',True),('ssrf','reflection',False),('ssrf','safe',False),
    ('upload','vulnerable',True),('upload','reject',False),('upload','safe',False)])
@pytest.mark.asyncio
async def test_real_system_contracts_positive_and_defended(tmp_path,kind,mode,expected):
    app=create_app(tmp_path);lab=LocalTestbed(app);base=await lab.start()
    case={'kind':kind,'url':base+f'/{kind}/{mode}'}
    if kind=='file':case.update(control_value='guide.txt',probe_value='../canary.txt',expected_marker='WVA_BENIGN_FILE_CANARY_6e6de08c')
    if kind=='command':case['shell']='windows' if os.name=='nt' else 'posix'
    if kind=='ssrf':case.update(callback_url=base+'/callback/{marker}',receipt_url=base+'/receipt/{marker}')
    if kind=='upload':case.update(read_url=base+'/files/{filename}',cleanup_url=base+'/cleanup/ok')
    bb,gov,opts,budget=setup({'mode':'deep','system_cases':[case]},base)
    try:
        async with budget.client() as client:await SystemAuditor(bb,gov,opts,budget).audit(client)
        checks=bb.asset.metadata['checks']
        selected=next(c for c in checks if c['required'])
        assert selected['status']==('FINDING' if expected else 'PASS'),selected
        assert bool(bb.findings)==expected
        assert all(not f.yielded_postconditions for f in bb.findings.values())
        assert not app.state.files
        if kind=='upload':assert all(r['verified'] for r in bb.asset.metadata['cleanup_receipts'])
    finally:await lab.stop()


@pytest.mark.asyncio
async def test_upload_cleanup_failure_is_error(tmp_path):
    app=create_app(tmp_path);lab=LocalTestbed(app);base=await lab.start()
    bb,gov,opts,budget=setup({'mode':'deep','system_cases':[{'kind':'upload','url':base+'/upload/vulnerable','read_url':base+'/files/{filename}','cleanup_url':base+'/cleanup/fail'}]},base)
    try:
        async with budget.client() as client:
            await SystemAuditor(bb,gov,opts,budget).audit(client)
            await PolicyAuditor(bb,gov,opts,budget).teardown_lifecycle(client)
        assert next(c for c in bb.asset.metadata['checks'] if c['rule_id']=='R19')['status']=='ERROR'
        assert next(c for c in bb.asset.metadata['checks'] if c['rule_id']=='R14')['status']=='ERROR'
        assert not bb.findings
    finally:app.state.files.clear();await lab.stop()


@pytest.mark.asyncio
async def test_authenticated_owner_is_not_unauthenticated_bola():
    bb,gov,opts,budget=setup()
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda req:httpx.Response(200,json={'user_id':'1001','role':'user'})),headers={'Authorization':'Bearer local-review'}) as client:
        await IdorAndBolaAuditor(bb,gov).audit(client)
    assert not bb.findings


@pytest.mark.parametrize('failures',[1,3,5])
@pytest.mark.asyncio
async def test_concurrency_errors_are_not_pass(failures):
    bb,gov,opts,budget=setup({'mode':'deep'});count=0
    async def respond(request):
        nonlocal count
        count+=1
        if 3<=count<3+failures:raise httpx.ConnectError('owned failure',request=request)
        return httpx.Response(200,text='stable')
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:await PolicyAuditor(bb,gov,opts,budget).concurrency(client)
    result=bb.asset.metadata['checks'][0]
    assert result['status']=='ERROR' and result['errors']==failures


@pytest.mark.asyncio
async def test_teardown_requires_real_receipts():
    bb,gov,opts,budget=setup({'mode':'deep'})
    await PolicyAuditor(bb,gov,opts,budget).teardown_lifecycle(None)
    assert bb.asset.metadata['checks'][0]['status']=='NOT_RUN'
    assert bb.asset.metadata['checks'][0]['tested']==0


@pytest.mark.parametrize('mode,url',[('safe','http://127.0.0.1'),('deep','https://example.invalid')])
@pytest.mark.asyncio
async def test_explicit_system_contract_rejects_unsafe_context_without_requests(mode,url):
    bb,gov,opts,budget=setup({'mode':mode,'system_cases':[{'kind':'command','url':url+'/command'}]},url)
    hits=[]
    def respond(req):hits.append(req);return httpx.Response(200)
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:await SystemAuditor(bb,gov,opts,budget).audit(client)
    assert not hits and not bb.findings
    assert next(r for r in bb.asset.metadata['checks'] if r['rule_id']=='R17')['status']=='ERROR'


@pytest.mark.asyncio
async def test_failed_stored_cleanup_cannot_be_reported_as_pass():
    bb,gov,opts,budget=setup()
    bb.asset.metadata['cleanup_receipts']=[{'kind':'stored','attempted':True,'cleaned':False,'verified':False}]
    await PolicyAuditor(bb,gov,opts,budget).teardown_lifecycle(None)
    assert bb.asset.metadata['checks'][0]['status']=='ERROR'


@pytest.mark.asyncio
async def test_selected_options_and_lower_budget_preserved(client):
    response=await client.post('/api/scan/start',json={'target_url':'http://127.0.0.1:1','mode':'deep','consent':True,'options':{'sql':False,'browser':False,'xss':False,'max_requests':40}})
    assert response.status_code==200
    assert not dashboard.state.options.sql and not dashboard.state.options.browser
    assert dashboard.state.options.max_requests==40
    await client.post('/api/scan/stop',json={})


@pytest.mark.asyncio
async def test_http_500_is_not_a_confirmed_race_condition():
    bb,gov,opts,budget=setup({'mode':'deep'});count=0
    def respond(req):
        nonlocal count
        count+=1
        return httpx.Response(200 if count<=2 else 500,text='owned fixture')
    async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:await PolicyAuditor(bb,gov,opts,budget).concurrency(client)
    assert not bb.findings
    assert bb.asset.metadata['checks'][0]['status']=='ERROR'


@pytest.mark.parametrize('status,tested,errors,expected',[('PASS',0,0,'NOT_RUN'),('PASS',1,1,'ERROR')])
def test_check_invariants(status,tested,errors,expected):
    bb,*_=setup()
    assert record(bb,'R16','case',status,'reason',tested,errors=errors)['status']==expected


@pytest.mark.asyncio
async def test_consent_omission_and_remote_deep_rejected(client):
    assert (await client.post('/api/scan/start',json={'target_url':'http://127.0.0.1:1'})).status_code==400
    assert (await client.post('/api/scan/start',json={'target_url':'https://example.invalid','mode':'deep','consent':True})).status_code==400
    assert (await client.get('/api/scan/consent_log')).json()==[]


def finding(id,post=None,pre=None):
    return VulnerabilityFinding(id=id,vuln_type=VulnerabilityType.INFO_DISCLOSURE,severity=Severity.HIGH,title=id,endpoint='/',description='owned test',evidence='test',required_preconditions=pre or {},yielded_postconditions=post or {})


@pytest.mark.parametrize('different', ['value','session'])
def test_graph_does_not_join_unrelated_credentials(different):
    bb,*_=setup()
    artifact={'type':'api_key','value':'one-private-key','session':'anonymous'}
    wanted={**artifact,different:'other-value'}
    bb.add_finding(finding('source',{'leaked_artifact':artifact}))
    bb.add_finding(finding('access',{'privilege':'admin','privilege_verified':True},{'artifact_ref':wanted}))
    assert AttackGraphEngine(bb).find_exploit_chains()==[]


def test_graph_target_privilege_and_idempotence():
    bb,*_=setup();artifact={'type':'api_key','value':'private-key'}
    bb.add_finding(finding('source',{'leaked_artifact':artifact}))
    bb.add_finding(finding('access',{'privilege':'system','privilege_verified':True},{'artifact_ref':artifact}))
    graph=AttackGraphEngine(bb);first=graph.find_exploit_chains()
    assert first[0].attained_privilege.value=='system'
    assert len(graph.find_exploit_chains())==len(bb.chains)==1
    assert bb.chains[0].chain_id==first[0].chain_id


def test_unverified_privilege_never_creates_chain():
    bb,*_=setup();bb.add_finding(finding('not-proven',{'privilege':'system'}))
    graph=AttackGraphEngine(bb);graph.build_graph()
    assert 'STATE:system' not in graph.graph


def test_large_graph_has_a_bounded_search():
    bb,*_=setup();engine=AttackGraphEngine(bb)
    for i in range(16):
        for a in range(5):
            for b in range(5):engine.graph.add_edge(f'{i}-{a}',f'{i+1}-{b}')
    paths=list(engine.bounded_paths('0-0','16-0'))
    assert not paths and bb.asset.metadata['chain_truncated']


@pytest.mark.asyncio
async def test_authenticated_debug_response_not_claimed_public():
    from agents.config_auditor import ConfigAndHeaderAuditor
    bb,gov,*_=setup()
    response=httpx.Response(200,json={'api_key':'owned-private-key'},request=httpx.Request('GET',bb.target_url+'/debug/config',headers={'Authorization':'Bearer owned'}))
    ConfigAndHeaderAuditor(bb,gov)._inspect_debug_response(response,'/debug/config')
    assert not bb.findings


@pytest.mark.parametrize('status',['NOT_RUN','SIGNAL','ERROR'])
@pytest.mark.asyncio
async def test_required_incomplete_checks_withhold_all_grades(client,status):
    bb,*_=setup();bb.asset.metadata['checks']=[{'rule_id':'R19','title':'upload','status':status,'tested':0,'required':True}]
    dashboard.state.blackboard=bb;dashboard.state.status='completed'
    response=(await client.get('/api/scan/status')).json()
    assert response['grade'] is None and not response['assessment_complete']


@pytest.mark.asyncio
async def test_mixed_confirmed_and_inconclusive_withholds_grade(client):
    bb,*_=setup()
    for i in range(4):
        item=finding(str(i));item.severity=Severity.CRITICAL;bb.add_finding(item)
    record(bb,'R11','SQL 대조','FINDING','일부 미확정',2,1,required=True,inconclusive=1)
    dashboard.state.blackboard=bb;dashboard.state.status='completed'
    response=(await client.get('/api/scan/status')).json()
    assert response['score']<60 and response['grade'] is None and not response['assessment_complete']
