"""Opt-in test-account policies and reversible loopback-only extended probes."""
import asyncio
import hashlib
import ipaddress
import json
import statistics
import time
import uuid
from urllib.parse import urlsplit
import httpx
from bs4 import BeautifulSoup
from core.http.requester import ProbeSession
from core.rules.contracts import record
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity


def loopback(url):
    host=urlsplit(url).hostname
    if host=='localhost':return True
    try:return ipaddress.ip_address(host).is_loopback
    except ValueError:return False


async def post_form(client,url,fields):
    initial=await client.get(url)
    soup=BeautifulSoup(initial.text,'html.parser')
    hidden={node['name']:node.get('value','') for node in soup.select('input[type="hidden"][name]')}
    return await client.post(url,data={**hidden,**fields})


def protected(data,fields):
    result={}
    for field in fields:
        value=data
        try:
            for key in field.split('.'):value=value[key]
        except (KeyError,TypeError):return None
        result[field]=value
    return result


class PolicyAuditor:
    def __init__(self,bb,governance,options,budget):
        self.bb,self.gov,self.options,self.budget=bb,governance,options,budget

    def finding(self,kind,url,title,evidence,cwe,post=None):
        key=hashlib.sha256((url+title).encode()).hexdigest()[:12]
        self.bb.add_finding(VulnerabilityFinding(id='VULN-POLICY-'+key,vuln_type=kind,title=title,severity=Severity.HIGH,
            endpoint=urlsplit(url).path or '/',request_url=url,description=title,evidence=evidence,cwe_id=cwe,cvss_score=8.1,
            yielded_postconditions=post or {},remediation='해당 객체·역할의 서버 권한 검사와 입력·출력 처리를 보완하고 동일 계정 정책으로 재검증합니다.'))

    async def audit(self,client,browser):
        await self.access()
        await self.timing(client)
        await self.stored(client,browser)
        await self.concurrency(client)
        await self.teardown_lifecycle(client)

    async def access(self):
        clients={};errors=[];results={'object':[0,0],'role':[0,0]}
        try:
            for profile in self.options.sessions:
                if profile.alias in clients or profile.alias=='anonymous':raise ValueError('세션 별칭이 중복되거나 anonymous 예약 별칭입니다.')
                headers={k:v.get_secret_value() for k,v in profile.headers.items()}
                cookies={k:v.get_secret_value() for k,v in profile.cookies.items()}
                client=self.budget.client(headers=headers,cookies=cookies)
                clients[profile.alias]=client
                if profile.login_url:
                    self.budget.allow_post(profile.login_url)
                    response=await post_form(client,profile.login_url,{k:v.get_secret_value() for k,v in profile.login_fields.items()})
                    if response.status_code>=400:raise ValueError('테스트 계정 로그인 실패: '+profile.alias)
            clients['anonymous']=self.budget.client()
            for case in self.options.access_cases:
                try:
                    if case.owner not in clients or any(alias not in clients for alias in case.denied):raise ValueError('정책에 필요한 계정 별칭이 없습니다.')
                    first=await clients[case.owner].get(case.url)
                    second=await clients[case.owner].get(case.url)
                    expected=protected(first.json(),case.protected_fields) if first.status_code==200 else None
                    if expected is None or not any(v not in (None, '', [], {}) for v in expected.values()) or second.status_code!=200 or expected!=protected(second.json(),case.protected_fields):raise ValueError('소유자/관리자의 보호 데이터 기준 응답이 없거나 불안정합니다.')
                    for alias in case.denied:
                        responses=[await clients[alias].get(case.url) for _ in range(2)]
                        if any(r.status_code not in (200,401,403,404) for r in responses):raise ValueError('거부 계정 응답의 오류 또는 이동으로 대조를 완료하지 못했습니다.')
                        results[case.kind][0]+=1
                        exposed=all(r.status_code==200 for r in responses)
                        if exposed:
                            try:exposed=all(protected(r.json(),case.protected_fields)==expected for r in responses)
                            except ValueError:exposed=False
                        if exposed:
                            results[case.kind][1]+=1
                            self.finding(VulnerabilityType.BOLA_IDOR if case.kind=='object' else VulnerabilityType.AUTH_BYPASS,case.url,
                                '계정 간 비공개 객체 노출 확인' if case.kind=='object' else '역할별 보호 응답 접근 확인',
                                f'owner={case.owner}; denied_alias={alias}; protected fields={case.protected_fields}; exact protected data matches; policy explicitly declares denial; values omitted',
                                'CWE-639' if case.kind=='object' else 'CWE-862')
                except Exception as exc:errors.append(type(exc).__name__+': '+str(exc)[:100])
        except Exception as exc:errors.append(type(exc).__name__+': '+str(exc)[:100])
        finally:
            for client in clients.values():await client.aclose()
        for kind,id,title in [('object','R09','계정 간 객체 권한 대조'),('role','R10','역할별 관리 응답 대조')]:
            tested,found=results[kind]
            status='FINDING' if found else 'ERROR' if errors else 'PASS' if tested else 'NOT_RUN'
            record(self.bb,id,title,status,'; '.join(errors[:2]) if errors else f'정책 대조 {tested}회, 노출 {found}건.' if tested else '소유권·역할 정책과 테스트 세션을 지정하지 않았습니다.',tested,found,errors=len(errors))

    async def timing(self,client):
        tested=found=0;errors=[]
        for case in self.options.timing_cases:
            try:
                if not loopback(case.url):raise ValueError('시간 대조는 명시한 로컬 실습 대상에서만 실행합니다.')
                times=[[],[]]
                for _ in range(3):
                    for index,value in enumerate([case.false_value,case.true_value]):
                        start=time.perf_counter()
                        response=await asyncio.wait_for(ProbeSession(client).get(case.url,{case.parameter:value}),timeout=case.delay+2)
                        if response.status_code!=200:raise ValueError('정상 시간 대조 응답이 없습니다.')
                        times[index].append(time.perf_counter()-start)
                tested+=1
                baseline,delayed=map(statistics.median,times)
                stable=max(times[0])-min(times[0])<case.delay*.5
                if stable and delayed-baseline>=case.delay*.75 and all(b-a>=case.delay*.65 for a,b in zip(*times)):
                    found+=1
                    self.finding(VulnerabilityType.SQL_INJECTION,case.url,'시간 기반 SQL 조건 차이 확인',
                        f'parameter={case.parameter}; paired repeats=3; baseline median={baseline:.3f}s; conditional median={delayed:.3f}s; expected delay={case.delay}s; local declared fixture only','CWE-89')
                elif not stable:errors.append('대조 응답의 지터가 커서 시간 차이를 확정하지 않았습니다.')
            except Exception as exc:errors.append(type(exc).__name__+': '+str(exc)[:100])
        record(self.bb,'R11-T','시간 기반 SQL 조건 대조','FINDING' if found else 'ERROR' if errors else 'PASS' if tested else 'NOT_RUN',
               '; '.join(errors[:2]) if errors else f'3쌍 반복 대조 {tested}개, 확인 {found}건.' if tested else '로컬 시간 대조 시나리오를 지정하지 않았습니다.',tested,found,errors=len(errors))

    async def stored(self,client,browser_auditor):
        tested=found=0;errors=[]
        if self.options.stored_cases and not self.options.browser:
            record(self.bb,'R12-S','저장형 XSS 실행 대조','NOT_RUN','브라우저 검사를 먼저 켜세요. 저장 요청을 전송하지 않았습니다.');return
        for case in self.options.stored_cases:
            dirty=False
            receipt={'kind':'stored','attempted':False,'cleaned':False,'verified':False}
            self.bb.asset.metadata.setdefault('cleanup_receipts',[]).append(receipt)
            try:
                urls=[case.write_url,case.read_url,case.cleanup_url]
                if not all(loopback(url) and self.gov.is_in_scope(url) for url in urls):raise ValueError('저장형 검사는 범위 안의 명시한 로컬 실습 URL만 사용합니다.')
                from playwright.async_api import async_playwright
                from agents.browser_auditor import browser_executable
                async with async_playwright() as playwright:
                    # Launch first, so a missing browser cannot leave a stored test record.
                    browser=await playwright.chromium.launch(executable_path=browser_executable() or playwright.chromium.executable_path,headless=True,chromium_sandbox=True)
                    try:
                        self.budget.allow_post(case.write_url);self.budget.allow_post(case.cleanup_url)
                        marker=uuid.uuid4().hex;variable='__wva_'+uuid.uuid4().hex[:10]
                        fields={**case.fields,case.field:f'<script>window.{variable}="{marker}"</script>','wva_marker':marker}
                        dirty=True
                        receipt['attempted']=True
                        result=await post_form(client,case.write_url,fields)
                        if result.status_code>=400:raise ValueError('실습 저장 요청 실패')
                        context=await browser_auditor.context(browser,client)
                        try:
                            page=await context.new_page();await page.goto(case.read_url,wait_until='domcontentloaded',timeout=12000)
                            await page.wait_for_timeout(200)
                            tested+=1
                            if await page.evaluate('(p)=>window[p.variable]===p.marker',{'variable':variable,'marker':marker}) and self.gov.is_in_scope(page.url):
                                 found+=1
                                 self.finding(VulnerabilityType.XSS,case.read_url,'저장형 XSS 실행 확인',f'stored execution witness={marker}; separate read request; declared local fixture; cleanup attempted','CWE-79')
                        finally:await browser_auditor.close_context(context)
                    finally:await browser.close()
            except Exception as exc:errors.append(type(exc).__name__+': '+str(exc)[:100])
            finally:
                if dirty:
                    try:
                        cleaned=await post_form(client,case.cleanup_url,{**case.fields,'wva_marker':marker})
                        if cleaned.status_code>=400:raise ValueError('실습 표식 정리 응답 실패')
                        receipt['cleaned']=True
                        check=await client.get(case.read_url)
                        if check.status_code not in (200,404):raise ValueError('정리 후 조회 응답을 확인하지 못했습니다.')
                        if marker in check.text:raise ValueError('정리 후에도 저장 표식이 남아 있습니다.')
                        receipt['verified']=True
                    except Exception as exc:errors.append('정리 확인 실패: '+str(exc)[:100])
        record(self.bb,'R12-S','저장형 XSS 실행 대조','FINDING' if found else 'ERROR' if errors else 'PASS' if tested else 'NOT_RUN',
               '; '.join(errors[:2]) if errors else f'저장·별도 조회·정리 대조 {tested}개, 실행 {found}건.' if tested else '저장·조회·정리 URL을 가진 로컬 시나리오를 지정하지 않았습니다.',tested,found,errors=len(errors))

    async def concurrency(self,client):
        mode = getattr(self.options, 'mode', 'safe')
        if mode != 'deep' or not self.options.concurrency_check:
            record(self.bb,'R15','동시성 및 상태 일관성 대조','NOT_RUN','운영 안전 모드에서는 동시성 부하 검사를 수행하지 않습니다. 샌드박스 모드를 선택하세요.')
            return
        if not loopback(self.gov.target_base_url):
            record(self.bb,'R15','동시성 및 상태 일관성 대조','ERROR','명시한 로컬 대상에서만 동시 요청을 대조합니다.',errors=1);return
        candidates = [ep.url for ep in self.bb.asset.endpoints if ep.method=='GET' and ep.parameters and self.gov.is_in_scope(ep.url)]
        if not candidates:
            candidates = [self.gov.target_base_url]
        tested = signals = 0
        errors = []
        for url in candidates[:3]:
            try:
                from core.http.requester import fingerprint
                baseline=[await client.get(url,timeout=4.0) for _ in range(2)]
                if any(r.status_code!=200 for r in baseline):raise ValueError('정상 단일 요청 기준 응답이 없습니다.')
                stable=fingerprint(baseline[0])==fingerprint(baseline[1])
                responses = await asyncio.gather(*[client.get(url, timeout=4.0) for _ in range(5)], return_exceptions=True)
                errors.extend(type(r).__name__ for r in responses if isinstance(r,BaseException))
                valid = [r for r in responses if hasattr(r, 'status_code')]
                errors.extend(f'HTTP {r.status_code}' for r in valid if r.status_code!=200)
                if len(valid)==5 and all(r.status_code==200 for r in valid):
                    tested += 1
                    if not stable or any(fingerprint(r)!=fingerprint(baseline[0]) for r in valid):signals+=1
            except Exception as exc:
                errors.append(str(exc)[:60])
        status = 'ERROR' if errors else 'SIGNAL' if signals else 'PASS' if tested else 'NOT_RUN'
        reason = f'단일 2회·동시 5회 대조 {tested}개 완료, 응답 변동 {signals}개, 오류 {len(errors)}개. 응답 차이만으로 경쟁 상태를 확정하지 않습니다.'
        record(self.bb, 'R15', '동시성 및 상태 일관성 대조', status, reason, tested, errors=len(errors))

    async def teardown_lifecycle(self,client):
        receipts=self.bb.asset.metadata.get('cleanup_receipts',[])
        attempted=[r for r in receipts if r['attempted']]
        verified=[r for r in attempted if r['cleaned'] and r['verified']]
        failed=len(attempted)-len(verified)
        record(self.bb,'R14','테스트 데이터 생성 및 정리 생명주기',
               'ERROR' if failed else 'PASS' if verified else 'NOT_RUN',
               f'실제 작업 {len(attempted)}개, 정리·부재 확인 {len(verified)}개, 미확인 {failed}개. 실행하지 않은 작업은 성공으로 표시하지 않습니다.',
               len(verified),errors=failed,required=bool(attempted))
