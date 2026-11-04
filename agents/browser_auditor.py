"""XSS execution witnesses behind the same bounded HTTP requester as the scan."""
import asyncio
import hashlib
import os
from pathlib import Path
import uuid
from contextlib import suppress
from urllib.parse import urlsplit, urlunsplit, parse_qs, parse_qsl, urlencode
from core.http.requester import ProbeSession, replace_query
from core.rules.contracts import record
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity


def browser_executable():
    options=[os.environ.get('WVA_BROWSER','')]
    for base in [os.environ.get('PROGRAMFILES(X86)','C:/Program Files (x86)'),os.environ.get('PROGRAMFILES','C:/Program Files')]:
        options.extend([base+'/Microsoft/Edge/Application/msedge.exe',base+'/Google/Chrome/Application/chrome.exe'])
    return next((p for p in options if p and Path(p).is_file()),None)


class BrowserAuditor:
    def __init__(self,bb,governance,options,budget):
        self.bb,self.gov,self.options,self.budget=bb,governance,options,budget
        self.blocked=0
        self.executions=[]

    async def close_context(self,context):
        # Block native networking before removing routes, then ignore callbacks invalidated by teardown.
        context._wva_closing=True
        with suppress(Exception):await context.set_offline(True)
        pending=list(context._wva_pending)
        if pending:await asyncio.wait(pending,timeout=6)
        with suppress(Exception):await context.unroute_all(behavior='ignoreErrors')
        await context.close()

    async def context(self,browser,client):
        context=await browser.new_context(service_workers='block',accept_downloads=False,ignore_https_errors=False)
        context._wva_pending=set()
        context._wva_closing=False
        async def handle_request(route):
            if context._wva_closing:return
            request=route.request
            if request.method not in ('GET','HEAD') or not self.gov.is_in_scope(request.url) or not self.gov.is_safe_endpoint(urlsplit(request.url).path):
                self.blocked+=1
                with suppress(Exception):await route.abort()
                return
            try:
                headers={k:v for k,v in request.headers.items() if k.lower() not in ('host','cookie','content-length','connection','accept-encoding')}
                headers['accept-encoding']='identity'
                response=await client.request(request.method,request.url,headers=headers)
                # Cookies stay in the client jar; the private context receives only target cookies.
                filtered={k:v for k,v in response.headers.items() if k.lower() not in ('content-length','transfer-encoding','content-encoding','connection')}
                await route.fulfill(status=response.status_code,headers=filtered,body=response.content)
            except Exception:
                self.blocked+=1
                if not context._wva_closing:
                    with suppress(Exception):await route.abort()
        async def route_handler(route):
            task=asyncio.current_task();context._wva_pending.add(task)
            try:await handle_request(route)
            finally:context._wva_pending.discard(task)
        await context.route('**/*',route_handler)
        async def close_socket(socket):
            self.blocked+=1
            with suppress(Exception):await socket.close()
        await context.route_web_socket('**/*',close_socket)
        context.on('page',lambda page:page.on('dialog',lambda dialog:dialog.dismiss()))
        return context

    async def audit(self,client,reflections):
        if not self.options.browser or not self.options.xss:
            record(self.bb,'R12','브라우저 XSS 실행 확인','NOT_RUN','사용자가 브라우저 또는 XSS 검사를 끄었습니다.');return
        items=[(r['url'],r['parameter'],'reflected') for r in reflections]
        target=self.bb.target_url
        # A hash route is a browser URL; it is never mistaken for a server-side path.
        fragment=urlsplit(target).fragment
        if fragment:
            params=parse_qs(urlsplit(fragment).query,keep_blank_values=True)
            for param in params:
                if not self.options.parameters or param in self.options.parameters:items.append((target,param,'dom'))
        # Discover the SPA's actual landing URL and its links, rather than inventing routes.
        needs_discovery=any(ep.source=='script_parser' or 'script_parser' in ep.sources for ep in self.bb.asset.endpoints)
        if not items and not needs_discovery:
            record(self.bb,'R12','브라우저 XSS 실행 확인','NOT_RUN','범위 안에서 HTML 반사 또는 JavaScript 라우트 후보가 없습니다.');return
        found=0;tested=0;errors=[]
        try:
            from playwright.async_api import async_playwright
            async with async_playwright() as playwright:
                executable=browser_executable() or playwright.chromium.executable_path
                if not Path(executable).is_file():
                    record(self.bb,'R12','브라우저 XSS 실행 확인','NOT_RUN','지원 브라우저가 없습니다. Edge·Chrome 또는 Playwright Chromium을 설치하세요.');return
                browser=await playwright.chromium.launch(executable_path=executable,headless=True,chromium_sandbox=True,args=['--disable-background-networking','--force-webrtc-ip-handling-policy=disable_non_proxied_udp'])
                try:
                    if needs_discovery and not fragment:
                        context=await self.context(browser,client)
                        try:
                            page=await context.new_page()
                            await page.goto(target,wait_until='domcontentloaded',timeout=12000)
                            with suppress(Exception):await page.locator('a[href],button,input').first.wait_for(state='attached',timeout=3500)
                            opener=page.locator('button[aria-label*="open search" i],button[aria-label="search" i]')
                            if await opener.count():
                                # Operate the rendered search control to learn its actual route/parameter.
                                await opener.first.evaluate('(node)=>node.click()')
                                field=page.locator('input:not([type="password"]):not([type="hidden"]):visible')
                                if await field.count():
                                    await field.first.fill('WVA_baseline');await field.first.press('Enter')
                                    with suppress(Exception):await page.wait_for_url(lambda url:bool(urlsplit(urlsplit(str(url)).fragment).query),timeout=1800)
                            routes=await page.locator('a[href]').evaluate_all('(nodes)=>nodes.map(n=>n.href)')
                            routes=[page.url,*routes]
                            for url in routes[:40]:
                                p=urlsplit(url)
                                if not p.fragment.startswith(('/','!/')) or not self.gov.is_in_scope(url):continue
                                query=parse_qs(urlsplit(p.fragment).query,keep_blank_values=True)
                                for param in query:items.append((url,param,'dom'))
                            # A rendered search control provides a real candidate even when the landing route has no query yet.
                            if '#/' in page.url and await page.locator('input[type="search"],input[placeholder*="Search"],input[aria-label*="Search"]').count():
                                items.append((page.url,'q','dom'))
                        except Exception as exc:errors.append(type(exc).__name__)
                        finally:await self.close_context(context)
                    for url,param,kind in list(dict.fromkeys(items))[:8]:
                        nonce=uuid.uuid4().hex
                        variable='__wva_'+uuid.uuid4().hex[:10]
                        code=f"window.{variable}='{nonce}'"
                        # Two ordinary HTML sinks: script text and a same-document iframe URL.
                        payloads=[f'<script>{code}</script>',f'<iframe src="javascript:parent.{variable}=\'{nonce}\'"></iframe>']
                        for payload in payloads:
                            context=await self.context(browser,client)
                            try:
                                if kind=='dom':
                                    parsed=urlsplit(url)
                                    part=replace_query(parsed.fragment,{param:payload})
                                    test_url=urlunsplit((parsed.scheme,parsed.netloc,parsed.path,parsed.query,part))
                                else:test_url=await ProbeSession(client).prepare(url,{param:payload})
                                page=await context.new_page()
                                await page.goto(test_url,wait_until='domcontentloaded',timeout=12000)
                                tested+=1
                                try:await page.wait_for_function('(p)=>window[p.variable]===p.nonce',arg={'variable':variable,'nonce':nonce},timeout=1200)
                                except Exception:pass
                                executed=await page.evaluate('(p)=>window[p.variable]===p.nonce',{'variable':variable,'nonce':nonce})
                                if executed and self.gov.is_in_scope(page.url):
                                    key=hashlib.sha256((urlsplit(url).path+':'+param+':'+kind).encode()).hexdigest()[:12]
                                    self.bb.add_finding(VulnerabilityFinding(id='VULN-XSS-'+key,vuln_type=VulnerabilityType.XSS,
                                        title='DOM XSS 실행 확인' if kind=='dom' else '반사형 XSS 실행 확인',severity=Severity.HIGH,
                                        endpoint=urlsplit(url).path or '/',request_url=url,cwe_id='CWE-79',cvss_score=8.1,
                                        description='격리된 브라우저 문서에서 입력한 고유 실행 표식이 확인됐습니다. 쿠키 읽기나 외부 전송은 수행하지 않았습니다.',
                                        evidence=f'kind={kind}; parameter={param}; execution witness={nonce}; document origin verified; HTTP requests bounded; WebSockets blocked',
                                        remediation='출력 문맥에 맞는 인코딩과 안전한 DOM API를 적용하고 HTML 신뢰 우회를 제거합니다.'))
                                    found+=1
                                    self.executions.append({'kind':kind,'parameter':param,'marker':nonce})
                                    break
                            except Exception as exc:errors.append(type(exc).__name__)
                            finally:await self.close_context(context)
                finally:await browser.close()
        except ImportError:
            errors.append('Playwright 런타임을 설치하지 않았습니다.')
        except Exception as exc:errors.append(type(exc).__name__+': '+str(exc)[:100])
        status='FINDING' if found else 'ERROR' if errors else 'PASS' if tested else 'NOT_RUN'
        record(self.bb,'R12','브라우저 XSS 실행 확인',status,
               f'실행 대조 {tested}회, 표식 확인 {found}건, 경계 차단 {self.blocked}회. '+('; '.join(errors[:2]) if errors else '검사한 문서·매개변수 범위의 결과입니다.'),tested,found,errors=len(errors))
