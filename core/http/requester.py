import asyncio
import hashlib
import re
from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode
import httpx
from bs4 import BeautifulSoup


class ResourceLimit(ValueError):
    pass


class BoundedClient(httpx.AsyncClient):
    async def send(self, request, **kwargs):
        try:
            resp = await super().send(request, **kwargs)
            if resp.status_code == 429 or any(h in resp.headers for h in ('cf-ray', 'x-amzn-waf')) or 'waf' in resp.headers.get('server', '').lower():
                self._wva_budget.waf_detected = True
                self._wva_budget.adaptive_delay = min(self._wva_budget.adaptive_delay + 0.05, 0.5)
            return resp
        except (httpx.HTTPError, ValueError):
            self._wva_budget.failures += 1
            raise


class LimitedStream(httpx.AsyncByteStream):
    def __init__(self, stream, limit):
        self.stream,self.limit=stream,limit
    async def __aiter__(self):
        size=0
        async for chunk in self.stream:
            size+=len(chunk)
            if size>self.limit:
                await self.aclose()
                raise ResourceLimit('응답 크기 한도를 초과했습니다.')
            yield chunk
    async def aclose(self):
        await self.stream.aclose()


class BoundedTransport(httpx.AsyncBaseTransport):
    def __init__(self, limit):
        self.inner=httpx.AsyncHTTPTransport(verify=True,trust_env=False,retries=0)
        self.limit=limit
    async def handle_async_request(self, request):
        response=await self.inner.handle_async_request(request)
        if response.headers.get('content-encoding','identity').lower() not in ('identity',''):
            await response.aclose()
            raise ResourceLimit('서버가 identity 요청에도 압축 응답을 반환해 크기 제한 검사에서 중단했습니다.')
        response.stream=LimitedStream(response.stream,self.limit)
        return response
    async def aclose(self):
        await self.inner.aclose()


class RequestBudget:
    def __init__(self, governance, options):
        self.governance,self.options=governance,options
        self.count=0
        self.post_urls=set()
        self.delete_urls=set()
        self.lock=asyncio.Lock()
        self.last_request=0
        self.blocked=0
        self.failures=0
        self.waf_detected=False
        self.adaptive_delay=0.0

    def allow_post(self, url):
        if not self.governance.is_in_scope(url) or not self.governance.is_safe_endpoint(urlsplit(url).path):
            raise ValueError('명시한 작업이 진단 범위를 벗어났습니다.')
        self.post_urls.add(str(httpx.URL(url).copy_with(fragment='')))

    def allow_delete(self, url):
        if not self.governance.is_in_scope(url) or not self.governance.is_safe_endpoint(urlsplit(url).path):
            raise ValueError('명시한 작업이 진단 범위를 벗어났습니다.')
        self.delete_urls.add(str(httpx.URL(url).copy_with(fragment='')))

    async def enforce(self, request):
        url=str(request.url.copy_with(fragment=''))
        is_post = request.method == 'POST' and url in self.post_urls
        is_delete = request.method == 'DELETE' and url in self.delete_urls
        if (not self.governance.is_in_scope(url) or not self.governance.is_safe_endpoint(request.url.path)
                or request.method not in ('GET','HEAD') and not (is_post or is_delete)):
            self.blocked+=1
            raise ValueError('출처·경로·메서드 진단 경계에서 차단했습니다.')
        async with self.lock:
            if self.count>=self.options.max_requests:
                raise ResourceLimit('전체 진단 요청 예산을 소진했습니다.')
            loop=asyncio.get_running_loop()
            interval = (.005 if getattr(self.options, 'mode', 'safe') == 'deep' else .025) + self.adaptive_delay
            await asyncio.sleep(max(0, interval - (loop.time() - self.last_request)))
            self.last_request=loop.time()
            self.count+=1

    def client(self, **kwargs):
        headers={'Accept-Encoding':'identity',**kwargs.pop('headers',{})}
        client=BoundedClient(transport=BoundedTransport(self.options.max_response_bytes),follow_redirects=False,
                            trust_env=False,timeout=httpx.Timeout(5),event_hooks={'request':[self.enforce]},headers=headers,**kwargs)
        client._wva_budget=self
        return client


TOKEN=re.compile(r'csrf|token|nonce',re.I)
SKIP=re.compile(r'csrf|token|nonce|password|secret|submit|button|file|logout',re.I)


def replace_query(url, replacements):
    p=urlsplit(url)
    pairs=[(k,v) for k,v in parse_qsl(p.query,keep_blank_values=True) if k not in replacements]
    pairs.extend(replacements.items())
    return urlunsplit((p.scheme,p.netloc,p.path,urlencode(pairs,doseq=True),p.fragment))


class ProbeSession:
    def __init__(self, client):
        self.client=client

    async def prepare(self, url, overrides=None):
        # A fresh GET in the same jar refreshes hidden CSRF tokens for each probe.
        p=urlsplit(url)
        retained=[(k,v) for k,v in parse_qsl(p.query,keep_blank_values=True) if not TOKEN.search(k) and k.lower()!='submit' and k not in (overrides or {})]
        page_url=urlunsplit((p.scheme,p.netloc,p.path,urlencode(retained),''))
        page=await self.client.get(page_url)
        values={}
        if 'text/html' in page.headers.get('content-type',''):
            soup=BeautifulSoup(page.text,'html.parser')
            for form in soup.find_all('form'):
                if form.get('method','get').lower()!='get':continue
                from urllib.parse import urljoin
                action=urljoin(page_url,form.get('action') or page_url)
                if urlsplit(action).path!=p.path:continue
                for field in form.find_all('input',attrs={'name':True}):
                    name=field['name'];kind=field.get('type','text').lower()
                    if kind in ('hidden','submit') or TOKEN.search(name):
                        values[name]=field.get('value','')
        values.update(overrides or {})
        return replace_query(url,values)

    async def get(self, url, overrides=None):
        prepared=await self.prepare(url,overrides)
        response=await self.client.get(prepared)
        if response.status_code in (401,403) or response.is_redirect:
            raise ValueError('인증 거부 또는 이동 응답으로 비교 전제를 충족하지 못했습니다.')
        return response


def fingerprint(response, values=()):
    if 'application/json' in response.headers.get('content-type',''):
        try:
            import json
            text=json.dumps(response.json(),sort_keys=True,ensure_ascii=False)
        except ValueError:text=response.text
    else:
        soup=BeautifulSoup(response.text,'html.parser')
        for node in soup(['script','style','input']):node.decompose()
        text=soup.get_text(' ',strip=True)
    for value in sorted(set(str(v) for v in values if str(v)),key=len,reverse=True):
        text=text.replace(value,'[INPUT]')
    text=re.sub(r'\b(?:csrf|token|nonce)[=: ]+[a-zA-Z0-9_-]+','[TOKEN]',text,flags=re.I)
    return hashlib.sha256((str(response.status_code)+' '+re.sub(r'\s+',' ',text)).encode()).hexdigest()
