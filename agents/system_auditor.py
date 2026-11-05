"""Server checks with independent evidence from declared owned loopback fixtures.

Missing contracts are NOT_RUN. No metadata probes or implicit upload discovery.
"""
import hashlib
import uuid
from urllib.parse import urlsplit
from agents.policy_auditor import loopback
from core.http.requester import replace_query
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.rules.contracts import ScanOptions, record

RULES = {
    'file': ('R16', '경로 순회 표식 파일 대조', VulnerabilityType.PATH_TRAVERSAL, 'CWE-22'),
    'command': ('R17', '명령어 실행 표식 대조', VulnerabilityType.COMMAND_INJECTION, 'CWE-78'),
    'ssrf': ('R18', '서버 요청 수신 기록 대조', VulnerabilityType.SSRF, 'CWE-918'),
    'upload': ('R19', '파일 저장·조회·정리 대조', VulnerabilityType.ARBITRARY_FILE_UPLOAD, 'CWE-434'),
}


class SystemAuditor:
    def __init__(self, bb, governance, options=None, budget=None):
        self.bb, self.gov = bb, governance
        self.options, self.budget = options or ScanOptions(), budget

    def validate(self, *urls):
        if self.options.mode != 'deep':
            raise ValueError('명시한 서버 시나리오는 심화 모드에서만 수행합니다.')
        if not all(url and self.gov.is_in_scope(url)
                   and self.gov.is_safe_endpoint(urlsplit(url).path) for url in urls):
            raise ValueError('모든 시나리오 URL은 범위 안의 안전한 대상 주소여야 합니다.')

    async def audit(self, client):
        for kind in RULES: await self.check(client, kind)

    async def audit_path_traversal(self, client): await self.check(client, 'file')
    async def audit_command_injection(self, client): await self.check(client, 'command')
    async def audit_ssrf(self, client): await self.check(client, 'ssrf')
    async def audit_file_upload(self, client): await self.check(client, 'upload')

    async def check(self, client, kind):
        rule, title, vuln, cwe = RULES[kind]
        cases = [c for c in self.options.system_cases if c.kind == kind]
        tested = found = signals = 0
        errors = []
        for case in cases:
            try:
                if kind == 'upload': confirmed, reason = await self.upload(client, case)
                else:
                    self.validate(case.url)
                    confirmed, reason = await getattr(self, kind)(client, case)
                tested += 1
                if confirmed is None:signals+=1
                if confirmed:
                    found += 1
                    key = hashlib.sha256((kind + case.url + case.parameter).encode()).hexdigest()[:12]
                    self.bb.add_finding(VulnerabilityFinding(
                        id=f'VULN-{rule}-{key}', vuln_type=vuln, severity=Severity.HIGH,
                        title=title + ' 확인', endpoint=urlsplit(case.url).path, request_url=case.url,
                        method='POST' if kind == 'upload' else 'GET', cwe_id=cwe, cvss_score=8.1,
                        description=reason, evidence=reason,
                        remediation='서버 입력과 권한·파일 처리 경계를 보완하고 동일한 정상·거부 대조를 반복합니다.',
                        yielded_postconditions={}))
            except Exception as exc: errors.append(type(exc).__name__ + ': ' + str(exc)[:140])
        status = 'FINDING' if found else 'ERROR' if errors else 'SIGNAL' if signals else 'PASS' if tested else 'NOT_RUN'
        reason = f'명시한 시나리오 {tested}개 대조, 확인 {found}건, 미확정 {signals}건.'
        if not cases: reason = '독립 증거를 확인할 시나리오를 지정하지 않았습니다.'
        if errors: reason += ' ' + '; '.join(errors[:2])
        record(self.bb, rule, title, status, reason, tested, found, len(errors), required=bool(cases),inconclusive=signals)

    async def get(self, client, case, value):
        response = await client.get(replace_query(case.url, {case.parameter: value}))
        if response.status_code != 200:
            raise ValueError(f'대조 요청 미완료: HTTP {response.status_code}')
        return response.text

    async def file(self, client, case):
        marker = case.expected_marker
        if len(marker) < 16 or not case.probe_value or marker in case.probe_value:
            raise ValueError('입력에 없는 16자 이상 표식과 별도 실습 파일 경로가 필요합니다.')
        controls = [await self.get(client, case, case.control_value) for _ in range(2)]
        if controls[0]!=controls[1]:raise ValueError('표식 파일 대조의 정상 기준 응답이 불안정합니다.')
        probes = [await self.get(client, case, case.probe_value) for _ in range(2)]
        confirmed = controls[0] == controls[1] and all(marker not in s for s in controls) and all(s.strip() == marker for s in probes)
        return confirmed, 'known benign file; stable controls=2; exact marker reads=2; no secret collection'

    async def command(self, client, case):
        for _ in range(2):
            marker = 'wva_' + uuid.uuid4().hex
            left, right = marker[:20], marker[20:]
            payload = ('127.0.0.1&echo ' + left + '^' + right if case.shell == 'windows'
                       else "127.0.0.1;printf '%s%s\\n' '" + left + "' '" + right + "'")
            baseline = await self.get(client, case, case.control_value)
            response = await self.get(client, case, payload)
            if marker in baseline or marker in payload or marker not in response.splitlines(): return False, ''
        return True, 'independent split random output markers=2; input reflection rejected; OS privilege not established'

    async def ssrf(self, client, case):
        for _ in range(2):
            marker = uuid.uuid4().hex
            callback = (case.callback_url or '').replace('{marker}', marker)
            receipt = (case.receipt_url or '').replace('{marker}', marker)
            if '{marker}' not in (case.callback_url or '') or '{marker}' not in (case.receipt_url or ''):
                raise ValueError('고유 표식 수신 URL과 별도 수신 기록 URL이 필요합니다.')
            self.validate(callback, receipt)
            async def count():
                response = await client.get(receipt)
                data = response.json() if response.status_code == 200 else {}
                if data.get('marker') != marker or type(data.get('count')) is not int:
                    raise ValueError('수신 기록의 표식 또는 횟수가 유효하지 않습니다.')
                return data['count']
            if await count() != 0: raise ValueError('수신 기준 기록이 비어 있지 않습니다.')
            await self.get(client, case, case.control_value)
            if await count() != 0: raise ValueError('대조 요청에서도 표식 수신이 발생했습니다.')
            await self.get(client, case, callback)
            if await count() != 1: return False, ''
        return True, 'unique callback receipts=2; counters before=0 after=1; no cloud metadata requested'

    async def upload(self, client, case):
        marker = uuid.uuid4().hex
        filename = 'wva_' + marker + '.php'
        read_url = (case.read_url or '').replace('{filename}', filename)
        self.validate(case.url, read_url, case.cleanup_url)
        if '{filename}' not in (case.read_url or '') or not self.budget:
            raise ValueError('표식 파일 조회 URL과 공통 요청 경계가 필요합니다.')
        receipt = {'kind': 'upload', 'attempted': False, 'cleaned': False, 'verified': False}
        self.bb.asset.metadata.setdefault('cleanup_receipts', []).append(receipt)
        before = await client.get(read_url)
        if before.status_code != 404: raise ValueError('고유 테스트 파일의 부재를 확인하지 못했습니다.')
        self.budget.allow_post(case.url)
        self.budget.allow_post(case.cleanup_url)
        confirmed = False
        try:
            receipt['attempted'] = True
            response = await client.post(case.url, files={case.field: (filename, marker.encode(), 'text/plain')}, data={'wva_marker': marker})
            if response.status_code not in (200, 201):
                if response.status_code in (400, 403, 415, 422): return False, ''
                raise ValueError('업로드 요청을 완료하지 못했습니다.')
            try:
                data=response.json()
                accepted = data.get('success') is True
                rejected = data.get('success') is False or bool(data.get('error'))
            except (ValueError, AttributeError): accepted = rejected = False
            if not accepted: return (False if rejected else None), '업로드 성공 여부를 확인하지 못했습니다.'
            reads = [await client.get(read_url) for _ in range(2)]
            if any(r.status_code not in (200,404) for r in reads):raise ValueError('업로드 파일 조회 요청 실패')
            confirmed = all(r.status_code == 200 and r.text == marker for r in reads)
        finally:
            if receipt['attempted']:
                cleaned = await client.post(case.cleanup_url, data={'wva_marker': marker, 'filename': filename})
                if cleaned.status_code not in (200, 204): raise ValueError('테스트 파일 정리 요청 실패')
                receipt['cleaned'] = True
                after = await client.get(read_url)
                if after.status_code != 404: raise ValueError('테스트 파일 부재를 확인하지 못했습니다.')
                receipt['verified'] = True
        return (True if confirmed else None), 'explicit success; exact-content reads=2; cleanup/absence verified; code execution not established'
