"""Reproduce the original rule without equating missing signatures with remediation."""
from urllib.parse import urlsplit
from core.models.vulnerability import VulnerabilityType
from core.graph.blackboard import SecurityBlackboard
from agents.injection_auditor import InjectionAuditor


async def verify(finding,client,governance,options):
    url=finding.request_url or governance.url_for_path(finding.endpoint)
    if not governance.is_in_scope(url) or not governance.is_safe_endpoint(urlsplit(url).path):
        raise ValueError('원래 진단 범위를 벗어난 요청입니다.')
    kind=finding.vuln_type
    if kind not in (VulnerabilityType.SQL_INJECTION,VulnerabilityType.OPEN_REDIRECT,VulnerabilityType.MISSING_SECURITY_HEADER,VulnerabilityType.CORS_MISCONFIGURATION):
        return 'NOT_VERIFIABLE','이 유형은 개별 자동 재검증을 지원하지 않습니다. 같은 프로필로 전체 진단과 원문 증거를 대조하세요.'
    if kind==VulnerabilityType.SQL_INJECTION:
        context=finding.verification_context
        if not context.get('parameter') or 'original_value' not in context:return 'NOT_VERIFIABLE','원래 SQL 매개변수와 기준 값 기록이 없어 반복 대조할 수 없습니다.'
        auditor=InjectionAuditor(SecurityBlackboard(governance.target_base_url),governance,options)
        from core.http.requester import ProbeSession
        result=await auditor.sql(ProbeSession(client),url,context['parameter'],context['original_value'])
        if result=='FINDING':return 'STILL_VULNERABLE','원래 매개변수의 정상·참·거짓 조건 반복 대조에서 다시 확인됐습니다.'
        if result:return 'INCONCLUSIVE','SQL 대조를 확정하지 못했습니다: '+result
        return 'NOT_REPRODUCED','같은 SQL 조건 대조에서 이번에는 재현되지 않았습니다. 모든 주입 문맥의 수정 완료를 보증하지 않습니다.'
    response=await client.get(url)
    if kind==VulnerabilityType.OPEN_REDIRECT:
        if response.status_code not in (200,301,302,303,307,308):raise ValueError('리다이렉트 대조 응답 오류')
        destination=urlsplit(response.headers.get('location',''))
        return ('STILL_VULNERABLE','원래 시험 목적지로 이동하는 응답이 다시 확인됐습니다.') if destination.hostname=='example.com' else ('NOT_REPRODUCED','원래 시험 목적지 이동이 재현되지 않았습니다.')
    if response.status_code!=200:raise ValueError(f'정상 기준 응답을 확인하지 못했습니다: HTTP {response.status_code}')
    if kind==VulnerabilityType.MISSING_SECURITY_HEADER:
        signature=(finding.id+' '+finding.title).upper()
        header='content-security-policy' if 'CSP' in signature or 'CONTENT-SECURITY' in signature else 'strict-transport-security' if 'HSTS' in signature or 'STRICT-TRANSPORT' in signature else None
        if not header:return 'NOT_VERIFIABLE','원래 헤더 규칙을 특정할 수 없습니다.'
        return ('NOT_REPRODUCED',header+' 헤더가 현재 응답에 있습니다. 정책 내용의 적정성은 별도 확인해야 합니다.') if response.headers.get(header) else ('STILL_VULNERABLE',header+' 헤더가 현재도 없습니다.')
    if kind==VulnerabilityType.CORS_MISCONFIGURATION:
        origin='null' if 'Null Origin' in finding.title else 'https://evil-attacker.com'
        response=await client.get(url,headers={'Origin':origin})
        if response.status_code!=200:raise ValueError('CORS 대조 응답 오류')
        exposed=response.headers.get('access-control-allow-origin')==origin and response.headers.get('access-control-allow-credentials','').lower()=='true'
        return ('STILL_VULNERABLE','원래 시험 출처와 인증 허용 헤더 조합이 다시 확인됐습니다.') if exposed else ('NOT_REPRODUCED','원래 CORS 헤더 조합이 이번에는 재현되지 않았습니다.')
    return 'NOT_VERIFIABLE','이 유형은 개별 자동 재검증을 지원하지 않습니다. 같은 프로필로 전체 진단과 원문 증거를 대조하세요.'
