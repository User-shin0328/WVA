"""Bounded anonymous exposure checks; no repository dump or credential use."""
import hashlib
import re
import uuid
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.rules.contracts import record

SENSITIVE=re.compile(r'PASSWORD|SECRET|PRIVATE_KEY|API_KEY|ACCESS_KEY|DATABASE_URL',re.I)
PLACEHOLDER=re.compile(r'example|changeme|placeholder|your[_ -]|redacted|^\*+$',re.I)


class ExposureAuditor:
    def __init__(self,bb,governance):self.bb,self.gov=bb,governance

    async def audit(self,client):
        specs=[('R21','환경설정 파일 외부 노출','/.env','env'),
               ('R22','Git 메타데이터 외부 노출','/.git/HEAD','git'),
               ('R23','관리 환경설정의 비밀 값 노출','/actuator/env','management')]
        for rule,title,path,kind in specs:
            tested=found=signals=0;errors=[]
            url=self.gov.origin_url+self.gov.probe_paths([path])[0]
            try:
                client.cookies.clear()
                first=await client.get(url)
                tested=1
                if first.status_code in (401,403,404,410):
                    pass
                elif first.status_code!=200:
                    raise ValueError('노출 확인 요청 미완료: HTTP '+str(first.status_code))
                elif 'text/html' in first.headers.get('content-type',''):
                    pass
                else:
                    proof,secrets=self.inspect(first,kind)
                    if proof:
                        client.cookies.clear()
                        second=await client.get(url)
                        other,_=self.inspect(second,kind) if second.status_code==200 else (None,[])
                        control_url=self.gov.origin_url+self.gov.probe_paths(['/wva-missing-'+uuid.uuid4().hex])[0]
                        control=await client.get(control_url)
                        if second.status_code!=200:raise ValueError('반복 확인 요청 실패')
                        if other!=proof or (control.status_code==200 and control.content==first.content):
                            signals=1
                        elif kind=='git':
                            config=await client.get(self.gov.origin_url+self.gov.probe_paths(['/.git/config'])[0])
                            if config.status_code==200 and re.search(r'^\[core\]',config.text,re.M) and re.search(r'^\s*repositoryformatversion\s*=\s*\d+',config.text,re.M):found=1
                            elif config.status_code in (200,401,403,404):signals=1
                            else:raise ValueError('Git 설정 대조 요청 실패')
                        else:found=1
                        if found:
                            self.bb.private_values.update(secrets)
                            self.bb.add_finding(VulnerabilityFinding(
                                id='VULN-'+rule+'-'+hashlib.sha256(url.encode()).hexdigest()[:12],
                                vuln_type=VulnerabilityType.INFO_DISCLOSURE,severity=Severity.HIGH,
                                title=title,endpoint=self.gov.probe_paths([path])[0],request_url=url,
                                description='별도 미인증 요청에서 노출 형식을 반복 확인하고 무관한 경로의 응답과 구분했습니다. 비밀 값은 보고서에 저장하지 않습니다.',
                                evidence=f'format={kind}; stable proof={proof}; repeats=2; anonymous; values omitted',
                                cwe_id='CWE-200',cvss_score=7.5,
                                verification_context={'exposure_kind':kind},
                                remediation='외부 제공 경로에서 설정·저장소 파일을 제거하고 관리 응답을 제한합니다. 노출된 실제 비밀 값은 회수·교체한 뒤 미인증 요청을 재검증합니다.'))
            except Exception as exc:errors.append(type(exc).__name__+': '+str(exc)[:120])
            record(self.bb,rule,title,'FINDING' if found else 'ERROR' if errors else 'SIGNAL' if signals else 'PASS' if tested else 'NOT_RUN',
                   f'미인증 형식·반복·무관 경로 대조. 발견 {found}개. '+('; '.join(errors) if errors else '비밀 값 원문은 저장하지 않았습니다.'),
                   tested,found,len(errors),inconclusive=signals)

    @staticmethod
    def inspect(response,kind):
        if kind=='env':
            fields=dict(re.findall(r'^([A-Z][A-Z0-9_]{2,})\s*=\s*[\"\']?([^\r\n]+)',response.text,re.M))
            secrets=[v.strip('\"\' ') for k,v in fields.items() if SENSITIVE.search(k) and len(v.strip('\"\' '))>=8 and not PLACEHOLDER.search(v)]
            return ('env:'+','.join(sorted(k for k in fields if SENSITIVE.search(k))) if len(fields)>=2 and secrets else None),secrets
        if kind=='git':
            match=re.fullmatch(r'ref: refs/heads/[A-Za-z0-9_./-]+\s*',response.text)
            return ('git:HEAD-ref' if match else None),[]
        try:data=response.json()
        except ValueError:return None,[]
        if not isinstance(data,dict):return None,[]
        secrets=[];keys=[]
        for source in data.get('propertySources',[])[:50]:
            if not isinstance(source,dict) or not isinstance(source.get('properties'),dict):continue
            for key,item in list(source['properties'].items())[:500]:
                value=item.get('value') if isinstance(item,dict) else item
                if SENSITIVE.search(key) and isinstance(value,str) and len(value)>=8 and not PLACEHOLDER.search(value):
                    keys.append(key);secrets.append(value)
        return ('management:'+','.join(sorted(keys)) if secrets else None),secrets
