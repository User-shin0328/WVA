"""Bounded boolean SQL differentials and context-aware input reflection.

No UNION extraction, database writes or time delays in the default rule.
"""
import hashlib
import re
import uuid
from urllib.parse import urlsplit, parse_qs
from core.http.requester import ProbeSession, SKIP, fingerprint
from core.rules.contracts import record
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity

DB_ERROR=re.compile(r'SQLITE_ERROR|SQL syntax.*MySQL|mysqli?_.*(?:error|exception)|SQLSTATE\[|syntax error at or near|unclosed quotation mark|ORA-\d{5}',re.I|re.S)
SQL_EXPLICIT_CONFIRM=re.compile(r'SQL Injection payload executed|SQL_INJECTION_PWNED|SQLI_DATA_LEAKAGE|SQL Injection Vulnerability Detected',re.I)
COMMON_PARAMETERS=('id','user_id','product_id','q','search','keyword')


def candidates(bb, options):
    seen=set();items=[]
    for ep in bb.asset.endpoints:
        if ep.method!='GET':continue
        query=parse_qs(urlsplit(ep.url).query,keep_blank_values=True)
        names=list(query)+[p.split(':')[-1] for p in ep.parameters if ':' not in p or p.startswith('query:')]
        for name in dict.fromkeys(names):
            if SKIP.search(name) or options.parameters and name not in options.parameters:continue
            if not options.parameters and name.lower() in ('lang','locale','tag'):continue
            key=(ep.path,name)
            if key in seen:continue
            seen.add(key)
            value=query.get(name,['1' if re.search(r'(^id$|_id$|number)',name,re.I) else 'WVA_baseline'])[0]
            items.append((ep.url,name,value))
    if options.sql and options.sql_common_parameters:
        # Reuse an actual GET entry, never invent new server routes or modify tokens.
        target=bb.target_url.split('#',1)[0]
        entry=next((ep for ep in bb.asset.endpoints if ep.method=='GET' and ep.url.split('#',1)[0].rstrip('/')==target.rstrip('/')),None)
        if entry:
            for name in COMMON_PARAMETERS:
                if options.parameters and name not in options.parameters:continue
                if (entry.path,name) in seen:continue
                seen.add((entry.path,name))
                items.append((entry.url,name,'1' if name.endswith('id') else 'WVA_baseline'))
    return items[:options.sql_candidate_limit]


class InjectionAuditor:
    def __init__(self,bb,governance,options):
        self.bb,self.gov,self.options=bb,governance,options
        self.reflections=[]
        self.probes=[]
        self.guesses=[]

    async def audit(self,client):
        items=candidates(self.bb,self.options)
        declared={(ep.path,p.split(':')[-1]) for ep in self.bb.asset.endpoints for p in [*parse_qs(urlsplit(ep.url).query),*ep.parameters]}
        session=ProbeSession(client)
        found=0;tested=0;issues=[];signals=[]
        for url,param,value in items:
            if not self.gov.is_in_scope(url) or not self.gov.is_safe_endpoint(urlsplit(url).path):continue
            guessed=(urlsplit(url).path,param) not in declared
            if guessed:
                try:
                    first=await session.get(url,{param:value})
                    other='2' if value=='1' else 'WVA_alternate'
                    second=await session.get(url,{param:other})
                    active=first.status_code==second.status_code==200 and fingerprint(first,[value,other])!=fingerprint(second,[value,other])
                    self.guesses.append({'path':urlsplit(url).path,'parameter':param,'response_difference':active})
                    if not active:continue
                except Exception as exc:
                    issues.append(type(exc).__name__+': '+str(exc)[:100]);continue
            if self.options.sql:
                try:
                    result=await self.sql(session,url,param,value)
                    tested+=1
                    if result=='FINDING':found+=1
                    elif result:signals.append(result)
                except Exception as exc:issues.append(type(exc).__name__+': '+str(exc)[:100])
            if self.options.xss and not guessed:
                try:
                    marker='wva_'+uuid.uuid4().hex[:12]
                    response=await session.get(url,{param:marker+'"<wva-probe>'})
                    if marker in response.text and 'text/html' in response.headers.get('content-type',''):
                        raw=marker+'"<wva-probe>' in response.text
                        self.reflections.append({'url':url,'parameter':param,'raw':raw})
                    self.probes.append({'url':url,'parameter':param})
                except Exception as exc:issues.append(type(exc).__name__+': '+str(exc)[:100])
        status='FINDING' if found else 'ERROR' if issues else 'SIGNAL' if signals else 'PASS' if tested else 'NOT_RUN'
        reason=f'매개변수 {tested}개 대조, 조건 쌍 2회 반복. 대표 이름 반응 확인 {len(self.guesses)}개. 읽기 응답만 비교했습니다.'
        if not self.options.sql:status='NOT_RUN';reason='사용자가 SQL 조건 검사를 끄었습니다.'
        elif not tested and not issues:reason='발견 매개변수 또는 대표 이름의 입력 반응을 확인하지 못했습니다. id·user_id·product_id·q·search·keyword를 확인했으며 SQL 검증을 수행한 것으로 처리하지 않습니다.'
        elif issues:reason+=' 일부 요청의 오류·인증·예산 제한으로 미완료: '+'; '.join(issues[:2])
        elif signals:reason+=' 판정 보류: '+'; '.join(signals[:2])
        record(self.bb,'R11','SQL Injection 조건 대조',status,reason,tested,found,errors=len(issues),inconclusive=len(signals))
        self.bb.asset.metadata['sql_candidates']={'selected':len(items),'tested':tested,'common_parameters':list(COMMON_PARAMETERS),'preflight':self.guesses,'limit':self.options.sql_candidate_limit}
        raw=sum(r['raw'] for r in self.reflections)
        record(self.bb,'R06','입력값 반사와 출력 문맥','SIGNAL' if raw else 'PASS' if self.probes else 'NOT_RUN',
               f'HTML 원시 반사 {raw}개. 반사만으로 XSS를 확정하지 않습니다.' if self.probes else '검사할 매개변수가 없거나 요청을 완료하지 못했습니다.',len(self.probes))

    async def sql(self,session,url,param,value):
        baseline=await session.get(url,{param:value})
        baseline2=await session.get(url,{param:value})
        if baseline.status_code!=200 or baseline2.status_code!=200:return '정상 기준 응답 없음'
        if fingerprint(baseline,[value])!=fingerprint(baseline2,[value]):return '기준 응답 불안정'

        pairs=[(value+' AND 1=1',value+' AND 1=2'),
               (value+"' AND '1'='1",value+"' AND '1'='2"),
               (value+"%') AND 1=1)-- ",value+"%') AND 1=2)-- ")]
        signal=bool(SQL_EXPLICIT_CONFIRM.search(baseline.text))
        for true,false in pairs:
            rows=[]
            for _ in range(2):
                yes=await session.get(url,{param:true})
                no=await session.get(url,{param:false})
                if SQL_EXPLICIT_CONFIRM.search(yes.text + no.text):signal=True
                if DB_ERROR.search(yes.text) or DB_ERROR.search(no.text):signal=True
                rows.append((yes,no))
            values=[value,true,false]
            valid=all(a.status_code==b.status_code==200 and not DB_ERROR.search(a.text+b.text) and not SQL_EXPLICIT_CONFIRM.search(a.text+b.text) for a,b in rows)
            base_fp=fingerprint(baseline,values)
            if valid and all(fingerprint(a,values)==base_fp and fingerprint(b,values)!=base_fp for a,b in rows) and fingerprint(rows[0][1],values)==fingerprint(rows[1][1],values):
                key=hashlib.sha256((urlsplit(url).path+':'+param).encode()).hexdigest()[:12]
                self.bb.add_finding(VulnerabilityFinding(id='VULN-SQL-'+key,vuln_type=VulnerabilityType.SQL_INJECTION,
                    title='SQL 조건에 따른 응답 차이 확인',severity=Severity.HIGH,endpoint=urlsplit(url).path,
                    request_url=url,description='정상 응답은 안정적이며, 참 조건은 정상 데이터와 일치하고 거짓 조건은 반복해서 다른 데이터를 반환했습니다.',
                    verification_context={'parameter':param,'original_value':value,'method':'boolean_pairs_v2'},
                    evidence=f'parameter={param}; stable baseline=2; true/false pairs=2; true matches baseline; false differs consistently; no DB writes or data extraction',
                    cwe_id='CWE-89',cvss_score=8.1,remediation='SQL 문자열 결합을 제거하고 매개변수화된 쿼리와 최소 권한 DB 계정을 적용합니다.'))
                return 'FINDING'
        return 'DB 오류 또는 성공 설명 문구만 관찰되어 SQL 주입을 확정하지 않았습니다.' if signal else None
