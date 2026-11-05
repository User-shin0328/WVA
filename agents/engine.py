import httpx
from typing import Optional, Callable, Any
from core.graph.blackboard import SecurityBlackboard
from core.safety.governance import SafetyGovernance
from surface.recon import SurfaceReconEngine
from agents.config_auditor import ConfigAndHeaderAuditor
from agents.idor_auditor import IdorAndBolaAuditor
from agents.chain_planner import ChainPlannerAgent
from agents.injection_auditor import InjectionAuditor
from agents.browser_auditor import BrowserAuditor
from core.rules.contracts import ScanOptions, record
from core.http.requester import RequestBudget

class VulnerabilityAnalysisEngine:
    """
    Main Orchestrator for the Web Vulnerability & Attack Path Chaining Agent.
    Drives the pipeline: Surface Recon -> Specialized Auditors -> Chaining Planner -> Threat Graph.
    """
    def __init__(self, target_url: str, event_callback: Optional[Callable[[str, Any], None]] = None, scope_mode: str = "path", options=None):
        self.governance = SafetyGovernance(target_url, scope_mode=scope_mode)
        self.target_url = self.governance.target_base_url
        self.blackboard = SecurityBlackboard(self.target_url, event_callback=event_callback)
        self.blackboard.asset.metadata.update(scope_mode=scope_mode, scope_path=self.governance.scope_path or "/")
        self.options=options if isinstance(options,ScanOptions) else ScanOptions(**(options or {}))
        self.budget=RequestBudget(self.governance,self.options)
        required=['BASE','IO']
        if self.options.sql:required.append('R11')
        if self.options.xss and self.options.browser:required.append('R12')
        required += ['R09' if c.kind=='object' else 'R10' for c in self.options.access_cases]
        if self.options.timing_cases:required.append('R11-T')
        if self.options.stored_cases:required.extend(['R12-S','R14'])
        mapping={'file':'R16','command':'R17','ssrf':'R18','upload':'R19'}
        required += [mapping[c.kind] for c in self.options.system_cases]
        if self.options.mode=='deep' and self.options.concurrency_check:required.append('R15')
        self.blackboard.asset.metadata['required_checks']=list(dict.fromkeys(required))
        for profile in self.options.sessions:
            for values in [profile.headers,profile.cookies,profile.login_fields]:
                self.blackboard.private_values.update(v.get_secret_value() for v in values.values())

    async def execute_audit(self) -> SecurityBlackboard:
        self.blackboard.log(f"=== Starting Security Assessment against: {self.target_url} ===")
        
        self.blackboard.asset.metadata['checks']=[]
        self.blackboard.asset.metadata['waf_detected']=getattr(self.budget, 'waf_detected', False)
        auth={}
        profile=None
        if self.options.primary_session:
            profile=next((s for s in self.options.sessions if s.alias==self.options.primary_session),None)
            if profile is None:raise ValueError('기준 검사 세션 별칭을 찾을 수 없습니다.')
            auth={'headers':{k:v.get_secret_value() for k,v in profile.headers.items()},'cookies':{k:v.get_secret_value() for k,v in profile.cookies.items()}}
        async with self.budget.client(**auth) as client:
            if profile and profile.login_url:
                from agents.policy_auditor import post_form
                self.budget.allow_post(profile.login_url)
                logged_in=await post_form(client,profile.login_url,{k:v.get_secret_value() for k,v in profile.login_fields.items()})
                if logged_in.status_code>=400:raise ValueError('기준 검사 세션의 로그인 요청이 거부됐습니다.')
            try:
                probe = await client.get(self.target_url, timeout=5.0)
                if probe.status_code >= 500:
                    raise RuntimeError(f"대상 서버 오류: HTTP {probe.status_code}")
            except httpx.HTTPError as exc:
                raise RuntimeError("대상에 연결하지 못했습니다. 주소·포트·서버 실행 상태·TLS 인증서를 확인하세요.") from exc
            # 1. Surface Discovery & Asset Mapping
            self.blackboard.log("[Phase 1] Surface Discovery & Endpoint Mapping")
            recon_engine = SurfaceReconEngine(self.blackboard, self.governance)
            await recon_engine.run_discovery(client)

            # 2. Configuration & Security Header Auditor
            self.blackboard.log("[Phase 2] Configuration, Headers & Debug Info Audit")
            config_auditor = ConfigAndHeaderAuditor(self.blackboard, self.governance)
            await config_auditor.audit(client)
            record(self.blackboard,'BASE','헤더·쿠키·CORS·정보 노출','FINDING' if self.blackboard.findings else 'PASS','실제로 측정한 응답에 대한 기존 규칙 결과입니다.',len(self.blackboard.asset.endpoints),len(self.blackboard.findings))

            # 3. Access Control & BOLA Auditor
            self.blackboard.log("[Phase 3] Access Control & BOLA Differential Audit")
            idor_auditor = IdorAndBolaAuditor(self.blackboard, self.governance)
            async with self.budget.client() as anonymous:
                await idor_auditor.audit(anonymous)
            self.blackboard.log('[Phase 3] SQL 조건·입력 반사·브라우저 실행 대조')
            injection=InjectionAuditor(self.blackboard,self.governance,self.options)
            await injection.audit(client)
            browser=BrowserAuditor(self.blackboard,self.governance,self.options,self.budget)
            await browser.audit(client,injection.reflections)
            # System and server-level auditor (Path Traversal, Command Injection, SSRF, File Upload)
            self.blackboard.log("[Phase 3] 경로 순회·명령어 삽입·SSRF·파일 업로드 검증")
            from agents.system_auditor import SystemAuditor
            system_auditor = SystemAuditor(self.blackboard, self.governance, self.options, self.budget)
            await system_auditor.audit(client)
            # Optional declared policies are handled in isolated sessions.
            from agents.policy_auditor import PolicyAuditor
            await PolicyAuditor(self.blackboard,self.governance,self.options,self.budget).audit(client,browser)

            # 4. Strategic Vulnerability Chaining Planner & Attack Graph
            self.blackboard.log("[Phase 4] Vulnerability Chaining & Attack Path Analysis")
            chain_planner = ChainPlannerAgent(self.blackboard, self.governance)
            async with self.budget.client() as anonymous:
                await chain_planner.audit(anonymous)

        self.blackboard.log(f"=== Security Assessment Complete. Total Findings: {len(self.blackboard.findings)}, Chains: {len(self.blackboard.chains)} ===")
        self.blackboard.asset.metadata['request_budget']={'used':self.budget.count,'limit':self.options.max_requests,'max_response_bytes':self.options.max_response_bytes,'blocked':self.budget.blocked}
        self.blackboard.asset.metadata['waf_detected']=getattr(self.budget, 'waf_detected', False)
        record(self.blackboard,'IO','요청 경계·응답 수신 완료','ERROR' if self.budget.failures else 'PASS',
               f'요청 {self.budget.count}회, 수신·한도·경계 오류 {self.budget.failures}회.',self.budget.count,errors=self.budget.failures)
        return self.blackboard
