import httpx
from typing import Optional, Callable, Any
from core.graph.blackboard import SecurityBlackboard
from core.safety.governance import SafetyGovernance
from surface.recon import SurfaceReconEngine
from agents.config_auditor import ConfigAndHeaderAuditor
from agents.idor_auditor import IdorAndBolaAuditor
from agents.chain_planner import ChainPlannerAgent

class VulnerabilityAnalysisEngine:
    """
    Main Orchestrator for the Web Vulnerability & Attack Path Chaining Agent.
    Drives the pipeline: Surface Recon -> Specialized Auditors -> Chaining Planner -> Threat Graph.
    """
    def __init__(self, target_url: str, event_callback: Optional[Callable[[str, Any], None]] = None):
        self.target_url = target_url.rstrip("/")
        self.governance = SafetyGovernance(self.target_url)
        self.blackboard = SecurityBlackboard(self.target_url, event_callback=event_callback)

    async def execute_audit(self) -> SecurityBlackboard:
        self.blackboard.log(f"=== Starting Security Assessment against: {self.target_url} ===")
        
        async def enforce_scope(request):
            if not self.governance.is_in_scope(str(request.url)) or not self.governance.is_safe_endpoint(request.url.path):
                raise ValueError("스코프 밖이거나 금지된 경로입니다.")
            if request.method not in ("GET", "HEAD"):
                raise ValueError("읽기 전용 진단만 허용됩니다.")

        async with httpx.AsyncClient(verify=True, follow_redirects=False, trust_env=False,
                                     event_hooks={"request": [enforce_scope]}) as client:
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

            # 3. Access Control & BOLA Auditor
            self.blackboard.log("[Phase 3] Access Control & BOLA Differential Audit")
            idor_auditor = IdorAndBolaAuditor(self.blackboard, self.governance)
            await idor_auditor.audit(client)

            # 4. Strategic Vulnerability Chaining Planner & Attack Graph
            self.blackboard.log("[Phase 4] Vulnerability Chaining & Attack Path Analysis")
            chain_planner = ChainPlannerAgent(self.blackboard, self.governance)
            await chain_planner.audit(client)

        self.blackboard.log(f"=== Security Assessment Complete. Total Findings: {len(self.blackboard.findings)}, Chains: {len(self.blackboard.chains)} ===")
        return self.blackboard
