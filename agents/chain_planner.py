import httpx
from agents.base import BaseAuditor
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.models.state import LeakedArtifactType, PrivilegeLevel
from core.graph.attack_graph import AttackGraphEngine
from core.rules.contracts import record

class ChainPlannerAgent(BaseAuditor):
    """
    Strategic Vulnerability Chaining Planner.
    Correlates findings across different stages:
    Step 1 (Debug Info Leak) -> Step 2 (BOLA Data Exfiltration) -> Step 3 (Admin Priv Escalation)
    Discovers multi-step attack graphs and pinpoints defensive choke points.
    """
    async def audit(self, client: httpx.AsyncClient):
        tested=found=0;errors=[]
        if client.auth is not None or any(client.headers.get(k) for k in ('authorization','x-api-key','cookie')) or client.cookies:
            record(self.blackboard,'CHAIN','유출 키의 관리자 응답 접근 대조','NOT_RUN','별도 미인증 클라이언트가 필요합니다.',required=True)
            return

        # Check if we have harvested an API key or auth token from previous steps
        api_keys = self.blackboard.get_artifacts(LeakedArtifactType.API_KEY)
        
        # Test whether the harvested key unlocks privileged admin endpoints
        admin_paths = self.governance.probe_paths(["/api/v1/admin/config", "/api/admin/config", "/api/v1/admin/status", "/api/v1/admin/system-config"])
        admin_paths += [ep.path for ep in self.blackboard.asset.endpoints if ep.method == "GET" and ("/admin/" in ep.path or ep.path.endswith(("/admin/config", "/admin/status")))]

        for key_art in api_keys:
            headers = {"X-API-Key": key_art.value}
            for path in dict.fromkeys(admin_paths):
                try:
                    url = self.governance.url_for_path(path)
                    if not self.governance.is_in_scope(url) or not self.governance.is_safe_endpoint(path):
                        continue
                    client.cookies.clear()
                    baseline=await client.get(url,timeout=5.0)
                    if baseline.status_code not in (401,403):continue
                    client.cookies.clear()
                    wrong=await client.get(url,headers={'X-API-Key':'wva-invalid-key'},timeout=5.0)
                    if wrong.status_code not in (401,403):continue
                    client.cookies.clear()
                    resp = await client.get(url, headers=headers, timeout=5.0)

                    if resp.status_code == 200:
                        data = resp.json() if "application/json" in resp.headers.get("content-type", "") else {}
                        if not isinstance(data, dict) or data.get("privilege") not in ("ADMIN", "admin", "ROOT_ADMIN", "root_admin"):
                            continue
                        client.cookies.clear()
                        repeat=await client.get(url,headers=headers,timeout=5.0)
                        if repeat.status_code!=200 or repeat.json()!=data:raise ValueError('키 사용 응답이 반복 대조에서 일치하지 않습니다.')
                        tested+=1
                        evidence = f"anonymous and invalid-key requests denied; exact leaked key returns stable administrative response twice at {path}; no administrative action executed"
                        finding = VulnerabilityFinding(
                            id=f"VULN-PRIVESC-ADMIN-{path.replace('/', '_')}",
                            vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                            title=f"Administrative Privilege Escalation via Leaked Key at {path}",
                            severity=Severity.CRITICAL,
                            endpoint=path,
                            request_url=str(resp.request.url),
                            description='유출된 키를 사용한 별도 요청에서 관리자 응답 접근을 확인했습니다. 관리자 기능 실행이나 시스템 장악은 확인하지 않았습니다.',
                            evidence=evidence,
                            cwe_id="CWE-269",
                            cvss_score=9.8,
                            required_preconditions={
                                "artifact_ref": {'type':LeakedArtifactType.API_KEY.value,'value':key_art.value,'session':'anonymous'}
                            },
                            yielded_postconditions={
                                "privilege": PrivilegeLevel.ADMIN.value,
                                "privilege_verified": True
                            },
                            remediation="Implement strict role-based access control (RBAC), rotate leaked keys, and enforce MFA for admin endpoints."
                        )
                        self.blackboard.add_finding(finding)
                        found+=1
                except Exception as exc:
                    errors.append(type(exc).__name__)

        record(self.blackboard,'CHAIN','유출 키의 관리자 응답 접근 대조','FINDING' if found else 'ERROR' if errors else 'PASS' if tested else 'NOT_RUN',
               f'미인증·잘못된 키 거부와 실제 키 응답을 대조했습니다. 확인 {found}개.',tested,found,len(errors),required=bool(api_keys))

        # Now, execute the graph analysis to synthesize exploit chains
        graph_engine = AttackGraphEngine(self.blackboard)
        chains = graph_engine.find_exploit_chains()
        self.blackboard.log(f"[ChainPlanner] Completed Attack Path Analysis. Found {len(chains)} exploit chain(s).")
