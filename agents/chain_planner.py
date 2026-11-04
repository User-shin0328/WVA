import httpx
from agents.base import BaseAuditor
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.models.state import LeakedArtifactType, PrivilegeLevel
from core.graph.attack_graph import AttackGraphEngine

class ChainPlannerAgent(BaseAuditor):
    """
    Strategic Vulnerability Chaining Planner.
    Correlates findings across different stages:
    Step 1 (Debug Info Leak) -> Step 2 (BOLA Data Exfiltration) -> Step 3 (Admin Priv Escalation)
    Discovers multi-step attack graphs and pinpoints defensive choke points.
    """
    async def audit(self, client: httpx.AsyncClient):

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
                    resp = await client.get(url, headers=headers, timeout=5.0)

                    if resp.status_code == 200:
                        data = resp.json() if "application/json" in resp.headers.get("content-type", "") else {}
                        if not isinstance(data, dict) or data.get("privilege") not in ("ADMIN", "admin", "ROOT_ADMIN", "root_admin"):
                            continue
                        evidence = f"Harvested API Key '{key_art.value[:6]}...' successfully unlocked {path}. Admin status: 200 OK"
                        finding = VulnerabilityFinding(
                            id=f"VULN-PRIVESC-ADMIN-{path.replace('/', '_')}",
                            vuln_type=VulnerabilityType.PRIVILEGE_ESCALATION,
                            title=f"Administrative Privilege Escalation via Leaked Key at {path}",
                            severity=Severity.CRITICAL,
                            endpoint=path,
                            request_url=str(resp.request.url),
                            description=f"Using an API key leaked via upstream BOLA vulnerability grants unauthenticated attackers full administrative control.",
                            evidence=evidence,
                            cwe_id="CWE-269",
                            cvss_score=9.8,
                            required_preconditions={
                                "artifact_type": LeakedArtifactType.API_KEY.value
                            },
                            yielded_postconditions={
                                "privilege": PrivilegeLevel.ADMIN.value
                            },
                            remediation="Implement strict role-based access control (RBAC), rotate leaked keys, and enforce MFA for admin endpoints."
                        )
                        self.blackboard.add_finding(finding)
                except Exception:
                    continue

        # Now, execute the graph analysis to synthesize exploit chains
        graph_engine = AttackGraphEngine(self.blackboard)
        chains = graph_engine.find_exploit_chains()
        self.blackboard.log(f"[ChainPlanner] Completed Attack Path Analysis. Found {len(chains)} exploit chain(s).")
