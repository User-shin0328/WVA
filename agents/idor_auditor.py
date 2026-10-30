import httpx
from agents.base import BaseAuditor
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.models.state import LeakedArtifactType, PrivilegeLevel

class IdorAndBolaAuditor(BaseAuditor):
    """
    Tests for Broken Object Level Authorization (BOLA / IDOR).
    Takes harvested identifiers (e.g. from debug endpoints or candidate lists)
    and verifies whether arbitrary object data can be read without proper authorization.
    """
    async def audit(self, client: httpx.AsyncClient):
        base_url = self.blackboard.target_url.rstrip("/")

        # Gather candidate user IDs: from blackboard state + standard test fixtures
        candidate_ids = []
        for art in self.blackboard.get_artifacts(LeakedArtifactType.USER_ID):
            candidate_ids.append(art.value)
        if not candidate_ids:
            candidate_ids.extend(["1001", "usr_staging_99"])

        # Target endpoints known or discovered for user profiles/objects
        target_paths = ["/api/v1/user/profile", "/api/user/profile", "/api/v1/user/export"]

        for path in target_paths:
            for uid in candidate_ids:
                try:
                    url = f"{base_url}{path}"
                    resp = await client.get(url, params={"user_id": uid}, timeout=5.0)

                    if resp.status_code == 200:
                        data = resp.json() if "application/json" in resp.headers.get("content-type", "") else {}
                        
                        # Check if sensitive fields (role, api_key, email) are exposed
                        leaked_key = None
                        leaked_role = None
                        if isinstance(data, dict):
                            for k, v in data.items():
                                if "api_key" in k.lower() or "apikey" in k.lower() or "token" in k.lower():
                                    leaked_key = str(v)
                                if "role" in k.lower():
                                    leaked_role = str(v)

                        evidence = f"Endpoint returned 200 OK for user_id={uid} without session auth. Role: {leaked_role}"
                        yielded_post = {
                            "bola_confirmed": True,
                            "disclosed_user": uid
                        }

                        if leaked_key:
                            yielded_post["leaked_artifact"] = {
                                "type": LeakedArtifactType.API_KEY.value,
                                "key": "api_key",
                                "value": leaked_key
                            }

                        finding = VulnerabilityFinding(
                            id=f"VULN-BOLA-{uid}-{path.replace('/', '_')}",
                            vuln_type=VulnerabilityType.BOLA_IDOR,
                            title=f"Broken Object Level Authorization (BOLA) at {path}",
                            severity=Severity.HIGH,
                            endpoint=path,
                            description=f"Unauthenticated request with user_id={uid} retrieved full user profile data and credentials.",
                            evidence=evidence,
                            cwe_id="CWE-639",
                            cvss_score=7.5,
                            required_preconditions={
                                "privilege": "unauthenticated",
                                "artifact_type": LeakedArtifactType.USER_ID.value
                            },
                            yielded_postconditions=yielded_post,
                            remediation="Implement server-side session-to-object ownership validation on every data access query."
                        )
                        self.blackboard.add_finding(finding)
                        break

                except Exception:
                    continue
