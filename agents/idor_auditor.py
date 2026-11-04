import httpx
from urllib.parse import urlsplit, parse_qs
from agents.base import BaseAuditor
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.models.state import LeakedArtifactType, PrivilegeLevel
from core.rules.contracts import record

class IdorAndBolaAuditor(BaseAuditor):
    """
    Tests for Broken Object Level Authorization (BOLA / IDOR).
    Takes harvested identifiers (e.g. from debug endpoints or candidate lists)
    and verifies whether arbitrary object data can be read without proper authorization.
    """
    async def audit(self, client: httpx.AsyncClient):
        if client.auth is not None or client.headers.get('authorization') or client.headers.get('x-api-key') or client.headers.get('cookie') or client.cookies:
            record(self.blackboard,'IDOR','미인증 자격증명 응답 대조','NOT_RUN','인증된 세션은 미인증 검사의 근거로 사용하지 않습니다.',required=False)
            return
        tested=found=0
        errors=[]

        # Gather candidate user IDs: from blackboard state + standard test fixtures
        candidate_ids = []
        candidate_ids.extend(parse_qs(urlsplit(self.blackboard.target_url).query).get("user_id", []))
        for art in self.blackboard.get_artifacts(LeakedArtifactType.USER_ID):
            candidate_ids.append(art.value)
        candidate_ids.extend(["usr_staging_99", "admin", "1001", "0"])
        candidate_ids = list(dict.fromkeys(candidate_ids))

        # Target endpoints known or discovered for user profiles/objects
        target_paths = self.governance.probe_paths(["/api/v1/user/profile", "/api/user/profile", "/api/v1/user/export"])
        target_paths += [ep.path for ep in self.blackboard.asset.endpoints if ep.method == "GET" and
                         (any(p.split(":")[-1] == "user_id" for p in ep.parameters) or ep.path.endswith(("/user/profile", "/user/export")))]

        for path in dict.fromkeys(target_paths):
            url = self.governance.url_for_path(path)
            if not self.governance.is_in_scope(url) or not self.governance.is_safe_endpoint(path):
                continue
            for uid in candidate_ids:
                try:
                    client.cookies.clear()
                    request_url = httpx.URL(url).copy_merge_params({"user_id": uid})
                    resp = await client.get(request_url, timeout=5.0)

                    if resp.status_code == 200:
                        data = resp.json() if "application/json" in resp.headers.get("content-type", "") else {}
                        
                        # Check if sensitive fields (role, api_key, email) are exposed
                        leaked_key = None
                        leaked_role = None
                        if isinstance(data, dict):
                            for k, v in data.items():
                                if "api_key" in k.lower() or "apikey" in k.lower() or "token" in k.lower():
                                    if isinstance(v,str) and len(v)>=8 and v.lower() not in ('null','none','[redacted]'):leaked_key = v
                                if "role" in k.lower():
                                    leaked_role = str(v)

                        # A generic 200 (for example an export status) is not proof of BOLA.
                        if not isinstance(data, dict) or str(data.get("user_id", "")) != uid or not leaked_key:
                            continue
                        client.cookies.clear()
                        repeat=await client.get(request_url,timeout=5.0)
                        if repeat.status_code!=200 or repeat.json()!=data:raise ValueError('미인증 응답이 반복 대조에서 일치하지 않습니다.')
                        tested+=1
                        evidence = f"Endpoint returned 200 OK for user_id={uid} without session auth. Role: {leaked_role}"
                        yielded_post = {
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
                            vuln_type=VulnerabilityType.INFO_DISCLOSURE,
                            title=f"미인증 자격증명 응답 노출 at {path}",
                            severity=Severity.HIGH,
                            endpoint=path,
                            request_url=str(resp.request.url),
                            description=f"별도 미인증 요청에서 user_id={uid}와 자격증명 필드가 반복 노출됐습니다. 계정 간 소유권 위반은 별도 선언 정책으로 확인해야 합니다.",
                            evidence=evidence,
                            cwe_id="CWE-200",
                            cvss_score=7.5,
                            required_preconditions={
                                "privilege": "unauthenticated",
                                **({'artifact_ref':{'type':LeakedArtifactType.USER_ID.value,'value':uid,'session':'anonymous'}}
                                   if any(a.value==uid for a in self.blackboard.get_artifacts(LeakedArtifactType.USER_ID)) else {})
                            },
                            yielded_postconditions=yielded_post,
                            remediation="Implement server-side session-to-object ownership validation on every data access query."
                        )
                        self.blackboard.add_finding(finding)
                        found+=1
                        if leaked_key:
                            break

                except Exception as exc:
                    errors.append(type(exc).__name__)
        record(self.blackboard,'IDOR','미인증 자격증명 응답 대조','FINDING' if found else 'ERROR' if errors else 'PASS' if tested else 'NOT_RUN',
               f'미인증 자격증명 반복 대조 {tested}개, 노출 {found}개. 소유권 정책은 별도 검사합니다.',tested,found,len(errors),required=False)
