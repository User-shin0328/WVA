import json
import httpx
from agents.base import BaseAuditor
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.models.state import LeakedArtifactType

class ConfigAndHeaderAuditor(BaseAuditor):
    """
    Audits security headers, cookie flags, CORS configuration,
    and passive information disclosure endpoints.
    """
    async def audit(self, client: httpx.AsyncClient):
        base_url = self.blackboard.target_url.rstrip("/")

        # 1. Audit root and base endpoints for security headers
        try:
            resp = await client.get(base_url, timeout=5.0)
            self._audit_headers(resp, "/")
            self._audit_cookies(resp, "/")
            await self._audit_cors(client, base_url, "/")
        except Exception as e:
            self.blackboard.log(f"[Auditor:Config] Base URL check failed: {e}")

        for ep in list(self.blackboard.asset.endpoints):
            if ep.path != "/" and ep.method == "GET":
                await self._audit_cors(client, base_url, ep.path)

        # 2. Check for Debug/Information Disclosure Endpoints
        debug_endpoints = ["/debug/version", "/debug/config", "/api/v1/info"]
        for path in debug_endpoints:
            url = f"{base_url}{path}"
            try:
                d_resp = await client.get(url, timeout=5.0)
                if d_resp.status_code == 200:
                    self._inspect_debug_response(d_resp, path)
            except Exception:
                continue

    def _audit_headers(self, resp: httpx.Response, endpoint: str):
        headers = {k.lower(): v for k, v in resp.headers.items()}
        
        # CSP Check
        if "content-security-policy" not in headers:
            self.blackboard.add_finding(
                VulnerabilityFinding(
                    id=f"VULN-CSP-MISSING-{endpoint.replace('/', '_')}",
                    vuln_type=VulnerabilityType.MISSING_SECURITY_HEADER,
                    title="Missing Content-Security-Policy (CSP)",
                    severity=Severity.LOW,
                    endpoint=endpoint,
                    description="The server does not enforce a Content-Security-Policy header, reducing defense-in-depth against XSS and content injection.",
                    evidence=f"HTTP Response Headers did not contain 'content-security-policy'",
                    cwe_id="CWE-1021",
                    cvss_score=3.1,
                    required_preconditions={"privilege": "unauthenticated"},
                    yielded_postconditions={"weakness": "csp_missing"},
                    remediation="Define and enforce a strict CSP (e.g. default-src 'self')."
                )
            )

        # HSTS Check
        if "strict-transport-security" not in headers and resp.url.scheme == "https":
            self.blackboard.add_finding(
                VulnerabilityFinding(
                    id=f"VULN-HSTS-MISSING-{endpoint.replace('/', '_')}",
                    vuln_type=VulnerabilityType.MISSING_SECURITY_HEADER,
                    title="Missing Strict-Transport-Security (HSTS)",
                    severity=Severity.LOW,
                    endpoint=endpoint,
                    description="The web server is served over HTTPS but lacks HSTS header to enforce encrypted connections.",
                    evidence=f"HSTS header missing on HTTPS endpoint",
                    cwe_id="CWE-319",
                    cvss_score=3.5,
                    required_preconditions={"privilege": "unauthenticated"},
                    remediation="Add Strict-Transport-Security: max-age=31536000; includeSubDomains."
                )
            )

    def _audit_cookies(self, resp: httpx.Response, endpoint: str):
        for cookie in resp.cookies.jar:
            flags_missing = []
            if not cookie.secure:
                flags_missing.append("Secure")
            if "httponly" not in {key.lower() for key in cookie._rest}:
                flags_missing.append("HttpOnly")

            if flags_missing:
                self.blackboard.add_finding(
                    VulnerabilityFinding(
                        id=f"VULN-COOKIE-{cookie.name}-{endpoint.replace('/', '_')}",
                        vuln_type=VulnerabilityType.COOKIE_SECURITY_FLAG,
                        title=f"Insecure Cookie Flags ({cookie.name})",
                        severity=Severity.LOW,
                        endpoint=endpoint,
                        description=f"Cookie '{cookie.name}' is missing security flags: {', '.join(flags_missing)}.",
                        evidence=f"Cookie {cookie.name}: Secure={cookie.secure}",
                        cwe_id="CWE-1004",
                        cvss_score=3.0,
                        required_preconditions={"privilege": "unauthenticated"},
                        remediation="Set 'HttpOnly; Secure; SameSite=Lax' flags on all session cookies."
                    )
                )

    async def _audit_cors(self, client: httpx.AsyncClient, base_url: str, endpoint: str):
        test_origin = "https://evil-attacker.com"
        try:
            resp = await client.get(f"{base_url}{endpoint}", headers={"Origin": test_origin}, timeout=5.0)
            acao = resp.headers.get("access-control-allow-origin")
            acac = resp.headers.get("access-control-allow-credentials")

            if acao == test_origin:
                if acac and acac.lower() == "true":
                    self.blackboard.add_finding(
                        VulnerabilityFinding(
                            id=f"VULN-CORS-{endpoint.replace('/', '_')}",
                            vuln_type=VulnerabilityType.CORS_MISCONFIGURATION,
                            title="Permissive CORS Origin Reflection",
                            severity=Severity.MEDIUM,
                            endpoint=endpoint,
                            description=f"The application reflects arbitrary origin '{test_origin}' with Access-Control-Allow-Credentials: true, allowing cross-origin credentialed reads.",
                            evidence=f"ACAO: {acao}, ACAC: {acac}",
                            cwe_id="CWE-346",
                            cvss_score=6.5,
                            required_preconditions={"privilege": "unauthenticated"},
                            yielded_postconditions={"cors_leak_possible": True},
                            remediation="Implement strict origin allowlists and never reflect arbitrary origins with credentials."
                        )
                    )
        except Exception:
            pass

    def _inspect_debug_response(self, resp: httpx.Response, endpoint: str):
        try:
            data = resp.json()
            # Check for leaked user IDs, tokens, or debug flags
            evidence_items = []
            leaked_artifact = None

            if isinstance(data, dict):
                for k, v in data.items():
                    k_lower = k.lower()
                    if "user_id" in k_lower or "userid" in k_lower or "staging_user" in k_lower:
                        evidence_items.append(f"{k}: {v}")
                        leaked_artifact = {
                            "type": LeakedArtifactType.USER_ID.value,
                            "key": k,
                            "value": str(v)
                        }
                    elif "api_key" in k_lower or "token" in k_lower or "secret" in k_lower:
                        evidence_items.append(f"{k}: [REDACTED]")
                        leaked_artifact = {
                            "type": LeakedArtifactType.API_KEY.value,
                            "key": k,
                            "value": str(v)
                        }

            if evidence_items:
                evidence_str = "; ".join(evidence_items)
                finding = VulnerabilityFinding(
                    id=f"VULN-INFO-DEBUG-{endpoint.replace('/', '_')}",
                    vuln_type=VulnerabilityType.EXPOSED_DEBUG_ENDPOINT,
                    title=f"Sensitive Information Disclosure at {endpoint}",
                    severity=Severity.LOW,
                    endpoint=endpoint,
                    description=f"Debug endpoint exposes internal identifiers and system metadata without authentication.",
                    evidence=f"Disclosed metadata: {evidence_str}",
                    cwe_id="CWE-200",
                    cvss_score=4.3,
                    required_preconditions={"privilege": "unauthenticated"},
                    yielded_postconditions={
                        "leaked_artifact": leaked_artifact or {"type": "debug_info", "key": "metadata", "value": evidence_str}
                    },
                    remediation="Disable debug endpoints in production environments and restrict access via authentication middleware."
                )
                self.blackboard.add_finding(finding)
        except Exception:
            pass
