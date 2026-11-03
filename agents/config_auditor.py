import json
import re
import asyncio
import ssl
from contextlib import suppress
from datetime import datetime, timezone
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
        base_url = self.governance.origin_url
        entry_path = self.governance.entry_path

        # 1. Audit root and base endpoints for security headers
        try:
            resp = await client.get(self.governance.target_base_url, timeout=5.0)
            self._audit_headers(resp, entry_path)
            self._audit_cookies(resp, entry_path)
            await self._audit_cors(client, base_url, entry_path)
        except Exception as e:
            self.blackboard.log(f"[Auditor:Config] Base URL check failed: {e}")

        for ep in list(self.blackboard.asset.endpoints):
            if ep.url != str(httpx.URL(self.governance.target_base_url).copy_with(path=entry_path)) and ep.method == "GET":
                await self._audit_cors(client, base_url, ep.path, ep.url)

        # 2. Check for Debug/Information Disclosure Endpoints
        debug_endpoints = self.governance.probe_paths(["/debug/version", "/debug/config", "/api/v1/info"])
        debug_endpoints += [ep.path for ep in self.blackboard.asset.endpoints if ep.path.endswith(("/debug/version", "/debug/config", "/api/v1/info"))]
        for path in dict.fromkeys(debug_endpoints):
            url = self.governance.url_for_path(path)
            if not self.governance.is_in_scope(url) or not self.governance.is_safe_endpoint(path):
                continue
            try:
                d_resp = await client.get(url, timeout=5.0)
                if d_resp.status_code == 200:
                    self._inspect_debug_response(d_resp, path)
            except Exception:
                continue

        # 3. Check client-side JS bundles for leaked secrets
        await self._audit_js_secrets(client)

        # 4. Check TLS/SSL certificate status and HTTPS enforcement
        await self._audit_tls_security(client)

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
                    request_url=str(resp.request.url),
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
                    request_url=str(resp.request.url),
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
                        request_url=str(resp.request.url),
                        description=f"Cookie '{cookie.name}' is missing security flags: {', '.join(flags_missing)}.",
                        evidence=f"Cookie {cookie.name}: Secure={cookie.secure}",
                        cwe_id="CWE-1004",
                        cvss_score=3.0,
                        required_preconditions={"privilege": "unauthenticated"},
                        remediation="Set 'HttpOnly; Secure; SameSite=Lax' flags on all session cookies."
                    )
                )

    async def _audit_cors(self, client: httpx.AsyncClient, base_url: str, endpoint: str, request_url=None):
        test_origin = "https://evil-attacker.com"
        try:
            url = request_url or self.governance.url_for_path(endpoint)
            if not self.governance.is_in_scope(url) or not self.governance.is_safe_endpoint(endpoint):
                return
            resp = await client.get(url, headers={"Origin": test_origin}, timeout=5.0)
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
                            request_url=str(resp.request.url),
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
                    request_url=str(resp.request.url),
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

    async def _audit_js_secrets(self, client: httpx.AsyncClient):
        js_endpoints = [
            ep for ep in self.blackboard.asset.endpoints
            if (ep.path.endswith(".js") or "script_parser" in (ep.sources or []))
            and ep.method == "GET"
        ]
        secret_patterns = [
            ("OpenAI API Key", re.compile(r"(sk-(?:proj-)?[A-Za-z0-9_-]{24,})")),
            ("AWS Access Key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
            ("Google/Firebase API Key", re.compile(r"\b(AIza[0-9A-Za-z\-_]{35})\b")),
            ("Slack Token", re.compile(r"\b(xox[baprs]-[0-9A-Za-z-]{10,})\b")),
            ("Private Key Header", re.compile(r"(-----BEGIN [A-Z ]*PRIVATE KEY-----)")),
        ]
        checked = set()
        for ep in js_endpoints[:5]:
            if ep.url in checked or not self.governance.is_in_scope(ep.url):
                continue
            checked.add(ep.url)
            try:
                resp = await client.get(ep.url, timeout=4.0)
                if resp.status_code == 200 and resp.text:
                    body = resp.text[:1_000_000]
                    for name, pat in secret_patterns:
                        m = pat.search(body)
                        if m:
                            raw = m.group(1)
                            masked = raw[:6] + "...[REDACTED]"
                            self.blackboard.add_finding(
                                VulnerabilityFinding(
                                    id=f"VULN-SECRET-LEAK-{ep.path.replace('/', '_')[:30]}",
                                    vuln_type=VulnerabilityType.INFO_DISCLOSURE,
                                    title=f"Frontend Script Secret Leak ({name})",
                                    severity=Severity.HIGH,
                                    endpoint=ep.path,
                                    request_url=str(resp.request.url) if hasattr(resp, "request") and getattr(resp, "request") is not None else ep.url,
                                    description=f"Publicly accessible client-side JavaScript exposes sensitive credential ({name}).",
                                    evidence=f"Disclosed {name} in {ep.path}: {masked}",
                                    cwe_id="CWE-798",
                                    cvss_score=7.5,
                                    required_preconditions={"privilege": "unauthenticated"},
                                    remediation="Remove sensitive secrets from client-side bundles and proxy requests via backend server."
                                )
                            )
                            break
            except Exception:
                continue

    async def _audit_tls_security(self, client: httpx.AsyncClient):
        target = self.governance.target_base_url
        parsed = httpx.URL(target)
        host = parsed.host
        if not host or host in ("127.0.0.1", "localhost", "::1", "testserver"):
            return

        if parsed.scheme == "https":
            port = parsed.port or 443
            try:
                ctx = ssl.create_default_context()
                writer = None
                try:
                    _, writer = await asyncio.wait_for(asyncio.open_connection(host, port, ssl=ctx, server_hostname=host), timeout=3.0)
                    ssl_object = writer.get_extra_info("ssl_object")
                    cert = ssl_object.getpeercert() if ssl_object else None
                    if cert and "notAfter" in cert:
                        expire_dt = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
                        days_left = (expire_dt - datetime.now(timezone.utc)).total_seconds() / 86400
                        if days_left <= 15:
                            self.blackboard.add_finding(
                                VulnerabilityFinding(
                                    id=f"VULN-TLS-EXPIRING-{host.replace('.', '_')}",
                                    vuln_type=VulnerabilityType.MISSING_SECURITY_HEADER,
                                    title="TLS Certificate Expiring Soon",
                                    severity=Severity.HIGH if days_left <= 0 else Severity.MEDIUM,
                                    endpoint=parsed.path or "/",
                                    request_url=target,
                                    description=f"The SSL/TLS certificate for {host} expires on {expire_dt.strftime('%Y-%m-%d')} ({days_left} days remaining).",
                                    evidence=f"Certificate notAfter={cert['notAfter']} (remaining days: {days_left:.1f})",
                                    cwe_id="CWE-295",
                                    cvss_score=6.5 if days_left <= 0 else 4.5,
                                    required_preconditions={"privilege": "unauthenticated"},
                                    remediation="Renew and reconfigure the SSL/TLS certificate before expiration to avoid browser warnings."
                                )
                            )
                finally:
                    if writer:
                        writer.close()
                        with suppress(Exception):
                            await asyncio.wait_for(writer.wait_closed(), timeout=1.0)
            except Exception:
                pass
