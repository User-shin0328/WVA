# -*- coding: utf-8 -*-
import pytest
import json
import base64
import httpx
from core.graph.blackboard import SecurityBlackboard
from core.models.asset import HttpEndpoint
from core.models.vulnerability import VulnerabilityFinding, VulnerabilityType, Severity
from core.safety.governance import SafetyGovernance
from core.http.requester import RequestBudget
from agents.config_auditor import ConfigAndHeaderAuditor
from agents.system_auditor import SystemAuditor
from core.rules.contracts import ScanOptions
from reporting.selected_export import render_sarif, render_export
from dashboard.server import app, state


def test_kisa_web_mapping():
    f_sql = VulnerabilityFinding(
        id="VULN-SQL-1",
        vuln_type=VulnerabilityType.SQL_INJECTION,
        severity=Severity.HIGH,
        title="SQL Injection Detected",
        description="SQL injection vulnerability",
        endpoint="/items",
        evidence="' OR 1=1 --",
        remediation="Use parameterized queries",
        cwe_id="CWE-89"
    )
    assert f_sql.kisa_id == "KISA-WEB-01"

    f_xss = VulnerabilityFinding(
        id="VULN-XSS-1",
        vuln_type=VulnerabilityType.XSS,
        severity=Severity.HIGH,
        title="Stored XSS",
        description="XSS vulnerability",
        endpoint="/comment",
        evidence="<script>alert(1)</script>",
        remediation="Escape output",
        cwe_id="CWE-79"
    )
    assert f_xss.kisa_id == "KISA-WEB-02"

    f_redir = VulnerabilityFinding(
        id="VULN-REDIR-1",
        vuln_type=VulnerabilityType.OPEN_REDIRECT,
        severity=Severity.MEDIUM,
        title="Open Redirect",
        description="Arbitrary URL redirection",
        endpoint="/login?next=//evil.com",
        evidence="Location: //evil.com",
        remediation="Validate redirection targets",
        cwe_id="CWE-601"
    )
    assert f_redir.kisa_id == "KISA-WEB-04"

    f_sec_hdr = VulnerabilityFinding(
        id="VULN-CSP-1",
        vuln_type=VulnerabilityType.MISSING_SECURITY_HEADER,
        severity=Severity.LOW,
        title="Missing CSP",
        description="CSP header not present",
        endpoint="/",
        evidence="No CSP",
        remediation="Add CSP header",
        cwe_id="CWE-693"
    )
    assert f_sec_hdr.kisa_id == "KISA-WEB-17"


def test_sarif_export_rendering():
    payload = {
        "metadata": {
            "scan_id": "test_scan_123",
            "target_url": "http://target.local"
        },
        "findings": [
            {
                "id": "VULN-SQL-1",
                "vuln_type": "SQL_INJECTION",
                "severity": "HIGH",
                "title": "SQL Injection Detected",
                "description": "SQL injection vulnerability",
                "endpoint": "/search?q=test",
                "request_url": "http://target.local/search?q=test",
                "evidence": "' OR 1=1 -- returns extra rows",
                "remediation": "Use prepared statements",
                "cwe_id": "CWE-89",
                "kisa_id": "KISA-WEB-01",
                "cvss_score": 8.5
            }
        ]
    }
    sarif_str, media_type, ext = render_export(payload, "sarif")
    assert media_type == "application/sarif+json"
    assert ext == "sarif"

    data = json.loads(sarif_str)
    assert data["version"] == "2.1.0"
    assert "https://raw.githubusercontent.com/oasis-tcs/sarif-spec" in data["$schema"]
    run = data["runs"][0]
    assert run["tool"]["driver"]["name"] == "WVA"
    assert len(run["results"]) == 1
    res = run["results"][0]
    assert res["ruleId"] == "CWE-89"
    assert res["level"] == "error"
    assert res["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "http://target.local/search?q=test"

    rule = next(r for r in run["tool"]["driver"]["rules"] if r["id"] == "CWE-89")
    assert rule["properties"]["kisa"] == "KISA-WEB-01"
    assert rule["properties"]["cvss"] == 8.5


@pytest.mark.asyncio
async def test_jwt_inspection_alg_none_and_missing_exp():
    hdr = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').decode().rstrip('=')
    pld = base64.urlsafe_b64encode(b'{"sub":"user123","role":"admin"}').decode().rstrip('=')
    jwt_token = f"{hdr}.{pld}."

    bb = SecurityBlackboard("http://target.local")
    gov = SafetyGovernance("http://target.local", scope_mode="origin")
    auditor = ConfigAndHeaderAuditor(bb, gov)
    auditor._inspect_jwt(f"token={jwt_token}", "/profile")

    ids = list(bb.findings.keys())
    assert any("JWT-ALG-NONE" in f_id for f_id in ids)
    assert any("JWT-NO-EXP" in f_id for f_id in ids)


@pytest.mark.asyncio
async def test_cors_origin_null_audit():
    class DummyResponse:
        def __init__(self, headers):
            self.status_code = 200
            self.headers = httpx.Headers(headers)
            self.request = httpx.Request("GET", "http://target.local/api/data")
            self.text = "OK"

    class DummyClient:
        async def get(self, url, headers=None, follow_redirects=False, timeout=5.0):
            origin = (headers or {}).get("Origin", "")
            if origin == "null":
                return DummyResponse({
                    "Access-Control-Allow-Origin": "null",
                    "Access-Control-Allow-Credentials": "true"
                })
            return DummyResponse({})

    bb = SecurityBlackboard("http://target.local")
    ep = HttpEndpoint(
        url="http://target.local/api/data",
        path="/api/data",
        method="GET",
        headers={},
        source="surface_discovery"
    )
    bb.asset.endpoints.append(ep)

    gov = SafetyGovernance("http://target.local", scope_mode="origin")
    auditor = ConfigAndHeaderAuditor(bb, gov)
    client = DummyClient()
    await auditor._audit_cors(client, "http://target.local", "/api/data")

    null_finding = next((f for f in bb.findings.values() if "Null Origin Trust" in f.title), None)
    assert null_finding is not None
    assert null_finding.severity == Severity.HIGH


@pytest.mark.asyncio
async def test_system_auditor_auto_probe_open_redirect():
    class DummyResponse:
        def __init__(self, location=""):
            self.status_code = 302
            self.headers = {"location": location} if location else {}
            self.text = ""

    class DummyClient:
        async def get(self, url, headers=None, follow_redirects=False):
            if "redirect=https://example.com" in url or "redirect=https%3A%2F%2Fexample.com" in url:
                return DummyResponse("https://example.com")
            return DummyResponse()

    bb = SecurityBlackboard("http://target.local")
    ep = HttpEndpoint(
        url="http://target.local/login?redirect=prev",
        path="/login",
        method="GET",
        parameters=["redirect"],
        source="surface_discovery"
    )
    bb.asset.endpoints.append(ep)

    gov = SafetyGovernance("http://target.local", scope_mode="origin")
    options = ScanOptions(mode="deep")
    budget = RequestBudget(gov, options)
    auditor = SystemAuditor(bb, gov, options, budget)
    client = DummyClient()
    await auditor.audit(client)

    redir_finding = next((f for f in bb.findings.values() if f.vuln_type == VulnerabilityType.OPEN_REDIRECT), None)
    assert redir_finding is not None
    assert redir_finding.cwe_id == "CWE-601"
    assert redir_finding.kisa_id == "KISA-WEB-04"


def test_waf_detection_and_adaptive_delay():
    gov = SafetyGovernance("http://target.local", scope_mode="origin")
    budget = RequestBudget(gov, ScanOptions())
    assert budget.waf_detected is False
    assert budget.adaptive_delay == 0.0

    # Test BoundedClient WAF / 429 response handling
    client = budget.client()
    assert client._wva_budget.waf_detected is False


@pytest.mark.asyncio
async def test_retest_endpoint(client):
    import dashboard.server as dashboard
    assert (await client.post('/api/finding/retest',json={'finding_id':'missing'})).status_code==400
    dashboard.state.blackboard=SecurityBlackboard('http://127.0.0.1')
    assert (await client.post('/api/finding/retest',json={'finding_id':'missing'})).status_code==409
