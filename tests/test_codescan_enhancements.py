import pytest
import json
from pathlib import Path
from reporting.remediation import build_ai_prompt, finding_details
from dashboard.server import compute_score_and_grade, get_previous_scan_report
from agents.config_auditor import ConfigAndHeaderAuditor
from core.graph.blackboard import SecurityBlackboard
from core.models.asset import HttpEndpoint
from core.safety.governance import SafetyGovernance

def test_compute_score_and_grade():
    assert compute_score_and_grade([]) == (100, "A")

    findings_a = [{"severity": "LOW"}]
    assert compute_score_and_grade(findings_a) == (97, "A")

    findings_b = [{"severity": "HIGH"}]
    assert compute_score_and_grade(findings_b) == (85, "B")

    findings_c = [{"severity": "CRITICAL"}]
    assert compute_score_and_grade(findings_c) == (75, "C")

    findings_d = [{"severity": "CRITICAL"}, {"severity": "HIGH"}, {"severity": "CRITICAL"}]
    assert compute_score_and_grade(findings_d) == (35, "F")

def test_build_ai_prompt():
    f = {
        "id": "VULN-CSP-01",
        "title": "Missing Content-Security-Policy",
        "vuln_type": "MISSING_SECURITY_HEADER",
        "severity": "LOW",
        "endpoint": "/index.html",
        "cwe_id": "CWE-693",
        "evidence": "Header not present"
    }
    details = finding_details(f)
    assert "ai_prompt" in details
    prompt = details["ai_prompt"]
    assert "[취약점 조치 요청" in prompt
    assert "Missing Content-Security-Policy" in prompt
    assert "/index.html" in prompt
    assert "권고 조치 순서" in prompt
    assert "수정 후 확인 기준" in prompt
    assert "AI 요청 사항" in prompt

@pytest.mark.asyncio
async def test_audit_js_secrets_detection():
    class DummyResponse:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code

    class DummyClient:
        async def get(self, url, timeout=4.0):
            if str(url).endswith("/bundle.js"):
                return DummyResponse("const config = { apiKey: 'sk-1234567890abcdef1234567890abcdef' };")
            return DummyResponse("", 404)

    bb = SecurityBlackboard("http://example.com")
    ep = HttpEndpoint(
        url="http://example.com/bundle.js",
        path="/bundle.js",
        method="GET",
        source="script_parser"
    )
    bb.asset.endpoints.append(ep)
    gov = SafetyGovernance("http://example.com")
    auditor = ConfigAndHeaderAuditor(bb, gov)

    await auditor._audit_js_secrets(DummyClient())
    findings = bb.get_findings_list()
    assert len(findings) == 1
    f = findings[0]
    assert f.id.startswith("VULN-SECRET-LEAK")
    assert f.severity.value == "HIGH"
    assert f.cwe_id == "CWE-798"
    assert "sk-123" in f.evidence
    assert "[REDACTED]" in f.evidence

@pytest.mark.asyncio
async def test_consent_validation_in_start_scan(client):
    res = await client.post("/api/scan/start", json={
        "target_url": "http://127.0.0.1:8990",
        "consent": False,
        "demo": False
    })
    assert res.status_code == 400
    assert "동의" in res.json().get("detail", "")
