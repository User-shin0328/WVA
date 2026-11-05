import pytest
import pytest_asyncio
import httpx
from core.rules.contracts import ScanOptions
from core.http.requester import RequestBudget, ResourceLimit
from agents.policy_auditor import PolicyAuditor
from core.graph.blackboard import SecurityBlackboard
from core.safety.governance import SafetyGovernance
from core.models.asset import HttpEndpoint

@pytest.mark.asyncio
async def test_request_budget_safe_and_deep_modes():
    gov = SafetyGovernance("http://example.com")
    options_safe = ScanOptions(mode="safe", max_requests=50)
    budget_safe = RequestBudget(gov, options_safe)

    # GET is allowed
    req_get = httpx.Request("GET", "http://example.com/resource")
    await budget_safe.enforce(req_get)

    # DELETE is blocked by default
    req_del = httpx.Request("DELETE", "http://example.com/resource")
    with pytest.raises(ValueError, match="진단 경계"):
        await budget_safe.enforce(req_del)

    # Deep mode budget
    options_deep = ScanOptions(mode="deep", max_requests=1000)
    budget_deep = RequestBudget(gov, options_deep)

    # Unauthorized DELETE is blocked
    req_del_unauth = httpx.Request("DELETE", "http://example.com/unauthorized")
    with pytest.raises(ValueError, match="진단 경계"):
        await budget_deep.enforce(req_del_unauth)

    # Registered teardown URL DELETE is permitted
    teardown_target = "http://example.com/items/wva_test_item_99"
    budget_deep.allow_delete(teardown_target)
    req_del_teardown = httpx.Request("DELETE", teardown_target)
    await budget_deep.enforce(req_del_teardown)

@pytest.mark.asyncio
async def test_policy_auditor_safe_mode_skips_deep_tests():
    bb = SecurityBlackboard("http://example.com")
    gov = SafetyGovernance("http://example.com")
    options = ScanOptions(mode="safe")
    budget = RequestBudget(gov, options)
    auditor = PolicyAuditor(bb, gov, options, budget)

    class DummyClient:
        async def post(self, *args, **kwargs):
            raise AssertionError("POST should not be called in safe mode")
        async def delete(self, *args, **kwargs):
            raise AssertionError("DELETE should not be called in safe mode")
        async def get(self, *args, **kwargs):
            raise AssertionError("GET should not be called in safe mode")

    client = DummyClient()
    await auditor.concurrency(client)
    await auditor.teardown_lifecycle(client)

    checks = bb.asset.metadata.get("checks", [])
    check_titles = [c["title"] for c in checks]
    assert any("동시성" in title for title in check_titles)
    assert any("생명주기" in title for title in check_titles)
    # Both should be NOT_RUN in safe mode
    r15 = next(c for c in checks if "동시성" in c["title"])
    r14 = next(c for c in checks if "생명주기" in c["title"])
    assert r15["status"] == "NOT_RUN"
    assert r14["status"] == "NOT_RUN"

@pytest.mark.asyncio
async def test_policy_auditor_deep_mode_concurrency_and_teardown():
    bb = SecurityBlackboard("http://127.0.0.1")
    gov = SafetyGovernance("http://127.0.0.1")
    ep = HttpEndpoint(
        url="http://127.0.0.1/api/items?q=1",
        path="/api/items",
        method="GET",
        parameters=["q"]
    )
    bb.asset.endpoints.append(ep)
    options = ScanOptions(mode="deep")
    budget = RequestBudget(gov, options)
    auditor = PolicyAuditor(bb, gov, options, budget)

    class DummyResponse:
        def __init__(self, status_code):
            self.status_code = status_code
            self.headers = {}
            self.text = 'stable'

    class DummyClient:
        async def get(self, url, timeout=4.0):
            return DummyResponse(200)

    client = DummyClient()
    await auditor.concurrency(client)
    await auditor.teardown_lifecycle(client)

    checks = bb.asset.metadata.get("checks", [])
    r15 = next(c for c in checks if "동시성" in c["title"])
    r14 = next(c for c in checks if "생명주기" in c["title"])
    assert r15["status"] == "PASS"
    assert r14["status"] == "NOT_RUN"

@pytest.mark.asyncio
async def test_audit_consent_api_and_deep_mode(client):
    res = await client.post("/api/scan/start", json={
        "target_url": "http://127.0.0.1:8990",
        "consent": True,
        "mode": "deep"
    })
    assert res.status_code == 200
    data = res.json()
    assert data["mode"] == "deep"
    assert data["status"] == "started"

    status = (await client.get("/api/scan/status")).json()
    assert status["mode"] == "deep"

    consent_logs = (await client.get("/api/scan/consent_log")).json()
    assert len(consent_logs) >= 1
    latest = consent_logs[-1]
    assert latest["mode"] == "deep"
    assert "격리는 별도로 확인" in latest["statement"]
    assert latest["target_url"] == "http://127.0.0.1:8990"

    # Stop the scan
    stop_res = await client.post("/api/scan/stop", json={})
    assert stop_res.status_code == 200

@pytest.mark.asyncio
async def test_scan_options_are_respected(client):
    res = await client.post("/api/scan/start", json={
        "target_url": "http://127.0.0.1:8990",
        "consent": True,
        "options": {"sql": False, "browser": False}
    })
    assert res.status_code == 200
    import dashboard.server as d_server
    assert d_server.state.options.sql is False
    assert d_server.state.options.browser is False
    await client.post("/api/scan/stop", json={})

from agents.system_auditor import SystemAuditor
from agents.injection_auditor import InjectionAuditor
from core.models.vulnerability import VulnerabilityType

@pytest.mark.asyncio
async def test_legacy_lfi_cmdi_keywords_without_contract_do_not_confirm():
    bb = SecurityBlackboard("http://example.com")
    gov = SafetyGovernance("http://example.com")
    bb.asset.endpoints.append(HttpEndpoint(
        url="http://example.com/api/docs?file=guide",
        path="/api/docs",
        method="GET",
        parameters=["file"]
    ))
    bb.asset.endpoints.append(HttpEndpoint(
        url="http://example.com/api/tools/ping?target=127.0.0.1",
        path="/api/tools/ping",
        method="GET",
        parameters=["target"]
    ))
    options = ScanOptions(mode="safe")
    budget = RequestBudget(gov, options)
    auditor = SystemAuditor(bb, gov, options, budget)

    class MockResp:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code
            self.headers = {}
            self.request = httpx.Request("GET", "http://example.com/test")

    class MockClient:
        async def get(self, url, params=None, timeout=5.0):
            p = str(url) + " " + str(params)
            if "etc/passwd" in p or "win.ini" in p:
                return MockResp("root:x:0:0:root:/root:/bin/bash\nARTEX{PATH_TRAVERSAL_BREACH_5541}")
            if "whoami" in p or "wva_canary" in p:
                return MockResp("uid=0(root) gid=0(root)\nARTEX{REMOTE_CODE_EXECUTION_FLAG_1092}")
            return MockResp("Normal safe output")

    await auditor.audit_path_traversal(MockClient())
    await auditor.audit_command_injection(MockClient())

    findings = bb.get_findings_list()
    types = [f.vuln_type for f in findings]
    assert types == []

    checks = bb.asset.metadata.get("checks", [])
    r16 = next(c for c in checks if c["rule_id"] == "R16")
    r17 = next(c for c in checks if c["rule_id"] == "R17")
    assert r16["status"] == "NOT_RUN"
    assert r17["status"] == "NOT_RUN"

@pytest.mark.asyncio
async def test_legacy_ssrf_upload_keywords_without_contract_do_not_confirm():
    bb = SecurityBlackboard("http://example.com")
    gov = SafetyGovernance("http://example.com")
    bb.asset.endpoints.append(HttpEndpoint(
        url="http://example.com/api/webhook?url=test",
        path="/api/webhook",
        method="GET",
        parameters=["url"]
    ))
    bb.asset.endpoints.append(HttpEndpoint(
        url="http://example.com/api/upload",
        path="/api/upload",
        method="POST",
        parameters=[]
    ))
    options = ScanOptions(mode="safe")
    budget = RequestBudget(gov, options)
    auditor = SystemAuditor(bb, gov, options, budget)

    class MockResp:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code
            self.headers = {}
            self.request = httpx.Request("POST", "http://example.com/test")

    class MockClient:
        async def get(self, url, params=None, timeout=5.0):
            p = str(url) + " " + str(params)
            if "169.254.169.254" in p:
                return MockResp('{"service": "Cloud Metadata Service", "AccessKeyId": "ASIA123"}')
            return MockResp("Normal webhook response")

        async def post(self, url, json=None, files=None, headers=None, timeout=5.0):
            if "upload" in str(url):
                return MockResp('{"success": true, "path": "/uploads/shell.php", "flag": "ARTEX{ARBITRARY_FILE_UPLOAD_FLAG_4412}"}')
            return MockResp("Normal upload")

    client = MockClient()
    await auditor.audit_ssrf(client)
    await auditor.audit_file_upload(client)

    findings = bb.get_findings_list()
    types = [f.vuln_type for f in findings]
    assert types == []

    checks = bb.asset.metadata.get("checks", [])
    r18 = next(c for c in checks if c["rule_id"] == "R18")
    r19 = next(c for c in checks if c["rule_id"] == "R19")
    assert r18["status"] == "NOT_RUN"
    assert r19["status"] == "NOT_RUN"

@pytest.mark.asyncio
async def test_sql_success_banner_is_only_a_signal():
    bb = SecurityBlackboard("http://example.com")
    gov = SafetyGovernance("http://example.com")
    bb.asset.endpoints.append(HttpEndpoint(
        url="http://example.com/api/search?q=abc",
        path="/api/search",
        method="GET",
        parameters=["q"]
    ))
    options = ScanOptions(mode="safe", sql=True)
    auditor = InjectionAuditor(bb, gov, options)

    class MockResp:
        def __init__(self, text, status_code=200):
            self.text = text
            self.status_code = status_code
            self.headers = {}
            self.is_redirect = False

    class MockClient:
        async def get(self, url, params=None, timeout=5.0):
            from urllib.parse import urlsplit, parse_qs
            q = (params or {}).get("q", "") or parse_qs(urlsplit(url).query).get("q", [""])[0]
            if "AND 1=" in q or "SQL" in q:
                return MockResp("SQL Injection payload executed successfully! ARTEX{SQL_INJECTION_PWNED_8391}")
            return MockResp("Normal search result: 0 items")

    await auditor.audit(MockClient())
    findings = bb.get_findings_list()
    assert not any(f.vuln_type == VulnerabilityType.SQL_INJECTION for f in findings)
    checks = bb.asset.metadata.get("checks", [])
    r11 = next(c for c in checks if c["rule_id"] == "R11")
    assert r11["status"] == "SIGNAL"


@pytest.mark.asyncio
async def test_deep_mode_allows_remote_target(client):
    res = await client.post("/api/scan/start", json={
        "target_url": "https://staging.internal.corp",
        "consent": True,
        "mode": "deep"
    })
    assert res.status_code == 200
    assert res.json()["mode"] == "deep"
    await client.post("/api/scan/stop", json={})
