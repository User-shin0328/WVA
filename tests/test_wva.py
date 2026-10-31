import asyncio
import json
from pathlib import Path
import socket
import httpx
import pytest
from fastapi import FastAPI
from fastapi.responses import RedirectResponse
from pydantic import ValidationError
import dashboard.server as dashboard
from dashboard.server import ScanRequest
from dashboard.testbed import LocalTestbed
from core.safety.governance import SafetyGovernance
from agents.engine import VulnerabilityAnalysisEngine
from tests.lab.target import hardened_app
from agents.config_auditor import ConfigAndHeaderAuditor
from core.graph.blackboard import SecurityBlackboard

@pytest.mark.parametrize("url", ["https://example.com/", "https://example.com:443"])
def test_same_origin_allowed(url):
    assert SafetyGovernance("https://example.com").is_in_scope(url)

@pytest.mark.parametrize("url", ["https://sub.example.com", "https://example.com.evil.test", "http://example.com", "https://example.com:444", "https://other.test", "file:///etc/hosts", "https://a:b@example.com"])
def test_outside_origin_blocked(url):
    assert not SafetyGovernance("https://example.com").is_in_scope(url)

@pytest.mark.parametrize("path", ["/delete-user", "/%64elete", "/%2564elete", "/reset-db", "/purchase"])
def test_destructive_paths_blocked(path):
    assert not SafetyGovernance("http://localhost").is_safe_endpoint(path)

@pytest.mark.parametrize("url", ["example.com", "ftp://example.com", "https://a:b@example.com", "http://localhost:99999", "http://localhost:0", "http://localhost/path", "http://localhost?x=1", "http://local host"])
def test_invalid_target_rejected(url):
    with pytest.raises(ValidationError):
        ScanRequest(target_url=url)

@pytest.mark.asyncio
async def test_empty_state_and_report_gate(client):
    assert (await client.get("/api/scan/status")).json()["findings_count"] == 0
    assert (await client.get("/api/scan/graph")).json() == {"nodes": [], "edges": []}
    assert (await client.get("/api/scan/report/md")).status_code == 409

@pytest.mark.asyncio
async def test_cross_origin_and_form_blocked(client):
    assert (await client.post("/api/scan/start", json={"demo": True}, headers={"Origin": "https://foreign.test"})).status_code == 403
    assert (await client.post("/api/scan/start", content="demo=true", headers={"Content-Type": "application/x-www-form-urlencoded"})).status_code == 415
    assert (await client.get("/api/health", headers={"Host": "foreign.test"})).status_code == 400

def test_secure_cookie_is_not_false_positive():
    bb = SecurityBlackboard("https://example.com")
    auditor = ConfigAndHeaderAuditor(bb, SafetyGovernance(bb.target_url))
    response = httpx.Response(200, headers={"Set-Cookie": "session=demo; Secure; HttpOnly; SameSite=Lax"}, request=httpx.Request("GET", bb.target_url))
    auditor._audit_cookies(response, "/")
    assert not bb.findings

@pytest.mark.parametrize("origin,credentials,expected", [("*","true",0),("https://evil-attacker.com","false",0),("https://evil-attacker.com","true",1)])
@pytest.mark.asyncio
async def test_cors_requires_credentialed_reflection(origin, credentials, expected):
    bb = SecurityBlackboard("http://example.com")
    auditor = ConfigAndHeaderAuditor(bb, SafetyGovernance(bb.target_url))
    def response(request):
        return httpx.Response(200, headers={"Access-Control-Allow-Origin": origin,"Access-Control-Allow-Credentials": credentials})
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as c:
        await auditor._audit_cors(c,bb.target_url,"/")
    assert len(bb.findings) == expected

async def wait_scan(client):
    for _ in range(400):
        value = (await client.get("/api/scan/status")).json()
        if value["status"] != "running":
            return value
        await asyncio.sleep(0.025)
    pytest.fail("scan did not finish in 10 seconds")

@pytest.mark.asyncio
async def test_vulnerable_demo_and_reports(client):
    started = await client.post("/api/scan/start", json={"demo": True})
    assert started.status_code == 200
    status = await wait_scan(client)
    assert status["status"] == "completed", status
    assert (status["endpoints_count"], status["findings_count"], status["chains_count"]) == (8, 5, 1)
    assert status["severity"] == {"CRITICAL": 1, "HIGH": 1, "MEDIUM": 1, "LOW": 2, "INFO": 0}
    findings = (await client.get("/api/scan/findings")).json()
    assert not any(f["vuln_type"] == "BOLA_IDOR" and f["endpoint"].endswith("export") for f in findings)
    chains = (await client.get("/api/scan/chains")).json()
    assert len(chains[0]["steps"]) == 3
    assert len(chains[0]["choke_points"]) == 3
    graph = (await client.get("/api/scan/graph")).json()
    ids = {n["data"]["id"] for n in graph["nodes"]}
    assert all(e["data"]["source"] in ids and e["data"]["target"] in ids for e in graph["edges"])
    report = (await client.get("/api/scan/report/json")).json()
    assert len(report["findings"]) == status["findings_count"]
    assert all(f["remediation_details"]["steps"] for f in report["findings"])
    assert len(report["exploit_chains"]) == status["chains_count"]
    assert (await client.get("/api/scan/report/md")).text.startswith("# Web Vulnerability")
    assert "#### 조치 순서" in (await client.get("/api/scan/report/md")).text
    for path in status["report_paths"]:
        assert Path(path).is_file()
    assert dashboard.state.testbed is None
    assert not any("supersecret_token" in item["data"] for item in (await client.get("/api/scan/logs")).json())

@pytest.mark.asyncio
async def test_direct_target_hardened_profile(client):
    lab = LocalTestbed(hardened_app())
    target = await lab.start()
    try:
        assert (await client.post("/api/scan/start", json={"target_url": target, "demo": False})).status_code == 200
        status = await wait_scan(client)
        assert status["status"] == "completed", status
        assert status["findings_count"] == 0
        assert status["chains_count"] == 0
        assert status["endpoints_count"] == 4
    finally:
        await lab.stop()

@pytest.mark.asyncio
async def test_unreachable_target_is_error(client):
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    await client.post("/api/scan/start", json={"target_url": f"http://127.0.0.1:{port}"})
    status = await wait_scan(client)
    assert status["status"] == "error"
    assert status["error"]
    assert not status["report_paths"]
    assert (await client.get("/api/scan/report/json")).status_code == 409

@pytest.mark.asyncio
async def test_duplicate_start_cancel_and_reset(client, monkeypatch):
    original = dashboard.VulnerabilityAnalysisEngine
    class SlowEngine(original):
        async def execute_audit(self):
            await asyncio.sleep(30)
    monkeypatch.setattr(dashboard, "VulnerabilityAnalysisEngine", SlowEngine)
    dashboard.state.last_error = "old error"
    first = await client.post("/api/scan/start", json={"target_url": "http://127.0.0.1:8990"})
    assert first.status_code == 200
    assert (await client.post("/api/scan/start", json={"demo": True})).status_code == 409
    assert not dashboard.state.last_error
    assert (await client.post("/api/scan/stop", json={})).json()["status"] == "stopped"
    assert dashboard.state.scan_task.done()
    assert (await client.get("/api/scan/report/md")).status_code == 409
    assert (await client.post("/api/scan/stop", json={})).json()["status"] == "not_running"

@pytest.mark.asyncio
async def test_events_broadcast_and_replay(client):
    dashboard.event_callback("log", "one")
    dashboard.event_callback("log", "two")
    class Reader:
        headers = {}
        async def is_disconnected(self):
            return False
    a = await dashboard.sse_events(Reader())
    b = await dashboard.sse_events(Reader())
    assert await anext(a.body_iterator) == await anext(b.body_iterator)
    replay = Reader()
    replay.headers = {"last-event-id": "1"}
    c = await dashboard.sse_events(replay)
    assert '"data": "two"' in await anext(c.body_iterator)
    await a.body_iterator.aclose()
    await b.body_iterator.aclose()
    await c.body_iterator.aclose()

@pytest.mark.asyncio
async def test_redirects_do_not_escape_scope():
    external = FastAPI()
    hits = []
    @external.get("/")
    async def endpoint():
        hits.append(1)
        return {"unexpected": True}
    outside = LocalTestbed(external)
    outside_url = await outside.start()
    local = FastAPI()
    @local.get("/")
    async def redirect():
        return RedirectResponse(outside_url)
    inside = LocalTestbed(local)
    inside_url = await inside.start()
    try:
        await VulnerabilityAnalysisEngine(inside_url).execute_audit()
        assert not hits
    finally:
        await inside.stop()
        await outside.stop()
