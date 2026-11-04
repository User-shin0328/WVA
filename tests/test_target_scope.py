"""Entry URL preservation and actual network boundaries, including mounted apps."""
import asyncio
from urllib.parse import urlsplit, parse_qs
import httpx
import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import ValidationError
from agents.engine import VulnerabilityAnalysisEngine
from core.graph.blackboard import SecurityBlackboard
from core.models.asset import HttpEndpoint
from core.safety.governance import SafetyGovernance
from dashboard.server import ScanRequest
from dashboard.testbed import LocalTestbed
from reporting.report_generator import SecurityReportGenerator


@pytest.mark.parametrize("url", [
    "https://example.com/app/", "https://example.com/app/login?next=%2Fapp%2F&lang=ko",
    "http://127.0.0.1:8990?empty=&tag=a&tag=b", "https://example.com/api/item?value=tail/",
])
def test_entry_path_and_query_are_preserved(url):
    req = ScanRequest(target_url=url)
    assert req.target_url == url


@pytest.mark.parametrize("path", ["/app/..", "/app/%2e%2e/", "/app/%252e%252e/"])
def test_ambiguous_entry_path_cannot_expand_the_scope_to_root(path):
    with pytest.raises(ValidationError):
        ScanRequest(target_url="https://example.com" + path)


@pytest.mark.parametrize("candidate", [
    "https://example.com/application", "https://example.com/private",
    "https://example.com/app/../private", "https://example.com/app/%2e%2e/private",
    "https://example.com/app/%252e%252e/private", "https://example.com/app/%255c..%255cprivate",
    "https://other.test/app/item", "http://example.com/app/item",
])
def test_path_boundary_rejects_siblings_traversal_and_other_origins(candidate):
    assert not SafetyGovernance("https://example.com/app/?page=1").is_in_scope(candidate)


def test_scope_choice_is_explicit_and_query_not_copied_to_other_paths():
    scope = SafetyGovernance("https://example.com/app/?page=1")
    assert scope.is_in_scope("https://example.com/app")
    assert scope.is_in_scope("https://example.com/app/items?id=2")
    assert scope.url_for_path("/app/") == "https://example.com/app/?page=1"
    assert scope.url_for_path("/app/items") == "https://example.com/app/items"
    assert SafetyGovernance("https://example.com/app/?page=1", scope_mode="origin").is_in_scope("https://example.com/other")
    with pytest.raises(ValidationError):
        ScanRequest(target_url="https://example.com/app/", scope_mode="all_hosts")


def test_query_variants_are_distinct_but_root_slash_is_not():
    bb = SecurityBlackboard("https://example.com")
    for url in ["https://example.com", "https://example.com/", "https://example.com/?page=1", "https://example.com/?page=2"]:
        bb.add_endpoint(HttpEndpoint(url=url, path="/"))
    assert len(bb.asset.endpoints) == 3


def scope_lab():
    app = FastAPI(docs_url=None, openapi_url=None)
    hits = []

    @app.middleware("http")
    async def record(request: Request, call_next):
        hits.append((request.method, request.url.path, str(request.url.query)))
        return await call_next(request)

    @app.get("/app/", response_class=HTMLResponse)
    async def entry(request: Request):
        if request.query_params.get("slow"):
            await asyncio.sleep(2)
        return '<a href="items?page=2&filter=active">items</a><a href="/outside">outside</a><a href="%2e%2e/private">escape</a><a href="/application">sibling</a>'

    @app.get("/app/items", response_class=HTMLResponse)
    async def items(request: Request):
        return '<a href="details?id=7">details</a><a href="/app/items?page=3">other page</a>' if request.query_params.get("page") == "2" else "ok"

    @app.get("/app/details")
    async def details():
        return {"ok": True}

    @app.get("/api/v1/user/profile")
    @app.get("/app/api/v1/user/profile")
    async def profile(request: Request):
        uid = request.query_params.get("user_id")
        return {"user_id": uid, "role": "test", "api_key": "fixture-key"} if uid else JSONResponse({}, status_code=422)

    @app.get("/app/debug/version")
    async def debug():
        return {"user_id": "fixture-user"}

    @app.get("/app/api/v1/admin/config")
    async def admin(request: Request):
        return {"privilege": "ADMIN"} if request.headers.get("X-API-Key") == "fixture-key" else JSONResponse({}, status_code=403)

    return app, hits


@pytest.mark.asyncio
async def test_mounted_app_follows_relative_links_and_keeps_actual_boundary():
    app, hits = scope_lab()
    lab = LocalTestbed(app)
    base = await lab.start()
    try:
        target = base + "/app/?lang=ko&tag=a&tag=b"
        engine = VulnerabilityAnalysisEngine(target)
        bb = await engine.execute_audit()
        assert hits and all(path == "/app" or path.startswith("/app/") for _,path,_ in hits)
        assert any(path == "/app/" and query == "lang=ko&tag=a&tag=b" for _,path,query in hits)
        assert any(path == "/app/items" and parse_qs(query).get("page") == ["2"] for _,path,query in hits)
        assert any(path == "/app/details" and query == "id=7" for _,path,query in hits)
        assert len(bb.chains) == 1 and len(bb.chains[0].steps) == 3
        assert all(f.endpoint.startswith("/app/") for f in bb.findings.values())
        assert SecurityReportGenerator(bb).generate_json_report()["target_url"] == target
    finally:
        await lab.stop()


@pytest.mark.asyncio
async def test_direct_query_endpoint_preserves_other_parameters_during_id_check():
    app, hits = scope_lab()
    lab = LocalTestbed(app)
    base = await lab.start()
    try:
        target = base + "/api/v1/user/profile?user_id=alice&lang=ko&tag=a&tag=b"
        bb = await VulnerabilityAnalysisEngine(target).execute_audit()
        assert any(f.vuln_type.value == "INFO_DISCLOSURE" for f in bb.findings.values())
        assert all(path == "/api/v1/user/profile" or path.startswith("/api/v1/user/profile/") for _,path,_ in hits)
        checks = [parse_qs(q) for _,p,q in hits if p == "/api/v1/user/profile"]
        assert all(q.get("lang") == ["ko"] and q.get("tag") == ["a", "b"] for q in checks)
        finding = next(f for f in bb.findings.values() if f.vuln_type.value == "INFO_DISCLOSURE")
        assert parse_qs(urlsplit(finding.request_url).query) == {"user_id": ["alice"], "lang": ["ko"], "tag": ["a", "b"]}
    finally:
        await lab.stop()


@pytest.mark.asyncio
async def test_origin_choice_can_probe_root_but_still_requests_the_entry():
    app, hits = scope_lab()
    lab = LocalTestbed(app)
    base = await lab.start()
    try:
        await VulnerabilityAnalysisEngine(base + "/app/?lang=ko", scope_mode="origin").execute_audit()
        assert any(p == "/app/" and q == "lang=ko" for _,p,q in hits)
        assert any(p == "/api/v1/user/profile" for _,p,_ in hits)
    finally:
        await lab.stop()


@pytest.mark.asyncio
async def test_dashboard_accepts_path_query_and_reports_selected_scope(client):
    app, _ = scope_lab()
    lab = LocalTestbed(app)
    base = await lab.start()
    try:
        target = base + "/app/?lang=ko"
        response = await client.post("/api/scan/start", json={"consent": True, "target_url": target, "scope_mode": "path"})
        assert response.status_code == 200 and response.json()["target_url"] == target
        for _ in range(400):
            status = (await client.get("/api/scan/status")).json()
            if status["status"] != "running":
                break
            await asyncio.sleep(.025)
        assert status["status"] == "completed" and status["scope_mode"] == "path"
        assert status["chains_count"] == 1
    finally:
        await lab.stop()
