import asyncio
import csv
import io
import json
from pathlib import Path
import httpx
import pytest
from tests.test_wva import wait_scan
from reporting.selected_export import render_export
from surface.recon import SurfaceReconEngine
from core.graph.blackboard import SecurityBlackboard
from core.safety.governance import SafetyGovernance
from reporting.remediation import finding_details

async def demo(client):
    await client.post("/api/scan/start", json={"demo": True})
    result = await wait_scan(client)
    assert result["status"] == "completed", result
    return result

@pytest.mark.asyncio
async def test_surface_measured_metadata_and_openapi(client):
    result = await demo(client)
    endpoints = (await client.get("/api/scan/endpoints")).json()
    surface = (await client.get("/api/scan/surface")).json()
    profile = next(e for e in endpoints if e["path"] == "/api/v1/user/profile")
    assert profile["status_code"] == 422
    assert profile["response_time_ms"] >= 0
    assert profile["response_bytes"] > 0
    assert profile["content_type"] == "application/json"
    assert profile["checked_at"]
    assert "query:user_id" in profile["parameters"]
    assert {"link_parser", "surface_discovery", "openapi"}.issubset(profile["sources"])
    assert surface["measured_count"] + surface["schema_only_count"] == result["endpoints_count"]
    assert surface["auth_response_count"] == 1
    assert result["phase"] == 4
    assert len(surface["tech_stack"]) == len(set(surface["tech_stack"]))
    assert all("set-cookie" not in e["headers"] for e in endpoints)

@pytest.mark.asyncio
async def test_persistent_utf8_scan_log_and_rotation(client):
    first = await demo(client)
    path = Path(first["log_path"])
    lines = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert lines[0]["data"]["status"] == "running"
    assert lines[-1]["data"]["status"] == "completed"
    assert any("보고서" in str(line["data"]) for line in lines)
    assert all(line["event"] in ("log", "status") for line in lines)
    assert "supersecret_token" not in path.read_text(encoding="utf-8")
    second = await demo(client)
    assert first["log_path"] != second["log_path"]
    assert path.is_file() and Path(second["log_path"]).is_file()

@pytest.mark.parametrize("format", ["json", "md", "csv"])
@pytest.mark.asyncio
async def test_selected_export_formats_and_detailed_remediation(client, format):
    result = await demo(client)
    response = await client.post("/api/scan/export", json={"sections": ["findings"], "format": format, "scan_id": result["scan_id"]})
    assert response.status_code == 200
    assert "attachment" in response.headers["content-disposition"]
    if format == "json":
        content = response.json()
        assert set(content) == {"metadata", "findings"}
        assert len(content["findings"]) == 5
        assert all(f["remediation_details"]["actions"] and f["remediation_details"]["verification"] for f in content["findings"])
        for finding in content["findings"]:
            steps = finding["remediation_details"]["steps"]
            assert [s["order"] for s in steps] == list(range(1, len(steps) + 1))
            assert all(s["title"] and s["action"] and s["expected_result"] for s in steps)
    elif format == "md":
        assert "#### 조치사항" in response.text
        assert "#### 수정 후 확인" in response.text
        assert "1. **" in response.text and "완료 기준:" in response.text
        assert "## 공격 표면" not in response.text
    else:
        assert response.content.startswith(b"\xef\xbb\xbf")
        rows = list(csv.reader(io.StringIO(response.text.lstrip("\ufeff"))))
        assert len(rows) == 7  # column headings + metadata + 5 findings
        assert all(len(row) == 22 for row in rows)
        assert rows[2][0] == "발견 항목"
        assert rows[2][13].startswith("1. ") and "완료 기준:" in rows[2][13]

@pytest.mark.parametrize("header", ["CSP", "HSTS"])
def test_header_remediation_does_not_mix_unrelated_policies(header):
    finding = {"id": "VULN-" + header, "title": "Missing " + header, "vuln_type": "MISSING_SECURITY_HEADER", "endpoint": "/"}
    result = finding_details(finding)["remediation_details"]
    content = json.dumps(result,ensure_ascii=False)
    if header == "CSP":
        assert "HSTS" not in content and "max-age" not in content
        assert "Report-Only" in content
    else:
        assert "CSP" not in content and "Report-Only" not in content
        assert "includeSubDomains" in content

@pytest.mark.parametrize("sections,format", [([], "json"), (["other"], "json"), (["summary", "summary"], "md"), (["logs"], "xlsx")])
@pytest.mark.asyncio
async def test_export_selection_validation(client, sections, format):
    response = await client.post("/api/scan/export", json={"sections": sections, "format": format, "scan_id": "test"})
    assert response.status_code == 422

@pytest.mark.asyncio
async def test_export_requires_completed_current_scan_and_full_disk_logs(client):
    payload = {"sections": ["logs"], "format": "json", "scan_id": "old"}
    assert (await client.post("/api/scan/export", json=payload)).status_code == 409
    result = await demo(client)
    assert (await client.post("/api/scan/export", json=payload)).status_code == 409
    payload["scan_id"] = result["scan_id"]
    response = await client.post("/api/scan/export", json=payload)
    content = response.json()
    assert set(content) == {"metadata", "logs"}
    records = [json.loads(line) for line in Path(result["log_path"]).read_text(encoding="utf-8").splitlines()]
    assert len(content["logs"]) == sum(r["event"] == "log" for r in records)

def test_csv_preserves_rows_and_blocks_formulas():
    payload = {"metadata": {"scan_id": "test", "target_url": "http://127.0.0.1"}, "findings": [
        {"id": "1", "title": "=formula()", "evidence": "comma, and\nnew line", "endpoint": "+bad"}]}
    text, media, extension = render_export(payload,"csv")
    rows = list(csv.reader(io.StringIO(text.lstrip("\ufeff"))))
    assert rows[2][5] == "'=formula()"
    assert rows[2][7] == "'+bad"
    assert rows[2][11] == "comma, and\nnew line"

@pytest.mark.asyncio
async def test_openapi_discovery_never_executes_declared_operations():
    bb = SecurityBlackboard("http://lab.test")
    engine = SurfaceReconEngine(bb, SafetyGovernance(bb.target_url))
    requests = []
    def response(request):
        requests.append((request.method,str(request.url)))
        if request.url.path == "/openapi.json":
            return httpx.Response(200, json={"paths": {"/new-api": {"post": {"parameters": [{"in":"query","name":"q"}]}}, "//other.test/out": {"get": {}}, "/delete-db": {"get": {}}}})
        return httpx.Response(404)
    async with httpx.AsyncClient(transport=httpx.MockTransport(response)) as client:
        await engine.run_discovery(client)
    endpoint = bb.asset.find_endpoint("/new-api", "POST")
    assert endpoint and endpoint.status_code is None
    assert endpoint.parameters == ["query:q"]
    assert not bb.asset.find_endpoint("/delete-db")
    assert all(method == "GET" and "other.test" not in url and "/new-api" not in url for method,url in requests)
