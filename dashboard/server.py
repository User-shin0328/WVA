"""Local WVA dashboard with owned scan lifecycle and broadcast event replay."""
import asyncio
from collections import deque
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import uuid
import re
from typing import Literal
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, PlainTextResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from fastapi.exceptions import RequestValidationError
import uvicorn
from agents.engine import VulnerabilityAnalysisEngine
from core.graph.attack_graph import AttackGraphEngine
from reporting.report_generator import SecurityReportGenerator
from dashboard.testbed import LocalTestbed
from reporting.remediation import finding_details
from reporting.selected_export import render_export
from core.safety.target import normalize_target_url
from core.rules.contracts import ScanOptions
from core.rules.redaction import public_data
import hashlib

STATIC_DIR = Path(__file__).parent / "static"
VERSION = "2.5.0"

def now():
    return datetime.now(timezone.utc).isoformat()

def compute_score_and_grade(findings):
    def get_sev(f):
        if isinstance(f, dict):
            s = f.get("severity", "")
            return getattr(s, "value", s) if s else ""
        return getattr(f.severity, "value", str(f.severity))

    crit = sum(1 for f in findings if get_sev(f) == "CRITICAL")
    high = sum(1 for f in findings if get_sev(f) == "HIGH")
    med = sum(1 for f in findings if get_sev(f) == "MEDIUM")
    low = sum(1 for f in findings if get_sev(f) == "LOW")

    penalty = min(50, crit * 25) + min(30, high * 15) + min(20, med * 8) + min(10, low * 3)
    score = max(0, 100 - penalty)
    if score >= 90:
        grade = "A"
    elif score >= 80:
        grade = "B"
    elif score >= 70:
        grade = "C"
    elif score >= 60:
        grade = "D"
    else:
        grade = "F"
    return score, grade

def pending_checks(checks):
    return [r['title'] for r in checks if r['status']=='ERROR' or r.get('errors',0)>0 or (r['rule_id'] in ('R11','R12') and r['status'] not in ('PASS','FINDING'))]


def get_previous_scan_report(target_url: str, current_scan_id: str, profile=None):
    if not profile:
        return None
    report_dir = data_root() / "reports"
    if not report_dir.exists():
        return None
    files = sorted(report_dir.glob("*.json"), key=os.path.getmtime, reverse=True)
    for p in files:
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
            stem_id = p.stem.split("_")[-1] if "_" in p.stem else ""
            meta = data.get("scan_metadata", {})
            if (data.get("schema") == "wva-report-2" and data.get("target_url") == target_url and stem_id != current_scan_id
                    and meta.get("completed") is True and meta.get("scan_id") != current_scan_id and meta.get("profile") == profile):
                return data
        except Exception:
            continue
    return None

class ScanRequest(BaseModel):
    target_url: str = "http://127.0.0.1:8989"
    demo: bool = False
    scope_mode: Literal["path", "origin"] = "path"
    consent: bool = True
    options: ScanOptions = Field(default_factory=ScanOptions)

    @field_validator("target_url")
    @classmethod
    def validate_target(cls, value):
        return normalize_target_url(value)

class DashboardState:
    def __init__(self):
        self.status = "idle"
        self.target_url = ""
        self.blackboard = None
        self.scan_task = None
        self.last_error = ""
        self.scan_id = ""
        self.started_at = None
        self.finished_at = None
        self.demo = False
        self.events = deque(maxlen=1000)
        self.sequence = 0
        self.testbed = None
        self.report_paths = []
        self.log_path = ""
        self.log_error = ""
        self.phase = 0
        self.scope_mode = "path"

state = DashboardState()

def data_root():
    return Path(os.environ.get("WVA_DATA_DIR", Path(__file__).resolve().parents[1]))

def event_callback(event_type, data):
    state.sequence += 1
    record = {"id": state.sequence, "event": event_type, "data": data, "timestamp": now()}
    state.events.append(record)
    if event_type == "log" and isinstance(data, str):
        phase = re.search(r"\[Phase (\d)\]", data)
        if phase:
            state.phase = int(phase[1])
    if state.log_path and event_type in ("log", "status"):
        try:
            with Path(state.log_path).open("a", encoding="utf-8") as handle:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            state.log_error = "진단 로그 파일 기록 실패: " + str(exc)

async def run_scan_worker(target_url, is_demo, scope_mode="path", options=None):
    terminal_status = "completed"
    try:
        if is_demo:
            state.testbed = LocalTestbed()
            target_url = await state.testbed.start()
            state.target_url = target_url
            event_callback("log", "로컬 취약 실습 환경이 준비되었습니다.")
        engine = VulnerabilityAnalysisEngine(target_url, event_callback=event_callback, scope_mode=scope_mode, options=options)
        state.blackboard = engine.blackboard
        await asyncio.wait_for(engine.execute_audit(), timeout=180)
        state.blackboard.asset.metadata["report_metadata"] = {
            "scan_id": state.scan_id, "completed": True,
            "profile": {"scope_mode": state.scope_mode, "scope_path": engine.governance.scope_path or "/", "ruleset": VERSION,
                        "options": hashlib.sha256(json.dumps(engine.options.model_dump(mode='json',exclude={'sessions'}),sort_keys=True).encode()).hexdigest(),
                        "accounts": sorted(s.alias for s in engine.options.sessions)}}
        reporter = SecurityReportGenerator(state.blackboard)
        report_dir = data_root() / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        stem = datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + state.scan_id
        md_path, json_path = report_dir / (stem + ".md"), report_dir / (stem + ".json")
        md_path.write_text(reporter.generate_markdown_report(), encoding="utf-8")
        json_path.write_text(json.dumps(reporter.generate_json_report(), ensure_ascii=False, indent=2), encoding="utf-8")
        state.report_paths = [str(md_path), str(json_path)]
        event_callback("log", "진단이 완료되어 Markdown·JSON 보고서를 저장했습니다.")
    except asyncio.CancelledError:
        terminal_status = "stopped"
        event_callback("log", "사용자가 진단을 중단했습니다. 현재 결과는 부분 결과입니다.")
        raise
    except Exception as exc:
        terminal_status = "error"
        state.last_error = str(exc) or "진단 시간이 180초를 초과했습니다."
        event_callback("log", "진단 실패: " + state.last_error)
    finally:
        if state.testbed:
            await state.testbed.stop()
            state.testbed = None
        state.status = terminal_status
        state.finished_at = now()
        event_callback("status", {"status": state.status, "error": state.last_error})

async def cancel_scan():
    task = state.scan_task
    if task and not task.done():
        task.cancel()
        try:
            await task
        except asyncio.CancelledError:
            pass

@asynccontextmanager
async def lifespan(app):
    yield
    await cancel_scan()

app = FastAPI(title="WVA Local Auditor", lifespan=lifespan)

@app.exception_handler(RequestValidationError)
async def validation_error(request,exc):
    return JSONResponse({'detail':[{'loc':item['loc'],'msg':item['msg'],'type':item['type']} for item in exc.errors()]},status_code=422)

@app.middleware("http")
async def local_browser_boundary(request: Request, call_next):
    if request.url.hostname not in ("127.0.0.1", "localhost", "::1", "[::1]"):
        return JSONResponse({"detail": "로컬 주소로 접근하세요."}, status_code=400)
    if request.method == "POST":
        origin = request.headers.get("origin")
        if origin and origin != str(request.base_url).rstrip("/"):
            return JSONResponse({"detail": "다른 웹사이트에서 보낸 요청은 허용하지 않습니다."}, status_code=403)
        if request.headers.get("content-type", "").split(";")[0] != "application/json":
            return JSONResponse({"detail": "JSON 요청이 필요합니다."}, status_code=415)
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"
    response.headers["Cache-Control"] = "no-store"
    return response

@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse((STATIC_DIR / "index.html").read_text(encoding="utf-8"))

@app.get("/api/health")
async def health():
    return {"product": "WVA", "version": VERSION, "status": "ok"}

@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    if state.status == "running":
        raise HTTPException(409, "진단이 진행 중입니다. 완료하거나 중단한 뒤 다시 시작하세요.")
    if not req.consent and not req.demo:
        raise HTTPException(400, "진단 권한 확인에 동의해야 시작할 수 있습니다.")
    scan_id = uuid.uuid4().hex[:12]
    log_path = data_root() / "logs" / "scans" / (datetime.now().strftime("%Y%m%d_%H%M%S") + "_" + scan_id + ".jsonl")
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
        log_path.touch(exist_ok=False)
    except OSError as exc:
        raise HTTPException(503, "진단 로그 저장 위치를 준비하지 못했습니다.") from exc
    state.status = "running"
    state.blackboard = None
    state.last_error = ""
    state.events.clear()
    state.scan_id = scan_id
    state.log_path, state.log_error, state.phase = str(log_path), "", 0
    state.started_at, state.finished_at = now(), None
    state.demo, state.report_paths = req.demo, []
    state.scope_mode = req.scope_mode
    state.target_url = req.target_url if not req.demo else "로컬 실습 환경 준비 중"
    event_callback("status", {"status": "running", "target_url": state.target_url})
    state.scan_task = asyncio.create_task(run_scan_worker(req.target_url, req.demo, req.scope_mode, req.options))
    return {"status": "started", "target_url": state.target_url, "demo": req.demo, "scan_id": state.scan_id, "scope_mode": req.scope_mode}

@app.post("/api/scan/stop")
async def stop_scan():
    if state.status != "running":
        return {"status": "not_running"}
    await cancel_scan()
    if state.status == "running":
        state.status = "stopped"
        state.finished_at = now()
    return {"status": state.status}

@app.get("/api/scan/events")
async def sse_events(request: Request):
    try:
        cursor = int(request.headers.get("last-event-id", "0"))
    except ValueError:
        cursor = 0
    async def events():
        nonlocal cursor
        while not getattr(app.state, "shutting_down", False) and not await request.is_disconnected():
            batch = [e for e in state.events if e["id"] > cursor]
            if batch:
                for item in batch:
                    cursor = item["id"]
                    yield f"id: {cursor}\ndata: {json.dumps(item, ensure_ascii=False)}\n\n"
            else:
                yield ": heartbeat\n\n"
            await asyncio.sleep(0.3)
    return StreamingResponse(events(), media_type="text/event-stream", headers={"X-Accel-Buffering": "no"})

@app.get("/api/scan/status")
async def get_status():
    bb = state.blackboard
    findings = bb.get_findings_list() if bb else []
    severity = dict.fromkeys(("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"), 0)
    for f in findings:
        severity[f.severity.value] += 1
    checks=bb.asset.metadata.get('checks',[]) if bb else []
    score, grade = compute_score_and_grade(findings) if state.status == "completed" else (None, None)
    pending=pending_checks(checks)
    if pending and grade in ('A','B','C','D'):grade=None
    return {"status": state.status, "target_url": state.target_url,
            "endpoints_count": len(bb.asset.endpoints) if bb else 0,
            "findings_count": len(findings), "chains_count": len(bb.chains) if bb else 0,
            "severity": severity, "score": score, "grade": grade, "checks":checks,"assessment_complete":bool(checks) and not pending,
            "assessment_note":'전체 사이트 안전 등급이 아닌 발견 항목 기준 점수입니다.' if not pending else '판정 보류: '+', '.join(pending),
            "error": state.last_error, "scan_id": state.scan_id,
            "started_at": state.started_at, "finished_at": state.finished_at,
            "demo": state.demo, "report_paths": state.report_paths,
            "phase": state.phase, "scope_mode": state.scope_mode, "log_path": state.log_path, "log_error": state.log_error,
            "app_log_path": str(data_root() / "logs" / "WVA.log")}

@app.get("/api/scan/diff")
async def get_diff():
    if state.status != "completed" or not state.blackboard:
        return {"has_previous": False, "comparison_status": "not_completed"}
    curr_findings = [finding_details(f) for f in state.blackboard.get_findings_list()]
    curr_score, curr_grade = compute_score_and_grade(curr_findings)
    curr_grade=(await get_status())['grade']
    profile = public_data(state.blackboard.asset.metadata.get("report_metadata", {}).get("profile"),state.blackboard.private_values)
    prev = get_previous_scan_report(state.target_url, state.scan_id, profile)
    if not prev or not isinstance(prev.get("findings"), list):
        return {
            "has_previous": False,
            "comparison_status": "no_compatible_baseline",
            "current_score": curr_score,
            "current_grade": curr_grade
        }
    prev_findings = prev.get("findings", [])
    prev_score, prev_grade = compute_score_and_grade(prev_findings)
    prev_checks=prev.get('scan_scope',{}).get('checks',[])
    if prev_grade in ('A','B','C','D') and pending_checks(prev_checks):prev_grade=None
    prev_ids = {f["id"]: f for f in prev_findings if isinstance(f, dict) and "id" in f}
    curr_ids = {f["id"]: f for f in curr_findings if isinstance(f, dict) and "id" in f}

    fixed_ids = set(prev_ids.keys()) - set(curr_ids.keys())
    new_ids = set(curr_ids.keys()) - set(prev_ids.keys())
    persistent_ids = set(curr_ids.keys()) & set(prev_ids.keys())

    return {
        "has_previous": True,
        "previous_score": prev_score,
        "previous_grade": prev_grade,
        "current_score": curr_score,
        "current_grade": curr_grade,
        "score_diff": curr_score - prev_score,
        "fixed_count": len(fixed_ids),
        "new_count": len(new_ids),
        "persistent_count": len(persistent_ids),
        "fixed_findings": [prev_ids[i] for i in sorted(fixed_ids)],
        "new_ids": sorted(list(new_ids))
    }

@app.get("/api/scan/graph")
async def get_graph():
    return AttackGraphEngine(state.blackboard).to_cytoscape_elements() if state.blackboard else {"nodes": [], "edges": []}

@app.get("/api/scan/findings")
async def get_findings():
    return [finding_details(public_data(f.model_dump(mode='json'),state.blackboard.private_values)) for f in state.blackboard.get_findings_list()] if state.blackboard else []

@app.get("/api/scan/endpoints")
async def get_endpoints():
    return public_data([e.model_dump(mode="json") for e in state.blackboard.asset.endpoints],state.blackboard.private_values) if state.blackboard else []

@app.get("/api/scan/chains")
async def get_chains():
    return public_data([c.model_dump(mode="json") for c in state.blackboard.chains],state.blackboard.private_values) if state.blackboard else []

@app.get("/api/scan/logs")
async def get_logs():
    return [e for e in state.events if e["event"] == "log"]

@app.get("/api/scan/surface")
async def surface_summary():
    bb = state.blackboard
    eps = bb.asset.endpoints if bb else []
    methods, codes = {}, {}
    for ep in eps:
        methods[ep.method] = methods.get(ep.method, 0) + 1
        code = str(ep.status_code) if ep.status_code is not None else "unmeasured"
        codes[code] = codes.get(code, 0) + 1
    return {"target_url": state.target_url, "methods": methods, "status_codes": codes,
            "measured_count": sum(ep.status_code is not None for ep in eps),
            "schema_only_count": sum(ep.status_code is None for ep in eps),
            "auth_response_count": sum(ep.status_code in (401, 403) for ep in eps),
            "tech_stack": bb.asset.tech_stack if bb else []}

class ExportRequest(BaseModel):
    sections: list[Literal["summary", "findings", "chains", "endpoints", "logs"]] = Field(min_length=1, max_length=5)
    format: Literal["json", "md", "csv"]
    scan_id: str

    @field_validator("sections")
    @classmethod
    def unique_sections(cls, sections):
        if len(set(sections)) != len(sections):
            raise ValueError("저장 항목을 중복 선택할 수 없습니다.")
        return sections

@app.post("/api/scan/export")
async def selected_export(req: ExportRequest):
    completed_report()
    if req.scan_id != state.scan_id:
        raise HTTPException(409, "진단이 변경되었습니다. 현재 결과를 확인하고 다시 저장하세요.")
    payload = {"metadata": {"scan_id": state.scan_id, "target_url": state.target_url,
                            "started_at": state.started_at, "finished_at": state.finished_at,
                            "status": state.status, "demo": state.demo, "scope_mode": state.scope_mode, "scope_path": state.blackboard.asset.metadata.get("scope_path", "/"), "checks":state.blackboard.asset.metadata.get('checks',[]),"exported_at": now()}}
    for section in req.sections:
        if section == "summary":
            status = await get_status()
            payload[section] = {k: status[k] for k in ("findings_count", "chains_count", "endpoints_count", "severity", "score", "grade")}
        elif section == "findings":
            payload[section] = await get_findings()
        elif section == "chains":
            payload[section] = await get_chains()
        elif section == "endpoints":
            payload[section] = await get_endpoints()
        elif section == "logs":
            if state.log_error:
                raise HTTPException(503, state.log_error)
            try:
                records = [json.loads(line) for line in Path(state.log_path).read_text(encoding="utf-8").splitlines() if line]
            except (OSError, ValueError) as exc:
                raise HTTPException(503, "저장된 진단 로그를 읽지 못했습니다.") from exc
            payload[section] = [r for r in records if r["event"] == "log"]
    content, media_type, extension = render_export(public_data(payload,state.blackboard.private_values), req.format)
    return Response(content, media_type=media_type, headers={"Content-Disposition": f"attachment; filename=WVA_{state.scan_id}.{extension}"})

def completed_report():
    if state.status != "completed" or not state.blackboard:
        raise HTTPException(409, "완료된 진단이 없습니다. 진단 완료 후 보고서를 저장하세요.")
    return SecurityReportGenerator(state.blackboard)

@app.get("/api/scan/report/md")
async def markdown_report():
    return PlainTextResponse(completed_report().generate_markdown_report(), headers={"Content-Disposition": "attachment; filename=WVA_report.md"})

@app.get("/api/scan/report/json")
async def json_report():
    return JSONResponse(completed_report().generate_json_report(), headers={"Content-Disposition": "attachment; filename=WVA_report.json"})

@app.post("/api/app/shutdown")
async def shutdown(request: Request):
    server = getattr(request.app.state, "server", None)
    if not server:
        raise HTTPException(503, "실행파일에서 시작한 서버에서만 종료할 수 있습니다.")
    request.app.state.shutting_down = True
    asyncio.get_running_loop().call_later(0.3, setattr, server, "should_exit", True)
    return {"status": "shutting_down"}

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")

def start_server(host="127.0.0.1", port=9030):
    uvicorn.run(app, host=host, port=port, log_level="warning")

if __name__ == "__main__":
    start_server()
