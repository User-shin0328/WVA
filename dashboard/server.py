import os
import sys
import json
import time
import asyncio
import subprocess
from typing import Optional, Dict, Any
from pathlib import Path

from fastapi import FastAPI, BackgroundTasks, HTTPException
from fastapi.responses import HTMLResponse, StreamingResponse, JSONResponse, PlainTextResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
import uvicorn

from agents.engine import VulnerabilityAnalysisEngine
from core.graph.blackboard import SecurityBlackboard
from core.graph.attack_graph import AttackGraphEngine
from reporting.report_generator import SecurityReportGenerator

app = FastAPI(title="WVA Execution Dashboard Server")

# Serve static dashboard files
STATIC_DIR = Path(__file__).parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

class ScanRequest(BaseModel):
    target_url: str = "http://127.0.0.1:8989"
    demo: bool = True

class DashboardState:
    def __init__(self):
        self.status = "idle"  # idle, running, completed, error
        self.target_url = ""
        self.blackboard: Optional[SecurityBlackboard] = None
        self.event_queue: asyncio.Queue = asyncio.Queue()
        self.scan_task: Optional[asyncio.Task] = None
        self.mock_proc: Optional[subprocess.Popen] = None
        self.last_error = ""

state = DashboardState()

def event_callback(event_type: str, data: Any):
    """Bridge blackboard events to the SSE event queue."""
    msg = json.dumps({"event": event_type, "data": data, "timestamp": time.strftime("%H:%M:%S")}, ensure_ascii=False)
    state.event_queue.put_nowait(msg)

async def run_scan_worker(target_url: str, is_demo: bool):
    state.status = "running"
    state.target_url = target_url
    event_callback("status", {"status": "running", "target_url": target_url})

    if is_demo:
        # Check and spawn mock_target.py if needed
        event_callback("log", "[WVA] Launching local vulnerable testbed server (port 8989)...")
        if not state.mock_proc or state.mock_proc.poll() is not None:
            state.mock_proc = subprocess.Popen(
                [sys.executable, "mock_target.py"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            await asyncio.sleep(1.5)
        event_callback("log", "[WVA] Testbed online. Beginning automated attack path analysis...")

    try:
        engine = VulnerabilityAnalysisEngine(target_url, event_callback=event_callback)
        blackboard = await engine.execute_audit()
        state.blackboard = blackboard
        state.status = "completed"

        # Auto save reports
        reporter = SecurityReportGenerator(blackboard)
        with open("WVA_vulnerability_report.md", "w", encoding="utf-8") as f:
            f.write(reporter.generate_markdown_report())
        with open("WVA_vulnerability_report.json", "w", encoding="utf-8") as f:
            json.dump(reporter.generate_json_report(), f, indent=2, ensure_ascii=False)

        event_callback("status", {"status": "completed", "target_url": target_url})
        event_callback("log", "[WVA] Audit execution completed successfully. Reports saved.")
    except Exception as e:
        state.status = "error"
        state.last_error = str(e)
        event_callback("status", {"status": "error", "error": str(e)})
        event_callback("log", f"[ERROR] Audit encountered failure: {e}")

@app.get("/", response_class=HTMLResponse)
async def serve_index():
    index_file = STATIC_DIR / "index.html"
    if index_file.exists():
        return HTMLResponse(content=index_file.read_text(encoding="utf-8"))
    return HTMLResponse("<h1>WVA Dashboard: index.html not found</h1>", status_code=404)

@app.post("/api/scan/start")
async def start_scan(req: ScanRequest):
    if state.status == "running":
        raise HTTPException(status_code=400, detail="Scan is already running")

    # Clear event queue
    state.event_queue = asyncio.Queue()
    target = "http://127.0.0.1:8989" if req.demo else req.target_url
    state.scan_task = asyncio.create_task(run_scan_worker(target, req.demo))
    return {"status": "started", "target_url": target, "demo": req.demo}

@app.post("/api/scan/stop")
async def stop_scan():
    if state.status == "running" and state.scan_task:
        state.scan_task.cancel()
        state.status = "idle"
        if state.mock_proc and state.mock_proc.poll() is None:
            state.mock_proc.terminate()
        event_callback("status", {"status": "stopped"})
        return {"status": "stopped"}
    return {"status": "not_running"}

@app.get("/api/scan/events")
async def sse_events():
    async def event_generator():
        # First send initial status
        init_data = json.dumps({
            "event": "status",
            "data": {"status": state.status, "target_url": state.target_url},
            "timestamp": time.strftime("%H:%M:%S")
        })
        yield f"data: {init_data}\n\n"

        while True:
            try:
                # Wait for next event or heartbeat
                msg = await asyncio.wait_for(state.event_queue.get(), timeout=2.0)
                yield f"data: {msg}\n\n"
            except asyncio.TimeoutError:
                # Keep-alive heartbeat
                yield f": heartbeat\n\n"

    return StreamingResponse(event_generator(), media_type="text/event-stream")

@app.get("/api/scan/status")
async def get_status():
    bb = state.blackboard
    findings_list = bb.get_findings_list() if bb else []
    chains_list = bb.chains if bb else []
    endpoints_list = bb.asset.endpoints if bb else []

    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings_list:
        sev = f.severity.value
        severity_counts[sev] = severity_counts.get(sev, 0) + 1

    return {
        "status": state.status,
        "target_url": state.target_url,
        "endpoints_count": len(endpoints_list),
        "findings_count": len(findings_list),
        "chains_count": len(chains_list),
        "severity": severity_counts,
        "error": state.last_error
    }

@app.get("/api/scan/graph")
async def get_graph():
    if not state.blackboard:
        return {"nodes": [], "edges": []}
    graph_engine = AttackGraphEngine(state.blackboard)
    return graph_engine.to_cytoscape_elements()

@app.get("/api/scan/findings")
async def get_findings():
    if not state.blackboard:
        return []
    return [f.model_dump() for f in state.blackboard.get_findings_list()]

@app.get("/api/scan/endpoints")
async def get_endpoints():
    if not state.blackboard:
        return []
    return [ep.model_dump() for ep in state.blackboard.asset.endpoints]

@app.get("/api/scan/chains")
async def get_chains():
    if not state.blackboard:
        return []
    return [c.model_dump() for c in state.blackboard.chains]

@app.get("/api/scan/report/md")
async def download_markdown_report():
    if not state.blackboard:
        raise HTTPException(status_code=404, detail="No scan data available")
    reporter = SecurityReportGenerator(state.blackboard)
    content = reporter.generate_markdown_report()
    return PlainTextResponse(content, headers={"Content-Disposition": "attachment; filename=WVA_report.md"})

@app.get("/api/scan/report/json")
async def download_json_report():
    if not state.blackboard:
        raise HTTPException(status_code=404, detail="No scan data available")
    reporter = SecurityReportGenerator(state.blackboard)
    return JSONResponse(reporter.generate_json_report(), headers={"Content-Disposition": "attachment; filename=WVA_report.json"})

def start_server(host: str = "127.0.0.1", port: int = 8787):
    uvicorn.run("dashboard.server:app", host=host, port=port, log_level="warning")

if __name__ == "__main__":
    start_server()
