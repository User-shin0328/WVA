"""Validate a copied, standalone executable from a Korean path, without source files."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import time
from datetime import datetime
import httpx

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "tests" / "artifacts"

def run():
    OUT.mkdir(parents=True, exist_ok=True)
    result = {"at": datetime.now().astimezone().isoformat(), "checks": [], "status": "FAIL"}
    def check(name, condition, actual):
        result["checks"].append({"name": name, "status": "PASS" if condition else "FAIL", "actual": actual})
        assert condition, f"{name}: {actual}"
    isolated = OUT / "독립 실행 한글 경로"
    isolated.mkdir(exist_ok=True)
    source = ROOT / "WVA.exe"
    executable = isolated / "WVA.exe"
    shutil.copy2(source, executable)
    result["sha256"] = hashlib.sha256(source.read_bytes()).hexdigest()
    result["bytes"] = source.stat().st_size
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    base = f"http://127.0.0.1:{port}"
    proc = subprocess.Popen([str(executable), "--no-browser", "--port", str(port)], cwd=isolated,
                            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
    client = httpx.Client(base_url=base, timeout=10, trust_env=False)
    try:
        for _ in range(200):
            try:
                if client.get("/api/health").json().get("product") == "WVA":
                    break
            except httpx.HTTPError:
                pass
            if proc.poll() is not None:
                raise RuntimeError(f"Executable exited before health check: {proc.returncode}")
            time.sleep(0.15)
        check("standalone_health", client.get("/api/health").status_code == 200, "Copied exe starts from Korean path, no project sources")
        for path in ["/", "/static/app.css", "/static/app.js", "/static/fonts/NotoSansKR.ttf", "/static/fonts/IBMPlexMono-Regular.ttf"]:
            response = client.get(path)
            check("bundled_asset:"+path, response.status_code == 200 and len(response.content) > 100, {"status": response.status_code,"bytes": len(response.content)})
        check("start_demo", client.post("/api/scan/start", json={"demo": True}).status_code == 200, "Embedded lab starts without Python subprocess")
        for _ in range(200):
            status = client.get("/api/scan/status").json()
            if status["status"] != "running":
                break
            time.sleep(0.1)
        check("demo_result", status["status"] == "completed" and (status["findings_count"],status["chains_count"],status["endpoints_count"]) == (5,1,8), status)
        check("report_download", len(client.get("/api/scan/report/json").json()["findings"]) == 5, "5 findings in downloaded JSON")
        check("report_persistence", len(status["report_paths"]) == 2 and all(Path(p).is_file() for p in status["report_paths"]), status["report_paths"])
        details = client.get("/api/scan/findings").json()
        check("detailed_remediation", all(f["remediation_details"]["steps"] and all(s["expected_result"] for s in f["remediation_details"]["steps"]) for f in details), "5 findings include ordered actions, completion criteria and verification")
        surface = client.get("/api/scan/surface").json()
        check("surface_metadata", surface["measured_count"] == 7 and surface["schema_only_count"] == 1, surface)
        log_file = Path(status["log_path"])
        check("persistent_scan_log", log_file.is_file() and '"status": "completed"' in log_file.read_text(encoding="utf-8"), str(log_file))
        exported = client.post("/api/scan/export", json={"sections": ["findings", "logs"], "format": "json", "scan_id": status["scan_id"]}).json()
        check("selected_json_export", set(exported) == {"metadata", "findings", "logs"} and len(exported["findings"]) == 5, "Only selected findings/logs plus provenance")
        csv_response = client.post("/api/scan/export", json={"sections": ["endpoints"], "format": "csv", "scan_id": status["scan_id"]})
        check("selected_csv_export", csv_response.status_code == 200 and csv_response.content.startswith(b"\xef\xbb\xbf") and "query:user_id" in csv_response.text, "UTF-8 BOM CSV includes enriched endpoint metadata")
        # Both SSE clients must receive the same first event; resume skips it.
        first_lines = []
        for _ in range(2):
            with client.stream("GET", "/api/scan/events") as stream:
                first_lines.append(next(line for line in stream.iter_lines() if line.startswith("data:")))
        check("two_sse_clients", first_lines[0] == first_lines[1], "Independent clients receive identical first event")
        first_id = json.loads(first_lines[0][5:])["id"]
        with client.stream("GET", "/api/scan/events", headers={"Last-Event-ID": str(first_id)}) as stream:
            resumed = next(line for line in stream.iter_lines() if line.startswith("data:"))
        check("sse_resume", json.loads(resumed[5:])["id"] > first_id, "Last-Event-ID resumes after acknowledged event")
        duplicate = subprocess.run([str(executable), "--no-browser", "--port", str(port)], cwd=isolated, timeout=15,
                                   creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
        check("second_launch_reuses_server", duplicate.returncode == 0 and client.get("/api/health").status_code == 200, "Second launcher exits; original service stays healthy")
        with client.stream("GET", "/api/scan/events") as active_events:
            next(line for line in active_events.iter_lines() if line.startswith("data:"))
            check("shutdown_request", client.post("/api/app/shutdown", json={}).status_code == 200, "Graceful shutdown accepted with an active SSE subscriber")
            proc.wait(timeout=15)
        check("graceful_exit", proc.returncode == 0, proc.returncode)
        with socket.socket() as sock:
            released = sock.connect_ex(("127.0.0.1", port)) != 0
        check("port_released", released, "Service port closed after exit")
        result["status"] = "PASS"
    except Exception as exc:
        result["error"] = str(exc)
        raise
    finally:
        client.close()
        if proc.poll() is None:
            proc.terminate()
            proc.wait(timeout=10)
        (OUT / "executable-smoke.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({"status":result["status"],"checks":len(result["checks"]),"bytes":result["bytes"],"sha256":result["sha256"]}, indent=2))

if __name__ == "__main__":
    run()
