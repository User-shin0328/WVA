"""Windows no-console launcher. Bundles the dashboard and local lab."""
import argparse
import json
import logging
import os
from pathlib import Path
import socket
import sys
import threading
import time
import urllib.request
import webbrowser

def data_directory(explicit=None):
    root = Path(explicit) if explicit else (Path(sys.executable).parent if getattr(sys, "frozen", False) else Path(__file__).parent)
    try:
        root.mkdir(parents=True, exist_ok=True)
        probe = root / ".wva-write-check"
        probe.touch()
        probe.unlink()
        return root
    except OSError:
        fallback = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "WVA"
        fallback.mkdir(parents=True, exist_ok=True)
        return fallback

def main():
    parser = argparse.ArgumentParser(description="WVA local dashboard")
    parser.add_argument("--port", type=int, help="Local port; default searches 9030-9039")
    parser.add_argument("--no-browser", action="store_true")
    parser.add_argument("--data-dir")
    args = parser.parse_args()
    root = data_directory(args.data_dir)
    os.environ["WVA_DATA_DIR"] = str(root)
    (root / "logs").mkdir(exist_ok=True)
    logging.basicConfig(filename=root / "logs" / "WVA.log", level=logging.WARNING, encoding="utf-8")
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    candidates = [args.port] if args.port is not None else range(9030, 9040)
    sock = None
    for port in candidates:
        base = f"http://127.0.0.1:{port}"
        try:
            with opener.open(base + "/api/health", timeout=0.4) as response:
                existing = json.load(response)
            if existing.get("product") == "WVA":
                if not args.no_browser:
                    webbrowser.open(base)
                return
        except Exception:
            pass
        candidate = socket.socket()
        try:
            candidate.bind(("127.0.0.1", port))
            candidate.listen(128)
            sock = candidate
            break
        except OSError:
            candidate.close()
    if sock is None:
        raise RuntimeError("사용 가능한 로컬 포트가 없습니다. --port 옵션으로 다른 포트를 지정하세요.")
    try:
        import uvicorn
        from dashboard.server import app
        config = uvicorn.Config(app, log_config=None, log_level="warning", loop="asyncio", timeout_graceful_shutdown=5)
        server = uvicorn.Server(config)
        app.state.server = server
        def open_when_ready():
            for _ in range(200):
                if server.started:
                    webbrowser.open(base)
                    return
                time.sleep(0.05)
        if not args.no_browser:
            threading.Thread(target=open_when_ready, daemon=True).start()
        server.run(sockets=[sock])
    finally:
        sock.close()

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        logging.exception("WVA startup failed")
        if getattr(sys, "frozen", False) and "--no-browser" not in sys.argv:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, f"WVA를 시작하지 못했습니다.\n{exc}\n포트 충돌과 logs/WVA.log를 확인하세요.", "WVA", 0x10)
        elif not getattr(sys, "frozen", False):
            raise
        sys.exit(1)
