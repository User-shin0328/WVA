"""Two loopback-only lab profiles: intentionally vulnerable and defended."""
import argparse
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse
import uvicorn
from mock_target import app as vulnerable_app

def hardened_app():
    app = FastAPI(title="WVA defended lab", docs_url=None, redoc_url=None, openapi_url=None)

    @app.middleware("http")
    async def headers(request, call_next):
        response = await call_next(request)
        response.headers["Content-Security-Policy"] = "default-src 'self'"
        response.headers["X-Content-Type-Options"] = "nosniff"
        return response

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return '<html><body><h1>WVA defended lab</h1><a href="/api/v1/user/profile">Profile</a></body></html>'

    @app.get("/api/v1/user/profile")
    @app.get("/api/v1/user/export")
    async def profile():
        raise HTTPException(401, "Authentication required")

    @app.get("/api/v1/admin/config")
    async def admin():
        raise HTTPException(403, "Role validation required")

    return app

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=["vulnerable", "hardened"], default="vulnerable")
    parser.add_argument("--port", type=int, default=8990)
    args = parser.parse_args()
    uvicorn.run(vulnerable_app if args.mode == "vulnerable" else hardened_app(), host="127.0.0.1", port=args.port, log_level="warning")

if __name__ == "__main__":
    main()
