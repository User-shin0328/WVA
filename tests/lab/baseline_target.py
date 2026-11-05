from fastapi import FastAPI, Header, Query, Response, HTTPException
from fastapi.responses import JSONResponse, HTMLResponse
import uvicorn

app = FastAPI(title="WVA Realistic Target Web App (Chained Vulnerability Simulation)")

@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <html>
        <head><title>WVA Corporate Portal</title></head>
        <body>
            <h1>WVA Internal Corporate Portal</h1>
            <p>Welcome to the employee self-service portal.</p>
            <a href="/api/v1/user/profile">My Profile</a>
            <form action="/search" method="GET">
                <input type="text" name="query" placeholder="Search docs..." />
                <button type="submit">Search</button>
            </form>
        </body>
    </html>
    """

@app.get("/debug/version")
def debug_version():
    """
    Step 1 in Exploit Chain:
    Information Disclosure (Low Severity).
    Exposes staging user identifier.
    """
    return {
        "status": "healthy",
        "app_name": "wva-corp-service",
        "version": "v2.4.1-staging",
        "staging_user_id": "usr_staging_99",
        "environment": "development"
    }

@app.get("/api/v1/user/profile")
def get_user_profile(user_id: str = Query(..., description="Target User ID")):
    """
    Step 2 in Exploit Chain:
    Broken Object Level Authorization (BOLA / IDOR) (High Severity).
    Fails to check session authentication; returns credentials for arbitrary user_id.
    """
    profiles = {
        "usr_staging_99": {
            "user_id": "usr_staging_99",
            "name": "Alex Mercer",
            "role": "admin_developer",
            "department": "Infrastructure",
            "api_key": "sec_k98_admin_supersecret_token"
        },
        "1001": {
            "user_id": "1001",
            "name": "Standard User",
            "role": "user",
            "api_key": "sec_usr_standard_key"
        }
    }
    if user_id in profiles:
        return profiles[user_id]
    raise HTTPException(status_code=404, detail="User not found")

@app.get("/api/v1/admin/config")
def get_admin_config(x_api_key: str = Header(None, alias="X-API-Key")):
    """
    Step 3 in Exploit Chain:
    Admin Privilege Escalation (Critical Severity).
    Accepts the API key leaked in Step 2 to grant full administrative config access.
    """
    if x_api_key == "sec_k98_admin_supersecret_token":
        return {
            "status": "admin_authenticated",
            "privilege": "ADMIN",
            "internal_db_host": "postgres-prod.internal.corp",
            "encryption_vault": "vault-01.internal",
            "system_message": "Full administrative control granted."
        }
    raise HTTPException(status_code=403, detail="Forbidden: Invalid or missing X-API-Key")

@app.get("/api/v1/user/export")
def export_user_data(response: Response):
    """Permissive CORS Misconfiguration."""
    response.headers["Access-Control-Allow-Origin"] = "https://evil-attacker.com"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return {"status": "export_ready", "format": "csv"}

if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8989, log_level="warning")
