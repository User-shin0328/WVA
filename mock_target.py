"""
WVA Comprehensive Security Testbed Web Application (v2.6.0 Compatible)
========================================================================
Interactive Vulnerability Simulator with Real-Time Click-to-Toggle Switches.
Allows toggling individual or all vulnerabilities ON (Vulnerable) / OFF (Patched)
directly from the web UI to verify security posture and compare WVA scan results.
"""

import argparse
import html
import json
import re
from typing import Optional, Dict
from fastapi import FastAPI, Header, Query, Request, Response, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse
import uvicorn

app = FastAPI(
    title="NexusCorp Security Testbed & Vulnerability Simulator",
    description="WVA Full Vulnerability Coverage Target Server with Toggleable Controls",
    version="2.6.0",
    docs_url=None,
    redoc_url=None,
    openapi_url=None
)

# --------------------------------------------------------------------------
# Dynamic Vulnerability State Configuration (All ON by default)
# --------------------------------------------------------------------------
VULN_CONFIG: Dict[str, bool] = {
    "command_injection": True,    # R17: OS Command Injection / RCE (CWE-78)
    "sql_injection": True,        # R11: SQL Injection (CWE-89)
    "file_upload": True,          # R19: Arbitrary File Upload (CWE-434)
    "path_traversal": True,       # R16: Path Traversal / LFI (CWE-22)
    "ssrf": True,                 # R18: Server-Side Request Forgery (CWE-918)
    "idor": True,                 # R09: Broken Object Level Authorization (CWE-639)
    "reflected_xss": True,        # R12: Reflected XSS (CWE-79)
    "open_redirect": True,        # R20: Open Redirect (CWE-601)
    "cors_misconfig": True,       # Permissive CORS Misconfiguration (CWE-942)
    "jwt_insecure": True,         # Insecure JWT alg: none (CWE-287)
    "missing_headers": True,      # Missing Security Headers (CSP, X-Frame, Nosniff)
    "insecure_cookies": True,     # Insecure Cookie Flags (Missing HttpOnly, Secure)
    "debug_endpoints": True,      # Information Disclosure via Debug (CWE-200)
    "chaining_admin": True,       # Multi-step Privilege Escalation
    "leaked_secrets": True,       # Client Script Secret Leak (CWE-798)
    "sensitive_files": True,      # Sensitive Files Exposure (.env, backup.sql)
}


# --------------------------------------------------------------------------
# API Endpoints for Control Panel (Toggle / Preset)
# --------------------------------------------------------------------------
@app.get("/api/v1/testbed/config")
def get_testbed_config():
    """Returns current active vulnerability statuses."""
    return VULN_CONFIG


@app.post("/api/v1/testbed/toggle")
def toggle_vulnerability(key: str = Query(...), enabled: Optional[bool] = Query(None)):
    """Toggles or sets the status of a specific vulnerability rule."""
    if key not in VULN_CONFIG:
        raise HTTPException(status_code=400, detail=f"Unknown vulnerability key: {key}")
    if enabled is None:
        VULN_CONFIG[key] = not VULN_CONFIG[key]
    else:
        VULN_CONFIG[key] = enabled
    return {"key": key, "status": "VULNERABLE" if VULN_CONFIG[key] else "PATCHED", "enabled": VULN_CONFIG[key]}


@app.post("/api/v1/testbed/preset")
def set_testbed_preset(preset: str = Query(...)):
    """Applies bulk presets: 'all_vulnerable' (ON) or 'all_patched' (OFF)."""
    val = (preset.lower() in ("all_vulnerable", "all_on", "vulnerable", "on", "1"))
    for k in VULN_CONFIG:
        VULN_CONFIG[k] = val
    return {"preset": "ALL_VULNERABLE" if val else "ALL_PATCHED", "config": VULN_CONFIG}


# --------------------------------------------------------------------------
# Global Middleware: Security Headers & Server Banner
# --------------------------------------------------------------------------
@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    response = await call_next(request)
    if VULN_CONFIG.get("missing_headers", True):
        # Vulnerable state: reveal server banner and strip defenses
        response.headers["Server"] = "Apache/2.4.52 (Ubuntu) OpenSSL/1.1.1w PHP/8.1.2"
        response.headers["X-Powered-By"] = "PHP/8.1.2"
        for h in ["Content-Security-Policy", "X-Content-Type-Options", "X-Frame-Options", "Strict-Transport-Security"]:
            if h in response.headers:
                del response.headers[h]
    else:
        # Patched state: apply defense-in-depth headers
        response.headers["Server"] = "NexusWeb"
        if "X-Powered-By" in response.headers:
            del response.headers["X-Powered-By"]
        response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none';"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    return response


# --------------------------------------------------------------------------
# Portal Main Dashboard with Interactive Toggle Switches UI
# --------------------------------------------------------------------------
@app.get("/", response_class=HTMLResponse)
def index(response: Response):
    # Set Cookie: Insecure if toggled ON, Hardened if toggled OFF
    if VULN_CONFIG.get("insecure_cookies", True):
        response.set_cookie(key="nexus_session_id", value="wva_sess_98374284920485710293", path="/")
    else:
        response.set_cookie(key="nexus_session_id", value="wva_sess_secure_token", path="/", httponly=True, secure=True, samesite="lax")

    config_json = json.dumps(VULN_CONFIG)

    return """<!DOCTYPE html>
<html lang="ko">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NexusCorp Enterprise Portal - Vulnerability Control Lab</title>
    <style>
        :root {
            --bg-primary: #0a0e17;
            --bg-card: rgba(18, 26, 43, 0.9);
            --border: #1e293b;
            --accent: #38bdf8;
            --accent-glow: rgba(56, 189, 248, 0.25);
            --danger: #ef4444;
            --danger-bg: rgba(239, 68, 68, 0.15);
            --success: #10b981;
            --success-bg: rgba(16, 185, 129, 0.15);
            --warning: #f59e0b;
            --text-main: #f1f5f9;
            --text-muted: #94a3b8;
        }
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            background: radial-gradient(circle at 50% 0%, #172554 0%, var(--bg-primary) 70%);
            color: var(--text-main);
            min-height: 100vh;
            padding: 24px 16px;
        }
        .container { max-width: 1240px; margin: 0 auto; }
        header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding-bottom: 20px;
            border-bottom: 1px solid var(--border);
            margin-bottom: 24px;
            flex-wrap: wrap;
            gap: 16px;
        }
        .brand { display: flex; align-items: center; gap: 14px; }
        .logo {
            width: 44px; height: 44px;
            background: linear-gradient(135deg, #38bdf8, #6366f1);
            border-radius: 10px;
            display: flex; align-items: center; justify-content: center;
            font-size: 22px; font-weight: bold;
            box-shadow: 0 0 20px var(--accent-glow);
        }
        h1 { font-size: 22px; font-weight: 700; letter-spacing: -0.5px; }
        .subtitle { font-size: 13px; color: var(--text-muted); }

        /* Top Master Control Panel */
        .master-panel {
            background: rgba(15, 23, 42, 0.95);
            border: 1px solid #334155;
            border-radius: 12px;
            padding: 18px 24px;
            margin-bottom: 24px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            flex-wrap: wrap;
            gap: 16px;
            box-shadow: 0 8px 30px rgba(0, 0, 0, 0.5);
        }
        .master-info h3 { font-size: 16px; font-weight: 600; color: #fff; margin-bottom: 4px; display: flex; align-items: center; gap: 8px; }
        .master-info p { font-size: 13px; color: var(--text-muted); }
        .master-actions { display: flex; gap: 12px; }
        .btn-preset {
            padding: 10px 18px;
            border-radius: 8px;
            border: none;
            font-size: 13px;
            font-weight: 700;
            cursor: pointer;
            transition: all 0.2s;
            display: flex;
            align-items: center;
            gap: 8px;
        }
        .btn-preset-danger {
            background: linear-gradient(135deg, #dc2626, #b91c1c);
            color: #fff;
            box-shadow: 0 0 15px rgba(220, 38, 38, 0.4);
        }
        .btn-preset-danger:hover { transform: translateY(-1px); opacity: 0.9; }
        .btn-preset-safe {
            background: linear-gradient(135deg, #059669, #047857);
            color: #fff;
            box-shadow: 0 0 15px rgba(5, 150, 105, 0.4);
        }
        .btn-preset-safe:hover { transform: translateY(-1px); opacity: 0.9; }

        /* Grid */
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(360px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }

        .card {
            background: var(--bg-card);
            border: 1px solid var(--border);
            border-radius: 12px;
            padding: 20px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.4);
            display: flex;
            flex-direction: column;
            gap: 12px;
            transition: border-color 0.3s;
        }
        .card.is-vuln { border-left: 4px solid var(--danger); }
        .card.is-patched { border-left: 4px solid var(--success); }

        .card-top {
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .card-title {
            font-size: 15px;
            font-weight: 600;
            display: flex;
            align-items: center;
            gap: 8px;
        }

        /* Switch Toggle Control */
        .switch-wrap {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        .status-badge {
            font-size: 11px;
            font-weight: 700;
            padding: 3px 8px;
            border-radius: 9999px;
            text-transform: uppercase;
        }
        .status-badge.vuln { background: var(--danger-bg); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.4); }
        .status-badge.safe { background: var(--success-bg); color: #34d399; border: 1px solid rgba(16, 185, 129, 0.4); }

        .toggle-switch {
            position: relative;
            display: inline-block;
            width: 48px;
            height: 24px;
        }
        .toggle-switch input { opacity: 0; width: 0; height: 0; }
        .slider {
            position: absolute;
            cursor: pointer;
            top: 0; left: 0; right: 0; bottom: 0;
            background-color: #334155;
            transition: .3s;
            border-radius: 24px;
        }
        .slider:before {
            position: absolute;
            content: "";
            height: 18px;
            width: 18px;
            left: 3px;
            bottom: 3px;
            background-color: white;
            transition: .3s;
            border-radius: 50%;
        }
        input:checked + .slider {
            background-color: #ef4444;
        }
        input:not(:checked) + .slider {
            background-color: #10b981;
        }
        input:checked + .slider:before {
            transform: translateX(24px);
        }

        .card-desc { font-size: 13px; color: var(--text-muted); line-height: 1.5; }
        .form-wrap { display: flex; flex-direction: column; gap: 8px; margin-top: 4px; }
        .input-group { display: flex; gap: 8px; }
        input[type="text"], input[type="file"] {
            flex: 1;
            padding: 8px 12px;
            background: #0f172a;
            border: 1px solid #334155;
            border-radius: 6px;
            color: #fff;
            font-size: 13px;
        }
        button.btn-test {
            padding: 8px 16px;
            background: linear-gradient(135deg, #0284c7, #2563eb);
            border: none;
            border-radius: 6px;
            color: #fff;
            font-weight: 600;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s;
        }
        button.btn-test:hover { opacity: 0.9; }

        .links-list { list-style: none; display: flex; flex-direction: column; gap: 6px; }
        .links-list li a {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 7px 10px;
            background: #0f172a;
            border: 1px solid #1e293b;
            border-radius: 6px;
            color: var(--accent);
            text-decoration: none;
            font-size: 12px;
            font-family: monospace;
            transition: all 0.2s;
        }
        .links-list li a:hover { border-color: var(--accent); background: #1e293b; }

        .chain-box {
            background: rgba(15, 23, 42, 0.9);
            border: 1px dashed #475569;
            border-radius: 8px;
            padding: 14px;
        }
        .chain-steps {
            display: flex;
            align-items: center;
            gap: 8px;
            margin-top: 10px;
            font-size: 12px;
            flex-wrap: wrap;
        }
        .chain-step { padding: 6px 10px; background: #1e293b; border-radius: 4px; font-family: monospace; }
        .chain-arrow { color: var(--danger); font-weight: bold; }

        footer {
            margin-top: 30px;
            padding-top: 20px;
            border-top: 1px solid var(--border);
            text-align: center;
            font-size: 12px;
            color: var(--text-muted);
        }
    </style>
</head>
<body>
    <div class="container">
        <header>
            <div class="brand">
                <div class="logo">⚡</div>
                <div>
                    <h1>NexusCorp Enterprise Service Portal</h1>
                    <div class="subtitle">WVA Comprehensive Interactive Vulnerability Simulator (v2.6.0)</div>
                </div>
            </div>
            <div>
                <span class="status-badge vuln" id="global-badge">VULNERABILITY LAB ACTIVE</span>
            </div>
        </header>

        <!-- Master Switch Control Banner -->
        <div class="master-panel">
            <div class="master-info">
                <h3>🎛️ 실시간 취약점 통제 센터 (Live Security Control Panel)</h3>
                <p>각 항목의 토글 스위치를 클릭하면 해당 취약점이 즉시 [🚨 취약(VULNERABLE)] 또는 [🛡️ 방어(PATCHED)] 상태로 변경됩니다.</p>
            </div>
            <div class="master-actions">
                <button class="btn-preset btn-preset-danger" onclick="setPreset('all_vulnerable')">
                    🚨 전체 취약 모드 적용 (All Vulnerable)
                </button>
                <button class="btn-preset btn-preset-safe" onclick="setPreset('all_patched')">
                    🛡️ 전체 보안 패치 적용 (All Patched)
                </button>
            </div>
        </div>

        <div class="grid">
            <!-- 1. Command Injection (R17) -->
            <div class="card is-vuln" id="card-command_injection">
                <div class="card-top">
                    <span class="card-title">🖥️ 시스템 네트워크 진단 (Ping)</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-command_injection">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-command_injection" checked onchange="toggleRule('command_injection', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>R17 / CWE-78:</strong> OS 명령 삽입. 끄면(OFF) 메타문자 차단 및 안전한 파라미터 필터링이 적용됩니다.</div>
                <form class="form-wrap" action="/tools/ping" method="GET">
                    <div class="input-group">
                        <input type="text" name="target" value="127.0.0.1; echo wva_canary" />
                        <button class="btn-test" type="submit">Ping</button>
                    </div>
                </form>
            </div>

            <!-- 2. SQL Injection (R11) -->
            <div class="card is-vuln" id="card-sql_injection">
                <div class="card-top">
                    <span class="card-title">🔍 사내 제품 & 라이선스 검색</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-sql_injection">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-sql_injection" checked onchange="toggleRule('sql_injection', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>R11 / CWE-89:</strong> SQL 인젝션. 끄면(OFF) PreparedStatement 매개변수화 바인딩이 적용됩니다.</div>
                <form class="form-wrap" action="/api/v1/products/search" method="GET">
                    <div class="input-group">
                        <input type="text" name="query" value="' OR 1=1 -- " />
                        <button class="btn-test" type="submit">검색</button>
                    </div>
                </form>
            </div>

            <!-- 3. Arbitrary File Upload (R19) -->
            <div class="card is-vuln" id="card-file_upload">
                <div class="card-top">
                    <span class="card-title">📁 임직원 첨부파일 / 아바타 업로드</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-file_upload">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-file_upload" checked onchange="toggleRule('file_upload', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>R19 / CWE-434:</strong> 파일 업로드. 끄면(OFF) 실행형 확장자(.php, .jsp 등) 차단 화이트리스트가 적용됩니다.</div>
                <form class="form-wrap" action="/uploads" method="POST" enctype="multipart/form-data">
                    <div class="input-group">
                        <input type="file" name="file" />
                        <button class="btn-test" type="submit">업로드</button>
                    </div>
                </form>
            </div>

            <!-- 4. Path Traversal / LFI (R16) -->
            <div class="card is-vuln" id="card-path_traversal">
                <div class="card-top">
                    <span class="card-title">📄 사내 규정 문서 뷰어 / 다운로드</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-path_traversal">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-path_traversal" checked onchange="toggleRule('path_traversal', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>R16 / CWE-22:</strong> 경로 순회. 끄면(OFF) 상위 경로(`..`) 이동 차단 및 파일명 정규화 검증이 적용됩니다.</div>
                <form class="form-wrap" action="/download" method="GET">
                    <div class="input-group">
                        <input type="text" name="file" value="../../../../../../etc/passwd" />
                        <button class="btn-test" type="submit">조회</button>
                    </div>
                </form>
            </div>

            <!-- 5. SSRF (R18) -->
            <div class="card is-vuln" id="card-ssrf">
                <div class="card-top">
                    <span class="card-title">🌐 외부 웹훅 & 프록시 통신</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-ssrf">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-ssrf" checked onchange="toggleRule('ssrf', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>R18 / CWE-918:</strong> SSRF. 끄면(OFF) 사설망 및 메타데이터 IP(`169.254.169.254`) 접근이 차단됩니다.</div>
                <form class="form-wrap" action="/webhook" method="GET">
                    <div class="input-group">
                        <input type="text" name="url" value="http://169.254.169.254/latest/meta-data/" />
                        <button class="btn-test" type="submit">전송</button>
                    </div>
                </form>
            </div>

            <!-- 6. Reflected XSS (R12) -->
            <div class="card is-vuln" id="card-reflected_xss">
                <div class="card-top">
                    <span class="card-title">💬 사내 통합 질의 검색</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-reflected_xss">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-reflected_xss" checked onchange="toggleRule('reflected_xss', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>R12 / CWE-79:</strong> 반사형 XSS. 끄면(OFF) HTML 특수문자 엔티티 이스케이프(`&lt;`, `&gt;`)가 적용됩니다.</div>
                <form class="form-wrap" action="/search" method="GET">
                    <div class="input-group">
                        <input type="text" name="query" value="&lt;script&gt;alert('XSS')&lt;/script&gt;" />
                        <button class="btn-test" type="submit">검색</button>
                    </div>
                </form>
            </div>

            <!-- 7. Open Redirect (R20) -->
            <div class="card is-vuln" id="card-open_redirect">
                <div class="card-top">
                    <span class="card-title">↗️ 외부 서비스 바로가기</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-open_redirect">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-open_redirect" checked onchange="toggleRule('open_redirect', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>R20 / CWE-601:</strong> 오픈 리다이렉트. 끄면(OFF) 승인된 도메인 화이트리스트 외 목적지는 거부됩니다.</div>
                <form class="form-wrap" action="/redirect" method="GET">
                    <div class="input-group">
                        <input type="text" name="next" value="https://example.com" />
                        <button class="btn-test" type="submit">이동</button>
                    </div>
                </form>
            </div>

            <!-- 8. BOLA / IDOR (R09) -->
            <div class="card is-vuln" id="card-idor">
                <div class="card-top">
                    <span class="card-title">👤 사원 프로필 및 권한 조회</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-idor">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-idor" checked onchange="toggleRule('idor', this.checked)">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>R09 / CWE-639:</strong> IDOR/BOLA. 끄면(OFF) 미인증 요청에 대해 세션 검증(401 Unauthorized)이 강제됩니다.</div>
                <form class="form-wrap" action="/api/v1/user/profile" method="GET">
                    <div class="input-group">
                        <input type="text" name="user_id" value="usr_staging_99" />
                        <button class="btn-test" type="submit">조회</button>
                    </div>
                </form>
            </div>

            <!-- 9. Security Headers & Cookie Flags (R01~R07) -->
            <div class="card is-vuln" id="card-missing_headers">
                <div class="card-top">
                    <span class="card-title">🛡️ 보안 헤더 및 쿠키 플래그</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-missing_headers">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-missing_headers" checked onchange="toggleRule('missing_headers', this.checked); toggleRule('insecure_cookies', this.checked);">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>R01~R07:</strong> CSP, X-Frame-Options, Nosniff 및 HttpOnly/Secure 쿠키 플래그. 끄면(OFF) 표준 보안 헤더가 전면 적용됩니다.</div>
                <ul class="links-list">
                    <li><a href="/"><span>메인 포털 응답 헤더 확인</span> <span>[헤더 및 쿠키 검증]</span></a></li>
                </ul>
            </div>

            <!-- 10. CORS & JWT Security -->
            <div class="card is-vuln" id="card-cors_misconfig">
                <div class="card-top">
                    <span class="card-title">🔑 CORS 설정 & JWT 토큰 검증</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-cors_misconfig">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-cors_misconfig" checked onchange="toggleRule('cors_misconfig', this.checked); toggleRule('jwt_insecure', this.checked);">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>CWE-942 / CWE-287:</strong> 과도한 CORS Origin 허용 및 `alg: none` JWT. 끄면(OFF) 엄격한 CORS 및 서명 검증이 적용됩니다.</div>
                <ul class="links-list">
                    <li><a href="/api/v1/user/export"><span>/api/v1/user/export</span> <span>[CORS 오설정]</span></a></li>
                    <li><a href="/api/v1/info"><span>/api/v1/info</span> <span>[JWT None 알고리즘]</span></a></li>
                </ul>
            </div>

            <!-- 11. Exploit Chaining Simulator -->
            <div class="card is-vuln" style="grid-column: 1 / -1;" id="card-chaining_admin">
                <div class="card-top">
                    <span class="card-title">⚡ Multi-Step Privilege Escalation Exploit Chain (공격 체인 시뮬레이션)</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-chaining_admin">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-chaining_admin" checked onchange="toggleRule('chaining_admin', this.checked); toggleRule('debug_endpoints', this.checked);">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc">
                    개별 취약점을 연계하여 최종 관리자 권한을 탈취하는 3단계 공격 경로입니다. 끄면(OFF) 관리자 인증에 MFA 및 엄격한 RBAC가 적용되어 체인이 차단됩니다:
                </div>
                <div class="chain-box">
                    <div class="chain-steps">
                        <div class="chain-step"><strong>Step 1</strong>: /debug/version (usr_staging_99 노출)</div>
                        <div class="chain-arrow">➔</div>
                        <div class="chain-step"><strong>Step 2</strong>: /api/v1/user/profile (BOLA로 Admin Key 탈취)</div>
                        <div class="chain-arrow">➔</div>
                        <div class="chain-step"><strong>Step 3</strong>: /api/v1/admin/config (X-API-Key 헤더로 관리자 전권 장악)</div>
                    </div>
                </div>
            </div>

            <!-- 12. Exposed Secrets & Sensitive Files -->
            <div class="card is-vuln" id="card-leaked_secrets">
                <div class="card-top">
                    <span class="card-title">🔐 민감 파일 및 JS 시크릿 노출</span>
                    <div class="switch-wrap">
                        <span class="status-badge vuln" id="badge-leaked_secrets">VULN</span>
                        <label class="toggle-switch">
                            <input type="checkbox" id="toggle-leaked_secrets" checked onchange="toggleRule('leaked_secrets', this.checked); toggleRule('sensitive_files', this.checked);">
                            <span class="slider"></span>
                        </label>
                    </div>
                </div>
                <div class="card-desc"><strong>CWE-798 / CWE-538:</strong> JS 내 AWS/GitHub 키 및 .env/backup.sql 노출. 끄면(OFF) 파일이 비활성화(404)됩니다.</div>
                <ul class="links-list">
                    <li><a href="/static/app.js"><span>/static/app.js</span> <span>[AWS/GitHub Key]</span></a></li>
                    <li><a href="/robots.txt"><span>/robots.txt</span> <span>[관리자 경로]</span></a></li>
                    <li><a href="/.env"><span>/.env</span> <span>[DB 패스워드]</span></a></li>
                    <li><a href="/backup.sql"><span>/backup.sql</span> <span>[DB 덤프]</span></a></li>
                </ul>
            </div>
        </div>

        <footer>
            NexusCorp Interactive Security Testbed • Click-to-Toggle Vulnerability Simulator • Port 8989
        </footer>
    </div>

    <!-- Client Script for UI Sync & Live Toggle -->
    <script>
        const initialConfig = """ + config_json + """;

        function updateCardUI(key, isVuln) {
            const card = document.getElementById('card-' + key);
            const badge = document.getElementById('badge-' + key);
            const toggle = document.getElementById('toggle-' + key);

            if (toggle) toggle.checked = isVuln;
            if (badge) {
                badge.textContent = isVuln ? 'VULN' : 'PATCHED';
                badge.className = 'status-badge ' + (isVuln ? 'vuln' : 'safe');
            }
            if (card) {
                if (isVuln) {
                    card.classList.add('is-vuln');
                    card.classList.remove('is-patched');
                } else {
                    card.classList.remove('is-vuln');
                    card.classList.add('is-patched');
                }
            }
        }

        async function toggleRule(key, enabled) {
            try {
                const res = await fetch(`/api/v1/testbed/toggle?key=${key}&enabled=${enabled}`, { method: 'POST' });
                const data = await res.json();
                updateCardUI(key, data.enabled);
            } catch (err) {
                console.error('Failed to toggle rule:', err);
            }
        }

        async function setPreset(preset) {
            try {
                const res = await fetch(`/api/v1/testbed/preset?preset=${preset}`, { method: 'POST' });
                const data = await res.json();
                const isVuln = (preset === 'all_vulnerable');
                for (const k in data.config) {
                    updateCardUI(k, data.config[k]);
                }
                const globalBadge = document.getElementById('global-badge');
                if (isVuln) {
                    globalBadge.textContent = 'ALL VULNERABILITIES ACTIVE';
                    globalBadge.className = 'status-badge vuln';
                } else {
                    globalBadge.textContent = 'ALL DEFENSES PATCHED';
                    globalBadge.className = 'status-badge safe';
                }
            } catch (err) {
                console.error('Failed to apply preset:', err);
            }
        }
    </script>
</body>
</html>
"""


# --------------------------------------------------------------------------
# 1. R17: OS Command Injection / RCE (CWE-78)
# --------------------------------------------------------------------------
@app.get("/tools/ping", response_class=PlainTextResponse)
def tools_ping(target: str = Query("127.0.0.1")):
    # If Vulnerability is TOGGLED OFF (Patched)
    if not VULN_CONFIG.get("command_injection", True):
        # Strict validation: Only valid IPv4/hostname allowed without metacharacters
        if not re.fullmatch(r"^[a-zA-Z0-9.-]+$", target) or any(c in target for c in [";", "|", "&", "`", "$", "\n"]):
            return PlainTextResponse("Error: Invalid characters detected in target IP. Security policy blocked execution.", status_code=400)
        return f"PING {target} ({target}) 56(84) bytes: 0% packet loss. [Security Filter: Active]"

    # If Vulnerability is TOGGLED ON (Vulnerable)
    if any(sep in target for sep in [";", "|", "&", "`", "$", "\n"]) or "wva_canary" in target or "echo" in target:
        return f"""PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.
64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.038 ms
wva_canary
uid=0(root) gid=0(root) groups=0(root),4(adm),24(cdrom),27(sudo)
Linux nexus-corp-prod-01 5.15.0-89-generic #99-Ubuntu SMP x86_64 GNU/Linux
"""
    return f"""PING {target} ({target}) 56(84) bytes of data.
64 bytes from {target}: icmp_seq=1 ttl=64 time=0.035 ms
--- {target} ping statistics ---
2 packets transmitted, 2 received, 0% packet loss
"""


# --------------------------------------------------------------------------
# 2. R11: SQL Injection (CWE-89)
# --------------------------------------------------------------------------
@app.get("/api/v1/products/search", response_class=HTMLResponse)
def products_search(query: str = Query("baseline")):
    # If Vulnerability is TOGGLED OFF (Patched)
    if not VULN_CONFIG.get("sql_injection", True):
        # Safe parameterized search simulation: treats all queries as literal text
        safe_query = html.escape(query)
        return f"""<div><h3>Product Results for: {safe_query}</h3><p>Parameterized query executed safely. 0 records matched.</p></div>"""

    # If Vulnerability is TOGGLED ON (Vulnerable)
    if any(q in query for q in ["'", '"', "/*", "--", ";", "\\", "UNION"]):
        if any(c in query.upper() for c in ["OR 1=1", "OR '1'='1", "OR 1=1--", "' OR '1'='1'"]):
            return """<!-- SQL Injection payload executed: SQL_INJECTION_PWNED -->
            <div class="sql-results">
                <h3>Search Results for: """ + query + """</h3>
                <p>SQL Injection Vulnerability Detected: SQL_INJECTION_PWNED</p>
                <ul>
                    <li>[ID 1] Enterprise Core License ($25,000)</li>
                    <li>[ID 2] Internal Root DB Backup Credentials</li>
                    <li>[ID 3] Admin SSO Private Certificate</li>
                </ul>
            </div>
            """
        return HTMLResponse(
            content="SQLITE_ERROR: unrecognized token in query expression 'SELECT * FROM products WHERE name LIKE '%" + query + "%''",
            status_code=500
        )
    return f"""<div><h3>Product Results for: {query}</h3><p>No public products matched your query.</p></div>"""


# --------------------------------------------------------------------------
# 3. R19: Arbitrary File Upload (CWE-434)
# --------------------------------------------------------------------------
@app.post("/uploads")
async def handle_file_upload(request: Request):
    filename = "uploaded_file.php"
    try:
        body = await request.body()
        body_str = body.decode("latin1", errors="ignore")
        match = re.search(r'filename=["\']?([^"\'\r\n]+)["\']?', body_str)
        if match:
            filename = match.group(1)
    except Exception:
        pass

    # If Vulnerability is TOGGLED OFF (Patched)
    if not VULN_CONFIG.get("file_upload", True):
        ext = os.path.splitext(filename)[1].lower()
        if ext not in [".png", ".jpg", ".jpeg", ".pdf", ".txt"]:
            return JSONResponse(
                status_code=400,
                content={"error": "Upload Rejected: File extension disallowed by security policy."}
            )

    # If Vulnerability is TOGGLED ON (Vulnerable)
    return JSONResponse(
        status_code=200,
        content={
            "status": "success",
            "message": "File uploaded successfully to web document root.",
            "filename": filename,
            "filepath": f"/uploads/{filename}",
            "file_url": f"http://127.0.0.1:8989/uploads/{filename}"
        }
    )


# --------------------------------------------------------------------------
# 4. R16: Path Traversal / LFI (CWE-22)
# --------------------------------------------------------------------------
@app.get("/download", response_class=PlainTextResponse)
def download_file(file: str = Query("guide.pdf")):
    # If Vulnerability is TOGGLED OFF (Patched)
    if not VULN_CONFIG.get("path_traversal", True):
        if ".." in file or "/" in file or "\\" in file:
            return PlainTextResponse("Forbidden: Path traversal sequence detected and blocked.", status_code=403)
        return f"Contents of document: {file}\n[Nexus Corporation Confidential User Guide v2.6]"

    # If Vulnerability is TOGGLED ON (Vulnerable)
    if ".." in file or "passwd" in file or "etc" in file or "boot.ini" in file or "win.ini" in file:
        return """root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
[boot loader]
timeout=30
default=multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS
[operating systems]
multi(0)disk(0)rdisk(0)partition(1)\\WINDOWS="Microsoft Windows Server 2022" /fastdetect
"""
    return f"Contents of document: {file}\n[Nexus Corporation Confidential User Guide v2.6]"


# --------------------------------------------------------------------------
# 5. R18: Server-Side Request Forgery (SSRF) (CWE-918)
# --------------------------------------------------------------------------
@app.get("/webhook", response_class=PlainTextResponse)
def webhook_forward(url: str = Query("https://api.internal/callback")):
    # If Vulnerability is TOGGLED OFF (Patched)
    if not VULN_CONFIG.get("ssrf", True):
        if "169.254" in url or "127.0.0.1" in url or "localhost" in url or "internal" in url:
            return PlainTextResponse("Forbidden: Destination host is restricted by egress network policy.", status_code=403)
        return f'{{"status": "blocked", "message": "Only verified external endpoints are permitted."}}'

    # If Vulnerability is TOGGLED ON (Vulnerable)
    if "169.254.169.254" in url or "metadata" in url or "latest" in url or "meta-data" in url:
        return """Cloud Metadata Service
ami-id: ami-0c55b159cbfafe1f0
instance-id: i-0123456789abcdef0
hostname: ip-10-0-12-45.ec2.internal
security_credentials: {
  "RoleName": "nexus-prod-iam-admin-role",
  "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
  "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
}
"""
    return f'{{"status": "forwarded", "target": "{url}", "http_status": 200}}'


# --------------------------------------------------------------------------
# 6. R12: Reflected Cross-Site Scripting (XSS) (CWE-79)
# --------------------------------------------------------------------------
@app.get("/search", response_class=HTMLResponse)
def general_search(query: str = Query("")):
    # If Vulnerability is TOGGLED OFF (Patched)
    if not VULN_CONFIG.get("reflected_xss", True):
        safe_query = html.escape(query)
        return f"""<!DOCTYPE html><html><head><title>Search</title></head><body>
        <h2>Search Inquiry</h2>
        <div>You searched for: <span>{safe_query}</span></div>
        <p>[XSS Defense Active: HTML Entities Escaped]</p>
        </body></html>"""

    # If Vulnerability is TOGGLED ON (Vulnerable)
    return f"""<!DOCTYPE html><html><head><title>Search</title></head><body>
    <h2>Search Inquiry</h2>
    <div class="result-box">You searched for: <span>{query}</span></div>
    <p>0 results found in corporate archive.</p>
    </body></html>"""


# --------------------------------------------------------------------------
# 7. R20: Open Redirect (CWE-601)
# --------------------------------------------------------------------------
@app.get("/redirect")
def open_redirect(next: str = Query("/")):
    # If Vulnerability is TOGGLED OFF (Patched)
    if not VULN_CONFIG.get("open_redirect", True):
        # Only allow relative internal paths
        if next.startswith("http://") or next.startswith("https://") or next.startswith("//"):
            return RedirectResponse(url="/", status_code=302)
        return RedirectResponse(url=next, status_code=302)

    # If Vulnerability is TOGGLED ON (Vulnerable)
    return RedirectResponse(url=next, status_code=302)


# --------------------------------------------------------------------------
# 8. Permissive CORS Misconfiguration (CWE-942)
# --------------------------------------------------------------------------
@app.get("/api/v1/user/export")
def export_user_data(request: Request, response: Response):
    # If Vulnerability is TOGGLED OFF (Patched)
    if not VULN_CONFIG.get("cors_misconfig", True):
        response.headers["Access-Control-Allow-Origin"] = "https://portal.nexuscorp.com"
        response.headers["Access-Control-Allow-Credentials"] = "false"
        return {"status": "export_ready", "classification": "RESTRICTED"}

    # If Vulnerability is TOGGLED ON (Vulnerable)
    req_origin = request.headers.get("origin")
    response.headers["Access-Control-Allow-Origin"] = req_origin if req_origin else "https://evil-attacker.com"
    response.headers["Access-Control-Allow-Credentials"] = "true"
    return {"status": "export_ready", "format": "csv", "exported_records": 128}


# --------------------------------------------------------------------------
# 9. Passive Information Disclosure (CWE-200)
# --------------------------------------------------------------------------
@app.get("/debug/version")
def debug_version():
    if not VULN_CONFIG.get("debug_endpoints", True):
        raise HTTPException(status_code=404, detail="Endpoint not found")

    return {
        "status": "healthy",
        "app_name": "nexus-corp-service",
        "version": "v2.6.0-staging",
        "staging_user_id": "usr_staging_99",
        "environment": "development"
    }


@app.get("/debug/config")
def debug_config():
    if not VULN_CONFIG.get("debug_endpoints", True):
        raise HTTPException(status_code=404, detail="Endpoint not found")

    return {
        "debug_mode": True,
        "database_url": "postgresql://dbadmin:p@ssw0rd123!@10.0.12.45:5432/corp_db",
        "staging_user_id": "usr_staging_99",
        "api_key": "sec_k98_admin_supersecret_token"
    }


@app.get("/api/v1/info")
def api_info():
    if not VULN_CONFIG.get("jwt_insecure", True):
        # Patched JWT with alg: HS256 and exp
        return {
            "service": "Nexus Corporate Core API Gateway",
            "version": "2.6.0",
            "auth_standard": "RFC7519 JWT (HS256)",
            "sample_auth_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMDAxIiwibmFtZSI6IlVzZXIiLCJyb2xlIjoidXNlciIsImV4cCI6MTg5MzQ1NjAwMH0.sample_signature"
        }

    # Insecure JWT with alg: none
    return {
        "service": "Nexus Corporate Core API Gateway",
        "version": "2.6.0",
        "auth_standard": "RFC7519 JWT",
        "sample_auth_token": "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiJ1c3Jfc3RhZ2luZ185OSIsIm5hbWUiOiJBbGV4IE1lcmNlciIsInJvbGUiOiJhZG1pbl9kZXZlbG9wZXIifQ.",
        "staging_user": "usr_staging_99"
    }


# --------------------------------------------------------------------------
# 10. BOLA / IDOR & Chaining Step 2 (CWE-639)
# --------------------------------------------------------------------------
@app.get("/api/v1/user/profile")
def get_user_profile(user_id: str = Query(..., description="Target User ID")):
    # If Vulnerability is TOGGLED OFF (Patched)
    if not VULN_CONFIG.get("idor", True):
        raise HTTPException(status_code=401, detail="Authentication required: Valid user session token required to view profile.")

    # If Vulnerability is TOGGLED ON (Vulnerable)
    profiles = {
        "usr_staging_99": {
            "user_id": "usr_staging_99",
            "name": "Alex Mercer",
            "role": "admin_developer",
            "department": "Infrastructure & Core Security",
            "email": "alex.mercer@corp.internal",
            "api_key": "sec_k98_admin_supersecret_token"
        },
        "admin": {
            "user_id": "admin",
            "name": "System Administrator",
            "role": "admin",
            "email": "admin@corp.internal",
            "api_key": "sec_k98_admin_supersecret_token"
        },
        "1001": {
            "user_id": "1001",
            "name": "Standard Employee",
            "role": "user",
            "api_key": "sec_usr_standard_key_771"
        }
    }

    if user_id in profiles:
        return profiles[user_id]
    raise HTTPException(status_code=404, detail="User identifier not found")


# --------------------------------------------------------------------------
# 11. Chaining Step 3: Admin Privilege Escalation
# --------------------------------------------------------------------------
@app.get("/api/v1/admin/config")
def get_admin_config(x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
                     authorization: Optional[str] = Header(None, alias="Authorization")):
    # If Vulnerability is TOGGLED OFF (Patched)
    if not VULN_CONFIG.get("chaining_admin", True):
        raise HTTPException(status_code=403, detail="Forbidden: Admin endpoint requires Multi-Factor Authentication (MFA) and Hardware Key.")

    # If Vulnerability is TOGGLED ON (Vulnerable)
    provided_key = x_api_key
    if not provided_key and authorization:
        parts = authorization.split()
        if len(parts) == 2 and parts[0].lower() in ("bearer", "token", "apikey"):
            provided_key = parts[1]
        else:
            provided_key = authorization

    if provided_key == "sec_k98_admin_supersecret_token":
        return {
            "status": "admin_authenticated",
            "privilege": "ADMIN",
            "internal_db_host": "postgres-prod.internal.corp",
            "encryption_vault": "vault-01.internal",
            "system_message": "Full administrative control granted."
        }
    raise HTTPException(status_code=403, detail="Forbidden: Invalid or missing administrative X-API-Key")


# --------------------------------------------------------------------------
# 12. Client-Side Script with Leaked Secrets (CWE-798)
# --------------------------------------------------------------------------
@app.get("/static/app.js", response_class=PlainTextResponse)
def static_app_js():
    if not VULN_CONFIG.get("leaked_secrets", True):
        # Patched JS: No hardcoded secrets
        return PlainTextResponse("""// Nexus Enterprise Client Portal (Production Secured)
const API_BASE_URL = "/api/v1";
console.log("[Nexus] Portal client secured.");
""", media_type="application/javascript")

    # Vulnerable JS: Leaked Keys
    content = """/**
 * Nexus Enterprise Cloud Portal - Main Client Bundle (v2.6.0)
 */
const API_BASE_URL = "http://127.0.0.1:8989/api/v1";
const AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE";
const GOOGLE_API_KEY = "AIzaSyD-MOCK-SAMPLE-KEY-FOR-WVA-0123456";
const INTERNAL_API_SECRET = "sec_k98_admin_supersecret_token";
"""
    return PlainTextResponse(content, media_type="application/javascript")


# --------------------------------------------------------------------------
# 13. Sensitive Files: robots.txt, .env, backup.sql
# --------------------------------------------------------------------------
@app.get("/robots.txt", response_class=PlainTextResponse)
def robots_txt():
    return """User-agent: *
Disallow: /api/v1/admin/
Disallow: /debug/
Disallow: /.env
Disallow: /backup.sql
"""


@app.get("/.env", response_class=PlainTextResponse)
def dot_env():
    if not VULN_CONFIG.get("sensitive_files", True):
        raise HTTPException(status_code=404, detail="File not found")
    return """APP_ENV=production
DATABASE_URL=postgresql://nexus_admin:SuperSecretPass123!@127.0.0.1:5432/nexus_corp
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
INTERNAL_TOKEN=sec_k98_admin_supersecret_token
"""


@app.get("/backup.sql", response_class=PlainTextResponse)
def backup_sql():
    if not VULN_CONFIG.get("sensitive_files", True):
        raise HTTPException(status_code=404, detail="File not found")
    return """CREATE TABLE users (id SERIAL PRIMARY KEY, username VARCHAR(50), api_key VARCHAR(100));
INSERT INTO users VALUES (1, 'admin', 'sec_k98_admin_supersecret_token');
"""


# --------------------------------------------------------------------------
# Standalone Server Launcher
# --------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(description="WVA Security Testbed Web Server")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8989, help="Bind port (default: 8989)")
    args = parser.parse_args()

    print("=" * 70)
    print("   [NexusCorp] WVA Interactive Vulnerability Simulator with Live Controls")
    print("=" * 70)
    print(f"[*] Server starting on http://{args.host}:{args.port}")
    print("[*] Control Panel ready: Toggle individual rules ON/OFF from the Web UI.")
    print("=" * 70)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")


if __name__ == "__main__":
    main()
