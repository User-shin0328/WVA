@echo off
chcp 65001 >nul
title NexusCorp Security Testbed - WVA Target Server
cd /d "%~dp0"

echo ======================================================================
echo    NexusCorp Security Testbed Web Application (v2.6.0 Compatible)
echo ======================================================================
echo [*] Starting local vulnerability target server on http://127.0.0.1:8989 ...
echo [*] Target encompasses OWASP Top 10, KISA 21, and Multi-Step Chaining.
echo ======================================================================

start "" http://127.0.0.1:8989

if exist .venv\Scripts\python.exe (
    .venv\Scripts\python.exe mock_target.py --host 127.0.0.1 --port 8989
) else (
    python mock_target.py --host 127.0.0.1 --port 8989
)

pause
