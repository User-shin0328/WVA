@echo off
chcp 949 >nul
title WVA - Web Vulnerability Auditor Execution Dashboard
cd /d "%~dp0"

echo ============================================================
echo   [WVA] Web Vulnerability and Attack Path Chaining Dashboard
echo ============================================================
echo.

set PYTHON_BIN=.venv\Scripts\python.exe
if not exist "%PYTHON_BIN%" set PYTHON_BIN=python.exe

echo [INFO] Python executable: %PYTHON_BIN%
echo [INFO] Starting Dashboard Server at http://127.0.0.1:8787 ...
echo [INFO] Opening web browser...
echo.

start "" "http://127.0.0.1:8787"
"%PYTHON_BIN%" -m dashboard.server

echo.
pause
