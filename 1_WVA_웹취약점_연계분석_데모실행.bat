@echo off
chcp 949 >nul
title WVA - Web Vulnerability Chaining Agent Demo
cd /d "%~dp0"

echo ============================================================
echo   [WVA] Web Vulnerability and Attack Path Chaining Agent
echo   Demo: Vulnerable Testbed App and Multi-Step Chaining Analysis
echo ============================================================
echo.

set PYTHON_BIN=.venv\Scripts\python.exe
if not exist "%PYTHON_BIN%" set PYTHON_BIN=python.exe

echo [INFO] Python executable: %PYTHON_BIN%
echo [INFO] Running WVA demo with local testbed...
echo.

"%PYTHON_BIN%" cli.py --demo

echo.
echo ============================================================
echo   Analysis Completed. Check WVA_vulnerability_report.md
echo ============================================================
echo.
pause
