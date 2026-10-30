@echo off
chcp 949 >nul
title WVA - Interactive Vulnerability Scanner CLI
cd /d "%~dp0"

echo ============================================================
echo   [WVA] Web Vulnerability and Attack Path Chaining Agent CLI
echo ============================================================
echo.

set PYTHON_BIN=.venv\Scripts\python.exe
if not exist "%PYTHON_BIN%" set PYTHON_BIN=python.exe

"%PYTHON_BIN%" cli.py

echo.
pause
