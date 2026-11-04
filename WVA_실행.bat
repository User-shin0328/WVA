@echo off
chcp 949 >nul
title WVA
cd /d "%~dp0"
if exist WVA.exe start "" WVA.exe
if not exist WVA.exe .venv\Scripts\python.exe launcher.py
