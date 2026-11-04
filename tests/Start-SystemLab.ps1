$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot
$labPython = Join-Path $projectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $labPython)) { throw 'Setup-TestEnvironment.ps1을 먼저 실행하세요.' }
& $labPython -c "import uvicorn; from tests.lab.system_target import create_app; uvicorn.run(create_app('tests/artifacts/system-lab'), host='127.0.0.1', port=18914, log_level='warning')"
