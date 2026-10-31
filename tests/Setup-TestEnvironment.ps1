$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot
$testPython = Join-Path $projectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $testPython)) {
    $runtimePython = Join-Path $env:USERPROFILE '.cache/codex-runtimes/codex-primary-runtime/dependencies/python/python.exe'
    if ($env:WVA_PYTHON) { $runtimePython = $env:WVA_PYTHON }
    elseif (-not (Test-Path -LiteralPath $runtimePython)) {
        $candidatePython = Get-Command python -ErrorAction SilentlyContinue
        if (-not $candidatePython) { throw 'Python 3.11 이상을 설치하거나 WVA_PYTHON에 python.exe 경로를 지정하세요.' }
        $runtimePython = $candidatePython.Source
    }
    & $runtimePython -c 'import sys; assert sys.version_info >= (3,11)'
    if ($LASTEXITCODE -ne 0) { throw 'Python 3.11 이상을 찾을 수 없습니다. WVA_PYTHON을 지정하세요.' }
    & $runtimePython -m venv .venv
    if ($LASTEXITCODE -ne 0) { throw '테스트 환경 생성에 실패했습니다.' }
}
& $testPython -m pip install -r requirements-lock.txt
if ($LASTEXITCODE -ne 0) { throw '테스트 의존성 설치에 실패했습니다.' }
Write-Host '환경 준비 완료. python -m tests.run_tests 명령은 .venv/Scripts/python.exe로 실행하세요.'
