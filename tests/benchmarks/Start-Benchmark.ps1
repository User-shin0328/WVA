$ErrorActionPreference = 'Stop'
$composeFile = Join-Path $PSScriptRoot 'compose.yaml'
& docker info --format '{{.ServerVersion}}'
if ($LASTEXITCODE -ne 0) {
    & docker desktop start
    if ($LASTEXITCODE -ne 0) { throw 'Docker Desktop을 실행한 뒤 다시 시도하세요.' }
}
& docker compose -f $composeFile up -d --wait --wait-timeout 120
if ($LASTEXITCODE -ne 0) { throw '실습 환경 시작 실패. docker compose logs를 확인하세요.' }
& docker compose -f $composeFile ps
Write-Host 'DVWA low: http://127.0.0.1:18910 / DVWA impossible: http://127.0.0.1:18911 / Juice Shop: http://127.0.0.1:18912'
