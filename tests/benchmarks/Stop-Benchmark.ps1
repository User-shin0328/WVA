$ErrorActionPreference = 'Stop'
& docker compose -f (Join-Path $PSScriptRoot 'compose.yaml') down
if ($LASTEXITCODE -ne 0) { throw '실습 환경 종료 실패. 전용 compose 상태를 확인하세요.' }
Write-Host 'WVA benchmark containers stopped. Dedicated test DB volume and images are retained.'
