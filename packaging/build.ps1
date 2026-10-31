$ErrorActionPreference = 'Stop'
$projectRoot = Split-Path $PSScriptRoot -Parent
Set-Location -LiteralPath $projectRoot
$buildPython = Join-Path $projectRoot '.venv/Scripts/python.exe'
if (-not (Test-Path -LiteralPath $buildPython)) { throw 'tests/Setup-TestEnvironment.ps1을 먼저 실행하세요.' }
$sslPolicyFile = (& $buildPython -c "import ssl,pathlib,json; print(json.dumps(str(pathlib.Path(ssl.__file__).with_name('codex-rejected-cas.pem'))))") | ConvertFrom-Json
$extraData = @()
if (Test-Path -LiteralPath $sslPolicyFile) { $extraData = @('--add-data', "$sslPolicyFile;.") }
& $buildPython -m PyInstaller --noconfirm --clean --onefile --windowed --name WVA --icon (Join-Path $PSScriptRoot 'WVA.ico') --distpath $projectRoot --workpath (Join-Path $projectRoot 'build') --specpath $PSScriptRoot --add-data "$projectRoot/dashboard/static;dashboard/static" @extraData --exclude-module pytest --exclude-module PIL --collect-submodules uvicorn --hidden-import mock_target (Join-Path $projectRoot 'launcher.py')
if ($LASTEXITCODE -ne 0) { throw '실행파일 빌드에 실패했습니다.' }
Get-FileHash -LiteralPath (Join-Path $projectRoot 'WVA.exe') -Algorithm SHA256
