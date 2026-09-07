$ErrorActionPreference = 'Stop'
& (Join-Path $PSScriptRoot 'ServiceEdition\build.ps1')
Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'ServiceEdition\AppGateService.exe') -Destination (Join-Path $PSScriptRoot 'AppGate.exe') -Force
