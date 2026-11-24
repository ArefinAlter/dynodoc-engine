$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoRoot

. (Join-Path $PSScriptRoot 'dev-port.ps1')

$apiHost = if ($env:API_HOST) { $env:API_HOST } else { '127.0.0.1' }
$apiPort = if ($env:API_PORT) { $env:API_PORT } else { '8080' }

if ($apiPort -eq '8080') {
    $freePort = Get-FreeLocalPort -HostAddress $apiHost -StartPort 8080
    if ($freePort -ne 8080) {
        Write-Output "[run] port 8080 is in use; starting engine-api on ${apiHost}:${freePort} (set API_PORT in .env to pin a port)"
        $env:API_PORT = [string]$freePort
    }
}

& cargo run --locked -p engine-api --bin engine-api
exit $LASTEXITCODE
