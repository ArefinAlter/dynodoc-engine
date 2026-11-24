$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoRoot

$RustVer = if (Get-Command rustc -ErrorAction SilentlyContinue) { (rustc --version) } else { 'MISSING' }
$DockerVer = if (Get-Command docker -ErrorAction SilentlyContinue) { (docker --version) } else { 'MISSING' }
$DotEnv = if (Test-Path -LiteralPath (Join-Path $RepoRoot '.env')) { 'present' } else { 'MISSING (run: task setup)' }
$MigrateEnv = if (Test-Path -LiteralPath (Join-Path $RepoRoot '.env.migrate')) { 'present' } else { 'MISSING (run: task setup)' }

Write-Output "Rust:   $RustVer"
Write-Output "Docker: $DockerVer"
Write-Output ".env:         $DotEnv"
Write-Output ".env.migrate: $MigrateEnv"
