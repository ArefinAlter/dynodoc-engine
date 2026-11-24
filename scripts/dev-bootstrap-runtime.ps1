$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoRoot

$EnvPath = Join-Path $RepoRoot '.env'
if (-not (Test-Path -LiteralPath $EnvPath)) {
    [Console]::Error.WriteLine("error: .env not found; run 'task setup' first")
    exit 1
}

$DatabaseUrl = $null
foreach ($rawLine in [System.IO.File]::ReadAllLines($EnvPath)) {
    $line = $rawLine.TrimEnd("`r")
    if ($line -match '^DATABASE_URL=(.*)$') {
        $DatabaseUrl = $Matches[1]
        break
    }
}

if ([string]::IsNullOrEmpty($DatabaseUrl)) {
    [Console]::Error.WriteLine('error: DATABASE_URL is not set in .env')
    exit 1
}

if ($DatabaseUrl -notmatch '^postgres(?:ql)?://dynodoc_runtime:([^@]+)@127\.0\.0\.1:5548/dynodoc_engine(\?.*)?$') {
    [Console]::Error.WriteLine('error: dev-bootstrap-runtime only supports the local Compose DATABASE_URL')
    [Console]::Error.WriteLine('       expected: postgres://dynodoc_runtime:<password>@127.0.0.1:5548/dynodoc_engine')
    exit 1
}

$RawPw = $Matches[1]
if ([string]::IsNullOrEmpty($RawPw) -or $RawPw -eq 'REPLACE_WITH_RUNTIME_PASSWORD') {
    [Console]::Error.WriteLine("error: DATABASE_URL still contains the placeholder password; run 'task setup' or set a password in .env")
    exit 1
}

$RuntimePw = [System.Uri]::UnescapeDataString($RawPw)
$EscapedPw = $RuntimePw.Replace("'", "''")

$Sql = @"
DO `$`$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'dynodoc_runtime') THEN
    CREATE ROLE dynodoc_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
  END IF;
END
`$`$;
ALTER ROLE dynodoc_runtime WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS PASSWORD '$EscapedPw';
"@

$Sql | docker compose exec -T postgres psql -v ON_ERROR_STOP=1 -q -U dynodoc -d dynodoc_engine
if ($LASTEXITCODE -ne 0) {
    exit $LASTEXITCODE
}

Write-Output '[db:bootstrap-runtime] ensured restricted role dynodoc_runtime in local PostgreSQL'
