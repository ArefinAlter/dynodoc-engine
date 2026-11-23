$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
Set-Location $RepoRoot

function New-Hex32 {
    $bytes = New-Object byte[] 32
    $rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    try {
        $rng.GetBytes($bytes)
    } finally {
        $rng.Dispose()
    }
    return ([System.BitConverter]::ToString($bytes) -replace '-', '').ToLowerInvariant()
}

$Utf8NoBom = New-Object System.Text.UTF8Encoding($false)

$EnvPath = Join-Path $RepoRoot '.env'
if (Test-Path -LiteralPath $EnvPath) {
    Write-Output '[setup] preserved existing .env'
} else {
    $ExamplePath = Join-Path $RepoRoot '.env.example'
    if (-not (Test-Path -LiteralPath $ExamplePath)) {
        [Console]::Error.WriteLine("error: .env.example not found in $RepoRoot")
        exit 1
    }

    $pasetoKey = New-Hex32
    $webKey = New-Hex32
    $runtimePw = New-Hex32

    $lines = [System.IO.File]::ReadAllLines($ExamplePath, $Utf8NoBom)
    $out = New-Object System.Collections.Generic.List[string]
    foreach ($rawLine in $lines) {
        $line = $rawLine.TrimEnd("`r")
        if ($line -match '^DATABASE_URL=.*REPLACE_WITH_RUNTIME_PASSWORD') {
            $out.Add($line.Replace('REPLACE_WITH_RUNTIME_PASSWORD', $runtimePw))
        } elseif ($line -eq 'PASETO_LOCAL_KEY=') {
            $out.Add("PASETO_LOCAL_KEY=$pasetoKey")
        } elseif ($line -eq 'WEB_SERVICE_KEY=') {
            $out.Add("WEB_SERVICE_KEY=$webKey")
        } else {
            $out.Add($line)
        }
    }

    $TmpPath = Join-Path $RepoRoot (".env.tmp." + [System.Guid]::NewGuid().ToString('N'))
    try {
        [System.IO.File]::WriteAllText($TmpPath, (($out.ToArray()) -join "`n") + "`n", $Utf8NoBom)
        Move-Item -LiteralPath $TmpPath -Destination $EnvPath
    } finally {
        if (Test-Path -LiteralPath $TmpPath) {
            Remove-Item -LiteralPath $TmpPath -Force
        }
    }
    Write-Output '[setup] created .env with generated local development keys'
}

$MigrateEnvPath = Join-Path $RepoRoot '.env.migrate'
if (Test-Path -LiteralPath $MigrateEnvPath) {
    Write-Output '[setup] preserved existing .env.migrate'
} else {
    $MigrateExamplePath = Join-Path $RepoRoot 'migration.env.example'
    if (-not (Test-Path -LiteralPath $MigrateExamplePath)) {
        [Console]::Error.WriteLine("error: migration.env.example not found in $RepoRoot")
        exit 1
    }
    $migrateContent = ([System.IO.File]::ReadAllText($MigrateExamplePath, $Utf8NoBom)).Replace("`r`n", "`n")
    [System.IO.File]::WriteAllText($MigrateEnvPath, $migrateContent, $Utf8NoBom)
    Write-Output '[setup] created .env.migrate from migration.env.example'
}
