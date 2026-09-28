<#
.SYNOPSIS
  EvoNIDS backup.ps1 — Windows equivalent of scripts/backup/backup.sh for the
  single-node dev/lab path.

.DESCRIPTION
  Creates a timestamped backup directory under the backup root containing:
    * the PostgreSQL logical dump (pg_dump -Fc) for the Compose stack, or
      a consistent file copy of the SQLite demo database (backend/evonids.db),
    * the dataset registration metadata manifest (PostgreSQL mode only),
    * a model-artifacts archive (backend/model-artifacts),
    * an optional datasets-files archive (--IncludeDatasets),
    * SHA-256 checksums (SHA256SUMS.txt, sha256sum-compatible) and backup.json.
  Retention: keeps the newest -Keep directories (default 14).

  PostgreSQL mode refuses to run without PG*/POSTGRES_* credentials and
  without a working pg_dump (PATH) or Docker (docker compose exec).
  SQLite mode refuses when the database file does not exist.

.EXAMPLE
  powershell -ExecutionPolicy Bypass -File .\scripts\backup\backup.ps1
  powershell -ExecutionPolicy Bypass -File .\scripts\backup\backup.ps1 -IncludeDatasets -Keep 7
#>
[CmdletBinding()]
param(
    [string]$BackupDir = "",                    # default: <repo>\backups
    [int]$Keep = 14,                            # newest directories to keep
    [switch]$IncludeDatasets,                   # archive backend/datasets files
    [switch]$SkipDb,                            # skip DB dump/copy (files only)
    [string]$EnvFile = ""                       # default: <repo>\.env
)

$ErrorActionPreference = 'Stop'

function Get-RepoRoot {
    # scripts/backup/backup.ps1 -> <repo>
    $dir = Split-Path -Parent $PSScriptRoot
    return Split-Path -Parent $dir
}

$RepoRoot = Get-RepoRoot
$DefaultEnvFile = Join-Path $RepoRoot '.env'
if ([string]::IsNullOrEmpty($EnvFile)) { $EnvFile = $DefaultEnvFile }

# --- load optional .env (KEY=VALUE lines only) ------------------------------
$envMap = @{}
if (Test-Path $EnvFile) {
    Get-Content $EnvFile | ForEach-Object {
        $line = $_.Trim()
        if ($line -and -not $line.StartsWith('#') -and $line.Contains('=')) {
            $idx = $line.IndexOf('=')
            $k = $line.Substring(0, $idx).Trim()
            $v = $line.Substring($idx + 1).Trim().Trim('"').Trim("'")
            if ($k -match '^[A-Za-z_][A-Za-z0-9_]*$') { $envMap[$k] = $v }
        }
    }
}

# --- defaults ----------------------------------------------------------------
if ([string]::IsNullOrEmpty($BackupDir)) {
    if ($envMap.ContainsKey('EVONIDS_BACKUP_DIR') -and $envMap['EVONIDS_BACKUP_DIR']) {
        $BackupDir = $envMap['EVONIDS_BACKUP_DIR']
    } else {
        $BackupDir = Join-Path $RepoRoot 'backups'
    }
}
$ModelDir = Join-Path $RepoRoot 'backend\model-artifacts'
$DatasetsDir = Join-Path $RepoRoot 'backend\datasets'
$DbFile = Join-Path $RepoRoot 'backend\evonids.db'

function Get-Env($Name) {
    # process env first, then .env map
    $v = [System.Environment]::GetEnvironmentVariable($Name)
    if ($v) { return [string]$v }
    if ($envMap.ContainsKey($Name)) { return [string]$envMap[$Name] }
    return ''
}

$evDbUrl = Get-Env 'EVONIDS_DATABASE_URL'
$pgPass = Get-Env 'POSTGRES_PASSWORD'
$sqliteMode = $false
if (-not $SkipDb) {
    if ($evDbUrl -like 'sqlite*') {
        $sqliteMode = $true
    } elseif ($pgPass) {
        $sqliteMode = $false
    } else {
        # local dev default is SQLite when the file exists
        $sqliteMode = Test-Path $DbFile
    }
}

# --- tool checks ---------------------------------------------------------------
function Test-Command($Name) { return [bool](Get-Command $Name -ErrorAction SilentlyContinue) }

$pgHost = if (Get-Env 'PGHOST') { Get-Env 'PGHOST' } elseif (Get-Env 'POSTGRES_HOST') { Get-Env 'POSTGRES_HOST' } else { '127.0.0.1' }
$pgPort = if (Get-Env 'PGPORT') { Get-Env 'PGPORT' } elseif (Get-Env 'POSTGRES_PORT') { Get-Env 'POSTGRES_PORT' } else { '5432' }
$pgUser = if (Get-Env 'PGUSER') { Get-Env 'PGUSER' } elseif (Get-Env 'POSTGRES_USER') { Get-Env 'POSTGRES_USER' } else { 'evonids' }
$pgDb = if (Get-Env 'PGDATABASE') { Get-Env 'PGDATABASE' } elseif (Get-Env 'POSTGRES_DB') { Get-Env 'POSTGRES_DB' } else { 'evonids' }

if (-not $SkipDb) {
    if ($sqliteMode) {
        if (-not (Test-Path $DbFile)) {
            Write-Error "backup.ps1: SQLite database not found: $DbFile (start the demo first or set EVONIDS_DATABASE_URL / POSTGRES_* for the Compose stack)"
        }
    } else {
        if (-not $pgPass) {
            Write-Error 'backup.ps1: PostgreSQL mode requires POSTGRES_PASSWORD (or PGPASSWORD) in the process environment or in .env'
        }
        if (-not ((Test-Command 'pg_dump') -or (Test-Command 'docker'))) {
            Write-Error 'backup.ps1: PostgreSQL mode needs pg_dump on PATH or a working docker (docker compose exec postgres pg_dump)'
        }
    }
}

# --- create timestamped backup dir ----------------------------------------------
$ts = Get-Date -Format 'yyyyMMdd-HHmmss'
$dest = Join-Path $BackupDir "evonids-$ts"
New-Item -ItemType Directory -Path $dest -Force | Out-Null
Write-Host "==> EvoNIDS backup: $dest"

$artifacts = [System.Collections.Generic.List[string]]::new()

# --- 1. database ----------------------------------------------------------------
if (-not $SkipDb) {
    if ($sqliteMode) {
        Write-Host "==> copying SQLite database: $DbFile"
        # Copy the WAL/SHM too when present so the copy is as consistent as possible.
        # Stop the demo (stop-demo.ps1) for a guaranteed consistent snapshot.
        Copy-Item $DbFile (Join-Path $dest "evonids-db-$ts.sqlite") -Force
        foreach ($ext in @('-wal', '-shm')) {
            $side = "$DbFile$ext"
            if (Test-Path $side) { Copy-Item $side (Join-Path $dest "evonids-db-$ts.sqlite$ext") -Force }
        }
        $artifacts.Add("evonids-db-$ts.sqlite")
    } else {
        $dump = Join-Path $dest "evonids-db-$ts.dump"
        Write-Host "==> pg_dump ${pgHost}:${pgPort}/${pgDb}"
        $pgArgs = @('-U', $pgUser, '-h', $pgHost, '-p', $pgPort, '-d', $pgDb)
        $env:PGPASSWORD = $pgPass
        try {
            if (Test-Command 'pg_dump') {
                & pg_dump -Fc -f $dump @pgArgs
                if ($LASTEXITCODE -ne 0) { throw "pg_dump exited with code $LASTEXITCODE" }
            } else {
                # Compose path: the postgres service exposes pg_dump inside the container.
                $proc = Start-Process -FilePath 'docker' -ArgumentList @(
                    'compose', '-f', (Join-Path $RepoRoot 'docker-compose.yml'), '-f', (Join-Path $RepoRoot 'docker-compose.prod.yml'),
                    'exec', '-T', 'postgres', 'pg_dump', '-Fc', '-U', $pgUser, '-d', $pgDb
                ) -NoNewWindow -Wait -PassThru -RedirectStandardOutput $dump
                if ($proc.ExitCode -ne 0) { throw "docker compose exec pg_dump exited with code $($proc.ExitCode)" }
            }

            # dataset metadata sidecar (best-effort; records are inside the dump)
            $manifest = Join-Path $dest "datasets-manifest-$ts.txt"
            try {
                if (Test-Command 'psql') {
                    & psql -h $pgHost -p $pgPort -U $pgUser -d $pgDb -At -F '|' -c `
                        "SELECT id, name, version, relative_path, state, COALESCE(sha256, '') FROM dataset_assets ORDER BY id;" |
                        Set-Content -Path $manifest -Encoding utf8
                    if ($LASTEXITCODE -ne 0) { Remove-Item $manifest -ErrorAction SilentlyContinue }
                    else { $artifacts.Add("datasets-manifest-$ts.txt") }
                }
            } catch {
                Write-Warning "backup.ps1: dataset manifest export skipped: $($_.Exception.Message)"
                Remove-Item $manifest -ErrorAction SilentlyContinue
            }
        } finally {
            Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
        }
        $artifacts.Add("evonids-db-$ts.dump")
    }
}

# --- 2. model artifacts ----------------------------------------------------------
if (Test-Path $ModelDir) {
    Write-Host "==> archiving model artifacts: $ModelDir"
    $models = Join-Path $dest "model-artifacts-$ts.tar.gz"
    tar -czf $models -C (Split-Path -Parent $ModelDir) (Split-Path -Leaf $ModelDir)
    if ($LASTEXITCODE -ne 0) { throw "tar failed with code $LASTEXITCODE" }
    $artifacts.Add("model-artifacts-$ts.tar.gz")
} else {
    Write-Warning "model artifact directory not found (skipped): $ModelDir"
}

# --- 3. datasets files (optional) -------------------------------------------------
if ($IncludeDatasets -and (Test-Path $DatasetsDir)) {
    Write-Host "==> archiving dataset files: $DatasetsDir"
    $ds = Join-Path $dest "datasets-files-$ts.tar.gz"
    tar -czf $ds -C (Split-Path -Parent $DatasetsDir) (Split-Path -Leaf $DatasetsDir)
    if ($LASTEXITCODE -ne 0) { throw "tar failed with code $LASTEXITCODE" }
    $artifacts.Add("datasets-files-$ts.tar.gz")
}

# --- 4. checksums + metadata -------------------------------------------------------
$checksumLines = foreach ($name in ($artifacts | Sort-Object)) {
    $path = Join-Path $dest $name
    if (Test-Path $path) {
        $hash = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()
        "$hash  $name"
    }
}
$checksumLines | Set-Content -Path (Join-Path $dest 'SHA256SUMS.txt') -Encoding ascii

$meta = [ordered]@{
    tool = 'scripts/backup/backup.ps1'
    created_at = $ts
    mode = if ($SkipDb) { 'files-only' } elseif ($sqliteMode) { 'sqlite-copy' } else { 'postgres-pg_dump' }
    database = if ($SkipDb -or $sqliteMode) { $null } else { @{ host = $pgHost; port = $pgPort; name = $pgDb; user = $pgUser } }
    artifacts = @($artifacts | Sort-Object)
}
(ConvertTo-Json $meta -Depth 4) | Set-Content -Path (Join-Path $dest 'backup.json') -Encoding utf8

# --- 5. verify checksums -------------------------------------------------------------
Write-Host '==> verifying checksums'
$bad = 0
foreach ($name in ($artifacts | Sort-Object)) {
    $path = Join-Path $dest $name
    if (-not (Test-Path $path)) { Write-Warning "missing artifact: $name"; $bad++ ; continue }
    $stored = ((Get-Content (Join-Path $dest 'SHA256SUMS.txt') | Where-Object { $_ -like "*  $name" }) -split '\s+')[0]
    $actual = (Get-FileHash -Path $path -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($stored -ne $actual) { Write-Warning "checksum mismatch: $name"; $bad++ }
}
if ($bad -gt 0) { throw "backup.ps1: $bad artifact(s) failed checksum verification" }

# --- 6. retention (keep newest $Keep) ------------------------------------------------
$existing = Get-ChildItem -Path $BackupDir -Directory -Filter 'evonids-*' |
    Sort-Object Name -Descending
$i = 0
foreach ($d in $existing) {
    $i++
    if ($i -gt $Keep) {
        Write-Host "==> pruning $($d.FullName)"
        Remove-Item -Path $d.FullName -Recurse -Force
    }
}

Write-Host ''
Write-Host "==> backup complete: $dest"
Get-ChildItem $dest | Select-Object Name, Length | Format-Table -AutoSize
Write-Host "Validate later on a POSIX host with: scripts/backup/verify-backup.sh $dest"
