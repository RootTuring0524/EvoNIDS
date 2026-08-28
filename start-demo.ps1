[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$backendRoot = Join-Path $root 'backend'
$frontendRoot = Join-Path $root 'project'
$runtimeRoot = Join-Path $root 'tmp\demo-runtime'
$statePath = Join-Path $runtimeRoot 'pids.json'
$backendUrl = 'http://127.0.0.1:8000/api/v1/health'
$frontendUrl = 'http://127.0.0.1:3000/overview'
$rootEnvPath = Join-Path $root '.env'

# Some Windows launchers can inject both Path and PATH. Start-Process builds a
# case-insensitive environment dictionary and fails when both spellings exist.
$processPath = $env:Path
[Environment]::SetEnvironmentVariable('PATH', $null, 'Process')
[Environment]::SetEnvironmentVariable('Path', $processPath, 'Process')

function Test-LocalUrl {
    param([Parameter(Mandatory)][string]$Url)
    try {
        $response = Invoke-WebRequest -UseBasicParsing -Uri $Url -TimeoutSec 2
        return $response.StatusCode -ge 200 -and $response.StatusCode -lt 500
    }
    catch {
        return $false
    }
}

function Get-LocalListenerPid {
    param([Parameter(Mandatory)][int]$Port)
    foreach ($line in (netstat -ano -p tcp)) {
        if ($line -match ("^\s*TCP\s+127\.0\.0\.1:" + $Port + "\s+\S+\s+LISTENING\s+(\d+)\s*$")) {
            return [int]$Matches[1]
        }
    }
    return $null
}

$backendReady = Test-LocalUrl -Url $backendUrl
$frontendReady = Test-LocalUrl -Url $frontendUrl
if ($backendReady -and $frontendReady) {
    Write-Host 'EvoNIDS is already running:' -ForegroundColor Green
    Write-Host '  UI   http://127.0.0.1:3000/overview'
    Write-Host '  API  http://127.0.0.1:8000/docs'
    exit 0
}
if ($backendReady -xor $frontendReady) {
    throw 'Only one service is running. Stop the stale process before rerunning start-demo.ps1 so both services share one token.'
}

$deepSeekNames = @(
    'NUXT_DEEPSEEK_API_BASE',
    'NUXT_DEEPSEEK_API_KEY',
    'NUXT_DEEPSEEK_MODEL'
)
if (Test-Path -LiteralPath $rootEnvPath) {
    $rootEnvLines = Get-Content -LiteralPath $rootEnvPath -Encoding UTF8
    foreach ($name in $deepSeekNames) {
        $prefix = "$name="
        $line = $rootEnvLines | Where-Object { $_.StartsWith($prefix) } | Select-Object -First 1
        if ($line) {
            $value = $line.Substring($prefix.Length).Trim()
            if (
                ($value.StartsWith('"') -and $value.EndsWith('"')) -or
                ($value.StartsWith("'") -and $value.EndsWith("'"))
            ) {
                $value = $value.Substring(1, $value.Length - 2)
            }
            [Environment]::SetEnvironmentVariable($name, $value, 'Process')
        }
    }
}

$python = Join-Path $backendRoot '.venv\Scripts\python.exe'
if (-not (Test-Path -LiteralPath $python)) {
    throw "Backend virtual environment was not found: $python"
}
$node = (Get-Command node.exe -ErrorAction Stop).Source
$nuxt = Join-Path $frontendRoot 'node_modules\nuxt\bin\nuxt.mjs'
if (-not (Test-Path -LiteralPath $nuxt)) {
    throw 'Frontend dependencies are missing. Run corepack pnpm install in the project directory first.'
}

New-Item -ItemType Directory -Path $runtimeRoot -Force | Out-Null
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'

$bytes = New-Object byte[] 32
$rng = New-Object System.Security.Cryptography.RNGCryptoServiceProvider
try {
    $rng.GetBytes($bytes)
}
finally {
    $rng.Dispose()
}
$token = ([BitConverter]::ToString($bytes)).Replace('-', '').ToLowerInvariant()

$env:PYTHONUNBUFFERED = '1'
$env:EVONIDS_AUTO_CREATE_DB = 'true'
$env:EVONIDS_ADMIN_API_TOKEN = $token
$env:EVONIDS_SENSOR_INGEST_TOKEN = $token
$backendProcess = Start-Process `
    -FilePath $python `
    -ArgumentList @('-m', 'uvicorn', 'app.main:app', '--host', '127.0.0.1', '--port', '8000') `
    -WorkingDirectory $backendRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $runtimeRoot "backend-$stamp.out.log") `
    -RedirectStandardError (Join-Path $runtimeRoot "backend-$stamp.err.log") `
    -PassThru

$env:NUXT_PUBLIC_USE_MOCK_API = 'false'
$env:NUXT_BACKEND_API_BASE = 'http://127.0.0.1:8000/api/v1'
$env:NUXT_BACKEND_ADMIN_TOKEN = $token
$env:NUXT_SENSOR_INGEST_TOKEN = $token
$frontendProcess = Start-Process `
    -FilePath $node `
    -ArgumentList @('.\node_modules\nuxt\bin\nuxt.mjs', 'dev', '--host', '127.0.0.1') `
    -WorkingDirectory $frontendRoot `
    -WindowStyle Hidden `
    -RedirectStandardOutput (Join-Path $runtimeRoot "frontend-$stamp.out.log") `
    -RedirectStandardError (Join-Path $runtimeRoot "frontend-$stamp.err.log") `
    -PassThru

@{
    startedAt = (Get-Date).ToString('o')
    backendPid = $backendProcess.Id
    frontendPid = $frontendProcess.Id
} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8

$deadline = (Get-Date).AddSeconds(45)
do {
    Start-Sleep -Milliseconds 750
    $backendReady = Test-LocalUrl -Url $backendUrl
    $frontendReady = Test-LocalUrl -Url $frontendUrl
} until (($backendReady -and $frontendReady) -or (Get-Date) -ge $deadline)

if (-not ($backendReady -and $frontendReady)) {
    throw "Services did not become ready in 45 seconds. Inspect logs in: $runtimeRoot"
}

$backendListenerPid = Get-LocalListenerPid -Port 8000
$frontendListenerPid = Get-LocalListenerPid -Port 3000
@{
    startedAt = (Get-Date).ToString('o')
    backendPid = if ($backendListenerPid) { $backendListenerPid } else { $backendProcess.Id }
    frontendPid = if ($frontendListenerPid) { $frontendListenerPid } else { $frontendProcess.Id }
} | ConvertTo-Json | Set-Content -LiteralPath $statePath -Encoding UTF8

Write-Host 'EvoNIDS started:' -ForegroundColor Green
Write-Host '  UI    http://127.0.0.1:3000/overview'
Write-Host '  API   http://127.0.0.1:8000/docs'
Write-Host '  Stop  .\stop-demo.ps1'
Write-Host "  Logs  $runtimeRoot"
