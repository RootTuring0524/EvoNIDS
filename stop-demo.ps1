[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $MyInvocation.MyCommand.Path
$statePath = Join-Path $root 'tmp\demo-runtime\pids.json'

if (-not (Test-Path -LiteralPath $statePath)) {
    Write-Host 'No process record from start-demo.ps1 was found; nothing was stopped.'
    exit 0
}

$state = Get-Content -LiteralPath $statePath -Raw | ConvertFrom-Json
foreach ($processId in @($state.frontendPid, $state.backendPid)) {
    if (-not $processId) {
        continue
    }
    $process = Get-Process -Id ([int]$processId) -ErrorAction SilentlyContinue
    if ($process) {
        Stop-Process -Id $process.Id -Force
        Write-Host "Stopped process $($process.Id) ($($process.ProcessName))."
    }
}

Remove-Item -LiteralPath $statePath -Force
Write-Host 'EvoNIDS demo services stopped.' -ForegroundColor Green
