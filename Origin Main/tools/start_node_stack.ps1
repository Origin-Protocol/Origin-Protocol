#pragma warning disable PSAvoidAssignmentToAutomaticVariable
param(
  [string]$ProjectRoot = "$(Split-Path -Parent (Split-Path -Parent $PSScriptRoot))",
  [string]$PythonExe = "python",
  [string]$ServerHost = "127.0.0.1",
  [int]$ServerPort = 4000,
  [int]$FullNodePort = 9021,
  [int]$RegistryPort = 9031,
  [string]$SharedLedgerPath = "$env:TEMP/origin_shared_ledger.json",
  [int]$SyncIntervalSeconds = 60,
  [switch]$Stop
)

$ErrorActionPreference = "Stop"

$serverDir = Join-Path $ProjectRoot "Origin-Protocol/experimental/server"
$fullNodeScript = Join-Path $ProjectRoot "Origin Main/tools/full_node_service.py"
$registryScript = Join-Path $ProjectRoot "Origin Main/tools/node_registry_service.py"
$stackStatePath = Join-Path $PSScriptRoot ".node-stack.pids.json"
$pythonPathValue = Join-Path $ProjectRoot "Origin Main"
$backendHealthUrl = "http://$ServerHost`:$ServerPort/healthz"
$logDir = Join-Path $PSScriptRoot "logs"

function Wait-HttpReady {
  param(
    [string]$Url,
    [int]$Retries = 20,
    [int]$SleepSeconds = 1
  )

  for ($i = 0; $i -lt $Retries; $i++) {
    try {
      $null = Invoke-WebRequest -Uri $Url -UseBasicParsing -TimeoutSec 3
      return $true
    } catch {
      Start-Sleep -Seconds $SleepSeconds
    }
  }

  return $false
}

function Stop-ByPidFile {
  if (-not (Test-Path $stackStatePath)) {
    Write-Host "No PID file found at $stackStatePath"
    return
  }

  $state = Get-Content $stackStatePath -Raw | ConvertFrom-Json
  foreach ($name in @("registry", "fullNode", "backend")) {
    if ($name -eq "backend" -and -not $state.backendManaged) {
      continue
    }
    $procId = $state.$name
    if ($procId) {
      try {
        Stop-Process -Id ([int]$procId) -Force -ErrorAction Stop
        Write-Host "Stopped $name (PID $procId)"
      } catch {
        Write-Host "$name already stopped (PID $procId)"
      }
    }
  }

  Remove-Item -Force $stackStatePath -ErrorAction SilentlyContinue
}

function Stop-PortOwner {
  param([int]$Port)

  try {
    $listeners = Get-NetTCPConnection -LocalPort $Port -State Listen -ErrorAction Stop |
      Select-Object -ExpandProperty OwningProcess -Unique
  } catch {
    return
  }

  foreach ($procId in $listeners) {
    if (-not $procId) { continue }
    try {
      Stop-Process -Id ([int]$procId) -Force -ErrorAction Stop
      Write-Host "Stopped process on port $Port (PID $procId)"
    } catch {
      Write-Host "Port $Port owner already stopped (PID $procId)"
    }
  }
}

if ($Stop) {
  Stop-ByPidFile
  exit 0
}

if (Test-Path $stackStatePath) {
  Stop-ByPidFile
}

Stop-PortOwner -Port $FullNodePort
Stop-PortOwner -Port $RegistryPort

if (-not (Test-Path $serverDir)) {
  throw "Server directory not found: $serverDir"
}
if (-not (Test-Path $fullNodeScript)) {
  throw "full_node_service.py not found: $fullNodeScript"
}
if (-not (Test-Path $registryScript)) {
  throw "node_registry_service.py not found: $registryScript"
}

New-Item -ItemType Directory -Force $logDir | Out-Null
$stamp = Get-Date -Format "yyyyMMdd-HHmmss"
$fullNodeOut = Join-Path $logDir "fullnode-$stamp.out.log"
$fullNodeErr = Join-Path $logDir "fullnode-$stamp.err.log"
$registryOut = Join-Path $logDir "registry-$stamp.out.log"
$registryErr = Join-Path $logDir "registry-$stamp.err.log"

$backend = $null
if (-not (Wait-HttpReady -Url $backendHealthUrl -Retries 1 -SleepSeconds 1)) {
  $backend = Start-Process -FilePath "node" -ArgumentList "dist/index.js" -WorkingDirectory $serverDir -PassThru
} else {
  Write-Host "Backend already running at $backendHealthUrl (will not start another instance)"
}

$fullNode = Start-Process -FilePath $PythonExe -ArgumentList @(
  "`"$fullNodeScript`"",
  "--listen", "$ServerHost`:$FullNodePort",
  "--ledger-path", "`"$SharedLedgerPath`"",
  "--origin-server", "http://$ServerHost`:$ServerPort",
  "--sync-interval", "$SyncIntervalSeconds"
) -RedirectStandardOutput $fullNodeOut -RedirectStandardError $fullNodeErr -PassThru

$previousPythonPath = $env:PYTHONPATH
$env:PYTHONPATH = if ($previousPythonPath) { "$pythonPathValue;$previousPythonPath" } else { $pythonPathValue }
try {
  $registry = Start-Process -FilePath $PythonExe -ArgumentList @(
    "`"$registryScript`"",
    "--listen", "$ServerHost`:$RegistryPort",
    "--ledger-path", "`"$SharedLedgerPath`""
  ) -RedirectStandardOutput $registryOut -RedirectStandardError $registryErr -PassThru
} finally {
  $env:PYTHONPATH = $previousPythonPath
}

$state = [ordered]@{
  startedAt = (Get-Date).ToString("o")
  backendManaged = [bool]$backend
  backend = if ($backend) { $backend.Id } else { $null }
  fullNode = $fullNode.Id
  registry = $registry.Id
  sharedLedgerPath = $SharedLedgerPath
  logs = [ordered]@{
    fullNodeOut = $fullNodeOut
    fullNodeErr = $fullNodeErr
    registryOut = $registryOut
    registryErr = $registryErr
  }
  urls = [ordered]@{
    backendHealth = $backendHealthUrl
    fullNodeHealth = "http://$ServerHost`:$FullNodePort/health"
    registryHealth = "http://$ServerHost`:$RegistryPort/health"
    registryNodes = "http://$ServerHost`:$RegistryPort/nodes"
  }
}

$state | ConvertTo-Json -Depth 5 | Set-Content -Path $stackStatePath -Encoding UTF8

$backendOk = Wait-HttpReady -Url $state.urls.backendHealth
$fullNodeOk = Wait-HttpReady -Url $state.urls.fullNodeHealth
$registryOk = Wait-HttpReady -Url $state.urls.registryHealth

Write-Host ""
Write-Host "Origin node stack started"
Write-Host "  Backend  PID: $(if ($backend) { $backend.Id } else { 'reused-existing' })"
Write-Host "  FullNode PID: $($fullNode.Id)"
Write-Host "  Registry PID: $($registry.Id)"
Write-Host "  PID file: $stackStatePath"
Write-Host "  Logs:"
Write-Host "    $fullNodeErr"
Write-Host "    $registryErr"
Write-Host ""
Write-Host "Health"
Write-Host "  $($state.urls.backendHealth)  => $backendOk"
Write-Host "  $($state.urls.fullNodeHealth) => $fullNodeOk"
Write-Host "  $($state.urls.registryHealth) => $registryOk"

if (-not $fullNodeOk -and (Test-Path $fullNodeErr)) {
  Write-Host ""
  Write-Host "Full node stderr (last 20 lines):"
  Get-Content $fullNodeErr -Tail 20 | ForEach-Object { Write-Host "  $_" }
}
if (-not $registryOk -and (Test-Path $registryErr)) {
  Write-Host ""
  Write-Host "Registry stderr (last 20 lines):"
  Get-Content $registryErr -Tail 20 | ForEach-Object { Write-Host "  $_" }
}
Write-Host ""
Write-Host "Inspect"
Write-Host "  $($state.urls.registryNodes)"
Write-Host ""
Write-Host "Stop stack"
Write-Host "  pwsh -File \"$PSCommandPath\" -Stop"
#pragma warning restore PSAvoidAssignmentToAutomaticVariable
