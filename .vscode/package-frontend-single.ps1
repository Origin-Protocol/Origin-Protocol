param(
  [string]$ProjectPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-FrontendProjectPath {
  param(
    [Parameter(Mandatory = $true)]
    [string]$WorkspaceRoot
  )

  $candidates = @(
    (Join-Path $WorkspaceRoot 'Origin-Protocol.worktrees/copilot-worktree-2026-02-24T12-31-44/experimental/social-media'),
    (Join-Path $WorkspaceRoot 'Origin-Protocol/experimental/social-media'),
    (Join-Path $WorkspaceRoot 'experimental/social-media')
  )

  foreach ($candidate in $candidates) {
    $pkgPath = Join-Path $candidate 'package.json'
    if (-not (Test-Path -LiteralPath $pkgPath)) {
      continue
    }

    try {
      $pkg = Get-Content -LiteralPath $pkgPath -Raw | ConvertFrom-Json
      if ($null -ne $pkg.scripts -and $null -ne $pkg.scripts.build) {
        return $candidate
      }
    } catch {
      continue
    }
  }

  throw "No social-media frontend project with package.json + build script was found under: $WorkspaceRoot"
}

$workspaceRoot = Split-Path -Parent $PSScriptRoot
$project = if ($ProjectPath) {
  $resolved = [System.IO.Path]::GetFullPath($ProjectPath)
  $pkgPath = Join-Path $resolved 'package.json'
  if (-not (Test-Path -LiteralPath $pkgPath)) {
    throw "Provided ProjectPath does not contain package.json: $resolved"
  }
  $pkg = Get-Content -LiteralPath $pkgPath -Raw | ConvertFrom-Json
  if ($null -eq $pkg.scripts -or $null -eq $pkg.scripts.build) {
    throw "Provided ProjectPath package.json has no build script: $resolved"
  }
  $resolved
} else {
  Resolve-FrontendProjectPath -WorkspaceRoot $workspaceRoot
}

Write-Host "Using frontend project: $project"

npm --prefix "$project" run build

$deploy = Join-Path $project 'deploy'
if (-not (Test-Path $deploy)) {
  New-Item -ItemType Directory -Path $deploy | Out-Null
}
Get-ChildItem $deploy -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force

Copy-Item (Join-Path $project 'dist/*') $deploy -Recurse -Force

$headers = Join-Path $project '_headers'
$redirects = Join-Path $project '_redirects'
if (Test-Path $headers) {
  Copy-Item $headers (Join-Path $deploy '_headers') -Force
}
if (Test-Path $redirects) {
  Copy-Item $redirects (Join-Path $deploy '_redirects') -Force
}

$zip = Join-Path $deploy 'origin-social-frontend-upload.zip'
if (Test-Path $zip) {
  Remove-Item $zip -Force
}
Compress-Archive -Path (Join-Path $deploy '*') -DestinationPath $zip -CompressionLevel Optimal -Force

Get-Item $zip | Select-Object Name, Length, LastWriteTime | Format-Table -AutoSize
