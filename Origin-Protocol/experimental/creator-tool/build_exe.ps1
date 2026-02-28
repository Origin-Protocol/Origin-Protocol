param(
  [string]$PythonExe = "python"
)

$ErrorActionPreference = "Stop"
Set-StrictMode -Version Latest

$projectRoot = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $projectRoot

& $PythonExe -m pip install -r requirements.txt

& $PythonExe -m PyInstaller `
  --noconfirm `
  --clean `
  --windowed `
  --name "OriginCreatorTool" `
  app.py

Write-Host "EXE ready at: $projectRoot\dist\OriginCreatorTool\OriginCreatorTool.exe"
