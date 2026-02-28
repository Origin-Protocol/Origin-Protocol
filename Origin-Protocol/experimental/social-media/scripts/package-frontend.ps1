Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Set-Location 'c:/Users/Ommi/Desktop/ORIGIN Protocol/Origin-Protocol/experimental/social-media'

npm run build
if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }

if (-not (Test-Path 'deploy')) { New-Item -ItemType Directory -Path 'deploy' | Out-Null }
Get-ChildItem 'deploy' -Force -ErrorAction SilentlyContinue | Remove-Item -Recurse -Force
Copy-Item 'dist/*' 'deploy' -Recurse -Force
if (Test-Path '_headers') { Copy-Item '_headers' 'deploy/_headers' -Force }
if (Test-Path '_redirects') { Copy-Item '_redirects' 'deploy/_redirects' -Force }
if (Test-Path 'deploy/origin-social-frontend-upload.zip') { Remove-Item 'deploy/origin-social-frontend-upload.zip' -Force }
Compress-Archive -Path 'deploy/*' -DestinationPath 'deploy/origin-social-frontend-upload.zip' -CompressionLevel Optimal -Force

Get-Item 'deploy/origin-social-frontend-upload.zip' |
  Select-Object Name, Length, LastWriteTime |
  ConvertTo-Json -Compress
