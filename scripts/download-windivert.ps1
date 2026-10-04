# Download and extract official signed WinDivert binaries for Windows x64
param(
    [string]$Version = "2.2.2",
    [string]$DestinationDir = "bin"
)

$ErrorActionPreference = "Stop"

$url = "https://github.com/basil00/WinDivert/releases/download/v$Version/WinDivert-$Version-A.zip"
$zipFile = Join-Path $PSScriptRoot "windivert-temp.zip"
$extractDir = Join-Path $PSScriptRoot "windivert-temp"

Write-Host "Downloading WinDivert v$Version from $url..." -ForegroundColor Cyan
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
Invoke-WebRequest -Uri $url -OutFile $zipFile

Write-Host "Extracting archive..." -ForegroundColor Cyan
Expand-Archive -Path $zipFile -DestinationPath $extractDir -Force

$targetDir = Join-Path (Split-Path $PSScriptRoot -Parent) $DestinationDir
if (-not (Test-Path $targetDir)) {
    New-Item -ItemType Directory -Path $targetDir -Force | Out-Null
}

$x64Source = Join-Path $extractDir "WinDivert-$Version-A\x64"
Write-Host "Copying x64 binaries to $targetDir..." -ForegroundColor Cyan

Copy-Item (Join-Path $x64Source "WinDivert.dll") (Join-Path $targetDir "WinDivert.dll") -Force
Copy-Item (Join-Path $x64Source "WinDivert64.sys") (Join-Path $targetDir "WinDivert64.sys") -Force

# Clean up temporary files
Remove-Item -Recurse -Force $zipFile, $extractDir

Write-Host "WinDivert binaries installed successfully in $targetDir" -ForegroundColor Green
Get-ChildItem $targetDir | Format-Table Name, Length, LastWriteTime
