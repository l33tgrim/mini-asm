# Pull the latest version from GitHub and rebuild the container.
# Run from the mini-asm folder:  .\update.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
git pull --ff-only
docker compose up -d --build --pull always
docker image prune -f | Out-Null
docker compose ps
Write-Host "Mini ASM is running on http://localhost:3001"
