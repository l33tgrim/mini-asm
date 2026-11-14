# Pull the latest version from GitHub and rebuild the container.
# Run from the mini-asm folder:  .\update.ps1
$ErrorActionPreference = 'Stop'
Set-Location $PSScriptRoot
git pull --ff-only

# First run: ask for the sign-in details and keep them in .env (never committed).
if (-not (Test-Path .env)) {
    Write-Host "No .env found. Choose the username and password for the sign-in page."
    $user = Read-Host "Username"
    $secure = Read-Host "Password" -AsSecureString
    $pass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure))
    if (-not $user -or -not $pass) { throw "Username and password cannot be empty." }
    "ASM_USERNAME=$user`nASM_PASSWORD=$pass`n" | Set-Content -NoNewline -Encoding ascii .env
    Write-Host "Saved to .env"
}

docker compose up -d --build --pull always
docker image prune -f | Out-Null
docker compose ps
Write-Host "Mini ASM is running on http://localhost:3001"
