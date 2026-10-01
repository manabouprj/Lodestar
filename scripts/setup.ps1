<#
 LODESTAR - Windows 11 / PowerShell setup and demo
 Usage:  powershell -ExecutionPolicy Bypass -File scripts\setup.ps1 [-Serve]
#>
param([switch]$Serve)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (Get-Command py -ErrorAction SilentlyContinue) { $py = "py -3" } else { $py = "python" }   # works on Windows PowerShell 5.1 and PowerShell 7
Write-Host "==> Creating virtual environment (.venv)" -ForegroundColor Cyan
Invoke-Expression "$py -m venv .venv"
& .\.venv\Scripts\python.exe -m pip install --upgrade pip | Out-Null
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.txt

Write-Host "==> Running tests" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe -m pytest -q
if ($LASTEXITCODE -ne 0) { throw "Tests failed" }

Write-Host "==> Generating demo data, running agents, writing reports and dashboard" -ForegroundColor Cyan
& .\.venv\Scripts\python.exe -m lodestar demo
Write-Host "Dashboard file: dist\lodestar-dashboard.html   Reports: reports\" -ForegroundColor Green

if (-not (Test-Path .env)) { Copy-Item .env.example .env; Write-Host "Created .env from template - edit before live mode." }
if ($Serve) { & .\.venv\Scripts\python.exe -m lodestar serve }
