<#
 Send a signed test payload to LODESTAR's webhook ingestion endpoint (Windows PowerShell 5.1+).

   powershell -ExecutionPolicy Bypass -File scripts\send-test-webhook.ps1 -Domain waf -File samples\webhooks\waf_findings.json
   powershell -ExecutionPolicy Bypass -File scripts\send-test-webhook.ps1 -Domain fraud -File my.json -Url https://lodestar.your-org.example

 The HMAC secret is read from $env:LODESTAR_WEBHOOK_SECRET or, if unset, from .env in the repository root.
 Use the same code in your SOAR / Logic App / script to push real findings.
#>
param(
  [Parameter(Mandatory = $true)][string]$Domain,
  [Parameter(Mandatory = $true)][string]$File,
  [string]$Url = "http://127.0.0.1:8080"
)
$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot ".."
$secret = $env:LODESTAR_WEBHOOK_SECRET
if (-not $secret -and (Test-Path (Join-Path $root ".env"))) {
  $line = Get-Content (Join-Path $root ".env") | Where-Object { $_ -match '^\s*LODESTAR_WEBHOOK_SECRET\s*=' } | Select-Object -First 1
  if ($line) { $secret = ($line -split '=', 2)[1].Trim().Trim('"') }
}
if (-not $secret) { throw "Set LODESTAR_WEBHOOK_SECRET (environment or .env) first." }

$path = Resolve-Path $File
$bytes = [System.IO.File]::ReadAllBytes($path)
$hmac = New-Object System.Security.Cryptography.HMACSHA256 (,[Text.Encoding]::UTF8.GetBytes($secret))
$sig = -join ($hmac.ComputeHash($bytes) | ForEach-Object { $_.ToString("x2") })

$resp = Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$($Url.TrimEnd('/'))/api/ingest/$Domain" -Body $bytes `
  -ContentType "application/json" -Headers @{ "X-Lodestar-Signature" = "sha256=$sig" }
Write-Host "HTTP $($resp.StatusCode): $($resp.Content)" -ForegroundColor Green
Write-Host "Now run:  python -m lodestar test-connector $Domain" -ForegroundColor Cyan
