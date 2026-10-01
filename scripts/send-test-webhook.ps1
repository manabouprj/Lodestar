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
  [string]$Url = "http://127.0.0.1:8080",
  [string]$Org = ""          # multi-tenant deployments: the organisation key (uses LODESTAR_WEBHOOK_SECRET_<ORG> if set)
)
$ErrorActionPreference = "Stop"
$root = Join-Path $PSScriptRoot ".."
$names = @()
if ($Org) { $names += "LODESTAR_WEBHOOK_SECRET_" + ($Org.ToUpper() -replace '-', '_') }
$names += "LODESTAR_WEBHOOK_SECRET"
$secret = $null
foreach ($n in $names) {
  $v = [Environment]::GetEnvironmentVariable($n)
  if (-not $v -and (Test-Path (Join-Path $root ".env"))) {
    $line = Get-Content (Join-Path $root ".env") | Where-Object { $_ -match ('^\s*' + $n + '\s*=') } | Select-Object -First 1
    if ($line) { $v = ($line -split '=', 2)[1].Trim().Trim('"') }
  }
  if ($v) { $secret = $v; break }
}
if (-not $secret) { throw "Set LODESTAR_WEBHOOK_SECRET (environment or .env) first." }

$path = Resolve-Path $File
$bytes = [System.IO.File]::ReadAllBytes($path)
# replay protection: sign "<unix seconds>.<body>" and send the timestamp header (accepted for 5 minutes)
$ts = [string][DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
$signed = [Text.Encoding]::UTF8.GetBytes("$ts.") + $bytes
$hmac = New-Object System.Security.Cryptography.HMACSHA256 (,[Text.Encoding]::UTF8.GetBytes($secret))
$sig = -join ($hmac.ComputeHash([byte[]]$signed) | ForEach-Object { $_.ToString("x2") })

$target = "$($Url.TrimEnd('/'))/api/ingest/$Domain" + $(if ($Org) { "?org=$Org" } else { "" })
$resp = Invoke-WebRequest -UseBasicParsing -Method Post -Uri $target -Body $bytes `
  -ContentType "application/json" -Headers @{ "X-Lodestar-Signature" = "sha256=$sig"; "X-Lodestar-Timestamp" = $ts }
Write-Host "HTTP $($resp.StatusCode): $($resp.Content)" -ForegroundColor Green
Write-Host "Now run:  python -m lodestar test-connector $Domain" -ForegroundColor Cyan
