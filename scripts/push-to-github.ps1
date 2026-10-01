<#
 Push LODESTAR to GitHub from Windows.

 Usage (from the repository folder):
   powershell -ExecutionPolicy Bypass -File scripts\push-to-github.ps1 -Owner manabouprj -Repo Lodestar
   powershell -ExecutionPolicy Bypass -File scripts\push-to-github.ps1 -Owner manabouprj -Repo Lodestar -Public

 Uses GitHub CLI (gh) when installed - it creates the repository for you.
 Without gh, create an EMPTY repository on github.com first (no README / licence / .gitignore).
#>
param(
  [Parameter(Mandatory = $true)][string]$Owner,
  [string]$Repo = "Lodestar",
  [switch]$Public
)
$ErrorActionPreference = "Stop"
Set-Location (Join-Path $PSScriptRoot "..")

if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
  throw "Git is not installed. Run: winget install --id Git.Git -e   then open a new PowerShell window."
}

# Repository folders unpacked from a zip can trip Git's ownership check
git config --global --add safe.directory ((Get-Location).Path -replace '\\','/') | Out-Null

if (-not (git config user.name))  { git config user.name  (Read-Host "Your name for commits") }
if (-not (git config user.email)) { git config user.email (Read-Host "Your e-mail for commits (GitHub noreply address is fine)") }

git branch -M main
$status = git status --porcelain
if ($status) {
  Write-Host "Committing local changes..." -ForegroundColor Cyan
  git add -A
  git commit -m "Local changes before first push"
}

$url = "https://github.com/$Owner/$Repo.git"
$visibility = if ($Public) { "--public" } else { "--private" }

if (Get-Command gh -ErrorAction SilentlyContinue) {
  gh auth status 2>$null; if ($LASTEXITCODE -ne 0) { gh auth login --web --git-protocol https }
  $exists = $true; gh repo view "$Owner/$Repo" 2>$null | Out-Null; if ($LASTEXITCODE -ne 0) { $exists = $false }
  if (-not $exists) {
    Write-Host "Creating $Owner/$Repo ($visibility) on GitHub..." -ForegroundColor Cyan
    gh repo create "$Owner/$Repo" $visibility --description "LODESTAR - security posture prioritisation agents" --source . --remote origin
  }
}

if (-not (git remote | Select-String -SimpleMatch "origin")) { git remote add origin $url }
else { git remote set-url origin $url }

Write-Host "Pushing main and tags to $url ..." -ForegroundColor Cyan
git push -u origin main
git push origin --tags
Write-Host "Done. Open https://github.com/$Owner/$Repo/actions to watch the CI run." -ForegroundColor Green
