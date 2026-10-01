# Push LODESTAR to GitHub (Windows)

The download is a complete Git repository: the commit history and the `v1.2.0` tag are already
inside. You only need to unpack it, point it at a GitHub repository and push.

## 1. One-time tools

Open **PowerShell** (not as administrator) and install:

```powershell
winget install --id Git.Git -e                # Git for Windows (includes Git Credential Manager)
winget install --id GitHub.cli -e             # optional: creates the repo for you
winget install --id Python.Python.3.12 -e     # to run LODESTAR locally
```

Close and reopen PowerShell so the new commands are on your PATH. Check with `git --version`.

## 2. Unpack the download

```powershell
$zip = "$env:USERPROFILE\Downloads\lodestar-v1.2.0.zip"
Unblock-File $zip                                   # removes the "downloaded from internet" flag so scripts run
New-Item -ItemType Directory -Force C:\Projects | Out-Null
Expand-Archive $zip -DestinationPath C:\Projects -Force
cd C:\Projects\lodestar
git log --oneline                                   # you should see the LODESTAR v1.0.0 / v1.1.0 / v1.2.0 commits
```

Use a short path outside OneDrive (for example `C:\Projects`) to avoid sync conflicts and
long-path errors.

## 3a. Push with the helper script (recommended)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\push-to-github.ps1 -Owner manabouprj -Repo lodestar
```

With GitHub CLI installed, the script signs you in through the browser, creates a **private**
repository `manabouprj/lodestar`, and pushes `main` plus tags. Add `-Public` for a public
repository.

## 3b. Push manually

1. On github.com: **New repository** → name `lodestar` → **Private** → leave *Add README*,
   *.gitignore* and *licence* **unticked** (the repo must be empty) → **Create repository**.
2. In PowerShell, from `C:\Projects\lodestar`:

```powershell
git config user.name  "Peter Akinyele"
git config user.email "your-github-email@example.com"     # or your GitHub noreply address
git branch -M main
git remote add origin https://github.com/manabouprj/lodestar.git
git push -u origin main
git push origin --tags
```

The first push opens a browser window (Git Credential Manager) to sign in to GitHub. No token
needs to be pasted.

## 4. Check the result

* **Code** tab: README renders with the architecture diagram.
* **Actions** tab: the `ci` workflow runs lint, 47 tests, `validate`, the demo build and a Docker
  build/smoke test. Download the `demo-dashboard-and-reports` artifact from the run.
* **Releases**: optionally create a release from tag `v1.2.0` and attach `samples/lodestar-dashboard.html`.

## 5. Recommended repository settings

| Setting | Where | Why |
|---|---|---|
| Keep the repository **private** | Settings → General | It describes your security architecture |
| Branch protection on `main` (PR + passing `ci`) | Settings → Branches | No untested changes reach production |
| Secret scanning + push protection | Settings → Code security | Blocks accidental API keys (`.env` is already git-ignored) |
| Dependabot alerts and security updates | Settings → Code security | Python and Docker base-image updates |
| Add a licence | Add file → `LICENSE` | Choose before sharing outside your organisation |

Never commit `.env`. Secrets belong in environment variables, a secret store, or GitHub Actions
secrets.

## 6. Everyday workflow

```powershell
git checkout -b feature/new-connector
# ...edit...
python -m pytest -q
git add -A
git commit -m "Add Bugcrowd adapter"
git push -u origin feature/new-connector        # then open a pull request on GitHub
```

Release: `git tag v1.3.0` then `git push origin --tags`.

## Troubleshooting

| Message | Fix |
|---|---|
| `fatal: detected dubious ownership in repository` | `git config --global --add safe.directory C:/Projects/lodestar` (the script does this) |
| `running scripts is disabled on this system` | Use `powershell -ExecutionPolicy Bypass -File ...` or run `Unblock-File` on the zip before extracting |
| `! [rejected] main -> main (fetch first)` | The GitHub repo was created with a README. Either recreate it empty, or `git pull --rebase origin main` then push |
| `LF will be replaced by CRLF` warnings | Harmless; `.gitattributes` keeps LF in the repository |
| `Permission denied (publickey)` | You used an SSH URL. Use the HTTPS URL above, or set up an SSH key |
| Push opens no browser | `git credential-manager configure` then retry, or install GitHub CLI and run `gh auth login` |
