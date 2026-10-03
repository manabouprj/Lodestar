# Push LODESTAR to GitHub (Windows)

The download is a complete Git repository with the commit history and version tags already
inside. You only need to unpack it, point it at a GitHub repository and push.

* **First time?** Follow steps 1 to 5.
* **Already pushed an earlier version?** Go to [Update an existing GitHub repository](#update-an-existing-github-repository).
* **Ready to connect real tools?** After pushing, follow [AGENT_SETUP.md](AGENT_SETUP.md).
* **Want the dashboard visible on GitHub?** Go to [Show the dashboard on GitHub](#show-the-dashboard-on-github).

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
$zip = "$env:USERPROFILE\Downloads\lodestar-v2.1.0.zip"   # the version you downloaded
Unblock-File $zip                                   # removes the "downloaded from internet" flag so scripts run
New-Item -ItemType Directory -Force C:\Projects | Out-Null
Expand-Archive $zip -DestinationPath C:\Projects -Force
cd C:\Projects\lodestar
git log --oneline                                   # you should see the LODESTAR v1.0.0 ... v2.1.0 commits
```

Use a short path outside OneDrive (for example `C:\Projects`) to avoid sync conflicts and
long-path errors.

## 3a. Push with the helper script (recommended)

```powershell
powershell -ExecutionPolicy Bypass -File scripts\push-to-github.ps1 -Owner manabouprj -Repo lodestar
```

With GitHub CLI installed, the script signs you in through the browser, creates a **private**
repository `manabouprj/Lodestar`, and pushes `main` plus tags. Add `-Public` for a public
repository.

## 3b. Push manually

1. On github.com: **New repository** → name `lodestar` → **Private** → leave *Add README*,
   *.gitignore* and *licence* **unticked** (the repo must be empty) → **Create repository**.
2. In PowerShell, from `C:\Projects\lodestar`:

```powershell
git config user.name  "Peter Akinyele"
git config user.email "your-github-email@example.com"     # or your GitHub noreply address
git branch -M main
git remote add origin https://github.com/manabouprj/Lodestar.git
git push -u origin main
git push origin --tags
```

The first push opens a browser window (Git Credential Manager) to sign in to GitHub. No token
needs to be pasted.

## 4. Check the result

* **Code** tab: README renders with the architecture diagram.
* **Actions** tab: the `ci` workflow runs lint, the full test suite (including the SIEM contract tests),
  `validate`, `doctor`, the demo build and a Docker build/smoke test. Download the `demo-dashboard-and-reports` artifact from the run.
* **Releases**: optionally create a release from the latest tag (for example `v2.1.0`) and attach `samples/lodestar-dashboard.html`.

## Update an existing GitHub repository

If you already pushed an earlier version, the new download contains the same history plus the
new commit, so the push is a simple fast-forward.

**Option A - keep your existing folder** (recommended if you have local changes):

```powershell
cd C:\Projects\lodestar                             # your existing clone
git status                                         # commit or stash anything you changed first
Expand-Archive "$env:USERPROFILE\Downloads\lodestar-v2.1.0.zip" -DestinationPath C:\Temp\lodestar-new -Force
git fetch C:\Temp\lodestar-new\lodestar main --tags     # bring in the new commit from the unpacked copy
git merge --ff-only FETCH_HEAD
git push origin main --tags
```

**Option B - replace the folder:**

```powershell
Rename-Item C:\Projects\lodestar lodestar-old
Expand-Archive "$env:USERPROFILE\Downloads\lodestar-v2.1.0.zip" -DestinationPath C:\Projects -Force
cd C:\Projects\lodestar
git remote add origin https://github.com/manabouprj/Lodestar.git
git push origin main --tags
```

**If `main` is protected** (a ruleset that requires pull requests: the push fails with
`GH013: Repository rule violations ... Changes must be made through a pull request`), push the new
commit to a branch and merge it through a pull request, so CI runs before it reaches `main`:

```powershell
git push origin HEAD:release/v2.1.0
Start-Process "https://github.com/manabouprj/Lodestar/compare/main...release/v2.1.0?expand=1"
# create the pull request, wait for the checks, merge with "Create a merge commit", then:
git checkout main; git pull origin main
git push origin v2.1.0
git push origin --delete release/v2.1.0
```

If Git says `rejected (non-fast-forward)`, someone changed GitHub directly (for example by editing
the README in the browser). Run `git pull --rebase origin main`, then push again.

## Show the dashboard on GitHub

There are two ways, and you can use both.

**1. Screenshots in the README (works on every plan, private or public).**
The README already embeds the images in `docs/images/`. They render as soon as you push. To
refresh them after changing the dashboard:

```powershell
pip install playwright pillow
python -m playwright install chromium
python -m lodestar demo
python scripts\readme_screenshots.py
git add docs/images
git commit -m "Refresh dashboard screenshots"
git push
```

**2. A live, clickable demo on GitHub Pages.**
The workflow `.github/workflows/pages.yml` builds the demo (fictional data only) and publishes
it with the sample reports.

1. GitHub → your repository → **Settings → Pages**.
2. Under *Build and deployment*, set **Source: GitHub Actions**.
3. **Actions** tab → **demo-dashboard** → **Run workflow** (it also runs automatically on every push
   to `main` that changes the code or config).
4. When the run finishes, the dashboard is at `https://manabouprj.github.io/Lodestar/` and the
   reports are under `/reports/`. The README's *Open the live demo dashboard* link already points
   there. Edit that link if your repository or user name differs.

Pages on a **private** repository needs GitHub Pro, Team or Enterprise. On the free plan, either
keep the repository private and rely on the screenshots (plus the downloadable
`samples/lodestar-dashboard.html`), or publish only the demo from a separate public repository.
The Pages workflow always runs `lodestar demo`, so real findings can never be published by it.
Never change it to a live configuration.

**3. Attach the dashboard to a release (optional).** **Releases → Draft a new release → tag
`v1.2.1`**, attach `samples/lodestar-dashboard.html` and the quarterly report. Viewers download
the file and open it in any browser.

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

Release: `git tag -a v2.1.0 -m "LODESTAR v2.1.0"` then `git push origin --tags`.

## Troubleshooting

| Message | Fix |
|---|---|
| `fatal: detected dubious ownership in repository` | `git config --global --add safe.directory C:/Projects/lodestar` (the script does this) |
| `running scripts is disabled on this system` | Use `powershell -ExecutionPolicy Bypass -File ...` or run `Unblock-File` on the zip before extracting |
| `! [rejected] main -> main (fetch first)` | The GitHub repo was created with a README. Either recreate it empty, or `git pull --rebase origin main` then push |
| `LF will be replaced by CRLF` warnings | Harmless; `.gitattributes` keeps LF in the repository |
| `Permission denied (publickey)` | You used an SSH URL. Use the HTTPS URL above, or set up an SSH key |
| README images don't show | Check the paths are `docs/images/...` (case-sensitive on GitHub) and that the PNGs were committed (`git ls-files docs/images`) |
| Pages URL shows 404 | Settings → Pages source must be **GitHub Actions**; wait for the *demo-dashboard* run to finish; private repos need a paid plan |
| Push opens no browser | `git credential-manager configure` then retry, or install GitHub CLI and run `gh auth login` |
