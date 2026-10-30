# Setup Guide – Six New Workflows

This package adds six workflows to the automation repository. They follow the same privacy rules as the existing ones, plus a few stricter ones:

| # | Workflow file | Script | Trigger | Report (e-mail attachments) |
|---|---|---|---|---|
| 1 | `malware-scan.yml` | `malware_scan.py` | Manual (inbox / URL / drive) + nightly incremental Workspace scan + weekly full scan | HTML report, findings CSV, run log |
| 2 | `code-testing-server.yml` | `code_quality_scan.py` | 03:15 and 15:15 UTC (incremental), Sunday 01:00 UTC (full), manual | HTML report, findings CSV, ZAP HTML reports (zipped), run log |
| 3 | `load-test.yml` | `load_test.py` | Manual, with parameters | HTML summary, k6 dashboard HTML with charts, raw JSON, run log |
| 4 | `lighthouse-audit.yml` | `lighthouse_audit.py` | Monday 05:30 UTC + manual | HTML summary, scores CSV, one full Lighthouse report per URL and device (zipped, split across several e-mails if needed) |
| 5 | `server-backup.yml` | `server_backup.py` | Daily 02:30 UTC + manual | HTML report with the Google Drive link, size, SHA-256, upload check |
| 6 | `release-factory.yml` | `release_factory.py` | Manual (sealed payload) | HTML report with the release link, steps, package checksum |

Shared files: `sec_common.py` (Drive, reports, mail splitting, sealed payloads), `.github/actions/install-scanners/action.yml` (ClamAV, Trivy and Gitleaks, all checksum-verified), and `tools/seal_dispatch.py` (a local helper that you never run in CI).

Your existing `common.py` is reused unchanged for sending e-mails.

---

## 1. Privacy model (how “no metadata leaks” is enforced)

| Leak path in a public repository | Countermeasure used |
|---|---|
| Console output of scripts and tools | Every command runs with `> /dev/null 2>&1`. Scripts never print anything. |
| **Step `env:` header in the log** (GitHub shows every env value in plain text unless it is a secret) | Only `secrets.*` values or harmless constants are placed in `env:`. Sensitive dispatch parameters are **sealed** (AES-256-GCM) or passed as **aliases**. |
| `workflow_dispatch` inputs (shown in the log header, readable by anyone while the run exists) | Release Factory and the URL scan accept only a sealed token. The load test accepts only an alias such as `t1`; the real URL is in a secret. All other inputs are numbers or booleans. |
| Matrix job names | Matrix contains only shard numbers 0–5. Each shard works out its own repositories internally. |
| Artifacts / step summaries | None. Results between jobs are exchanged through a private Google Drive staging folder and deleted afterwards. |
| Run history | Each workflow deletes its own run at the end. Your hourly `cleanup-history.yml` removes everything else. |
| Re-use of an old sealed token seen in a log | Tokens expire after 1 hour (`PAYLOAD_MAX_AGE_SECONDS`). |
| Secrets in reports | Gitleaks runs with `--redact`. All script logs pass through the `Redactor`. |

What GitHub always shows publicly (this cannot be avoided): the workflow name, start time, duration, success or failure, and the account that triggered the run. That account is your own, and it is already visible in the repository URL.

---

## 2. New secrets

Add these under **Settings → Secrets and variables → Actions → New repository secret**. Secrets you already have are reused: `SRC_GH_TOKEN`, `SRC_GH_OWNER`, `SRC_GH_OWNER_TYPE`, `GDRIVE_SA_JSON`, `REPORT_TO`, `SMTP_*`.

| Secret | Needed by | Required | Content |
|---|---|---|---|
| `GDRIVE_FOLDER_ID` | 1, 2, 5 | yes* | ID of a folder **inside a Shared Drive** (see note below). *Workflows fall back to `vars.GDRIVE_FOLDER_ID`, but a secret is recommended (see section 9). |
| `DISPATCH_KEY` | 1 (URL mode), 6 | yes | Random 32-byte key in base64. Create it with `python tools/seal_dispatch.py --new-key` |
| `SCAN_INBOX_FOLDER_ID` | 1 | yes | Drive folder where you drop files that should be scanned |
| `SCAN_CLEAN_FOLDER_ID` | 1 | recommended | Clean files are moved here automatically |
| `SCAN_QUARANTINE_FOLDER_ID` | 1 | recommended | Infected or suspicious files are moved here |
| `GWS_ADMIN_EMAIL` | 1 (drive mode) | for org scan | A Workspace super-admin address used for impersonation |
| `GWS_SCANNER_SA_JSON` | 1 (drive mode) | optional | A separate service account with domain-wide delegation (recommended – see 3.2). Falls back to `GDRIVE_SA_JSON`. |
| `DRIVE_SKIP_USERS` | 1 | optional | Comma-separated mailboxes to skip |
| `SCAN_REPO_LIST` | 2 | optional | One repository per line (`name` or `owner/name`). Empty or `*` means all repositories. |
| `SCAN_REPO_EXCLUDE` | 2 | optional | Repositories to skip |
| `ZAP_TARGETS` | 2 | optional | One URL per line, **your own sites only** |
| `LOADTEST_TARGETS` | 3 | yes | JSON mapping of aliases to targets (see 3.4) |
| `LOADTEST_BYPASS_HEADER` | 3 | optional | `Header-Name: random-value` that lets your CDN or WAF allow the test traffic |
| `LIGHTHOUSE_URLS` | 4 | yes | One URL per line |
| `VPS_HOST`, `VPS_PORT`, `VPS_USER` | 5 | yes (port defaults to 22, user to root) | SSH target |
| `VPS_SSH_KEY` | 5 | yes | Private key (ed25519), dedicated to backups |
| `VPS_KNOWN_HOSTS` | 5 | yes | Output of `ssh-keyscan -p PORT HOST` (pins the server identity) |
| `BACKUP_ENC_PASSPHRASE` | 5 | yes | Long random passphrase. **Keep an offline copy** – without it the backups cannot be restored. |
| `VPS_BACKUP_FOLDER_ID` | 5 | optional | Separate Shared Drive folder for server backups (default: `GDRIVE_FOLDER_ID`) |
| `VPS_BACKUP_EXCLUDES` | 5 | optional | Extra paths to exclude, one per line (e.g. `/var/log/journal`) |
| `RELEASE_GIT_NAME`, `RELEASE_GIT_EMAIL` | 6 | optional | Tagger identity (default: neutral “Release Factory”) |

**Shared Drive note:** service accounts have no storage quota of their own. Uploads to a normal “My Drive” folder fail. All folders above must be inside a **Shared Drive** where the service account is a member with the **Content manager** role.

Quick way to set secrets with GitHub CLI (Windows PowerShell or bash):

```bash
gh secret set DISPATCH_KEY --body "<key from --new-key>"
gh secret set VPS_SSH_KEY < backup_ed25519
gh secret set LOADTEST_TARGETS < loadtest_targets.json
gh secret set SCAN_REPO_LIST < repos.txt
```

Add to `requirements.txt` (the workflows also install these explicitly, so this is optional):

```
cryptography
oletools
```

---

## 3. Per-workflow setup

### 3.1 Malware Scanner – the “upload” workaround

GitHub Actions has **no file-upload input**. `workflow_dispatch` only supports text, number, boolean, choice and environment inputs. Anything typed into an input is visible in the public log. Use one of these two private channels instead:

**A) Drive inbox (recommended, zero metadata in the run):**
1. In the Shared Drive, create three folders: `Scan-Inbox`, `Scan-Clean` and `Scan-Quarantine`. Copy their IDs (the last part of the folder URL) into the three `SCAN_*_FOLDER_ID` secrets.
2. Drop the third-party ZIP into `Scan-Inbox`. Only you and the service account can see it.
3. Run **Malware-Scan → mode `inbox`** with an empty payload.
4. Result: clean files are moved to `Scan-Clean`. Infected or suspicious files go to `Scan-Quarantine`. You get the report by e-mail.

**B) Sealed URL** (e.g. a GitHub “Download ZIP” link):
```bash
python tools/seal_dispatch.py --workflow malware-scan.yml --url "https://github.com/x/y/archive/refs/heads/main.zip" --store-if-clean
```
Only an unreadable token appears in the run. With `--store-if-clean`, the file is uploaded to `Scan-Clean` if it passes.

**What is checked:**
- ClamAV signatures, including inside archives, PDFs and Office files.
- Safe extraction that blocks zip-slip (files trying to escape the target folder), zip bombs and links, and goes up to 3 levels of nested archives.
- Office macros (oletools).
- Disguised executables, for example `invoice.pdf.exe` or file names using the right-to-left character trick.
- Dangerous code patterns: `curl | bash`, eval of decoded data, web shells, reverse shells, PowerShell download-and-run, crypto miners, exfiltration webhooks, persistence tricks, obfuscated blobs, and npm `postinstall` / `setup.py` side effects.
- Trivy for vulnerable dependencies and Gitleaks for embedded secrets.

**Verdicts:** `INFECTED` means a known signature was found. `SUSPICIOUS` means it needs manual review. `CLEAN` means nothing was found. If ClamAV could not run, the verdict is never `CLEAN`.

### 3.2 Malware Scanner – whole Workspace storage (drive mode)

This needs **domain-wide delegation**. It is a powerful permission, so give it to a separate, read-only service account (`GWS_SCANNER_SA_JSON`) rather than to your backup service account.

1. In Google Cloud (the same project is fine): create a service account, create a JSON key, and enable the **Google Drive API** and the **Admin SDK API**.
2. In the Admin console, go to **Security → Access and data control → API controls → Domain-wide delegation → Add new**. Enter the service account’s **Client ID** and these scopes:
   `https://www.googleapis.com/auth/drive.readonly,https://www.googleapis.com/auth/admin.directory.user.readonly`
3. Set `GWS_ADMIN_EMAIL` to a super-admin address. It is used to list users and the Shared Drives that this admin is a member of.

**How it runs efficiently:**
- **Incremental:** each user and Shared Drive keeps a “last scanned” timestamp, stored in Drive under `Security_Scanner_State`. Only changed files are downloaded.
- **Duplicate skip:** files whose MD5 hash was already scanned clean are skipped.
- **Batching:** files are downloaded in batches of about 3 GB and scanned with one ClamAV call per batch.
- **Time budget:** a run stops after 300 minutes and the next run continues where it left off.
- **Limits:** Google Docs, Sheets and Slides are skipped (they cannot be downloaded as binaries). Files larger than 300 MB are listed in the report but not scanned.
- **Report only:** in drive mode the scanner never deletes or moves users’ files. You decide what happens to them.

### 3.3 Code Testing Server (180+ repositories)

**Strategy:**
- **Six parallel shards.** Repositories are spread across them by size, so the load is balanced.
- **Change detection.** A repository is only re-scanned when its HEAD commit changed, or when its last scan is older than 7 days. Unchanged repositories reuse their previous results, so every report is still complete. Most twice-daily runs only scan a handful of repositories.
- **Weekly full run (Sunday).** Every repository is re-scanned, and Gitleaks checks the **complete git history**, not only the current files.

**Tools by language:**

| Language / file type | Tool |
|---|---|
| Python | ruff (lint), bandit (security checks) |
| JavaScript / TypeScript | Biome |
| Shell | ShellCheck |
| Dockerfile | Hadolint |
| YAML | yamllint |
| PHP | `php -l` (syntax check) |
| Go | gofmt |
| All repositories | Gitleaks (secrets), Trivy (dependencies and misconfiguration) |

**OWASP ZAP** runs a passive baseline scan against the URLs in `ZAP_TARGETS`. It runs in its own job, in parallel to the repository scans. Only list sites you own.

**Configuration:**
- Leave `SCAN_REPO_LIST` empty to scan every repository that `SRC_GH_TOKEN` can see. Archived repositories, forks and empty repositories are skipped.
- To scan only a selection, put one repository per line in `SCAN_REPO_LIST`.
- To change the number of shards, edit `matrix.shard` **and** `EXPECTED_SHARDS` in the workflow.

### 3.4 Load Test (Lasttest)

`LOADTEST_TARGETS` example:
```json
{
  "t1": { "base_url": "https://www.your-domain.tld", "paths": ["/", "/pricing", {"path": "/api/health", "weight": 3}] },
  "t2": "https://shop.your-domain.tld"
}
```

Run **Load-Test** and choose: target alias, profile, peak users, duration, ramp-up, optional requests per second, and the pass thresholds (p95 response time, error rate).

**Profiles:**

| Profile | What it does |
|---|---|
| `smoke` | 5 users for 1 minute (quick check) |
| `load` | Ramp up, hold, ramp down |
| `stress` | Four rising steps up to the peak |
| `spike` | Sudden burst of users |
| `soak` | Long hold to find slow degradation |
| `breakpoint` | Request rate keeps rising until the site fails |

**Important:**
- **CDN / WAF:** Cloudflare and similar services block or challenge test traffic, which shows up as 403/429 errors. Create a WAF custom rule *“skip if header `X-Loadtest` equals <random value>”* and store `X-Loadtest: <random value>` in `LOADTEST_BYPASS_HEADER`.
- **Capacity:** one GitHub runner (4 vCPU) can produce a few thousand simple requests per second. Safety caps: 5000 users and 90 minutes.
- **Only test your own infrastructure.** Inform your hosting provider before heavy tests – some providers treat sudden traffic as an attack.

### 3.5 Lighthouse Audit

Put one URL per line in `LIGHTHOUSE_URLS`. Every URL is audited as mobile and/or desktop.

With `runs` > 1, the run with the median performance score is reported. This smooths out the natural ups and downs between runs.

The e-mail contains:
- A summary with scores, Core Web Vitals and the top improvement opportunities.
- A CSV with all scores.
- The **original Lighthouse HTML report for every URL** (zipped). If the attachments exceed about 17 MB, they are split across several e-mails, numbered `[1/3]`, `[2/3]` and so on.

### 3.6 Server Backup (VPS → Google Drive)

**How it works:** the backup is streamed directly. The server creates the archive (`tar | zstd`), the runner encrypts it with GnuPG AES-256, and the result is uploaded straight to Drive with a resumable upload. Nothing is stored on the runner, so the server size is not limited by the runner’s disk.

**Setup on your PC:**
```bash
ssh-keygen -t ed25519 -f backup_ed25519 -N "" -C "backup"
ssh-keyscan -p 22 YOUR_SERVER > known_hosts.txt        # -> secret VPS_KNOWN_HOSTS
python -c "import secrets;print(secrets.token_urlsafe(48))"   # -> secret BACKUP_ENC_PASSPHRASE
```

**Setup on the server:**
- Add `backup_ed25519.pub` to `/root/.ssh/authorized_keys`.
- Or, if you use a non-root user: add the key to that user and give it passwordless sudo for `tar`, `mysqldump`/`mariadb-dump` and `pg_dumpall`.
- Install `zstd` (`apt install zstd`). It is faster and smaller than gzip. gzip is used automatically if zstd is missing.

**What gets backed up:**

| Part | Content |
|---|---|
| `rootfs.tar.zst.gpg` | The complete filesystem, including permissions, ACLs and xattrs. Excludes `/proc /sys /dev /run /tmp /mnt /media /var/tmp`, swap files and (by default) rebuildable Docker image layers. |
| `mysql_all.sql.zst.gpg` / `postgres_all.sql.zst.gpg` | Consistent database dumps (only if the database service is running) |
| `inventory.txt.gz.gpg` | Packages, services, disks, network, cron jobs, Docker containers |
| `manifest.json`, `RESTORE.txt` | Backup details and step-by-step restore instructions |

**Checks and retention:**
- Every part is verified after upload: the MD5 calculated locally must equal the MD5 that Drive reports.
- The newest `retention` backups are kept. Older ones are deleted **only** if the new backup is complete.
- The e-mail contains the folder link.

**Before you rely on it:** restore one backup into a test VM (see `RESTORE.txt`). An untested backup is not a backup.

### 3.7 Release Factory

**One-time setup on your PC (Windows):**
```powershell
pip install cryptography requests
setx DISPATCH_KEY "<same value as the secret>"
setx GH_DISPATCH_TOKEN "<a PAT that may run workflows in the automation repo>"
setx GH_DISPATCH_REPO "<owner>/<automation-repo>"
```

**Use:**
```powershell
python tools/seal_dispatch.py --workflow release-factory.yml --repo my-repo --branch release/1.4 --tag v1.4.0
# or only print the token and paste it into the "payload" field in the Actions UI:
python tools/seal_dispatch.py --repo my-repo --branch release/1.4 --tag v1.4.0
```

**Options:**

| Option | Effect |
|---|---|
| `--commit <sha>` | Tag a specific commit instead of the branch head |
| `--name` | Release title |
| `--notes` | Release text |
| `--prerelease` | Mark as pre-release |
| `--draft` | Create as draft |
| `--make-latest` | Make this the “latest” release (default: off) |
| `--no-backdate` | Date the tag today instead of the commit date |
| `dry_run` checkbox (in the Actions UI) | Build and verify only – no tag push, no release |

**Safety behaviour:**
- If the tag already exists on a **different** commit, nothing is changed.
- If it exists on the **same** commit, it is reused and the assets are refreshed.
- Retroactive releases are **not** marked “latest”, so your current release stays on top.

**Package:** `git archive` builds `<repo>-<tag>.zip`, and a `.sha256` file is uploaded next to it as a release asset.

**Token permission:** `SRC_GH_TOKEN` needs **Contents: read and write** on the target repositories. Pushing a tag can start tag-triggered workflows in the target repository.

---

## 4. Test checklist (first run of each workflow)

1. **Malware:** put the EICAR test file (an official, harmless antivirus test file) into a ZIP in the inbox and run mode `inbox`. Expect `INFECTED` and the file to move to quarantine.
2. **Code server:** run it manually with mode `full`. Expect one e-mail with “shards received 6/6”.
3. **Load test:** run profile `smoke` first. Check the status codes in the report: no 403/429.
4. **Lighthouse:** run it with two URLs and check that the attachments arrive.
5. **Backup:** run it manually, then download `inventory.txt.gz.gpg` and decrypt it with the passphrase.
6. **Release Factory:** run with `dry_run` on a test repository, then for real.
7. **Every workflow:** open the run while it is still running (from a logged-out browser) and confirm that no names, URLs or IDs are visible.

---

## 5. Issues noticed in the existing workflows

- **`vars.*` values are printed in plain text** in the step log header (`env:` block): `SRC_GH_OWNER`, `GDRIVE_FOLDER_ID`, `GITLAB_NAMESPACE`, `BACKUP_GH_OWNER` and others in `backup.yml`, `backup-integrity.yml`, `branch-observatory.yml`, `code_tracker.yml`, `cross-repo-index.yml` and `changelog-aggregator.yml`. Variables are not masked. Move them to secrets and change `vars.X` to `secrets.X`.
- **`branch_observatory.py` writes the names of failed repositories to `GITHUB_STEP_SUMMARY`.** The step summary is shown publicly on the run page. Remove that block.
- **`backup.yml` and `code_tracker.yml` do not delete their own run.** They stay visible for up to one hour, until `cleanup-history.yml` runs.
