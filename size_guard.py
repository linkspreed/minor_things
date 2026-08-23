#!/usr/bin/env python3
"""
====================================================================
  GROESSEN-/KOSTEN-WAECHTER
--------------------------------------------------------------------
  Woechentliche Pruefung, ob:
    - einzelne GitHub-Quell-Repos ungewoehnlich gross geworden sind
      (z.B. versehentlich committete Binaerdateien),
    - der Google-Drive-Speicher (Ziel 4) sich einem Limit naehert,
    - GitLab-Account-#1-Projekte (Ziel 2) ungewoehnlich gross sind.

  GitLab-Account-#2 (Ziel 3) wird bewusst NICHT auf Groesse geprueft -
  dessen unbegrenztes Wachstum ist gewolltes Design (siehe
  backup_repos.py Modul-Docstring).

  Nutzt dieselben Secrets/Variablen wie backup.yml, zusaetzlich die
  neue Variable SIZE_WARNING_THRESHOLD_MB.
====================================================================
"""

import json
import sys
from pathlib import Path

from common import env, Redactor, SummaryLogger, list_github_repos, http_get, send_google_chat, with_retry

SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")

GITLAB_TOKEN = env("GITLAB_TOKEN")
GITLAB_NAMESPACE = env("GITLAB_NAMESPACE")
GITLAB_URL = env("GITLAB_URL", default="https://gitlab.com")

GDRIVE_SA_JSON = env("GDRIVE_SA_JSON")
GOOGLE_CHAT_WEBHOOK = env("GOOGLE_CHAT_WEBHOOK", required=True)

SIZE_WARNING_THRESHOLD_MB = float(env("SIZE_WARNING_THRESHOLD_MB", default="500"))

redact = Redactor([SRC_GH_TOKEN, GITLAB_TOKEN, GDRIVE_SA_JSON])
log = SummaryLogger(redact)


def check_github_sizes(repos) -> list:
    """repo['size'] ist in KB (GitHub-API-Konvention)."""
    big = []
    threshold_kb = SIZE_WARNING_THRESHOLD_MB * 1024
    for repo in repos:
        if repo.get("size", 0) >= threshold_kb:
            big.append((repo["name"], repo["size"] / 1024))
    return big


def check_gitlab_sizes() -> list:
    if not (GITLAB_TOKEN and GITLAB_NAMESPACE):
        return []
    big = []
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    page = 1
    threshold_kb = SIZE_WARNING_THRESHOLD_MB * 1024
    while True:
        r = http_get(f"{GITLAB_URL}/api/v4/projects", headers=headers,
                     params={"membership": True, "per_page": 100, "page": page, "statistics": True},
                     timeout=30, description="GitLab-Projekte auflisten (Statistik)", logger=log)
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        for proj in batch:
            stats = proj.get("statistics") or {}
            size_kb = stats.get("storage_size", 0) / 1024
            if size_kb >= threshold_kb:
                big.append((proj["path_with_namespace"], size_kb / 1024))
        page += 1
    return big


def check_drive_quota():
    if not GDRIVE_SA_JSON:
        return None
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    info = json.loads(GDRIVE_SA_JSON)
    creds = service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/drive.readonly"]
    )
    service = build("drive", "v3", credentials=creds)
    about = with_retry(
        lambda: service.about().get(fields="storageQuota").execute(),
        "Google-Drive-Speicherquota abfragen", logger=log,
    )
    quota = about.get("storageQuota", {})
    usage = int(quota.get("usage", 0))
    limit = quota.get("limit")
    usage_gb = usage / (1024 ** 3)
    if limit:
        limit_gb = int(limit) / (1024 ** 3)
        pct = usage / int(limit) * 100
        return f"{usage_gb:.2f} GB von {limit_gb:.2f} GB belegt ({pct:.1f}%)"
    return f"{usage_gb:.2f} GB belegt (Konto ohne festes Limit, z.B. Workspace)"


def main():
    log.log("Groessen-/Kosten-Check gestartet.")
    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception as e:  # noqa: BLE001
        log.log(f"!! FEHLER beim Abrufen der Repo-Liste: {e}")
        sys.exit(1)

    big_github = check_github_sizes(repos)
    big_gitlab = check_gitlab_sizes()
    try:
        drive_status = check_drive_quota()
    except Exception as e:  # noqa: BLE001
        log.log(f"!! FEHLER bei Google-Drive-Quota: {e}")
        drive_status = None

    lines = [f"📦 Groessen-/Kosten-Report (Schwelle: {SIZE_WARNING_THRESHOLD_MB:.0f} MB)\n"]

    if big_github:
        lines.append(f"GitHub-Quell-Repos ueber der Schwelle ({len(big_github)}):")
        for name, mb in sorted(big_github, key=lambda x: -x[1]):
            lines.append(f"  - {name}: {mb:.1f} MB")
    else:
        lines.append("GitHub-Quell-Repos: keine ueber der Schwelle.")

    if big_gitlab:
        lines.append(f"\nGitLab-#1-Projekte ueber der Schwelle ({len(big_gitlab)}):")
        for name, mb in sorted(big_gitlab, key=lambda x: -x[1]):
            lines.append(f"  - {name}: {mb:.1f} MB")
    elif GITLAB_TOKEN:
        lines.append("\nGitLab-#1-Projekte: keine ueber der Schwelle.")

    if drive_status:
        lines.append(f"\nGoogle Drive: {drive_status}")

    log.log("\n".join(lines))
    send_google_chat(GOOGLE_CHAT_WEBHOOK, "\n".join(lines))
    Path("size_guard_summary.txt").write_text("\n".join(log.lines) + "\n", encoding="utf-8")
    print("Groessen-/Kosten-Check abgeschlossen.", flush=True)


if __name__ == "__main__":
    main()
