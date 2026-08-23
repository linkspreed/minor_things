#!/usr/bin/env python3
"""
====================================================================
  CROSS-REPO-INDEX
--------------------------------------------------------------------
  Baut woechentlich einen durchsuchbaren Index (Dateiname + Zeilen-
  anzahl je Datei) ueber ALLE Quell-Repos und laedt ihn als EINE JSON-
  Datei zu Google Drive hoch (ueberschreibt die vorherige Version).
  So kannst du bei Bedarf lokal durchsuchen, "in welchem Repo hatte
  ich diese Funktion nochmal" - ohne dass der Index selbst irgendwo
  oeffentlich sichtbar ist.

  Klont jedes Repo SHALLOW (--depth 1, nur Standard-Branch) statt
  vollstaendig gespiegelt - schont die 14-GB-Runner-SSD. Nutzt
  ripgrep (wird im Workflow als Binary installiert, kein pip-Paket).

  Nutzt SRC_GH_TOKEN sowie GDRIVE_SA_JSON/GDRIVE_FOLDER_ID wieder wie
  backup.yml - es werden KEINE neuen Secrets benoetigt.
====================================================================
"""

import json
import shutil
import subprocess
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from common import env, Redactor, SummaryLogger, list_github_repos, with_retry

SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")

GDRIVE_FOLDER_ID = env("GDRIVE_FOLDER_ID")
GDRIVE_SA_JSON = env("GDRIVE_SA_JSON")
INDEX_FILE_NAME = env("CROSS_REPO_INDEX_FILE_NAME", default="cross_repo_index.json")

WORKDIR = Path(env("INDEX_WORKDIR", default="index_clones"))

redact = Redactor([SRC_GH_TOKEN, GDRIVE_SA_JSON])
log = SummaryLogger(redact)


def shallow_clone(repo_name: str, clone_url: str) -> Path:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    dest = WORKDIR / repo_name
    if dest.exists():
        shutil.rmtree(dest)
    subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", clone_url, str(dest)],
        check=True, capture_output=True, text=True, timeout=300,
    )
    return dest


def index_with_ripgrep(repo_path: Path) -> list:
    """Liste von {path, lines} je Datei im Repo (ohne .git)."""
    result = subprocess.run(
        ["rg", "--files"], cwd=repo_path, capture_output=True, text=True, timeout=120,
    )
    entries = []
    for rel_path in result.stdout.splitlines():
        full = repo_path / rel_path
        try:
            with open(full, "r", encoding="utf-8", errors="ignore") as f:
                line_count = sum(1 for _ in f)
        except Exception:  # noqa: BLE001
            line_count = None
        entries.append({"path": rel_path, "lines": line_count})
    return entries


def upload_index_to_drive(local_path: Path):
    from googleapiclient.discovery import build
    from googleapiclient.http import MediaFileUpload
    from google.oauth2 import service_account

    info = json.loads(GDRIVE_SA_JSON)
    creds = service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/drive"]
    )
    service = build("drive", "v3", credentials=creds)

    query = f"name = '{INDEX_FILE_NAME}' and '{GDRIVE_FOLDER_ID}' in parents and trashed = false"
    existing = with_retry(
        lambda: service.files().list(
            q=query, fields="files(id)", supportsAllDrives=True, includeItemsFromAllDrives=True,
        ).execute(),
        "Alten Index suchen", logger=log,
    ).get("files", [])

    media = MediaFileUpload(str(local_path), mimetype="application/json", resumable=True)
    with_retry(
        lambda: service.files().create(
            body={"name": INDEX_FILE_NAME, "parents": [GDRIVE_FOLDER_ID]},
            media_body=media, fields="id", supportsAllDrives=True,
        ).execute(),
        "Neuen Index hochladen", logger=log,
    )

    for f in existing:
        try:
            service.files().delete(fileId=f["id"], supportsAllDrives=True).execute()
        except Exception as e:  # noqa: BLE001
            log.log(f"     (alten Index loeschen fehlgeschlagen, ignoriert: {e})")


def main():
    if not (GDRIVE_SA_JSON and GDRIVE_FOLDER_ID):
        print("Cross-Repo-Index: Google-Drive-Ziel nicht konfiguriert, Skript wird uebersprungen.", flush=True)
        sys.exit(0)

    log.log("Cross-Repo-Index-Aufbau gestartet.")
    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception as e:  # noqa: BLE001
        log.log(f"!! FEHLER beim Abrufen der Repo-Liste: {e}")
        sys.exit(1)

    index = {"generated_at": datetime.now(timezone.utc).isoformat(), "repos": {}}
    failed = []

    for i, repo in enumerate(repos, start=1):
        name = repo["name"]
        print(f"... Indexiere Repo {i}/{len(repos)} ...", flush=True)
        try:
            clone_url = repo["clone_url"].replace("https://", f"https://{SRC_GH_TOKEN}@")
            repo_path = shallow_clone(name, clone_url)
            entries = index_with_ripgrep(repo_path)
            index["repos"][name] = entries
            shutil.rmtree(repo_path, ignore_errors=True)
        except Exception as e:  # noqa: BLE001
            failed.append(name)
            log.log(f"!! FEHLER bei {name}: {e}")

    with tempfile.TemporaryDirectory() as tmp:
        index_path = Path(tmp) / INDEX_FILE_NAME
        index_path.write_text(json.dumps(index, indent=2), encoding="utf-8")
        try:
            upload_index_to_drive(index_path)
            log.log("Index erfolgreich zu Google Drive hochgeladen.")
        except Exception as e:  # noqa: BLE001
            log.log(f"!! FEHLER beim Hochladen des Index: {e}")
            failed.append("__upload__")

    shutil.rmtree(WORKDIR, ignore_errors=True)
    Path("cross_repo_index_summary.txt").write_text("\n".join(log.lines) + "\n", encoding="utf-8")
    print(f"Cross-Repo-Index abgeschlossen. {len(repos) - len(failed)} von {len(repos)} Repos indexiert.", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
