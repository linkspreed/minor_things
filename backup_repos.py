#!/usr/bin/env python3
"""
====================================================================
  GITHUB REPO SUPER-BACKUP  (Public-Repo-Safe Version + E-Mail)
--------------------------------------------------------------------
  Spiegelt ALLE Repos eines GitHub-Accounts (voller Verlauf, alle
  Branches, alle Tags) automatisch nach:

    1) einem ZWEITEN GitHub-Account   (echtes Git-Mirror)
    2) GitLab                          (echtes Git-Mirror)
    3) Google Drive                    (komplettes .git-Bundle als ZIP,
                                         alte Version wird ersetzt)

  WICHTIGE FIXES IN DIESER VERSION (nach dem ersten Testlauf):

  1) JEDES ZIEL BEKOMMT EINEN EIGENEN try/except-BLOCK pro Repo.
     Vorher waren GitHub-Backup, GitLab und Google Drive in EINEM
     gemeinsamen try-Block - schlug z.B. GitLab fehl, wurde Google
     Drive fuer dasselbe Repo GAR NICHT ERST versucht (der Code sprang
     sofort zum except). Das erklaerte, warum bei GitLab und Drive
     fast gleich viele Repos fehlten. Jetzt wird JEDES Ziel unabhaengig
     versucht, egal ob ein anderes Ziel zuvor fehlgeschlagen ist.

  2) GITLAB-EXISTENZ-CHECK auf DIREKTE PFAD-ABFRAGE umgestellt statt
     Such-API. Die alte "search"-API durchsucht standardmaessig ALLE
     oeffentlichen Projekte auf ganz GitLab.com - bei generischen
     Repo-Namen wurde das eigene (bereits angelegte) Projekt von
     fremden oeffentlichen Treffern auf Seite 1 verdraengt, das Skript
     hielt es faelschlich fuer "existiert nicht" und versuchte es
     erneut anzulegen -> Fehler "Pfad bereits vergeben" -> Abbruch.
     Die neue Methode (GET /projects/:id mit URL-kodiertem
     "namespace/name") ist ein exakter, eindeutiger Treffer.

  (Bitbucket wurde bewusst NICHT eingebaut: Bitbucket begrenzt den
  KOSTENLOSEN Plan seit April 2025 auf nur 1 GB Speicher fuer den
  GESAMTEN Workspace.)

  WICHTIG ZU DEN VARIABLEN-NAMEN: GitHub reserviert das Praefix
  "GITHUB_" fuer sich selbst - deshalb heissen die Werte fuer Quelle
  und Backup-Account hier "SRC_GH_..." und "BACKUP_GH_...".

  GOOGLE DRIVE: Dienstkonten (Service Accounts) haben KEIN eigenes
  Speicherkontingent und koennen NICHT in "Meine Ablage" hochladen.
  Es MUSS eine GETEILTE ABLAGE (Shared Drive) sein. Innerhalb dieser
  legt das Skript automatisch einen Unterordner an (Standardname
  "Repo_Backups", per GDRIVE_BACKUP_FOLDER_NAME aenderbar).

  DESIGN-ZIEL: Dieses Skript ist dafuer gebaut, in einem OEFFENTLICHEN
  GitHub-Repo zu laufen (fuer unbegrenzte, kostenlose Actions-Minuten),
  OHNE dass irgendjemand aus den Actions-Logs ablesen kann, welche
  Repos du hast (Konsole zeigt nur "Repo 3/156", nie echte Namen; alle
  Details landen ausschliesslich in der E-Mail-Zusammenfassung).

  FESTPLATTEN-MANAGEMENT: Standard-Runner haben nur 14 GB SSD. Nach
  jedem einzelnen Repo wird der lokale Mirror-Ordner SOFORT wieder
  geloescht.
====================================================================
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
import urllib.parse
import zipfile
from datetime import datetime, timezone
from pathlib import Path

import requests

# ====================================================================
#  CONFIG - alles kommt aus Umgebungsvariablen (siehe .env.example)
# ====================================================================

def env(name, required=False, default=None):
    val = os.environ.get(name, default)
    if required and not val:
        print(f"FEHLER: Pflicht-Konfiguration fehlt (Name absichtlich nicht angezeigt).")
        sys.exit(1)
    return val

# --- Quelle: dein Haupt-GitHub-Account, dessen Repos gesichert werden
SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")  # "user" oder "org"

# --- Ziel 1: zweiter GitHub-Account (optional, leer lassen zum Deaktivieren)
BACKUP_GH_TOKEN = env("BACKUP_GH_TOKEN")
BACKUP_GH_OWNER = env("BACKUP_GH_OWNER")
BACKUP_GH_OWNER_TYPE = env("BACKUP_GH_OWNER_TYPE", default="user")

# --- Ziel 2: GitLab (optional)
GITLAB_TOKEN = env("GITLAB_TOKEN")
GITLAB_NAMESPACE = env("GITLAB_NAMESPACE")   # dein GitLab-Benutzername oder Gruppen-Pfad
GITLAB_URL = env("GITLAB_URL", default="https://gitlab.com")

# --- Ziel 3: Google Drive (optional) ---------------------------------
GDRIVE_FOLDER_ID = env("GDRIVE_FOLDER_ID")          # ID der geteilten Ablage / des Ordners darin
GDRIVE_SA_JSON = env("GDRIVE_SA_JSON")              # Inhalt des Service-Account-JSON-Keys (als Text)
GDRIVE_BACKUP_FOLDER_NAME = env("GDRIVE_BACKUP_FOLDER_NAME", default="Repo_Backups")

# --- E-Mail-Benachrichtigung (wird bei JEDEM Lauf verschickt, Erfolg wie Fehler) ---
EMAIL_SUMMARY_FILE = Path(env("EMAIL_SUMMARY_FILE", default="email_summary.txt"))

# --- Allgemein
WORKDIR = Path(env("BACKUP_WORKDIR", default="mirrors"))
GIT_TIMEOUT_SECONDS = int(env("GIT_TIMEOUT_SECONDS", default="1800"))  # 30 Min je Git-Befehl

CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO = env("CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO", default="true").lower() == "true"
QUIET_CONSOLE = env("QUIET_CONSOLE", default="true").lower() == "true"

_SECRETS = [s for s in [
    SRC_GH_TOKEN, BACKUP_GH_TOKEN, GITLAB_TOKEN, GDRIVE_SA_JSON,
] if s]


def redact(text: str) -> str:
    for s in _SECRETS:
        if s and s in text:
            text = text.replace(s, "***REDACTED***")
    return text


# ====================================================================
#  LOGGING: Konsole = anonym/leer. E-Mail-Text = vollstaendig.
# ====================================================================

EMAIL_LINES = []
_repo_total = 0
_repo_index = 0


def email_log(msg: str):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    EMAIL_LINES.append(f"[{ts}] {redact(str(msg))}")


def console_heartbeat(msg: str = None):
    if QUIET_CONSOLE:
        if msg:
            print(msg, flush=True)
        else:
            print(f"... Verarbeite Repo {_repo_index}/{_repo_total} ...", flush=True)
    else:
        print(msg or f"Repo {_repo_index}/{_repo_total}", flush=True)


def run(cmd, cwd=None, timeout=GIT_TIMEOUT_SECONDS):
    try:
        result = subprocess.run(
            cmd, cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout,
        )
        return result.stdout
    except subprocess.CalledProcessError as e:
        raise RuntimeError(redact(f"Git-Befehl fehlgeschlagen: {e.stderr}"))
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Timeout nach {timeout}s bei einem Git-Befehl.")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ====================================================================
#  1) QUELLE: Repo-Liste von GitHub holen
# ====================================================================

def list_source_repos():
    repos = []
    page = 1
    base = (f"https://api.github.com/orgs/{SRC_GH_OWNER}/repos"
            if SRC_GH_OWNER_TYPE == "org"
            else "https://api.github.com/user/repos")
    headers = {"Authorization": f"token {SRC_GH_TOKEN}", "Accept": "application/vnd.github+json"}
    while True:
        params = {"per_page": 100, "page": page}
        if SRC_GH_OWNER_TYPE != "org":
            params["affiliation"] = "owner"
        r = requests.get(base, headers=headers, params=params, timeout=60)
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
    return repos


# ====================================================================
#  2) LOKALES BARE-MIRROR anlegen (immer frisch, siehe Modul-Docstring)
# ====================================================================

def mirror_clone_local(repo_name: str, source_clone_url_with_token: str) -> Path:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    bare_path = WORKDIR / f"{repo_name}.git"
    if bare_path.exists():
        shutil.rmtree(bare_path)
    email_log(f"  -> klone {repo_name}")
    run(["git", "clone", "--mirror", source_clone_url_with_token, str(bare_path)])
    return bare_path


def push_mirror(bare_path: Path, target_url_with_token: str, label: str):
    email_log(f"  -> spiegle nach {label}")
    try:
        run(["git", "--git-dir", str(bare_path), "push", "--mirror", target_url_with_token])
    except RuntimeError as e:
        if "up-to-date" in str(e).lower():
            email_log(f"     ({label}: bereits aktuell)")
        else:
            raise


def cleanup_local_mirror(bare_path: Path):
    if CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO and bare_path and bare_path.exists():
        shutil.rmtree(bare_path, ignore_errors=True)


# ====================================================================
#  3) ZIEL-REPOS bei Bedarf einmalig anlegen
# ====================================================================

def ensure_github_target_repo(name: str):
    """Direkter Lookup (GET /repos/:owner/:name) - eindeutig, keine Suche noetig."""
    headers = {"Authorization": f"token {BACKUP_GH_TOKEN}", "Accept": "application/vnd.github+json"}
    check_url = f"https://api.github.com/repos/{BACKUP_GH_OWNER}/{name}"
    r = requests.get(check_url, headers=headers, timeout=30)
    if r.status_code == 200:
        return
    create_url = (f"https://api.github.com/orgs/{BACKUP_GH_OWNER}/repos"
                   if BACKUP_GH_OWNER_TYPE == "org" else "https://api.github.com/user/repos")
    r = requests.post(create_url, headers=headers, json={"name": name, "private": True}, timeout=30)
    if r.status_code not in (201, 422):
        raise RuntimeError(redact(f"GitHub-Backup-Repo konnte nicht angelegt werden: {r.text}"))
    email_log(f"  -> GitHub-Backup-Repo '{name}' neu angelegt")


def ensure_gitlab_target_repo(name: str):
    """
    FIX: Direkter Pfad-Lookup statt Such-API. Die Such-API durchsucht
    standardmaessig ALLE oeffentlichen GitLab-Projekte weltweit - bei
    generischen Repo-Namen wurde das eigene Projekt von fremden
    Treffern verdraengt und faelschlich fuer "existiert nicht"
    gehalten. GET /api/v4/projects/:id (mit URL-kodiertem
    "namespace/name" als :id) ist ein exakter, eindeutiger Treffer.
    """
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    project_path = f"{GITLAB_NAMESPACE}/{name}"
    encoded_path = urllib.parse.quote(project_path, safe="")
    check_url = f"{GITLAB_URL}/api/v4/projects/{encoded_path}"

    r = requests.get(check_url, headers=headers, timeout=30)
    if r.status_code == 200:
        return  # existiert bereits - fertig

    # Existiert noch nicht -> anlegen. Namespace-ID ermitteln (direkter
    # Lookup statt Suche - funktioniert mit Pfad ODER numerischer ID).
    payload = {"name": name, "path": name, "visibility": "private"}
    encoded_ns = urllib.parse.quote(GITLAB_NAMESPACE, safe="")
    ns_r = requests.get(f"{GITLAB_URL}/api/v4/namespaces/{encoded_ns}", headers=headers, timeout=30)
    if ns_r.status_code == 200:
        ns_data = ns_r.json()
        # Nur bei Gruppen-Namespaces explizit setzen; bei einem
        # persoenlichen Namespace legt GitLab automatisch im eigenen
        # Account an, wenn namespace_id weggelassen wird.
        if ns_data.get("kind") == "group":
            payload["namespace_id"] = ns_data["id"]

    r = requests.post(f"{GITLAB_URL}/api/v4/projects", headers=headers, json=payload, timeout=30)
    if r.status_code != 201:
        raise RuntimeError(redact(f"GitLab-Projekt konnte nicht angelegt werden: {r.text}"))
    email_log(f"  -> GitLab-Projekt '{name}' neu angelegt")


# ====================================================================
#  4) GOOGLE DRIVE Backup
# ====================================================================

_drive_service = None
_drive_backup_folder_id = None


def get_drive_service():
    global _drive_service
    if _drive_service is not None:
        return _drive_service
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    info = json.loads(GDRIVE_SA_JSON)
    creds = service_account.Credentials.from_service_account_info(
        info, scopes=["https://www.googleapis.com/auth/drive"]
    )
    _drive_service = build("drive", "v3", credentials=creds)
    return _drive_service


def ensure_drive_backup_folder(service) -> str:
    global _drive_backup_folder_id
    if _drive_backup_folder_id:
        return _drive_backup_folder_id

    query = (
        f"name = '{GDRIVE_BACKUP_FOLDER_NAME}' and '{GDRIVE_FOLDER_ID}' in parents "
        f"and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    )
    existing = service.files().list(
        q=query, fields="files(id)",
        supportsAllDrives=True, includeItemsFromAllDrives=True,
    ).execute().get("files", [])

    if existing:
        _drive_backup_folder_id = existing[0]["id"]
        email_log(f"Google-Drive-Backup-Ordner '{GDRIVE_BACKUP_FOLDER_NAME}' gefunden (wird verwendet).")
        return _drive_backup_folder_id

    folder = service.files().create(
        body={
            "name": GDRIVE_BACKUP_FOLDER_NAME,
            "mimeType": "application/vnd.google-apps.folder",
            "parents": [GDRIVE_FOLDER_ID],
        },
        fields="id",
        supportsAllDrives=True,
    ).execute()
    _drive_backup_folder_id = folder["id"]
    email_log(f"Google-Drive-Backup-Ordner '{GDRIVE_BACKUP_FOLDER_NAME}' neu angelegt.")
    return _drive_backup_folder_id


def backup_to_drive(bare_path: Path, repo_name: str):
    from googleapiclient.http import MediaFileUpload

    service = get_drive_service()
    target_folder_id = ensure_drive_backup_folder(service)
    zip_name = f"{repo_name}.git.zip"

    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / zip_name
        email_log(f"  -> packe für Google Drive")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in bare_path.rglob("*"):
                if file.is_file():
                    zf.write(file, arcname=str(file.relative_to(bare_path.parent)))

        query = f"name = '{zip_name}' and '{target_folder_id}' in parents and trashed = false"
        existing = service.files().list(
            q=query, fields="files(id)",
            supportsAllDrives=True, includeItemsFromAllDrives=True,
        ).execute().get("files", [])
        for f in existing:
            service.files().delete(fileId=f["id"], supportsAllDrives=True).execute()

        email_log(f"  -> lade zu Google Drive hoch")
        media = MediaFileUpload(str(zip_path), mimetype="application/zip", resumable=True)
        service.files().create(
            body={"name": zip_name, "parents": [target_folder_id]},
            media_body=media,
            fields="id",
            supportsAllDrives=True,
        ).execute()


# ====================================================================
#  HAUPTPROGRAMM
# ====================================================================

def process_repo(repo: dict) -> bool:
    """
    Verarbeitet ein Repo. WICHTIG (FIX): Jedes Ziel (GitHub-Backup,
    GitLab, Google Drive) hat einen EIGENEN try/except-Block. Schlaegt
    z.B. GitLab fehl, wird Google Drive fuer dasselbe Repo TROTZDEM
    versucht - anders als in der vorherigen Version, wo ein Fehler bei
    einem Ziel alle nachfolgenden Ziele fuer dieses Repo blockierte.
    """
    name = repo["name"]
    email_log(f"--- {name} ---")
    bare_path = None
    overall_ok = True

    # Klonen ist die Grundvoraussetzung fuer ALLE Ziele - schlaegt das
    # fehl, koennen wir fuer dieses Repo gar nichts tun.
    try:
        source_url = repo["clone_url"].replace("https://", f"https://{SRC_GH_TOKEN}@")
        bare_path = mirror_clone_local(name, source_url)
    except Exception as e:  # noqa: BLE001
        email_log(f"  !! FEHLER beim Klonen von {name}: {e}")
        return False

    if BACKUP_GH_TOKEN and BACKUP_GH_OWNER:
        try:
            ensure_github_target_repo(name)
            target = f"https://{BACKUP_GH_TOKEN}@github.com/{BACKUP_GH_OWNER}/{name}.git"
            push_mirror(bare_path, target, "GitHub-Backup-Account")
        except Exception as e:  # noqa: BLE001
            email_log(f"  !! FEHLER (GitHub-Backup) bei {name}: {e}")
            overall_ok = False

    if GITLAB_TOKEN and GITLAB_NAMESPACE:
        try:
            ensure_gitlab_target_repo(name)
            gitlab_host = GITLAB_URL.replace("https://", "")
            target = f"https://oauth2:{GITLAB_TOKEN}@{gitlab_host}/{GITLAB_NAMESPACE}/{name}.git"
            push_mirror(bare_path, target, "GitLab")
        except Exception as e:  # noqa: BLE001
            email_log(f"  !! FEHLER (GitLab) bei {name}: {e}")
            overall_ok = False

    if GDRIVE_SA_JSON and GDRIVE_FOLDER_ID:
        try:
            backup_to_drive(bare_path, name)
        except Exception as e:  # noqa: BLE001
            email_log(f"  !! FEHLER (Google Drive) bei {name}: {e}")
            overall_ok = False

    cleanup_local_mirror(bare_path)

    if overall_ok:
        email_log(f"  OK ({name})")
    return overall_ok


def main():
    global _repo_total, _repo_index

    start_time = datetime.now(timezone.utc)
    console_heartbeat("Backup gestartet.")
    email_log("===== Repo-Backup gestartet =====")

    ok, failed, failed_names = 0, 0, []

    try:
        repos = list_source_repos()
        _repo_total = len(repos)
        email_log(f"{_repo_total} Quell-Repos gefunden.")

        for i, repo in enumerate(repos, start=1):
            _repo_index = i
            console_heartbeat()
            success = process_repo(repo)
            if success:
                ok += 1
            else:
                failed += 1
                failed_names.append(repo["name"])

    except Exception as e:  # noqa: BLE001
        email_log(f"!! SCHWERWIEGENDER FEHLER, Lauf abgebrochen: {e}")
        email_log(redact(traceback.format_exc()))

    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    summary_line = f"===== Fertig: {ok} ok, {failed} Fehler von {ok + failed} Repos. Dauer: {int(duration)}s ====="
    email_log(summary_line)
    console_heartbeat("Backup beendet.")

    subject_status = "OK" if failed == 0 else f"{failed} FEHLER"
    header = (
        f"Backup-Zusammenfassung ({subject_status})\n"
        f"Repos gesamt: {ok + failed} | erfolgreich (ALLE Ziele ok): {ok} | mit mind. 1 Fehler: {failed}\n"
        f"Dauer: {int(duration)} Sekunden\n"
    )
    if failed_names:
        header += "Repos mit mindestens einem Fehler: " + ", ".join(failed_names) + "\n"
    header += "\n----- Vollständiges Protokoll -----\n"

    EMAIL_SUMMARY_FILE.write_text(header + "\n".join(EMAIL_LINES) + "\n", encoding="utf-8")
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
