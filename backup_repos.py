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

  (Bitbucket wurde bewusst NICHT eingebaut: Bitbucket begrenzt den
  KOSTENLOSEN Plan seit April 2025 auf nur 1 GB Speicher fuer den
  GESAMTEN Workspace - nicht pro Repo, sondern summiert ueber alle
  Repos zusammen. Bei 155+ teils grossen Repos waere das nahezu
  garantiert sofort ausgeschoepft.)

  WICHTIG ZU DEN VARIABLEN-NAMEN: GitHub reserviert das Praefix
  "GITHUB_" fuer sich selbst - sowohl bei Secrets als auch bei
  Variables darf KEIN eigener Name damit beginnen (Fehler: "Secret
  names must not start with GITHUB_"). Deshalb heissen die Werte fuer
  die Quelle und den Backup-Account hier "SRC_GH_..." und
  "BACKUP_GH_..." statt "GITHUB_...".

  GOOGLE DRIVE: Dienstkonten (Service Accounts) haben KEIN eigenes
  Speicherkontingent und koennen NICHT in "Meine Ablage" hochladen -
  das schlaegt IMMER mit "storageQuotaExceeded" fehl. Es MUSS eine
  GETEILTE ABLAGE (Shared Drive) sein (siehe README). Innerhalb dieser
  legt das Skript automatisch einen Unterordner an (Standardname
  "Repo_Backups", per GDRIVE_BACKUP_FOLDER_NAME aenderbar) und
  speichert dort alle ZIP-Dateien.

  DESIGN-ZIEL DIESER VERSION: Dieses Skript ist dafuer gebaut, in einem
  OEFFENTLICHEN GitHub-Repo zu laufen (fuer unbegrenzte, kostenlose
  Actions-Minuten), OHNE dass irgendjemand aus den Actions-Logs
  ablesen kann, welche Repos du hast:

    - Auf der Konsole (= oeffentlich sichtbares Actions-Log) werden
      Repos NUR ueber neutrale Nummern angesprochen ("Repo 3/155"),
      NIE ueber ihren echten Namen.
    - Alle Details (echte Namen, Fehler, Erfolge) werden NUR in eine
      lokale Datei geschrieben, die am Ende per E-Mail verschickt wird
      - NICHT ins Repo committet, NICHT als Actions-Artifact hochgeladen
      (Artifacts sind bei oeffentlichen Repos fuer jeden herunterladbar!).
    - Die Datei existiert nur auf der Festplatte des Runners, der nach
      dem Lauf ohnehin komplett vernichtet wird.

  FESTPLATTEN-MANAGEMENT: Standard-Runner haben nur 14 GB SSD, egal ob
  Linux/Windows/macOS. Damit das bei 150+ teils grossen Repos nicht
  ausgeht, wird nach jedem einzelnen Repo der lokale Mirror-Ordner
  SOFORT wieder geloescht (kein Zwischenspeichern/Caching zwischen
  Läufen). Das kostet etwas mehr Zeit pro Lauf (kompletter Klon statt
  nur Aenderungen), ist aber egal, da auf oeffentlichen Repos die
  Minuten unbegrenzt und kostenlos sind.
====================================================================
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
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
#     (Namen mit "SRC_GH_" statt "GITHUB_", da GitHub das Praefix
#     "GITHUB_" fuer eigene Secrets/Variables reserviert hat)
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
# GDRIVE_FOLDER_ID MUSS die ID einer GETEILTEN ABLAGE (Shared Drive) sein,
# oder eines Ordners INNERHALB einer geteilten Ablage - NICHT "Meine
# Ablage"! Service Accounts haben kein eigenes Speicherkontingent (siehe
# Modul-Docstring oben).
GDRIVE_FOLDER_ID = env("GDRIVE_FOLDER_ID")          # ID der geteilten Ablage / des Ordners darin
GDRIVE_SA_JSON = env("GDRIVE_SA_JSON")              # Inhalt des Service-Account-JSON-Keys (als Text)
GDRIVE_BACKUP_FOLDER_NAME = env("GDRIVE_BACKUP_FOLDER_NAME", default="Repo_Backups")

# --- E-Mail-Benachrichtigung (wird bei JEDEM Lauf verschickt, Erfolg wie Fehler) ---
# Alles hier - inkl. Empfaenger-Adresse! - kommt aus Secrets, damit auch die
# Ziel-Mailadresse in einem oeffentlichen Repo NIRGENDWO im Klartext steht.
EMAIL_SUMMARY_FILE = Path(env("EMAIL_SUMMARY_FILE", default="email_summary.txt"))

# --- Allgemein
WORKDIR = Path(env("BACKUP_WORKDIR", default="mirrors"))
GIT_TIMEOUT_SECONDS = int(env("GIT_TIMEOUT_SECONDS", default="1800"))  # 30 Min je Git-Befehl

# Nach jedem Repo den lokalen Mirror wieder loeschen? ("true" empfohlen bei
# oeffentlichen Standard-Runnern mit nur 14 GB Festplatte - siehe Doku oben).
CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO = env("CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO", default="true").lower() == "true"

# Konsole moeglichst leer halten (fuer oeffentliche Repos empfohlen: true).
# Bei false werden auch auf der Konsole Klarnamen/Details ausgegeben -
# NUR sinnvoll, wenn das Steuerungs-Repo PRIVAT ist oder du lokal testest.
QUIET_CONSOLE = env("QUIET_CONSOLE", default="true").lower() == "true"

# Alle Geheimnisse sammeln, damit wir sie aus Konsolen-Ausgaben rausfiltern
# koennen, falls doch mal (z.B. bei einem Python-Traceback) etwas auftaucht.
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

EMAIL_LINES = []          # vollstaendiges Protokoll, landet NUR in der E-Mail
_repo_total = 0
_repo_index = 0


def email_log(msg: str):
    """Schreibt eine Zeile ins E-Mail-Protokoll (mit Klarnamen etc.)."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    EMAIL_LINES.append(f"[{ts}] {redact(str(msg))}")


def console_heartbeat(msg: str = None):
    """
    Gibt auf der Konsole (=oeffentliches Actions-Log) NUR eine neutrale,
    nichtssagende Statuszeile aus - ohne Repo-Namen, ohne Details.
    """
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
        shutil.rmtree(bare_path)  # sauberer Neustart, kein Rest von einem Vorlauf
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
    if CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO and bare_path.exists():
        shutil.rmtree(bare_path, ignore_errors=True)


# ====================================================================
#  3) ZIEL-REPOS bei Bedarf einmalig anlegen
# ====================================================================

def ensure_github_target_repo(name: str):
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
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    r = requests.get(f"{GITLAB_URL}/api/v4/projects", headers=headers, params={"search": name}, timeout=30)
    r.raise_for_status()
    for proj in r.json():
        if proj["path"] == name and proj["namespace"]["path"] == GITLAB_NAMESPACE:
            return
    payload = {"name": name, "path": name, "visibility": "private"}
    ns_r = requests.get(f"{GITLAB_URL}/api/v4/namespaces", headers=headers,
                         params={"search": GITLAB_NAMESPACE}, timeout=30)
    if ns_r.ok:
        for ns in ns_r.json():
            if ns["path"] == GITLAB_NAMESPACE:
                payload["namespace_id"] = ns["id"]
                break
    r = requests.post(f"{GITLAB_URL}/api/v4/projects", headers=headers, json=payload, timeout=30)
    if r.status_code != 201:
        raise RuntimeError(redact(f"GitLab-Projekt konnte nicht angelegt werden: {r.text}"))
    email_log(f"  -> GitLab-Projekt '{name}' neu angelegt")


# ====================================================================
#  4) GOOGLE DRIVE Backup
#     - MUSS eine geteilte Ablage (Shared Drive) sein (siehe oben)
#     - legt automatisch einen Unterordner an (Standard: "Repo_Backups")
#     - alte Zip loeschen, neue mit voller Historie hochladen
# ====================================================================

_drive_service = None
_drive_backup_folder_id = None  # wird einmal pro Lauf ermittelt/angelegt (Cache)


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
    """
    Sucht innerhalb von GDRIVE_FOLDER_ID (geteilte Ablage / Ordner darin)
    nach einem Unterordner namens GDRIVE_BACKUP_FOLDER_NAME. Legt ihn an,
    falls er noch nicht existiert. Ergebnis wird fuer den Rest des Laufs
    zwischengespeichert (_drive_backup_folder_id), damit nicht bei jedem
    einzelnen Repo erneut danach gesucht werden muss.
    """
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

        # Alte Version dieser Datei im Backup-Ordner finden und löschen
        query = (
            f"name = '{zip_name}' and '{target_folder_id}' in parents and trashed = false"
        )
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
    """Verarbeitet ein Repo komplett. Gibt True bei Erfolg zurueck."""
    name = repo["name"]
    email_log(f"--- {name} ---")
    bare_path = None
    try:
        source_url = repo["clone_url"].replace("https://", f"https://{SRC_GH_TOKEN}@")
        bare_path = mirror_clone_local(name, source_url)

        if BACKUP_GH_TOKEN and BACKUP_GH_OWNER:
            ensure_github_target_repo(name)
            target = f"https://{BACKUP_GH_TOKEN}@github.com/{BACKUP_GH_OWNER}/{name}.git"
            push_mirror(bare_path, target, "GitHub-Backup-Account")

        if GITLAB_TOKEN and GITLAB_NAMESPACE:
            ensure_gitlab_target_repo(name)
            gitlab_host = GITLAB_URL.replace("https://", "")
            target = f"https://oauth2:{GITLAB_TOKEN}@{gitlab_host}/{GITLAB_NAMESPACE}/{name}.git"
            push_mirror(bare_path, target, "GitLab")

        if GDRIVE_SA_JSON and GDRIVE_FOLDER_ID:
            backup_to_drive(bare_path, name)

        email_log(f"  OK ({name})")
        return True

    except Exception as e:  # noqa: BLE001 - ein kaputtes Repo darf den Lauf nicht stoppen
        email_log(f"  !! FEHLER bei {name}: {e}")
        return False

    finally:
        if bare_path:
            cleanup_local_mirror(bare_path)


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
            console_heartbeat()  # nur "Verarbeite Repo i/n ..." - kein Name
            success = process_repo(repo)
            if success:
                ok += 1
            else:
                failed += 1
                failed_names.append(repo["name"])

    except Exception as e:  # noqa: BLE001 - selbst bei einem Totalausfall soll die Mail rausgehen
        email_log(f"!! SCHWERWIEGENDER FEHLER, Lauf abgebrochen: {e}")
        email_log(redact(traceback.format_exc()))

    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    summary_line = f"===== Fertig: {ok} ok, {failed} Fehler von {ok + failed} Repos. Dauer: {int(duration)}s ====="
    email_log(summary_line)
    console_heartbeat("Backup beendet.")  # Konsole bekommt NUR das - kein "ok/failed" mit Namen

    # E-Mail-Zusammenfassung schreiben (wird von der Workflow-Datei
    # verschickt, NICHT von diesem Skript selbst - kein SMTP hier drin,
    # damit alle Mail-Zugangsdaten sauber als GitHub Secrets bleiben).
    subject_status = "OK" if failed == 0 else f"{failed} FEHLER"
    header = (
        f"Backup-Zusammenfassung ({subject_status})\n"
        f"Repos gesamt: {ok + failed} | erfolgreich: {ok} | fehlgeschlagen: {failed}\n"
        f"Dauer: {int(duration)} Sekunden\n"
    )
    if failed_names:
        header += "Fehlgeschlagene Repos: " + ", ".join(failed_names) + "\n"
    header += "\n----- Vollständiges Protokoll -----\n"

    EMAIL_SUMMARY_FILE.write_text(header + "\n".join(EMAIL_LINES) + "\n", encoding="utf-8")

    # Exit-Code widerspiegelt Erfolg/Misserfolg (für evtl. spätere Auswertung),
    # verhindert aber NICHT den E-Mail-Versand, da der Workflow-Schritt dafür
    # "if: always()" verwendet.
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
