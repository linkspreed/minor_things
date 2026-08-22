#!/usr/bin/env python3
"""
====================================================================
  GITHUB REPO SUPER-BACKUP  (Public-Repo-Safe Version + Google Chat)
--------------------------------------------------------------------
  Spiegelt ALLE Repos eines GitHub-Accounts (voller Verlauf, alle
  Branches, alle Tags) automatisch nach VIER Zielen, alle 6 Stunden
  (4x taeglich):

    1) einem ZWEITEN GitHub-Account      (echtes Git-Mirror, ueberschreibt)
    2) GitLab-Account #1                  (echtes Git-Mirror, ueberschreibt)
    3) GitLab-Account #2                  (NEUES, datiertes Projekt JEDEN Lauf)
    4) Google Drive                       (ZIP, alte Version wird ersetzt)

  ---------------------------------------------------------------
  FIXES NACH DEM ZWEITEN TESTLAUF (22.08.2026):
  ---------------------------------------------------------------

  FIX A) "deny updating a hidden ref" beim Push zu GitHub/GitLab-Zielen:
  `git clone --mirror` kopiert AUCH GitHubs interne, "versteckte"
  Referenzen fuer Pull Requests (refs/pull/123/head, refs/pull/123/merge).
  Diese darf ein normaler Nutzer nicht selbst schreiben - versucht
  `git push --mirror` das trotzdem (weil --mirror wirklich ALLES
  ueberträgt), lehnt das Ziel diese eine Referenz ab und der GESAMTE
  Push-Befehl gilt als fehlgeschlagen, OBWOHL die eigentlich wichtigen
  Branches/Tags meist schon uebertragen wurden.
  LOESUNG: Statt `--mirror` wird jetzt gezielt NUR
  `refs/heads/*` (Branches) und `refs/tags/*` (Tags) gepusht, mit
  `--prune` (damit im Ziel geloeschte Branches/Tags auch dort entfernt
  werden). Das ist alles, was fuer ein Backup zaehlt, und umgeht das
  Problem mit den GitHub-internen PR-Referenzen komplett.

  FIX B) Ungueltige GitLab-Projektnamen (z.B. "World-ID-"):
  GitLab verbietet Projekt-PFADE, die mit '-', '_' oder '.' beginnen
  oder enden. Repo-Namen wie "World-ID-" (Bindestrich am Ende) wurden
  deshalb bei der Anlage abgelehnt.
  LOESUNG: sanitize_gitlab_path() entfernt automatisch fuehrende/
  abschliessende Sonderzeichen, bevor der Name als GitLab-Pfad
  verwendet wird. Der ANZEIGE-Name ("name"-Feld) bleibt unveraendert,
  nur der URL-Pfad ("path"-Feld) wird bereinigt.

  FIX C) Google-Drive-Upload-Reihenfolge:
  Bisher wurde die alte ZIP-Datei ZUERST geloescht und DANACH die neue
  hochgeladen. Schlaegt der Upload fehl (z.B. Netzwerkfehler, auch nach
  allen Retries), gab es zwischenzeitlich GAR KEIN Backup mehr auf
  Google Drive fuer dieses Repo.
  LOESUNG: Reihenfolge umgedreht - ERST wird die neue ZIP-Datei
  hochgeladen, ERST DANACH (bei Erfolg) wird die alte Datei geloescht.

  ---------------------------------------------------------------
  FIXES NACH DEM DRITTEN TESTLAUF (22.08.2026, abends):
  ---------------------------------------------------------------

  FIX D) Google-Drive-Suche in Shared Drives war UNZUVERLAESSIG:
  `files().list()` findet Dateien/Ordner in einem Shared Drive NUR
  zuverlaessig, wenn zusaetzlich zu `supportsAllDrives=True` und
  `includeItemsFromAllDrives=True` auch `corpora="drive"` UND die
  konkrete `driveId` des Shared Drives mitgegeben werden. Ohne das
  lieferte die Suche nach der "alten" ZIP-Datei manchmal KEINEN
  Treffer, obwohl die Datei existierte - das Skript lud dann eine
  weitere, doppelte ZIP hoch, statt die alte zu ersetzen. Ueber
  mehrere Laeufe hinweg haeuften sich so Dutzende Duplikate pro Repo
  an (beobachtet: ~330 ZIPs statt ~156).
  Das erklaert vermutlich auch die vorherigen "File not found beim
  Loeschen"-Fehler: Der Such-Index eines Shared Drives ohne korrekte
  `corpora`/`driveId`-Angabe kann veraltete/inkonsistente Treffer
  liefern (Datei-ID wird gefunden, existiert aber schon nicht mehr).
  LOESUNG:
    - Beim ersten Zugriff wird EINMALIG die driveId des Shared Drives
      ermittelt, in dem GDRIVE_FOLDER_ID liegt (ueber files().get).
    - Ab dann verwenden ALLE Ordner-/Datei-Suchen `corpora="drive"`
      und diese `driveId` - das ist die von Google empfohlene,
      zuverlaessige Methode fuer Shared Drives.
    - Falls GDRIVE_FOLDER_ID NICHT in einem Shared Drive liegt
      (z.B. normale "Meine Ablage"), wird ganz normal ohne corpora/
      driveId gesucht (Verhalten wie vorher, unveraendert).

  FIX E) Alte Dateien wurden nur "irgendwie" (erste Seite) gesucht:
  Die Suche nach existierenden ZIPs holte nur eine einzelne Ergebnis-
  Seite. Bei bereits vorhandenen Duplikaten (z.B. durch FIX D
  verursacht) wurden dadurch nicht alle Alt-Versionen gefunden/
  bereinigt.
  LOESUNG: Die Suche blaettert jetzt vollstaendig durch alle Seiten
  (list_all_drive_files) und loescht ALLE gefundenen Alt-Dateien mit
  demselben Namen - das Skript heilt bestehende Duplikate dadurch
  von selbst ueber die naechsten paar Laeufe aus.

  FIX F) 404 ("File not found") beim Loeschen wurde bisher wie ein
  echter Fehler behandelt (3x wiederholt, dann als FEHLER gemeldet),
  obwohl eine bereits nicht mehr existierende Datei zu loeschen
  eigentlich KEIN Problem ist (Ziel "Datei soll weg sein" ist ja
  laengst erreicht).
  LOESUNG: Ein 404 beim Loeschen wird jetzt abgefangen, nur als Info
  geloggt (nicht als Fehler gezaehlt) und NICHT mehr wiederholt.

  FIX G) Ordner-Auswahl war nicht deterministisch, falls es (z.B.
  durch Fix D verursacht) mehrere Ordner mit demselben Namen
  "Repo_Backups" gab: `existing[0]` haette je nach Laufzeit-Zufall
  mal den einen, mal den anderen Ordner zurueckgeben koennen - Dateien
  waeren dann quer ueber zwei Ordner verteilt gelandet.
  LOESUNG: Ordner-Suche nutzt jetzt `orderBy="createdTime"` und nimmt
  IMMER konsequent den AELTESTEN Ordner. Werden mehrere Ordner
  gleichen Namens gefunden, wird das zusaetzlich als Warnung geloggt,
  damit man es manuell in Drive bereinigen kann (Duplikat-Ordner
  automatisch zusammenzufuehren waere riskanter als einmal manuell
  nachzusehen).

  ---------------------------------------------------------------
  BESTEHENDE FUNKTIONSWEISE:
  ---------------------------------------------------------------

  ZIEL 3 (GitLab-Account #2) legt bei JEDEM Lauf ein KOMPLETT NEUES
  Projekt an - benannt nach dem Schema:

      <repo-name>_<TT>_<MM>_<JJJJ>_<hh>_<mm>_<am/pm>

  Beispiel: mein-repo_22_08_2026_07_10_pm

  Das ist eine zusaetzliche Absicherung gegen Force-Push/History-
  Rewrite im Original: Waehrend die ueberschreibenden Mirrors (Ziel 1,
  2, 4) so eine nachtraegliche Manipulation der Commit-Historie beim
  naechsten Lauf "brav nachvollziehen" wuerden, bleibt bei
  GitLab-Account #2 JEDER jemals gesicherte Stand fuer immer als
  eigenes, unveraendertes Projekt bestehen.

  Der Zeitstempel wird in UTC berechnet (GitHub-Actions-Runner laufen
  in UTC) - er kann daher 1-2 Stunden von deiner lokalen Uhrzeit
  (Muenchen) abweichen. Das ist kein Fehler.

  Da bei Ziel 3 JEDEN Lauf 156 neue Projekte entstehen (bei 4
  Laeufen/Tag also ~624 neue Projekte PRO TAG), waechst die
  Projektanzahl auf GitLab-Account #2 kontinuierlich und unbegrenzt.
  Es gibt KEINE automatische Bereinigung alter Staende - das ist
  Absicht (maximale Paranoia/Sicherheit vor Speicherersparnis).

  RETRY-LOGIK: Alle Netzwerk-Operationen (HTTP-Requests UND
  Git-Befehle) werden bei Fehlschlag automatisch bis zu 3x wiederholt
  (mit kurzer, ansteigender Pause dazwischen).

  Jedes Ziel hat einen EIGENEN try/except-Block pro Repo - schlaegt
  eines fehl, werden die anderen fuer dasselbe Repo trotzdem versucht.

  GitLab-Existenz-Check per direkter Pfad-Abfrage statt Such-API (die
  Such-API durchsucht sonst ALLE oeffentlichen GitLab-Projekte
  weltweit und liefert bei generischen Namen falsche Treffer).

  (Bitbucket wurde bewusst NICHT eingebaut: 1 GB Gesamtspeicher-Limit
  im kostenlosen Plan.)

  VARIABLEN-NAMEN: GitHub reserviert das Praefix "GITHUB_" fuer sich
  selbst - deshalb "SRC_GH_..." und "BACKUP_GH_..." statt "GITHUB_...".

  GOOGLE DRIVE: Dienstkonten brauchen zwingend eine geteilte Ablage
  (Shared Drive), kein eigenes Speicherkontingent fuer "Meine Ablage".

  DESIGN-ZIEL: Laeuft in einem OEFFENTLICHEN GitHub-Repo (unbegrenzte,
  kostenlose Actions-Minuten), OHNE dass aus den Actions-Logs ablesbar
  ist, welche Repos gesichert werden (Konsole zeigt nur "Repo 3/156").
  Alle Details landen ausschliesslich in der Google-Chat-Zusammenfassung.

  FESTPLATTEN-MANAGEMENT: Standard-Runner haben nur 14 GB SSD. Nach
  jedem einzelnen Repo wird der lokale Mirror-Ordner SOFORT geloescht.
====================================================================
"""

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
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
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")

# --- Ziel 1: zweiter GitHub-Account (optional, überschreibt)
BACKUP_GH_TOKEN = env("BACKUP_GH_TOKEN")
BACKUP_GH_OWNER = env("BACKUP_GH_OWNER")
BACKUP_GH_OWNER_TYPE = env("BACKUP_GH_OWNER_TYPE", default="user")

# --- Ziel 2: GitLab-Account #1 (optional, überschreibt/mirrort)
GITLAB_TOKEN = env("GITLAB_TOKEN")
GITLAB_NAMESPACE = env("GITLAB_NAMESPACE")
GITLAB_URL = env("GITLAB_URL", default="https://gitlab.com")

# --- Ziel 3: GitLab-Account #2 (optional, legt JEDEN Lauf neue,
#     datierte Projekte an - siehe Modul-Docstring oben)
GITLAB2_TOKEN = env("GITLAB2_TOKEN")
GITLAB2_NAMESPACE = env("GITLAB2_NAMESPACE")
GITLAB2_URL = env("GITLAB2_URL", default="https://gitlab.com")

# --- Ziel 4: Google Drive (optional)
GDRIVE_FOLDER_ID = env("GDRIVE_FOLDER_ID")
GDRIVE_SA_JSON = env("GDRIVE_SA_JSON")
GDRIVE_BACKUP_FOLDER_NAME = env("GDRIVE_BACKUP_FOLDER_NAME", default="Repo_Backups")

# --- Zusammenfassung für Benachrichtigung (Google Chat, siehe backup.yml)
SUMMARY_FILE = Path(env("EMAIL_SUMMARY_FILE", default="email_summary.txt"))

# --- Allgemein
WORKDIR = Path(env("BACKUP_WORKDIR", default="mirrors"))
GIT_TIMEOUT_SECONDS = int(env("GIT_TIMEOUT_SECONDS", default="1800"))

CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO = env("CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO", default="true").lower() == "true"
QUIET_CONSOLE = env("QUIET_CONSOLE", default="true").lower() == "true"

MAX_RETRIES = int(env("MAX_RETRIES", default="3"))
RETRY_BASE_DELAY_SECONDS = float(env("RETRY_BASE_DELAY_SECONDS", default="3"))

_SECRETS = [s for s in [
    SRC_GH_TOKEN, BACKUP_GH_TOKEN, GITLAB_TOKEN, GITLAB2_TOKEN, GDRIVE_SA_JSON,
] if s]


def redact(text: str) -> str:
    for s in _SECRETS:
        if s and s in text:
            text = text.replace(s, "***REDACTED***")
    return text


# ====================================================================
#  LOGGING: Konsole = anonym/leer. Summary-Datei = vollstaendig.
# ====================================================================

SUMMARY_LINES = []
_repo_total = 0
_repo_index = 0


def summary_log(msg: str):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    SUMMARY_LINES.append(f"[{ts}] {redact(str(msg))}")


def console_heartbeat(msg: str = None):
    if QUIET_CONSOLE:
        if msg:
            print(msg, flush=True)
        else:
            print(f"... Verarbeite Repo {_repo_index}/{_repo_total} ...", flush=True)
    else:
        print(msg or f"Repo {_repo_index}/{_repo_total}", flush=True)


# ====================================================================
#  RETRY-HELFER
# ====================================================================

def with_retry(func, description: str):
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return func()
        except Exception as e:  # noqa: BLE001
            last_error = e
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY_SECONDS * attempt
                summary_log(f"     (Versuch {attempt}/{MAX_RETRIES} fehlgeschlagen bei '{description}': {e} "
                            f"- neuer Versuch in {delay:.0f}s)")
                time.sleep(delay)
            else:
                summary_log(f"     (Endgültig fehlgeschlagen nach {MAX_RETRIES} Versuchen bei '{description}': {e})")
    raise last_error


def run(cmd, cwd=None, timeout=GIT_TIMEOUT_SECONDS, description: str = None):
    def _attempt():
        try:
            result = subprocess.run(
                cmd, cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout,
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(redact(f"Git-Befehl fehlgeschlagen: {e.stderr}"))
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Timeout nach {timeout}s bei einem Git-Befehl.")

    return with_retry(_attempt, description or " ".join(cmd[:2]))


def http_get(url, headers=None, params=None, timeout=30, description: str = None):
    def _attempt():
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code >= 500:
            raise RuntimeError(f"Serverfehler HTTP {r.status_code} bei {url}")
        return r

    return with_retry(_attempt, description or f"GET {url}")


def http_post(url, headers=None, json_body=None, auth=None, timeout=30, description: str = None):
    def _attempt():
        r = requests.post(url, headers=headers, json=json_body, auth=auth, timeout=timeout)
        if r.status_code >= 500:
            raise RuntimeError(f"Serverfehler HTTP {r.status_code} bei {url}")
        return r

    return with_retry(_attempt, description or f"POST {url}")


def now_iso():
    return datetime.now(timezone.utc).isoformat()


def make_run_timestamp_suffix() -> str:
    """
    Erzeugt EINEN Zeitstempel fuer den GESAMTEN Lauf. Format:
    TT_MM_JJJJ_hh_mm_am/pm, in UTC. Beispiel: 22_08_2026_07_10_pm
    """
    now = datetime.now(timezone.utc)
    date_part = now.strftime("%d_%m_%Y")
    time_part = now.strftime("%I_%M_%p").lower()
    return f"{date_part}_{time_part}"


# ====================================================================
#  FIX B: GitLab-Pfad-Bereinigung
#  GitLab-Projekt-Pfade duerfen nicht mit '-', '_' oder '.' beginnen
#  oder enden, und nur Buchstaben/Ziffern/'-'/'_'/'.' enthalten.
# ====================================================================

def sanitize_gitlab_path(name: str) -> str:
    # Ungueltige Zeichen durch '-' ersetzen (GitLab erlaubt nur
    # Buchstaben, Ziffern, '_', '-', '.')
    cleaned = re.sub(r"[^a-zA-Z0-9_.\-]", "-", name)
    # Fuehrende/abschliessende Sonderzeichen entfernen (GitLab-Regel)
    cleaned = cleaned.strip("-_.")
    # Darf nicht auf .git oder .atom enden
    for suffix in (".git", ".atom"):
        if cleaned.lower().endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            cleaned = cleaned.strip("-_.")
    if not cleaned:
        cleaned = "repo"
    return cleaned


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
        r = http_get(base, headers=headers, params=params, timeout=60, description="Quell-Repos auflisten")
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
    return repos


# ====================================================================
#  2) LOKALES BARE-MIRROR anlegen (immer frisch)
# ====================================================================

def mirror_clone_local(repo_name: str, source_clone_url_with_token: str) -> Path:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    bare_path = WORKDIR / f"{repo_name}.git"
    if bare_path.exists():
        shutil.rmtree(bare_path)
    summary_log(f"  -> klone {repo_name}")
    run(["git", "clone", "--mirror", source_clone_url_with_token, str(bare_path)],
        description=f"klonen {repo_name}")
    return bare_path


def push_branches_and_tags(bare_path: Path, target_url_with_token: str, label: str):
    """
    FIX A: Statt `git push --mirror` (das ALLES ueberträgt, inkl.
    GitHubs interner "hidden refs" fuer Pull Requests, was zu "deny
    updating a hidden ref"-Fehlern fuehrt) werden hier GEZIELT nur
    Branches und Tags gepusht - das ist alles, was fuer ein Backup
    zaehlt. --prune sorgt dafuer, dass im Ziel geloeschte Branches/Tags
    auch dort entfernt werden (entspricht weiterhin einem echten Mirror
    fuer den Code-Inhalt selbst).
    """
    summary_log(f"  -> spiegle nach {label}")
    try:
        run([
            "git", "--git-dir", str(bare_path), "push", "--prune",
            target_url_with_token,
            "+refs/heads/*:refs/heads/*",
            "+refs/tags/*:refs/tags/*",
        ], description=f"push (heads+tags) nach {label}")
    except RuntimeError as e:
        if "up-to-date" in str(e).lower() or "everything up-to-date" in str(e).lower():
            summary_log(f"     ({label}: bereits aktuell)")
        else:
            raise


def cleanup_local_mirror(bare_path: Path):
    if CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO and bare_path and bare_path.exists():
        shutil.rmtree(bare_path, ignore_errors=True)


# ====================================================================
#  3) ZIEL-REPOS bei Bedarf anlegen
# ====================================================================

def ensure_github_target_repo(name: str):
    """Ziel 1: Direkter Lookup, legt bei Bedarf EINMALIG an (danach ueberschreiben/mirrorn)."""
    headers = {"Authorization": f"token {BACKUP_GH_TOKEN}", "Accept": "application/vnd.github+json"}
    check_url = f"https://api.github.com/repos/{BACKUP_GH_OWNER}/{name}"
    r = http_get(check_url, headers=headers, timeout=30, description=f"GitHub-Backup-Repo pruefen ({name})")
    if r.status_code == 200:
        return
    create_url = (f"https://api.github.com/orgs/{BACKUP_GH_OWNER}/repos"
                   if BACKUP_GH_OWNER_TYPE == "org" else "https://api.github.com/user/repos")
    r = http_post(create_url, headers=headers, json_body={"name": name, "private": True},
                  timeout=30, description=f"GitHub-Backup-Repo anlegen ({name})")
    if r.status_code not in (201, 422):
        raise RuntimeError(redact(f"GitHub-Backup-Repo konnte nicht angelegt werden: {r.text}"))
    summary_log(f"  -> GitHub-Backup-Repo '{name}' neu angelegt")


def _gitlab_namespace_id_if_group(url: str, token: str, namespace: str):
    headers = {"PRIVATE-TOKEN": token}
    encoded_ns = urllib.parse.quote(namespace, safe="")
    ns_r = http_get(f"{url}/api/v4/namespaces/{encoded_ns}", headers=headers, timeout=30,
                     description="GitLab-Namespace ermitteln")
    if ns_r.status_code == 200:
        ns_data = ns_r.json()
        if ns_data.get("kind") == "group":
            return ns_data["id"]
    return None


def ensure_gitlab_target_repo(name: str) -> str:
    """
    Ziel 2 (GitLab-Account #1): Direkter Pfad-Lookup mit bereinigtem
    Pfad (FIX B). Gibt den tatsaechlich verwendeten Pfad zurueck (kann
    vom Original-Namen abweichen, falls bereinigt wurde).
    """
    safe_path = sanitize_gitlab_path(name)
    headers = {"PRIVATE-TOKEN": GITLAB_TOKEN}
    project_path = f"{GITLAB_NAMESPACE}/{safe_path}"
    encoded_path = urllib.parse.quote(project_path, safe="")
    check_url = f"{GITLAB_URL}/api/v4/projects/{encoded_path}"

    r = http_get(check_url, headers=headers, timeout=30, description=f"GitLab-#1-Projekt pruefen ({safe_path})")
    if r.status_code == 200:
        return safe_path

    payload = {"name": name, "path": safe_path, "visibility": "private"}
    ns_id = _gitlab_namespace_id_if_group(GITLAB_URL, GITLAB_TOKEN, GITLAB_NAMESPACE)
    if ns_id:
        payload["namespace_id"] = ns_id

    r = http_post(f"{GITLAB_URL}/api/v4/projects", headers=headers, json_body=payload,
                  timeout=30, description=f"GitLab-#1-Projekt anlegen ({safe_path})")
    if r.status_code != 201:
        raise RuntimeError(redact(f"GitLab-Projekt konnte nicht angelegt werden: {r.text}"))
    if safe_path != name:
        summary_log(f"  -> GitLab-Projekt '{safe_path}' neu angelegt (Name bereinigt aus '{name}')")
    else:
        summary_log(f"  -> GitLab-Projekt '{safe_path}' neu angelegt")
    return safe_path


def create_gitlab2_dated_project(dated_name: str) -> str:
    """
    Ziel 3 (GitLab-Account #2): Legt IMMER ein NEUES Projekt an. Der
    Pfad wird ebenfalls bereinigt (FIX B). Gibt den tatsaechlich
    verwendeten Pfad zurueck.
    """
    safe_path = sanitize_gitlab_path(dated_name)
    headers = {"PRIVATE-TOKEN": GITLAB2_TOKEN}
    payload = {"name": dated_name, "path": safe_path, "visibility": "private"}
    ns_id = _gitlab_namespace_id_if_group(GITLAB2_URL, GITLAB2_TOKEN, GITLAB2_NAMESPACE)
    if ns_id:
        payload["namespace_id"] = ns_id

    r = http_post(f"{GITLAB2_URL}/api/v4/projects", headers=headers, json_body=payload,
                  timeout=30, description=f"GitLab-#2-Projekt anlegen ({safe_path})")
    if r.status_code != 201:
        raise RuntimeError(redact(f"GitLab-Account-#2-Projekt konnte nicht angelegt werden: {r.text}"))
    summary_log(f"  -> GitLab-Account-#2: neues datiertes Projekt '{safe_path}' angelegt")
    time.sleep(0.3)  # Rate-Limit-Schonung bei 156 Anlagen pro Lauf
    return safe_path


# ====================================================================
#  4) GOOGLE DRIVE Backup
#  (ueberschreibt - alte Zip wird ERST NACH erfolgreichem Upload der
#  neuen Zip geloescht, siehe FIX C. Suche jetzt zuverlaessig ueber
#  corpora="drive"+driveId, siehe FIX D/E/F/G oben im Modul-Docstring.)
# ====================================================================

_drive_service = None
_drive_backup_folder_id = None
_drive_shared_drive_id = None
_drive_shared_drive_id_resolved = False


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


def get_shared_drive_id(service) -> str | None:
    """
    FIX D: Ermittelt EINMALIG die driveId des Shared Drives, in dem
    GDRIVE_FOLDER_ID liegt (falls es ueberhaupt in einem Shared Drive
    liegt - bei normaler "Meine Ablage" gibt es keine driveId, dann
    wird None zurueckgegeben und ganz normal weitergesucht wie vorher).
    Diese driveId wird danach bei JEDER Suche mit corpora="drive"
    verwendet - das ist die von Google empfohlene, zuverlaessige
    Methode fuer Suchen innerhalb von Shared Drives.
    """
    global _drive_shared_drive_id, _drive_shared_drive_id_resolved
    if _drive_shared_drive_id_resolved:
        return _drive_shared_drive_id

    try:
        info = with_retry(
            lambda: service.files().get(
                fileId=GDRIVE_FOLDER_ID, supportsAllDrives=True, fields="driveId",
            ).execute(),
            "Shared-Drive-ID ermitteln",
        )
        _drive_shared_drive_id = info.get("driveId")
    except Exception as e:  # noqa: BLE001
        summary_log(f"Hinweis: Shared-Drive-ID konnte nicht ermittelt werden ({e}) - "
                    f"nutze Standard-Suche ohne corpora/driveId.")
        _drive_shared_drive_id = None

    _drive_shared_drive_id_resolved = True
    if _drive_shared_drive_id:
        summary_log(f"Shared-Drive erkannt (driveId ermittelt) - nutze zuverlaessige Drive-Suche.")
    else:
        summary_log(f"GDRIVE_FOLDER_ID liegt nicht in einem Shared Drive (oder driveId nicht ermittelbar) - "
                    f"nutze Standard-Suche.")
    return _drive_shared_drive_id


def _drive_list_kwargs(service, query: str, fields: str):
    """Baut die kwargs fuer files().list() - inkl. corpora/driveId, falls Shared Drive (FIX D)."""
    kwargs = dict(
        q=query, fields=fields,
        supportsAllDrives=True, includeItemsFromAllDrives=True,
        pageSize=100,
    )
    drive_id = get_shared_drive_id(service)
    if drive_id:
        kwargs["corpora"] = "drive"
        kwargs["driveId"] = drive_id
    return kwargs


def list_all_drive_files(service, query: str, fields: str = "files(id, name, createdTime)"):
    """
    FIX E: Blaettert vollstaendig durch ALLE Ergebnis-Seiten (nicht nur
    die erste), damit auch mehrere bereits vorhandene Duplikate
    zuverlaessig gefunden werden.
    """
    results = []
    page_token = None
    while True:
        kwargs = _drive_list_kwargs(service, query, fields)
        if page_token:
            kwargs["pageToken"] = page_token
        response = with_retry(
            lambda kwargs=kwargs: service.files().list(**kwargs).execute(),
            "Google-Drive-Suche",
        )
        results.extend(response.get("files", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return results


def delete_drive_file_if_exists(service, file_id: str, description: str):
    """
    FIX F: Ein 404 ("File not found") beim Loeschen bedeutet, dass die
    Datei bereits nicht mehr existiert - das Ziel ist also schon
    erreicht. Das wird jetzt NICHT mehr als Fehler gewertet und NICHT
    mehr wiederholt (spart unnoetige Retry-Wartezeit).
    """
    try:
        service.files().delete(fileId=file_id, supportsAllDrives=True).execute()
    except Exception as e:  # noqa: BLE001
        if "404" in str(e) or "notFound" in str(e) or "File not found" in str(e):
            summary_log(f"     ({description}: Datei war bereits geloescht - ok)")
            return
        # Bei allen anderen Fehlern (z.B. Netzwerk, 5xx) ganz normal mit Retry versuchen
        with_retry(
            lambda: service.files().delete(fileId=file_id, supportsAllDrives=True).execute(),
            description,
        )


def ensure_drive_backup_folder(service) -> str:
    """
    FIX G: Nimmt bei mehreren gleichnamigen Ordnern IMMER konsequent
    den AELTESTEN (orderBy=createdTime) - deterministisch statt
    zufaellig. Warnt zusaetzlich im Log, falls Duplikate gefunden
    wurden (damit man sie manuell zusammenfuehren/loeschen kann).
    """
    global _drive_backup_folder_id
    if _drive_backup_folder_id:
        return _drive_backup_folder_id

    query = (
        f"name = '{GDRIVE_BACKUP_FOLDER_NAME}' and '{GDRIVE_FOLDER_ID}' in parents "
        f"and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    )
    existing = list_all_drive_files(service, query, fields="files(id, createdTime)")
    # Deterministisch sortieren: aeltester Ordner zuerst
    existing.sort(key=lambda f: f.get("createdTime", ""))

    if existing:
        if len(existing) > 1:
            summary_log(f"WARNUNG: {len(existing)} Ordner namens '{GDRIVE_BACKUP_FOLDER_NAME}' gefunden - "
                        f"verwende den aeltesten. Bitte pruefe/bereinige das manuell in Google Drive, "
                        f"sonst koennen Backups auf mehrere Ordner verteilt werden.")
        _drive_backup_folder_id = existing[0]["id"]
        summary_log(f"Google-Drive-Backup-Ordner '{GDRIVE_BACKUP_FOLDER_NAME}' gefunden (wird verwendet).")
        return _drive_backup_folder_id

    folder = with_retry(
        lambda: service.files().create(
            body={
                "name": GDRIVE_BACKUP_FOLDER_NAME,
                "mimeType": "application/vnd.google-apps.folder",
                "parents": [GDRIVE_FOLDER_ID],
            },
            fields="id",
            supportsAllDrives=True,
        ).execute(),
        "Google-Drive-Backup-Ordner anlegen",
    )
    _drive_backup_folder_id = folder["id"]
    summary_log(f"Google-Drive-Backup-Ordner '{GDRIVE_BACKUP_FOLDER_NAME}' neu angelegt.")
    return _drive_backup_folder_id


def backup_to_drive(bare_path: Path, repo_name: str):
    """
    Reihenfolge (FIX C): ERST wird die neue ZIP-Datei hochgeladen,
    ERST DANACH (nur bei Erfolg) werden alte, gleichnamige Dateien
    geloescht - so gibt es nie eine Luecke ohne Backup.

    FIX D/E/F: Suche nach Alt-Dateien ist jetzt zuverlaessig (corpora/
    driveId, vollstaendige Pagination) und loescht ALLE gefundenen
    Alt-Versionen (heilt bestehende Duplikate von selbst aus). 404
    beim Loeschen wird als "ok, schon weg" behandelt.
    """
    from googleapiclient.http import MediaFileUpload

    service = get_drive_service()
    target_folder_id = ensure_drive_backup_folder(service)
    zip_name = f"{repo_name}.git.zip"

    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / zip_name
        summary_log(f"  -> packe für Google Drive")
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for file in bare_path.rglob("*"):
                if file.is_file():
                    zf.write(file, arcname=str(file.relative_to(bare_path.parent)))

        # --- Schritt 1: ALLE alten Datei(en) mit gleichem Namen suchen (noch nicht loeschen) ---
        query = f"name = '{zip_name}' and '{target_folder_id}' in parents and trashed = false"
        existing = list_all_drive_files(service, query, fields="files(id, createdTime)")
        if len(existing) > 1:
            summary_log(f"     ({len(existing)} alte Duplikate von '{zip_name}' gefunden - werden bereinigt)")

        # --- Schritt 2: NEUE Datei hochladen (die alte(n) bleiben bis hierhin unangetastet) ---
        summary_log(f"  -> lade zu Google Drive hoch")
        media = MediaFileUpload(str(zip_path), mimetype="application/zip", resumable=True)
        with_retry(
            lambda: service.files().create(
                body={"name": zip_name, "parents": [target_folder_id]},
                media_body=media,
                fields="id",
                supportsAllDrives=True,
            ).execute(),
            f"Drive-Upload ({repo_name})",
        )

        # --- Schritt 3: erst JETZT (nach erfolgreichem Upload) ALLE alten Datei(en) loeschen ---
        for f in existing:
            delete_drive_file_if_exists(service, f["id"], f"alte Drive-Datei löschen ({repo_name})")


# ====================================================================
#  HAUPTPROGRAMM
# ====================================================================

def process_repo(repo: dict, run_timestamp_suffix: str) -> bool:
    name = repo["name"]
    summary_log(f"--- {name} ---")
    bare_path = None
    overall_ok = True

    try:
        source_url = repo["clone_url"].replace("https://", f"https://{SRC_GH_TOKEN}@")
        bare_path = mirror_clone_local(name, source_url)
    except Exception as e:  # noqa: BLE001
        summary_log(f"  !! FEHLER beim Klonen von {name}: {e}")
        return False

    # --- Ziel 1: zweiter GitHub-Account (ueberschreibt) ---
    if BACKUP_GH_TOKEN and BACKUP_GH_OWNER:
        try:
            ensure_github_target_repo(name)
            target = f"https://{BACKUP_GH_TOKEN}@github.com/{BACKUP_GH_OWNER}/{name}.git"
            push_branches_and_tags(bare_path, target, "GitHub-Backup-Account")
        except Exception as e:  # noqa: BLE001
            summary_log(f"  !! FEHLER (GitHub-Backup) bei {name}: {e}")
            overall_ok = False

    # --- Ziel 2: GitLab-Account #1 (ueberschreibt/mirrort) ---
    if GITLAB_TOKEN and GITLAB_NAMESPACE:
        try:
            safe_path = ensure_gitlab_target_repo(name)
            gitlab_host = GITLAB_URL.replace("https://", "")
            target = f"https://oauth2:{GITLAB_TOKEN}@{gitlab_host}/{GITLAB_NAMESPACE}/{safe_path}.git"
            push_branches_and_tags(bare_path, target, "GitLab-Account-#1")
        except Exception as e:  # noqa: BLE001
            summary_log(f"  !! FEHLER (GitLab-Account-#1) bei {name}: {e}")
            overall_ok = False

    # --- Ziel 3: GitLab-Account #2 (IMMER neues, datiertes Projekt) ---
    if GITLAB2_TOKEN and GITLAB2_NAMESPACE:
        try:
            dated_name = f"{name}_{run_timestamp_suffix}"
            safe_dated_path = create_gitlab2_dated_project(dated_name)
            gitlab2_host = GITLAB2_URL.replace("https://", "")
            target = f"https://oauth2:{GITLAB2_TOKEN}@{gitlab2_host}/{GITLAB2_NAMESPACE}/{safe_dated_path}.git"
            push_branches_and_tags(bare_path, target, "GitLab-Account-#2 (datiert)")
        except Exception as e:  # noqa: BLE001
            summary_log(f"  !! FEHLER (GitLab-Account-#2) bei {name}: {e}")
            overall_ok = False

    # --- Ziel 4: Google Drive (ueberschreibt) ---
    if GDRIVE_SA_JSON and GDRIVE_FOLDER_ID:
        try:
            backup_to_drive(bare_path, name)
        except Exception as e:  # noqa: BLE001
            summary_log(f"  !! FEHLER (Google Drive) bei {name}: {e}")
            overall_ok = False

    cleanup_local_mirror(bare_path)

    if overall_ok:
        summary_log(f"  OK ({name})")
    return overall_ok


def main():
    global _repo_total, _repo_index

    start_time = datetime.now(timezone.utc)
    run_timestamp_suffix = make_run_timestamp_suffix()
    console_heartbeat("Backup gestartet.")
    summary_log("===== Repo-Backup gestartet =====")
    summary_log(f"Zeitstempel für GitLab-Account-#2 (datierte Projekte, UTC): {run_timestamp_suffix}")

    ok, failed, failed_names = 0, 0, []

    try:
        repos = list_source_repos()
        _repo_total = len(repos)
        summary_log(f"{_repo_total} Quell-Repos gefunden.")

        for i, repo in enumerate(repos, start=1):
            _repo_index = i
            console_heartbeat()
            success = process_repo(repo, run_timestamp_suffix)
            if success:
                ok += 1
            else:
                failed += 1
                failed_names.append(repo["name"])

    except Exception as e:  # noqa: BLE001
        summary_log(f"!! SCHWERWIEGENDER FEHLER, Lauf abgebrochen: {e}")
        summary_log(redact(traceback.format_exc()))

    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    summary_line = f"===== Fertig: {ok} ok, {failed} Fehler von {ok + failed} Repos. Dauer: {int(duration)}s ====="
    summary_log(summary_line)
    console_heartbeat("Backup beendet.")

    subject_status = "OK" if failed == 0 else f"{failed} FEHLER"
    header = (
        f"Backup-Zusammenfassung ({subject_status})\n"
        f"Repos gesamt: {ok + failed} | erfolgreich (ALLE Ziele ok): {ok} | mit mind. 1 Fehler: {failed}\n"
        f"Dauer: {int(duration)} Sekunden\n"
        f"GitLab-#2-Zeitstempel dieses Laufs (UTC): {run_timestamp_suffix}\n"
    )
    if failed_names:
        header += "Repos mit mindestens einem Fehler: " + ", ".join(failed_names) + "\n"
    header += "\n----- Vollständiges Protokoll -----\n"

    SUMMARY_FILE.write_text(header + "\n".join(SUMMARY_LINES) + "\n", encoding="utf-8")
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
