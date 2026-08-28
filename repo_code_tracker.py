#!/usr/bin/env python3
"""
====================================================================
  REPO CODE-TRACKER  (Public-Repo-Safe Version, Google Sheets)
--------------------------------------------------------------------
  Geht durch ALLE Repos eines GitHub-Accounts (gleiche Quelle wie
  repo_backup.py), listet fuer jedes Repo saemtliche Dateien UND
  Ordner auf, zaehlt pro Datei die Codezeilen (NUR die Anzahl, NIEMALS
  der Dateiinhalt selbst wird irgendwo gespeichert) und schreibt das
  Ergebnis in EIN einziges Google Sheet auf Google Drive.

  Laeuft alle 6 Stunden (4x taeglich) per GitHub Action.

  ---------------------------------------------------------------
  AUFBAU DES GOOGLE SHEETS (immer dasselbe Sheet, nie ein neues):
  ---------------------------------------------------------------

  Tab "Overview":
      Eine Zeile pro Repo mit Gesamtzahlen (Dateien, Ordner,
      Codezeilen, Status Active/Removed, erstmals/zuletzt gesehen).

  Tab "Changelog":
      Ein einziges, chronologisches, NUR WACHSENDES Protokoll aller
      jemals erkannten Aenderungen (Datei hinzugefuegt/entfernt/
      geaendert, Repo hinzugefuegt/entfernt). Hier wird NIE etwas
      geloescht oder ueberschrieben, nur angehaengt.

  Ein Tab PRO REPO (Name = bereinigter Repo-Name):
      Eine Zeile pro Datei/Ordner mit Pfad, Typ, Codezeilen, Status,
      "erstmals gesehen", "zuletzt gesehen", "zuletzt geaendert".

  ---------------------------------------------------------------
  GRUNDPRINZIP: NUR ERGAENZEN, NIE ENTFERNEN
  ---------------------------------------------------------------

  - Neue Datei/neuer Ordner taucht auf     -> NEUE Zeile wird angehaengt.
  - Datei/Ordner verschwindet              -> Zeile bleibt STEHEN,
                                               Status wird "Removed",
                                               Zeile wird ROT markiert.
  - Datei/Ordner taucht wieder auf         -> Status wird wieder
                                               "Active", rote Markierung
                                               verschwindet, Vorgang wird
                                               im Changelog vermerkt.
  - Codezeilen-Anzahl einer Datei aendert
    sich                                    -> Zeile wird AKTUALISIERT
                                               (Zahl wird ersetzt), UND
                                               ein Eintrag landet im
                                               Changelog (alt -> neu).
  - Ganzes Repo verschwindet aus GitHub    -> Overview-Zeile bleibt
                                               STEHEN, wird rot markiert
                                               und Status "Removed".
                                               Der zugehoerige Datei-Tab
                                               bleibt unveraendert stehen
                                               (letzter bekannter Stand).
  - Es wird NIE eine Zeile geloescht und NIE ein komplettes Sheet neu
    angelegt - immer dasselbe Dokument wird weiter bearbeitet.

  ---------------------------------------------------------------
  GITHUB-LINK-SPALTE:
  ---------------------------------------------------------------

  Jede Zeile in einem Repo-Tab enthaelt zusaetzlich zum reinen Pfad
  eine Spalte "GitHub-Link" mit einer `=HYPERLINK(...)`-Formel, die
  direkt auf die Datei (bzw. bei Ordnern auf den Ordner) im Standard-
  Branch des Repos auf GitHub verweist. Dafuer wird der von der
  GitHub-API gelieferte `default_branch` des jeweiligen Repos
  verwendet (Fallback: "main", falls das Feld fehlen sollte). Damit
  diese Formeln von Google Sheets auch als Formeln (nicht als reiner
  Text) interpretiert werden, schreibt das Skript alle Werte mit
  `valueInputOption="USER_ENTERED"` statt "RAW".

  ---------------------------------------------------------------
  TECHNISCHE HINWEISE:
  ---------------------------------------------------------------

  - Pro Repo wird ein FLACHER Klon (`git clone --depth 1`) gemacht -
    das ist viel leichter als der volle Mirror-Klon aus
    repo_backup.py, weil hier nur der aktuelle Stand gezaehlt werden
    muss, nicht die komplette Historie. Der lokale Klon wird nach
    jedem Repo sofort wieder geloescht.
  - Binaerdateien (Bilder, ZIPs, etc.) werden erkannt (Null-Byte-Check
    bzw. UTF-8-Dekodierfehler) und mit Codezeilen = leer / Hinweis
    "binary" markiert statt einen falschen Wert einzutragen.
  - Das Sheet wird ueber Google Drive gesucht (Name + Ordner), nicht
    ueber eine gespeicherte ID im Repo - dadurch ist kein Schreibzugriff
    auf das Git-Repo noetig und es bleibt sicher fuer ein OEFFENTLICHES
    Repo (keine Tokens, keine IDs muessen dafuer versioniert werden).
  - GRENZEN VON GOOGLE SHEETS: Ein Spreadsheet darf insgesamt max. ca.
    10 Millionen Zellen enthalten (ueber ALLE Tabs zusammen). Bei ~200
    Repos mit vielen Dateien kann das theoretisch relevant werden -
    falls die Grenze erreicht wird, meldet die Google-Sheets-API einen
    Fehler beim Schreiben, was dann im Changelog-Fehlerblock in der
    Zusammenfassung auftaucht.
  - Tab-Namen duerfen laut Google Sheets keine der Zeichen
    : \\ / ? * [ ] enthalten und max. 100 Zeichen lang sein - das wird
    automatisch bereinigt (sanitize_sheet_title). Bei Namenskollisionen
    (zwei Repos ergeben nach Bereinigung denselben Tab-Namen) wird
    automatisch eine fortlaufende Nummer angehaengt.
  - Sicherheits-/Oeffentlichkeits-Prinzip identisch zu repo_backup.py:
    Konsole bleibt bewusst still (nur "Repo x/y"), alle Tokens werden
    in jeder Fehlermeldung redigiert, Details landen ausschliesslich
    im (privaten) Google Sheet bzw. optional in der Google-Chat-
    Zusammenfassung.
====================================================================
"""

import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path

import requests

# ====================================================================
#  CONFIG - alles kommt aus Umgebungsvariablen
# ====================================================================

def env(name, required=False, default=None):
    val = os.environ.get(name, default)
    if required and not val:
        print(f"FEHLER: Pflicht-Konfiguration fehlt (Name absichtlich nicht angezeigt).")
        sys.exit(1)
    return val

# --- Quelle: derselbe GitHub-Account wie bei repo_backup.py ---
SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")

# --- Google Drive / Sheets (dieselbe Ablage wie bei repo_backup.py) ---
GDRIVE_FOLDER_ID = env("GDRIVE_FOLDER_ID", required=True)
GDRIVE_SA_JSON = env("GDRIVE_SA_JSON", required=True)
GSHEET_NAME = env("GSHEET_NAME", default="Repo_Code_Tracking")

# --- Zusammenfassung fuer optionale Google-Chat-Benachrichtigung ---
SUMMARY_FILE = Path(env("EMAIL_SUMMARY_FILE", default="code_tracker_summary.txt"))

# --- Allgemein ---
WORKDIR = Path(env("TRACKER_WORKDIR", default="tracker_clones"))
GIT_TIMEOUT_SECONDS = int(env("GIT_TIMEOUT_SECONDS", default="900"))
QUIET_CONSOLE = env("QUIET_CONSOLE", default="true").lower() == "true"
MAX_RETRIES = int(env("MAX_RETRIES", default="3"))
RETRY_BASE_DELAY_SECONDS = float(env("RETRY_BASE_DELAY_SECONDS", default="3"))
SLEEP_BETWEEN_REPOS_SECONDS = float(env("SLEEP_BETWEEN_REPOS_SECONDS", default="0.4"))

_SECRETS = [s for s in [SRC_GH_TOKEN, GDRIVE_SA_JSON] if s]


def redact(text: str) -> str:
    for s in _SECRETS:
        if s and s in text:
            text = text.replace(s, "***REDACTED***")
    return text


# ====================================================================
#  LOGGING
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
#  RETRY-HELFER (identisch zum Prinzip aus repo_backup.py)
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


def now_str() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


# ====================================================================
#  1) QUELLE: Repo-Liste von GitHub holen (gleiche Logik wie
#     repo_backup.py)
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
#  2) FLACHER KLON + DATEIBAUM EINLESEN
# ====================================================================

def shallow_clone(repo_name: str, source_clone_url_with_token: str) -> Path:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    target = WORKDIR / repo_name
    if target.exists():
        shutil.rmtree(target)
    run(["git", "clone", "--depth", "1", "--single-branch", "--quiet",
         source_clone_url_with_token, str(target)],
        description=f"flach klonen {repo_name}")
    return target


def count_lines(path: Path):
    """
    Zaehlt NUR die Anzahl der Zeilen einer Datei - der Inhalt selbst
    wird nirgendwo gespeichert oder weitergegeben. Erkennt Binaer-
    dateien ueber ein Null-Byte im ersten Chunk bzw. ueber einen
    UTF-8-Dekodierfehler und zaehlt diese NICHT als Codezeilen.
    """
    try:
        with open(path, "rb") as fh:
            chunk = fh.read(8192)
        if b"\x00" in chunk:
            return None, "binary"
        with open(path, "r", encoding="utf-8", errors="strict") as fh:
            count = sum(1 for _ in fh)
        return count, ""
    except UnicodeDecodeError:
        return None, "binary/non-utf8"
    except Exception as e:  # noqa: BLE001
        return None, f"unlesbar: {e}"


def scan_repo_tree(root: Path):
    """
    Liefert eine sortierte Liste aller Dateien UND Ordner (relativ zum
    Repo-Root), jeweils mit Typ, Codezeilen (nur bei Dateien) und
    einem optionalen Hinweis (z.B. "binary").
    """
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir != ".":
            entries.append({
                "path": rel_dir.replace(os.sep, "/"), "type": "folder",
                "lines": None, "note": "",
            })
        for fn in filenames:
            full = Path(dirpath) / fn
            rel = os.path.relpath(full, root).replace(os.sep, "/")
            lines, note = count_lines(full)
            entries.append({"path": rel, "type": "file", "lines": lines, "note": note})
    entries.sort(key=lambda e: e["path"])
    return entries


def cleanup_local_clone(path: Path):
    if path and path.exists():
        shutil.rmtree(path, ignore_errors=True)


# ====================================================================
#  3) GOOGLE DRIVE + SHEETS: Zugriff, Suche, Anlegen
# ====================================================================

_drive_service = None
_sheets_service = None
_shared_drive_id = None
_shared_drive_id_resolved = False


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


def get_sheets_service():
    global _sheets_service
    if _sheets_service is not None:
        return _sheets_service
    from google.oauth2 import service_account
    from googleapiclient.discovery import build

    info = json.loads(GDRIVE_SA_JSON)
    creds = service_account.Credentials.from_service_account_info(
        info, scopes=[
            "https://www.googleapis.com/auth/spreadsheets",
            "https://www.googleapis.com/auth/drive",
        ]
    )
    _sheets_service = build("sheets", "v4", credentials=creds)
    return _sheets_service


def get_shared_drive_id(drive_service) -> str | None:
    """Siehe FIX D in repo_backup.py - zuverlaessige Suche in Shared Drives."""
    global _shared_drive_id, _shared_drive_id_resolved
    if _shared_drive_id_resolved:
        return _shared_drive_id
    try:
        info = with_retry(
            lambda: drive_service.files().get(
                fileId=GDRIVE_FOLDER_ID, supportsAllDrives=True, fields="driveId",
            ).execute(),
            "Shared-Drive-ID ermitteln",
        )
        _shared_drive_id = info.get("driveId")
    except Exception as e:  # noqa: BLE001
        summary_log(f"Hinweis: Shared-Drive-ID konnte nicht ermittelt werden ({e}).")
        _shared_drive_id = None
    _shared_drive_id_resolved = True
    return _shared_drive_id


def _drive_list_all(drive_service, query: str, fields: str):
    results = []
    page_token = None
    drive_id = get_shared_drive_id(drive_service)
    while True:
        kwargs = dict(
            q=query, fields=fields,
            supportsAllDrives=True, includeItemsFromAllDrives=True, pageSize=100,
        )
        if drive_id:
            kwargs["corpora"] = "drive"
            kwargs["driveId"] = drive_id
        if page_token:
            kwargs["pageToken"] = page_token
        response = with_retry(
            lambda kwargs=kwargs: drive_service.files().list(**kwargs).execute(),
            "Google-Drive-Suche",
        )
        results.extend(response.get("files", []))
        page_token = response.get("nextPageToken")
        if not page_token:
            break
    return results


def find_or_create_spreadsheet() -> str:
    """
    Sucht das Sheet ueber Name+Ordner in Google Drive (KEINE ID wird
    im Git-Repo gespeichert - dadurch bleibt das ganze public-repo-
    sicher). Existiert es nicht, wird es einmalig neu angelegt und der
    Standard-Tab "Sheet1" in "Overview" umbenannt.
    """
    drive_service = get_drive_service()
    query = (
        f"name = '{GSHEET_NAME}' and '{GDRIVE_FOLDER_ID}' in parents "
        f"and mimeType = 'application/vnd.google-apps.spreadsheet' and trashed = false"
    )
    existing = _drive_list_all(drive_service, query, fields="files(id, createdTime)")
    existing.sort(key=lambda f: f.get("createdTime", ""))

    if existing:
        if len(existing) > 1:
            summary_log(f"WARNUNG: {len(existing)} Sheets namens '{GSHEET_NAME}' gefunden - "
                        f"verwende das aelteste. Bitte manuell in Drive bereinigen.")
        summary_log(f"Bestehendes Sheet '{GSHEET_NAME}' gefunden - wird weiterverwendet.")
        return existing[0]["id"]

    summary_log(f"Kein Sheet '{GSHEET_NAME}' gefunden - lege neues an.")
    created = with_retry(
        lambda: drive_service.files().create(
            body={
                "name": GSHEET_NAME,
                "mimeType": "application/vnd.google-apps.spreadsheet",
                "parents": [GDRIVE_FOLDER_ID],
            },
            fields="id",
            supportsAllDrives=True,
        ).execute(),
        "Sheet anlegen",
    )
    spreadsheet_id = created["id"]

    # Den von Google automatisch angelegten Standard-Tab "Sheet1" in
    # "Overview" umbenennen, damit kein leerer Extra-Tab herumliegt.
    sheets_service = get_sheets_service()
    meta = with_retry(
        lambda: sheets_service.spreadsheets().get(
            spreadsheetId=spreadsheet_id, fields="sheets.properties(sheetId,title)",
        ).execute(),
        "Sheet-Metadaten lesen (nach Anlage)",
    )
    first_sheet_id = meta["sheets"][0]["properties"]["sheetId"]
    with_retry(
        lambda: sheets_service.spreadsheets().batchUpdate(
            spreadsheetId=spreadsheet_id,
            body={"requests": [{
                "updateSheetProperties": {
                    "properties": {"sheetId": first_sheet_id, "title": "Overview"},
                    "fields": "title",
                },
            }]},
        ).execute(),
        "Standard-Tab in 'Overview' umbenennen",
    )
    summary_log(f"Neues Sheet '{GSHEET_NAME}' angelegt (Standard-Tab in 'Overview' umbenannt).")
    return spreadsheet_id


# ====================================================================
#  4) TAB-VERWALTUNG (anlegen, Header schreiben, Cache der Tab-IDs)
# ====================================================================

OVERVIEW_HEADER = [
    "Repo", "Status", "Dateien", "Ordner", "Codezeilen",
    "Erstmals gesehen (UTC)", "Zuletzt gesehen (UTC)", "Zuletzt geändert (UTC)", "Sheet-Tab",
]
CHANGELOG_HEADER = [
    "Zeitstempel (UTC)", "Repo", "Pfad", "Änderung", "Alt (Zeilen)", "Neu (Zeilen)", "Hinweis",
]
REPO_TAB_HEADER = [
    "Pfad", "GitHub-Link", "Typ", "Codezeilen", "Status",
    "Erstmals gesehen (UTC)", "Zuletzt gesehen (UTC)", "Zuletzt geändert (UTC)", "Hinweis",
]

RED_FORMAT = {"backgroundColor": {"red": 0.96, "green": 0.80, "blue": 0.80}}
CLEAR_FORMAT = {"backgroundColor": {"red": 1.0, "green": 1.0, "blue": 1.0}}

_FORBIDDEN_TAB_CHARS = re.compile(r"[:\\/\?\*\[\]]")
_used_tab_titles = set()


def build_github_link(owner: str, repo_name: str, branch: str, path: str, entry_type: str) -> str:
    """
    Baut eine =HYPERLINK(...)-Formel, die direkt auf die Datei (Typ
    "file" -> /blob/) bzw. den Ordner (Typ "folder" -> /tree/) im
    angegebenen Branch auf GitHub verweist. Der Pfad wird fuer die URL
    korrekt escaped (Leerzeichen/Sonderzeichen), Schraegstriche bleiben
    als Trenner erhalten. Anfuehrungszeichen im sichtbaren Label werden
    verdoppelt, damit die Formel gueltig bleibt.
    """
    encoded_path = urllib.parse.quote(path, safe="/")
    kind = "tree" if entry_type == "folder" else "blob"
    url = f"https://github.com/{owner}/{repo_name}/{kind}/{branch}/{encoded_path}"
    safe_label = path.replace('"', '""')
    return f'=HYPERLINK("{url}", "{safe_label}")'


def sanitize_sheet_title(name: str) -> str:
    cleaned = _FORBIDDEN_TAB_CHARS.sub("-", name).strip()
    if not cleaned:
        cleaned = "repo"
    cleaned = cleaned[:95]  # Puffer fuer evtl. Suffix lassen (Limit ist 100)
    base = cleaned
    suffix = 2
    while cleaned.lower() in _used_tab_titles:
        cleaned = f"{base}_{suffix}"
        suffix += 1
    _used_tab_titles.add(cleaned.lower())
    return cleaned


class SheetManager:
    """Buendelt Tab-Cache, Lese-/Schreibzugriffe fuer ein Spreadsheet."""

    def __init__(self, spreadsheet_id: str):
        self.spreadsheet_id = spreadsheet_id
        self.service = get_sheets_service()
        self.tab_ids = {}  # title -> sheetId
        self._load_existing_tabs()

    def _load_existing_tabs(self):
        meta = with_retry(
            lambda: self.service.spreadsheets().get(
                spreadsheetId=self.spreadsheet_id, fields="sheets.properties(sheetId,title)",
            ).execute(),
            "Sheet-Tabs laden",
        )
        for s in meta.get("sheets", []):
            props = s["properties"]
            self.tab_ids[props["title"]] = props["sheetId"]
            _used_tab_titles.add(props["title"].lower())

    def ensure_tab(self, title: str, header: list) -> int:
        if title in self.tab_ids:
            return self.tab_ids[title]
        response = with_retry(
            lambda: self.service.spreadsheets().batchUpdate(
                spreadsheetId=self.spreadsheet_id,
                body={"requests": [{"addSheet": {"properties": {"title": title}}}]},
            ).execute(),
            f"Tab '{title}' anlegen",
        )
        sheet_id = response["replies"][0]["addSheet"]["properties"]["sheetId"]
        self.tab_ids[title] = sheet_id
        with_retry(
            lambda: self.service.spreadsheets().values().update(
                spreadsheetId=self.spreadsheet_id,
                range=f"'{title}'!A1",
                valueInputOption="USER_ENTERED",
                body={"values": [header]},
            ).execute(),
            f"Header fuer '{title}' schreiben",
        )
        return sheet_id

    def get_values(self, title: str) -> list:
        response = with_retry(
            lambda: self.service.spreadsheets().values().get(
                spreadsheetId=self.spreadsheet_id, range=f"'{title}'!A:Z",
            ).execute(),
            f"Werte aus '{title}' lesen",
        )
        return response.get("values", [])

    def append_rows(self, title: str, rows: list):
        if not rows:
            return
        with_retry(
            lambda: self.service.spreadsheets().values().append(
                spreadsheetId=self.spreadsheet_id,
                range=f"'{title}'!A1",
                valueInputOption="USER_ENTERED",
                insertDataOption="INSERT_ROWS",
                body={"values": rows},
            ).execute(),
            f"Zeilen an '{title}' anhaengen",
        )

    def batch_update_values(self, updates: list):
        """updates: Liste von (range, values_2d) Tupeln."""
        if not updates:
            return
        data = [{"range": r, "values": v} for r, v in updates]
        with_retry(
            lambda: self.service.spreadsheets().values().batchUpdate(
                spreadsheetId=self.spreadsheet_id,
                body={"valueInputOption": "USER_ENTERED", "data": data},
            ).execute(),
            "Zellwerte aktualisieren",
        )

    def flush_formatting(self, format_requests: list):
        if not format_requests:
            return
        chunk_size = 200
        for i in range(0, len(format_requests), chunk_size):
            chunk = format_requests[i:i + chunk_size]
            with_retry(
                lambda chunk=chunk: self.service.spreadsheets().batchUpdate(
                    spreadsheetId=self.spreadsheet_id, body={"requests": chunk},
                ).execute(),
                "Zeilen-Formatierung anwenden",
            )


def make_format_request(sheet_id: int, row_number_1based: int, num_cols: int, red: bool):
    """row_number_1based = Zeilennummer WIE IM SHEET (Header = Zeile 1)."""
    fmt = RED_FORMAT if red else CLEAR_FORMAT
    return {
        "repeatCell": {
            "range": {
                "sheetId": sheet_id,
                "startRowIndex": row_number_1based - 1,
                "endRowIndex": row_number_1based,
                "startColumnIndex": 0,
                "endColumnIndex": num_cols,
            },
            "cell": {"userEnteredFormat": fmt},
            "fields": "userEnteredFormat.backgroundColor",
        },
    }


# ====================================================================
#  5) DIFF-LOGIK PRO REPO-TAB (Dateien/Ordner)
# ====================================================================

def process_repo_tab(mgr: SheetManager, tab_title: str, current_entries: list,
                      changelog_rows: list, format_requests: list,
                      owner: str, repo_name: str, branch: str):
    """
    Spalten-Layout (0-basiert):
      0 Pfad | 1 GitHub-Link | 2 Typ | 3 Codezeilen | 4 Status |
      5 Erstmals gesehen | 6 Zuletzt gesehen | 7 Zuletzt geändert | 8 Hinweis
    """
    header = REPO_TAB_HEADER
    sheet_id = mgr.ensure_tab(tab_title, header)
    ts = now_str()

    existing_rows = mgr.get_values(tab_title)
    data_rows = existing_rows[1:] if len(existing_rows) > 1 else []

    existing_map = {}
    for i, row in enumerate(data_rows):
        row = row + [""] * (len(header) - len(row))
        existing_map[row[0]] = {"row_number": i + 2, "values": row}

    current_map = {e["path"]: e for e in current_entries}

    new_rows = []
    value_updates = []

    for path, entry in current_map.items():
        lines_str = "" if entry["lines"] is None else str(entry["lines"])
        link_formula = build_github_link(owner, repo_name, branch, path, entry["type"])

        if path not in existing_map:
            new_rows.append([path, link_formula, entry["type"], lines_str, "Active",
                              ts, ts, ts, entry["note"]])
            changelog_rows.append([ts, tab_title, path, "Hinzugefügt", "", lines_str, entry["note"]])
            continue

        old = existing_map[path]["values"]
        row_number = existing_map[path]["row_number"]
        old_status, old_lines, old_first_seen, old_last_changed = old[4], old[3], old[5], old[7]
        changed = False

        if old_status != "Active":
            changed = True
            changelog_rows.append([ts, tab_title, path, "Wieder aufgetaucht (war entfernt)",
                                    old_lines, lines_str, entry["note"]])
            format_requests.append(make_format_request(sheet_id, row_number, len(header), red=False))

        if entry["type"] == "file" and old_lines != lines_str:
            changelog_rows.append([ts, tab_title, path, "Geändert (Codezeilen)",
                                    old_lines, lines_str, entry["note"]])
            changed = True

        last_changed = ts if changed else old_last_changed
        # Spalten B (GitHub-Link) bis I (Hinweis) - Link wird bei jedem
        # Lauf aktualisiert (falls sich z.B. der Default-Branch aendert).
        value_updates.append((
            f"'{tab_title}'!B{row_number}:I{row_number}",
            [[link_formula, entry["type"], lines_str, "Active", old_first_seen, ts,
              last_changed, entry["note"]]],
        ))

    for path, info in existing_map.items():
        if path in current_map:
            continue
        if info["values"][4] != "Active":
            continue  # war schon als entfernt markiert - nichts zu tun
        row_number = info["row_number"]
        old = info["values"]
        changelog_rows.append([ts, tab_title, path, "Entfernt", old[3], "", ""])
        # Spalten E (Status) bis H (Zuletzt geändert)
        value_updates.append((
            f"'{tab_title}'!E{row_number}:H{row_number}",
            [["Removed", old[5], old[6], ts]],
        ))
        format_requests.append(make_format_request(sheet_id, row_number, len(header), red=True))

    mgr.append_rows(tab_title, new_rows)
    mgr.batch_update_values(value_updates)

    files_count = sum(1 for e in current_map.values() if e["type"] == "file")
    folders_count = sum(1 for e in current_map.values() if e["type"] == "folder")
    lines_total = sum(e["lines"] for e in current_map.values() if e["type"] == "file" and e["lines"] is not None)
    return {"files": files_count, "folders": folders_count, "lines": lines_total}


# ====================================================================
#  6) OVERVIEW-TAB PFLEGEN (Repo-Ebene)
# ====================================================================

def load_overview_map(mgr: SheetManager):
    rows = mgr.get_values("Overview")
    data_rows = rows[1:] if len(rows) > 1 else []
    result = {}
    for i, row in enumerate(data_rows):
        row = row + [""] * (len(OVERVIEW_HEADER) - len(row))
        result[row[0]] = {"row_number": i + 2, "values": row}
    return result


def update_overview_for_repo(mgr: SheetManager, overview_map: dict, repo_name: str,
                              tab_title: str, stats: dict, changelog_rows: list,
                              format_requests: list, new_overview_rows: list,
                              overview_value_updates: list):
    ts = now_str()
    lines_str, files_str, folders_str = str(stats["lines"]), str(stats["files"]), str(stats["folders"])
    sheet_id = mgr.tab_ids["Overview"]

    if repo_name not in overview_map:
        new_overview_rows.append([repo_name, "Active", files_str, folders_str, lines_str,
                                   ts, ts, ts, tab_title])
        changelog_rows.append([ts, repo_name, "(gesamtes Repo)", "Repo hinzugefügt", "", "", ""])
        return

    old = overview_map[repo_name]["values"]
    row_number = overview_map[repo_name]["row_number"]
    old_status, old_files, old_folders, old_lines = old[1], old[2], old[3], old[4]
    old_first_seen, old_last_changed = old[5], old[7]
    changed = False

    if old_status != "Active":
        changed = True
        changelog_rows.append([ts, repo_name, "(gesamtes Repo)", "Repo wieder aufgetaucht", "", "", ""])
        format_requests.append(make_format_request(sheet_id, row_number, len(OVERVIEW_HEADER), red=False))

    if (old_files, old_folders, old_lines) != (files_str, folders_str, lines_str):
        changed = True

    last_changed = ts if changed else old_last_changed
    overview_value_updates.append((
        f"'Overview'!B{row_number}:I{row_number}",
        [["Active", files_str, folders_str, lines_str, old_first_seen, ts, last_changed, tab_title]],
    ))


def mark_overview_repos_removed(mgr: SheetManager, overview_map: dict, current_repo_names: set,
                                 changelog_rows: list, format_requests: list, overview_value_updates: list):
    ts = now_str()
    sheet_id = mgr.tab_ids["Overview"]
    for repo_name, info in overview_map.items():
        if repo_name in current_repo_names:
            continue
        if info["values"][1] != "Active":
            continue
        row_number = info["row_number"]
        old = info["values"]
        changelog_rows.append([ts, repo_name, "(gesamtes Repo)", "Repo entfernt", "", "", ""])
        overview_value_updates.append((
            f"'Overview'!B{row_number}:H{row_number}",
            [["Removed", old[2], old[3], old[4], old[5], old[6], ts]],
        ))
        format_requests.append(make_format_request(sheet_id, row_number, len(OVERVIEW_HEADER), red=True))


# ====================================================================
#  HAUPTPROGRAMM
# ====================================================================

def main():
    global _repo_total, _repo_index

    start_time = datetime.now(timezone.utc)
    console_heartbeat("Code-Tracker gestartet.")
    summary_log("===== Repo-Code-Tracker gestartet =====")

    changelog_rows = []
    ok, failed, failed_names = 0, 0, []

    try:
        repos = list_source_repos()
        _repo_total = len(repos)
        summary_log(f"{_repo_total} Quell-Repos gefunden.")

        spreadsheet_id = find_or_create_spreadsheet()
        mgr = SheetManager(spreadsheet_id)
        mgr.ensure_tab("Overview", OVERVIEW_HEADER)
        mgr.ensure_tab("Changelog", CHANGELOG_HEADER)

        overview_map = load_overview_map(mgr)
        overview_format_requests = []
        overview_value_updates = []
        new_overview_rows = []
        current_repo_names = {r["name"] for r in repos}

        for i, repo in enumerate(repos, start=1):
            _repo_index = i
            console_heartbeat()
            name = repo["name"]
            summary_log(f"--- {name} ---")
            clone_path = None
            try:
                source_url = repo["clone_url"].replace("https://", f"https://{SRC_GH_TOKEN}@")
                clone_path = shallow_clone(name, source_url)
                entries = scan_repo_tree(clone_path)
                branch = repo.get("default_branch") or "main"

                tab_title = sanitize_sheet_title(name)
                repo_format_requests = []
                stats = process_repo_tab(mgr, tab_title, entries, changelog_rows, repo_format_requests,
                                          owner=SRC_GH_OWNER, repo_name=name, branch=branch)
                mgr.flush_formatting(repo_format_requests)

                update_overview_for_repo(
                    mgr, overview_map, name, tab_title, stats, changelog_rows,
                    overview_format_requests, new_overview_rows, overview_value_updates,
                )
                summary_log(f"  OK ({name}): {stats['files']} Dateien, {stats['folders']} Ordner, "
                            f"{stats['lines']} Codezeilen")
                ok += 1
            except Exception as e:  # noqa: BLE001
                summary_log(f"  !! FEHLER bei {name}: {e}")
                failed += 1
                failed_names.append(name)
            finally:
                cleanup_local_clone(clone_path)
            time.sleep(SLEEP_BETWEEN_REPOS_SECONDS)

        mark_overview_repos_removed(mgr, overview_map, current_repo_names,
                                     changelog_rows, overview_format_requests, overview_value_updates)
        mgr.append_rows("Overview", new_overview_rows)
        mgr.batch_update_values(overview_value_updates)
        mgr.flush_formatting(overview_format_requests)
        mgr.append_rows("Changelog", changelog_rows)

    except Exception as e:  # noqa: BLE001
        summary_log(f"!! SCHWERWIEGENDER FEHLER, Lauf abgebrochen: {e}")
        summary_log(redact(traceback.format_exc()))

    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    summary_line = (f"===== Fertig: {ok} ok, {failed} Fehler von {ok + failed} Repos. "
                     f"{len(changelog_rows)} Änderungen protokolliert. Dauer: {int(duration)}s =====")
    summary_log(summary_line)
    console_heartbeat("Code-Tracker beendet.")

    subject_status = "OK" if failed == 0 else f"{failed} FEHLER"
    header = (
        f"Code-Tracker-Zusammenfassung ({subject_status})\n"
        f"Repos gesamt: {ok + failed} | ok: {ok} | mit Fehler: {failed}\n"
        f"Änderungen in diesem Lauf: {len(changelog_rows)}\n"
        f"Dauer: {int(duration)} Sekunden\n"
    )
    if failed_names:
        header += "Repos mit Fehler: " + ", ".join(failed_names) + "\n"
    header += "\n----- Vollständiges Protokoll -----\n"

    SUMMARY_FILE.write_text(header + "\n".join(SUMMARY_LINES) + "\n", encoding="utf-8")
    sys.exit(1 if failed > 0 else 0)


if __name__ == "__main__":
    main()
