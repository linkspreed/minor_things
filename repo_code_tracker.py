#!/usr/bin/env python3
import json
import os
import re
import shutil
import subprocess
import sys
import time
import traceback
import urllib.parse
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
import requests

def env(name, required=False, default=None):
    val = os.environ.get(name, default)
    if required and (not val):
        sys.exit(1)
    return val
SRC_GH_TOKEN = env('SRC_GH_TOKEN', required=True)
SRC_GH_OWNER = env('SRC_GH_OWNER', required=True)
SRC_GH_OWNER_TYPE = env('SRC_GH_OWNER_TYPE', default='user')
GDRIVE_FOLDER_ID = env('GDRIVE_FOLDER_ID', required=True)
GDRIVE_SA_JSON = env('GDRIVE_SA_JSON', required=True)
GSHEET_NAME = env('GSHEET_NAME', default='Repo_Code_Tracking')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='code_tracker_summary.txt'))
WORKDIR = Path(env('TRACKER_WORKDIR', default='tracker_clones'))
GIT_TIMEOUT_SECONDS = int(env('GIT_TIMEOUT_SECONDS', default='900'))
QUIET_CONSOLE = env('QUIET_CONSOLE', default='true').lower() == 'true'
MAX_RETRIES = int(env('MAX_RETRIES', default='3'))
RETRY_BASE_DELAY_SECONDS = float(env('RETRY_BASE_DELAY_SECONDS', default='3'))
SLEEP_BETWEEN_REPOS_SECONDS = float(env('SLEEP_BETWEEN_REPOS_SECONDS', default='0.4'))
SHEETS_MAX_CALLS_PER_MINUTE = int(env('SHEETS_MAX_CALLS_PER_MINUTE', default='45'))
SHEETS_QUOTA_BACKOFF_SECONDS = float(env('SHEETS_QUOTA_BACKOFF_SECONDS', default='65'))
MAX_REPO_TABS = int(env('MAX_REPO_TABS', default='195'))
_SECRETS = [s for s in [SRC_GH_TOKEN, GDRIVE_SA_JSON] if s]

def redact(text: str) -> str:
    for s in _SECRETS:
        if s and s in text:
            text = text.replace(s, '***REDACTED***')
    return text
SUMMARY_LINES = []
_repo_total = 0
_repo_index = 0

def summary_log(msg: str):
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    SUMMARY_LINES.append(f'[{ts}] {redact(str(msg))}')

def console_heartbeat(msg: str=None):
    if QUIET_CONSOLE:
        if msg:
            pass
        else:
            pass
    else:
        pass

class SheetsRateLimiter:

    def __init__(self, max_calls_per_minute: int):
        self.max_calls = max_calls_per_minute
        self.timestamps = deque()

    def wait_if_needed(self):
        now = time.monotonic()
        while self.timestamps and now - self.timestamps[0] > 60:
            self.timestamps.popleft()
        if len(self.timestamps) >= self.max_calls:
            sleep_for = 60 - (now - self.timestamps[0]) + 0.5
            if sleep_for > 0:
                time.sleep(sleep_for)
            now = time.monotonic()
            while self.timestamps and now - self.timestamps[0] > 60:
                self.timestamps.popleft()
        self.timestamps.append(time.monotonic())
_sheets_rate_limiter = SheetsRateLimiter(SHEETS_MAX_CALLS_PER_MINUTE)

def _is_quota_error(exc: Exception) -> bool:
    text = str(exc).lower()
    return '429' in text or 'resource_exhausted' in text or 'quota exceeded' in text or ('rate limit' in text) or ('too many requests' in text)

def with_retry(func, description: str):
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return func()
        except Exception as e:
            last_error = e
            if attempt < MAX_RETRIES:
                if _is_quota_error(e):
                    delay = SHEETS_QUOTA_BACKOFF_SECONDS
                    summary_log(f"     (Rate-Limit erkannt bei '{description}' - warte {delay:.0f}s auf naechstes Quota-Fenster, dann Versuch {attempt + 1}/{MAX_RETRIES})")
                else:
                    delay = RETRY_BASE_DELAY_SECONDS * attempt
                    summary_log(f"     (Versuch {attempt}/{MAX_RETRIES} fehlgeschlagen bei '{description}': {e} - neuer Versuch in {delay:.0f}s)")
                time.sleep(delay)
            else:
                summary_log(f"     (Endgültig fehlgeschlagen nach {MAX_RETRIES} Versuchen bei '{description}': {e})")
    raise last_error

def with_retry_sheets(func, description: str):

    def _throttled():
        _sheets_rate_limiter.wait_if_needed()
        return func()
    return with_retry(_throttled, description)

def run(cmd, cwd=None, timeout=GIT_TIMEOUT_SECONDS, description: str=None):

    def _attempt():
        try:
            result = subprocess.run(cmd, cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout)
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(redact(f'Git-Befehl fehlgeschlagen: {e.stderr}'))
        except subprocess.TimeoutExpired:
            raise RuntimeError(f'Timeout nach {timeout}s bei einem Git-Befehl.')
    return with_retry(_attempt, description or ' '.join(cmd[:2]))

def http_get(url, headers=None, params=None, timeout=30, description: str=None):

    def _attempt():
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code >= 500:
            raise RuntimeError(f'Serverfehler HTTP {r.status_code} bei {url}')
        return r
    return with_retry(_attempt, description or f'GET {url}')

def now_str() -> str:
    return datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')

def list_source_repos():
    repos = []
    page = 1
    base = f'https://api.github.com/orgs/{SRC_GH_OWNER}/repos' if SRC_GH_OWNER_TYPE == 'org' else 'https://api.github.com/user/repos'
    headers = {'Authorization': f'token {SRC_GH_TOKEN}', 'Accept': 'application/vnd.github+json'}
    while True:
        params = {'per_page': 100, 'page': page}
        if SRC_GH_OWNER_TYPE != 'org':
            params['affiliation'] = 'owner'
        r = http_get(base, headers=headers, params=params, timeout=60, description='Quell-Repos auflisten')
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
    return repos

def shallow_clone(repo_name: str, source_clone_url_with_token: str) -> Path:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    target = WORKDIR / repo_name
    if target.exists():
        shutil.rmtree(target)
    run(['git', 'clone', '--depth', '1', '--single-branch', '--quiet', source_clone_url_with_token, str(target)], description=f'flach klonen {repo_name}')
    return target

def count_lines(path: Path):
    try:
        with open(path, 'rb') as fh:
            chunk = fh.read(8192)
        if b'\x00' in chunk:
            return (None, 'binary')
        with open(path, 'r', encoding='utf-8', errors='strict') as fh:
            count = sum((1 for _ in fh))
        return (count, '')
    except UnicodeDecodeError:
        return (None, 'binary/non-utf8')
    except Exception as e:
        return (None, f'unlesbar: {e}')

def scan_repo_tree(root: Path):
    entries = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d != '.git']
        rel_dir = os.path.relpath(dirpath, root)
        if rel_dir != '.':
            entries.append({'path': rel_dir.replace(os.sep, '/'), 'type': 'folder', 'lines': None, 'note': ''})
        for fn in filenames:
            full = Path(dirpath) / fn
            rel = os.path.relpath(full, root).replace(os.sep, '/')
            lines, note = count_lines(full)
            entries.append({'path': rel, 'type': 'file', 'lines': lines, 'note': note})
    entries.sort(key=lambda e: e['path'])
    return entries

def compute_stats(entries: list) -> dict:
    files_count = sum((1 for e in entries if e['type'] == 'file'))
    folders_count = sum((1 for e in entries if e['type'] == 'folder'))
    lines_total = sum((e['lines'] for e in entries if e['type'] == 'file' and e['lines'] is not None))
    return {'files': files_count, 'folders': folders_count, 'lines': lines_total}

def cleanup_local_clone(path: Path):
    if path and path.exists():
        shutil.rmtree(path, ignore_errors=True)
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
    creds = service_account.Credentials.from_service_account_info(info, scopes=['https://www.googleapis.com/auth/drive'])
    _drive_service = build('drive', 'v3', credentials=creds)
    return _drive_service

def get_sheets_service():
    global _sheets_service
    if _sheets_service is not None:
        return _sheets_service
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    info = json.loads(GDRIVE_SA_JSON)
    creds = service_account.Credentials.from_service_account_info(info, scopes=['https://www.googleapis.com/auth/spreadsheets', 'https://www.googleapis.com/auth/drive'])
    _sheets_service = build('sheets', 'v4', credentials=creds)
    return _sheets_service

def get_shared_drive_id(drive_service) -> str | None:
    global _shared_drive_id, _shared_drive_id_resolved
    if _shared_drive_id_resolved:
        return _shared_drive_id
    try:
        info = with_retry(lambda: drive_service.files().get(fileId=GDRIVE_FOLDER_ID, supportsAllDrives=True, fields='driveId').execute(), 'Shared-Drive-ID ermitteln')
        _shared_drive_id = info.get('driveId')
    except Exception as e:
        summary_log(f'Hinweis: Shared-Drive-ID konnte nicht ermittelt werden ({e}).')
        _shared_drive_id = None
    _shared_drive_id_resolved = True
    return _shared_drive_id

def _drive_list_all(drive_service, query: str, fields: str):
    results = []
    page_token = None
    drive_id = get_shared_drive_id(drive_service)
    while True:
        kwargs = dict(q=query, fields=fields, supportsAllDrives=True, includeItemsFromAllDrives=True, pageSize=100)
        if drive_id:
            kwargs['corpora'] = 'drive'
            kwargs['driveId'] = drive_id
        if page_token:
            kwargs['pageToken'] = page_token
        response = with_retry(lambda kwargs=kwargs: drive_service.files().list(**kwargs).execute(), 'Google-Drive-Suche')
        results.extend(response.get('files', []))
        page_token = response.get('nextPageToken')
        if not page_token:
            break
    return results

def find_or_create_spreadsheet() -> str:
    drive_service = get_drive_service()
    query = f"name = '{GSHEET_NAME}' and '{GDRIVE_FOLDER_ID}' in parents and mimeType = 'application/vnd.google-apps.spreadsheet' and trashed = false"
    existing = _drive_list_all(drive_service, query, fields='files(id, createdTime)')
    existing.sort(key=lambda f: f.get('createdTime', ''))
    if existing:
        if len(existing) > 1:
            summary_log(f"WARNUNG: {len(existing)} Sheets namens '{GSHEET_NAME}' gefunden - verwende das aelteste. Bitte manuell in Drive bereinigen.")
        summary_log(f"Bestehendes Sheet '{GSHEET_NAME}' gefunden - wird weiterverwendet.")
        return existing[0]['id']
    summary_log(f"Kein Sheet '{GSHEET_NAME}' gefunden - lege neues an.")
    created = with_retry(lambda: drive_service.files().create(body={'name': GSHEET_NAME, 'mimeType': 'application/vnd.google-apps.spreadsheet', 'parents': [GDRIVE_FOLDER_ID]}, fields='id', supportsAllDrives=True).execute(), 'Sheet anlegen')
    spreadsheet_id = created['id']
    sheets_service = get_sheets_service()
    meta = with_retry_sheets(lambda: sheets_service.spreadsheets().get(spreadsheetId=spreadsheet_id, fields='sheets.properties(sheetId,title)').execute(), 'Sheet-Metadaten lesen (nach Anlage)')
    first_sheet_id = meta['sheets'][0]['properties']['sheetId']
    with_retry_sheets(lambda: sheets_service.spreadsheets().batchUpdate(spreadsheetId=spreadsheet_id, body={'requests': [{'updateSheetProperties': {'properties': {'sheetId': first_sheet_id, 'title': 'Overview'}, 'fields': 'title'}}, {'updateSpreadsheetProperties': {'properties': {'title': GSHEET_NAME}, 'fields': 'title'}}]}).execute(), 'Standard-Tab umbenennen + internen Dokumenttitel setzen')
    summary_log(f"Neues Sheet '{GSHEET_NAME}' angelegt (Titel gesetzt, Standard-Tab in 'Overview' umbenannt).")
    return spreadsheet_id
OVERVIEW_HEADER = ['Repo', 'Status', 'Dateien', 'Ordner', 'Codezeilen', 'Erstmals gesehen (UTC)', 'Zuletzt gesehen (UTC)', 'Zuletzt geändert (UTC)', 'Sheet-Tab']
CHANGELOG_HEADER = ['Zeitstempel (UTC)', 'Repo', 'Pfad', 'Änderung', 'Alt (Zeilen)', 'Neu (Zeilen)', 'Hinweis']
REPO_TAB_HEADER = ['Pfad', 'GitHub-Link', 'Typ', 'Codezeilen', 'Status', 'Erstmals gesehen (UTC)', 'Zuletzt gesehen (UTC)', 'Zuletzt geändert (UTC)', 'Hinweis']
RED_FORMAT = {'backgroundColor': {'red': 0.96, 'green': 0.8, 'blue': 0.8}}
CLEAR_FORMAT = {'backgroundColor': {'red': 1.0, 'green': 1.0, 'blue': 1.0}}
_FORBIDDEN_TAB_CHARS = re.compile('[:\\\\/\\?\\*\\[\\]]')
_used_tab_titles = set()

def build_github_link(owner: str, repo_name: str, branch: str, path: str, entry_type: str) -> str:
    encoded_path = urllib.parse.quote(path, safe='/')
    kind = 'tree' if entry_type == 'folder' else 'blob'
    url = f'https://github.com/{owner}/{repo_name}/{kind}/{branch}/{encoded_path}'
    safe_label = path.replace('"', '""')
    return f'=HYPERLINK("{url}", "{safe_label}")'

def sanitize_sheet_title(name: str) -> str:
    cleaned = _FORBIDDEN_TAB_CHARS.sub('-', name).strip()
    if not cleaned:
        cleaned = 'repo'
    cleaned = cleaned[:95]
    base = cleaned
    suffix = 2
    while cleaned.lower() in _used_tab_titles:
        cleaned = f'{base}_{suffix}'
        suffix += 1
    _used_tab_titles.add(cleaned.lower())
    return cleaned

class SheetManager:

    def __init__(self, spreadsheet_id: str):
        self.spreadsheet_id = spreadsheet_id
        self.service = get_sheets_service()
        self.tab_ids = {}
        self._load_existing_tabs()

    def _load_existing_tabs(self):
        meta = with_retry_sheets(lambda: self.service.spreadsheets().get(spreadsheetId=self.spreadsheet_id, fields='sheets.properties(sheetId,title)').execute(), 'Sheet-Tabs laden')
        for s in meta.get('sheets', []):
            props = s['properties']
            self.tab_ids[props['title']] = props['sheetId']
            _used_tab_titles.add(props['title'].lower())

    def tab_count(self) -> int:
        return len(self.tab_ids)

    def ensure_tab(self, title: str, header: list) -> tuple:
        if title in self.tab_ids:
            return (self.tab_ids[title], False)
        num_cols = len(header)
        response = with_retry_sheets(lambda: self.service.spreadsheets().batchUpdate(spreadsheetId=self.spreadsheet_id, body={'requests': [{'addSheet': {'properties': {'title': title}}}]}).execute(), f"Tab '{title}' anlegen")
        sheet_id = response['replies'][0]['addSheet']['properties']['sheetId']
        self.tab_ids[title] = sheet_id
        header_row = {'values': [{'userEnteredValue': {'stringValue': h}} for h in header]}
        with_retry_sheets(lambda: self.service.spreadsheets().batchUpdate(spreadsheetId=self.spreadsheet_id, body={'requests': [{'updateCells': {'rows': [header_row], 'fields': 'userEnteredValue', 'start': {'sheetId': sheet_id, 'rowIndex': 0, 'columnIndex': 0}}}]}).execute(), f"Header fuer '{title}' schreiben")
        return (sheet_id, True)

    def get_values(self, title: str) -> list:
        response = with_retry_sheets(lambda: self.service.spreadsheets().values().get(spreadsheetId=self.spreadsheet_id, range=f"'{title}'!A:Z").execute(), f"Werte aus '{title}' lesen")
        return response.get('values', [])

    def append_rows(self, title: str, rows: list):
        if not rows:
            return
        with_retry_sheets(lambda: self.service.spreadsheets().values().append(spreadsheetId=self.spreadsheet_id, range=f"'{title}'!A1", valueInputOption='USER_ENTERED', insertDataOption='INSERT_ROWS', body={'values': rows}).execute(), f"Zeilen an '{title}' anhaengen")

    def batch_update_values(self, updates: list):
        if not updates:
            return
        data = [{'range': r, 'values': v} for r, v in updates]
        with_retry_sheets(lambda: self.service.spreadsheets().values().batchUpdate(spreadsheetId=self.spreadsheet_id, body={'valueInputOption': 'USER_ENTERED', 'data': data}).execute(), 'Zellwerte aktualisieren')

    def flush_formatting(self, format_requests: list):
        if not format_requests:
            return
        chunk_size = 200
        for i in range(0, len(format_requests), chunk_size):
            chunk = format_requests[i:i + chunk_size]
            with_retry_sheets(lambda chunk=chunk: self.service.spreadsheets().batchUpdate(spreadsheetId=self.spreadsheet_id, body={'requests': chunk}).execute(), 'Zeilen-Formatierung anwenden')

def make_format_request(sheet_id: int, row_number_1based: int, num_cols: int, red: bool):
    fmt = RED_FORMAT if red else CLEAR_FORMAT
    return {'repeatCell': {'range': {'sheetId': sheet_id, 'startRowIndex': row_number_1based - 1, 'endRowIndex': row_number_1based, 'startColumnIndex': 0, 'endColumnIndex': num_cols}, 'cell': {'userEnteredFormat': fmt}, 'fields': 'userEnteredFormat.backgroundColor'}}

def process_repo_tab(mgr: SheetManager, tab_title: str, current_entries: list, changelog_rows: list, format_requests: list, owner: str, repo_name: str, branch: str):
    header = REPO_TAB_HEADER
    sheet_id, is_new_tab = mgr.ensure_tab(tab_title, header)
    ts = now_str()
    if is_new_tab:
        existing_rows = []
    else:
        existing_rows = mgr.get_values(tab_title)
    data_rows = existing_rows[1:] if len(existing_rows) > 1 else []
    existing_map = {}
    for i, row in enumerate(data_rows):
        row = row + [''] * (len(header) - len(row))
        existing_map[row[0]] = {'row_number': i + 2, 'values': row}
    current_map = {e['path']: e for e in current_entries}
    new_rows = []
    value_updates = []
    for path, entry in current_map.items():
        lines_str = '' if entry['lines'] is None else str(entry['lines'])
        link_formula = build_github_link(owner, repo_name, branch, path, entry['type'])
        if path not in existing_map:
            new_rows.append([path, link_formula, entry['type'], lines_str, 'Active', ts, ts, ts, entry['note']])
            changelog_rows.append([ts, tab_title, path, 'Hinzugefügt', '', lines_str, entry['note']])
            continue
        old = existing_map[path]['values']
        row_number = existing_map[path]['row_number']
        old_status, old_lines, old_first_seen, old_last_changed = (old[4], old[3], old[5], old[7])
        changed = False
        if old_status != 'Active':
            changed = True
            changelog_rows.append([ts, tab_title, path, 'Wieder aufgetaucht (war entfernt)', old_lines, lines_str, entry['note']])
            format_requests.append(make_format_request(sheet_id, row_number, len(header), red=False))
        if entry['type'] == 'file' and old_lines != lines_str:
            changelog_rows.append([ts, tab_title, path, 'Geändert (Codezeilen)', old_lines, lines_str, entry['note']])
            changed = True
        last_changed = ts if changed else old_last_changed
        value_updates.append((f"'{tab_title}'!B{row_number}:I{row_number}", [[link_formula, entry['type'], lines_str, 'Active', old_first_seen, ts, last_changed, entry['note']]]))
    for path, info in existing_map.items():
        if path in current_map:
            continue
        if info['values'][4] != 'Active':
            continue
        row_number = info['row_number']
        old = info['values']
        changelog_rows.append([ts, tab_title, path, 'Entfernt', old[3], '', ''])
        value_updates.append((f"'{tab_title}'!E{row_number}:H{row_number}", [['Removed', old[5], old[6], ts]]))
        format_requests.append(make_format_request(sheet_id, row_number, len(header), red=True))
    mgr.append_rows(tab_title, new_rows)
    mgr.batch_update_values(value_updates)
    return compute_stats(current_entries)

def load_overview_map(mgr: SheetManager):
    rows = mgr.get_values('Overview')
    data_rows = rows[1:] if len(rows) > 1 else []
    result = {}
    for i, row in enumerate(data_rows):
        row = row + [''] * (len(OVERVIEW_HEADER) - len(row))
        result[row[0]] = {'row_number': i + 2, 'values': row}
    return result

def update_overview_for_repo(mgr: SheetManager, overview_map: dict, repo_name: str, tab_title: str, stats: dict, changelog_rows: list, format_requests: list, new_overview_rows: list, overview_value_updates: list):
    ts = now_str()
    lines_str, files_str, folders_str = (str(stats['lines']), str(stats['files']), str(stats['folders']))
    sheet_id = mgr.tab_ids['Overview']
    if repo_name not in overview_map:
        new_overview_rows.append([repo_name, 'Active', files_str, folders_str, lines_str, ts, ts, ts, tab_title])
        changelog_rows.append([ts, repo_name, '(gesamtes Repo)', 'Repo hinzugefügt', '', '', ''])
        return
    old = overview_map[repo_name]['values']
    row_number = overview_map[repo_name]['row_number']
    old_status, old_files, old_folders, old_lines = (old[1], old[2], old[3], old[4])
    old_first_seen, old_last_changed = (old[5], old[7])
    changed = False
    if old_status != 'Active':
        changed = True
        changelog_rows.append([ts, repo_name, '(gesamtes Repo)', 'Repo wieder aufgetaucht', '', '', ''])
        format_requests.append(make_format_request(sheet_id, row_number, len(OVERVIEW_HEADER), red=False))
    if (old_files, old_folders, old_lines) != (files_str, folders_str, lines_str):
        changed = True
    last_changed = ts if changed else old_last_changed
    overview_value_updates.append((f"'Overview'!B{row_number}:I{row_number}", [['Active', files_str, folders_str, lines_str, old_first_seen, ts, last_changed, tab_title]]))

def mark_overview_repos_removed(mgr: SheetManager, overview_map: dict, current_repo_names: set, changelog_rows: list, format_requests: list, overview_value_updates: list):
    ts = now_str()
    sheet_id = mgr.tab_ids['Overview']
    for repo_name, info in overview_map.items():
        if repo_name in current_repo_names:
            continue
        if info['values'][1] != 'Active':
            continue
        row_number = info['row_number']
        old = info['values']
        changelog_rows.append([ts, repo_name, '(gesamtes Repo)', 'Repo entfernt', '', '', ''])
        overview_value_updates.append((f"'Overview'!B{row_number}:H{row_number}", [['Removed', old[2], old[3], old[4], old[5], old[6], ts]]))
        format_requests.append(make_format_request(sheet_id, row_number, len(OVERVIEW_HEADER), red=True))

def main():
    global _repo_total, _repo_index
    start_time = datetime.now(timezone.utc)
    console_heartbeat('Code-Tracker gestartet.')
    summary_log('===== Repo-Code-Tracker gestartet =====')
    changelog_rows = []
    ok, failed, failed_names = (0, 0, [])
    tab_limit_warning_logged = False
    try:
        repos = list_source_repos()
        _repo_total = len(repos)
        summary_log(f'{_repo_total} Quell-Repos gefunden.')
        spreadsheet_id = find_or_create_spreadsheet()
        mgr = SheetManager(spreadsheet_id)
        mgr.ensure_tab('Overview', OVERVIEW_HEADER)
        mgr.ensure_tab('Changelog', CHANGELOG_HEADER)
        overview_map = load_overview_map(mgr)
        overview_format_requests = []
        overview_value_updates = []
        new_overview_rows = []
        current_repo_names = {r['name'] for r in repos}
        for i, repo in enumerate(repos, start=1):
            _repo_index = i
            console_heartbeat()
            name = repo['name']
            summary_log(f'--- {name} ---')
            clone_path = None
            try:
                source_url = repo['clone_url'].replace('https://', f'https://{SRC_GH_TOKEN}@')
                clone_path = shallow_clone(name, source_url)
                entries = scan_repo_tree(clone_path)
                branch = repo.get('default_branch') or 'main'
                tab_title = sanitize_sheet_title(name)
                would_be_new_tab = tab_title not in mgr.tab_ids
                if would_be_new_tab and mgr.tab_count() >= MAX_REPO_TABS:
                    stats = compute_stats(entries)
                    if not tab_limit_warning_logged:
                        summary_log(f"WARNUNG: Google-Sheets-Tab-Limit (max. 200) bald erreicht ({mgr.tab_count()} Tabs belegt) - fuer '{name}' und ggf. weitere neue Repos wird KEIN Detail-Tab mehr angelegt. Gesamtzahlen werden trotzdem in 'Overview' gefuehrt.")
                        changelog_rows.append([now_str(), name, '(gesamtes Repo)', 'Kein Detail-Tab (Tab-Limit erreicht)', '', '', ''])
                        tab_limit_warning_logged = True
                else:
                    repo_format_requests = []
                    stats = process_repo_tab(mgr, tab_title, entries, changelog_rows, repo_format_requests, owner=SRC_GH_OWNER, repo_name=name, branch=branch)
                    mgr.flush_formatting(repo_format_requests)
                update_overview_for_repo(mgr, overview_map, name, tab_title, stats, changelog_rows, overview_format_requests, new_overview_rows, overview_value_updates)
                summary_log(f"  OK ({name}): {stats['files']} Dateien, {stats['folders']} Ordner, {stats['lines']} Codezeilen")
                ok += 1
            except Exception as e:
                summary_log(f'  !! FEHLER bei {name}: {e}')
                failed += 1
                failed_names.append(name)
            finally:
                cleanup_local_clone(clone_path)
            time.sleep(SLEEP_BETWEEN_REPOS_SECONDS)
        mark_overview_repos_removed(mgr, overview_map, current_repo_names, changelog_rows, overview_format_requests, overview_value_updates)
        mgr.append_rows('Overview', new_overview_rows)
        mgr.batch_update_values(overview_value_updates)
        mgr.flush_formatting(overview_format_requests)
        mgr.append_rows('Changelog', changelog_rows)
    except Exception as e:
        summary_log(f'!! SCHWERWIEGENDER FEHLER, Lauf abgebrochen: {e}')
        summary_log(redact(traceback.format_exc()))
    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    summary_line = f'===== Fertig: {ok} ok, {failed} Fehler von {ok + failed} Repos. {len(changelog_rows)} Änderungen protokolliert. Dauer: {int(duration)}s ====='
    summary_log(summary_line)
    console_heartbeat('Code-Tracker beendet.')
    subject_status = 'OK' if failed == 0 else f'{failed} FEHLER'
    header = f'Code-Tracker-Zusammenfassung ({subject_status})\nRepos gesamt: {ok + failed} | ok: {ok} | mit Fehler: {failed}\nÄnderungen in diesem Lauf: {len(changelog_rows)}\nDauer: {int(duration)} Sekunden\n'
    if failed_names:
        header += 'Repos mit Fehler: ' + ', '.join(failed_names) + '\n'
    header += '\n----- Vollständiges Protokoll -----\n'
    SUMMARY_FILE.write_text(header + '\n'.join(SUMMARY_LINES) + '\n', encoding='utf-8')
    sys.exit(1 if failed > 0 else 0)
if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        sys.exit(1)
