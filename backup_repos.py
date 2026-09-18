#!/usr/bin/env python3
import contextlib
import hashlib
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
from common import send_email_report

def env(name, required=False, default=None):
    val = os.environ.get(name, default)
    if required and (not val):
        sys.exit(1)
    return val
SRC_GH_TOKEN = env('SRC_GH_TOKEN', required=True)
SRC_GH_OWNER = env('SRC_GH_OWNER', required=True)
SRC_GH_OWNER_TYPE = env('SRC_GH_OWNER_TYPE', default='user')
BACKUP_GH_TOKEN = env('BACKUP_GH_TOKEN')
BACKUP_GH_OWNER = env('BACKUP_GH_OWNER')
BACKUP_GH_OWNER_TYPE = env('BACKUP_GH_OWNER_TYPE', default='user')
GITLAB_TOKEN = env('GITLAB_TOKEN')
GITLAB_NAMESPACE = env('GITLAB_NAMESPACE')
GITLAB_URL = env('GITLAB_URL', default='https://gitlab.com')
GITLAB2_TOKEN = env('GITLAB2_TOKEN')
GITLAB2_NAMESPACE = env('GITLAB2_NAMESPACE')
GITLAB2_URL = env('GITLAB2_URL', default='https://gitlab.com')
GDRIVE_FOLDER_ID = env('GDRIVE_FOLDER_ID')
GDRIVE_SA_JSON = env('GDRIVE_SA_JSON')
GDRIVE_BACKUP_FOLDER_NAME = env('GDRIVE_BACKUP_FOLDER_NAME', default='Repo_Backups')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='email_summary.txt'))
WORKDIR = Path(env('BACKUP_WORKDIR', default='mirrors'))
GIT_TIMEOUT_SECONDS = int(env('GIT_TIMEOUT_SECONDS', default='1800'))
CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO = env('CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO', default='true').lower() == 'true'
QUIET_CONSOLE = env('QUIET_CONSOLE', default='true').lower() == 'true'
MAX_RETRIES = int(env('MAX_RETRIES', default='3'))
RETRY_BASE_DELAY_SECONDS = float(env('RETRY_BASE_DELAY_SECONDS', default='3'))
GIT_LFS_MODE = env('GIT_LFS_MODE', default='never').lower()
_SECRETS = [s for s in [SRC_GH_TOKEN, BACKUP_GH_TOKEN, GITLAB_TOKEN, GITLAB2_TOKEN, GDRIVE_SA_JSON] if s]

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

@contextlib.contextmanager
def timed(label: str):
    start = time.monotonic()
    try:
        yield
    finally:
        summary_log(f'     (Dauer {label}: {time.monotonic() - start:.1f}s)')

def with_retry(func, description: str):
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return func()
        except Exception as e:
            last_error = e
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY_SECONDS * attempt
                summary_log(f"     (Versuch {attempt}/{MAX_RETRIES} fehlgeschlagen bei '{description}': {e} - neuer Versuch in {delay:.0f}s)")
                time.sleep(delay)
            else:
                summary_log(f"     (Endgueltig fehlgeschlagen nach {MAX_RETRIES} Versuchen bei '{description}': {e})")
    raise last_error

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

def run_quiet_no_retry(cmd, timeout=30):
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        if result.returncode != 0:
            return None
        return result.stdout
    except subprocess.TimeoutExpired:
        return None
RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}

def _retry_after_seconds(response, attempt: int) -> float:
    header = response.headers.get('Retry-After')
    if header:
        try:
            return min(float(header), 120.0)
        except ValueError:
            pass
    remaining = response.headers.get('X-RateLimit-Remaining')
    reset = response.headers.get('X-RateLimit-Reset')
    if remaining == '0' and reset:
        try:
            wait = float(reset) - time.time()
            if 0 < wait < 300:
                return wait + 1
        except ValueError:
            pass
    return min(RETRY_BASE_DELAY_SECONDS * 2 ** (attempt - 1), 120.0)

def _is_secondary_rate_limit(response) -> bool:
    if response.status_code != 403:
        return False
    body = (response.text or '').lower()
    return 'secondary rate limit' in body or 'abuse detection' in body

def http_request(method, url, *, headers=None, params=None, json_body=None, auth=None, timeout=30, description=None):
    label = description or f'{method} {url}'
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.request(method, url, headers=headers, params=params, json=json_body, auth=auth, timeout=timeout)
        except requests.RequestException as e:
            last_error = e
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY_SECONDS * attempt
                summary_log(f"     (Netzwerkfehler bei '{label}': {e} - neuer Versuch in {delay:.0f}s)")
                time.sleep(delay)
                continue
            raise RuntimeError(redact(f"Netzwerkfehler bei '{label}': {e}"))
        if r.status_code in RETRYABLE_STATUS or _is_secondary_rate_limit(r):
            if attempt < MAX_RETRIES:
                delay = _retry_after_seconds(r, attempt)
                summary_log(f"     (HTTP {r.status_code} bei '{label}' - warte {delay:.0f}s und versuche erneut, Versuch {attempt}/{MAX_RETRIES})")
                time.sleep(delay)
                continue
            summary_log(f"     (HTTP {r.status_code} bei '{label}' auch nach {MAX_RETRIES} Versuchen)")
        return r
    raise RuntimeError(redact(f'Fehlgeschlagen: {label} ({last_error})'))

def http_get(url, headers=None, params=None, timeout=30, description=None):
    return http_request('GET', url, headers=headers, params=params, timeout=timeout, description=description)

def http_post(url, headers=None, json_body=None, auth=None, timeout=30, description=None):
    return http_request('POST', url, headers=headers, json_body=json_body, auth=auth, timeout=timeout, description=description)

def http_patch(url, headers=None, json_body=None, timeout=30, description=None):
    return http_request('PATCH', url, headers=headers, json_body=json_body, timeout=timeout, description=description)

def now_iso():
    return datetime.now(timezone.utc).isoformat()

def make_run_timestamp_suffix() -> str:
    now = datetime.now(timezone.utc)
    date_part = now.strftime('%d_%m_%Y')
    time_part = now.strftime('%I_%M_%p').lower()
    return f'{date_part}_{time_part}'

def sanitize_gitlab_path(name: str) -> str:
    cleaned = re.sub('[^a-zA-Z0-9_.\\-]', '-', name)
    cleaned = cleaned.strip('-_.')
    for suffix in ('.git', '.atom'):
        if cleaned.lower().endswith(suffix):
            cleaned = cleaned[:-len(suffix)]
            cleaned = cleaned.strip('-_.')
    if not cleaned:
        cleaned = 'repo'
    if cleaned != name:
        digest = hashlib.sha1(name.encode('utf-8')).hexdigest()[:6]
        cleaned = f'{cleaned}-{digest}'.strip('-_.')
    return cleaned[:200]
GIT_BIG_REPO_OPTS = ['-c', 'http.postBuffer=524288000', '-c', 'http.lowSpeedLimit=1000', '-c', 'http.lowSpeedTime=300']
_pack_threads_override = env('GIT_PACK_THREADS', default='')
if _pack_threads_override:
    GIT_BIG_REPO_OPTS += ['-c', f'pack.threads={_pack_threads_override}']
_compression_override = env('GIT_COMPRESSION_LEVEL', default='')
if _compression_override:
    GIT_BIG_REPO_OPTS += ['-c', f'core.compression={_compression_override}']

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

def mirror_clone_local(repo_name: str, source_clone_url_with_token: str) -> Path:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    bare_path = WORKDIR / f'{repo_name}.git'
    if bare_path.exists():
        shutil.rmtree(bare_path)
    summary_log(f'  -> klone {repo_name}')
    run(['git'] + GIT_BIG_REPO_OPTS + ['clone', '--mirror', source_clone_url_with_token, str(bare_path)], description=f'klonen {repo_name}')
    return bare_path

def cleanup_local_mirror(bare_path: Path):
    if CLEAN_LOCAL_MIRROR_AFTER_EACH_REPO and bare_path and bare_path.exists():
        shutil.rmtree(bare_path, ignore_errors=True)

def local_refs(bare_path) -> dict:
    out = run(['git', '--git-dir', str(bare_path), 'for-each-ref', '--format=%(refname) %(objectname)', 'refs/heads/', 'refs/tags/'], description='lokale Refs auflisten')
    refs = {}
    for line in out.splitlines():
        parts = line.strip().split(' ', 1)
        if len(parts) == 2:
            refs[parts[0]] = parts[1]
    return refs

def remote_refs(target_url_with_token: str, label: str) -> dict:
    out = run(['git'] + GIT_BIG_REPO_OPTS + ['ls-remote', '--heads', '--tags', target_url_with_token], description=f'Refs im Ziel auflisten ({label})')
    refs = {}
    for line in out.splitlines():
        parts = line.strip().split('\t')
        if len(parts) == 2 and (not parts[1].endswith('^{}')):
            refs[parts[1]] = parts[0]
    return refs

def verify_refs(bare_path, target_url_with_token: str, label: str, repo_name: str, src_refs: dict=None) -> bool:
    src = src_refs if src_refs is not None else local_refs(bare_path)
    dst = remote_refs(target_url_with_token, label)
    missing = sorted(set(src) - set(dst))
    mismatched = sorted((r for r in set(src) & set(dst) if src[r] != dst[r]))
    if not missing and (not mismatched):
        summary_log(f'     (VERIFIZIERT {label}: {len(src)} Refs vollstaendig und identisch)')
        return True
    if missing:
        summary_log(f"  !! UNVOLLSTAENDIG {label} bei {repo_name}: {len(missing)} von {len(src)} Refs FEHLEN: {', '.join(missing[:20])}" + (' ...' if len(missing) > 20 else ''))
    if mismatched:
        summary_log(f"  !! ABWEICHEND {label} bei {repo_name}: {len(mismatched)} Refs zeigen auf anderen Commit: {', '.join(mismatched[:20])}" + (' ...' if len(mismatched) > 20 else ''))
    return False

def push_branches_and_tags(bare_path, target_url_with_token: str, label: str, repo_name: str='', src_refs: dict=None) -> bool:
    summary_log(f'  -> spiegle nach {label}')
    push_ok = True
    with timed(f'Push {label}'):
        try:
            run(['git'] + GIT_BIG_REPO_OPTS + ['--git-dir', str(bare_path), 'push', '--atomic', '--prune', target_url_with_token, '+refs/heads/*:refs/heads/*', '+refs/tags/*:refs/tags/*'], description=f'push (atomar, heads+tags) nach {label}')
        except RuntimeError as e:
            text = str(e).lower()
            if 'up-to-date' in text:
                summary_log(f'     ({label}: bereits aktuell)')
            else:
                summary_log(f'  !! PUSH-FEHLER {label} bei {repo_name}: {e}')
                push_ok = False
    with timed(f'Verifikation {label}'):
        try:
            verify_ok = verify_refs(bare_path, target_url_with_token, label, repo_name, src_refs=src_refs)
        except Exception as e:
            summary_log(f'  !! VERIFIKATION {label} bei {repo_name} nicht moeglich: {e}')
            verify_ok = False
    return push_ok and verify_ok

def repo_uses_lfs(bare_path: Path) -> bool:
    if GIT_LFS_MODE == 'never':
        return False
    if GIT_LFS_MODE == 'always':
        return True
    try:
        branches_out = run(['git', '--git-dir', str(bare_path), 'for-each-ref', '--format=%(refname)', 'refs/heads/'], description='Branch-Liste fuer LFS-Check')
    except RuntimeError:
        return False
    for branch_ref in branches_out.splitlines():
        branch_ref = branch_ref.strip()
        if not branch_ref:
            continue
        attrs = run_quiet_no_retry(['git', '--git-dir', str(bare_path), 'show', f'{branch_ref}:.gitattributes'])
        if attrs and 'filter=lfs' in attrs:
            return True
    return False

def fetch_lfs_objects(bare_path, source_url_with_token: str, repo_name: str):
    if shutil.which('git-lfs') is None:
        return
    try:
        run(['git', '--git-dir', str(bare_path), 'lfs', 'fetch', '--all', source_url_with_token], description=f'LFS-Objekte holen ({repo_name})')
        summary_log('     (LFS-Objekte gesichert)')
    except RuntimeError as e:
        text = str(e).lower()
        if 'not a valid' in text or 'no lfs' in text or 'does not appear' in text:
            return
        summary_log(f'  !! LFS-Warnung bei {repo_name}: {e}')

def push_lfs_objects(bare_path, target_url_with_token: str, label: str, repo_name: str):
    if shutil.which('git-lfs') is None:
        return
    try:
        run(['git', '--git-dir', str(bare_path), 'lfs', 'push', '--all', target_url_with_token], description=f'LFS-Objekte pushen nach {label}')
    except RuntimeError as e:
        summary_log(f'  !! LFS-Push-Warnung {label} bei {repo_name}: {e}')

def ensure_github_target_repo(name: str):
    headers = {'Authorization': f'token {BACKUP_GH_TOKEN}', 'Accept': 'application/vnd.github+json'}
    check_url = f'https://api.github.com/repos/{BACKUP_GH_OWNER}/{name}'
    r = http_get(check_url, headers=headers, timeout=30, description=f'GitHub-Backup-Repo pruefen ({name})')
    if r.status_code == 200:
        return
    if r.status_code != 404:
        raise RuntimeError(redact(f"Unklare Antwort HTTP {r.status_code} bei Pruefung von '{name}': {r.text[:200]}"))
    create_url = f'https://api.github.com/orgs/{BACKUP_GH_OWNER}/repos' if BACKUP_GH_OWNER_TYPE == 'org' else 'https://api.github.com/user/repos'
    r = http_post(create_url, headers=headers, json_body={'name': name, 'private': True}, timeout=30, description=f'GitHub-Backup-Repo anlegen ({name})')
    if r.status_code not in (201, 422):
        raise RuntimeError(redact(f'GitHub-Backup-Repo konnte nicht angelegt werden: {r.text}'))
    summary_log(f"  -> GitHub-Backup-Repo '{name}' neu angelegt")

def _gitlab_namespace_id_if_group(url: str, token: str, namespace: str):
    headers = {'PRIVATE-TOKEN': token}
    encoded_ns = urllib.parse.quote(namespace, safe='')
    ns_r = http_get(f'{url}/api/v4/namespaces/{encoded_ns}', headers=headers, timeout=30, description='GitLab-Namespace ermitteln')
    if ns_r.status_code == 200:
        ns_data = ns_r.json()
        if ns_data.get('kind') == 'group':
            return ns_data['id']
    return None

def ensure_gitlab_target_repo(name: str) -> str:
    safe_path = sanitize_gitlab_path(name)
    headers = {'PRIVATE-TOKEN': GITLAB_TOKEN}
    project_path = f'{GITLAB_NAMESPACE}/{safe_path}'
    encoded_path = urllib.parse.quote(project_path, safe='')
    check_url = f'{GITLAB_URL}/api/v4/projects/{encoded_path}'
    r = http_get(check_url, headers=headers, timeout=30, description=f'GitLab-#1-Projekt pruefen ({safe_path})')
    if r.status_code == 200:
        return safe_path
    if r.status_code != 404:
        raise RuntimeError(redact(f"Unklare Antwort HTTP {r.status_code} bei Pruefung von '{safe_path}': {r.text[:200]}"))
    payload = {'name': name, 'path': safe_path, 'visibility': 'private'}
    ns_id = _gitlab_namespace_id_if_group(GITLAB_URL, GITLAB_TOKEN, GITLAB_NAMESPACE)
    if ns_id:
        payload['namespace_id'] = ns_id
    r = http_post(f'{GITLAB_URL}/api/v4/projects', headers=headers, json_body=payload, timeout=30, description=f'GitLab-#1-Projekt anlegen ({safe_path})')
    if r.status_code != 201:
        raise RuntimeError(redact(f'GitLab-Projekt konnte nicht angelegt werden: {r.text}'))
    if safe_path != name:
        summary_log(f"  -> GitLab-Projekt '{safe_path}' neu angelegt (bereinigt aus '{name}')")
    else:
        summary_log(f"  -> GitLab-Projekt '{safe_path}' neu angelegt")
    return safe_path

def create_gitlab2_dated_project(dated_name: str) -> str:
    safe_path = sanitize_gitlab_path(dated_name)
    headers = {'PRIVATE-TOKEN': GITLAB2_TOKEN}
    payload = {'name': dated_name, 'path': safe_path, 'visibility': 'private'}
    ns_id = _gitlab_namespace_id_if_group(GITLAB2_URL, GITLAB2_TOKEN, GITLAB2_NAMESPACE)
    if ns_id:
        payload['namespace_id'] = ns_id
    r = http_post(f'{GITLAB2_URL}/api/v4/projects', headers=headers, json_body=payload, timeout=30, description=f'GitLab-#2-Projekt anlegen ({safe_path})')
    if r.status_code != 201:
        raise RuntimeError(redact(f'GitLab-Account-#2-Projekt konnte nicht angelegt werden: {r.text}'))
    summary_log(f"  -> GitLab-Account-#2: neues datiertes Projekt '{safe_path}' angelegt")
    time.sleep(0.3)
    return safe_path

def sync_github_default_branch(backup_token: str, backup_owner: str, name: str, source_default_branch: str):
    if not source_default_branch:
        return
    headers = {'Authorization': f'token {backup_token}', 'Accept': 'application/vnd.github+json'}
    r = http_patch(f'https://api.github.com/repos/{backup_owner}/{name}', headers=headers, json_body={'default_branch': source_default_branch}, description=f'Default-Branch setzen ({name})')
    if r.status_code == 200:
        summary_log(f"     (Default-Branch im Backup auf '{source_default_branch}' gesetzt)")

def check_disk_space(workdir, repo_size_kb: int, repo_name: str) -> bool:
    try:
        usage = shutil.disk_usage(workdir if workdir.exists() else '.')
    except OSError:
        return True
    free_mb = usage.free / (1024 * 1024)
    needed_mb = repo_size_kb / 1024 * 2.5
    if free_mb < needed_mb:
        summary_log(f'  !! ZU WENIG PLATTENPLATZ fuer {repo_name}: {free_mb:.0f} MB frei, ca. {needed_mb:.0f} MB noetig - Repo wird UEBERSPRUNGEN')
        return False
    if free_mb < 2048:
        summary_log(f'     (Warnung: nur noch {free_mb:.0f} MB Plattenplatz frei)')
    return True
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
    creds = service_account.Credentials.from_service_account_info(info, scopes=['https://www.googleapis.com/auth/drive'])
    _drive_service = build('drive', 'v3', credentials=creds)
    return _drive_service

def get_shared_drive_id(service):
    global _drive_shared_drive_id, _drive_shared_drive_id_resolved
    if _drive_shared_drive_id_resolved:
        return _drive_shared_drive_id
    try:
        info = with_retry(lambda: service.files().get(fileId=GDRIVE_FOLDER_ID, supportsAllDrives=True, fields='driveId').execute(), 'Shared-Drive-ID ermitteln')
        _drive_shared_drive_id = info.get('driveId')
    except Exception as e:
        summary_log(f'Hinweis: Shared-Drive-ID konnte nicht ermittelt werden ({e}) - nutze Standard-Suche ohne corpora/driveId.')
        _drive_shared_drive_id = None
    _drive_shared_drive_id_resolved = True
    if _drive_shared_drive_id:
        summary_log('Shared-Drive erkannt (driveId ermittelt) - nutze zuverlaessige Suche.')
    else:
        summary_log('GDRIVE_FOLDER_ID liegt nicht in einem Shared Drive - Standard-Suche.')
    return _drive_shared_drive_id

def _drive_list_kwargs(service, query: str, fields: str):
    kwargs = dict(q=query, fields=f'nextPageToken, {fields}', supportsAllDrives=True, includeItemsFromAllDrives=True, pageSize=100)
    drive_id = get_shared_drive_id(service)
    if drive_id:
        kwargs['corpora'] = 'drive'
        kwargs['driveId'] = drive_id
    return kwargs

def list_all_drive_files(service, query: str, fields: str='files(id, name, createdTime)'):
    results = []
    page_token = None
    while True:
        kwargs = _drive_list_kwargs(service, query, fields)
        if page_token:
            kwargs['pageToken'] = page_token
        response = with_retry(lambda kwargs=kwargs: service.files().list(**kwargs).execute(), 'Google-Drive-Suche')
        results.extend(response.get('files', []))
        page_token = response.get('nextPageToken')
        if not page_token:
            break
    return results

def delete_drive_file_if_exists(service, file_id: str, description: str):
    try:
        service.files().delete(fileId=file_id, supportsAllDrives=True).execute()
    except Exception as e:
        if '404' in str(e) or 'notFound' in str(e) or 'File not found' in str(e):
            summary_log(f'     ({description}: Datei war bereits geloescht - ok)')
            return
        with_retry(lambda: service.files().delete(fileId=file_id, supportsAllDrives=True).execute(), description)

def ensure_drive_backup_folder(service) -> str:
    global _drive_backup_folder_id
    if _drive_backup_folder_id:
        return _drive_backup_folder_id
    query = f"name = '{GDRIVE_BACKUP_FOLDER_NAME}' and '{GDRIVE_FOLDER_ID}' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    existing = list_all_drive_files(service, query, fields='files(id, createdTime)')
    existing.sort(key=lambda f: f.get('createdTime', ''))
    if existing:
        if len(existing) > 1:
            summary_log(f"WARNUNG: {len(existing)} Ordner namens '{GDRIVE_BACKUP_FOLDER_NAME}' gefunden - verwende den aeltesten. Bitte manuell in Google Drive bereinigen.")
        _drive_backup_folder_id = existing[0]['id']
        summary_log(f"Google-Drive-Backup-Ordner '{GDRIVE_BACKUP_FOLDER_NAME}' gefunden.")
        return _drive_backup_folder_id
    folder = with_retry(lambda: service.files().create(body={'name': GDRIVE_BACKUP_FOLDER_NAME, 'mimeType': 'application/vnd.google-apps.folder', 'parents': [GDRIVE_FOLDER_ID]}, fields='id', supportsAllDrives=True).execute(), 'Google-Drive-Backup-Ordner anlegen')
    _drive_backup_folder_id = folder['id']
    summary_log(f"Google-Drive-Backup-Ordner '{GDRIVE_BACKUP_FOLDER_NAME}' neu angelegt.")
    return _drive_backup_folder_id

def backup_to_drive(bare_path: Path, repo_name: str):
    from googleapiclient.http import MediaFileUpload
    service = get_drive_service()
    target_folder_id = ensure_drive_backup_folder(service)
    zip_name = f'{repo_name}.git.zip'
    with tempfile.TemporaryDirectory() as tmp:
        zip_path = Path(tmp) / zip_name
        summary_log('  -> packe fuer Google Drive')
        with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED) as zf:
            for file in bare_path.rglob('*'):
                if file.is_file():
                    zf.write(file, arcname=str(file.relative_to(bare_path.parent)))
        query = f"name = '{zip_name}' and '{target_folder_id}' in parents and trashed = false"
        existing = list_all_drive_files(service, query, fields='files(id, createdTime)')
        if len(existing) > 1:
            summary_log(f"     ({len(existing)} alte Duplikate von '{zip_name}' gefunden - werden bereinigt)")
        summary_log('  -> lade zu Google Drive hoch')
        media = MediaFileUpload(str(zip_path), mimetype='application/zip', resumable=True)
        with_retry(lambda: service.files().create(body={'name': zip_name, 'parents': [target_folder_id]}, media_body=media, fields='id', supportsAllDrives=True).execute(), f'Drive-Upload ({repo_name})')
        for f in existing:
            delete_drive_file_if_exists(service, f['id'], f'alte Drive-Datei loeschen ({repo_name})')

def process_repo(repo: dict, run_timestamp_suffix: str) -> bool:
    name = repo['name']
    default_branch = repo.get('default_branch') or ''
    size_kb = int(repo.get('size') or 0)
    summary_log(f"--- {name} (Default-Branch: {default_branch or 'unbekannt'}, ca. {size_kb / 1024:.0f} MB) ---")
    repo_start = time.monotonic()
    if not check_disk_space(WORKDIR, size_kb, name):
        return False
    bare_path = None
    overall_ok = True
    source_url = repo['clone_url'].replace('https://', f'https://{SRC_GH_TOKEN}@')
    try:
        with timed(f'Klonen {name}'):
            bare_path = mirror_clone_local(name, source_url)
        uses_lfs = repo_uses_lfs(bare_path)
        if uses_lfs:
            with timed(f'LFS-Fetch {name}'):
                fetch_lfs_objects(bare_path, source_url, name)
        else:
            summary_log("     (LFS uebersprungen - GIT_LFS_MODE steht auf 'never'/kein Treffer)")
        src_refs = local_refs(bare_path)
        summary_log(f'     (Quelle enthaelt {len(src_refs)} Refs)')
    except Exception as e:
        summary_log(f'  !! FEHLER beim Klonen von {name}: {e}')
        cleanup_local_mirror(bare_path)
        return False
    if BACKUP_GH_TOKEN and BACKUP_GH_OWNER:
        try:
            ensure_github_target_repo(name)
            target = f'https://{BACKUP_GH_TOKEN}@github.com/{BACKUP_GH_OWNER}/{name}.git'
            if not push_branches_and_tags(bare_path, target, 'GitHub-Backup-Account', name, src_refs=src_refs):
                overall_ok = False
            if uses_lfs:
                with timed(f'LFS-Push GitHub-Backup-Account {name}'):
                    push_lfs_objects(bare_path, target, 'GitHub-Backup-Account', name)
            sync_github_default_branch(BACKUP_GH_TOKEN, BACKUP_GH_OWNER, name, default_branch)
        except Exception as e:
            summary_log(f'  !! FEHLER (GitHub-Backup) bei {name}: {e}')
            overall_ok = False
    if GITLAB_TOKEN and GITLAB_NAMESPACE:
        try:
            safe_path = ensure_gitlab_target_repo(name)
            host = GITLAB_URL.replace('https://', '')
            target = f'https://oauth2:{GITLAB_TOKEN}@{host}/{GITLAB_NAMESPACE}/{safe_path}.git'
            if not push_branches_and_tags(bare_path, target, 'GitLab-Account-#1', name, src_refs=src_refs):
                overall_ok = False
            if uses_lfs:
                with timed(f'LFS-Push GitLab-Account-#1 {name}'):
                    push_lfs_objects(bare_path, target, 'GitLab-Account-#1', name)
        except Exception as e:
            summary_log(f'  !! FEHLER (GitLab-Account-#1) bei {name}: {e}')
            overall_ok = False
    if GITLAB2_TOKEN and GITLAB2_NAMESPACE:
        try:
            dated_name = f'{name}_{run_timestamp_suffix}'
            safe_dated_path = create_gitlab2_dated_project(dated_name)
            host = GITLAB2_URL.replace('https://', '')
            target = f'https://oauth2:{GITLAB2_TOKEN}@{host}/{GITLAB2_NAMESPACE}/{safe_dated_path}.git'
            if not push_branches_and_tags(bare_path, target, 'GitLab-Account-#2 (datiert)', name, src_refs=src_refs):
                overall_ok = False
        except Exception as e:
            summary_log(f'  !! FEHLER (GitLab-Account-#2) bei {name}: {e}')
            overall_ok = False
    if GDRIVE_SA_JSON and GDRIVE_FOLDER_ID:
        try:
            with timed(f'Google-Drive-Backup {name}'):
                backup_to_drive(bare_path, name)
        except Exception as e:
            summary_log(f'  !! FEHLER (Google Drive) bei {name}: {e}')
            overall_ok = False
    cleanup_local_mirror(bare_path)
    repo_duration = time.monotonic() - repo_start
    if overall_ok:
        summary_log(f'  OK ({name}) - alle Ziele verifiziert vollstaendig (Gesamtdauer: {repo_duration:.1f}s)')
    else:
        summary_log(f'  UNVOLLSTAENDIG ({name}) - siehe Details oben (Gesamtdauer: {repo_duration:.1f}s)')
    return overall_ok

def main():
    global _repo_total, _repo_index
    start_time = datetime.now(timezone.utc)
    run_timestamp_suffix = make_run_timestamp_suffix()
    console_heartbeat('Backup gestartet.')
    summary_log('===== Repo-Backup gestartet =====')
    summary_log(f'Zeitstempel fuer GitLab-Account-#2 (UTC): {run_timestamp_suffix}')
    summary_log(f"GIT_LFS_MODE={GIT_LFS_MODE} | GIT_PACK_THREADS={_pack_threads_override or '(Git-Standard)'} | GIT_COMPRESSION_LEVEL={_compression_override or '(Git-Standard)'}")
    ok, failed, failed_names = (0, 0, [])
    try:
        repos = list_source_repos()
        _repo_total = len(repos)
        summary_log(f'{_repo_total} Quell-Repos gefunden.')
        for i, repo in enumerate(repos, start=1):
            _repo_index = i
            console_heartbeat()
            success = process_repo(repo, run_timestamp_suffix)
            if success:
                ok += 1
            else:
                failed += 1
                failed_names.append(repo['name'])
    except Exception as e:
        summary_log(f'!! SCHWERWIEGENDER FEHLER, Lauf abgebrochen: {e}')
        summary_log(redact(traceback.format_exc()))
    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    summary_log(f'===== Fertig: {ok} ok, {failed} Fehler von {ok + failed} Repos. Dauer: {int(duration)}s =====')
    console_heartbeat('Backup beendet.')
    subject_status = 'OK' if failed == 0 else f'{failed} FEHLER'
    header = f'Backup-Zusammenfassung ({subject_status})\nRepos gesamt: {ok + failed} | vollstaendig verifiziert: {ok} | mit mind. 1 Problem: {failed}\nDauer: {int(duration)} Sekunden\nGitLab-#2-Zeitstempel dieses Laufs (UTC): {run_timestamp_suffix}\n'
    if failed_names:
        header += 'Repos mit mindestens einem Problem: ' + ', '.join(failed_names) + '\n'
    header += '\n----- Vollstaendiges Protokoll -----\n'
    SUMMARY_FILE.write_text(header + '\n'.join(SUMMARY_LINES) + '\n', encoding='utf-8')
    subject = f'Repo Super-Backup Ergebnis ({subject_status})'
    body = f'{header}\nDer ungekuerzte vollstaendige Report befindet sich als Anhang im Dateianhang.'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE])
    except Exception:
        pass
    sys.exit(1 if failed > 0 else 0)
if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        sys.exit(1)
