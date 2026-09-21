#!/usr/bin/env python3
import json
import os
import shutil
import subprocess
import sys
import tempfile
import traceback
from datetime import datetime, timezone
from pathlib import Path
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaFileUpload
from common import env, Redactor, SummaryLogger, send_google_chat, send_email_report, list_github_repos, with_retry

SRC_GH_TOKEN = env('SRC_GH_TOKEN', required=True)
SRC_GH_OWNER = env('SRC_GH_OWNER', required=True)
SRC_GH_OWNER_TYPE = env('SRC_GH_OWNER_TYPE', default='user')
GDRIVE_SA_JSON = env('GDRIVE_SA_JSON')
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='sbom_inventory_summary.txt'))

redact = Redactor([SRC_GH_TOKEN, GDRIVE_SA_JSON])
log = SummaryLogger(redact)

def get_drive_service(sa_json: str):
    info = json.loads(sa_json)
    creds = service_account.Credentials.from_service_account_info(
        info, scopes=['https://www.googleapis.com/auth/drive']
    )
    return build('drive', 'v3', credentials=creds)

def list_drive_files(service, query: str):
    results = []
    page_token = None
    while True:
        kwargs = {
            'q': query,
            'fields': 'nextPageToken, files(id, name, createdTime, webViewLink)',
            'supportsAllDrives': True,
            'includeItemsFromAllDrives': True,
            'pageSize': 100
        }
        if page_token:
            kwargs['pageToken'] = page_token
        res = with_retry(lambda kwargs=kwargs: service.files().list(**kwargs).execute(), 'Drive-Suche', logger=log)
        results.extend(res.get('files', []))
        page_token = res.get('nextPageToken')
        if not page_token:
            break
    return results

def get_or_create_folder(service, folder_name: str, parent_id: str = None) -> str:
    if parent_id:
        q = f"name = '{folder_name}' and '{parent_id}' in parents and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    else:
        q = f"name = '{folder_name}' and mimeType = 'application/vnd.google-apps.folder' and trashed = false"
    files = list_drive_files(service, q)
    if files:
        return files[0]['id']
    meta = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    if parent_id:
        meta['parents'] = [parent_id]
    f = with_retry(lambda: service.files().create(body=meta, fields='id', supportsAllDrives=True).execute(), f"Ordner '{folder_name}' anlegen", logger=log)
    return f['id']

def upload_sbom_file(service, folder_id: str, file_name: str, local_file_path: Path) -> str:
    q = f"name = '{file_name}' and '{folder_id}' in parents and trashed = false"
    existing = list_drive_files(service, q)
    media = MediaFileUpload(str(local_file_path), mimetype='application/json', resumable=True)
    if existing:
        file_id = existing[0]['id']
        res = with_retry(
            lambda: service.files().update(
                fileId=file_id,
                media_body=media,
                fields='id, webViewLink',
                supportsAllDrives=True
            ).execute(),
            f"Datei '{file_name}' aktualisieren",
            logger=log
        )
        return res.get('webViewLink', '')
    else:
        meta = {
            'name': file_name,
            'parents': [folder_id]
        }
        res = with_retry(
            lambda: service.files().create(
                body=meta,
                media_body=media,
                fields='id, webViewLink',
                supportsAllDrives=True
            ).execute(),
            f"Datei '{file_name}' hochladen",
            logger=log
        )
        return res.get('webViewLink', '')

def process_repository(repo: dict, drive_service, root_sbom_id: str, date_str: str) -> tuple:
    name = repo['name']
    if repo.get('archived'):
        return ('SKIP', f"{name}: Uebersprungen (Archiviert)", None)
    if repo.get('disabled') or repo.get('size', 0) == 0 or not repo.get('default_branch'):
        return ('SKIP', f"{name}: Uebersprungen (Leeres oder deaktiviertes Repo)", None)

    default_branch = repo.get('default_branch')
    clone_url = repo['clone_url'].replace('https://', f'https://{SRC_GH_TOKEN}@')
    filename = f"{name}_sbom_{date_str}.json"

    syft_bin = shutil.which('syft') or '/usr/local/bin/syft'

    with tempfile.TemporaryDirectory() as tmp_dir:
        tmp_path = Path(tmp_dir)
        repo_dir = tmp_path / 'repo'
        sbom_file = tmp_path / filename

        try:
            clone_cmd = ['git', 'clone', '--depth', '1', '--branch', default_branch, clone_url, str(repo_dir)]
            subprocess.run(clone_cmd, capture_output=True, text=True, check=True, timeout=300)
        except Exception as e:
            return ('FAIL', f"{name}: Fehlgeschlagen (Git Clone: {redact(str(e))})", None)

        try:
            syft_cmd = [syft_bin, f"dir:{repo_dir}", f"-o=cyclonedx-json={sbom_file}"]
            subprocess.run(syft_cmd, capture_output=True, text=True, check=True, timeout=300)
        except Exception as e:
            return ('FAIL', f"{name}: Fehlgeschlagen (Syft-Generierung: {redact(str(e))})", None)

        if not sbom_file.exists() or sbom_file.stat().st_size == 0:
            return ('FAIL', f"{name}: Fehlgeschlagen (Leere SBOM-Datei)", None)

        try:
            repo_folder_id = get_or_create_folder(drive_service, name, root_sbom_id)
            link = upload_sbom_file(drive_service, repo_folder_id, filename, sbom_file)
            return ('OK', f"{name}: Erfolgreich", link)
        except Exception as e:
            return ('FAIL', f"{name}: Fehlgeschlagen (Drive Upload: {redact(str(e))})", None)

def main():
    start_time = datetime.now(timezone.utc)
    date_str = start_time.strftime('%Y-%m-%d')
    date_display = start_time.strftime('%d.%m.%Y %H:%M UTC')

    log.log("Woechentliches SBOM-Inventar gestartet.")

    drive_service = None
    root_sbom_id = None
    if GDRIVE_SA_JSON:
        try:
            drive_service = get_drive_service(GDRIVE_SA_JSON)
            root_sbom_id = get_or_create_folder(drive_service, "SBOM", None)
        except Exception as e:
            log.log(f"Schwerwiegender Fehler beim Initialisieren von Google Drive: {redact(str(e))}")

    if not drive_service or not root_sbom_id:
        log.log("Google Drive nicht verfuegbar - abgebrochen.")
        sys.exit(0)

    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception as e:
        log.log(f"Fehler beim Abrufen der Repository-Liste: {redact(str(e))}")
        sys.exit(0)

    total_count = len(repos)
    ok_count = 0
    skip_count = 0
    fail_count = 0
    repo_results = []

    for repo in repos:
        status, detail, link = process_repository(repo, drive_service, root_sbom_id, date_str)
        if status == 'OK':
            ok_count += 1
            repo_results.append(f"✅ {detail} | Link: {link}")
            log.log(f"Repo {repo['name']}: OK")
        elif status == 'SKIP':
            skip_count += 1
            repo_results.append(f"⚪ {detail}")
            log.log(f"Repo {repo['name']}: SKIP")
        else:
            fail_count += 1
            repo_results.append(f"❌ {detail}")
            log.log(f"Repo {repo['name']}: FAIL")

    duration = int((datetime.now(timezone.utc) - start_time).total_seconds())

    status_str = "OK" if fail_count == 0 else f"{fail_count} FEHLER"
    subject = f"SBOM-Inventar Report ({status_str}) - {date_display}"

    header_lines = [
        f"Woechentlicher SBOM-Inventar-Report - {date_display}",
        f"Repos gesamt: {total_count} | Erfolgreich: {ok_count} | Uebersprungen: {skip_count} | Fehlgeschlagen: {fail_count}",
        f"Dauer: {duration} Sekunden",
        "",
        "----- Status pro Repository -----"
    ]

    report_text = "\n".join(header_lines + repo_results) + "\n\n----- Vollstaendiges Protokoll -----\n" + "\n".join(log.lines) + "\n"
    SUMMARY_FILE.write_text(report_text, encoding='utf-8')

    email_body = f"{subject}\n\nDer vollstaendige Report befindet sich im Anhang.\n\n" + "\n".join(header_lines + repo_results)
    send_email_report(subject, email_body, attachments=[SUMMARY_FILE], logger=log)

    if GOOGLE_CHAT_WEBHOOK:
        chat_msg = f"📦 SBOM-Inventar ({status_str}): {ok_count}/{total_count} Repos erfolgreich verarbeitet. Vollstaendiger Report per E-Mail."
        send_google_chat(GOOGLE_CHAT_WEBHOOK, chat_msg)

    if SUMMARY_FILE.exists():
        try:
            SUMMARY_FILE.write_bytes(b'0' * SUMMARY_FILE.stat().st_size)
            SUMMARY_FILE.unlink()
        except Exception:
            pass

    sys.exit(0)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(0)
