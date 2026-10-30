#!/usr/bin/env python3
"""Shared helpers for the security / operations workflows.

Design rules (apply to every script that imports this module):
  * Nothing is ever printed to stdout/stderr. All details go into report files
    that are e-mailed and then shredded.
  * Sensitive dispatch parameters arrive as an AES-256-GCM sealed token
    (see tools/seal_dispatch.py), never as plain-text workflow inputs.
  * No GitHub artifacts, no step summaries, no files committed back.
"""
import base64
import hashlib
import html
import json
import os
import shutil
import subprocess
import time
import zipfile
from datetime import datetime, timezone
from pathlib import Path

from common import env, Redactor, SummaryLogger, with_retry, send_email_report

DRIVE_SCOPE = 'https://www.googleapis.com/auth/drive'
DRIVE_RO_SCOPE = 'https://www.googleapis.com/auth/drive.readonly'
DIRECTORY_USER_RO_SCOPE = 'https://www.googleapis.com/auth/admin.directory.user.readonly'
FOLDER_MIME = 'application/vnd.google-apps.folder'
PAYLOAD_AAD = b'dispatch-v1'

# Gmail and most providers reject mails above ~25 MB (base64 adds ~33 %).
MAX_MAIL_ATTACHMENT_MB = float(os.environ.get('MAX_MAIL_ATTACHMENT_MB', '17'))


# --------------------------------------------------------------------------- #
# Time helpers
# --------------------------------------------------------------------------- #
def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def ts_label() -> str:
    return utc_now().strftime('%Y-%m-%d %H:%M UTC')


def file_stamp() -> str:
    return utc_now().strftime('%Y%m%d_%H%M%S')


def human_bytes(n) -> str:
    try:
        n = float(n)
    except (TypeError, ValueError):
        return 'n/a'
    for unit in ('B', 'KB', 'MB', 'GB', 'TB'):
        if abs(n) < 1024 or unit == 'TB':
            return f'{n:.1f} {unit}' if unit != 'B' else f'{int(n)} B'
        n /= 1024
    return f'{n:.1f} TB'


def human_duration(seconds) -> str:
    seconds = int(seconds or 0)
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f'{h}h {m:02d}m {s:02d}s'
    if m:
        return f'{m}m {s:02d}s'
    return f'{s}s'


# --------------------------------------------------------------------------- #
# Sealed dispatch payloads
# --------------------------------------------------------------------------- #
def open_payload(token: str, key_b64: str, max_age_seconds: int = 3600) -> dict:
    """Decrypt a payload created by tools/seal_dispatch.py.

    Raises RuntimeError with a neutral message on any problem.
    """
    token = (token or '').strip()
    if not token:
        return {}
    if not key_b64:
        raise RuntimeError('DISPATCH_KEY secret is missing.')
    try:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    except ImportError as exc:
        raise RuntimeError('Python package "cryptography" is not installed.') from exc
    try:
        key = base64.b64decode(key_b64.strip())
    except Exception as exc:
        raise RuntimeError('DISPATCH_KEY is not valid base64.') from exc
    if len(key) != 32:
        raise RuntimeError('DISPATCH_KEY must decode to exactly 32 bytes.')
    try:
        raw = base64.urlsafe_b64decode(token + '=' * (-len(token) % 4))
        nonce, ciphertext = raw[:12], raw[12:]
        data = json.loads(AESGCM(key).decrypt(nonce, ciphertext, PAYLOAD_AAD).decode('utf-8'))
    except Exception as exc:
        raise RuntimeError('Sealed payload could not be decrypted (wrong key or corrupted token).') from exc
    issued = int(data.pop('_ts', 0) or 0)
    if max_age_seconds > 0 and abs(time.time() - issued) > max_age_seconds:
        raise RuntimeError(f'Sealed payload expired (older than {max_age_seconds}s). Create a fresh one.')
    return data


def seal_payload(data: dict, key_b64: str) -> str:
    """Counterpart of open_payload (used by tools/seal_dispatch.py and tests)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = base64.b64decode(key_b64.strip())
    body = dict(data)
    body['_ts'] = int(time.time())
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(body, separators=(',', ':')).encode('utf-8'), PAYLOAD_AAD)
    return base64.urlsafe_b64encode(nonce + ct).decode('ascii').rstrip('=')


def parse_list(raw: str) -> list:
    """Accepts newline, comma or semicolon separated values. '#' starts a comment."""
    items = []
    for line in (raw or '').replace(';', '\n').replace(',', '\n').splitlines():
        line = line.split('#', 1)[0].strip()
        if line:
            items.append(line)
    return items


# --------------------------------------------------------------------------- #
# Process helper (never raises on non-zero exit, never prints)
# --------------------------------------------------------------------------- #
def run_cmd(cmd, cwd=None, timeout=600, input_text=None, env_extra=None, shell=False):
    run_env = os.environ.copy()
    if env_extra:
        run_env.update(env_extra)
    try:
        proc = subprocess.run(
            cmd, cwd=cwd, input=input_text, capture_output=True, text=True,
            timeout=timeout, env=run_env, shell=shell, errors='replace',
        )
        return proc.returncode, proc.stdout or '', proc.stderr or ''
    except subprocess.TimeoutExpired as exc:
        out = exc.stdout.decode('utf-8', 'replace') if isinstance(exc.stdout, bytes) else (exc.stdout or '')
        return 124, out, f'Timeout after {timeout}s'
    except FileNotFoundError as exc:
        return 127, '', f'Executable not found: {exc}'


def tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def sha256_file(path: Path, chunk: int = 4 * 1024 * 1024) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for block in iter(lambda: f.read(chunk), b''):
            h.update(block)
    return h.hexdigest()


def shred_paths(*paths):
    """Best-effort removal of local working data (files or directories)."""
    for p in paths:
        if not p:
            continue
        p = Path(p)
        try:
            if p.is_dir():
                shutil.rmtree(p, ignore_errors=True)
            elif p.exists():
                try:
                    size = p.stat().st_size
                    if size < 64 * 1024 * 1024:
                        p.write_bytes(b'\0' * size)
                except Exception:
                    pass
                p.unlink(missing_ok=True)
        except Exception:
            pass


# --------------------------------------------------------------------------- #
# Google Drive
# --------------------------------------------------------------------------- #
def google_credentials(sa_json: str, scopes, subject: str = None):
    from google.oauth2 import service_account
    info = json.loads(sa_json)
    creds = service_account.Credentials.from_service_account_info(info, scopes=list(scopes))
    if subject:
        creds = creds.with_subject(subject)
    return creds


def drive_service(sa_json: str, subject: str = None, scopes=None):
    from googleapiclient.discovery import build
    creds = google_credentials(sa_json, scopes or [DRIVE_SCOPE], subject)
    return build('drive', 'v3', credentials=creds, cache_discovery=False)


def _q(value: str) -> str:
    return str(value).replace('\\', '\\\\').replace("'", "\\'")


class Drive:
    """Small wrapper around the Drive v3 API with Shared-Drive support and retries."""

    def __init__(self, service, logger: SummaryLogger = None):
        self.s = service
        self.log = logger

    def _exec(self, request, description):
        return with_retry(lambda: request.execute(), description, max_retries=4, base_delay=4.0, logger=self.log)

    def list(self, query: str, fields: str = 'id,name,mimeType,size,createdTime,modifiedTime,webViewLink,md5Checksum',
             corpora: str = None, drive_id: str = None, page_size: int = 200):
        results, token = [], None
        while True:
            kwargs = dict(q=query, fields=f'nextPageToken, files({fields})', pageSize=page_size,
                          supportsAllDrives=True, includeItemsFromAllDrives=True)
            if corpora:
                kwargs['corpora'] = corpora
            if drive_id:
                kwargs['driveId'] = drive_id
            if token:
                kwargs['pageToken'] = token
            resp = self._exec(self.s.files().list(**kwargs), 'Drive list')
            results.extend(resp.get('files', []))
            token = resp.get('nextPageToken')
            if not token:
                return results

    def iter_list(self, query: str, fields: str, corpora: str = None, drive_id: str = None, page_size: int = 500):
        token = None
        while True:
            kwargs = dict(q=query, fields=f'nextPageToken, files({fields})', pageSize=page_size,
                          supportsAllDrives=True, includeItemsFromAllDrives=True)
            if corpora:
                kwargs['corpora'] = corpora
            if drive_id:
                kwargs['driveId'] = drive_id
            if token:
                kwargs['pageToken'] = token
            resp = self._exec(self.s.files().list(**kwargs), 'Drive list')
            for f in resp.get('files', []):
                yield f
            token = resp.get('nextPageToken')
            if not token:
                return

    def children(self, parent_id: str, folders_only=False, files_only=False):
        q = f"'{_q(parent_id)}' in parents and trashed = false"
        if folders_only:
            q += f" and mimeType = '{FOLDER_MIME}'"
        if files_only:
            q += f" and mimeType != '{FOLDER_MIME}'"
        return self.list(q)

    def find_child(self, parent_id: str, name: str, folder: bool = None):
        q = f"name = '{_q(name)}' and '{_q(parent_id)}' in parents and trashed = false"
        if folder is True:
            q += f" and mimeType = '{FOLDER_MIME}'"
        elif folder is False:
            q += f" and mimeType != '{FOLDER_MIME}'"
        found = self.list(q)
        found.sort(key=lambda f: f.get('createdTime', ''))
        return found[0] if found else None

    def ensure_folder(self, parent_id: str, name: str) -> str:
        existing = self.find_child(parent_id, name, folder=True)
        if existing:
            return existing['id']
        body = {'name': name, 'mimeType': FOLDER_MIME, 'parents': [parent_id]}
        return self._exec(self.s.files().create(body=body, fields='id', supportsAllDrives=True),
                          'Drive create folder')['id']

    def get(self, file_id: str, fields: str = 'id,name,mimeType,size,webViewLink,md5Checksum,parents'):
        return self._exec(self.s.files().get(fileId=file_id, fields=fields, supportsAllDrives=True), 'Drive get')

    def upload_file(self, path: Path, parent_id: str, name: str = None, mimetype: str = 'application/octet-stream',
                    replace_existing: bool = True) -> dict:
        from googleapiclient.http import MediaFileUpload
        name = name or Path(path).name
        old = self.find_child(parent_id, name, folder=False) if replace_existing else None
        media = MediaFileUpload(str(path), mimetype=mimetype, resumable=True, chunksize=32 * 1024 * 1024)
        if old:
            req = self.s.files().update(fileId=old['id'], media_body=media,
                                        fields='id,webViewLink,size,md5Checksum', supportsAllDrives=True)
        else:
            req = self.s.files().create(body={'name': name, 'parents': [parent_id]}, media_body=media,
                                        fields='id,webViewLink,size,md5Checksum', supportsAllDrives=True)

        def _upload():
            response = None
            while response is None:
                _, response = req.next_chunk(num_retries=5)
            return response
        return with_retry(_upload, f'Drive upload ({name})', max_retries=3, base_delay=10, logger=self.log)

    def upload_bytes(self, content: bytes, parent_id: str, name: str, mimetype: str = 'application/json') -> dict:
        import io
        from googleapiclient.http import MediaIoBaseUpload
        old = self.find_child(parent_id, name, folder=False)
        media = MediaIoBaseUpload(io.BytesIO(content), mimetype=mimetype, resumable=False)
        if old:
            req = self.s.files().update(fileId=old['id'], media_body=media, fields='id,webViewLink',
                                        supportsAllDrives=True)
        else:
            req = self.s.files().create(body={'name': name, 'parents': [parent_id]}, media_body=media,
                                        fields='id,webViewLink', supportsAllDrives=True)
        return self._exec(req, f'Drive write ({name})')

    def download(self, file_id: str, dest: Path, max_bytes: int = 0) -> int:
        """Streams a binary file to disk. Returns bytes written. Raises if max_bytes exceeded."""
        from googleapiclient.http import MediaIoBaseDownload
        dest = Path(dest)
        dest.parent.mkdir(parents=True, exist_ok=True)

        def _dl():
            with open(dest, 'wb') as fh:
                request = self.s.files().get_media(fileId=file_id, supportsAllDrives=True)
                downloader = MediaIoBaseDownload(fh, request, chunksize=16 * 1024 * 1024)
                done = False
                while not done:
                    _, done = downloader.next_chunk(num_retries=4)
                    if max_bytes and fh.tell() > max_bytes:
                        raise RuntimeError('download exceeds size limit')
            return dest.stat().st_size
        return with_retry(_dl, 'Drive download', max_retries=3, base_delay=5, logger=self.log)

    def read_json(self, parent_id: str, name: str, default=None):
        f = self.find_child(parent_id, name, folder=False)
        if not f:
            return default
        try:
            data = self._exec(self.s.files().get_media(fileId=f['id'], supportsAllDrives=True), f'Drive read ({name})')
            return json.loads(data.decode('utf-8') if isinstance(data, bytes) else data)
        except Exception:
            return default

    def write_json(self, parent_id: str, name: str, data) -> dict:
        return self.upload_bytes(json.dumps(data, indent=1, default=str).encode('utf-8'), parent_id, name)

    def move(self, file_id: str, new_parent: str):
        meta = self.get(file_id, fields='parents')
        old_parents = ','.join(meta.get('parents', []))
        return self._exec(self.s.files().update(fileId=file_id, addParents=new_parent, removeParents=old_parents,
                                                fields='id,parents', supportsAllDrives=True), 'Drive move')

    def delete(self, file_id: str):
        try:
            self._exec(self.s.files().delete(fileId=file_id, supportsAllDrives=True), 'Drive delete')
        except Exception as exc:
            if 'notFound' not in str(exc) and '404' not in str(exc):
                raise


# --------------------------------------------------------------------------- #
# HTML report builder (self-contained, sober black / white / red styling)
# --------------------------------------------------------------------------- #
SEVERITY_ORDER = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'WARNING': 2, 'LOW': 3, 'INFO': 4, 'OK': 5, 'NONE': 5}

_CSS = """
*{box-sizing:border-box}body{font-family:Segoe UI,Helvetica,Arial,sans-serif;margin:0;background:#f4f4f4;color:#111}
header{background:#111;color:#fff;padding:22px 32px;border-bottom:4px solid #c8102e}
header h1{margin:0;font-size:22px;font-weight:600}header p{margin:6px 0 0;color:#bbb;font-size:13px}
main{padding:24px 32px;max-width:1500px}section{background:#fff;border:1px solid #ddd;margin:0 0 20px;padding:18px 22px}
h2{font-size:16px;margin:0 0 12px;padding-bottom:6px;border-bottom:2px solid #c8102e;display:inline-block}
.kpis{display:flex;flex-wrap:wrap;gap:12px}.kpi{border:1px solid #ddd;padding:10px 16px;min-width:150px;background:#fafafa}
.kpi .v{font-size:22px;font-weight:700}.kpi .l{font-size:11px;color:#666;text-transform:uppercase;letter-spacing:.04em}
table{border-collapse:collapse;width:100%;font-size:12.5px}th{background:#111;color:#fff;text-align:left;padding:7px 8px;position:sticky;top:0}
td{border-bottom:1px solid #e5e5e5;padding:6px 8px;vertical-align:top;word-break:break-word}tr:nth-child(even) td{background:#fafafa}
.b{display:inline-block;padding:2px 8px;font-size:11px;font-weight:700;border-radius:2px;color:#fff;background:#777}
.CRITICAL{background:#7a0019}.HIGH{background:#c8102e}.MEDIUM,.WARNING{background:#e07b00}.LOW{background:#b59a00}
.INFO{background:#6b6b6b}.OK,.NONE,.CLEAN,.PASS{background:#2e7d32}.FAIL,.INFECTED{background:#c8102e}.SUSPICIOUS{background:#e07b00}
.SKIPPED,.CACHED{background:#999}pre{background:#111;color:#eee;padding:12px;overflow:auto;font-size:11.5px;max-height:600px;white-space:pre-wrap}
p.note{color:#555;font-size:12.5px}footer{color:#888;font-size:11px;padding:0 32px 24px}
"""


def badge(value: str) -> str:
    v = html.escape(str(value))
    cls = ''.join(ch for ch in str(value).upper() if ch.isalnum() or ch == '_')
    return f'<span class="b {cls}">{v}</span>'


class HtmlReport:
    def __init__(self, title: str, subtitle: str = ''):
        self.title = title
        self.subtitle = subtitle or ts_label()
        self.parts = []

    def kpis(self, items: dict, heading: str = 'Summary'):
        cells = ''.join(f'<div class="kpi"><div class="v">{html.escape(str(v))}</div>'
                        f'<div class="l">{html.escape(str(k))}</div></div>' for k, v in items.items())
        self.parts.append(f'<section><h2>{html.escape(heading)}</h2><div class="kpis">{cells}</div></section>')

    def table(self, heading: str, headers: list, rows: list, badge_cols=(), raw_cols=(), note: str = ''):
        """rows: list of lists. badge_cols: column indexes rendered as badges. raw_cols: trusted HTML."""
        head = ''.join(f'<th>{html.escape(str(h))}</th>' for h in headers)
        body = []
        for r in rows:
            cells = []
            for i, c in enumerate(r):
                if i in badge_cols:
                    cells.append(f'<td>{badge(c)}</td>')
                elif i in raw_cols:
                    cells.append(f'<td>{c}</td>')
                else:
                    cells.append(f'<td>{html.escape(str(c if c is not None else ""))}</td>')
            body.append('<tr>' + ''.join(cells) + '</tr>')
        if not rows:
            body.append(f'<tr><td colspan="{len(headers)}">No entries.</td></tr>')
        note_html = f'<p class="note">{html.escape(note)}</p>' if note else ''
        self.parts.append(f'<section><h2>{html.escape(heading)}</h2>{note_html}'
                          f'<table><thead><tr>{head}</tr></thead><tbody>{"".join(body)}</tbody></table></section>')

    def text(self, heading: str, paragraphs):
        if isinstance(paragraphs, str):
            paragraphs = [paragraphs]
        ps = ''.join(f'<p class="note">{html.escape(p)}</p>' for p in paragraphs)
        self.parts.append(f'<section><h2>{html.escape(heading)}</h2>{ps}</section>')

    def pre(self, heading: str, content: str, max_chars: int = 200_000):
        content = content or ''
        if len(content) > max_chars:
            content = '...(truncated, see full log attachment)...\n' + content[-max_chars:]
        self.parts.append(f'<section><h2>{html.escape(heading)}</h2><pre>{html.escape(content)}</pre></section>')

    def link(self, url: str, label: str = None) -> str:
        return f'<a href="{html.escape(url, quote=True)}">{html.escape(label or url)}</a>'

    def render(self) -> str:
        return ('<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">'
                '<meta name="viewport" content="width=device-width,initial-scale=1">'
                f'<title>{html.escape(self.title)}</title><style>{_CSS}</style></head><body>'
                f'<header><h1>{html.escape(self.title)}</h1><p>{html.escape(self.subtitle)}</p></header>'
                f'<main>{"".join(self.parts)}</main>'
                f'<footer>Generated automatically on {ts_label()}. Confidential - do not forward.</footer>'
                '</body></html>')

    def write(self, path: Path) -> Path:
        Path(path).write_text(self.render(), encoding='utf-8')
        return Path(path)


def write_csv(path: Path, headers: list, rows: list) -> Path:
    import csv
    with open(path, 'w', newline='', encoding='utf-8-sig') as f:
        w = csv.writer(f, delimiter=';')
        w.writerow(headers)
        for r in rows:
            w.writerow(['' if c is None else str(c) for c in r])
    return Path(path)


# --------------------------------------------------------------------------- #
# Mail delivery with automatic packing / splitting of attachments
# --------------------------------------------------------------------------- #
def _zip_files(files, zip_path: Path) -> Path:
    with zipfile.ZipFile(zip_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for f in files:
            f = Path(f)
            if f.is_dir():
                for sub in sorted(f.rglob('*')):
                    if sub.is_file():
                        zf.write(sub, arcname=str(Path(f.name) / sub.relative_to(f)))
            elif f.exists():
                zf.write(f, arcname=f.name)
    return zip_path


def _split_into_zips(files, workdir: Path, base: str, limit_bytes: int) -> list:
    """Greedy split of files into several zips that each stay below limit_bytes."""
    groups, current, current_size = [], [], 0
    for f in sorted((Path(x) for x in files), key=lambda p: p.stat().st_size if p.exists() else 0):
        size = f.stat().st_size if f.exists() else 0
        compressible = f.suffix.lower() in ('.html', '.htm', '.json', '.csv', '.txt', '.log', '.xml', '.md')
        est = int(size * 0.6) if compressible else size  # conservative compression estimate
        if current and current_size + est > limit_bytes:
            groups.append(current)
            current, current_size = [], 0
        current.append(f)
        current_size += est
    if current:
        groups.append(current)
    zips = []
    for i, g in enumerate(groups, 1):
        zips.append(_zip_files(g, workdir / f'{base}_part{i}of{len(groups)}.zip'))
    return zips


def deliver_report(subject: str, body: str, primary: list, bulk: list = None, logger: SummaryLogger = None,
                   workdir: Path = Path('.'), bulk_name: str = 'detailed_reports') -> int:
    """Send the report.

    primary: small files that always go into mail #1 (HTML summary, CSV, log).
    bulk:    possibly large files (per-target reports). They are zipped and, if needed,
             split across additional mails so no single mail exceeds the size limit.
    Returns number of mails sent.
    """
    limit = int(MAX_MAIL_ATTACHMENT_MB * 1024 * 1024)
    primary = [Path(p) for p in (primary or []) if p and Path(p).exists()]
    bulk = [Path(p) for p in (bulk or []) if p and Path(p).exists()]
    created = []
    attachments = list(primary)
    if sum(p.stat().st_size for p in attachments) > limit:
        z = _zip_files(attachments, workdir / 'report_bundle.zip')
        created.append(z)
        attachments = [z]

    extra_mails = []
    if bulk:
        zips = _split_into_zips(bulk, workdir, bulk_name, limit)
        created.extend(zips)
        used = sum(p.stat().st_size for p in attachments)
        first = zips[0]
        if used + first.stat().st_size <= limit:
            attachments.append(first)
            extra_mails = zips[1:]
        else:
            extra_mails = zips

    sent = 0
    total = 1 + len(extra_mails)
    suffix = f' [1/{total}]' if total > 1 else ''
    if extra_mails:
        body += f'\n\nDetailed reports are split across {total} e-mails because of size limits.'
    try:
        if send_email_report(subject + suffix, body, attachments=attachments, logger=logger):
            sent += 1
    except Exception as exc:
        if logger:
            logger.log(f'Mail with attachments failed: {exc}. Retrying without large attachments.')
        try:
            small = [p for p in attachments if p.stat().st_size < 5 * 1024 * 1024]
            if send_email_report(subject + suffix + ' (reduced)', body + '\n\nSome attachments were too large.',
                                 attachments=small, logger=logger):
                sent += 1
        except Exception:
            pass
    for i, z in enumerate(extra_mails, 2):
        try:
            if send_email_report(f'{subject} [{i}/{total}]', f'Part {i} of {total}: detailed reports attached.',
                                 attachments=[z], logger=logger):
                sent += 1
        except Exception as exc:
            if logger:
                logger.log(f'Mail part {i} failed: {exc}')
    shred_paths(*created)
    return sent


def write_log(logger: SummaryLogger, path: Path, header: str = '') -> Path:
    path = Path(path)
    path.write_text((header + '\n' if header else '') + '\n'.join(logger.lines) + '\n', encoding='utf-8')
    return path
