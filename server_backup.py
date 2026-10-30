#!/usr/bin/env python3
"""Full VPS backup over SSH, streamed and encrypted directly into Google Drive.

Pipeline per backup part (nothing is written to the runner's disk):
    ssh  ->  remote: tar | zstd (or gzip)   ->   local: gpg --symmetric AES256   ->   Drive resumable upload

Parts: rootfs (complete filesystem minus virtual/temporary paths), MySQL/MariaDB dump,
PostgreSQL dump, system inventory. All parts land in a dated folder inside a Shared Drive;
older backup folders beyond the retention count are deleted.
"""
import hashlib
import json
import os
import shlex
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from common import env, Redactor, SummaryLogger
from sec_common import (Drive, DRIVE_SCOPE, HtmlReport, deliver_report, drive_service, google_credentials,
                        human_bytes, human_duration, shred_paths, ts_label, utc_now, write_log)

VPS_HOST = env('VPS_HOST')
VPS_PORT = env('VPS_PORT', default='22') or '22'
VPS_USER = env('VPS_USER', default='root') or 'root'
VPS_SSH_KEY = env('VPS_SSH_KEY')
VPS_KNOWN_HOSTS = env('VPS_KNOWN_HOSTS')
ENC_PASSPHRASE = env('BACKUP_ENC_PASSPHRASE')
EXTRA_EXCLUDES = env('VPS_BACKUP_EXCLUDES', default='')
GDRIVE_SA_JSON = env('GDRIVE_SA_JSON')
GDRIVE_FOLDER_ID = env('VPS_BACKUP_FOLDER_ID') or env('GDRIVE_FOLDER_ID')
ROOT_FOLDER_NAME = env('VPS_BACKUP_FOLDER_NAME', default='Server_Backups')
RETENTION = max(1, int(env('VPS_BACKUP_RETENTION', default='7') or 7))
INCLUDE_DB = env('VPS_BACKUP_INCLUDE_DB', default='true').lower() == 'true'
INCLUDE_DOCKER_LAYERS = env('VPS_BACKUP_INCLUDE_DOCKER_LAYERS', default='false').lower() == 'true'
CHUNK = 64 * 1024 * 1024  # multiple of 256 KiB as required by Drive

redact = Redactor([VPS_HOST, VPS_SSH_KEY, ENC_PASSPHRASE, GDRIVE_SA_JSON, VPS_USER if VPS_USER != 'root' else None])
log = SummaryLogger(redact)
START = time.monotonic()
SSH_DIR = Path(tempfile.mkdtemp(prefix='bk_'))

BASE_EXCLUDES = ['/proc', '/sys', '/dev', '/run', '/tmp', '/mnt', '/media', '/lost+found', '/var/tmp',
                 '/swapfile', '/swap.img', '/var/cache/apt/archives', '/var/lib/lxcfs', '/snap/*/*/.cache']


# --------------------------------------------------------------------------- #
# SSH helpers
# --------------------------------------------------------------------------- #
def ssh_setup():
    if not (VPS_HOST and VPS_SSH_KEY and VPS_KNOWN_HOSTS):
        raise RuntimeError('VPS_HOST, VPS_SSH_KEY and VPS_KNOWN_HOSTS secrets are required.')
    key = SSH_DIR / 'id'
    key.write_text(VPS_SSH_KEY.strip() + '\n', encoding='utf-8')
    os.chmod(key, 0o600)
    kh = SSH_DIR / 'known_hosts'
    kh.write_text(VPS_KNOWN_HOSTS.strip() + '\n', encoding='utf-8')
    return ['ssh', '-i', str(key), '-p', str(VPS_PORT), '-o', f'UserKnownHostsFile={kh}',
            '-o', 'StrictHostKeyChecking=yes', '-o', 'BatchMode=yes', '-o', 'ServerAliveInterval=30',
            '-o', 'ServerAliveCountMax=10', '-o', 'LogLevel=ERROR', '-o', 'Compression=no',
            f'{VPS_USER}@{VPS_HOST}']


def ssh_run(base, script: str, timeout=300):
    proc = subprocess.run(base + ['bash -c ' + shlex.quote(script)], capture_output=True, text=True,
                          timeout=timeout, errors='replace')
    return proc.returncode, proc.stdout, proc.stderr


PREFLIGHT = r'''
set -u
echo "uid=$(id -u)"
echo "hostname=$(hostname -f 2>/dev/null || hostname)"
echo "os=$(. /etc/os-release 2>/dev/null; echo ${PRETTY_NAME:-unknown})"
echo "kernel=$(uname -r)"
echo "uptime=$(uptime -p 2>/dev/null)"
echo "rootfs_used_kb=$(df -Pk / | awk 'NR==2{print $3}')"
echo "total_used_kb=$(df -Pk -x tmpfs -x devtmpfs -x overlay -x squashfs 2>/dev/null | awk 'NR>1{s+=$3}END{print s}')"
for t in zstd pigz gzip mysqldump mariadb-dump pg_dumpall docker; do command -v $t >/dev/null 2>&1 && echo "has_$t=1"; done
if [ "$(id -u)" != "0" ]; then sudo -n true 2>/dev/null && echo "sudo=1" || echo "sudo=0"; fi
(systemctl is-active mysql mariadb 2>/dev/null | grep -q '^active') && echo "mysql_active=1"
(systemctl is-active postgresql 2>/dev/null | grep -q '^active') && echo "pg_active=1"
'''


def preflight(base) -> dict:
    rc, out, err = ssh_run(base, PREFLIGHT, timeout=120)
    if rc not in (0, 1) or 'uid=' not in out:
        raise RuntimeError(f'SSH preflight failed (rc={rc}): {redact(err.strip())[-300:]}')
    info = {}
    for line in out.splitlines():
        if '=' in line:
            k, v = line.split('=', 1)
            info[k.strip()] = v.strip()
    if info.get('uid') != '0' and info.get('sudo') != '1':
        raise RuntimeError('Remote user is not root and has no passwordless sudo - a full backup is impossible.')
    return info


# --------------------------------------------------------------------------- #
# Drive streaming upload (resumable, unknown total size)
# --------------------------------------------------------------------------- #
class StreamUploader:
    def __init__(self, parent_id: str, name: str):
        from google.auth.transport.requests import AuthorizedSession
        self.session = AuthorizedSession(google_credentials(GDRIVE_SA_JSON, [DRIVE_SCOPE]))
        meta = {'name': name, 'parents': [parent_id]}
        r = self.session.post('https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable'
                              '&supportsAllDrives=true&fields=id,size,md5Checksum,webViewLink',
                              json=meta, headers={'X-Upload-Content-Type': 'application/octet-stream'}, timeout=60)
        r.raise_for_status()
        self.url = r.headers['Location']
        self.offset = 0
        self.result = None

    def _put(self, data: bytes, last: bool):
        end = self.offset + len(data) - 1
        total = str(self.offset + len(data)) if last else '*'
        if len(data) == 0:
            rng = f'bytes */{self.offset}'
        else:
            rng = f'bytes {self.offset}-{end}/{total}'
        for attempt in range(1, 8):
            try:
                r = self.session.put(self.url, data=data, headers={'Content-Range': rng}, timeout=600)
                if r.status_code in (200, 201):
                    self.result = r.json()
                    self.offset += len(data)
                    return
                if r.status_code == 308:
                    confirmed = r.headers.get('Range')
                    new_offset = int(confirmed.split('-')[1]) + 1 if confirmed else 0
                    sent = new_offset - self.offset
                    if sent == len(data):
                        self.offset = new_offset
                        return
                    # partial: resend the remainder
                    data = data[sent:]
                    self.offset = new_offset
                    end = self.offset + len(data) - 1
                    rng = f'bytes {self.offset}-{end}/{total}'
                    continue
                if r.status_code in (429, 500, 502, 503, 504):
                    time.sleep(min(60, 5 * attempt))
                    continue
                raise RuntimeError(f'Drive upload HTTP {r.status_code}: {r.text[:200]}')
            except RuntimeError:
                raise
            except Exception as exc:
                log.log(f'Upload chunk retry {attempt}: {exc}')
                time.sleep(min(60, 5 * attempt))
                st = self.session.put(self.url, headers={'Content-Range': f'bytes */{total if last else "*"}'},
                                      timeout=60)
                if st.status_code == 308 and st.headers.get('Range'):
                    new_offset = int(st.headers['Range'].split('-')[1]) + 1
                    data = data[new_offset - self.offset:]
                    self.offset = new_offset
                    end = self.offset + len(data) - 1
                    rng = f'bytes {self.offset}-{end}/{total}' if data else f'bytes */{self.offset}'
        raise RuntimeError('Drive upload failed after retries.')

    def upload_stream(self, stream, digest_sha, digest_md5) -> int:
        def read_full(n):
            buf = bytearray()
            while len(buf) < n:
                block = stream.read(n - len(buf))
                if not block:
                    break
                buf += block
            return bytes(buf)
        current = read_full(CHUNK)
        while True:
            nxt = read_full(CHUNK)
            digest_sha.update(current)
            digest_md5.update(current)
            last = len(nxt) == 0
            self._put(current, last)
            if last:
                return self.offset
            current = nxt


def stream_part(base, remote_script: str, folder_id: str, name: str, timeout_h: int = 5) -> dict:
    """Run remote_script (stdout = data), encrypt locally with gpg, stream to Drive."""
    pass_file = SSH_DIR / 'pp'
    pass_file.write_text(ENC_PASSPHRASE, encoding='utf-8')
    os.chmod(pass_file, 0o600)
    err_file = SSH_DIR / f'{name}.err'
    started = time.monotonic()
    with open(err_file, 'w') as errf:
        ssh = subprocess.Popen(base + ['bash -c ' + shlex.quote(remote_script)], stdout=subprocess.PIPE,
                               stderr=errf, stdin=subprocess.DEVNULL)
        gpg = subprocess.Popen(['gpg', '--batch', '--yes', '--quiet', '--symmetric', '--cipher-algo', 'AES256',
                                '--compress-algo', 'none', '--s2k-digest-algo', 'SHA512', '--s2k-count', '65011712',
                                '--pinentry-mode', 'loopback', '--passphrase-file', str(pass_file), '-o', '-'],
                               stdin=ssh.stdout, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
        ssh.stdout.close()
        watchdog = threading.Timer(timeout_h * 3600, lambda: (ssh.kill(), gpg.kill()))
        watchdog.start()
        sha, md5 = hashlib.sha256(), hashlib.md5()
        try:
            up = StreamUploader(folder_id, name)
            size = up.upload_stream(gpg.stdout, sha, md5)
        finally:
            watchdog.cancel()
            ssh_rc = ssh.wait()
            gpg_rc = gpg.wait()
            shred_paths(pass_file)
    stderr_tail = redact(err_file.read_text(errors='replace'))[-3000:]
    shred_paths(err_file)
    result = up.result or {}
    md5_ok = (result.get('md5Checksum') == md5.hexdigest()) if result.get('md5Checksum') else None
    return {'name': name, 'bytes': size, 'sha256': sha.hexdigest(), 'drive_md5_match': md5_ok,
            'link': result.get('webViewLink', ''), 'remote_rc': ssh_rc, 'gpg_rc': gpg_rc,
            'seconds': int(time.monotonic() - started), 'stderr_tail': stderr_tail}


# --------------------------------------------------------------------------- #
# Remote scripts
# --------------------------------------------------------------------------- #
def sudo(info):
    return '' if info.get('uid') == '0' else 'sudo -n '


def compressor(info):
    if info.get('has_zstd'):
        return 'zstd -T2 -6 -q -c', 'zst'
    if info.get('has_pigz'):
        return 'pigz -p 2 -6 -c', 'gz'
    return 'gzip -6 -c', 'gz'


def rootfs_script(info):
    excludes = list(BASE_EXCLUDES)
    if not INCLUDE_DOCKER_LAYERS:
        excludes += ['/var/lib/docker/overlay2', '/var/lib/docker/image', '/var/lib/containerd']
    excludes += [e for e in (x.strip() for x in EXTRA_EXCLUDES.replace(',', '\n').splitlines()) if e]
    # Members are stored as ./path (because of "-C / ."), so patterns must use the same prefix.
    norm = ['.' + e if e.startswith('/') else e for e in excludes]
    ex = ' '.join(f'--exclude={shlex.quote(e)}' for e in norm)
    comp, _ = compressor(info)
    s = sudo(info)
    return (f'set -o pipefail; {s}nice -n 19 ionice -c3 tar --create --file=- --acls --xattrs --numeric-owner '
            f'--sparse --ignore-failed-read --warning=no-file-changed --warning=no-file-removed '
            f'--warning=no-file-ignored {ex} -C / . | nice -n 19 {comp}; rc=$?; '
            f'[ $rc -eq 1 ] && exit 0; exit $rc')


def mysql_script(info):
    tool = 'mariadb-dump' if info.get('has_mariadb-dump') else 'mysqldump'
    comp, _ = compressor(info)
    return (f'set -o pipefail; {sudo(info)}{tool} --all-databases --single-transaction --quick --routines '
            f'--events --triggers --hex-blob --flush-privileges | {comp}')


def pg_script(info):
    comp, _ = compressor(info)
    return f'set -o pipefail; {sudo(info)}-u postgres pg_dumpall --clean --if-exists | {comp}' if sudo(info) else \
        f'set -o pipefail; su postgres -c "pg_dumpall --clean --if-exists" | {comp}'


def inventory_script(info):
    s = sudo(info)
    return (f'{{ echo "== generated $(date -u)"; echo "== packages"; (dpkg --get-selections 2>/dev/null || rpm -qa); '
            f'echo "== enabled services"; systemctl list-unit-files --state=enabled --no-pager 2>/dev/null; '
            f'echo "== disks"; lsblk -f 2>/dev/null; df -h; echo "== fstab"; cat /etc/fstab; '
            f'echo "== network"; ip -br addr 2>/dev/null; echo "== crontabs"; {s}ls -la /var/spool/cron/crontabs 2>/dev/null; '
            f'echo "== docker"; {s}docker ps -a --format "{{{{.Names}}}} {{{{.Image}}}} {{{{.Status}}}}" 2>/dev/null; '
            f'{s}docker volume ls 2>/dev/null; }} | gzip -c')


RESTORE_TXT = """RESTORE GUIDE
=============
All parts are encrypted with GnuPG (AES-256, symmetric). The passphrase is stored in the
GitHub secret BACKUP_ENC_PASSPHRASE (keep an offline copy in your password manager!).

1) Decrypt:        gpg --decrypt rootfs.tar.zst.gpg > rootfs.tar.zst
2) Test archive:   zstd -t rootfs.tar.zst            (or: gzip -t for .gz)
3) Inspect:        zstd -dc rootfs.tar.zst | tar -tvf - | less
4) Restore files:  zstd -dc rootfs.tar.zst | sudo tar -xpf - --numeric-owner --acls --xattrs -C /mnt/restore
   (restore into an empty, freshly installed system or a rescue-mounted disk, then copy back what you need)
5) MySQL/MariaDB:  gpg -d mysql_all.sql.zst.gpg | zstd -dc | mysql -u root
6) PostgreSQL:     gpg -d postgres_all.sql.zst.gpg | zstd -dc | sudo -u postgres psql
Excluded on purpose: /proc /sys /dev /run /tmp /mnt /media /var/tmp swap files (virtual or temporary data).
"""


# --------------------------------------------------------------------------- #
def main():
    stamp = utc_now().strftime('%Y-%m-%d_%H%M%S')
    parts, info, fatal, folder_link, deleted = [], {}, None, '', []
    report_dir = Path(env('REPORT_DIR', default='bk_reports')).resolve()
    report_dir.mkdir(parents=True, exist_ok=True)
    try:
        if not (GDRIVE_SA_JSON and GDRIVE_FOLDER_ID and ENC_PASSPHRASE):
            raise RuntimeError('GDRIVE_SA_JSON, GDRIVE_FOLDER_ID (Shared Drive) and BACKUP_ENC_PASSPHRASE are required.')
        base = ssh_setup()
        info = preflight(base)
        log.log(f"Preflight ok. Used space approx. {human_bytes(int(info.get('total_used_kb') or 0) * 1024)}.")
        drv = Drive(drive_service(GDRIVE_SA_JSON), log)
        root = drv.ensure_folder(GDRIVE_FOLDER_ID, ROOT_FOLDER_NAME)
        folder = drv.ensure_folder(root, f'vps_{stamp}')
        folder_link = drv.get(folder, fields='webViewLink').get('webViewLink', '')
        _, ext = compressor(info)

        jobs = [('inventory.txt.gz.gpg', inventory_script(info), 1)]
        if INCLUDE_DB and (info.get('has_mysqldump') or info.get('has_mariadb-dump')) and info.get('mysql_active'):
            jobs.append((f'mysql_all.sql.{ext}.gpg', mysql_script(info), 3))
        if INCLUDE_DB and info.get('has_pg_dumpall') and info.get('pg_active'):
            jobs.append((f'postgres_all.sql.{ext}.gpg', pg_script(info), 3))
        jobs.append((f'rootfs.tar.{ext}.gpg', rootfs_script(info), 5))
        for name, script, hours in jobs:
            log.log(f'Starting part {name}.')
            try:
                p = stream_part(base, script, folder, name, timeout_h=hours)
            except Exception as exc:
                p = {'name': name, 'error': redact(str(exc))[:400], 'bytes': 0}
            ok = not p.get('error') and p.get('remote_rc') == 0 and p.get('gpg_rc') == 0 and p.get('bytes', 0) > 0 \
                and p.get('drive_md5_match') is not False
            p['status'] = 'OK' if ok else 'FAIL'
            parts.append(p)
            log.log(f"Part {name}: {p['status']} {human_bytes(p.get('bytes'))} in {human_duration(p.get('seconds', 0))}.")
        manifest = {'created_utc': stamp, 'os': info.get('os'), 'kernel': info.get('kernel'),
                    'parts': [{k: v for k, v in p.items() if k not in ('stderr_tail', 'link')} for p in parts],
                    'encryption': 'gpg symmetric AES256', 'excludes': BASE_EXCLUDES}
        drv.write_json(folder, 'manifest.json', manifest)
        drv.upload_bytes(RESTORE_TXT.encode('utf-8'), folder, 'RESTORE.txt', mimetype='text/plain')
        # Retention: only delete old backups if this one is complete.
        if all(p['status'] == 'OK' for p in parts):
            backups = sorted((f for f in drv.children(root, folders_only=True) if f['name'].startswith('vps_')),
                             key=lambda f: f['name'])
            for old in backups[:-RETENTION]:
                drv.delete(old['id'])
                deleted.append(old['name'])
        else:
            log.log('Retention skipped because this backup is not complete.')
    except Exception as exc:
        fatal = redact(str(exc))
        log.log(f'FATAL: {fatal}')
    finally:
        shred_paths(SSH_DIR)

    ok = not fatal and parts and all(p['status'] == 'OK' for p in parts)
    total = sum(p.get('bytes', 0) for p in parts)
    rep = HtmlReport('Server Backup Report', f'{ts_label()} | Duration {human_duration(time.monotonic() - START)}')
    rep.kpis({'Status': 'OK' if ok else 'FAIL', 'Parts': len(parts), 'Total size (encrypted)': human_bytes(total),
              'Retention': f'last {RETENTION}', 'Deleted old backups': len(deleted)})
    if folder_link:
        rep.table('Backup location', ['Item', 'Link'], [['Backup folder (Google Drive)', rep.link(folder_link)]],
                  raw_cols=(1,))
    if fatal:
        rep.text('Error', [fatal])
    rep.table('Parts', ['Status', 'File', 'Size', 'Duration', 'SHA-256 (encrypted file)', 'Upload verified (MD5)',
                        'Remote exit', 'Link'],
              [[p['status'], p['name'], human_bytes(p.get('bytes')), human_duration(p.get('seconds', 0)),
                p.get('sha256', ''), {True: 'yes', False: 'NO', None: 'n/a'}[p.get('drive_md5_match')],
                p.get('remote_rc', '-'), rep.link(p['link'], 'open') if p.get('link') else (p.get('error') or '')]
               for p in parts], badge_cols=(0,), raw_cols=(7,))
    rep.table('Server', ['Property', 'Value'], [[k, info.get(k, '-')] for k in ('hostname', 'os', 'kernel', 'uptime')]
              + [['Used disk space', human_bytes(int(info.get('total_used_kb') or 0) * 1024)]])
    rep.table('Excluded paths', ['Path'], [[e] for e in BASE_EXCLUDES] +
              ([] if INCLUDE_DOCKER_LAYERS else [['/var/lib/docker/overlay2, /image, containerd (rebuildable layers)']]))
    if deleted:
        rep.table('Removed by retention', ['Folder'], [[d] for d in deleted])
    for p in parts:
        if p.get('stderr_tail'):
            rep.pre(f"Remote messages: {p['name']}", p['stderr_tail'])
    html_path = rep.write(report_dir / f'server_backup_{stamp}.html')
    log_path = write_log(log, report_dir / 'run_log.txt')
    subject = f"{'✅' if ok else '❌'} Server Backup {'OK' if ok else 'FAILED'} - {human_bytes(total)}"
    body = (f'{subject}\n\nBackup folder: {folder_link or "n/a"}\nParts: {len(parts)}\n'
            f'Duration: {human_duration(time.monotonic() - START)}\n\nFull report attached.')
    deliver_report(subject, body, [html_path, log_path], logger=log, workdir=report_dir)
    shred_paths(report_dir)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        shred_paths(SSH_DIR)
        sys.exit(1)
