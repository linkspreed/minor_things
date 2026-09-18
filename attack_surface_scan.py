#!/usr/bin/env python3
import json
import shutil
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from common import env, Redactor, SummaryLogger, send_google_chat, send_email_report
from domain_common import parse_list, get_zones, get_all_records, web_hostnames
CLOUDFLARE_API_TOKEN = env('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_ZONE_EXCLUDE = env('CLOUDFLARE_ZONE_EXCLUDE', default='')
ATTACK_SURFACE_IGNORE_HOSTS = env('ATTACK_SURFACE_IGNORE_HOSTS', default='')
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='attack_surface_summary.txt'))
SUBFINDER_TIMEOUT = int(env('SUBFINDER_TIMEOUT_SECONDS', default='300'))
HTTPX_TIMEOUT = int(env('HTTPX_TIMEOUT_SECONDS', default='300'))
redact = Redactor([CLOUDFLARE_API_TOKEN])
log = SummaryLogger(redact)
SEVERITY_ICON = {'HIGH': '🟠', 'MEDIUM': '🟡', 'INFO': '⚪', 'NONE': '✅'}
REQUIRED_HEADERS = ['strict-transport-security', 'x-content-type-options', 'x-frame-options']
WEAK_TLS = {'tls1.0', 'tls1.1', 'ssl3.0', 'ssl2.0'}

def _shred(path: Path):
    try:
        if path.exists():
            path.write_bytes(b'0' * path.stat().st_size)
            path.unlink()
    except Exception:
        pass

def run_subfinder(domain: str) -> list:
    if shutil.which('subfinder') is None:
        raise RuntimeError('subfinder ist nicht installiert.')
    proc = subprocess.run(['subfinder', '-d', domain, '-silent', '-json'], capture_output=True, text=True, timeout=SUBFINDER_TIMEOUT)
    hosts = []
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            hosts.append(json.loads(line).get('host', '').lower())
        except json.JSONDecodeError:
            continue
    return [h for h in hosts if h]

def run_httpx(hosts: list) -> dict:
    if not hosts:
        return {}
    if shutil.which('httpx') is None:
        raise RuntimeError('httpx ist nicht installiert.')
    proc = subprocess.run(['httpx', '-silent', '-json', '-status-code', '-tls-grab', '-rc'], input='\n'.join(hosts), capture_output=True, text=True, timeout=HTTPX_TIMEOUT)
    results = {}
    for line in proc.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except json.JSONDecodeError:
            continue
        host = (d.get('input') or d.get('host') or '').split(':')[0].lower()
        if host:
            results[host] = d
    return results

def analyse_headers(headers: dict) -> list:
    lower = {k.lower(): v for k, v in (headers or {}).items()}
    return [h for h in REQUIRED_HEADERS if h not in lower]

def send_final_report(level, findings, known_count, discovered_count, unexpected_count, probed_count, zones_count, errors, duration, fatal_error=None):
    header = [f'SEVERITY_LEVEL: {level}', f"Externer Attack-Surface-Scan - {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}", f'Zonen: {zones_count} | Bekannte Hosts (Cloudflare): {known_count} | Neu entdeckt (subfinder): {discovered_count} | Unerwartet: {unexpected_count} | Probed: {probed_count}', f'Dauer: {duration}s', '']
    if fatal_error:
        header.append(f'!! Der Lauf wurde durch einen Fehler vorzeitig beendet: {fatal_error}')
        header.append('')
    if findings:
        header.append('----- Auffaelligkeiten (nach Schwere sortiert) -----')
        order = {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}
        for sev, host, detail in sorted(findings, key=lambda f: order.get(f[0], 9)):
            header.append(f"{SEVERITY_ICON.get(sev, '?')} [{sev}] {host}: {detail}")
        header.append('')
    else:
        header.append('Keine Auffaelligkeiten.')
    if errors:
        header.append('----- Fehler -----')
        header.extend(errors)
        header.append('')
    header.append('----- Vollstaendiges Protokoll -----')
    full_report = '\n'.join(header) + '\n' + '\n'.join(log.lines) + '\n'
    SUMMARY_FILE.write_text(full_report, encoding='utf-8')
    subject = f"{SEVERITY_ICON.get(level, '✅')} Attack-Surface-Scan ({level}) - {len(findings)} Auffaelligkeit(en)"
    body = f'{subject}\n\nDer vollstaendige Report befindet sich im Anhang.\n'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE], logger=log)
    except Exception:
        pass
    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK, f"{SEVERITY_ICON.get(level, '✅')} Attack-Surface-Scan: {level} ({len(findings)} Auffaelligkeit(en), {unexpected_count} unerwartete Hosts). Vollstaendiger Report per E-Mail.")
        except Exception:
            pass
    _shred(SUMMARY_FILE)

def main():
    start = datetime.now(timezone.utc)
    zone_exclude = parse_list(CLOUDFLARE_ZONE_EXCLUDE)
    ignore_hosts = set(parse_list(ATTACK_SURFACE_IGNORE_HOSTS))
    findings = []
    errors = []
    known_hosts = {}
    discovered = set()
    unexpected = []
    probed = {}
    zones_count = 0
    fatal_error = None
    try:
        if not CLOUDFLARE_API_TOKEN:
            raise RuntimeError('CLOUDFLARE_API_TOKEN ist nicht gesetzt (Secret fehlt oder ist leer).')
        zones = get_zones(CLOUDFLARE_API_TOKEN, zone_exclude, logger=log)
        zones_count = len(zones)
        root_domains = [z['name'] for z in zones if z.get('name')]
        records = get_all_records(CLOUDFLARE_API_TOKEN, zones, logger=log)
        known_hosts = web_hostnames(records)
        for domain in root_domains:
            try:
                found = run_subfinder(domain)
                discovered.update(found)
            except Exception as e:
                errors.append(f'subfinder ({domain}): {e}')
        known_set = set(known_hosts.keys()) | set(root_domains)
        unexpected = sorted(discovered - known_set - ignore_hosts)
        all_targets = sorted((known_set | discovered) - ignore_hosts)
        try:
            probed = run_httpx(all_targets)
        except Exception as e:
            errors.append(f'httpx: {e}')
        for host in unexpected:
            findings.append(('MEDIUM', host, 'Von subfinder neu entdeckt, aber NICHT als aktueller Cloudflare-DNS-Eintrag vorhanden - bitte pruefen (evtl. anderer DNS-Provider, veralteter Eintrag oder Schatten-IT).'))
        for host, data in probed.items():
            status = data.get('status_code') or data.get('status-code')
            tls = (data.get('tls', {}) or {}).get('version') or data.get('tls_version') or ''
            tls_norm = str(tls).lower().replace(' ', '').replace('-', '').replace('_', '')
            if tls_norm and any((weak in tls_norm for weak in WEAK_TLS)):
                findings.append(('HIGH', host, f'Veraltete TLS-Version erkannt: {tls}'))
            headers = data.get('header') or data.get('headers') or {}
            missing = analyse_headers(headers) if isinstance(headers, dict) else []
            if missing and status and (int(status) < 400):
                findings.append(('INFO', host, f"Fehlende Security-Header: {', '.join(missing)}"))
    except Exception as e:
        fatal_error = str(e)
        log.log(f'FATAL: {fatal_error}')
    duration = int((datetime.now(timezone.utc) - start).total_seconds())
    level = 'NONE'
    for lvl in ('HIGH', 'MEDIUM', 'INFO'):
        if any((f[0] == lvl for f in findings)):
            level = lvl
            break
    if fatal_error and level == 'NONE':
        level = 'INFO'
    send_final_report(level, findings, len(known_hosts), len(discovered), len(unexpected), len(probed), zones_count, errors, duration, fatal_error)
    sys.exit(1 if fatal_error or level == 'HIGH' else 0)
if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
