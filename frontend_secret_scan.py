#!/usr/bin/env python3
import re
import sys
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import requests

from common import env, Redactor, SummaryLogger, send_google_chat, send_email_report
from domain_common import parse_list, get_zones, get_all_records, web_hostnames
from pathlib import Path

CLOUDFLARE_API_TOKEN = env('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_ZONE_EXCLUDE = env('CLOUDFLARE_ZONE_EXCLUDE', default='')
FRONTEND_SCAN_IGNORE_HOSTS = env('FRONTEND_SCAN_IGNORE_HOSTS', default='')
MAX_JS_FILES_PER_HOST = int(env('MAX_JS_FILES_PER_HOST', default='25'))
MAX_BYTES_PER_FILE = int(env('MAX_BYTES_PER_FILE', default='3000000'))
REQUEST_TIMEOUT = int(env('REQUEST_TIMEOUT_SECONDS', default='15'))
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='frontend_secret_scan_summary.txt'))

redact = Redactor([CLOUDFLARE_API_TOKEN])
log = SummaryLogger(redact)
SEVERITY_ICON = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'INFO': '⚪', 'NONE': '✅'}

SECRET_PATTERNS = [
    ('AWS Access Key ID', re.compile(r'\bAKIA[0-9A-Z]{16}\b'), 'CRITICAL',
     'AWS-Zugriffsschluessel im Frontend-Code gefunden - AWS-Keys gehoeren NIEMALS ins Frontend.'),
    ('AWS Secret Access Key (Kontext)', re.compile(r'aws_secret_access_key["\']?\s*[:=]\s*["\']?[A-Za-z0-9/+=]{40}["\']?', re.I), 'CRITICAL',
     'Moeglicher AWS-Secret-Access-Key im Frontend-Code gefunden.'),
    ('Google API Key', re.compile(r'\bAIza[0-9A-Za-z\-_]{35}\b'), 'MEDIUM',
     'Google-API-Key gefunden - PRUEFEN, ob dieser Key in der Google Cloud Console auf bestimmte Domains/APIs eingeschraenkt ist (falls ja, ist eine Veroeffentlichung im Frontend ueblich und unkritisch; falls nein, sofort einschraenken).'),
    ('Stripe Secret Key (live)', re.compile(r'\bsk_live_[0-9a-zA-Z]{20,}\b'), 'CRITICAL',
     'Stripe LIVE Secret Key im Frontend gefunden - erlaubt vollen Zugriff auf euer Stripe-Konto (Zahlungen, Kundendaten). SOFORT im Stripe-Dashboard widerrufen.'),
    ('Stripe Secret Key (test)', re.compile(r'\bsk_test_[0-9a-zA-Z]{20,}\b'), 'MEDIUM',
     'Stripe TEST Secret Key im Frontend gefunden - im Testmodus geringeres Risiko, sollte aber trotzdem nicht oeffentlich sein.'),
    ('GitHub Personal Access Token', re.compile(r'\bgh[pousr]_[0-9A-Za-z]{36,}\b'), 'CRITICAL',
     'GitHub-Zugriffstoken im Frontend gefunden - erlaubt ggf. Zugriff auf private Repos/Aktionen. SOFORT widerrufen.'),
    ('Slack Token', re.compile(r'\bxox[baprs]-[0-9A-Za-z\-]{10,}\b'), 'HIGH',
     'Slack-Zugriffstoken im Frontend gefunden.'),
    ('SendGrid API Key', re.compile(r'\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b'), 'CRITICAL',
     'SendGrid-API-Key im Frontend gefunden - erlaubt Mailversand in eurem Namen.'),
    ('Mailgun API Key', re.compile(r'\bkey-[0-9a-zA-Z]{32}\b'), 'HIGH',
     'Moeglicher Mailgun-API-Key im Frontend gefunden.'),
    ('Twilio Auth Token (Kontext)', re.compile(r'twilio[_-]?auth[_-]?token["\']?\s*[:=]\s*["\']?[0-9a-f]{32}["\']?', re.I), 'CRITICAL',
     'Twilio-Auth-Token im Frontend gefunden - erlaubt SMS/Anrufe in eurem Namen.'),
    ('Private-Key-Block', re.compile(r'-----BEGIN (RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'), 'CRITICAL',
     'Ein privater kryptografischer Schluessel ist direkt im Frontend-Code eingebettet - das darf NIEMALS oeffentlich sein.'),
    ('Firebase Server-Key (Kontext)', re.compile(r'firebase[_-]?(server|admin)[_-]?key["\']?\s*[:=]\s*["\']?[A-Za-z0-9_\-:]{30,}["\']?', re.I), 'CRITICAL',
     'Moeglicher Firebase-Server-/Admin-Key im Frontend gefunden.'),
    ('Hartcodiertes JWT', re.compile(r'\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b'), 'HIGH',
     'Ein fest einprogrammiertes JSON-Web-Token (Zugriffstoken) wurde im Frontend gefunden - falls dieses Token echte Rechte hat, kann es von jedem Besucher ausgelesen und wiederverwendet werden.'),
    ('Generische Secret-Zuweisung', re.compile(r'(?:secret|api[_-]?key|access[_-]?token|client[_-]?secret)["\']?\s*[:=]\s*["\'][A-Za-z0-9_\-]{20,}["\']', re.I), 'MEDIUM',
     'Eine Variable mit einem "secret/key/token"-aehnlichen Namen und einem langen, zufaellig aussehenden Wert wurde gefunden - bitte manuell pruefen, ob es sich um einen echten, sensiblen Schluessel handelt.'),
]

SAFE_PUBLIC_PREFIXES = ('pk_live_', 'pk_test_', 'NEXT_PUBLIC_', 'VITE_PUBLIC_', 'PUBLIC_')

SCRIPT_SRC_RE = re.compile(r'<script[^"\']+["\']', re.I)
INLINE_SCRIPT_RE = re.compile(r'<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>', re.I | re.S)


def _shred(path: Path):
    try:
        if path.exists():
            path.write_bytes(b'0' * path.stat().st_size)
            path.unlink()
    except Exception:
        pass


def fetch(url: str) -> str:
    r = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True,
                      headers={'User-Agent': 'linkspreed-isms-frontend-secret-scan/1.0'},
                      stream=True)
    r.raise_for_status()
    content = r.raw.read(MAX_BYTES_PER_FILE + 1, decode_content=True)
    return content[:MAX_BYTES_PER_FILE].decode('utf-8', errors='ignore')


def collect_js_urls(base_url: str, html: str) -> list:
    urls = []
    for m in SCRIPT_SRC_RE.finditer(html):
        src = m.group(1).strip()
        if src.startswith('data:'):
            continue
        full = urljoin(base_url, src)
        parsed_full = urlparse(full)
        parsed_base = urlparse(base_url)
        if parsed_full.netloc == parsed_base.netloc:
            urls.append(full)
    return urls[:MAX_JS_FILES_PER_HOST]


def scan_content(content: str, source_label: str) -> list:
    findings = []
    for name, pattern, severity, note in SECRET_PATTERNS:
        for m in pattern.finditer(content):
            matched_text = m.group(0)
            if any(safe in matched_text for safe in SAFE_PUBLIC_PREFIXES):
                continue
            snippet = matched_text[:12] + '...' + matched_text[-4:] if len(matched_text) > 20 else matched_text[:6] + '...'
            findings.append((severity, source_label, f'{name}: {note} (Ausschnitt zur Wiedererkennung: {snippet})'))
    return findings


def scan_host(host: str) -> tuple:
    findings = []
    base_url = None
    last_err = None
    for scheme in ('https', 'http'):
        try:
            base_url = f'{scheme}://{host}'
            html = fetch(base_url)
            break
        except Exception as e:
            html = None
            last_err = str(e)
    if html is None:
        return (findings, f'nicht erreichbar per HTTP(S): {last_err}')

    try:
        findings.extend(scan_content(html, f'{host} (HTML der Startseite)'))
    except Exception as e:
        return (findings, f'Fehler bei der Analyse des HTML-Inhalts: {e}')

    try:
        for m in INLINE_SCRIPT_RE.finditer(html):
            findings.extend(scan_content(m.group(1), f'{host} (Inline-<script>-Block)'))
    except Exception:
        pass

    try:
        js_urls = collect_js_urls(base_url, html)
    except Exception:
        js_urls = []

    for js_url in js_urls:
        try:
            js_content = fetch(js_url)
        except Exception:
            continue
        try:
            findings.extend(scan_content(js_content, f'{host} -> {js_url}'))
        except Exception:
            continue

    return (findings, None)


def send_final_report(level, all_findings, hosts_scanned, hosts_unreachable, zones_count, duration, fatal_error=None):
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}
    header = [
        f'SEVERITY_LEVEL: {level}',
        f'Frontend-Secret-Scan (Live-Webseiten) - {datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")}',
        f'Zonen: {zones_count} | Hosts erfolgreich gescannt: {hosts_scanned} | Nicht auswertbar/erreichbar: {hosts_unreachable} | Funde: {len(all_findings)}',
        f'Dauer: {duration}s',
        '',
    ]
    if fatal_error:
        header.append(f'!! Der Lauf wurde durch einen uebergeordneten Fehler vorzeitig beendet (unabhaengig von einzelnen Hosts): {fatal_error}')
        header.append('')
    if all_findings:
        header.append('----- Gefundene moegliche Secrets im Frontend-Code (nach Schwere sortiert) -----')
        for sev, source, detail in sorted(all_findings, key=lambda f: order.get(f[0], 9)):
            header.append(f'{SEVERITY_ICON.get(sev, "?")} [{sev}] {source}: {detail}')
        header.append('')
        header.append('WICHTIG: Ein hier gemeldeter Fund liegt auf einer OEFFENTLICH AUSGELIEFERTEN Seite - jeder Besucher kann ihn im Quelltext sehen. Bei CRITICAL/HIGH: betroffenen Schluessel SOFORT beim jeweiligen Anbieter widerrufen/rotieren, dann erst aus dem Code entfernen.')
    else:
        header.append('Keine bekannten Secret-Muster im gescannten Frontend-Code gefunden.')
    header.append('')
    header.append('----- Vollstaendiges Protokoll -----')

    full_report = '\n'.join(header) + '\n' + '\n'.join(log.lines) + '\n'
    SUMMARY_FILE.write_text(full_report, encoding='utf-8')

    subject = f'{SEVERITY_ICON.get(level, "✅")} Frontend-Secret-Scan ({level}) - {len(all_findings)} Fund(e)'
    body = f'{subject}\n\nDer vollstaendige Report befindet sich im Anhang.\n'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE], logger=log)
    except Exception:
        pass

    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK,
                              f'{SEVERITY_ICON.get(level, "✅")} Frontend-Secret-Scan: {level} '
                              f'({len(all_findings)} Fund(e) auf {hosts_scanned} Live-Seiten). Vollstaendiger Report per E-Mail.')
        except Exception:
            pass

    _shred(SUMMARY_FILE)


def main():
    start = datetime.now(timezone.utc)
    zone_exclude = parse_list(CLOUDFLARE_ZONE_EXCLUDE)
    ignore_hosts = set(parse_list(FRONTEND_SCAN_IGNORE_HOSTS))
    all_findings = []
    hosts_scanned = 0
    hosts_unreachable = 0
    zones_count = 0
    fatal_error = None

    try:
        if not CLOUDFLARE_API_TOKEN:
            raise RuntimeError('CLOUDFLARE_API_TOKEN ist nicht gesetzt (Secret fehlt oder ist leer).')
        zones = get_zones(CLOUDFLARE_API_TOKEN, zone_exclude, logger=log)
        zones_count = len(zones)
        records = get_all_records(CLOUDFLARE_API_TOKEN, zones, logger=log)
        hosts = web_hostnames(records)

        for host in hosts:
            if host in ignore_hosts:
                continue
            try:
                findings, error = scan_host(host)
            except Exception as e:
                hosts_unreachable += 1
                log.log(f'{host}: unerwarteter Fehler beim Scannen ({redact(str(e))}) - Host uebersprungen, Lauf laeuft fuer die uebrigen Hosts weiter.')
                continue
            if error:
                hosts_unreachable += 1
                log.log(f'{host}: {error}')
                continue
            hosts_scanned += 1
            all_findings.extend(findings)
    except Exception as e:
        fatal_error = str(e)
        log.log(f'FATAL (uebergeordneter Fehler, z.B. Cloudflare-Zugriff selbst): {fatal_error}')

    duration = int((datetime.now(timezone.utc) - start).total_seconds())
    level = 'NONE'
    for lvl in ('CRITICAL', 'HIGH', 'MEDIUM', 'INFO'):
        if any(f[0] == lvl for f in all_findings):
            level = lvl
            break
    if fatal_error and level == 'NONE':
        level = 'INFO'

    send_final_report(level, all_findings, hosts_scanned, hosts_unreachable, zones_count, duration, fatal_error)
    sys.exit(1 if (fatal_error or level in ('CRITICAL', 'HIGH')) else 0)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
