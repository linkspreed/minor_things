#!/usr/bin/env python3
"""
Vertiefter TLS-/Zertifikats-/Security-Header-Check (Policy 2.4: "HTTPS only,
HSTS, current TLS, security headers"). Hostliste kommt automatisch live aus
Cloudflare (alle Zonen) - keine manuelle Pflege noetig.

Prueft: TLS-Protokollversion (echter Handshake), Zertifikats-Ablaufdatum,
HSTS max-age, HTTP->HTTPS-Redirect-Pflicht, weitere Security-Header.

Gibt NICHTS auf der Konsole/im Actions-Log aus. Das vollstaendige Ergebnis
geht ausschliesslich per E-Mail (Anhang) an REPORT_TO. Ein Lauf sendet IMMER
eine E-Mail, auch wenn waehrend des Scans ein Fehler auftritt.
"""
import re
import socket
import ssl
import sys
from datetime import datetime, timezone
from pathlib import Path

import requests

from common import env, Redactor, SummaryLogger, send_google_chat, send_email_report
from domain_common import parse_list, get_zones, get_all_records, web_hostnames

CLOUDFLARE_API_TOKEN = env('CLOUDFLARE_API_TOKEN')  # bewusst nicht 'required=True', siehe main()
CLOUDFLARE_ZONE_EXCLUDE = env('CLOUDFLARE_ZONE_EXCLUDE', default='')
CERT_WARN_DAYS = int(env('CERT_EXPIRY_WARN_DAYS', default='21'))
CERT_CRITICAL_DAYS = int(env('CERT_EXPIRY_CRITICAL_DAYS', default='7'))
HSTS_MIN_MAX_AGE = int(env('HSTS_MIN_MAX_AGE_SECONDS', default='15552000'))
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='tls_header_summary.txt'))

redact = Redactor([CLOUDFLARE_API_TOKEN])
log = SummaryLogger(redact)
SEVERITY_ICON = {'HIGH': '🟠', 'MEDIUM': '🟡', 'INFO': '⚪', 'NONE': '✅'}
WEAK_PROTOCOLS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'}


def _shred(path: Path):
    try:
        if path.exists():
            path.write_bytes(b'0' * path.stat().st_size)
            path.unlink()
    except Exception:
        pass


def check_tls(host: str) -> list:
    findings = []
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, 443), timeout=10) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                protocol = ssock.version()
                cert = ssock.getpeercert()
        if protocol in WEAK_PROTOCOLS:
            findings.append(('HIGH', f'Veraltetes TLS-Protokoll ausgehandelt: {protocol}'))
        not_after = cert.get('notAfter')
        if not_after:
            expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
            days_left = (expiry - datetime.now(timezone.utc)).days
            if days_left < CERT_CRITICAL_DAYS:
                findings.append(('HIGH', f'TLS-Zertifikat laeuft in {days_left} Tag(en) ab ({expiry.date()})'))
            elif days_left < CERT_WARN_DAYS:
                findings.append(('MEDIUM', f'TLS-Zertifikat laeuft in {days_left} Tag(en) ab ({expiry.date()})'))
    except ssl.SSLCertVerificationError as e:
        findings.append(('HIGH', f'Zertifikatspruefung fehlgeschlagen: {e}'))
    except (socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
        findings.append(('INFO', f'TLS-Verbindung nicht moeglich: {e}'))
    except Exception as e:
        findings.append(('INFO', f'TLS-Check fehlgeschlagen: {e}'))
    return findings


def check_headers_and_redirect(host: str) -> list:
    findings = []
    try:
        r = requests.get(f'https://{host}', timeout=15, allow_redirects=True,
                          headers={'User-Agent': 'linkspreed-isms-tls-header-check/1.0'})
        headers = {k.lower(): v for k, v in r.headers.items()}

        hsts = headers.get('strict-transport-security')
        if not hsts:
            findings.append(('HIGH', 'Kein Strict-Transport-Security-Header (HSTS fehlt).'))
        else:
            m = re.search(r'max-age=(\d+)', hsts)
            max_age = int(m.group(1)) if m else 0
            if max_age < HSTS_MIN_MAX_AGE:
                findings.append(('MEDIUM', f'HSTS max-age zu niedrig ({max_age}s, empfohlen >= {HSTS_MIN_MAX_AGE}s).'))
            if 'includesubdomains' not in hsts.lower():
                findings.append(('INFO', 'HSTS ohne includeSubDomains gesetzt.'))

        if headers.get('x-content-type-options', '').lower() != 'nosniff':
            findings.append(('MEDIUM', 'X-Content-Type-Options: nosniff fehlt.'))
        if not headers.get('content-security-policy'):
            findings.append(('INFO', 'Content-Security-Policy fehlt.'))
        if not headers.get('referrer-policy'):
            findings.append(('INFO', 'Referrer-Policy fehlt.'))
        if not headers.get('x-frame-options') and 'frame-ancestors' not in headers.get('content-security-policy', '').lower():
            findings.append(('INFO', 'Weder X-Frame-Options noch CSP frame-ancestors gesetzt.'))
    except Exception as e:
        findings.append(('INFO', f'HTTPS-Header-Check fehlgeschlagen: {e}'))
        return findings

    try:
        r2 = requests.get(f'http://{host}', timeout=10, allow_redirects=False,
                           headers={'User-Agent': 'linkspreed-isms-tls-header-check/1.0'})
        if r2.status_code not in (301, 302, 307, 308) or not r2.headers.get('Location', '').startswith('https://'):
            findings.append(('MEDIUM', f'HTTP (Port 80) leitet nicht sauber auf HTTPS um (Status {r2.status_code}).'))
    except Exception:
        pass

    return findings


def send_final_report(level, all_findings, hosts_count, zones_count, duration, fatal_error=None):
    header = [
        f'SEVERITY_LEVEL: {level}',
        f'TLS-/Security-Header-Check - {datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")}',
        f'Zonen: {zones_count} | Hosts geprueft: {hosts_count} | Auffaelligkeiten: {len(all_findings)}',
        f'Dauer: {duration}s',
        '',
    ]
    if fatal_error:
        header.append(f'!! Der Lauf wurde durch einen Fehler vorzeitig beendet: {fatal_error}')
        header.append('')
    if all_findings:
        header.append('----- Auffaelligkeiten (nach Schwere sortiert) -----')
        order = {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}
        for sev, host, detail in sorted(all_findings, key=lambda f: order.get(f[0], 9)):
            header.append(f'{SEVERITY_ICON.get(sev, "?")} [{sev}] {host}: {detail}')
        header.append('')
    else:
        header.append('Keine Auffaelligkeiten.')
    header.append('')
    header.append('----- Vollstaendiges Protokoll -----')

    full_report = '\n'.join(header) + '\n' + '\n'.join(log.lines) + '\n'
    SUMMARY_FILE.write_text(full_report, encoding='utf-8')

    subject = f'{SEVERITY_ICON.get(level, "✅")} TLS-/Header-Check ({level}) - {len(all_findings)} Auffaelligkeit(en)'
    body = f'{subject}\n\nDer vollstaendige Report befindet sich im Anhang.\n'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE], logger=log)
    except Exception:
        pass

    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK,
                              f'{SEVERITY_ICON.get(level, "✅")} TLS-/Header-Check: {level} ({len(all_findings)} Auffaelligkeit(en)). Vollstaendiger Report per E-Mail.')
        except Exception:
            pass

    _shred(SUMMARY_FILE)


def main():
    start = datetime.now(timezone.utc)
    zone_exclude = parse_list(CLOUDFLARE_ZONE_EXCLUDE)
    all_findings = []
    hosts = {}
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
            for sev, detail in check_tls(host) + check_headers_and_redirect(host):
                if sev != 'NONE':
                    all_findings.append((sev, host, detail))
    except Exception as e:
        fatal_error = str(e)
        log.log(f'FATAL: {fatal_error}')

    duration = int((datetime.now(timezone.utc) - start).total_seconds())
    level = 'NONE'
    for lvl in ('HIGH', 'MEDIUM', 'INFO'):
        if any(f[0] == lvl for f in all_findings):
            level = lvl
            break
    if fatal_error and level == 'NONE':
        level = 'INFO'

    send_final_report(level, all_findings, len(hosts), zones_count, duration, fatal_error)
    sys.exit(1 if (fatal_error or level == 'HIGH') else 0)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
