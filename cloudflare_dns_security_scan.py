#!/usr/bin/env python3
import csv
import os
import re
import socket
import ssl
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import requests
from common import env, Redactor, SummaryLogger, send_google_chat, send_email_report, with_retry
from domain_common import parse_list, get_zones, get_all_records, check_takeover_fingerprint, fingerprint_text_for, target_resolves, fetch_body_snippet

CLOUDFLARE_API_TOKEN = env('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_ZONE_EXCLUDE = env('CLOUDFLARE_ZONE_EXCLUDE', default='')
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='cloudflare_dns_summary.txt'))
REPORT_CSV_FILE = Path('cloudflare_dns_security_report.csv')

redact = Redactor([CLOUDFLARE_API_TOKEN])
log = SummaryLogger(redact)

SEVERITY_ICON = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'WARNING': '🟡', 'INFO': '⚪', 'NONE': '✅'}
WEAK_PROTOCOLS = {'SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'}

def check_hostname_tls(hostname: str):
    res = {
        'protocol': 'N/A',
        'issuer': 'N/A',
        'expiry_date': 'N/A',
        'days_until_expiry': -1,
        'san_match': True,
        'findings': []
    }
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                protocol = ssock.version()
                cert = ssock.getpeercert()
                res['protocol'] = protocol
                if protocol in WEAK_PROTOCOLS:
                    res['findings'].append(('CRITICAL', f'Veraltetes TLS-Protokoll im Einsatz: {protocol}', 'TLS-Protokoll auf mindestens TLS 1.2/1.3 aktualisieren.'))

                issuer_dict = dict(x[0] for x in cert.get('issuer', ()))
                res['issuer'] = issuer_dict.get('organizationName') or issuer_dict.get('commonName') or 'Unknown'

                not_after = cert.get('notAfter')
                if not_after:
                    expiry = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z').replace(tzinfo=timezone.utc)
                    res['expiry_date'] = expiry.strftime('%Y-%m-%d')
                    days_left = (expiry - datetime.now(timezone.utc)).days
                    res['days_until_expiry'] = days_left
                    if days_left <= 0:
                        res['findings'].append(('CRITICAL', f'TLS-Zertifikat ist abgelaufen ({expiry.date()})', 'Zertifikat umgehend erneuern.'))
                    elif days_left <= 7:
                        res['findings'].append(('CRITICAL', f'TLS-Zertifikat laeuft in {days_left} Tag(en) ab ({expiry.date()})', 'Zertifikat vor Ablauf erneuern.'))
                    elif days_left <= 30:
                        res['findings'].append(('WARNING', f'TLS-Zertifikat laeuft in {days_left} Tag(en) ab ({expiry.date()})', 'Erneuerung des Zertifikats einplanen.'))

                sans = [item[1] for item in cert.get('subjectAltName', ()) if item[0] == 'DNS']
                res['san_list'] = sans
    except ssl.SSLCertVerificationError as e:
        if 'certificate has expired' in str(e).lower():
            res['findings'].append(('CRITICAL', f'TLS-Zertifikat abgelaufen/ungueltig: {e}', 'Neues Zertifikat ausstellen.'))
        elif 'hostname' in str(e).lower() or 'match' in str(e).lower():
            res['san_match'] = False
            res['findings'].append(('CRITICAL', f'TLS-Zertifikat/Hostname Abweichung (SAN Match Mismatch): {e}', 'Zertifikat fuer Hostnamen korrekt ausstellen.'))
        else:
            res['findings'].append(('CRITICAL', f'Zertifikatsketten-Pruefung fehlgeschlagen: {e}', 'Zertifikatskette und Aussteller korrigieren.'))
    except (socket.timeout, ConnectionRefusedError, socket.gaierror) as e:
        res['findings'].append(('INFO', f'Port 443 nicht erreichbar fuer TLS-Check: {e}', 'Keine Aktion erforderlich wenn HTTPS nicht genutzt wird.'))
    except Exception as e:
        res['findings'].append(('INFO', f'TLS-Check fehlgeschlagen: {e}', 'Manuelle Pruefung der HTTPS-Konfiguration.'))
    return res

def check_hostname_http(hostname: str):
    res = {
        'status_code': 'N/A',
        'headers_found': [],
        'headers_missing': [],
        'response_time_ms': -1,
        'redirect_chain_len': 0,
        'findings': []
    }
    start_time = time.time()
    https_ok = False
    try:
        r = requests.get(f'https://{hostname}', timeout=10, allow_redirects=True, headers={'User-Agent': 'isms-cloudflare-dns-scanner/1.0'})
        res['response_time_ms'] = int((time.time() - start_time) * 1000)
        res['status_code'] = str(r.status_code)
        res['redirect_chain_len'] = len(r.history)
        https_ok = True

        if len(r.history) > 3:
            res['findings'].append(('WARNING', f'Lange Weiterleitungskette ({len(r.history)} Redirects)', 'Weiterleitungskette auf ein Minimum reduzieren.'))
        if res['response_time_ms'] > 5000:
            res['findings'].append(('WARNING', f'Ungewoehnlich langsame Antwortzeit ({res["response_time_ms"]}ms)', 'Serverleistung oder CDN-Cache pruefen.'))

        if r.status_code >= 500:
            res['findings'].append(('CRITICAL', f'HTTP 5xx Serverfehler ({r.status_code})', 'Serverprotokolle und Anwendungsstatus pruefen.'))

        headers = {k.lower(): v for k, v in r.headers.items()}

        hsts = headers.get('strict-transport-security')
        if hsts:
            res['headers_found'].append('Strict-Transport-Security')
        else:
            res['headers_missing'].append('Strict-Transport-Security')
            res['findings'].append(('CRITICAL', 'Fehlender HSTS-Header (Strict-Transport-Security)', 'HSTS-Header konfigurieren.'))

        csp = headers.get('content-security-policy')
        if csp:
            res['headers_found'].append('Content-Security-Policy')
        else:
            res['headers_missing'].append('Content-Security-Policy')
            res['findings'].append(('WARNING', 'Fehlender Content-Security-Policy Header', 'CSP-Header einfuehren.'))

        xcto = headers.get('x-content-type-options')
        if xcto:
            res['headers_found'].append('X-Content-Type-Options')
        else:
            res['headers_missing'].append('X-Content-Type-Options')
            res['findings'].append(('WARNING', 'Fehlender X-Content-Type-Options Header', 'X-Content-Type-Options: nosniff setzen.'))

        xfo = headers.get('x-frame-options')
        if xfo or (csp and 'frame-ancestors' in csp.lower()):
            res['headers_found'].append('X-Frame-Options/frame-ancestors')
        else:
            res['headers_missing'].append('X-Frame-Options')
            res['findings'].append(('WARNING', 'Fehlender X-Frame-Options Header', 'X-Frame-Options auf SAMEORIGIN oder DENY setzen.'))

        rp = headers.get('referrer-policy')
        if rp:
            res['headers_found'].append('Referrer-Policy')
        else:
            res['headers_missing'].append('Referrer-Policy')
            res['findings'].append(('WARNING', 'Fehlender Referrer-Policy Header', 'Referrer-Policy Header konfigurieren.'))

    except requests.exceptions.SSLError as e:
        res['findings'].append(('CRITICAL', f'HTTPS SSL/TLS Fehler: {e}', 'TLS/SSL-Zertifikatskonfiguration pruefen.'))
    except requests.exceptions.RequestException as e:
        pass

    if not https_ok:
        try:
            r_http = requests.get(f'http://{hostname}', timeout=10, allow_redirects=False, headers={'User-Agent': 'isms-cloudflare-dns-scanner/1.0'})
            res['status_code'] = str(r_http.status_code)
        except Exception as e:
            if res['status_code'] == 'N/A':
                res['status_code'] = 'ERR'
                res['findings'].append(('WARNING', f'HTTP(S) Verbindung fehlgeschlagen: {e}', 'Erreichbarkeit des Hosts pruefen.'))
    return res

def check_subdomain(hostname: str, record_type: str, target: str):
    findings = []
    dangling_risk = False

    if record_type == 'CNAME' and target:
        marker = check_takeover_fingerprint(target)
        if marker:
            if not target_resolves(target):
                dangling_risk = True
                findings.append(('CRITICAL', f'Dangling CNAME zeigt auf {marker} ({target}), Ziel nicht aufloesbar', 'Entfernen Sie den verwaisten CNAME-Eintrag oder beanspruchen Sie die Ressource.'))
            else:
                snippet = fetch_body_snippet(hostname, logger=log)
                fp_text = fingerprint_text_for(marker)
                if fp_text and fp_text.lower() in snippet.lower():
                    dangling_risk = True
                    findings.append(('CRITICAL', f'Subdomain-Takeover Risiko auf {marker} ({target})', 'Ressource beim Cloud-Anbieter beanspruchen oder DNS-Eintrag loeschen.'))
                else:
                    findings.append(('WARNING', f'CNAME zeigt auf bekannten Dienst ({marker}), manuell pruefen', 'Ueberpruefen ob die Ressource aktiv genutzt wird.'))
        elif not target_resolves(target):
            dangling_risk = True
            findings.append(('CRITICAL', f'CNAME-Ziel "{target}" loest nicht mehr auf (Orphaned CNAME)', 'Nicht aufloesbares CNAME-Ziel aus dem DNS entfernen.'))
    elif record_type in ('A', 'AAAA'):
        if not target_resolves(hostname):
            findings.append(('CRITICAL', f'DNS-Aufloesung fehlgeschlagen fuer aktiven Record ({hostname})', 'A/AAAA Record auf Gueltigkeit pruefen.'))

    tls_res = check_hostname_tls(hostname)
    http_res = check_hostname_http(hostname)

    findings.extend(tls_res['findings'])
    findings.extend(http_res['findings'])

    severity_order = {'CRITICAL': 0, 'HIGH': 1, 'WARNING': 2, 'MEDIUM': 3, 'INFO': 4, 'NONE': 5}
    highest_sev = 'NONE'
    for f in findings:
        sev = f[0]
        if severity_order.get(sev, 9) < severity_order.get(highest_sev, 9):
            highest_sev = sev

    return {
        'hostname': hostname,
        'record_type': record_type,
        'target_or_ip': target or 'N/A',
        'http_status': http_res['status_code'],
        'cert_issuer': tls_res['issuer'],
        'cert_expiry_date': tls_res['expiry_date'],
        'days_until_expiry': str(tls_res['days_until_expiry']) if tls_res['days_until_expiry'] >= 0 else 'N/A',
        'tls_protocol': tls_res['protocol'],
        'headers_found': ';'.join(http_res['headers_found']),
        'headers_missing': ';'.join(http_res['headers_missing']),
        'dangling_risk': 'YES' if dangling_risk else 'NO',
        'overall_severity': highest_sev,
        'timestamp': datetime.now(timezone.utc).isoformat(),
        'findings': findings
    }

def analyze_dns_hygiene(all_records):
    hygiene_findings = []
    seen = {}
    for zone_name, _status, rec in all_records:
        rtype = rec.get('type')
        name = (rec.get('name') or '').lower()
        content = (rec.get('content') or '').strip()
        if rtype in ('A', 'AAAA', 'CNAME'):
            if name.startswith('*'):
                hygiene_findings.append(('WARNING', name, f'Wildcard-DNS-Eintrag ({rtype} -> {content}) existiert', 'Wildcard-Eintraege auf Notwendigkeit pruefen.'))
            key = (rtype, name, content)
            if key in seen:
                hygiene_findings.append(('WARNING', name, f'Doppelter DNS-Eintrag ({rtype} -> {content})', 'Doppelte DNS-Datensaetze bereinigen.'))
            else:
                seen[key] = True
    return hygiene_findings

def send_scan_report(level, critical_findings, all_scanned, hygiene_findings, duration, fatal_error=None):
    summary_lines = [
        f'SEVERITY_LEVEL: {level}',
        f"Cloudflare DNS Subdomain Security Scan - {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}",
        f'Gepruefte Subdomains/Hostnamen: {len(all_scanned)} | Kritische Befunde: {len(critical_findings)}',
        f'Dauer: {duration}s',
        ''
    ]
    if fatal_error:
        summary_lines.append(f'!! Scan vorzeitig beendet wegen Fehler: {fatal_error}')
        summary_lines.append('')

    if critical_findings:
        summary_lines.append('----- Kritische Befunde (CRITICAL) -----')
        for item in critical_findings:
            host = item['hostname']
            for sev, issue, action in item['findings']:
                if sev == 'CRITICAL':
                    summary_lines.append(f'🔴 [CRITICAL] {host}: {issue} | Empfehlung: {action}')
        summary_lines.append('')
    else:
        summary_lines.append('Keine kritischen Befunde heute.')
        summary_lines.append('')

    if hygiene_findings:
        summary_lines.append('----- DNS-Hygiene Hinweise -----')
        for sev, host, msg, act in hygiene_findings:
            summary_lines.append(f'🟡 [{sev}] {host}: {msg} | Empfehlung: {act}')
        summary_lines.append('')

    summary_lines.append('----- Vollstaendiges Ausfuehrungsprotokoll -----')
    summary_lines.extend(log.lines)

    SUMMARY_FILE.write_text('\n'.join(summary_lines) + '\n', encoding='utf-8')

    with open(REPORT_CSV_FILE, mode='w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        writer.writerow([
            'hostname', 'record_type', 'target_or_ip', 'http_status',
            'cert_issuer', 'cert_expiry_date', 'days_until_expiry',
            'tls_protocol', 'headers_found', 'headers_missing',
            'dangling_risk', 'overall_severity', 'timestamp'
        ])
        for row in all_scanned:
            writer.writerow([
                row['hostname'], row['record_type'], row['target_or_ip'], row['http_status'],
                row['cert_issuer'], row['cert_expiry_date'], row['days_until_expiry'],
                row['tls_protocol'], row['headers_found'], row['headers_missing'],
                row['dangling_risk'], row['overall_severity'], row['timestamp']
            ])

    subject = f"{SEVERITY_ICON.get(level, '✅')} Cloudflare Subdomain Security Scan ({level}) - {len(critical_findings)} kritische(r) Befund(e)"

    if critical_findings:
        email_body = f"{subject}\n\nEs wurden {len(critical_findings)} kritische Befunde festgestellt:\n\n"
        for item in critical_findings:
            host = item['hostname']
            for sev, issue, action in item['findings']:
                if sev == 'CRITICAL':
                    email_body += f"• Subdomain: {host}\n  Problem: {issue}\n  Empfehlung: {action}\n\n"
        email_body += "Der vollstaendige CSV-Bericht und das Protokoll befinden sich im Anhang.\n"
    elif fatal_error:
        email_body = f"{subject}\n\nDer Scan konnte nicht erfolgreich abgeschlossen werden:\n{fatal_error}\n\nBitte Protokolle pruefen.\n"
    else:
        email_body = f"{subject}\n\nKeine kritischen Befunde heute. {len(all_scanned)} Subdomains gescannt, 0 kritische Fehler.\n\nDer detaillierte Bericht befindet sich im Anhang.\n"

    attachments = []
    if REPORT_CSV_FILE.exists():
        attachments.append(REPORT_CSV_FILE)
    if SUMMARY_FILE.exists():
        attachments.append(SUMMARY_FILE)

    try:
        send_email_report(subject, email_body, attachments=attachments, logger=log)
    except Exception:
        pass

    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK, f"{SEVERITY_ICON.get(level, '✅')} Subdomain Scan: {level} ({len(critical_findings)} kritische Befunde von {len(all_scanned)} Subdomains).")
        except Exception:
            pass

def main():
    start = datetime.now(timezone.utc)
    zone_exclude = parse_list(CLOUDFLARE_ZONE_EXCLUDE)
    all_scanned = []
    critical_findings = []
    hygiene_findings = []
    fatal_error = None

    try:
        if not CLOUDFLARE_API_TOKEN:
            raise RuntimeError('CLOUDFLARE_API_TOKEN ist nicht gesetzt (Secret fehlt oder ist leer).')
        zones = get_zones(CLOUDFLARE_API_TOKEN, zone_exclude, logger=log)
        records = get_all_records(CLOUDFLARE_API_TOKEN, zones, logger=log)

        hygiene_findings = analyze_dns_hygiene(records)

        target_records = []
        for zone_name, _status, rec in records:
            rtype = rec.get('type')
            if rtype not in ('A', 'AAAA', 'CNAME'):
                continue
            name = (rec.get('name') or '').lower()
            if not name or name.startswith('*') or name.split('.')[0].startswith('_'):
                continue
            content = rec.get('content')
            target_records.append((name, rtype, content))

        unique_hosts = {}
        for name, rtype, content in target_records:
            if name not in unique_hosts:
                unique_hosts[name] = (rtype, content)

        for name, (rtype, content) in unique_hosts.items():
            result = check_subdomain(name, rtype, content)
            all_scanned.append(result)
            if result['overall_severity'] == 'CRITICAL':
                critical_findings.append(result)

    except Exception as e:
        fatal_error = str(e)
        log.log(f'FATAL: {fatal_error}')

    duration = int((datetime.now(timezone.utc) - start).total_seconds())
    level = 'NONE'
    if fatal_error or critical_findings:
        level = 'CRITICAL'
    elif any(r['overall_severity'] in ('WARNING', 'HIGH', 'MEDIUM') for r in all_scanned):
        level = 'WARNING'

    send_scan_report(level, critical_findings, all_scanned, hygiene_findings, duration, fatal_error)
    sys.exit(1 if level == 'CRITICAL' or fatal_error else 0)

if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
