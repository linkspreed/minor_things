#!/usr/bin/env python3
import sys
from datetime import datetime, timezone
from pathlib import Path
import requests
from common import env, Redactor, SummaryLogger, send_google_chat, send_email_report, with_retry
from domain_common import parse_list, get_zones
CLOUDFLARE_API_TOKEN = env('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_ZONE_EXCLUDE = env('CLOUDFLARE_ZONE_EXCLUDE', default='')
EXPIRY_WARN_DAYS = int(env('DOMAIN_EXPIRY_WARN_DAYS', default='60'))
EXPIRY_CRITICAL_DAYS = int(env('DOMAIN_EXPIRY_CRITICAL_DAYS', default='30'))
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='domain_expiry_summary.txt'))
redact = Redactor([CLOUDFLARE_API_TOKEN])
log = SummaryLogger(redact)
SEVERITY_ICON = {'HIGH': '🟠', 'MEDIUM': '🟡', 'INFO': '⚪', 'NONE': '✅'}

def _shred(path: Path):
    try:
        if path.exists():
            path.write_bytes(b'0' * path.stat().st_size)
            path.unlink()
    except Exception:
        pass

def fetch_rdap(domain: str) -> dict:

    def _attempt():
        r = requests.get(f'https://rdap.org/domain/{domain}', timeout=20, headers={'Accept': 'application/rdap+json', 'User-Agent': 'isms-domain-expiry-check/1.0'})
        if r.status_code == 404:
            raise RuntimeError('Domain nicht im RDAP gefunden (404)')
        if r.status_code >= 500:
            raise RuntimeError(f'RDAP-Serverfehler {r.status_code}')
        r.raise_for_status()
        return r.json()
    return with_retry(_attempt, f'RDAP-Abfrage ({domain})', max_retries=3, base_delay=5, logger=log)

def evaluate_domain(domain: str, zone_status: str) -> list:
    findings = []
    if zone_status != 'active':
        findings.append(('HIGH', f'Cloudflare-Zonen-Status ist "{zone_status}" (nicht "active") - Nameserver zeigen moeglicherweise NICHT korrekt auf Cloudflare, DNS-Aenderungen wirken evtl. nicht.'))
    else:
        findings.append(('NONE', 'Cloudflare-Zonen-Status "active" - Nameserver korrekt konfiguriert.'))
    try:
        data = fetch_rdap(domain)
    except Exception as e:
        findings.append(('INFO', f'RDAP-Abfrage fehlgeschlagen: {redact(str(e))}'))
        return findings
    expiry_date = None
    for event in data.get('events') or []:
        if event.get('eventAction') == 'expiration':
            try:
                expiry_date = datetime.fromisoformat(event['eventDate'].replace('Z', '+00:00'))
            except Exception:
                pass
            break
    if expiry_date is None:
        findings.append(('INFO', 'Kein Ablaufdatum im RDAP-Datensatz gefunden.'))
    else:
        days_left = (expiry_date - datetime.now(timezone.utc)).days
        if days_left < EXPIRY_CRITICAL_DAYS:
            findings.append(('HIGH', f'Domain laeuft in {days_left} Tag(en) ab ({expiry_date.date()}) - DRINGEND verlaengern!'))
        elif days_left < EXPIRY_WARN_DAYS:
            findings.append(('MEDIUM', f'Domain laeuft in {days_left} Tag(en) ab ({expiry_date.date()}).'))
        else:
            findings.append(('NONE', f'Domain laeuft erst in {days_left} Tag(en) ab ({expiry_date.date()}).'))
    return findings

def send_final_report(level, all_findings, domains_count, duration, fatal_error=None):
    header = [f'SEVERITY_LEVEL: {level}', f"Domain-Ablauf-/Nameserver-Check - {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}", f'Domains (Zonen) geprueft: {domains_count} | Auffaelligkeiten: {len(all_findings)}', f'Dauer: {duration}s', '']
    if fatal_error:
        header.append(f'!! Der Lauf wurde durch einen Fehler vorzeitig beendet: {fatal_error}')
        header.append('')
    if all_findings:
        header.append('----- Auffaelligkeiten (nach Schwere sortiert) -----')
        order = {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}
        for sev, domain, detail in sorted(all_findings, key=lambda f: order.get(f[0], 9)):
            header.append(f"{SEVERITY_ICON.get(sev, '?')} [{sev}] {domain}: {detail}")
        header.append('')
    else:
        header.append('Keine Auffaelligkeiten. Alle Domains ausreichend lang gueltig, alle Zonen aktiv.')
    header.append('')
    header.append('----- Vollstaendiges Protokoll -----')
    full_report = '\n'.join(header) + '\n' + '\n'.join(log.lines) + '\n'
    SUMMARY_FILE.write_text(full_report, encoding='utf-8')
    subject = f"{SEVERITY_ICON.get(level, '✅')} Domain-Ablauf-Check ({level}) - {len(all_findings)} Auffaelligkeit(en)"
    body = f'{subject}\n\nDer vollstaendige Report befindet sich im Anhang.\n'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE], logger=log)
    except Exception:
        pass
    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK, f"{SEVERITY_ICON.get(level, '✅')} Domain-Ablauf-Check: {level} ({len(all_findings)} Auffaelligkeit(en)). Vollstaendiger Report per E-Mail.")
        except Exception:
            pass
    _shred(SUMMARY_FILE)

def main():
    start = datetime.now(timezone.utc)
    zone_exclude = parse_list(CLOUDFLARE_ZONE_EXCLUDE)
    all_findings = []
    domains_count = 0
    fatal_error = None
    try:
        if not CLOUDFLARE_API_TOKEN:
            raise RuntimeError('CLOUDFLARE_API_TOKEN ist nicht gesetzt (Secret fehlt oder ist leer).')
        zones = get_zones(CLOUDFLARE_API_TOKEN, zone_exclude, logger=log)
        domains_count = len(zones)
        for zone in zones:
            domain = zone.get('name')
            if not domain:
                continue
            for sev, detail in evaluate_domain(domain, zone.get('status')):
                if sev != 'NONE':
                    all_findings.append((sev, domain, detail))
    except Exception as e:
        fatal_error = str(e)
        log.log(f'FATAL: {fatal_error}')
    duration = int((datetime.now(timezone.utc) - start).total_seconds())
    level = 'NONE'
    for lvl in ('HIGH', 'MEDIUM', 'INFO'):
        if any((f[0] == lvl for f in all_findings)):
            level = lvl
            break
    if fatal_error and level == 'NONE':
        level = 'INFO'
    send_final_report(level, all_findings, domains_count, duration, fatal_error)
    sys.exit(1 if fatal_error or level == 'HIGH' else 0)
if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
