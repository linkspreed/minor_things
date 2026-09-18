#!/usr/bin/env python3
import sys
from datetime import datetime, timezone
from pathlib import Path
from common import env, Redactor, SummaryLogger, send_google_chat, send_email_report
from domain_common import parse_list, get_zones, get_all_records, web_hostnames, check_takeover_fingerprint, fingerprint_text_for, target_resolves, fetch_body_snippet
CLOUDFLARE_API_TOKEN = env('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_ZONE_EXCLUDE = env('CLOUDFLARE_ZONE_EXCLUDE', default='')
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='dangling_dns_summary.txt'))
redact = Redactor([CLOUDFLARE_API_TOKEN])
log = SummaryLogger(redact)
SEVERITY_ICON = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'INFO': '⚪', 'NONE': '✅'}

def _shred(path: Path):
    try:
        if path.exists():
            path.write_bytes(b'0' * path.stat().st_size)
            path.unlink()
    except Exception:
        pass

def send_final_report(level: str, findings: list, checked: int, zones_count: int, duration: int, fatal_error: str=None):
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}
    header = [f'SEVERITY_LEVEL: {level}', f"Dangling-DNS-/Subdomain-Takeover-Scan - {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}", f'Zonen gepruefte: {zones_count} | Gepruefte Hostnamen: {checked} | Auffaelligkeiten: {len(findings)}', f'Dauer: {duration}s', '']
    if fatal_error:
        header.append(f'!! Der Lauf wurde durch einen Fehler vorzeitig beendet: {fatal_error}')
        header.append('')
    if findings:
        header.append('----- Auffaelligkeiten (nach Schwere sortiert) -----')
        for sev, host, detail in sorted(findings, key=lambda f: order.get(f[0], 9)):
            header.append(f"{SEVERITY_ICON.get(sev, '?')} [{sev}] {host}: {detail}")
        header.append('')
    else:
        header.append('Keine Auffaelligkeiten gefunden.')
    header.append('')
    header.append('----- Vollstaendiges Protokoll -----')
    full_report = '\n'.join(header) + '\n' + '\n'.join(log.lines) + '\n'
    SUMMARY_FILE.write_text(full_report, encoding='utf-8')
    subject = f"{SEVERITY_ICON.get(level, '✅')} Dangling-DNS-Scan ({level}) - {len(findings)} Auffaelligkeit(en)"
    body = f'{subject}\n\nDer vollstaendige Report befindet sich im Anhang.\n'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE], logger=log)
    except Exception:
        pass
    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK, f"{SEVERITY_ICON.get(level, '✅')} Dangling-DNS-Scan: {level} ({len(findings)} Auffaelligkeit(en) von {checked} Hostnamen). Vollstaendiger Report per E-Mail.")
        except Exception:
            pass
    _shred(SUMMARY_FILE)

def main():
    start = datetime.now(timezone.utc)
    zone_exclude = parse_list(CLOUDFLARE_ZONE_EXCLUDE)
    findings = []
    checked = 0
    zones_count = 0
    fatal_error = None
    try:
        if not CLOUDFLARE_API_TOKEN:
            raise RuntimeError('CLOUDFLARE_API_TOKEN ist nicht gesetzt (Secret fehlt oder ist leer).')
        zones = get_zones(CLOUDFLARE_API_TOKEN, zone_exclude, logger=log)
        zones_count = len(zones)
        records = get_all_records(CLOUDFLARE_API_TOKEN, zones, logger=log)
        hosts = web_hostnames(records)
        for host, rec in hosts.items():
            checked += 1
            rtype, target = (rec.get('type'), rec.get('content'))
            if rtype != 'CNAME' or not target:
                continue
            marker = check_takeover_fingerprint(target)
            if marker:
                if not target_resolves(target):
                    findings.append(('CRITICAL', host, f'CNAME zeigt auf bekannten Cloud-Dienst ({marker}), Ziel "{target}" ist NICHT mehr aufloesbar -> hohe Uebernahme-Gefahr.'))
                    continue
                snippet = fetch_body_snippet(host, logger=log)
                fp_text = fingerprint_text_for(marker)
                if fp_text and fp_text.lower() in snippet.lower():
                    findings.append(('CRITICAL', host, f'CNAME zeigt auf {marker} ("{target}") UND die Seite zeigt das "nicht beansprucht"-Signal ("{fp_text}") -> Uebernahme wahrscheinlich moeglich.'))
                else:
                    findings.append(('MEDIUM', host, f'CNAME zeigt auf bekannten uebernehmbaren Dienst-Typ ({marker}), aber kein eindeutiges Signal gefunden - bitte manuell pruefen.'))
            elif not target_resolves(target):
                findings.append(('HIGH', host, f'CNAME-Ziel "{target}" (kein bekannter Fingerprint-Dienst) loest NICHT mehr auf -> moeglicher dangling record.'))
    except Exception as e:
        fatal_error = str(e)
        log.log(f'FATAL: {fatal_error}')
    duration = int((datetime.now(timezone.utc) - start).total_seconds())
    level = 'NONE'
    for lvl in ('CRITICAL', 'HIGH', 'MEDIUM', 'INFO'):
        if any((f[0] == lvl for f in findings)):
            level = lvl
            break
    if fatal_error and level == 'NONE':
        level = 'INFO'
    send_final_report(level, findings, checked, zones_count, duration, fatal_error)
    sys.exit(1 if level in ('CRITICAL', 'HIGH') or fatal_error else 0)
if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
