#!/usr/bin/env python3
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from common import env, Redactor, SummaryLogger, send_google_chat, send_email_report
from domain_common import parse_list, get_zones, get_all_records, txt_records_by_name
CLOUDFLARE_API_TOKEN = env('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_ZONE_EXCLUDE = env('CLOUDFLARE_ZONE_EXCLUDE', default='')
MONITORED_SENDING_DOMAINS_OVERRIDE = env('MONITORED_SENDING_DOMAINS', default='')
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='email_auth_summary.txt'))
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

def evaluate_spf(domain: str, txt_by_name: dict) -> tuple:
    records = [r for r in txt_by_name.get(domain, []) if r.lower().startswith('v=spf1')]
    if not records:
        return ('HIGH', 'Kein SPF-Eintrag gefunden - Absenderadresse laesst sich beliebig faelschen.')
    record = records[0]
    m = re.search('([+\\-~?])all\\b', record)
    qualifier = m.group(1) if m else None
    if qualifier == '+':
        return ('CRITICAL', f'SPF mit "+all" gefunden ("{record}") - erlaubt praktisch JEDEM Server, in eurem Namen zu senden.')
    if qualifier == '-':
        return ('NONE', f'SPF korrekt mit "-all" (hard fail): "{record}"')
    if qualifier == '~':
        return ('MEDIUM', f'SPF nur mit "~all" (soft fail): "{record}" - Empfehlung: auf "-all" umstellen.')
    return ('HIGH', f'SPF ohne eindeutigen all-Mechanismus: "{record}" - nicht wirksam durchgesetzt.')

def evaluate_dmarc(domain: str, txt_by_name: dict) -> tuple:
    records = [r for r in txt_by_name.get(f'_dmarc.{domain}', []) if r.lower().startswith('v=dmarc1')]
    if not records:
        return ('HIGH', 'Kein DMARC-Eintrag gefunden - Phishing unter dieser Domain wird nicht erkannt/blockiert.')
    record = records[0]
    tags = {}
    for part in record.split(';'):
        part = part.strip()
        if '=' in part:
            k, v = part.split('=', 1)
            tags[k.strip().lower()] = v.strip()
    policy = tags.get('p', 'none').lower()
    pct = tags.get('pct', '100')
    if policy == 'reject':
        base = ('NONE', f'DMARC korrekt mit p=reject: "{record}"')
    elif policy == 'quarantine':
        base = ('MEDIUM', f'DMARC nur mit p=quarantine (nicht reject): "{record}"')
    else:
        base = ('HIGH', f'DMARC nur im Monitoring-Modus p=none: "{record}" - keine tatsaechliche Durchsetzung.')
    try:
        if int(pct) < 100 and policy in ('reject', 'quarantine'):
            sev, msg = base
            worse = 'MEDIUM' if sev == 'NONE' else sev
            return (worse, msg + f' Zusaetzlich: pct={pct} (<100%) - Durchsetzung gilt nur fuer einen Teil.')
    except ValueError:
        pass
    return base

def evaluate_dkim(domain: str, txt_by_name: dict) -> tuple:
    matches = [name for name in txt_by_name if name.endswith(f'._domainkey.{domain}')]
    if matches:
        selectors = sorted((m.split('._domainkey.')[0] for m in matches))
        return ('NONE', f"DKIM gefunden (Selektor(en): {', '.join(selectors)}).")
    return ('MEDIUM', 'Kein DKIM-TXT-Eintrag ("*._domainkey.<domain>") in der Cloudflare-Zone gefunden - falls DKIM ueber einen externen Mail-Anbieter laeuft, sollte trotzdem ein CNAME/TXT-Eintrag hier in der Zone existieren. Bitte pruefen.')

def send_final_report(level, all_findings, sending_domains, duration, fatal_error=None):
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}
    header = [f'SEVERITY_LEVEL: {level}', f"E-Mail-Authentifizierungs-Check (SPF/DMARC/DKIM) - {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}", f'Sendende Domains geprueft: {len(sending_domains)} | Auffaelligkeiten: {len(all_findings)}', f'Dauer: {duration}s', '']
    if fatal_error:
        header.append(f'!! Der Lauf wurde durch einen Fehler vorzeitig beendet: {fatal_error}')
        header.append('')
    if all_findings:
        header.append('----- Auffaelligkeiten (nach Schwere sortiert) -----')
        for sev, domain, check_name, detail in sorted(all_findings, key=lambda f: order.get(f[0], 9)):
            header.append(f"{SEVERITY_ICON.get(sev, '?')} [{sev}] {domain} [{check_name}]: {detail}")
        header.append('')
    else:
        header.append('Alle geprueften Domains: SPF (-all), DMARC (p=reject) korrekt konfiguriert, DKIM gefunden.')
    header.append('')
    header.append('----- Vollstaendiges Protokoll -----')
    full_report = '\n'.join(header) + '\n' + '\n'.join(log.lines) + '\n'
    SUMMARY_FILE.write_text(full_report, encoding='utf-8')
    subject = f"{SEVERITY_ICON.get(level, '✅')} E-Mail-Auth-Check ({level}) - {len(all_findings)} Auffaelligkeit(en)"
    body = f'{subject}\n\nDer vollstaendige Report befindet sich im Anhang.\n'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE], logger=log)
    except Exception:
        pass
    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK, f"{SEVERITY_ICON.get(level, '✅')} E-Mail-Auth-Check: {level} ({len(all_findings)} Auffaelligkeit(en)). Vollstaendiger Report per E-Mail.")
        except Exception:
            pass
    _shred(SUMMARY_FILE)

def main():
    start = datetime.now(timezone.utc)
    zone_exclude = parse_list(CLOUDFLARE_ZONE_EXCLUDE)
    extra_sending_domains = parse_list(MONITORED_SENDING_DOMAINS_OVERRIDE)
    all_findings = []
    sending_domains = []
    fatal_error = None
    try:
        if not CLOUDFLARE_API_TOKEN:
            raise RuntimeError('CLOUDFLARE_API_TOKEN ist nicht gesetzt (Secret fehlt oder ist leer).')
        zones = get_zones(CLOUDFLARE_API_TOKEN, zone_exclude, logger=log)
        root_domains = sorted((z['name'] for z in zones if z.get('name')))
        sending_domains = sorted(set(root_domains) | set(extra_sending_domains))
        records = get_all_records(CLOUDFLARE_API_TOKEN, zones, logger=log)
        txt_by_name = txt_records_by_name(records)
        for domain in sending_domains:
            for check_name, fn in (('SPF', evaluate_spf), ('DMARC', evaluate_dmarc)):
                sev, detail = fn(domain, txt_by_name)
                if sev != 'NONE':
                    all_findings.append((sev, domain, check_name, detail))
            sev, detail = evaluate_dkim(domain, txt_by_name)
            if sev != 'NONE':
                all_findings.append((sev, domain, 'DKIM', detail))
    except Exception as e:
        fatal_error = str(e)
        log.log(f'FATAL: {fatal_error}')
    duration = int((datetime.now(timezone.utc) - start).total_seconds())
    level = 'NONE'
    for lvl in ('CRITICAL', 'HIGH', 'MEDIUM', 'INFO'):
        if any((f[0] == lvl for f in all_findings)):
            level = lvl
            break
    if fatal_error and level == 'NONE':
        level = 'INFO'
    send_final_report(level, all_findings, sending_domains, duration, fatal_error)
    sys.exit(1 if fatal_error or level in ('CRITICAL', 'HIGH') else 0)
if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
