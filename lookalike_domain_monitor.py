#!/usr/bin/env python3
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from common import env, Redactor, SummaryLogger, send_google_chat, send_email_report
from domain_common import parse_list, get_zones
CLOUDFLARE_API_TOKEN = env('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_ZONE_EXCLUDE = env('CLOUDFLARE_ZONE_EXCLUDE', default='')
LOOKALIKE_IGNORE_LIST = env('LOOKALIKE_IGNORE_LIST', default='')
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='lookalike_domain_summary.txt'))
DNSTWIST_TIMEOUT = int(env('DNSTWIST_TIMEOUT_SECONDS', default='300'))
redact = Redactor([CLOUDFLARE_API_TOKEN])
log = SummaryLogger(redact)
SEVERITY_ICON = {'HIGH': '🟠', 'MEDIUM': '🟡', 'NONE': '✅'}
HIGH_RISK_FUZZERS = {'homoglyph', 'bitsquatting', 'hyphenation', 'insertion', 'omission', 'repetition', 'transposition', 'replacement'}

def _shred(path: Path):
    try:
        if path.exists():
            path.write_bytes(b'0' * path.stat().st_size)
            path.unlink()
    except Exception:
        pass

def run_dnstwist(domain: str) -> list:
    try:
        proc = subprocess.run(['dnstwist', '--format', 'json', '--registered', domain], capture_output=True, text=True, timeout=DNSTWIST_TIMEOUT)
    except FileNotFoundError:
        raise RuntimeError('dnstwist ist nicht installiert.')
    except subprocess.TimeoutExpired:
        raise RuntimeError(f'dnstwist-Zeitueberschreitung nach {DNSTWIST_TIMEOUT}s fuer {domain}')
    if proc.returncode != 0 and (not proc.stdout.strip()):
        raise RuntimeError(f'dnstwist-Fehler (Exit {proc.returncode})')
    try:
        return json.loads(proc.stdout or '[]')
    except json.JSONDecodeError:
        return []

def send_final_report(level: str, all_findings: list, root_domains: list, errors: list, duration: int, fatal_error: str=None):
    header = [f'SEVERITY_LEVEL: {level}', f"Lookalike-/Typosquatting-Domain-Monitor - {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}", f'Root-Domains (aus Cloudflare): {len(root_domains)} | Registrierte Lookalikes gefunden: {len(all_findings)} | Fehler: {len(errors)}', f'Dauer: {duration}s', '']
    if fatal_error:
        header.append(f'!! Der Lauf wurde durch einen Fehler vorzeitig beendet: {fatal_error}')
        header.append('')
    if all_findings:
        header.append('----- Gefundene registrierte Lookalike-Domains (nach Risiko sortiert) -----')
        for candidate, root, fuzzer, risk, dns_a, dns_mx in sorted(all_findings, key=lambda f: 0 if f[3] == 'HIGH' else 1):
            icon = SEVERITY_ICON.get(risk, '?')
            header.append(f"{icon} [{risk}] {candidate}  (aehnlich zu {root}, Fuzzer: {fuzzer})  A={dns_a or '-'}  MX={dns_mx or '-'}")
        header.append('')
        header.append('Hinweis: Ein Treffer mit gesetztem MX-Eintrag ist besonders relevant (Mailempfang moeglich -> klassisches Phishing-Setup).')
    else:
        header.append('Keine registrierten Lookalike-Domains gefunden.')
    if errors:
        header.append('')
        header.append('----- Fehler pro Domain -----')
        for domain, err in errors:
            header.append(f'{domain}: {err}')
    header.append('')
    header.append('----- Vollstaendiges Protokoll -----')
    full_report = '\n'.join(header) + '\n' + '\n'.join(log.lines) + '\n'
    SUMMARY_FILE.write_text(full_report, encoding='utf-8')
    subject = f"{SEVERITY_ICON.get(level, '✅')} Lookalike-Domain-Monitor ({level}) - {len(all_findings)} Treffer"
    body = f'{subject}\n\nDer vollstaendige Report befindet sich im Anhang.\n'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE], logger=log)
    except Exception:
        pass
    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK, f"{SEVERITY_ICON.get(level, '✅')} Lookalike-Domain-Monitor: {level} ({len(all_findings)} Treffer). Vollstaendiger Report per E-Mail.")
        except Exception:
            pass
    _shred(SUMMARY_FILE)

def main():
    start = datetime.now(timezone.utc)
    zone_exclude = parse_list(CLOUDFLARE_ZONE_EXCLUDE)
    ignore_list = set(parse_list(LOOKALIKE_IGNORE_LIST))
    all_findings = []
    errors = []
    root_domains = []
    fatal_error = None
    try:
        if not CLOUDFLARE_API_TOKEN:
            raise RuntimeError('CLOUDFLARE_API_TOKEN ist nicht gesetzt (Secret fehlt oder ist leer).')
        zones = get_zones(CLOUDFLARE_API_TOKEN, zone_exclude, logger=log)
        root_domains = sorted((z['name'] for z in zones if z.get('name')))
        for domain in root_domains:
            try:
                results = run_dnstwist(domain)
            except Exception as e:
                errors.append((domain, str(e)))
                continue
            for entry in results:
                candidate = entry.get('domain', '')
                if not candidate or candidate == domain or candidate in ignore_list:
                    continue
                fuzzer = entry.get('fuzzer', '?')
                risk = 'HIGH' if fuzzer in HIGH_RISK_FUZZERS else 'MEDIUM'
                dns_a = ', '.join(entry.get('dns_a', []) or [])
                dns_mx = ', '.join(entry.get('dns_mx', []) or [])
                all_findings.append((candidate, domain, fuzzer, risk, dns_a, dns_mx))
    except Exception as e:
        fatal_error = str(e)
        log.log(f'FATAL: {fatal_error}')
    duration = int((datetime.now(timezone.utc) - start).total_seconds())
    level = 'NONE'
    if any((f[3] == 'HIGH' for f in all_findings)):
        level = 'HIGH'
    elif all_findings:
        level = 'MEDIUM'
    if fatal_error and level == 'NONE':
        level = 'HIGH' if not root_domains else level
    send_final_report(level, all_findings, root_domains, errors, duration, fatal_error)
    sys.exit(1 if fatal_error or level == 'HIGH' else 0)
if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
