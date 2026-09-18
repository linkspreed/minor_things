#!/usr/bin/env python3
import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
import requests
from common import env, Redactor, SummaryLogger, send_google_chat, send_email_report
from domain_common import parse_list, get_zones, get_all_records, web_hostnames
CLOUDFLARE_API_TOKEN = env('CLOUDFLARE_API_TOKEN')
CLOUDFLARE_ZONE_EXCLUDE = env('CLOUDFLARE_ZONE_EXCLUDE', default='')
WEB_EXPOSURE_IGNORE_HOSTS = env('WEB_EXPOSURE_IGNORE_HOSTS', default='')
CORS_EXTRA_TEST_PATHS = env('CORS_EXTRA_TEST_PATHS', default='')
REQUEST_TIMEOUT = int(env('REQUEST_TIMEOUT_SECONDS', default='10'))
MAX_BYTES_PER_FILE = int(env('MAX_BYTES_PER_FILE', default='200000'))
REQUEST_DELAY_SECONDS = float(env('REQUEST_DELAY_SECONDS', default='0.2'))
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='web_exposure_summary.txt'))
redact = Redactor([CLOUDFLARE_API_TOKEN])
log = SummaryLogger(redact)
SEVERITY_ICON = {'CRITICAL': '🔴', 'HIGH': '🟠', 'MEDIUM': '🟡', 'INFO': '⚪', 'NONE': '✅'}
UA = {'User-Agent': 'isms-web-exposure-check/1.0'}

def _shred(path: Path):
    try:
        if path.exists():
            path.write_bytes(b'0' * path.stat().st_size)
            path.unlink()
    except Exception:
        pass

def get_working_base_url(host: str):
    for scheme in ('https', 'http'):
        try:
            url = f'{scheme}://{host}'
            r = requests.get(url, timeout=REQUEST_TIMEOUT, allow_redirects=True, headers=UA, stream=True)
            r.raw.read(1, decode_content=True)
            return url
        except Exception:
            continue
    return None

def fetch_raw(url: str, extra_headers: dict=None, method: str='GET'):
    try:
        r = requests.request(method, url, timeout=REQUEST_TIMEOUT, allow_redirects=False, headers={**UA, **(extra_headers or {})}, stream=True)
        content = r.raw.read(MAX_BYTES_PER_FILE + 1, decode_content=True) if method == 'GET' else b''
        return (r.status_code, content[:MAX_BYTES_PER_FILE], r.headers)
    except Exception:
        return (None, b'', {})

def _is_git_head(content: bytes) -> bool:
    return content.strip().startswith(b'ref: refs/') or bool(re.match(b'^[0-9a-f]{40}\\s*$', content.strip() or b''))

def _is_git_config(content: bytes) -> bool:
    return b'[core]' in content and b'repositoryformatversion' in content

def _is_dotenv(content: bytes) -> bool:
    text = content.decode('utf-8', errors='ignore')
    hits = len(re.findall('^[A-Z][A-Z0-9_]{2,}\\s*=.+$', text, re.M))
    return hits >= 2 or bool(re.search('\\b(DB_PASSWORD|API_KEY|SECRET_KEY|DATABASE_URL|AWS_SECRET)\\b', text, re.I))

def _is_sql_dump(content: bytes) -> bool:
    return bool(re.search(b'(-- MySQL dump|CREATE TABLE|INSERT INTO|PostgreSQL database dump)', content, re.I))

def _is_zip(content: bytes) -> bool:
    return content[:4] == b'PK\x03\x04'

def _is_gzip_tar(content: bytes) -> bool:
    return content[:2] == b'\x1f\x8b'

def _is_aws_credentials(content: bytes) -> bool:
    return b'aws_access_key_id' in content and (b'[default]' in content or b'aws_secret_access_key' in content)

def _is_private_key(content: bytes) -> bool:
    return b'PRIVATE KEY' in content or (content.strip().startswith(b'ssh-rsa') or content.strip().startswith(b'ssh-ed25519'))

def _is_npmrc(content: bytes) -> bool:
    return b'_authToken' in content or b'registry=' in content

def _is_netrc(content: bytes) -> bool:
    return b'machine ' in content and b'password' in content

def _is_docker_compose(content: bytes) -> bool:
    return b'version:' in content and b'services:' in content

def _is_htpasswd(content: bytes) -> bool:
    return bool(re.search(b'^[^:]+:\\$(apr1|2y|2b|2a)\\$', content, re.M))

def _is_phpinfo(content: bytes) -> bool:
    return b'PHP Version' in content and b'phpinfo()' in content.lower().replace(b' ', b'')

def _is_dsstore(content: bytes) -> bool:
    return content[:8] == b'\x00\x00\x00\x01Bud1'

def _is_webconfig(content: bytes) -> bool:
    return b'<configuration>' in content and (b'<system.web>' in content or b'<connectionStrings>' in content)

def _is_secrets_json(content: bytes) -> bool:
    text = content.decode('utf-8', errors='ignore').lower()
    return bool(re.search('"(secret|password|api_key|token|private_key)"\\s*:', text))
SENSITIVE_FILE_CHECKS = [('.env', 'Umgebungsvariablen-Datei (.env)', 'CRITICAL', _is_dotenv), ('.env.local', 'Umgebungsvariablen-Datei (.env.local)', 'CRITICAL', _is_dotenv), ('.env.production', 'Umgebungsvariablen-Datei (.env.production)', 'CRITICAL', _is_dotenv), ('.git/HEAD', 'Git-Repository (.git/HEAD)', 'CRITICAL', _is_git_head), ('.git/config', 'Git-Repository (.git/config)', 'CRITICAL', _is_git_config), ('.git/logs/HEAD', 'Git-Repository (.git/logs/HEAD)', 'CRITICAL', _is_git_head), ('.aws/credentials', 'AWS-Zugangsdaten', 'CRITICAL', _is_aws_credentials), ('id_rsa', 'Privater SSH-Schluessel (id_rsa)', 'CRITICAL', _is_private_key), ('.ssh/id_rsa', 'Privater SSH-Schluessel (.ssh/id_rsa)', 'CRITICAL', _is_private_key), ('backup.sql', 'Datenbank-Sicherung (backup.sql)', 'CRITICAL', _is_sql_dump), ('dump.sql', 'Datenbank-Sicherung (dump.sql)', 'CRITICAL', _is_sql_dump), ('database.sql', 'Datenbank-Sicherung (database.sql)', 'CRITICAL', _is_sql_dump), ('db_backup.sql', 'Datenbank-Sicherung (db_backup.sql)', 'CRITICAL', _is_sql_dump), ('backup.zip', 'Backup-Archiv (backup.zip)', 'HIGH', _is_zip), ('site-backup.zip', 'Backup-Archiv (site-backup.zip)', 'HIGH', _is_zip), ('www.zip', 'Backup-Archiv (www.zip)', 'HIGH', _is_zip), ('backup.tar.gz', 'Backup-Archiv (backup.tar.gz)', 'HIGH', _is_gzip_tar), ('.npmrc', 'NPM-Konfiguration (.npmrc)', 'HIGH', _is_npmrc), ('.netrc', 'Netzwerk-Zugangsdaten (.netrc)', 'HIGH', _is_netrc), ('docker-compose.yml', 'Docker-Compose-Konfiguration', 'MEDIUM', _is_docker_compose), ('docker-compose.yaml', 'Docker-Compose-Konfiguration', 'MEDIUM', _is_docker_compose), ('.htpasswd', 'Zugangsdaten-Datei (.htpasswd)', 'HIGH', _is_htpasswd), ('phpinfo.php', 'PHP-Info-Seite', 'MEDIUM', _is_phpinfo), ('wp-config.php.bak', 'WordPress-Konfigurations-Backup', 'CRITICAL', _is_dotenv), ('config.php.bak', 'Konfigurations-Backup (config.php.bak)', 'CRITICAL', _is_dotenv), ('.DS_Store', 'macOS-Ordnerindex (.DS_Store, verraet Dateistruktur)', 'MEDIUM', _is_dsstore), ('web.config', 'IIS-Konfigurationsdatei (web.config)', 'MEDIUM', _is_webconfig), ('secrets.json', 'Secrets-Datei (secrets.json)', 'CRITICAL', _is_secrets_json), ('secrets.yml', 'Secrets-Datei (secrets.yml)', 'CRITICAL', _is_secrets_json), ('credentials.json', 'Credentials-Datei (credentials.json)', 'CRITICAL', _is_secrets_json)]

def scan_exposed_files(base_url: str) -> list:
    findings = []
    baseline_token = uuid.uuid4().hex
    baseline_status, baseline_content, _ = fetch_raw(f'{base_url}/__web_exposure_baseline_{baseline_token}__')
    time.sleep(REQUEST_DELAY_SECONDS)
    for path, label, severity, check_fn in SENSITIVE_FILE_CHECKS:
        status, content, _headers = fetch_raw(f'{base_url}/{path}')
        time.sleep(REQUEST_DELAY_SECONDS)
        if status != 200 or not content:
            continue
        if baseline_status == 200 and content == baseline_content:
            continue
        if check_fn(content):
            findings.append((severity, path, f'{label} ist oeffentlich erreichbar und Inhalt wurde inhaltlich bestaetigt (Status 200).'))
        else:
            findings.append(('INFO', path, f'{label}: Pfad antwortet mit Status 200 und weicht von der Baseline ab, aber das erwartete Inhalts-Signal wurde nicht eindeutig erkannt - bitte manuell pruefen.'))
    return findings

def build_test_origins(zone_name: str) -> list:
    random_origin = f'https://cors-probe-{uuid.uuid4().hex[:12]}.invalid'
    origins = [(random_origin, 'zufaellige, voellig fremde Origin'), ('null', 'die spezielle "null"-Origin (z.B. aus sandboxed iframes)')]
    if zone_name:
        origins.append((f'https://evil-{zone_name}', f'Praefix-Angriff ("evil-{zone_name}") - faengt Server ab, die nur pruefen ob die Domain im String vorkommt'))
        origins.append((f'https://{zone_name}.attacker-controlled.invalid', f'Suffix-Angriff ("{zone_name}.attacker-controlled.invalid") - faengt Server ab, die nur mit endswith() pruefen'))
        origins.append((f'https://not{zone_name}', f'Verkettungs-Angriff ("not{zone_name}") ohne Trennzeichen'))
    return origins

def probe_cors_headers(url: str, origin: str) -> dict:
    _status, _content, headers = fetch_raw(url, extra_headers={'Origin': origin, 'Access-Control-Request-Method': 'GET', 'Access-Control-Request-Headers': 'content-type'}, method='OPTIONS')
    acao = headers.get('Access-Control-Allow-Origin') if headers else None
    if not acao:
        _status2, _content2, headers2 = fetch_raw(url, extra_headers={'Origin': origin}, method='GET')
        acao = headers2.get('Access-Control-Allow-Origin') if headers2 else None
        acac = headers2.get('Access-Control-Allow-Credentials', '') if headers2 else ''
    else:
        acac = headers.get('Access-Control-Allow-Credentials', '')
    return {'acao': acao, 'acac': (acac or '').strip().lower() == 'true'}

def scan_cors(base_url: str, zone_name: str, extra_paths: list) -> list:
    findings = []
    test_origins = build_test_origins(zone_name)
    paths = ['/'] + extra_paths
    for path in paths:
        url = base_url.rstrip('/') + path
        for origin, description in test_origins:
            result = probe_cors_headers(url, origin)
            time.sleep(REQUEST_DELAY_SECONDS)
            acao = result['acao']
            if not acao:
                continue
            reflects_hostile_origin = acao == origin or (origin != 'null' and acao == origin.rstrip('/'))
            is_wildcard = acao == '*'
            if reflects_hostile_origin and result['acac']:
                findings.append(('CRITICAL', path, f'Server spiegelt eine fremde Origin ({description}: "{origin}") direkt im Access-Control-Allow-Origin-Header zurueck UND erlaubt gleichzeitig Access-Control-Allow-Credentials: true. Das erlaubt einem Angreifer, im Namen eingeloggter Besucher Daten abzugreifen - dringend beheben.'))
            elif reflects_hostile_origin:
                findings.append(('HIGH', path, f'Server spiegelt eine fremde Origin ({description}: "{origin}") direkt im Access-Control-Allow-Origin-Header zurueck (ohne Credentials). Erlaubt fremden Webseiten, Antworten dieser Adresse zu lesen - bitte auf eine feste Allow-Liste umstellen.'))
            elif is_wildcard and result['acac']:
                findings.append(('MEDIUM', path, 'Access-Control-Allow-Origin: "*" zusammen mit Access-Control-Allow-Credentials: true gesetzt - das ist eine ungueltige/widerspruechliche Kombination (Browser ignorieren Credentials bei Wildcard), zeigt aber eine fehlerhafte CORS-Konfiguration, die aufgeraeumt werden sollte.'))
            elif is_wildcard:
                findings.append(('INFO', path, 'Access-Control-Allow-Origin: "*" gesetzt (voll oeffentlich lesbar, ohne Zugangsdaten). Falls dieser Pfad bewusst eine oeffentliche API ist, ist das unkritisch - andernfalls bitte auf eine feste Allow-Liste einschraenken.'))
    return findings

def send_final_report(level, file_findings, cors_findings, hosts_scanned, hosts_unreachable, zones_count, duration, fatal_error=None):
    order = {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2, 'INFO': 3}
    header = [f'SEVERITY_LEVEL: {level}', f"Web-Exposure-Check (Exposed-Files + CORS) - {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}", f'Zonen: {zones_count} | Hosts gescannt: {hosts_scanned} | Nicht erreichbar: {hosts_unreachable}', f'Funde Exposed-Files: {len(file_findings)} | Funde CORS: {len(cors_findings)}', f'Dauer: {duration}s', '']
    if fatal_error:
        header.append(f'!! Der Lauf wurde durch einen Fehler vorzeitig beendet: {fatal_error}')
        header.append('')
    header.append('===== TEIL 1: Exposed-Sensitive-Files-Scan =====')
    if file_findings:
        for sev, source, detail in sorted(file_findings, key=lambda f: order.get(f[0], 9)):
            header.append(f"{SEVERITY_ICON.get(sev, '?')} [{sev}] {source}: {detail}")
    else:
        header.append('Keine oeffentlich erreichbaren sensiblen Dateien gefunden.')
    header.append('')
    header.append('===== TEIL 2: CORS-Fehlkonfigurations-Check =====')
    if cors_findings:
        for sev, source, detail in sorted(cors_findings, key=lambda f: order.get(f[0], 9)):
            header.append(f"{SEVERITY_ICON.get(sev, '?')} [{sev}] {source}: {detail}")
    else:
        header.append('Keine riskanten CORS-Konfigurationen gefunden.')
    header.append('')
    header.append('----- Vollstaendiges Protokoll -----')
    full_report = '\n'.join(header) + '\n' + '\n'.join(log.lines) + '\n'
    SUMMARY_FILE.write_text(full_report, encoding='utf-8')
    total_findings = len(file_findings) + len(cors_findings)
    subject = f"{SEVERITY_ICON.get(level, '✅')} Web-Exposure-Check ({level}) - {total_findings} Fund(e)"
    body = f'{subject}\n\nDer vollstaendige Report (Exposed-Files + CORS) befindet sich im Anhang.\n'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE], logger=log)
    except Exception:
        pass
    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK, f"{SEVERITY_ICON.get(level, '✅')} Web-Exposure-Check: {level} ({len(file_findings)} Exposed-Files, {len(cors_findings)} CORS-Fund(e) auf {hosts_scanned} Hosts). Vollstaendiger Report per E-Mail.")
        except Exception:
            pass
    _shred(SUMMARY_FILE)

def main():
    start = datetime.now(timezone.utc)
    zone_exclude = parse_list(CLOUDFLARE_ZONE_EXCLUDE)
    ignore_hosts = set(parse_list(WEB_EXPOSURE_IGNORE_HOSTS))
    extra_cors_paths = parse_list(CORS_EXTRA_TEST_PATHS)
    all_file_findings = []
    all_cors_findings = []
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
        for host, rec in hosts.items():
            if host in ignore_hosts:
                continue
            base_url = get_working_base_url(host)
            if base_url is None:
                hosts_unreachable += 1
                continue
            hosts_scanned += 1
            file_findings = scan_exposed_files(base_url)
            for sev, path, detail in file_findings:
                all_file_findings.append((sev, f'{host}/{path}', detail))
            cors_findings = scan_cors(base_url, rec.get('zone', ''), extra_cors_paths)
            for sev, path, detail in cors_findings:
                all_cors_findings.append((sev, f'{host}{path}', detail))
    except Exception as e:
        fatal_error = str(e)
        log.log(f'FATAL: {fatal_error}')
    duration = int((datetime.now(timezone.utc) - start).total_seconds())
    combined = all_file_findings + all_cors_findings
    level = 'NONE'
    for lvl in ('CRITICAL', 'HIGH', 'MEDIUM', 'INFO'):
        if any((f[0] == lvl for f in combined)):
            level = lvl
            break
    if fatal_error and level == 'NONE':
        level = 'INFO'
    send_final_report(level, all_file_findings, all_cors_findings, hosts_scanned, hosts_unreachable, zones_count, duration, fatal_error)
    sys.exit(1 if fatal_error or level in ('CRITICAL', 'HIGH') else 0)
if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
