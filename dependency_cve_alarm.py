#!/usr/bin/env python3
import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import requests
from common import send_email_report

def env(name, required=False, default=None):
    val = os.environ.get(name, default)
    if required and (not val):
        print(f'FEHLER: Pflicht-Konfiguration fehlt (Name absichtlich nicht angezeigt).')
        sys.exit(1)
    return val
SRC_GH_TOKEN = env('SRC_GH_TOKEN', required=True)
SRC_GH_OWNER = env('SRC_GH_OWNER', required=True)
SRC_GH_OWNER_TYPE = env('SRC_GH_OWNER_TYPE', default='user')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='email_summary.txt'))
QUIET_CONSOLE = env('QUIET_CONSOLE', default='true').lower() == 'true'
MAX_RETRIES = int(env('MAX_RETRIES', default='3'))
RETRY_BASE_DELAY_SECONDS = float(env('RETRY_BASE_DELAY_SECONDS', default='3'))
MAX_DETAILS_PER_REPO = int(env('MAX_DETAILS_PER_REPO', default='10'))
MAX_TOP_REPOS = int(env('MAX_TOP_REPOS', default='15'))
_SECRETS = [s for s in [SRC_GH_TOKEN] if s]

def redact(text: str) -> str:
    for s in _SECRETS:
        if s and s in text:
            text = text.replace(s, '***REDACTED***')
    return text
SUMMARY_LINES = []
_repo_total = 0
_repo_index = 0

def summary_log(msg: str):
    ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
    SUMMARY_LINES.append(f'[{ts}] {redact(str(msg))}')

def console_heartbeat(msg: str=None):
    if QUIET_CONSOLE:
        if msg:
            print(msg, flush=True)
        else:
            print('... Pruefe ein Repo ...', flush=True)
    else:
        print(msg or '... Pruefe ein Repo ...', flush=True)

def with_retry(func, description: str):
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return func()
        except Exception as e:
            last_error = e
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY_SECONDS * attempt
                summary_log(f"     (Versuch {attempt}/{MAX_RETRIES} fehlgeschlagen bei '{description}': {e} - neuer Versuch in {delay:.0f}s)")
                time.sleep(delay)
            else:
                summary_log(f"     (Endgueltig fehlgeschlagen nach {MAX_RETRIES} Versuchen bei '{description}': {e})")
    raise last_error

def http_get(url, headers=None, params=None, timeout=30, description: str=None):

    def _attempt():
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code >= 500:
            raise RuntimeError(f'Serverfehler HTTP {r.status_code} bei {url}')
        return r
    return with_retry(_attempt, description or f'GET {url}')

def list_source_repos():
    repos = []
    page = 1
    base = f'https://api.github.com/orgs/{SRC_GH_OWNER}/repos' if SRC_GH_OWNER_TYPE == 'org' else 'https://api.github.com/user/repos'
    headers = {'Authorization': f'token {SRC_GH_TOKEN}', 'Accept': 'application/vnd.github+json'}
    while True:
        params = {'per_page': 100, 'page': page}
        if SRC_GH_OWNER_TYPE != 'org':
            params['affiliation'] = 'owner'
        r = http_get(base, headers=headers, params=params, timeout=60, description='Quell-Repos auflisten')
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
    return repos
SEVERITY_ORDER = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
SEVERITY_ICON = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '⚪'}

def get_dependabot_alerts(name: str):
    headers = {'Authorization': f'Bearer {SRC_GH_TOKEN}', 'Accept': 'application/vnd.github+json'}
    base = f'https://api.github.com/repos/{SRC_GH_OWNER}/{name}/dependabot/alerts'
    alerts = []
    page = 1
    while True:
        params = {'state': 'open', 'per_page': 100, 'page': page}
        r = http_get(base, headers=headers, params=params, timeout=30, description=f'Dependabot-Alerts abrufen ({name})')
        if r.status_code == 404:
            return None
        if r.status_code == 403:
            raise RuntimeError("Kein Zugriff auf Dependabot-Alerts (HTTP 403). Pruefe, ob der Token den Scope 'security_events' (klassischer PAT) bzw. die Berechtigung 'Dependabot alerts: Read-only' (feingranularer PAT) besitzt.")
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        alerts.extend(batch)
        page += 1
    return alerts

def summarize_alerts(alerts):
    counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    details = []
    for a in alerts:
        sev = (a.get('security_advisory', {}).get('severity') or 'unknown').lower()
        if sev in counts:
            counts[sev] += 1
        pkg = a.get('security_vulnerability', {}).get('package', {}).get('name', '?')
        eco = a.get('security_vulnerability', {}).get('package', {}).get('ecosystem', '?')
        summary = a.get('security_advisory', {}).get('summary', '')
        url = a.get('html_url', '')
        details.append({'severity': sev, 'package': pkg, 'ecosystem': eco, 'summary': summary, 'url': url})
    details.sort(key=lambda d: -SEVERITY_ORDER.get(d['severity'], 0))
    return (counts, details)

def process_repo(name: str):
    try:
        alerts = get_dependabot_alerts(name)
    except Exception as e:
        summary_log(f'--- {name} ---')
        summary_log(f'  !! FEHLER beim Abrufen der Dependabot-Alerts: {e}')
        return (None, True)
    if alerts is None:
        return ({'repo': name, 'disabled': True, 'counts': None, 'total': 0}, False)
    counts, details = summarize_alerts(alerts)
    total = sum(counts.values())
    if total > 0:
        summary_log(f'--- {name} ---')
        summary_log(f"  kritisch={counts['critical']} hoch={counts['high']} mittel={counts['medium']} niedrig={counts['low']}")
        for d in details[:MAX_DETAILS_PER_REPO]:
            icon = SEVERITY_ICON.get(d['severity'], '❔')
            summary_log(f"    {icon} [{d['severity'].upper()}] {d['ecosystem']}/{d['package']}: {d['summary']} ({d['url']})")
        if len(details) > MAX_DETAILS_PER_REPO:
            summary_log(f'    ... und {len(details) - MAX_DETAILS_PER_REPO} weitere Alert(s)')
    return ({'repo': name, 'disabled': False, 'counts': counts, 'total': total}, False)

def main():
    global _repo_total, _repo_index
    start_time = datetime.now(timezone.utc)
    console_heartbeat('Dependency-/CVE-Alarm gestartet.')
    summary_log('===== Dependency-/CVE-Alarm gestartet =====')
    grand = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    disabled_repos = []
    error_repos = []
    repos_with_findings = []
    fatal_error = False
    try:
        repos = list_source_repos()
        _repo_total = len(repos)
        summary_log(f'{_repo_total} Quell-Repos gefunden.')
        for i, repo in enumerate(repos, start=1):
            _repo_index = i
            console_heartbeat()
            result, had_error = process_repo(repo['name'])
            if had_error:
                error_repos.append(repo['name'])
                continue
            if result['disabled']:
                disabled_repos.append(result['repo'])
                continue
            for k in grand:
                grand[k] += result['counts'][k]
            if result['total'] > 0:
                repos_with_findings.append((result['repo'], result['total'], result['counts']))
    except Exception as e:
        summary_log(f'!! SCHWERWIEGENDER FEHLER, Lauf abgebrochen: {e}')
        fatal_error = True
    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    total_open = sum(grand.values())
    if grand['critical'] > 0:
        level = 'CRITICAL'
    elif grand['high'] > 0:
        level = 'HIGH'
    elif grand['medium'] > 0:
        level = 'MEDIUM'
    elif grand['low'] > 0:
        level = 'LOW'
    else:
        level = 'NONE'
    summary_line = f'===== Fertig: {total_open} offene Alert(s) gesamt. Dauer: {int(duration)}s ====='
    summary_log(summary_line)
    console_heartbeat('Dependency-/CVE-Alarm beendet.')
    header = f"SEVERITY_LEVEL: {level}\nDependency-/CVE-Alarm Zusammenfassung\nRepos geprueft: {_repo_total} | mit offenen Alerts: {len(repos_with_findings)} | Abruf-Fehler: {len(error_repos)} | Dependabot nicht aktiviert: {len(disabled_repos)}\nOffene Alerts gesamt: kritisch={grand['critical']} hoch={grand['high']} mittel={grand['medium']} niedrig={grand['low']}\nDauer: {int(duration)} Sekunden\n"
    if repos_with_findings:
        repos_with_findings.sort(key=lambda x: (-x[2]['critical'], -x[2]['high'], -x[1]))
        top = ', '.join((f"{n}({c['critical']}C/{c['high']}H/{c['medium']}M/{c['low']}L)" for n, t, c in repos_with_findings[:MAX_TOP_REPOS]))
        header += f'Betroffene Repos (Top {MAX_TOP_REPOS}, sortiert nach Schwere): {top}\n'
        if len(repos_with_findings) > MAX_TOP_REPOS:
            header += f'... und {len(repos_with_findings) - MAX_TOP_REPOS} weitere Repo(s) mit Alerts\n'
    if error_repos:
        header += 'Repos mit Abruf-Fehlern: ' + ', '.join(error_repos) + '\n'
    header += '\n----- Vollstaendiges Protokoll -----\n'
    SUMMARY_FILE.write_text(header + '\n'.join(SUMMARY_LINES) + '\n', encoding='utf-8')
    subject = f'Dependency-/CVE-Alarm Ergebnis ({level})'
    body = f'{header}\nDer ungekuerzte vollstaendige Report befindet sich als Anhang im Dateianhang.'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE])
    except Exception:
        pass
    sys.exit(1 if fatal_error or error_repos else 0)
if __name__ == '__main__':
    try:
        main()
    except Exception as exc:
        print('Ein unerwarteter Fehler ist aufgetreten.', file=sys.stderr, flush=True)
        sys.exit(1)
