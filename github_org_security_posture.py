#!/usr/bin/env python3
import sys
from datetime import datetime, timezone
from pathlib import Path
from common import env, Redactor, SummaryLogger, list_github_repos, http_get, send_google_chat, send_email_report
SRC_GH_TOKEN = env('SRC_GH_TOKEN')
SRC_GH_OWNER = env('SRC_GH_OWNER')
SRC_GH_OWNER_TYPE = env('SRC_GH_OWNER_TYPE', default='user')
GOOGLE_CHAT_WEBHOOK = env('GOOGLE_CHAT_WEBHOOK')
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='org_security_posture_summary.txt'))
redact = Redactor([SRC_GH_TOKEN])
log = SummaryLogger(redact)
HEADERS = {'Authorization': f'token {SRC_GH_TOKEN}', 'Accept': 'application/vnd.github+json'}
SEVERITY_ICON = {'HIGH': '🟠', 'MEDIUM': '🟡', 'INFO': '⚪', 'NONE': '✅'}

def _shred(path: Path):
    try:
        if path.exists():
            path.write_bytes(b'0' * path.stat().st_size)
            path.unlink()
    except Exception:
        pass

def paginated_get(url: str, params: dict=None) -> tuple:
    items = []
    page = 1
    base_params = dict(params or {})
    while True:
        p = {**base_params, 'per_page': 100, 'page': page}
        r = http_get(url, headers=HEADERS, params=p, timeout=30, description=f'GET {url}', logger=log)
        if r.status_code in (403, 404):
            return (items, f'HTTP {r.status_code}')
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        items.extend(batch)
        page += 1
    return (items, None)

def check_org_level(owner: str) -> list:
    findings = []
    r = http_get(f'https://api.github.com/orgs/{owner}', headers=HEADERS, timeout=30, description='Org-Details abrufen', logger=log)
    if r.status_code == 200:
        data = r.json()
        if not data.get('two_factor_requirement_enabled'):
            findings.append(('HIGH', 'Organisationsweite 2FA-Pflicht ist NICHT aktiviert.'))
        else:
            findings.append(('NONE', 'Organisationsweite 2FA-Pflicht ist aktiv.'))
    else:
        findings.append(('INFO', f'Org-Details nicht abrufbar (HTTP {r.status_code}) - Token braucht ggf. Scope "read:org".'))
        return findings
    members_2fa_disabled, err = paginated_get(f'https://api.github.com/orgs/{owner}/members', {'filter': '2fa_disabled'})
    if err:
        findings.append(('INFO', f'2FA-Status der Mitglieder nicht abrufbar: {err}'))
    elif members_2fa_disabled:
        names = ', '.join((m.get('login', '?') for m in members_2fa_disabled[:20]))
        findings.append(('HIGH', f'{len(members_2fa_disabled)} Mitglied(er) OHNE aktives 2FA: {names}'))
    else:
        findings.append(('NONE', 'Alle Mitglieder haben 2FA aktiv.'))
    outside, err2 = paginated_get(f'https://api.github.com/orgs/{owner}/outside_collaborators')
    if err2:
        findings.append(('INFO', f'Externe Kollaborateure nicht abrufbar: {err2}'))
    elif outside:
        names = ', '.join((m.get('login', '?') for m in outside[:20]))
        findings.append(('MEDIUM', f'{len(outside)} externe(r) Kollaborateur(e) mit Repo-Zugriff: {names}'))
    else:
        findings.append(('NONE', 'Keine externen Kollaborateure.'))
    return findings

def check_branch_protection(owner: str, repos: list) -> list:
    findings = []
    unprotected = []
    checked = 0
    for repo in repos:
        if repo.get('archived') or repo.get('fork'):
            continue
        name = repo['name']
        branch = repo.get('default_branch') or 'main'
        checked += 1
        r = http_get(f'https://api.github.com/repos/{owner}/{name}/branches/{branch}/protection', headers=HEADERS, timeout=30, description=f'Branch-Protection ({name})', logger=log)
        if r.status_code == 404:
            unprotected.append(name)
        elif r.status_code == 403:
            findings.append(('INFO', f'Branch-Protection fuer {name} nicht abrufbar (403).'))
    if unprotected:
        findings.append(('MEDIUM', f"{len(unprotected)} von {checked} aktiven Repos OHNE Branch-Protection: {', '.join(unprotected[:25])}" + (' ...' if len(unprotected) > 25 else '')))
    elif checked:
        findings.append(('NONE', f'Alle {checked} geprueften aktiven Repos haben Branch-Protection.'))
    return findings

def send_final_report(level, all_findings, repos_count, duration, fatal_error=None):
    header = [f'SEVERITY_LEVEL: {level}', f"GitHub-Org-Sicherheitslage - {datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M UTC')}", f'Repos gesamt: {repos_count} | Auffaelligkeiten: {len(all_findings)}', f'Dauer: {duration}s', '']
    if fatal_error:
        header.append(f'!! Der Lauf wurde durch einen Fehler vorzeitig beendet: {fatal_error}')
        header.append('')
    if all_findings:
        header.append('----- Auffaelligkeiten (nach Schwere sortiert) -----')
        order = {'HIGH': 0, 'MEDIUM': 1, 'INFO': 2}
        for sev, scope, detail in sorted(all_findings, key=lambda f: order.get(f[0], 9)):
            header.append(f"{SEVERITY_ICON.get(sev, '?')} [{sev}] [{scope}] {detail}")
        header.append('')
    else:
        header.append('Keine Auffaelligkeiten.')
    header.append('')
    header.append('----- Vollstaendiges Protokoll -----')
    full_report = '\n'.join(header) + '\n' + '\n'.join(log.lines) + '\n'
    SUMMARY_FILE.write_text(full_report, encoding='utf-8')
    subject = f"{SEVERITY_ICON.get(level, '✅')} GitHub-Org-Sicherheitslage ({level}) - {len(all_findings)} Auffaelligkeit(en)"
    body = f'{subject}\n\nDer vollstaendige Report befindet sich im Anhang.\n'
    try:
        send_email_report(subject, body, attachments=[SUMMARY_FILE], logger=log)
    except Exception:
        pass
    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK, f"{SEVERITY_ICON.get(level, '✅')} GitHub-Org-Sicherheitslage: {level} ({len(all_findings)} Auffaelligkeit(en)). Vollstaendiger Report per E-Mail.")
        except Exception:
            pass
    _shred(SUMMARY_FILE)

def main():
    start = datetime.now(timezone.utc)
    all_findings = []
    repos = []
    fatal_error = None
    try:
        if not SRC_GH_TOKEN or not SRC_GH_OWNER:
            raise RuntimeError('SRC_GH_TOKEN oder SRC_GH_OWNER ist nicht gesetzt (Secret/Variable fehlt oder ist leer).')
        if SRC_GH_OWNER_TYPE == 'org':
            for sev, detail in check_org_level(SRC_GH_OWNER):
                if sev != 'NONE':
                    all_findings.append((sev, 'Organisation', detail))
        else:
            all_findings.append(('INFO', 'Organisation', 'SRC_GH_OWNER_TYPE=user - organisationsweite Checks nicht anwendbar.'))
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
        for sev, detail in check_branch_protection(SRC_GH_OWNER, repos):
            if sev != 'NONE':
                all_findings.append((sev, 'Branch-Protection', detail))
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
    send_final_report(level, all_findings, len(repos), duration, fatal_error)
    sys.exit(1 if fatal_error or level == 'HIGH' else 0)
if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
