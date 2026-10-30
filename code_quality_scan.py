#!/usr/bin/env python3
"""Code Testing Server: linters, Gitleaks, Trivy and OWASP ZAP across many repositories.

Modes (env CQ_MODE):
  shard      Scan the repositories assigned to this matrix shard (SHARD_INDEX / SHARD_TOTAL).
             Unchanged repositories (same HEAD commit, scanned recently) are skipped and their
             previous results are re-used, so a twice-daily run over 180+ repos stays fast.
  zap        OWASP ZAP baseline (passive) scan of every URL in ZAP_TARGETS.
  aggregate  Merge all shard/ZAP results, update state, build reports, send the e-mail.

Intermediate results are exchanged through a private Google Drive staging folder
(never as GitHub artifacts) and deleted by the aggregate job.
"""
import hashlib
import json
import os
import re
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

from common import env, Redactor, SummaryLogger, list_github_repos
from sec_common import (Drive, HtmlReport, deliver_report, drive_service, file_stamp, human_duration, parse_list,
                        run_cmd, shred_paths, tool_available, ts_label, utc_now, write_csv, write_log)

MODE = env('CQ_MODE', default='shard')
SCAN_MODE = env('CQ_SCAN_MODE', default='incremental').lower()  # incremental | full
SHARD_INDEX = int(env('SHARD_INDEX', default='0'))
SHARD_TOTAL = max(1, int(env('SHARD_TOTAL', default='1')))
RUN_KEY = env('CQ_RUN_KEY', default=file_stamp())

SRC_GH_TOKEN = env('SRC_GH_TOKEN')
SRC_GH_OWNER = env('SRC_GH_OWNER')
SRC_GH_OWNER_TYPE = env('SRC_GH_OWNER_TYPE', default='user')
SCAN_REPO_LIST = env('SCAN_REPO_LIST', default='')
SCAN_REPO_EXCLUDE = env('SCAN_REPO_EXCLUDE', default='')
SKIP_ARCHIVED = env('SCAN_SKIP_ARCHIVED', default='true').lower() == 'true'
SKIP_FORKS = env('SCAN_SKIP_FORKS', default='true').lower() == 'true'
FORCE_RESCAN_DAYS = int(env('FORCE_RESCAN_DAYS', default='7'))
REPO_TIMEOUT_MIN = int(env('REPO_TIMEOUT_MIN', default='20'))
SHARD_BUDGET_MIN = int(env('SHARD_BUDGET_MIN', default='300'))
MAX_FINDINGS_PER_TOOL = int(env('MAX_FINDINGS_PER_TOOL', default='150'))

ZAP_TARGETS = env('ZAP_TARGETS', default='')
ZAP_MAX_MINUTES = env('ZAP_MAX_MINUTES', default='5')
ZAP_IMAGE = env('ZAP_IMAGE', default='ghcr.io/zaproxy/zaproxy:stable')

GDRIVE_SA_JSON = env('GDRIVE_SA_JSON')
GDRIVE_FOLDER_ID = env('GDRIVE_FOLDER_ID')
STATE_FOLDER_NAME = env('CQ_STATE_FOLDER_NAME', default='Code_Scan_State')

WORK = Path(env('CQ_WORKDIR', default='cq_work')).resolve()
REPORT_DIR = Path(env('REPORT_DIR', default='cq_reports')).resolve()
redact = Redactor([SRC_GH_TOKEN, GDRIVE_SA_JSON])
log = SummaryLogger(redact)
START = time.monotonic()
SKIP_DIRS = {'.git', 'node_modules', 'vendor', 'dist', 'build', '.venv', 'venv', '__pycache__', '.next',
             'target', 'bower_components', '.terraform', 'coverage', '.tox', 'site-packages'}
LANG_BY_EXT = {
    '.py': 'Python', '.js': 'JavaScript', '.mjs': 'JavaScript', '.cjs': 'JavaScript', '.jsx': 'JavaScript',
    '.ts': 'TypeScript', '.tsx': 'TypeScript', '.sh': 'Shell', '.bash': 'Shell', '.go': 'Go', '.php': 'PHP',
    '.yml': 'YAML', '.yaml': 'YAML', '.java': 'Java', '.kt': 'Kotlin', '.rb': 'Ruby', '.rs': 'Rust',
    '.cs': 'C#', '.c': 'C/C++', '.cpp': 'C/C++', '.h': 'C/C++', '.swift': 'Swift', '.dart': 'Dart',
    '.tf': 'Terraform', '.vue': 'Vue', '.svelte': 'Svelte', '.css': 'CSS', '.scss': 'CSS', '.html': 'HTML',
}


# --------------------------------------------------------------------------- #
# Drive staging / state
# --------------------------------------------------------------------------- #
def staging():
    if not (GDRIVE_SA_JSON and GDRIVE_FOLDER_ID):
        raise RuntimeError('GDRIVE_SA_JSON and GDRIVE_FOLDER_ID are required (results exchange + state).')
    drv = Drive(drive_service(GDRIVE_SA_JSON), log)
    root = drv.ensure_folder(GDRIVE_FOLDER_ID, STATE_FOLDER_NAME)
    run_folder = drv.ensure_folder(drv.ensure_folder(root, 'staging'), RUN_KEY)
    return drv, root, run_folder


# --------------------------------------------------------------------------- #
# Repository selection
# --------------------------------------------------------------------------- #
def select_repos() -> list:
    wanted = parse_list(SCAN_REPO_LIST)
    excluded = {x.lower() for x in parse_list(SCAN_REPO_EXCLUDE)}
    all_repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    by_name = {}
    for r in all_repos:
        by_name[r['full_name'].lower()] = r
        by_name.setdefault(r['name'].lower(), r)
    selected = []
    if wanted and wanted != ['*']:
        for w in wanted:
            r = by_name.get(w.lower())
            if r:
                selected.append(r)
            else:
                log.log(f'Listed repository not accessible with SRC_GH_TOKEN (entry #{wanted.index(w) + 1}).')
    else:
        selected = all_repos
    out = []
    for r in selected:
        if r['full_name'].lower() in excluded or r['name'].lower() in excluded:
            continue
        if SKIP_ARCHIVED and r.get('archived'):
            continue
        if SKIP_FORKS and r.get('fork') and not wanted:
            continue
        if int(r.get('size') or 0) == 0:
            continue
        out.append(r)
    uniq = {r['full_name']: r for r in out}
    return sorted(uniq.values(), key=lambda r: r['full_name'].lower())


def shard_of(repos: list) -> list:
    # Greedy size-balanced assignment: largest repos first onto the lightest shard.
    loads = [0] * SHARD_TOTAL
    assignment = {}
    for r in sorted(repos, key=lambda x: -int(x.get('size') or 0)):
        i = loads.index(min(loads))
        loads[i] += int(r.get('size') or 0) + 2000  # constant = per-repo overhead
        assignment[r['full_name']] = i
    return [r for r in repos if assignment[r['full_name']] == SHARD_INDEX]


# --------------------------------------------------------------------------- #
# Tools
# --------------------------------------------------------------------------- #
def walk_files(root: Path):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            yield Path(dirpath) / fn


def detect(root: Path):
    langs = Counter()
    files = {'sh': [], 'docker': [], 'php': [], 'yaml': []}
    for p in walk_files(root):
        ext = p.suffix.lower()
        if ext in LANG_BY_EXT:
            langs[LANG_BY_EXT[ext]] += 1
        if ext in ('.sh', '.bash'):
            files['sh'].append(p)
        elif ext == '.php':
            files['php'].append(p)
        elif ext in ('.yml', '.yaml'):
            files['yaml'].append(p)
        if p.name == 'Dockerfile' or p.name.startswith('Dockerfile.') or p.name.endswith('.dockerfile'):
            files['docker'].append(p)
    return langs, files


def rel(root: Path, path) -> str:
    try:
        return str(Path(path).resolve().relative_to(root.resolve()))
    except Exception:
        return str(path)


def lint_python(root, add):
    if not tool_available('ruff'):
        return 'skipped (ruff missing)'
    rc, out, _ = run_cmd(['ruff', 'check', '--exit-zero', '--output-format', 'json', '--no-cache', '.'], cwd=root,
                         timeout=600)
    try:
        items = json.loads(out or '[]')
    except Exception:
        items = []
    for it in items:
        loc = it.get('location') or {}
        add('lint', 'ruff', 'LOW', f"{rel(root, it.get('filename', ''))}:{loc.get('row')}", it.get('code'),
            it.get('message'))
    if tool_available('bandit'):
        rc, out, _ = run_cmd(['bandit', '-r', '.', '-f', 'json', '-q', '--exit-zero', '-x',
                              './.venv,./venv,./node_modules,./tests,./test'], cwd=root, timeout=900)
        try:
            for it in json.loads(out or '{}').get('results', []):
                sev = {'HIGH': 'HIGH', 'MEDIUM': 'MEDIUM'}.get(it.get('issue_severity'), 'LOW')
                add('sast', 'bandit', sev, f"{rel(root, it.get('filename'))}:{it.get('line_number')}",
                    it.get('test_id'), it.get('issue_text'))
        except Exception:
            pass
    return 'ok'


def lint_js(root, add):
    if not tool_available('biome'):
        return 'skipped (biome missing)'
    rc, out, err = run_cmd(['biome', 'lint', '--max-diagnostics=200', '--colors=off', '.'], cwd=root, timeout=600)
    text = out + '\n' + err
    errors = sum(int(x) for x in re.findall(r'Found (\d+) errors?', text))
    warnings = sum(int(x) for x in re.findall(r'Found (\d+) warnings?', text))
    for m in re.finditer(r'^(\S+?):(\d+):\d+\s+(lint/\S+)', text, re.M):
        add('lint', 'biome', 'LOW', f'{m.group(1)}:{m.group(2)}', m.group(3), 'Biome lint diagnostic')
    return f'ok ({errors} errors, {warnings} warnings reported by biome)'


def lint_shell(root, files, add):
    if not files or not tool_available('shellcheck'):
        return 'skipped'
    for i in range(0, len(files), 200):
        chunk = [str(f) for f in files[i:i + 200]]
        rc, out, _ = run_cmd(['shellcheck', '-f', 'json', '-S', 'warning'] + chunk, timeout=600)
        try:
            for it in json.loads(out or '[]'):
                sev = 'MEDIUM' if it.get('level') == 'error' else 'LOW'
                add('lint', 'shellcheck', sev, f"{rel(root, it.get('file'))}:{it.get('line')}", f"SC{it.get('code')}",
                    it.get('message'))
        except Exception:
            pass
    return 'ok'


def lint_docker(root, files, add):
    if not files or not tool_available('docker'):
        return 'skipped'
    for f in files[:50]:
        rc, out, _ = run_cmd(['docker', 'run', '--rm', '-i', '--network', 'none', 'hadolint/hadolint',
                              'hadolint', '-f', 'json', '-'], input_text=f.read_text(errors='ignore'), timeout=120)
        try:
            for it in json.loads(out or '[]'):
                sev = {'error': 'MEDIUM', 'warning': 'LOW'}.get(it.get('level'), 'LOW')
                add('lint', 'hadolint', sev, f"{rel(root, f)}:{it.get('line')}", it.get('code'), it.get('message'))
        except Exception:
            pass
    return 'ok'


def lint_yaml(root, files, add):
    if not files or not tool_available('yamllint'):
        return 'skipped'
    rc, out, _ = run_cmd(['yamllint', '-f', 'parsable', '-d', '{extends: relaxed, rules: {line-length: disable}}']
                         + [str(f) for f in files[:2000]], timeout=600)
    for line in out.splitlines():
        m = re.match(r'(.+?):(\d+):\d+: \[(\w+)\] (.+)', line)
        if m and m.group(3) == 'error':
            add('lint', 'yamllint', 'LOW', f'{rel(root, m.group(1))}:{m.group(2)}', 'yaml', m.group(4))
    return 'ok'


def lint_php(root, files, add):
    if not files or not tool_available('php'):
        return 'skipped'
    for f in files[:3000]:
        rc, out, err = run_cmd(['php', '-l', str(f)], timeout=30)
        if rc != 0:
            msg = (out + err).strip().splitlines()
            add('lint', 'php -l', 'MEDIUM', rel(root, f), 'syntax', msg[0][:300] if msg else 'syntax error')
    return 'ok'


def lint_go(root, add):
    if not tool_available('gofmt'):
        return 'skipped'
    rc, out, _ = run_cmd(['gofmt', '-l', '.'], cwd=root, timeout=300)
    for line in out.splitlines():
        if line.strip() and not any(part in SKIP_DIRS for part in Path(line).parts):
            add('lint', 'gofmt', 'LOW', line.strip(), 'format', 'File is not gofmt-formatted')
    return 'ok'


def run_gitleaks(root, add, history: bool):
    if not tool_available('gitleaks'):
        return 'skipped (gitleaks missing)'
    report = WORK / f'gl_{hashlib.md5(str(root).encode()).hexdigest()}.json'
    cmd = ['gitleaks', 'git' if history else 'dir', str(root), '--no-banner', '--redact', '--exit-code', '0',
           '--report-format', 'json', '--report-path', str(report), '--log-level', 'error']
    rc, _, err = run_cmd(cmd, timeout=REPO_TIMEOUT_MIN * 60)
    try:
        for it in json.loads(report.read_text(encoding='utf-8')) or []:
            where = f"{rel(root, it.get('File'))}:{it.get('StartLine')}"
            if history and it.get('Commit'):
                where += f" @{it.get('Commit')[:8]}"
            add('secret', 'gitleaks', 'HIGH', where, it.get('RuleID'), f"{it.get('Description')} (value redacted)")
    except Exception:
        return f'error ({err[-150:]})'
    finally:
        shred_paths(report)
    return 'ok (full history)' if history else 'ok (working tree)'


def run_trivy(root, add):
    if not tool_available('trivy'):
        return 'skipped (trivy missing)'
    report = WORK / f'tv_{hashlib.md5(str(root).encode()).hexdigest()}.json'
    rc, _, err = run_cmd(['trivy', 'fs', '--quiet', '--skip-db-update', '--scanners', 'vuln,misconfig',
                          '--format', 'json', '--output', str(report), '--timeout', f'{REPO_TIMEOUT_MIN}m',
                          '--skip-dirs', 'node_modules', str(root)], timeout=REPO_TIMEOUT_MIN * 60 + 60)
    try:
        data = json.loads(report.read_text(encoding='utf-8'))
    except Exception:
        return f'error ({err[-150:]})'
    finally:
        shred_paths(report)
    for t in data.get('Results', []) or []:
        tgt = t.get('Target', '')
        for v in t.get('Vulnerabilities', []) or []:
            sev = v.get('Severity', 'UNKNOWN')
            add('vuln', 'trivy', sev if sev in ('CRITICAL', 'HIGH', 'MEDIUM', 'LOW') else 'LOW', tgt,
                v.get('VulnerabilityID'), f"{v.get('PkgName')} {v.get('InstalledVersion')} -> "
                                          f"{v.get('FixedVersion') or 'no fix'}: {(v.get('Title') or '')[:160]}")
        for m in t.get('Misconfigurations', []) or []:
            sev = m.get('Severity', 'LOW')
            add('config', 'trivy', sev if sev in ('CRITICAL', 'HIGH', 'MEDIUM') else 'LOW', tgt, m.get('ID'),
                m.get('Title'))
    return 'ok'


def head_sha(clone_url: str) -> str:
    rc, out, _ = run_cmd(['git', 'ls-remote', clone_url, 'HEAD'], timeout=120)
    return out.split('\t', 1)[0].strip() if rc == 0 and out else ''


def scan_repo(repo: dict, sha: str) -> dict:
    full = repo['full_name']
    started = time.monotonic()
    url = repo['clone_url'].replace('https://', f'https://x-access-token:{SRC_GH_TOKEN}@')
    dest = WORK / hashlib.sha1(full.encode()).hexdigest()[:12]
    shred_paths(dest)
    history = SCAN_MODE == 'full'
    clone = ['git', 'clone', '--quiet', '--single-branch', '--no-tags']
    if not history:
        clone += ['--depth', '1']
    rc, _, err = run_cmd(clone + [url, str(dest)], timeout=REPO_TIMEOUT_MIN * 60)
    result = {'repo': full, 'sha': sha, 'private': bool(repo.get('private')), 'scanned_at': utc_now().isoformat(),
              'languages': {}, 'tools': {}, 'counts': {}, 'findings': [], 'truncated': {}, 'error': ''}
    if rc != 0:
        result['error'] = 'clone failed: ' + redact(err)[-300:]
        return result
    per_tool = Counter()

    def add(category, tool, severity, location, rule, message):
        key = f'{category}:{severity}'
        result['counts'][key] = result['counts'].get(key, 0) + 1
        per_tool[tool] += 1
        if per_tool[tool] <= MAX_FINDINGS_PER_TOOL:
            result['findings'].append([category, tool, severity, str(location)[:300], str(rule or '')[:80],
                                       redact(str(message or ''))[:400]])
        else:
            result['truncated'][tool] = per_tool[tool] - MAX_FINDINGS_PER_TOOL

    langs, files = detect(dest)
    result['languages'] = dict(langs.most_common(6))
    if langs.get('Python'):
        result['tools']['ruff/bandit'] = lint_python(dest, add)
    if langs.get('JavaScript') or langs.get('TypeScript'):
        result['tools']['biome'] = lint_js(dest, add)
    if files['sh']:
        result['tools']['shellcheck'] = lint_shell(dest, files['sh'], add)
    if files['docker']:
        result['tools']['hadolint'] = lint_docker(dest, files['docker'], add)
    if files['yaml']:
        result['tools']['yamllint'] = lint_yaml(dest, files['yaml'], add)
    if files['php']:
        result['tools']['php -l'] = lint_php(dest, files['php'], add)
    if langs.get('Go'):
        result['tools']['gofmt'] = lint_go(dest, add)
    result['tools']['gitleaks'] = run_gitleaks(dest, add, history)
    result['tools']['trivy'] = run_trivy(dest, add)
    result['duration_s'] = int(time.monotonic() - started)
    shred_paths(dest)
    return result


# --------------------------------------------------------------------------- #
# Modes
# --------------------------------------------------------------------------- #
def mode_shard():
    drv, root, run_folder = staging()
    state = drv.read_json(root, 'state.json', default={}) or {}
    repos = shard_of(select_repos())
    log.log(f'Shard {SHARD_INDEX + 1}/{SHARD_TOTAL}: {len(repos)} repositories, mode {SCAN_MODE}.')
    results, now = [], utc_now()
    for i, repo in enumerate(repos, 1):
        full = repo['full_name']
        auth_url = repo['clone_url'].replace('https://', f'https://x-access-token:{SRC_GH_TOKEN}@')
        sha = head_sha(auth_url)
        prev = state.get(full)
        if SCAN_MODE != 'full' and prev and sha and prev.get('sha') == sha:
            try:
                from datetime import datetime
                age = (now - datetime.fromisoformat(prev['scanned_at'])).days
            except Exception:
                age = 999
            if age < FORCE_RESCAN_DAYS:
                cached = dict(prev, cached=True)
                results.append(cached)
                continue
        if time.monotonic() - START > SHARD_BUDGET_MIN * 60:
            results.append({'repo': full, 'sha': sha, 'error': 'not scanned - shard time budget reached',
                            'skipped': True})
            continue
        try:
            res = scan_repo(repo, sha)
        except Exception as exc:
            res = {'repo': full, 'sha': sha, 'error': redact(str(exc))[:300]}
        res['cached'] = False
        results.append(res)
        log.log(f'[{i}/{len(repos)}] repo #{i} done ({res.get("duration_s", 0)}s).')
    drv.write_json(run_folder, f'shard_{SHARD_INDEX:02d}.json', {'shard': SHARD_INDEX, 'results': results,
                                                                 'log': log.lines})


def zap_one(url: str, idx: int, out_dir: Path) -> dict:
    out_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(out_dir, 0o777)
    base = f'zap_target{idx:02d}'
    rc, out, err = run_cmd(['docker', 'run', '--rm', '-v', f'{out_dir}:/zap/wrk:rw', ZAP_IMAGE,
                            'zap-baseline.py', '-t', url, '-m', str(ZAP_MAX_MINUTES), '-J', f'{base}.json',
                            '-r', f'{base}.html', '-I', '-s'], timeout=60 * 60)
    res = {'target': url, 'index': idx, 'rc': rc, 'alerts': [], 'html': f'{base}.html'}
    try:
        data = json.loads((out_dir / f'{base}.json').read_text(encoding='utf-8'))
        for site in data.get('site', []) or []:
            for a in site.get('alerts', []) or []:
                res['alerts'].append({'risk': {'3': 'HIGH', '2': 'MEDIUM', '1': 'LOW', '0': 'INFO'}.get(
                    str(a.get('riskcode')), 'INFO'), 'name': a.get('name') or a.get('alert'),
                    'count': int(a.get('count') or len(a.get('instances') or [])),
                    'solution': re.sub(r'<[^>]+>', '', a.get('solution') or '')[:300],
                    'cwe': a.get('cweid')})
    except Exception as exc:
        res['error'] = f'no ZAP report ({exc}); rc={rc}'
    return res


def mode_zap():
    drv, root, run_folder = staging()
    targets = parse_list(ZAP_TARGETS)
    out_dir = WORK / 'zap'
    results = []
    for i, url in enumerate(targets, 1):
        r = zap_one(url, i, out_dir)
        results.append(r)
        html = out_dir / r['html']
        if html.exists():
            drv.upload_file(html, run_folder, name=r['html'], mimetype='text/html')
        log.log(f'ZAP target #{i}: {len(r["alerts"])} alert type(s).')
    drv.write_json(run_folder, 'zap.json', {'results': results, 'log': log.lines})
    shred_paths(out_dir)


def mode_aggregate():
    drv, root, run_folder = staging()
    parts = drv.children(run_folder, files_only=True)
    repo_results, zap_results, logs, zap_html = [], [], [], []
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    zap_dir = REPORT_DIR / 'zap_html'
    for p in parts:
        if p['name'].startswith('shard_') and p['name'].endswith('.json'):
            d = drv.read_json(run_folder, p['name'], default={}) or {}
            repo_results += d.get('results', [])
            logs += [f"[shard {d.get('shard')}] {line}" for line in d.get('log', [])]
        elif p['name'] == 'zap.json':
            d = drv.read_json(run_folder, p['name'], default={}) or {}
            zap_results = d.get('results', [])
            logs += [f'[zap] {line}' for line in d.get('log', [])]
        elif p['name'].endswith('.html'):
            zap_html.append(drv.download(p['id'], zap_dir / p['name']) and zap_dir / p['name'])
    expected = int(env('EXPECTED_SHARDS', default=str(SHARD_TOTAL)))
    got = len({p['name'] for p in parts if p['name'].startswith('shard_')})

    # Update state with freshly scanned repos only.
    state = drv.read_json(root, 'state.json', default={}) or {}
    for r in repo_results:
        if not r.get('cached') and not r.get('error') and r.get('sha'):
            state[r['repo']] = {k: v for k, v in r.items() if k != 'cached'}
    current = {r['repo'] for r in repo_results}
    state = {k: v for k, v in state.items() if k in current} if current else state
    drv.write_json(root, 'state.json', state)

    def c(r, *keys):
        return sum(v for k, v in (r.get('counts') or {}).items() if k in keys)

    rows, csv_rows, totals = [], [], Counter()
    for r in sorted(repo_results, key=lambda x: (-c(x, 'secret:HIGH', 'vuln:CRITICAL'), x['repo'].lower())):
        crit = c(r, 'vuln:CRITICAL', 'config:CRITICAL')
        high = c(r, 'vuln:HIGH', 'config:HIGH', 'sast:HIGH')
        med = c(r, 'vuln:MEDIUM', 'config:MEDIUM', 'sast:MEDIUM')
        secrets = c(r, 'secret:HIGH')
        lint = sum(v for k, v in (r.get('counts') or {}).items() if k.startswith('lint:'))
        totals.update({'critical': crit, 'high': high, 'medium': med, 'secrets': secrets, 'lint': lint})
        status = 'FAIL' if r.get('error') else ('CRITICAL' if (crit or secrets) else ('HIGH' if high else (
            'MEDIUM' if med else 'OK')))
        rows.append([status, r['repo'], 'private' if r.get('private') else 'public',
                     ', '.join(f'{k} ({v})' for k, v in (r.get('languages') or {}).items()) or '-',
                     'cached' if r.get('cached') else 'scanned', crit, high, med, secrets, lint,
                     (r.get('sha') or '')[:8], r.get('error') or ''])
        for f in r.get('findings') or []:
            csv_rows.append([r['repo']] + f)
    zrows = []
    for z in zap_results:
        counts = Counter(a['risk'] for a in z.get('alerts', []))
        totals['zap_high'] += counts.get('HIGH', 0)
        zrows.append(['HIGH' if counts.get('HIGH') else ('MEDIUM' if counts.get('MEDIUM') else 'OK'), z['target'],
                      counts.get('HIGH', 0), counts.get('MEDIUM', 0), counts.get('LOW', 0), counts.get('INFO', 0),
                      z.get('error', '')])
    zdetail = [[a['risk'], z['target'], a['name'], a['count'], a.get('cwe') or '', a['solution']]
               for z in zap_results for a in z.get('alerts', []) if a['risk'] in ('HIGH', 'MEDIUM', 'LOW')]

    overall = 'CRITICAL' if (totals['critical'] or totals['secrets']) else ('HIGH' if (totals['high'] or totals['zap_high']) else 'OK')
    rep = HtmlReport('Code Testing Server Report', f'Mode: {SCAN_MODE} | {ts_label()} | shards received '
                                                   f'{got}/{expected}')
    rep.kpis({'Overall': overall, 'Repositories': len(repo_results),
              'Scanned now': sum(1 for r in repo_results if not r.get('cached')),
              'Re-used (unchanged)': sum(1 for r in repo_results if r.get('cached')),
              'Critical vulns': totals['critical'], 'High': totals['high'], 'Secrets': totals['secrets'],
              'Lint issues': totals['lint'], 'ZAP high alerts': totals['zap_high']})
    if got < expected:
        rep.text('Warning', [f'Only {got} of {expected} shard results arrived - some repositories are missing.'])
    rep.table('Repositories (worst first)', ['Status', 'Repository', 'Visibility', 'Languages', 'Result',
                                             'Critical', 'High', 'Medium', 'Secrets', 'Lint', 'Commit', 'Error'],
              rows, badge_cols=(0,), note='"cached" = HEAD commit unchanged since the last scan; previous results '
                                         f'are shown (forced re-scan every {FORCE_RESCAN_DAYS} days).')
    if zap_results:
        rep.table('OWASP ZAP baseline (passive) - targets', ['Status', 'Target', 'High', 'Medium', 'Low', 'Info',
                                                             'Error'], zrows, badge_cols=(0,))
        rep.table('OWASP ZAP alerts', ['Risk', 'Target', 'Alert', 'Instances', 'CWE', 'Solution'], zdetail,
                  badge_cols=(0,))
    top = sorted(csv_rows, key=lambda x: {'CRITICAL': 0, 'HIGH': 1, 'MEDIUM': 2}.get(x[3], 9))
    top = [x for x in top if x[1] in ('secret', 'vuln', 'sast', 'config') and x[3] in ('CRITICAL', 'HIGH')][:1500]
    rep.table('Critical / high findings (all details in CSV)', ['Repository', 'Category', 'Tool', 'Severity',
                                                                 'Location', 'Rule', 'Message'], top, badge_cols=(3,))
    html_path = rep.write(REPORT_DIR / f'code_quality_{file_stamp()}.html')
    csv_path = write_csv(REPORT_DIR / f'code_quality_findings_{file_stamp()}.csv',
                         ['repository', 'category', 'tool', 'severity', 'location', 'rule', 'message'], csv_rows)
    log.lines = logs + log.lines
    log_path = write_log(log, REPORT_DIR / 'run_log.txt')
    icon = {'CRITICAL': '🔴', 'HIGH': '🟠', 'OK': '✅'}[overall]
    subject = (f"{icon} Code Testing Server ({SCAN_MODE}): {overall} - {totals['critical']} critical, "
               f"{totals['secrets']} secrets, {totals['high']} high")
    body = (f'{subject}\n\nRepositories: {len(repo_results)}\nShards received: {got}/{expected}\n'
            f'ZAP targets: {len(zap_results)}\n\nFull HTML report, CSV with all findings, ZAP reports and run log '
            f'are attached.')
    deliver_report(subject, body, [html_path, csv_path, log_path], bulk=[p for p in zap_html if p],
                   logger=log, workdir=REPORT_DIR, bulk_name='zap_reports')
    for p in parts:
        try:
            drv.delete(p['id'])
        except Exception:
            pass
    try:
        drv.delete(run_folder)
    except Exception:
        pass
    shred_paths(REPORT_DIR, WORK)
    return overall


def main():
    WORK.mkdir(parents=True, exist_ok=True)
    try:
        if MODE == 'shard':
            if not (SRC_GH_TOKEN and SRC_GH_OWNER):
                raise RuntimeError('SRC_GH_TOKEN / SRC_GH_OWNER missing.')
            mode_shard()
            code = 0
        elif MODE == 'zap':
            mode_zap()
            code = 0
        elif MODE == 'aggregate':
            code = 1 if mode_aggregate() == 'CRITICAL' else 0
        else:
            raise RuntimeError(f'Unknown CQ_MODE {MODE}')
    except Exception as exc:
        log.log(f'FATAL: {redact(str(exc))}')
        if MODE == 'aggregate':
            REPORT_DIR.mkdir(parents=True, exist_ok=True)
            lp = write_log(log, REPORT_DIR / 'run_log.txt')
            deliver_report('❌ Code Testing Server: aggregation failed', 'See attached log.', [lp], logger=log,
                           workdir=REPORT_DIR)
        else:
            try:
                drv, _, run_folder = staging()
                name = f'shard_{SHARD_INDEX:02d}.json' if MODE == 'shard' else 'zap.json'
                drv.write_json(run_folder, name, {'shard': SHARD_INDEX, 'results': [], 'log': log.lines})
            except Exception:
                pass
        code = 1
    shred_paths(WORK)
    sys.exit(code)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
