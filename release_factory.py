#!/usr/bin/env python3
"""Release Factory: tag an (old) branch and publish a GitHub release with a ZIP package.

All parameters arrive in a sealed payload (see tools/seal_dispatch.py):
{
  "repo": "my-repo" | "owner/my-repo",          required
  "branch": "release/1.4",                      required
  "tag": "v1.4.0",                              required
  "commit": "<sha>",                            optional, tag this commit instead of the branch head
  "name": "Version 1.4.0",                      optional release title (default = tag)
  "notes": "text",                              optional release body (appended to generated notes)
  "generate_notes": true,                       optional (default true)
  "prerelease": false, "draft": false,          optional
  "make_latest": false,                         optional (default false - retroactive releases must not become "latest")
  "backdate": true,                             optional (default true - tag date = commit date)
  "reuse_existing_tag": true                    optional (default true - if tag already exists on the same commit)
}
"""
import json
import re
import sys
import time
from pathlib import Path

import requests

from common import env, Redactor, SummaryLogger
from sec_common import (HtmlReport, deliver_report, human_bytes, human_duration, open_payload, run_cmd,
                        sha256_file, shred_paths, ts_label, utc_now, write_log)

TOKEN = env('SRC_GH_TOKEN')
DEFAULT_OWNER = env('SRC_GH_OWNER')
DISPATCH_KEY = env('DISPATCH_KEY')
PAYLOAD = env('SEALED_PAYLOAD', default='')
MAX_AGE = int(env('PAYLOAD_MAX_AGE_SECONDS', default='3600'))
DRY_RUN = env('RF_DRY_RUN', default='false').lower() == 'true'
GIT_NAME = env('RELEASE_GIT_NAME') or 'Release Factory'
GIT_EMAIL = env('RELEASE_GIT_EMAIL') or 'release-factory@users.noreply.github.com'
WORK = Path(env('RF_WORKDIR', default='rf_work')).resolve()
REPORT_DIR = Path(env('REPORT_DIR', default='rf_reports')).resolve()
API = 'https://api.github.com'
redact = Redactor([TOKEN, DISPATCH_KEY])
log = SummaryLogger(redact)
START = time.monotonic()
H = {'Authorization': f'Bearer {TOKEN}', 'Accept': 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28'}
SAFE_REF = re.compile(r'^[A-Za-z0-9][A-Za-z0-9._/+-]{0,199}$')


def step(steps, name, status, detail=''):
    steps.append([status, name, redact(str(detail))[:500], f'{time.monotonic() - START:.0f}s'])
    log.log(f'{status} {name}: {redact(str(detail))[:300]}')


def git(args, cwd=None, timeout=900, env_extra=None):
    rc, out, err = run_cmd(['git'] + args, cwd=cwd, timeout=timeout, env_extra=env_extra)
    if rc != 0:
        raise RuntimeError(f'git {args[0]} failed: {redact(err.strip())[-400:]}')
    return out.strip()


def validate_ref(value: str, label: str) -> str:
    value = (value or '').strip()
    if not value or not SAFE_REF.match(value) or '..' in value or value.endswith(('.lock', '/', '.')) or '@{' in value:
        raise RuntimeError(f'Invalid {label}: must be a normal git ref name.')
    rc, _, _ = run_cmd(['git', 'check-ref-format', f'refs/tags/{value}' if label == 'tag' else f'refs/heads/{value}'])
    if rc != 0:
        raise RuntimeError(f'Invalid {label} (rejected by git check-ref-format).')
    return value


def api(method, url, **kw):
    for attempt in range(1, 5):
        r = requests.request(method, url, headers={**H, **kw.pop('headers', {})}, timeout=kw.pop('timeout', 60), **kw)
        if r.status_code in (502, 503, 504) or (r.status_code == 403 and 'rate limit' in r.text.lower()):
            time.sleep(5 * attempt)
            continue
        return r
    return r


def main():
    steps, fatal, release_url, asset_info, info = [], None, '', {}, {}
    WORK.mkdir(parents=True, exist_ok=True)
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    try:
        p = open_payload(PAYLOAD, DISPATCH_KEY, MAX_AGE)
        if not p:
            raise RuntimeError('No sealed payload supplied.')
        repo = (p.get('repo') or '').strip()
        full = repo if '/' in repo else f'{DEFAULT_OWNER}/{repo}'
        if not re.match(r'^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$', full):
            raise RuntimeError('Invalid repository name.')
        branch = validate_ref(p.get('branch'), 'branch')
        tag = validate_ref(p.get('tag'), 'tag')
        commit = (p.get('commit') or '').strip()
        if commit and not re.match(r'^[0-9a-f]{7,40}$', commit):
            raise RuntimeError('Invalid commit SHA.')
        backdate = p.get('backdate', True)
        make_latest = 'true' if p.get('make_latest') else 'false'
        info = {'Repository': full, 'Branch': branch, 'Tag': tag, 'Commit (requested)': commit or 'branch head',
                'Dry run': DRY_RUN, 'Make latest': make_latest, 'Backdate tag': backdate}
        step(steps, 'Payload decrypted and validated', 'OK')

        r = api('GET', f'{API}/repos/{full}')
        if r.status_code != 200:
            raise RuntimeError(f'Repository not accessible with SRC_GH_TOKEN (HTTP {r.status_code}).')
        meta = r.json()
        if not (meta.get('permissions') or {}).get('push'):
            raise RuntimeError('SRC_GH_TOKEN has no write (push) permission on this repository.')
        repo_name = meta['name']
        step(steps, 'Repository access verified', 'OK', f"default branch {meta.get('default_branch')}")

        url = f'https://x-access-token:{TOKEN}@github.com/{full}.git'
        src = WORK / 'src'
        git(['clone', '--quiet', '--no-tags', '--single-branch', '--branch', branch, '--depth', '200', url, str(src)])
        if commit:
            try:
                git(['cat-file', '-e', f'{commit}^{{commit}}'], cwd=src)
            except RuntimeError:
                git(['fetch', '--quiet', '--depth', '1', 'origin', commit], cwd=src)
            git(['checkout', '--quiet', '--detach', commit], cwd=src)
        target = git(['rev-parse', 'HEAD'], cwd=src)
        commit_date = git(['log', '-1', '--format=%cI', 'HEAD'], cwd=src)
        subject = git(['log', '-1', '--format=%s', 'HEAD'], cwd=src)
        info.update({'Commit tagged': target, 'Commit date': commit_date, 'Commit subject': subject[:120]})
        step(steps, 'Cloned and switched to branch', 'OK', f'{target[:12]} ({commit_date})')

        remote = git(['ls-remote', '--tags', 'origin', f'refs/tags/{tag}', f'refs/tags/{tag}^{{}}'], cwd=src)
        existing = {}
        for line in remote.splitlines():
            sha, ref = line.split('\t')
            existing[ref] = sha
        peeled = existing.get(f'refs/tags/{tag}^{{}}') or existing.get(f'refs/tags/{tag}')
        tag_created = False
        if peeled:
            if peeled != target:
                raise RuntimeError(f'Tag already exists on a different commit ({peeled[:12]}). Nothing was changed.')
            if not p.get('reuse_existing_tag', True):
                raise RuntimeError('Tag already exists and reuse_existing_tag is false.')
            git(['fetch', '--quiet', 'origin', f'refs/tags/{tag}:refs/tags/{tag}'], cwd=src)
            step(steps, 'Tag already exists on the same commit - reused', 'OK')
        else:
            git(['config', 'user.name', GIT_NAME], cwd=src)
            git(['config', 'user.email', GIT_EMAIL], cwd=src)
            env_extra = {'GIT_COMMITTER_DATE': commit_date} if backdate else None
            git(['tag', '-a', tag, '-m', p.get('name') or f'Release {tag}'], cwd=src, env_extra=env_extra)
            tag_created = True
            step(steps, 'Annotated tag created', 'OK', 'backdated to commit date' if backdate else 'dated now')

        zip_path = WORK / f'{repo_name}-{tag.replace("/", "-")}.zip'
        git(['archive', '--format=zip', f'--prefix={repo_name}-{tag.replace("/", "-")}/', '-o', str(zip_path), tag],
            cwd=src)
        digest = sha256_file(zip_path)
        sum_path = WORK / f'{zip_path.name}.sha256'
        sum_path.write_text(f'{digest}  {zip_path.name}\n', encoding='utf-8')
        asset_info = {'name': zip_path.name, 'size': zip_path.stat().st_size, 'sha256': digest}
        step(steps, 'Release ZIP built (git archive)', 'OK', f'{human_bytes(asset_info["size"])}, sha256 {digest[:16]}...')

        if DRY_RUN:
            step(steps, 'Dry run - push and release skipped', 'SKIPPED')
        else:
            if tag_created:
                git(['push', '--quiet', 'origin', f'refs/tags/{tag}'], cwd=src)
                step(steps, 'Tag pushed', 'OK')
            r = api('GET', f'{API}/repos/{full}/releases/tags/{tag}')
            if r.status_code == 200:
                rel = r.json()
                step(steps, 'Existing release for this tag found - updating assets', 'OK')
            else:
                body = {'tag_name': tag, 'name': p.get('name') or tag, 'body': p.get('notes') or '',
                        'draft': bool(p.get('draft')), 'prerelease': bool(p.get('prerelease')),
                        'generate_release_notes': bool(p.get('generate_notes', True)), 'make_latest': make_latest}
                r = api('POST', f'{API}/repos/{full}/releases', json=body)
                if r.status_code != 201:
                    raise RuntimeError(f'Release creation failed (HTTP {r.status_code}): {r.text[:300]}')
                rel = r.json()
                step(steps, 'GitHub release created', 'OK', f"draft={rel.get('draft')} prerelease={rel.get('prerelease')}")
            release_url = rel.get('html_url', '')
            for asset in rel.get('assets', []):
                if asset['name'] in (zip_path.name, sum_path.name):
                    api('DELETE', f"{API}/repos/{full}/releases/assets/{asset['id']}")
            upload_base = rel['upload_url'].split('{')[0]
            for path, ctype in ((zip_path, 'application/zip'), (sum_path, 'text/plain')):
                with open(path, 'rb') as fh:
                    r = api('POST', upload_base, params={'name': path.name}, data=fh,
                            headers={'Content-Type': ctype}, timeout=600)
                if r.status_code != 201:
                    raise RuntimeError(f'Asset upload failed for {path.name} (HTTP {r.status_code}).')
            step(steps, 'Assets uploaded (ZIP + SHA-256)', 'OK')
    except Exception as exc:
        fatal = redact(str(exc))
        step(steps, 'Aborted', 'FAIL', fatal)
    finally:
        shred_paths(WORK)

    ok = fatal is None
    rep = HtmlReport('Release Factory Report', f'{ts_label()} | Duration {human_duration(time.monotonic() - START)}')
    rep.kpis({'Status': 'OK' if ok else 'FAIL', 'Tag': info.get('Tag', '-'), 'Repository': info.get('Repository', '-'),
              'Dry run': 'yes' if DRY_RUN else 'no'})
    if release_url:
        rep.table('Release', ['Item', 'Value'], [['Release page', rep.link(release_url)]], raw_cols=(1,))
    rep.table('Parameters & result', ['Field', 'Value'], [[k, v] for k, v in info.items()])
    if asset_info:
        rep.table('Release package', ['File', 'Size', 'SHA-256'], [[asset_info['name'], human_bytes(asset_info['size']),
                                                                    asset_info['sha256']]])
    rep.table('Steps', ['Status', 'Step', 'Detail', 'Elapsed'], steps, badge_cols=(0,))
    rep.text('Notes', ['The release is created with make_latest=false unless requested, so retroactive releases do not '
                       'replace the current "latest" release.',
                       'Pushing a tag can trigger tag-based workflows in the target repository.'])
    html_path = rep.write(REPORT_DIR / f'release_factory_{utc_now().strftime("%Y%m%d_%H%M%S")}.html')
    log_path = write_log(log, REPORT_DIR / 'run_log.txt')
    subj = f"{'✅' if ok else '❌'} Release Factory: {info.get('Repository', '?')} {info.get('Tag', '')} " \
           f"{'OK' if ok else 'FAILED'}{' (dry run)' if DRY_RUN else ''}"
    body = f'{subj}\n\nRelease: {release_url or "n/a"}\n' + (f'Error: {fatal}\n' if fatal else '') + \
           '\nFull report attached.'
    deliver_report(subj, body, [html_path, log_path], logger=log, workdir=REPORT_DIR)
    shred_paths(REPORT_DIR)
    sys.exit(0 if ok else 1)


if __name__ == '__main__':
    try:
        main()
    except Exception:
        sys.exit(1)
