#!/usr/bin/env python3
"""Local helper (run on YOUR machine, never in CI).

Seals sensitive workflow parameters with the DISPATCH_KEY so that the public workflow run
only shows an unreadable token. Optionally triggers the workflow directly via the GitHub API.

Setup once:
    pip install cryptography requests
    python tools/seal_dispatch.py --new-key          # prints a key -> store as secret DISPATCH_KEY
    # keep the same key locally in an environment variable:
    #   Windows:  setx DISPATCH_KEY "<key>"     Linux/macOS: export DISPATCH_KEY="<key>"

Examples:
    # Release Factory: print token only (paste it into the "payload" field in the Actions UI)
    python tools/seal_dispatch.py --json "{\"repo\":\"my-repo\",\"branch\":\"release/1.4\",\"tag\":\"v1.4.0\"}"

    # Release Factory: seal AND trigger (needs GH_DISPATCH_TOKEN + GH_DISPATCH_REPO env vars)
    python tools/seal_dispatch.py --workflow release-factory.yml --repo my-repo --branch release/1.4 --tag v1.4.0

    # Malware scan of a ZIP from a URL
    python tools/seal_dispatch.py --workflow malware-scan.yml --url https://example.com/thing.zip --store-if-clean

Tokens expire after PAYLOAD_MAX_AGE_SECONDS (default 1 hour) to prevent re-use of old tokens.
"""
import argparse
import base64
import json
import os
import sys
import time


def seal(data: dict, key_b64: str) -> str:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    key = base64.b64decode(key_b64.strip())
    if len(key) != 32:
        sys.exit('DISPATCH_KEY must be 32 bytes (base64).')
    body = dict(data, _ts=int(time.time()))
    nonce = os.urandom(12)
    ct = AESGCM(key).encrypt(nonce, json.dumps(body, separators=(',', ':')).encode('utf-8'), b'dispatch-v1')
    return base64.urlsafe_b64encode(nonce + ct).decode('ascii').rstrip('=')


def main():
    ap = argparse.ArgumentParser(description='Seal workflow parameters and optionally dispatch the workflow.')
    ap.add_argument('--new-key', action='store_true', help='Generate a new random DISPATCH_KEY and exit.')
    ap.add_argument('--json', help='Raw JSON payload.')
    ap.add_argument('--repo')
    ap.add_argument('--branch')
    ap.add_argument('--tag')
    ap.add_argument('--commit')
    ap.add_argument('--name')
    ap.add_argument('--notes')
    ap.add_argument('--prerelease', action='store_true')
    ap.add_argument('--draft', action='store_true')
    ap.add_argument('--make-latest', action='store_true')
    ap.add_argument('--no-backdate', action='store_true')
    ap.add_argument('--url', help='Malware scan: file/archive URL.')
    ap.add_argument('--sha256', help='Malware scan: expected SHA-256 of the download.')
    ap.add_argument('--store-if-clean', action='store_true', help='Malware scan: upload to clean folder if clean.')
    ap.add_argument('--workflow', help='Workflow file name to dispatch, e.g. release-factory.yml')
    ap.add_argument('--ref', default='main', help='Branch of the automation repo (default main).')
    ap.add_argument('--input', action='append', default=[], help='Extra plain input key=value (non-sensitive only).')
    a = ap.parse_args()

    if a.new_key:
        print(base64.b64encode(os.urandom(32)).decode())
        return
    key = os.environ.get('DISPATCH_KEY')
    if not key:
        sys.exit('Set the DISPATCH_KEY environment variable first.')

    if a.json:
        data = json.loads(a.json)
    else:
        data = {k: v for k, v in {
            'repo': a.repo, 'branch': a.branch, 'tag': a.tag, 'commit': a.commit, 'name': a.name, 'notes': a.notes,
            'url': a.url, 'sha256': a.sha256}.items() if v}
        if a.prerelease:
            data['prerelease'] = True
        if a.draft:
            data['draft'] = True
        if a.make_latest:
            data['make_latest'] = True
        if a.no_backdate:
            data['backdate'] = False
        if a.store_if_clean:
            data['store_if_clean'] = True
    token = seal(data, key)

    if not a.workflow:
        print(token)
        return
    import requests
    gh_token = os.environ.get('GH_DISPATCH_TOKEN')
    gh_repo = os.environ.get('GH_DISPATCH_REPO')  # owner/automation-repo
    if not (gh_token and gh_repo):
        sys.exit('Set GH_DISPATCH_TOKEN and GH_DISPATCH_REPO (owner/repo of the automation repository).')
    inputs = {'payload': token}
    for kv in a.input:
        k, v = kv.split('=', 1)
        inputs[k] = v
    r = requests.post(f'https://api.github.com/repos/{gh_repo}/actions/workflows/{a.workflow}/dispatches',
                      headers={'Authorization': f'Bearer {gh_token}', 'Accept': 'application/vnd.github+json'},
                      json={'ref': a.ref, 'inputs': inputs}, timeout=30)
    if r.status_code == 204:
        print('Workflow dispatched. The report will arrive by e-mail.')
    else:
        sys.exit(f'Dispatch failed: HTTP {r.status_code} {r.text[:300]}')


if __name__ == '__main__':
    main()
