#!/usr/bin/env python3
import argparse
import hashlib
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
import requests

def env(name, required=False, default=None):
    val = os.environ.get(name, default)
    if required and not val:
        sys.exit(1)
    return val

SRC_GH_TOKEN = env('SRC_GH_TOKEN') or env('GITHUB_TOKEN')
SRC_GH_OWNER = env('SRC_GH_OWNER')
SRC_GH_OWNER_TYPE = env('SRC_GH_OWNER_TYPE', default='user')
GDRIVE_SA_JSON = env('GDRIVE_SA_JSON')
GDRIVE_FOLDER_ID = env('GDRIVE_FOLDER_ID')
GDRIVE_OBSERVATORY_FOLDER_NAME = env('GDRIVE_OBSERVATORY_FOLDER_NAME', default='GitHub Repository Branch Observatory')
CONFIG_FILE = env('BRANCH_OBSERVATORY_CONFIG', default='branch_observatory_config.yml')
STATE_FILE = Path(env('BRANCH_OBSERVATORY_STATE', default='branch_observatory_state.json'))
SUMMARY_FILE = Path(env('EMAIL_SUMMARY_FILE', default='branch_observatory_summary.txt'))
STALE_DAYS_THRESHOLD = int(env('STALE_DAYS', default='30'))
VERY_STALE_DAYS_THRESHOLD = int(env('VERY_STALE_DAYS', default='90'))
MAX_RETRIES = int(env('MAX_RETRIES', default='3'))
RETRY_BASE_DELAY = float(env('RETRY_BASE_DELAY', default='3.0'))

_SECRET_LIST = [s for s in [SRC_GH_TOKEN, GDRIVE_SA_JSON] if s]

def redact(text: str) -> str:
    text_str = str(text)
    for s in _SECRET_LIST:
        if s and s in text_str:
            text_str = text_str.replace(s, '***REDACTED***')
    return text_str

class Redactor:
    def __init__(self, secrets=None):
        self.secrets = [s for s in (secrets or _SECRET_LIST) if s]

    def __call__(self, text: str) -> str:
        text_str = str(text)
        for s in self.secrets:
            if s and s in text_str:
                text_str = text_str.replace(s, '***REDACTED***')
        return text_str

class SummaryLogger:
    def __init__(self, redactor: Redactor):
        self.lines = []
        self.redact = redactor

    def log(self, msg: str):
        ts = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')
        self.lines.append(f'[{ts}] {self.redact(str(msg))}')

    def write(self, path: Path, header: str = ''):
        path.write_text(header + '\n'.join(self.lines) + '\n', encoding='utf-8')

log = SummaryLogger(Redactor())

def sanitize_commit_message(msg: str) -> str:
    if not msg:
        return ''
    cleaned = str(msg)
    cleaned = re.sub(r'ghp_[a-zA-Z0-9]{36}', '[REDACTED_TOKEN]', cleaned)
    cleaned = re.sub(r'gho_[a-zA-Z0-9]{36}', '[REDACTED_TOKEN]', cleaned)
    cleaned = re.sub(r'glpat-[a-zA-Z0-9\-]{20,}', '[REDACTED_TOKEN]', cleaned)
    cleaned = re.sub(r'Bearer\s+[a-zA-Z0-9\._\-]+', 'Bearer [REDACTED]', cleaned, flags=re.IGNORECASE)
    cleaned = re.sub(r'-----BEGIN\s+[A-Z\s]+PRIVATE\s+KEY-----[\s\S]*?-----END\s+[A-Z\s]+PRIVATE\s+KEY-----', '[REDACTED_PRIVATE_KEY]', cleaned)
    cleaned = re.sub(r'([a-zA-Z0-9_]+://)[^:]+:[^@]+@', r'\1[REDACTED_CREDS]@', cleaned)
    cleaned = re.sub(r'(api_key|apikey|secret|password|token|auth)=[^&\s]+', r'\1=[REDACTED]', cleaned, flags=re.IGNORECASE)
    return cleaned.strip()

def sanitize_author_name(name: str) -> str:
    if not name:
        return 'Unknown'
    cleaned = str(name)
    cleaned = re.sub(r'[\w\.-]+@[\w\.-]+\.\w+', '[REDACTED_EMAIL]', cleaned)
    return cleaned

def with_retry(func, description: str, max_retries: int = MAX_RETRIES, base_delay: float = RETRY_BASE_DELAY):
    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            return func()
        except Exception as e:
            last_error = e
            if attempt < max_retries:
                delay = base_delay * attempt
                log.log(f"Versuch {attempt}/{max_retries} failed for '{description}': {e} - retry in {delay:.0f}s")
                time.sleep(delay)
            else:
                log.log(f"Failed after {max_retries} attempts for '{description}': {e}")
    raise last_error

def _check_rate_limit(response):
    remaining = response.headers.get('X-RateLimit-Remaining')
    if remaining is not None and int(remaining) < 10:
        reset_time = response.headers.get('X-RateLimit-Reset')
        if reset_time:
            wait_time = max(1.0, float(reset_time) - time.time() + 1.0)
            if wait_time < 120:
                log.log(f"Rate limit low ({remaining} remaining), pausing for {wait_time:.0f}s")
                time.sleep(wait_time)

def http_gh_request(method, url, token, params=None, json_body=None):
    headers = {
        'Accept': 'application/vnd.github+json',
        'User-Agent': 'Branch-Observatory'
    }
    if token:
        headers['Authorization'] = f'token {token}'

    def _call():
        r = requests.request(method, url, headers=headers, params=params, json=json_body, timeout=30)
        _check_rate_limit(r)
        if r.status_code in (408, 409, 425, 429) or r.status_code >= 500:
            raise RuntimeError(f"HTTP {r.status_code}: {r.text[:200]}")
        if r.status_code == 403:
            body_text = r.text.lower()
            if 'secondary rate limit' in body_text or 'abuse detection' in body_text:
                raise RuntimeError(f"Secondary rate limit HTTP 403: {r.text[:200]}")
        return r

    return with_retry(_call, f"{method} {url}")

def list_all_github_repos(token, owner=None, owner_type='user'):
    repos = []
    if owner and owner_type == 'org':
        url = f'https://api.github.com/orgs/{owner}/repos'
        params = {'per_page': 100, 'type': 'all'}
    else:
        url = 'https://api.github.com/user/repos'
        params = {'per_page': 100, 'affiliation': 'owner,collaborator,organization_member'}

    while url:
        r = http_gh_request('GET', url, token, params=params)
        if r.status_code != 200:
            break
        repos.extend(r.json())
        params = None
        url = None
        link_header = r.headers.get('Link', '')
        for part in link_header.split(','):
            if 'rel="next"' in part:
                match = re.search(r'<(.*?)>', part)
                if match:
                    url = match.group(1)
                break
    return repos

def get_repo_branches(token, owner, repo_name):
    branches = []
    url = f'https://api.github.com/repos/{owner}/{repo_name}/branches'
    params = {'per_page': 100}
    while url:
        r = http_gh_request('GET', url, token, params=params)
        if r.status_code != 200:
            break
        branches.extend(r.json())
        params = None
        url = None
        link_header = r.headers.get('Link', '')
        for part in link_header.split(','):
            if 'rel="next"' in part:
                match = re.search(r'<(.*?)>', part)
                if match:
                    url = match.group(1)
                break
    return branches

def get_repo_pull_requests(token, owner, repo_name, state='all'):
    prs = []
    url = f'https://api.github.com/repos/{owner}/{repo_name}/pulls'
    params = {'per_page': 100, 'state': state}
    while url:
        r = http_gh_request('GET', url, token, params=params)
        if r.status_code != 200:
            break
        prs.extend(r.json())
        params = None
        url = None
        link_header = r.headers.get('Link', '')
        for part in link_header.split(','):
            if 'rel="next"' in part:
                match = re.search(r'<(.*?)>', part)
                if match:
                    url = match.group(1)
                break
    return prs

def compare_refs(token, owner, repo_name, base, head):
    url = f'https://api.github.com/repos/{owner}/{repo_name}/compare/{base}...{head}'
    r = http_gh_request('GET', url, token)
    if r.status_code == 200:
        return r.json()
    return None

def get_branch_protection(token, owner, repo_name, branch_name):
    url = f'https://api.github.com/repos/{owner}/{repo_name}/branches/{branch_name}/protection'
    r = http_gh_request('GET', url, token)
    if r.status_code == 200:
        return True, r.json()
    return False, None

def load_config(config_path):
    if not os.path.exists(config_path):
        return {}
    try:
        import yaml
        with open(config_path, 'r', encoding='utf-8') as f:
            return yaml.safe_load(f) or {}
    except Exception:
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            return {}

def load_state(state_path: Path) -> dict:
    if not state_path.exists():
        return {}
    try:
        return json.loads(state_path.read_text(encoding='utf-8'))
    except Exception:
        return {}

def save_state(state_path: Path, state_data: dict):
    try:
        state_path.write_text(json.dumps(state_data, indent=2), encoding='utf-8')
    except Exception as e:
        log.log(f"Failed to save state file: {e}")

def get_google_services(sa_json_str):
    from google.oauth2 import service_account
    from googleapiclient.discovery import build
    info = json.loads(sa_json_str)
    creds = service_account.Credentials.from_service_account_info(
        info,
        scopes=[
            'https://www.googleapis.com/auth/drive',
            'https://www.googleapis.com/auth/documents'
        ]
    )
    drive_service = build('drive', 'v3', credentials=creds)
    docs_service = build('docs', 'v1', credentials=creds)
    return drive_service, docs_service

def resolve_or_create_drive_folder(drive_service, folder_id, folder_name, dry_run=False):
    if folder_id:
        try:
            res = with_retry(
                lambda: drive_service.files().get(fileId=folder_id, supportsAllDrives=True, fields='id, name, trashed').execute(),
                'Verify configured folder ID'
            )
            if res and not res.get('trashed'):
                return res['id']
        except Exception as e:
            log.log(f"Configured GDRIVE_FOLDER_ID invalid or inaccessible ({e}), falling back to search by name")

    query = f"mimeType = 'application/vnd.google-apps.folder' and name = '{folder_name}' and trashed = false"
    res = with_retry(
        lambda: drive_service.files().list(
            q=query,
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
            pageSize=10,
            fields='files(id, name, createdTime)'
        ).execute(),
        f"Search for folder '{folder_name}'"
    )
    files = res.get('files', [])
    if files:
        files.sort(key=lambda x: x.get('createdTime', ''))
        return files[0]['id']

    if dry_run:
        log.log(f"[DRY RUN] Would create Google Drive folder '{folder_name}'")
        return 'dry-run-folder-id'

    body = {
        'name': folder_name,
        'mimeType': 'application/vnd.google-apps.folder'
    }
    folder = with_retry(
        lambda: drive_service.files().create(body=body, supportsAllDrives=True, fields='id').execute(),
        f"Create Google Drive folder '{folder_name}'"
    )
    return folder['id']

def find_document_by_repo_id(drive_service, repo_id: str):
    query = f"appProperties has {{ key='github_repo_id' and value='{repo_id}' }} and trashed = false"
    res = with_retry(
        lambda: drive_service.files().list(
            q=query,
            supportsAllDrives=True,
            includeItemsFromAllDrives=True,
            pageSize=10,
            fields='files(id, name, appProperties, parents)'
        ).execute(),
        f"Search document for repo ID '{repo_id}'"
    )
    files = res.get('files', [])
    if files:
        return files[0]
    return None

def create_google_doc_for_repo(drive_service, folder_id: str, repo_id: str, doc_name: str, report_hash: str = '', dry_run=False):
    if dry_run:
        log.log(f"[DRY RUN] Would create Google Doc '{doc_name}' with github_repo_id='{repo_id}' in folder '{folder_id}'")
        return f"dry-run-doc-id-{repo_id}"

    body = {
        'name': doc_name,
        'mimeType': 'application/vnd.google-apps.document',
        'parents': [folder_id],
        'appProperties': {
            'github_repo_id': str(repo_id),
            'last_report_hash': str(report_hash)
        }
    }
    doc_file = with_retry(
        lambda: drive_service.files().create(body=body, supportsAllDrives=True, fields='id, name, appProperties').execute(),
        f"Create Google Doc for repo ID {repo_id}"
    )
    return doc_file['id']

def update_google_doc_metadata(drive_service, doc_id: str, new_name: str = None, report_hash: str = None, dry_run=False):
    if dry_run:
        log.log(f"[DRY RUN] Would update Google Doc ID '{doc_id}' metadata (name={new_name}, hash={report_hash})")
        return
    body = {}
    if new_name:
        body['name'] = new_name
    if report_hash:
        body['appProperties'] = {'last_report_hash': report_hash}

    if body:
        with_retry(
            lambda: drive_service.files().update(fileId=doc_id, body=body, supportsAllDrives=True).execute(),
            f"Update document metadata for {doc_id}"
        )

def get_existing_doc_text_content(docs_service, doc_id: str):
    try:
        doc = with_retry(
            lambda: docs_service.documents().get(documentId=doc_id).execute(),
            f"Get document text content for {doc_id}"
        )
        body_content = doc.get('body', {}).get('content', [])
        text_parts = []
        for elem in body_content:
            p = elem.get('paragraph')
            if p:
                for pe in p.get('elements', []):
                    tr = pe.get('textRun')
                    if tr and tr.get('content'):
                        text_parts.append(tr.get('content'))
        return "".join(text_parts).strip(), doc
    except Exception as e:
        log.log(f"Failed to read existing doc content for {doc_id}: {e}")
        return None, None

def overwrite_google_doc_content(docs_service, doc_id: str, new_content: str, existing_doc_obj=None, dry_run=False):
    if dry_run:
        log.log(f"[DRY RUN] Would overwrite Google Doc ID '{doc_id}' content ({len(new_content)} chars)")
        return True

    doc = existing_doc_obj
    if not doc:
        doc = with_retry(
            lambda: docs_service.documents().get(documentId=doc_id).execute(),
            f"Get document {doc_id}"
        )

    body_content = doc.get('body', {}).get('content', [])
    end_index = 1
    if body_content:
        end_index = body_content[-1].get('endIndex', 1)

    requests_batch = []
    if end_index > 2:
        requests_batch.append({
            'deleteContentRange': {
                'range': {
                    'startIndex': 1,
                    'endIndex': end_index - 1
                }
            }
        })

    requests_batch.append({
        'insertText': {
            'location': {
                'index': 1
            },
            'text': new_content
        }
    })

    with_retry(
        lambda: docs_service.documents().batchUpdate(
            documentId=doc_id,
            body={'requests': requests_batch}
        ).execute(),
        f"Batch update document content for {doc_id}"
    )
    return True

def determine_parent_branch(token, owner, repo_name, branch_name, default_branch, all_branches, prs, config_overrides):
    branch_map = {b['name']: b for b in all_branches}
    if branch_name == default_branch:
        return {
            'parent': 'None (Default Branch)',
            'type': 'Recorded',
            'confidence': 'High',
            'reason': 'This branch is designated as the repository default branch.'
        }

    repo_key = f"{owner}/{repo_name}"
    if repo_key in config_overrides and 'branches' in config_overrides[repo_key]:
        branch_cfg = config_overrides[repo_key]['branches'].get(branch_name, {})
        if 'parent' in branch_cfg:
            p = branch_cfg['parent']
            return {
                'parent': p,
                'type': 'Configured',
                'confidence': 'High',
                'reason': f"Manually configured parent in repository configuration overrides."
            }

    for pr in prs:
        head_ref = pr.get('head', {}).get('ref')
        if head_ref == branch_name:
            base_ref = pr.get('base', {}).get('ref')
            if base_ref and base_ref in branch_map:
                pr_num = pr.get('number')
                return {
                    'parent': base_ref,
                    'type': 'Pull request based',
                    'confidence': 'High',
                    'reason': f"Declared base branch in Pull Request #{pr_num} ({pr.get('state', 'open')})."
                }

    candidate_bases = []
    if 'develop' in branch_map and branch_name != 'develop':
        candidate_bases.append('develop')
    if default_branch in branch_map and default_branch not in candidate_bases:
        candidate_bases.append(default_branch)
    for b in branch_map:
        if b.startswith('release/') and b not in candidate_bases and b != branch_name:
            candidate_bases.append(b)

    for base in candidate_bases:
        comp = compare_refs(token, owner, repo_name, base, branch_name)
        if comp:
            behind_by = comp.get('behind_by', 0)
            ahead_by = comp.get('ahead_by', 0)
            status = comp.get('status', '')
            mb_commit = comp.get('merge_base_commit', {}) or {}
            mb_sha = mb_commit.get('sha', '')
            base_head_sha = branch_map.get(base, {}).get('commit', {}).get('sha', '')

            if status in ('ahead', 'identical') or (ahead_by > 0 and behind_by == 0):
                return {
                    'parent': base,
                    'type': 'Inferred',
                    'confidence': 'High' if status == 'identical' or behind_by == 0 else 'Medium',
                    'reason': f"Merge-base analysis against '{base}' shows status '{status}' (ahead: {ahead_by}, behind: {behind_by})."
                }
            elif mb_sha and base_head_sha and mb_sha == base_head_sha:
                return {
                    'parent': base,
                    'type': 'Inferred',
                    'confidence': 'High',
                    'reason': f"Merge-base commit matches head of '{base}' (ahead: {ahead_by}, behind: {behind_by})."
                }
            elif mb_sha:
                return {
                    'parent': base,
                    'type': 'Inferred',
                    'confidence': 'Medium',
                    'reason': f"Shares merge-base with '{base}' (status: {status}, ahead: {ahead_by}, behind: {behind_by})."
                }

    if branch_name.startswith(('feature/', 'feat/', 'fix/', 'bugfix/')):
        if 'develop' in branch_map and branch_name != 'develop':
            return {
                'parent': 'develop',
                'type': 'Inferred',
                'confidence': 'Medium',
                'reason': f"Branch naming convention matches feature/fix pattern; 'develop' exists."
            }
        elif default_branch in branch_map:
            return {
                'parent': default_branch,
                'type': 'Inferred',
                'confidence': 'Low',
                'reason': f"Branch naming convention matches feature/fix pattern; falling back to default branch '{default_branch}'."
            }

    if branch_name.startswith(('hotfix/', 'release/')) and default_branch in branch_map:
        return {
            'parent': default_branch,
            'type': 'Inferred',
            'confidence': 'Medium',
            'reason': f"Branch naming convention matches release/hotfix pattern targeting default branch '{default_branch}'."
        }

    if default_branch in branch_map:
        comp = compare_refs(token, owner, repo_name, default_branch, branch_name)
        if comp and comp.get('merge_base_commit'):
            return {
                'parent': default_branch,
                'type': 'Inferred',
                'confidence': 'Low',
                'reason': f"Fallback candidate; shares merge-base commit with default branch '{default_branch}'."
            }

    return {
        'parent': 'Unknown',
        'type': 'Unknown',
        'confidence': 'Low',
        'reason': 'Insufficient evidence or disconnected history to determine parent branch.'
    }

def classify_activity(commit_dt_utc, now_dt_utc):
    if not commit_dt_utc:
        return 'Unknown'
    delta_days = (now_dt_utc - commit_dt_utc).days
    if delta_days <= STALE_DAYS_THRESHOLD:
        return 'Active'
    elif delta_days <= VERY_STALE_DAYS_THRESHOLD:
        return 'Stale'
    else:
        return 'Very Stale'

def build_topology_tree(branches_data, default_branch):
    parent_to_children = {}
    nodes = {b['name']: b for b in branches_data}

    for b in branches_data:
        p = b['parent_info']['parent']
        if p not in parent_to_children:
            parent_to_children[p] = []
        parent_to_children[p].append(b['name'])

    lines = []

    def _render_node(node_name, prefix='', is_last=True, visited=None):
        if visited is None:
            visited = set()
        if node_name in visited:
            return
        visited.add(node_name)

        b_info = nodes.get(node_name, {})
        rel_type = b_info.get('parent_info', {}).get('type', '')
        rel_tag = f" ({rel_type})" if rel_type and rel_type not in ('Recorded', '') else ""

        connector = "└── " if is_last else "├── "
        if prefix == '':
            lines.append(f"{node_name}{rel_tag}")
        else:
            lines.append(f"{prefix}{connector}{node_name}{rel_tag}")

        children = parent_to_children.get(node_name, [])
        children_count = len(children)
        new_prefix = prefix + ("    " if is_last else "│   ") if prefix != '' else ""

        for idx, child in enumerate(children):
            child_is_last = (idx == children_count - 1)
            _render_node(child, new_prefix, child_is_last, visited)

    if default_branch in nodes:
        _render_node(default_branch)
    elif branches_data:
        _render_node(branches_data[0]['name'])

    rendered_nodes = set()
    for line in lines:
        cleaned_name = line.split(' ')[-1].split('(')[0].strip()
        cleaned_name = re.sub(r'^[├└]──\s*', '', cleaned_name)
        if cleaned_name in nodes:
            rendered_nodes.add(cleaned_name)

    unconnected = [b['name'] for b in branches_data if b['name'] not in rendered_nodes]
    if unconnected:
        lines.append("")
        lines.append("Unconnected / Unknown Parent Branches:")
        for u in unconnected:
            b_info = nodes.get(u, {})
            rel_type = b_info.get('parent_info', {}).get('type', 'Unknown')
            lines.append(f"├── {u} ({rel_type})")

    return "\n".join(lines)

def build_repository_report(repo, branches_data, open_prs_count, run_url, now_dt_utc):
    repo_id = str(repo['id'])
    repo_name = repo['name']
    full_name = repo['full_name']
    desc = repo.get('description') or 'No description provided.'
    visibility = 'Private' if repo.get('private') else 'Public'
    default_branch = repo.get('default_branch') or 'main'
    is_archived = repo.get('archived', False)
    repo_url = repo.get('html_url') or f"https://github.com/{full_name}"
    gen_time_str = now_dt_utc.strftime('%Y-%m-%d %H:%M:%S UTC')

    total_branches = len(branches_data)
    active_branches = sum(1 for b in branches_data if b['activity'] == 'Active')
    stale_branches = sum(1 for b in branches_data if b['activity'] == 'Stale')
    very_stale_branches = sum(1 for b in branches_data if b['activity'] == 'Very Stale')
    protected_branches = sum(1 for b in branches_data if b['protected'])

    report = []
    report.append("================================================================================")
    report.append(f"BRANCH TOPOLOGY REPORT: {full_name}")
    report.append("================================================================================")
    report.append("")
    report.append("--- METADATA ---")
    report.append(f"GitHub Repository ID: {repo_id}")
    report.append(f"Report Generated UTC: {gen_time_str}")
    report.append(f"Workflow Run URL: {run_url or 'N/A'}")
    report.append(f"Generator Version: 1.0.0")
    report.append(f"Report Schema Version: 1.0")
    report.append("")

    report.append("--- REPOSITORY SUMMARY ---")
    report.append(f"Repository Name: {repo_name}")
    report.append(f"Full Name: {full_name}")
    report.append(f"Description: {desc}")
    report.append(f"Visibility: {visibility}")
    report.append(f"Default Branch: {default_branch}")
    report.append(f"Archived: {'Yes' if is_archived else 'No'}")
    report.append(f"Repository URL: {repo_url}")
    report.append(f"Total Branches: {total_branches}")
    report.append(f"Active Branches (<= {STALE_DAYS_THRESHOLD}d): {active_branches}")
    report.append(f"Stale Branches ({STALE_DAYS_THRESHOLD}d-{VERY_STALE_DAYS_THRESHOLD}d): {stale_branches}")
    report.append(f"Very Stale Branches (>{VERY_STALE_DAYS_THRESHOLD}d): {very_stale_branches}")
    report.append(f"Protected Branches: {protected_branches}")
    report.append(f"Open Pull Requests: {open_prs_count}")
    report.append("")

    report.append("--- BRANCH OVERVIEW ---")
    if not branches_data:
        report.append("No branches found.")
    else:
        for b in branches_data:
            default_tag = " [DEFAULT]" if b['is_default'] else ""
            prot_tag = " [PROTECTED]" if b['protected'] else ""
            report.append(f"• {b['name']}{default_tag}{prot_tag}")
            report.append(f"  SHA: {b['sha_short']} | Date: {b['commit_date_str']} | Author: {b['author']}")
            report.append(f"  Parent: {b['parent_info']['parent']} ({b['parent_info']['type']}) | Status: {b['activity']}")
            report.append(f"  Message: {b['commit_message']}")
            report.append(f"  Branch Link: {b['branch_url']}")
            report.append(f"  Commit Link: {b['commit_url']}")
            report.append("")

    report.append("--- BRANCH TOPOLOGY TREE ---")
    tree_text = build_topology_tree(branches_data, default_branch)
    report.append(tree_text)
    report.append("")

    report.append("--- BRANCH DETAILS ---")
    for b in branches_data:
        p_info = b['parent_info']
        report.append(f"Branch: {b['name']}")
        report.append(f"Parent branch: {p_info['parent']}")
        report.append(f"Parent relationship: {p_info['type']}")
        report.append(f"Confidence: {p_info['confidence']}")
        report.append(f"Parent Determination Reason: {p_info['reason']}")
        report.append(f"Latest commit: {b['sha_short']}")
        report.append(f"Latest activity: {b['commit_date_str']}")
        report.append(f"Ahead of default ({default_branch}): {b['ahead_by']} commits")
        report.append(f"Behind default ({default_branch}): {b['behind_by']} commits")
        report.append(f"Protected: {'Yes' if b['protected'] else 'No'}")
        report.append(f"Merged: {'Yes' if b['merged'] else 'No'}")
        report.append(f"Status: {b['activity']}")
        report.append("--------------------------------------------------------------------------------")

    report.append("")
    report.append("--- WARNINGS AND OBSERVATIONS ---")
    warnings = []
    if is_archived:
        warnings.append("• Repository is archived and read-only.")

    for b in branches_data:
        if b['activity'] == 'Very Stale':
            warnings.append(f"• Branch '{b['name']}' has not been updated in over {VERY_STALE_DAYS_THRESHOLD} days.")
        elif b['activity'] == 'Stale':
            warnings.append(f"• Branch '{b['name']}' has not been updated in over {STALE_DAYS_THRESHOLD} days.")

        if b['behind_by'] > 50:
            warnings.append(f"• Branch '{b['name']}' is significantly behind default branch '{default_branch}' ({b['behind_by']} commits behind).")

        if b['merged'] and not b['is_default']:
            warnings.append(f"• Branch '{b['name']}' appears fully merged into default branch but still exists.")

        if b['parent_info']['parent'] == 'Unknown':
            warnings.append(f"• Parent branch for '{b['name']}' could not be definitively determined.")

    if not warnings:
        warnings.append("No specific warnings or risk observations for this repository.")

    for w in warnings:
        report.append(w)

    report.append("")
    report.append("================================================================================")
    return "\n".join(report)

def process_single_repository(repo, token, drive_service, docs_service, folder_id, config_overrides, state_data, run_url, dry_run=False):
    repo_id = str(repo['id'])
    repo_name = repo['name']
    full_name = repo['full_name']
    owner = repo.get('owner', {}).get('login', SRC_GH_OWNER)
    default_branch = repo.get('default_branch') or 'main'

    log.log(f"Processing repository '{full_name}' (ID: {repo_id})...")
    now_dt_utc = datetime.now(timezone.utc)

    raw_branches = get_repo_branches(token, owner, repo_name)
    open_prs = get_repo_pull_requests(token, owner, repo_name, state='open')
    all_prs = get_repo_pull_requests(token, owner, repo_name, state='all')

    branches_data = []
    for b in raw_branches:
        b_name = b['name']
        commit_obj = b.get('commit', {})
        sha = commit_obj.get('sha', '')
        sha_short = sha[:7] if sha else 'unknown'

        commit_dt_utc = None
        commit_date_str = 'Unknown'
        author_name = 'Unknown'
        commit_msg = ''

        if sha:
            commit_detail = http_gh_request('GET', f"https://api.github.com/repos/{owner}/{repo_name}/commits/{sha}", token)
            if commit_detail.status_code == 200:
                c_json = commit_detail.json()
                c_info = c_json.get('commit', {})
                committer_info = c_info.get('committer', {}) or c_info.get('author', {})
                date_raw = committer_info.get('date')
                if date_raw:
                    try:
                        commit_dt_utc = datetime.strptime(date_raw, '%Y-%m-%dT%H:%M:%SZ').replace(tzinfo=timezone.utc)
                        commit_date_str = commit_dt_utc.strftime('%Y-%m-%d %H:%M UTC')
                    except Exception:
                        commit_date_str = str(date_raw)

                author_raw = c_info.get('author', {}).get('name') or committer_info.get('name') or 'Unknown'
                author_name = sanitize_author_name(author_raw)
                commit_msg = sanitize_commit_message(c_info.get('message', ''))

        is_protected = b.get('protected', False)
        if not is_protected:
            has_prot, _ = get_branch_protection(token, owner, repo_name, b_name)
            is_protected = has_prot

        is_default = (b_name == default_branch)
        ahead_by, behind_by = 0, 0
        merged = False

        if not is_default:
            comp = compare_refs(token, owner, repo_name, default_branch, b_name)
            if comp:
                ahead_by = comp.get('ahead_by', 0)
                behind_by = comp.get('behind_by', 0)
                if ahead_by == 0:
                    merged = True

        parent_info = determine_parent_branch(token, owner, repo_name, b_name, default_branch, raw_branches, all_prs, config_overrides)
        activity = classify_activity(commit_dt_utc, now_dt_utc)

        branch_url = f"https://github.com/{full_name}/tree/{b_name}"
        commit_url = f"https://github.com/{full_name}/commit/{sha}" if sha else repo.get('html_url', '')

        branches_data.append({
            'name': b_name,
            'sha': sha,
            'sha_short': sha_short,
            'commit_dt_utc': commit_dt_utc,
            'commit_date_str': commit_date_str,
            'author': author_name,
            'commit_message': commit_msg,
            'protected': is_protected,
            'is_default': is_default,
            'ahead_by': ahead_by,
            'behind_by': behind_by,
            'merged': merged,
            'parent_info': parent_info,
            'activity': activity,
            'branch_url': branch_url,
            'commit_url': commit_url
        })

    branches_data.sort(
        key=lambda x: (x['commit_dt_utc'] if x['commit_dt_utc'] else datetime.min.replace(tzinfo=timezone.utc)),
        reverse=True
    )

    report_content = build_repository_report(repo, branches_data, len(open_prs), run_url, now_dt_utc)
    report_hash = hashlib.sha256(report_content.encode('utf-8')).hexdigest()

    doc_title = f"{full_name} - Branch Topology Report"
    doc_info = None

    if drive_service:
        doc_info = find_document_by_repo_id(drive_service, repo_id)

    doc_id = None
    existing_hash = None
    if doc_info:
        doc_id = doc_info['id']
        app_props = doc_info.get('appProperties', {}) or {}
        existing_hash = app_props.get('last_report_hash')
        existing_title = doc_info.get('name', '')
        if existing_title != doc_title:
            log.log(f"Repository renamed detected ({existing_title} -> {doc_title}). Updating title...")
            update_google_doc_metadata(drive_service, doc_id, new_name=doc_title, dry_run=dry_run)
    else:
        log.log(f"No existing Google Doc found for repo ID {repo_id}. Creating new document...")
        doc_id = create_google_doc_for_repo(drive_service, folder_id, repo_id, doc_title, report_hash=report_hash, dry_run=dry_run)

    state_last_hash = state_data.get(repo_id, {}).get('last_report_hash')
    if (existing_hash == report_hash or state_last_hash == report_hash) and not dry_run:
        log.log(f"Report content unchanged for '{full_name}' (hash: {report_hash[:8]}). Skipping document update.")
        return True, "No change required"

    existing_doc_obj = None
    if docs_service and not dry_run:
        existing_text, existing_doc_obj = get_existing_doc_text_content(docs_service, doc_id)
        if existing_text:
            existing_text_hash = hashlib.sha256(existing_text.encode('utf-8')).hexdigest()
            if existing_text_hash == report_hash:
                log.log(f"Existing document body content is identical for '{full_name}'. Skipping update.")
                if drive_service and existing_hash != report_hash:
                    update_google_doc_metadata(drive_service, doc_id, report_hash=report_hash, dry_run=dry_run)
                return True, "No change required"

    if docs_service:
        overwrite_google_doc_content(docs_service, doc_id, report_content, existing_doc_obj=existing_doc_obj, dry_run=dry_run)
        if drive_service and not dry_run:
            update_google_doc_metadata(drive_service, doc_id, report_hash=report_hash, dry_run=dry_run)

    state_data[repo_id] = {
        'repo_id': repo_id,
        'full_name': full_name,
        'doc_id': doc_id,
        'folder_id': folder_id,
        'last_updated_utc': now_dt_utc.isoformat(),
        'last_report_hash': report_hash
    }

    log.log(f"Successfully processed report for '{full_name}' (Doc ID: {doc_id}).")
    return True, "Updated successfully"

def main():
    parser = argparse.ArgumentParser(description='Branch Observatory Engine')
    parser.add_argument('--dry-run', action='store_true', help='Run without creating or modifying Google Drive resources')
    args = parser.parse_args()

    dry_run_mode = args.dry_run or env('DRY_RUN', default='false').lower() == 'true'

    log.log("===== Branch Observatory Started =====")
    if dry_run_mode:
        log.log("Running in DRY RUN mode. No external changes will be performed.")

    if not SRC_GH_TOKEN:
        log.log("CRITICAL ERROR: Neither SRC_GH_TOKEN nor GITHUB_TOKEN is configured.")
        sys.exit(1)

    drive_service, docs_service = None, None
    folder_id = None

    if GDRIVE_SA_JSON:
        try:
            drive_service, docs_service = get_google_services(GDRIVE_SA_JSON)
            folder_id = resolve_or_create_drive_folder(
                drive_service, GDRIVE_FOLDER_ID, GDRIVE_OBSERVATORY_FOLDER_NAME, dry_run=dry_run_mode
            )
            log.log(f"Target Google Drive Folder ID: {folder_id}")
        except Exception as e:
            log.log(f"CRITICAL ERROR initializing Google Services: {e}")
            sys.exit(1)
    else:
        if not dry_run_mode:
            log.log("CRITICAL ERROR: GDRIVE_SA_JSON is required for normal operation.")
            sys.exit(1)
        log.log("WARNING: GDRIVE_SA_JSON missing; continuing in dry-run mode.")

    config_overrides = load_config(CONFIG_FILE)
    state_data = load_state(STATE_FILE)

    run_url = f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{os.environ.get('GITHUB_RUN_ID', '')}"

    try:
        repos = list_all_github_repos(SRC_GH_TOKEN, owner=SRC_GH_OWNER, owner_type=SRC_GH_OWNER_TYPE)
        log.log(f"Retrieved {len(repos)} accessible repositories from GitHub.")
    except Exception as e:
        log.log(f"CRITICAL ERROR retrieving repositories: {e}")
        sys.exit(1)

    success_count, fail_count, skip_count = 0, 0, 0
    failed_repos = []

    for repo in repos:
        try:
            ok, msg = process_single_repository(
                repo, SRC_GH_TOKEN, drive_service, docs_service,
                folder_id, config_overrides, state_data, run_url, dry_run=dry_run_mode
            )
            if ok:
                if msg == "No change required":
                    skip_count += 1
                else:
                    success_count += 1
            else:
                fail_count += 1
                failed_repos.append(repo.get('full_name', repo.get('name')))
        except Exception as e:
            fail_count += 1
            failed_repos.append(repo.get('full_name', repo.get('name')))
            log.log(f"ERROR processing repository '{repo.get('full_name')}': {e}")

    if not dry_run_mode:
        save_state(STATE_FILE, state_data)

    status_str = "OK" if fail_count == 0 else f"{fail_count} FAILED"
    summary_header = f"Branch Observatory Summary ({status_str})\nProcessed: {len(repos)} | Updated: {success_count} | Unchanged: {skip_count} | Failed: {fail_count}\n"
    if failed_repos:
        summary_header += f"Failed Repositories: {', '.join(failed_repos)}\n"

    SUMMARY_FILE.write_text(summary_header + '\n'.join(log.lines) + '\n', encoding='utf-8')

    github_step_summary = os.environ.get('GITHUB_STEP_SUMMARY')
    if github_step_summary:
        try:
            with open(github_step_summary, 'a', encoding='utf-8') as f:
                f.write(summary_header + '\n')
        except Exception:
            pass

    log.log(f"===== Branch Observatory Completed ({status_str}) =====")

    if fail_count > 0:
        sys.exit(1)

if __name__ == '__main__':
    main()
