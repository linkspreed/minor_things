#!/usr/bin/env python3
"""
====================================================================
  GEMEINSAME HILFSFUNKTIONEN fuer die zentralen Actions
--------------------------------------------------------------------
  Wird von den NEUEN Skripten importiert:
    visibility_guard.py, backup_integrity.py, repo_health.py,
    dependency_updater.py, size_guard.py, license_check.py,
    cross_repo_index.py, changelog_aggregator.py

  WICHTIG: backup_repos.py, secret_scan.py und dependency_cve_alarm.py
  wurden NICHT angefasst und haben weiterhin ihren eigenen,
  unabhaengigen Code - dieses Modul aendert nichts an deren Verhalten.
  Es wird von den bestehenden Skripten auch NICHT importiert.
====================================================================
"""

import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests


# ====================================================================
#  CONFIG-HELFER
# ====================================================================

def env(name, required=False, default=None):
    val = os.environ.get(name, default)
    if required and not val:
        print("FEHLER: Pflicht-Konfiguration fehlt (Name absichtlich nicht angezeigt).")
        sys.exit(1)
    return val


# ====================================================================
#  REDACTING + LOGGING (gleiches Prinzip wie im Backup-Skript:
#  Konsole bleibt anonym/leer, Details nur in Summary-Datei / Chat)
# ====================================================================

class Redactor:
    """Ersetzt alle bekannten Geheimnisse in Log-Texten durch ***REDACTED***."""

    def __init__(self, secrets):
        self.secrets = [s for s in secrets if s]

    def __call__(self, text: str) -> str:
        text = str(text)
        for s in self.secrets:
            if s and s in text:
                text = text.replace(s, "***REDACTED***")
        return text


class SummaryLogger:
    """Sammelt Zeilen mit UTC-Zeitstempel und redacted dabei automatisch alle Geheimnisse."""

    def __init__(self, redactor: Redactor):
        self.lines = []
        self.redact = redactor

    def log(self, msg: str):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
        self.lines.append(f"[{ts}] {self.redact(str(msg))}")

    def write(self, path: Path, header: str = ""):
        path.write_text(header + "\n".join(self.lines) + "\n", encoding="utf-8")


# ====================================================================
#  RETRY-HELFER (identisches Verhalten wie in backup_repos.py)
# ====================================================================

def with_retry(func, description: str, max_retries: int = 3, base_delay: float = 3.0, logger: SummaryLogger = None):
    last_error = None
    for attempt in range(1, max_retries + 1):
        try:
            return func()
        except Exception as e:  # noqa: BLE001
            last_error = e
            if attempt < max_retries:
                delay = base_delay * attempt
                if logger:
                    logger.log(f"     (Versuch {attempt}/{max_retries} fehlgeschlagen bei '{description}': {e} "
                                f"- neuer Versuch in {delay:.0f}s)")
                time.sleep(delay)
            else:
                if logger:
                    logger.log(f"     (Endgueltig fehlgeschlagen nach {max_retries} Versuchen bei '{description}': {e})")
    raise last_error


def http_get(url, headers=None, params=None, timeout=30, description=None,
             max_retries=3, base_delay=3.0, logger=None):
    def _attempt():
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code >= 500:
            raise RuntimeError(f"Serverfehler HTTP {r.status_code} bei {url}")
        return r
    return with_retry(_attempt, description or f"GET {url}", max_retries, base_delay, logger)


def http_post(url, headers=None, json_body=None, timeout=30, description=None,
              max_retries=3, base_delay=3.0, logger=None):
    def _attempt():
        r = requests.post(url, headers=headers, json=json_body, timeout=timeout)
        if r.status_code >= 500:
            raise RuntimeError(f"Serverfehler HTTP {r.status_code} bei {url}")
        return r
    return with_retry(_attempt, description or f"POST {url}", max_retries, base_delay, logger)


def http_put(url, headers=None, json_body=None, timeout=30, description=None,
             max_retries=3, base_delay=3.0, logger=None):
    def _attempt():
        r = requests.put(url, headers=headers, json=json_body, timeout=timeout)
        if r.status_code >= 500:
            raise RuntimeError(f"Serverfehler HTTP {r.status_code} bei {url}")
        return r
    return with_retry(_attempt, description or f"PUT {url}", max_retries, base_delay, logger)


# ====================================================================
#  GITHUB: Repo-Liste (generisch, fuer beliebigen Token/Owner)
# ====================================================================

def list_github_repos(token, owner, owner_type="user", logger=None):
    """
    Listet ALLE Repos eines GitHub-Accounts auf. Gleiche Logik wie
    list_source_repos() in backup_repos.py, aber generisch nutzbar
    (z.B. auch fuer den Backup-Ziel-Account, falls jemals gebraucht).
    """
    repos = []
    page = 1
    base = (f"https://api.github.com/orgs/{owner}/repos"
            if owner_type == "org"
            else "https://api.github.com/user/repos")
    headers = {"Authorization": f"token {token}", "Accept": "application/vnd.github+json"}
    while True:
        params = {"per_page": 100, "page": page}
        if owner_type != "org":
            params["affiliation"] = "owner"
        r = http_get(base, headers=headers, params=params, timeout=60,
                     description="GitHub-Repos auflisten", logger=logger)
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
    return repos


# ====================================================================
#  GITLAB: Pfad-Bereinigung
#  (bewusst hier dupliziert statt aus backup_repos.py importiert,
#  damit backup_repos.py komplett unangetastet bleibt und keine
#  Modul-Kopplung zwischen den Skripten entsteht)
# ====================================================================

def sanitize_gitlab_path(name: str) -> str:
    cleaned = re.sub(r"[^a-zA-Z0-9_.\-]", "-", name)
    cleaned = cleaned.strip("-_.")
    for suffix in (".git", ".atom"):
        if cleaned.lower().endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            cleaned = cleaned.strip("-_.")
    if not cleaned:
        cleaned = "repo"
    return cleaned


# ====================================================================
#  GOOGLE CHAT
# ====================================================================

def send_google_chat(webhook_url: str, text: str, max_len: int = 4000):
    """Schickt eine Textnachricht an einen Google-Chat-Webhook (gleiches Format wie backup.yml)."""
    if not webhook_url:
        return
    if len(text) > max_len:
        text = "...(gekuerzt)...\n" + text[-max_len:]
    try:
        requests.post(
            webhook_url, json={"text": text}, timeout=30,
            headers={"Content-Type": "application/json; charset=UTF-8"},
        )
    except Exception as e:  # noqa: BLE001
        print(f"Fehler beim Senden an Google Chat: {e}", flush=True)


def now_iso():
    return datetime.now(timezone.utc).isoformat()
