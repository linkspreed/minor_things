#!/usr/bin/env python3
"""
====================================================================
  BACKUP-INTEGRITAETSPRUEFUNG
--------------------------------------------------------------------
  Vergleicht taeglich (zeitversetzt nach dem Backup-Lauf) fuer jedes
  Quell-Repo die Branch-/Tag-Hashes von:

    - Quelle (SRC_GH_OWNER)
    - Ziel 1: zweiter GitHub-Account (BACKUP_GH_OWNER)
    - Ziel 2: GitLab-Account #1 (GITLAB_NAMESPACE)

  gegeneinander (per `git ls-remote`, KEIN vollstaendiges Klonen -
  bleibt dadurch schnell auch bei 156 Repos). Stimmen die Hashes
  nicht ueberein, war der Push vermutlich unvollstaendig oder
  fehlgeschlagen, ohne dass es im Backup-Lauf selbst aufgefallen ist.

  Nutzt dieselben Secrets/Variablen wie backup.yml - es werden KEINE
  neuen Secrets benoetigt.
====================================================================
"""

import subprocess
import sys
from pathlib import Path

from common import (
    env, Redactor, SummaryLogger, list_github_repos, sanitize_gitlab_path,
    send_google_chat, with_retry,
)

SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")

BACKUP_GH_TOKEN = env("BACKUP_GH_TOKEN")
BACKUP_GH_OWNER = env("BACKUP_GH_OWNER")

GITLAB_TOKEN = env("GITLAB_TOKEN")
GITLAB_NAMESPACE = env("GITLAB_NAMESPACE")
GITLAB_URL = env("GITLAB_URL", default="https://gitlab.com")

GOOGLE_CHAT_WEBHOOK = env("GOOGLE_CHAT_WEBHOOK", required=True)

redact = Redactor([SRC_GH_TOKEN, BACKUP_GH_TOKEN, GITLAB_TOKEN])
log = SummaryLogger(redact)


def ls_remote_refs(url: str, description: str) -> dict:
    """Gibt {ref_name: sha} zurueck fuer refs/heads/* und refs/tags/* eines Remotes."""
    def _attempt():
        result = subprocess.run(
            ["git", "ls-remote", "--heads", "--tags", url],
            check=True, capture_output=True, text=True, timeout=120,
        )
        return result.stdout
    output = with_retry(_attempt, description, logger=log)
    refs = {}
    for line in output.splitlines():
        if not line.strip():
            continue
        sha, ref = line.split("\t")
        refs[ref] = sha
    return refs


def compare(source_refs: dict, target_refs: dict, label: str) -> list:
    """Gibt eine Liste von Abweichungen zurueck (leer = alles ok)."""
    problems = []
    for ref, sha in source_refs.items():
        if ref not in target_refs:
            problems.append(f"{ref} fehlt in {label}")
        elif target_refs[ref] != sha:
            problems.append(f"{ref} weicht in {label} ab (Quelle {sha[:8]} != Ziel {target_refs[ref][:8]})")
    return problems


def main():
    log.log("Backup-Integritaetspruefung gestartet.")

    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception as e:  # noqa: BLE001
        log.log(f"!! FEHLER beim Abrufen der Quell-Repos: {e}")
        sys.exit(1)

    total_problems = {}

    for repo in repos:
        name = repo["name"]
        log.log(f"--- {name} ---")
        try:
            source_url = repo["clone_url"].replace("https://", f"https://{SRC_GH_TOKEN}@")
            source_refs = ls_remote_refs(source_url, f"ls-remote Quelle ({name})")
        except Exception as e:  # noqa: BLE001
            log.log(f"  !! FEHLER beim Abfragen der Quelle: {e}")
            continue

        repo_problems = []

        if BACKUP_GH_TOKEN and BACKUP_GH_OWNER:
            try:
                target_url = f"https://{BACKUP_GH_TOKEN}@github.com/{BACKUP_GH_OWNER}/{name}.git"
                target_refs = ls_remote_refs(target_url, f"ls-remote GitHub-Backup ({name})")
                repo_problems += compare(source_refs, target_refs, "GitHub-Backup-Account")
            except Exception as e:  # noqa: BLE001
                repo_problems.append(f"GitHub-Backup nicht erreichbar: {e}")

        if GITLAB_TOKEN and GITLAB_NAMESPACE:
            try:
                safe_path = sanitize_gitlab_path(name)
                gitlab_host = GITLAB_URL.replace("https://", "")
                target_url = f"https://oauth2:{GITLAB_TOKEN}@{gitlab_host}/{GITLAB_NAMESPACE}/{safe_path}.git"
                target_refs = ls_remote_refs(target_url, f"ls-remote GitLab-#1 ({name})")
                repo_problems += compare(source_refs, target_refs, "GitLab-Account-#1")
            except Exception as e:  # noqa: BLE001
                repo_problems.append(f"GitLab-Account-#1 nicht erreichbar: {e}")

        if repo_problems:
            total_problems[name] = repo_problems
            for p in repo_problems:
                log.log(f"  !! {p}")
        else:
            log.log("  OK - Backups sind vollstaendig synchron.")

    if total_problems:
        lines = [f"⚠️ Backup-Integritaetspruefung: {len(total_problems)} Repo(s) mit Abweichungen\n"]
        for name, problems in total_problems.items():
            lines.append(f"- {name}: " + "; ".join(problems))
        send_google_chat(GOOGLE_CHAT_WEBHOOK, "\n".join(lines))
        print(f"Integritaetspruefung: {len(total_problems)} Repo(s) mit Abweichungen - Meldung gesendet.", flush=True)
    else:
        log.log(f"Alle {len(repos)} Repos sind auf allen geprueften Zielen synchron.")
        print(f"Integritaetspruefung: alle {len(repos)} Repos synchron. OK.", flush=True)

    Path("backup_integrity_summary.txt").write_text("\n".join(log.lines) + "\n", encoding="utf-8")
    sys.exit(1 if total_problems else 0)


if __name__ == "__main__":
    main()
