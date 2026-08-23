#!/usr/bin/env python3
"""
====================================================================
  CHANGELOG-/RELEASE-AGGREGATOR
--------------------------------------------------------------------
  Woechentliche Zusammenfassung: welche neuen Tags/Releases sind in
  den letzten 7 Tagen in deinen Repos entstanden. Guter Ueberblick
  ueber eigene Aktivitaet, ohne 156 einzelne GitHub-Benachrichtigungen
  durchsehen zu muessen.

  Nutzt dieselben Secrets/Variablen wie backup.yml - es werden KEINE
  neuen Secrets benoetigt.
====================================================================
"""

import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

from common import env, Redactor, SummaryLogger, list_github_repos, http_get, send_google_chat

SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")
GOOGLE_CHAT_WEBHOOK = env("GOOGLE_CHAT_WEBHOOK", required=True)

LOOKBACK_DAYS = int(env("CHANGELOG_LOOKBACK_DAYS", default="7"))

redact = Redactor([SRC_GH_TOKEN])
log = SummaryLogger(redact)

HEADERS = {"Authorization": f"token {SRC_GH_TOKEN}", "Accept": "application/vnd.github+json"}


def get_recent_releases(owner: str, repo: str, cutoff: datetime) -> list:
    url = f"https://api.github.com/repos/{owner}/{repo}/releases"
    r = http_get(url, headers=HEADERS, params={"per_page": 20}, timeout=30,
                 description=f"Releases abrufen ({repo})", logger=log)
    if r.status_code == 404:
        return []
    r.raise_for_status()
    recent = []
    for rel in r.json():
        published = rel.get("published_at")
        if not published:
            continue
        published_dt = datetime.strptime(published, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        if published_dt >= cutoff:
            recent.append(rel.get("tag_name", "unbekannt"))
    return recent


def main():
    log.log(f"Changelog-Aggregator gestartet (letzte {LOOKBACK_DAYS} Tage).")
    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception as e:  # noqa: BLE001
        log.log(f"!! FEHLER beim Abrufen der Repo-Liste: {e}")
        sys.exit(1)

    cutoff = datetime.now(timezone.utc) - timedelta(days=LOOKBACK_DAYS)
    activity = {}

    for repo in repos:
        name = repo["name"]
        owner = repo["owner"]["login"]
        try:
            recent = get_recent_releases(owner, name, cutoff)
            if recent:
                activity[name] = recent
                log.log(f"{name}: neue Releases {recent}")
        except Exception as e:  # noqa: BLE001
            log.log(f"!! FEHLER bei {name}: {e}")

    lines = [f"🗒️ Wochenrueckblick: neue Releases der letzten {LOOKBACK_DAYS} Tage\n"]
    if activity:
        total = sum(len(v) for v in activity.values())
        lines.append(f"{total} neue Release(s) in {len(activity)} Repo(s):")
        for name, tags in activity.items():
            lines.append(f"  - {name}: {', '.join(tags)}")
    else:
        lines.append("Keine neuen Releases in diesem Zeitraum.")

    send_google_chat(GOOGLE_CHAT_WEBHOOK, "\n".join(lines))
    Path("changelog_aggregator_summary.txt").write_text("\n".join(log.lines) + "\n", encoding="utf-8")
    print(f"Changelog-Aggregator abgeschlossen. {len(activity)} Repo(s) mit neuen Releases.", flush=True)


if __name__ == "__main__":
    main()
