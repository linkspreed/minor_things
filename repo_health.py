#!/usr/bin/env python3
"""
====================================================================
  REPO-GESUNDHEITS-SCORE
--------------------------------------------------------------------
  Woechentliche Uebersicht ueber alle Quell-Repos: fehlende Lizenz,
  fehlende Beschreibung, lange Inaktivitaet. Hilft, "vergessene"
  Projekte unter 156 Repos zu finden.

  Nutzt dieselben Secrets/Variablen wie backup.yml - es werden KEINE
  neuen Secrets benoetigt.
====================================================================
"""

import sys
from datetime import datetime, timezone
from pathlib import Path

from common import env, Redactor, SummaryLogger, list_github_repos, send_google_chat

SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")
GOOGLE_CHAT_WEBHOOK = env("GOOGLE_CHAT_WEBHOOK", required=True)

# Ab wie vielen Tagen ohne Push ein Repo als "inaktiv" gilt
INACTIVE_DAYS_THRESHOLD = int(env("INACTIVE_DAYS_THRESHOLD", default="365"))

redact = Redactor([SRC_GH_TOKEN])
log = SummaryLogger(redact)


def main():
    log.log("Repo-Gesundheits-Check gestartet.")
    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception as e:  # noqa: BLE001
        log.log(f"!! FEHLER beim Abrufen der Repo-Liste: {e}")
        sys.exit(1)

    now = datetime.now(timezone.utc)
    no_license, no_description, inactive = [], [], []

    for repo in repos:
        name = repo["name"]
        if not repo.get("license"):
            no_license.append(name)
        if not repo.get("description"):
            no_description.append(name)
        pushed_at = repo.get("pushed_at")
        if pushed_at:
            pushed_dt = datetime.strptime(pushed_at, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
            days_inactive = (now - pushed_dt).days
            if days_inactive >= INACTIVE_DAYS_THRESHOLD:
                inactive.append((name, days_inactive))

    inactive.sort(key=lambda x: -x[1])

    log.log(f"{len(repos)} Repos geprueft.")
    log.log(f"Ohne Lizenz: {len(no_license)} - {', '.join(no_license) if no_license else '-'}")
    log.log(f"Ohne Beschreibung: {len(no_description)} - {', '.join(no_description) if no_description else '-'}")
    log.log(f"Inaktiv (>= {INACTIVE_DAYS_THRESHOLD} Tage ohne Push): {len(inactive)}")

    lines = [f"📊 Woechentlicher Repo-Gesundheits-Report ({len(repos)} Repos)\n"]
    lines.append(f"Ohne Lizenz ({len(no_license)}): " + (", ".join(no_license) if no_license else "keine"))
    lines.append(f"Ohne Beschreibung ({len(no_description)}): " + (", ".join(no_description) if no_description else "keine"))
    if inactive:
        lines.append(f"\nAm laengsten inaktiv (>= {INACTIVE_DAYS_THRESHOLD} Tage):")
        for name, days in inactive[:15]:
            lines.append(f"- {name}: {days} Tage ohne Push")
        if len(inactive) > 15:
            lines.append(f"... und {len(inactive) - 15} weitere.")
    else:
        lines.append("\nKeine Repos ueber der Inaktivitaets-Schwelle.")

    send_google_chat(GOOGLE_CHAT_WEBHOOK, "\n".join(lines))
    Path("repo_health_summary.txt").write_text("\n".join(log.lines) + "\n", encoding="utf-8")
    print("Repo-Gesundheits-Check abgeschlossen.", flush=True)


if __name__ == "__main__":
    main()
