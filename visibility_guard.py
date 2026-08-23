#!/usr/bin/env python3
"""
====================================================================
  VISIBILITY-WAECHTER
--------------------------------------------------------------------
  Prueft alle 15 Minuten, ob eines deiner Quell-Repos (SRC_GH_OWNER)
  versehentlich von "private" auf "public" gestellt wurde, und
  schlaegt SOFORT Alarm im Google Chat - unabhaengig von der
  normalen Backup-Zusammenfassung, damit es nicht untergeht.

  Nutzt dieselben Secrets/Variablen wie backup.yml (SRC_GH_TOKEN,
  SRC_GH_OWNER, SRC_GH_OWNER_TYPE, GOOGLE_CHAT_WEBHOOK) - es muessen
  KEINE neuen Secrets angelegt werden.
====================================================================
"""

import sys
from pathlib import Path

from common import env, Redactor, SummaryLogger, list_github_repos, send_google_chat

SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")
GOOGLE_CHAT_WEBHOOK = env("GOOGLE_CHAT_WEBHOOK", required=True)

redact = Redactor([SRC_GH_TOKEN])
log = SummaryLogger(redact)


def main():
    log.log("Visibility-Check gestartet.")
    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception as e:  # noqa: BLE001
        log.log(f"!! FEHLER beim Abrufen der Repo-Liste: {e}")
        print("Visibility-Check: Fehler beim Abrufen der Repo-Liste.", flush=True)
        sys.exit(1)

    public_repos = [r["name"] for r in repos if r.get("private") is False]

    if public_repos:
        msg = (
            "🚨 WARNUNG: Oeffentlich sichtbare Repos gefunden!\n\n"
            + "\n".join(f"- {name}" for name in public_repos)
            + "\n\nBitte SOFORT in GitHub pruefen und ggf. auf 'private' zuruecksetzen."
        )
        log.log(f"{len(public_repos)} oeffentliche(s) Repo(s) gefunden: {', '.join(public_repos)}")
        send_google_chat(GOOGLE_CHAT_WEBHOOK, msg)
        print(f"Visibility-Check: {len(public_repos)} oeffentliche(s) Repo(s) gefunden - Alarm gesendet.", flush=True)
    else:
        log.log(f"Alle {len(repos)} Repos sind private. Alles ok.")
        print(f"Visibility-Check: alle {len(repos)} Repos sind private. OK.", flush=True)

    Path("visibility_guard_summary.txt").write_text("\n".join(log.lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
