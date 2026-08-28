#!/usr/bin/env python3
"""
====================================================================
  VISIBILITY-WAECHTER (mit Whitelist)
--------------------------------------------------------------------
  Prueft alle 15 Minuten, ob eines deiner Quell-Repos (SRC_GH_OWNER)
  versehentlich von "private" auf "public" gestellt wurde, und
  schlaegt SOFORT Alarm im Google Chat - unabhaengig von der
  normalen Backup-Zusammenfassung, damit es nicht untergeht.

  NEU: Repos in der Whitelist duerfen oeffentlich sein und loesen
  keinen Alarm aus. Sind keine unerwartet oeffentlichen Repos da,
  wird eine kurze Entwarnung in den Google Chat geschickt.

  Nutzt dieselben Secrets/Variablen wie backup.yml (SRC_GH_TOKEN,
  SRC_GH_OWNER, SRC_GH_OWNER_TYPE, GOOGLE_CHAT_WEBHOOK) - es muessen
  KEINE neuen Secrets angelegt werden.

  Optional: ueber die Umgebungsvariable PUBLIC_REPO_WHITELIST kann
  die Liste erweitert werden (Komma- oder Zeilen-getrennt).
====================================================================
"""

import sys
from pathlib import Path

from common import env, Redactor, SummaryLogger, list_github_repos, send_google_chat

SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")
GOOGLE_CHAT_WEBHOOK = env("GOOGLE_CHAT_WEBHOOK", required=True)

# --------------------------------------------------------------------
# Whitelist: diese Repos DUERFEN oeffentlich sein -> kein Alarm.
# Vergleich ist case-insensitive (Gross-/Kleinschreibung egal).
# --------------------------------------------------------------------
DEFAULT_PUBLIC_WHITELIST = [
    "General_Linkspreed",
    "linkspreed",
    "log",
    "LS-W4-Mini-RF_Addiction_Impact",
    "minor_things",
    "Oxygen",
    "smm",
    "Web4-Community-AI-Prompt-Lab",
    "Web4-Community-Name-Generator-AI",
    "Web4-Communitys-Audience-Architect",
    "Web4-Lite",
    "Web4-Lite-SchemaGuard",
    "Web4-Role-Tailor",
    "Web4-Rules-Generator-AI",
    "Web4-Structura",
    "Web4-Web2App",
]


def build_whitelist():
    """Standard-Whitelist + optionale Eintraege aus PUBLIC_REPO_WHITELIST."""
    names = list(DEFAULT_PUBLIC_WHITELIST)
    extra = env("PUBLIC_REPO_WHITELIST", default="") or ""
    for part in extra.replace("\n", ",").split(","):
        part = part.strip()
        if part:
            names.append(part)
    return {n.lower() for n in names}


WHITELIST = build_whitelist()

redact = Redactor([SRC_GH_TOKEN])
log = SummaryLogger(redact)


def main():
    log.log("Visibility-Check gestartet.")
    log.log(f"Whitelist enthaelt {len(WHITELIST)} Repo(s).")

    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception as e:  # noqa: BLE001
        log.log(f"!! FEHLER beim Abrufen der Repo-Liste: {e}")
        print("Visibility-Check: Fehler beim Abrufen der Repo-Liste.", flush=True)
        sys.exit(1)

    public_repos = [r["name"] for r in repos if r.get("private") is False]
    allowed = sorted([n for n in public_repos if n.lower() in WHITELIST], key=str.lower)
    unexpected = sorted([n for n in public_repos if n.lower() not in WHITELIST], key=str.lower)

    if allowed:
        log.log(f"{len(allowed)} oeffentliche(s) Repo(s) laut Whitelist erlaubt: {', '.join(allowed)}")

    if unexpected:
        msg = (
            "🚨 WARNUNG: Unerwartet oeffentlich sichtbare Repos gefunden!\n\n"
            + "\n".join(f"- {name}" for name in unexpected)
            + "\n\nBitte SOFORT in GitHub pruefen und ggf. auf 'private' zuruecksetzen."
        )
        log.log(f"{len(unexpected)} unerwartet oeffentliche(s) Repo(s): {', '.join(unexpected)}")
        send_google_chat(GOOGLE_CHAT_WEBHOOK, msg)
        print(
            f"Visibility-Check: {len(unexpected)} unerwartet oeffentliche(s) Repo(s) gefunden - Alarm gesendet.",
            flush=True,
        )
    else:
        msg = (
            "✅ Visibility-Check: keine unerwartet oeffentlichen Repos.\n"
            f"Geprueft: {len(repos)} Repo(s) | oeffentlich (erlaubt per Whitelist): {len(allowed)}"
        )
        log.log(f"Alles ok. Geprueft: {len(repos)} Repos, davon {len(allowed)} erlaubt oeffentlich.")
        send_google_chat(GOOGLE_CHAT_WEBHOOK, msg)
        print(
            f"Visibility-Check: OK - keine unerwartet oeffentlichen Repos ({len(repos)} geprueft).",
            flush=True,
        )

    Path("visibility_guard_summary.txt").write_text("\n".join(log.lines) + "\n", encoding="utf-8")


if __name__ == "__main__":
    main()
