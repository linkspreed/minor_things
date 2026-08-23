#!/usr/bin/env python3
"""
====================================================================
  DEPENDENCY-UPDATER (Dependabot-Rollout)
--------------------------------------------------------------------
  Legt einmalig pro Repo eine Standard-".github/dependabot.yml" an,
  falls noch keine existiert - damit GitHub selbst automatisch
  Update-Pull-Requests fuer veraltete Abhaengigkeiten erstellt. Dieses
  Skript programmiert KEINE Updates selbst, sondern rollt nur die
  Konfiguration aus (einmalig pro Repo, danach idempotent - ein
  bereits vorhandenes dependabot.yml wird nicht angefasst).

  Erkennung der Paket-Oekosysteme ueber vorhandene Marker-Dateien im
  Wurzelverzeichnis (z.B. requirements.txt -> pip, package.json ->
  npm). Kann leicht um weitere Marker ergaenzt werden.

  Nutzt dieselben Secrets/Variablen wie backup.yml - es werden KEINE
  neuen Secrets benoetigt (SRC_GH_TOKEN braucht Contents:Write, was
  ein normaler Personal Access Token mit "repo"-Scope bereits hat).
====================================================================
"""

import base64
import sys
from pathlib import Path

from common import env, Redactor, SummaryLogger, list_github_repos, http_get, http_put, send_google_chat

SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")
GOOGLE_CHAT_WEBHOOK = env("GOOGLE_CHAT_WEBHOOK", required=True)

redact = Redactor([SRC_GH_TOKEN])
log = SummaryLogger(redact)

HEADERS = {"Authorization": f"token {SRC_GH_TOKEN}", "Accept": "application/vnd.github+json"}

ECOSYSTEM_MARKERS = {
    "requirements.txt": "pip",
    "package.json": "npm",
    "pom.xml": "maven",
    "go.mod": "gomod",
    "Gemfile": "bundler",
}


def file_exists(owner: str, repo: str, path: str) -> bool:
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/{path}"
    r = http_get(url, headers=HEADERS, timeout=30,
                 description=f"Datei pruefen ({repo}/{path})", logger=log)
    return r.status_code == 200


def detect_ecosystems(owner: str, repo: str) -> list:
    found = []
    for marker, ecosystem in ECOSYSTEM_MARKERS.items():
        if file_exists(owner, repo, marker):
            found.append(ecosystem)
    return found


def create_dependabot_config(owner: str, repo: str, ecosystems: list):
    content = "version: 2\nupdates:\n"
    for eco in ecosystems:
        content += f'  - package-ecosystem: "{eco}"\n    directory: "/"\n    schedule:\n      interval: "weekly"\n'
    encoded = base64.b64encode(content.encode("utf-8")).decode("ascii")
    url = f"https://api.github.com/repos/{owner}/{repo}/contents/.github/dependabot.yml"
    body = {
        "message": "Add automated dependabot.yml (via zentrale Dependency-Updater-Action)",
        "content": encoded,
    }
    r = http_put(url, headers=HEADERS, json_body=body, timeout=30,
                 description=f"dependabot.yml anlegen ({repo})", logger=log)
    if r.status_code not in (200, 201):
        raise RuntimeError(f"Anlegen fehlgeschlagen: {r.status_code} {r.text[:200]}")


def main():
    log.log("Dependency-Updater-Rollout gestartet.")
    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception as e:  # noqa: BLE001
        log.log(f"!! FEHLER beim Abrufen der Repo-Liste: {e}")
        sys.exit(1)

    created, skipped_no_marker, already_present, failed = [], [], [], []

    for repo in repos:
        name = repo["name"]
        owner = repo["owner"]["login"]
        try:
            if file_exists(owner, name, ".github/dependabot.yml"):
                already_present.append(name)
                continue

            ecosystems = detect_ecosystems(owner, name)
            if not ecosystems:
                skipped_no_marker.append(name)
                continue

            create_dependabot_config(owner, name, ecosystems)
            created.append((name, ecosystems))
            log.log(f"{name}: dependabot.yml angelegt fuer {ecosystems}")
        except Exception as e:  # noqa: BLE001
            failed.append(name)
            log.log(f"!! FEHLER bei {name}: {e}")

    lines = [f"⚙️ Dependency-Updater-Rollout ({len(repos)} Repos geprueft)\n"]
    lines.append(f"Neu angelegt: {len(created)}")
    for name, eco in created:
        lines.append(f"  - {name} ({', '.join(eco)})")
    lines.append(f"Bereits vorhanden: {len(already_present)}")
    lines.append(f"Kein bekanntes Oekosystem erkannt: {len(skipped_no_marker)}")
    if skipped_no_marker:
        lines.append("  " + ", ".join(skipped_no_marker))
    if failed:
        lines.append(f"Fehlgeschlagen: {len(failed)} - " + ", ".join(failed))

    send_google_chat(GOOGLE_CHAT_WEBHOOK, "\n".join(lines))
    Path("dependency_updater_summary.txt").write_text("\n".join(log.lines) + "\n", encoding="utf-8")
    print(f"Dependency-Updater: {len(created)} neu, {len(already_present)} vorhanden, {len(failed)} Fehler.", flush=True)
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
