#!/usr/bin/env python3
"""
====================================================================
  LIZENZ-COMPLIANCE-CHECK
--------------------------------------------------------------------
  Nutzt den GitHub-SBOM-Endpoint (Software Bill of Materials), um pro
  Repo ALLE Abhaengigkeiten samt erkannter Lizenz abzufragen - ohne
  eigenes Aufloesen ueber PyPI/npm noetig. Meldet Treffer aus einer
  konfigurierbaren Verbotsliste (z.B. GPL-3.0, AGPL-3.0).

  Voraussetzung: "Dependency graph" muss fuer das jeweilige Repo
  aktiviert sein (bei oeffentlichen Repos automatisch aktiv, bei
  privaten ggf. einmalig in den Repo-Settings aktivieren).

  Nutzt dieselben Secrets/Variablen wie backup.yml, zusaetzlich die
  neue Variable DISALLOWED_LICENSES (kommagetrennt).
====================================================================
"""

import sys
from pathlib import Path

from common import env, Redactor, SummaryLogger, list_github_repos, http_get, send_google_chat

SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")
GOOGLE_CHAT_WEBHOOK = env("GOOGLE_CHAT_WEBHOOK", required=True)

DISALLOWED_LICENSES = {
    lic.strip().upper() for lic in env("DISALLOWED_LICENSES", default="GPL-3.0,AGPL-3.0").split(",") if lic.strip()
}

redact = Redactor([SRC_GH_TOKEN])
log = SummaryLogger(redact)

HEADERS = {"Authorization": f"token {SRC_GH_TOKEN}", "Accept": "application/vnd.github+json"}


def get_sbom(owner: str, repo: str):
    url = f"https://api.github.com/repos/{owner}/{repo}/dependency-graph/sbom"
    r = http_get(url, headers=HEADERS, timeout=60, description=f"SBOM abrufen ({repo})", logger=log)
    if r.status_code == 404:
        return None  # Dependency Graph nicht aktiviert oder keine Abhaengigkeiten
    r.raise_for_status()
    return r.json()


def find_disallowed(sbom: dict) -> list:
    hits = []
    packages = (sbom or {}).get("sbom", {}).get("packages", [])
    for pkg in packages:
        license_concluded = (pkg.get("licenseConcluded") or "").upper()
        license_declared = (pkg.get("licenseDeclared") or "").upper()
        combined = f"{license_concluded} {license_declared}"
        for disallowed in DISALLOWED_LICENSES:
            if disallowed in combined:
                hits.append((pkg.get("name", "unbekannt"), license_concluded or license_declared))
                break
    return hits


def main():
    log.log(f"Lizenz-Check gestartet. Verbotsliste: {', '.join(sorted(DISALLOWED_LICENSES))}")
    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception as e:  # noqa: BLE001
        log.log(f"!! FEHLER beim Abrufen der Repo-Liste: {e}")
        sys.exit(1)

    findings = {}
    no_sbom = []

    for repo in repos:
        name = repo["name"]
        owner = repo["owner"]["login"]
        try:
            sbom = get_sbom(owner, name)
            if sbom is None:
                no_sbom.append(name)
                continue
            hits = find_disallowed(sbom)
            if hits:
                findings[name] = hits
                log.log(f"{name}: {len(hits)} problematische Lizenz(en) gefunden: {hits}")
        except Exception as e:  # noqa: BLE001
            log.log(f"!! FEHLER bei {name}: {e}")

    lines = [f"⚖️ Lizenz-Compliance-Report ({len(repos)} Repos geprueft)\n"]
    if findings:
        lines.append(f"Repos mit verbotenen Lizenzen ({len(findings)}):")
        for name, hits in findings.items():
            hit_str = ", ".join(f"{pkg} ({lic})" for pkg, lic in hits[:5])
            lines.append(f"  - {name}: {hit_str}")
    else:
        lines.append("Keine verbotenen Lizenzen gefunden.")
    if no_sbom:
        lines.append(f"\nOhne SBOM/Dependency-Graph ({len(no_sbom)}): " + ", ".join(no_sbom[:20]))

    send_google_chat(GOOGLE_CHAT_WEBHOOK, "\n".join(lines))
    Path("license_check_summary.txt").write_text("\n".join(log.lines) + "\n", encoding="utf-8")
    print(f"Lizenz-Check abgeschlossen. {len(findings)} Repo(s) mit Treffern.", flush=True)
    sys.exit(1 if findings else 0)


if __name__ == "__main__":
    main()
