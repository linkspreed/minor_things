#!/usr/bin/env python3
"""
====================================================================
  DEPENDENCY-/CVE-ALARM  (Public-Repo-Safe Version + Google Chat)
--------------------------------------------------------------------
  Fragt STUENDLICH fuer ALLE Repos eines GitHub-Accounts die offenen
  Dependabot-Alerts (bekannte Schwachstellen in Abhaengigkeiten) ab
  und schickt eine gebuendelte Zusammenfassung an einen privaten
  Google-Chat-Webhook.

  ---------------------------------------------------------------
  SICHERHEITS-DESIGN (identisch zum Repo-Super-Backup-Skript):
  ---------------------------------------------------------------
  - Dieses Skript darf in einem OEFFENTLICHEN GitHub-Repo liegen
    (unbegrenzte, kostenlose Actions-Minuten), OHNE dass aus den
    Actions-Logs ablesbar ist, welche Repos betroffen sind. Die
    Konsole zeigt nur "Repo 3/156" (anonymer Fortschritt).
  - Repo-Namen, betroffene Pakete, Schweregrade und Advisory-Links
    landen AUSSCHLIESSLICH in der Zusammenfassungs-Datei, die per
    Webhook an deinen PRIVATEN Google Chat geschickt wird - niemals
    in der oeffentlich einsehbaren Actions-Konsole.
  - Alle Tokens werden vor jeder Log-Ausgabe per redact() unkenntlich
    gemacht (Verteidigung gegen versehentliches Token-Leck in
    Fehlermeldungen).
  - Es werden KEINE Anmeldedaten/Tokens Dritter benoetigt - nur dein
    eigener GitHub-Token mit Lesezugriff auf Dependabot-Alerts.

  WICHTIG ZUM TOKEN: Ein klassischer Personal Access Token braucht
  den Scope "security_events" (zusaetzlich zu "repo" fuer private
  Repos), sonst liefert GitHub HTTP 403 fuer dieses Endpoint - siehe
  GitHub-REST-API-Doku zu Dependabot-Alerts. Ein feingranularer PAT
  braucht die Repository-Permission "Dependabot alerts: Read-only".

  BEWUSSTE ENTSCHEIDUNG: Der Job-Exit-Code (und damit das ✅/❌-Icon
  in Google Chat) spiegelt NUR wider, ob der Scan technisch fehlerfrei
  durchgelaufen ist - NICHT, ob Schwachstellen gefunden wurden. Der
  eigentliche Schweregrad (kritisch/hoch/mittel/niedrig/keine) wird
  separat als "SEVERITY_LEVEL"-Zeile in der Zusammenfassung mitgegeben
  und vom Google-Chat-Versand-Schritt in ein eigenes Icon uebersetzt.
====================================================================
"""

import json
import os
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import requests

# ====================================================================
#  CONFIG - alles kommt aus Umgebungsvariablen
# ====================================================================

def env(name, required=False, default=None):
    val = os.environ.get(name, default)
    if required and not val:
        print(f"FEHLER: Pflicht-Konfiguration fehlt (Name absichtlich nicht angezeigt).")
        sys.exit(1)
    return val

SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")

SUMMARY_FILE = Path(env("EMAIL_SUMMARY_FILE", default="email_summary.txt"))

QUIET_CONSOLE = env("QUIET_CONSOLE", default="true").lower() == "true"
MAX_RETRIES = int(env("MAX_RETRIES", default="3"))
RETRY_BASE_DELAY_SECONDS = float(env("RETRY_BASE_DELAY_SECONDS", default="3"))

# Wie viele Einzel-Findings maximal pro Repo im Detail-Protokoll stehen
# (Schutz gegen ausufernd lange Summary-Dateien bei sehr vielen Alerts)
MAX_DETAILS_PER_REPO = int(env("MAX_DETAILS_PER_REPO", default="10"))
# Wie viele Repos in der Kurzuebersicht ("Top-Repos") gelistet werden
MAX_TOP_REPOS = int(env("MAX_TOP_REPOS", default="15"))

_SECRETS = [s for s in [SRC_GH_TOKEN] if s]


def redact(text: str) -> str:
    for s in _SECRETS:
        if s and s in text:
            text = text.replace(s, "***REDACTED***")
    return text


# ====================================================================
#  LOGGING: Konsole = anonym/leer. Summary-Datei = vollstaendig.
# ====================================================================

SUMMARY_LINES = []
_repo_total = 0
_repo_index = 0


def summary_log(msg: str):
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    SUMMARY_LINES.append(f"[{ts}] {redact(str(msg))}")


def console_heartbeat(msg: str = None):
    if QUIET_CONSOLE:
        if msg:
            print(msg, flush=True)
        else:
            print(f"... Pruefe Repo {_repo_index}/{_repo_total} ...", flush=True)
    else:
        print(msg or f"Repo {_repo_index}/{_repo_total}", flush=True)


# ====================================================================
#  RETRY-HELFER
# ====================================================================

def with_retry(func, description: str):
    last_error = None
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            return func()
        except Exception as e:  # noqa: BLE001
            last_error = e
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY_SECONDS * attempt
                summary_log(f"     (Versuch {attempt}/{MAX_RETRIES} fehlgeschlagen bei '{description}': {e} "
                            f"- neuer Versuch in {delay:.0f}s)")
                time.sleep(delay)
            else:
                summary_log(f"     (Endgueltig fehlgeschlagen nach {MAX_RETRIES} Versuchen bei '{description}': {e})")
    raise last_error


def http_get(url, headers=None, params=None, timeout=30, description: str = None):
    def _attempt():
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code >= 500:
            raise RuntimeError(f"Serverfehler HTTP {r.status_code} bei {url}")
        return r

    return with_retry(_attempt, description or f"GET {url}")


# ====================================================================
#  1) QUELLE: Repo-Liste von GitHub holen
# ====================================================================

def list_source_repos():
    repos = []
    page = 1
    base = (f"https://api.github.com/orgs/{SRC_GH_OWNER}/repos"
            if SRC_GH_OWNER_TYPE == "org"
            else "https://api.github.com/user/repos")
    headers = {"Authorization": f"token {SRC_GH_TOKEN}", "Accept": "application/vnd.github+json"}
    while True:
        params = {"per_page": 100, "page": page}
        if SRC_GH_OWNER_TYPE != "org":
            params["affiliation"] = "owner"
        r = http_get(base, headers=headers, params=params, timeout=60, description="Quell-Repos auflisten")
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        repos.extend(batch)
        page += 1
    return repos


# ====================================================================
#  2) DEPENDABOT-ALERTS pro Repo abrufen
# ====================================================================

SEVERITY_ORDER = {"critical": 4, "high": 3, "medium": 2, "low": 1}
SEVERITY_ICON = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "⚪"}


def get_dependabot_alerts(name: str):
    """
    Gibt eine Liste offener Alerts zurueck, oder None, falls Dependabot-
    Alerts fuer dieses Repo (noch) nicht aktiviert sind (HTTP 404 - das
    ist KEIN Fehler, sondern ein normaler Zustand bei frischen/leeren
    Repos oder Repos ohne unterstuetzte Manifest-Dateien).
    """
    headers = {"Authorization": f"Bearer {SRC_GH_TOKEN}", "Accept": "application/vnd.github+json"}
    base = f"https://api.github.com/repos/{SRC_GH_OWNER}/{name}/dependabot/alerts"
    alerts = []
    page = 1
    while True:
        params = {"state": "open", "per_page": 100, "page": page}
        r = http_get(base, headers=headers, params=params, timeout=30,
                     description=f"Dependabot-Alerts abrufen ({name})")
        if r.status_code == 404:
            return None
        if r.status_code == 403:
            raise RuntimeError(
                "Kein Zugriff auf Dependabot-Alerts (HTTP 403). Pruefe, ob der Token den Scope "
                "'security_events' (klassischer PAT) bzw. die Berechtigung 'Dependabot alerts: "
                "Read-only' (feingranularer PAT) besitzt."
            )
        r.raise_for_status()
        batch = r.json()
        if not batch:
            break
        alerts.extend(batch)
        page += 1
    return alerts


def summarize_alerts(alerts):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    details = []
    for a in alerts:
        sev = (a.get("security_advisory", {}).get("severity") or "unknown").lower()
        if sev in counts:
            counts[sev] += 1
        pkg = a.get("security_vulnerability", {}).get("package", {}).get("name", "?")
        eco = a.get("security_vulnerability", {}).get("package", {}).get("ecosystem", "?")
        summary = a.get("security_advisory", {}).get("summary", "")
        url = a.get("html_url", "")
        details.append({"severity": sev, "package": pkg, "ecosystem": eco, "summary": summary, "url": url})
    details.sort(key=lambda d: -SEVERITY_ORDER.get(d["severity"], 0))
    return counts, details


def process_repo(name: str):
    """Gibt (ergebnis_dict, hatte_fehler) zurueck."""
    try:
        alerts = get_dependabot_alerts(name)
    except Exception as e:  # noqa: BLE001
        summary_log(f"--- {name} ---")
        summary_log(f"  !! FEHLER beim Abrufen der Dependabot-Alerts: {e}")
        return None, True

    if alerts is None:
        return {"repo": name, "disabled": True, "counts": None, "total": 0}, False

    counts, details = summarize_alerts(alerts)
    total = sum(counts.values())

    if total > 0:
        summary_log(f"--- {name} ---")
        summary_log(f"  kritisch={counts['critical']} hoch={counts['high']} "
                    f"mittel={counts['medium']} niedrig={counts['low']}")
        for d in details[:MAX_DETAILS_PER_REPO]:
            icon = SEVERITY_ICON.get(d["severity"], "❔")
            summary_log(f"    {icon} [{d['severity'].upper()}] {d['ecosystem']}/{d['package']}: "
                        f"{d['summary']} ({d['url']})")
        if len(details) > MAX_DETAILS_PER_REPO:
            summary_log(f"    ... und {len(details) - MAX_DETAILS_PER_REPO} weitere Alert(s)")

    return {"repo": name, "disabled": False, "counts": counts, "total": total}, False


# ====================================================================
#  HAUPTPROGRAMM
# ====================================================================

def main():
    global _repo_total, _repo_index

    start_time = datetime.now(timezone.utc)
    console_heartbeat("Dependency-/CVE-Alarm gestartet.")
    summary_log("===== Dependency-/CVE-Alarm gestartet =====")

    grand = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    disabled_repos = []
    error_repos = []
    repos_with_findings = []
    fatal_error = False

    try:
        repos = list_source_repos()
        _repo_total = len(repos)
        summary_log(f"{_repo_total} Quell-Repos gefunden.")

        for i, repo in enumerate(repos, start=1):
            _repo_index = i
            console_heartbeat()
            result, had_error = process_repo(repo["name"])

            if had_error:
                error_repos.append(repo["name"])
                continue
            if result["disabled"]:
                disabled_repos.append(result["repo"])
                continue

            for k in grand:
                grand[k] += result["counts"][k]
            if result["total"] > 0:
                repos_with_findings.append((result["repo"], result["total"], result["counts"]))

    except Exception as e:  # noqa: BLE001
        summary_log(f"!! SCHWERWIEGENDER FEHLER, Lauf abgebrochen: {e}")
        fatal_error = True

    duration = (datetime.now(timezone.utc) - start_time).total_seconds()
    total_open = sum(grand.values())

    if grand["critical"] > 0:
        level = "CRITICAL"
    elif grand["high"] > 0:
        level = "HIGH"
    elif grand["medium"] > 0:
        level = "MEDIUM"
    elif grand["low"] > 0:
        level = "LOW"
    else:
        level = "NONE"

    summary_line = f"===== Fertig: {total_open} offene Alert(s) gesamt. Dauer: {int(duration)}s ====="
    summary_log(summary_line)
    console_heartbeat("Dependency-/CVE-Alarm beendet.")

    header = (
        f"SEVERITY_LEVEL: {level}\n"
        f"Dependency-/CVE-Alarm Zusammenfassung\n"
        f"Repos geprueft: {_repo_total} | mit offenen Alerts: {len(repos_with_findings)} | "
        f"Abruf-Fehler: {len(error_repos)} | Dependabot nicht aktiviert: {len(disabled_repos)}\n"
        f"Offene Alerts gesamt: kritisch={grand['critical']} hoch={grand['high']} "
        f"mittel={grand['medium']} niedrig={grand['low']}\n"
        f"Dauer: {int(duration)} Sekunden\n"
    )

    if repos_with_findings:
        repos_with_findings.sort(key=lambda x: (-x[2]["critical"], -x[2]["high"], -x[1]))
        top = ", ".join(
            f"{n}({c['critical']}C/{c['high']}H/{c['medium']}M/{c['low']}L)"
            for n, t, c in repos_with_findings[:MAX_TOP_REPOS]
        )
        header += f"Betroffene Repos (Top {MAX_TOP_REPOS}, sortiert nach Schwere): {top}\n"
        if len(repos_with_findings) > MAX_TOP_REPOS:
            header += f"... und {len(repos_with_findings) - MAX_TOP_REPOS} weitere Repo(s) mit Alerts\n"

    if error_repos:
        header += "Repos mit Abruf-Fehlern: " + ", ".join(error_repos) + "\n"

    header += "\n----- Vollstaendiges Protokoll -----\n"

    SUMMARY_FILE.write_text(header + "\n".join(SUMMARY_LINES) + "\n", encoding="utf-8")

    # Exit-Code spiegelt NUR technische Fehler wider, nicht die Anzahl
    # gefundener Schwachstellen (siehe Modul-Docstring oben).
    sys.exit(1 if (fatal_error or error_repos) else 0)


if __name__ == "__main__":
    main()
