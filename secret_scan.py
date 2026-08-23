#!/usr/bin/env python3
"""
====================================================================
  SECRET-SCAN  (Public-Repo-Safe Version + Google Chat, via Gitleaks)
--------------------------------------------------------------------
  Klont STUENDLICH ALLE Repos eines GitHub-Accounts als lokalen
  Bare-Mirror (voller Commit-Verlauf, alle Branches/Tags) und laesst
  Gitleaks (https://github.com/gitleaks/gitleaks) darueber laufen, um
  versehentlich eingecheckte Passwoerter, API-Keys und Tokens zu
  finden - auch in alten Commits, die laengst wieder "entfernt"
  wurden (die bleiben in Git ja trotzdem in der Historie erhalten!).

  ---------------------------------------------------------------
  WARUM SELBST BAUEN STATT GITHUBS EINGEBAUTES SECRET SCANNING?
  ---------------------------------------------------------------
  GitHubs natives "Secret scanning" ist fuer PRIVATE Repos nur mit
  einer kostenpflichtigen GitHub-Advanced-Security-Lizenz nutzbar.
  Gitleaks ist Open Source, kostenlos und laeuft lokal auf dem
  Actions-Runner - deshalb passt es ins gleiche "unbegrenzte,
  kostenlose Actions-Minuten"-Konzept wie das Backup-Skript.

  ---------------------------------------------------------------
  SICHERHEITS-DESIGN (identisch zum Repo-Super-Backup-Skript):
  ---------------------------------------------------------------
  - Laeuft in einem OEFFENTLICHEN GitHub-Repo, OHNE dass aus den
    Actions-Logs ablesbar ist, welche Repos gescannt werden. Die
    Konsole zeigt nur "Repo 3/156" (anonymer Fortschritt).
  - Repo-Namen, Dateipfade, Zeilennummern und Regel-Treffer landen
    AUSSCHLIESSLICH in der Zusammenfassung, die per Webhook an einen
    PRIVATEN Google-Chat geschickt wird.
  - GANZ WICHTIG: Gitleaks laeuft mit dem Flag `--redact`. Dadurch
    wird der eigentliche SECRET-WERT selbst NIRGENDWO ausgegeben -
    weder auf der Konsole noch in der Zusammenfassungs-Datei noch im
    Google-Chat-Text. Es wird nur gemeldet WAS (Regel-Name), WO
    (Datei:Zeile, Commit) gefunden wurde, niemals der Klartext-Wert.
    Das ist wichtiger Selbstschutz: Ohne dieses Flag wuerde ein
    gefundenes Geheimnis sonst 1:1 in den (privaten, aber trotzdem
    zusaetzlichen) Google-Chat-Verlauf kopiert werden.
  - Alle eigenen Tokens werden vor jeder Log-Ausgabe per redact()
    unkenntlich gemacht.
  - Nach jedem einzelnen Repo wird der lokale Mirror-Ordner SOFORT
    wieder geloescht (Standard-Runner haben nur 14 GB SSD).

  ---------------------------------------------------------------
  LAUFZEIT-HINWEIS (bei stuendlichem Turnus wichtig!):
  ---------------------------------------------------------------
  Ein vollstaendiger History-Scan von ~156 Repos kann je nach
  Repo-Groesse laenger als 60 Minuten dauern. Die `concurrency`-
  Gruppe im Workflow verhindert Ueberlappung (ein neuer Lauf wartet,
  bis der vorherige fertig ist) - dauert ein Lauf regelmaessig laenger
  als eine Stunde, "staut" sich das und du bekommst seltener als
  stuendlich eine Meldung. Beobachte die Lauf-Dauer in den ersten
  Tagen (siehe Zusammenfassung: Feld "Dauer") und erhoehe im Zweifel
  das Intervall in backup-secretscan.yml (z.B. auf alle 2 Stunden).
====================================================================
"""

import json
import os
import shutil
import subprocess
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

WORKDIR = Path(env("SECRETSCAN_WORKDIR", default="secretscan_mirrors"))
GIT_TIMEOUT_SECONDS = int(env("GIT_TIMEOUT_SECONDS", default="1800"))
GITLEAKS_TIMEOUT_SECONDS = int(env("GITLEAKS_TIMEOUT_SECONDS", default="1800"))
GITLEAKS_BIN = env("GITLEAKS_BIN", default="gitleaks")

QUIET_CONSOLE = env("QUIET_CONSOLE", default="true").lower() == "true"
MAX_RETRIES = int(env("MAX_RETRIES", default="3"))
RETRY_BASE_DELAY_SECONDS = float(env("RETRY_BASE_DELAY_SECONDS", default="3"))

MAX_DETAILS_PER_REPO = int(env("MAX_DETAILS_PER_REPO", default="15"))
MAX_TOP_REPOS = int(env("MAX_TOP_REPOS", default="15"))

_SECRETS = [s for s in [SRC_GH_TOKEN] if s]


def redact(text: str) -> str:
    for s in _SECRETS:
        if s and s in text:
            text = text.replace(s, "***REDACTED***")
    return text


# ====================================================================
#  LOGGING: Konsole = anonym/leer. Summary-Datei = vollstaendig
#  (aber ohne Klartext-Geheimnisse - siehe --redact weiter unten).
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
            print(f"... Scanne Repo {_repo_index}/{_repo_total} ...", flush=True)
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


def run_git(cmd, cwd=None, timeout=GIT_TIMEOUT_SECONDS, description: str = None):
    def _attempt():
        try:
            result = subprocess.run(
                cmd, cwd=cwd, check=True, capture_output=True, text=True, timeout=timeout,
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            raise RuntimeError(redact(f"Git-Befehl fehlgeschlagen: {e.stderr}"))
        except subprocess.TimeoutExpired:
            raise RuntimeError(f"Timeout nach {timeout}s bei einem Git-Befehl.")

    return with_retry(_attempt, description or " ".join(cmd[:2]))


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
#  2) LOKALES BARE-MIRROR anlegen (immer frisch, eigener Ordner
#     getrennt vom Backup-Skript, falls beide im selben Repo laufen)
# ====================================================================

def clone_bare(repo_name: str, source_clone_url_with_token: str) -> Path:
    WORKDIR.mkdir(parents=True, exist_ok=True)
    bare_path = WORKDIR / f"{repo_name}.git"
    if bare_path.exists():
        shutil.rmtree(bare_path)
    summary_log(f"  -> klone {repo_name}")
    run_git(["git", "clone", "--mirror", source_clone_url_with_token, str(bare_path)],
            description=f"klonen {repo_name}")
    return bare_path


def cleanup_local_mirror(bare_path: Path):
    if bare_path and bare_path.exists():
        shutil.rmtree(bare_path, ignore_errors=True)


# ====================================================================
#  3) GITLEAKS auf dem Mirror laufen lassen
# ====================================================================

def run_gitleaks(bare_path: Path, repo_name: str):
    """
    Laesst Gitleaks ueber den vollstaendigen Commit-Verlauf im
    Bare-Mirror laufen. --redact sorgt dafuer, dass der GEFUNDENE
    SECRET-WERT selbst niemals im Report auftaucht (nur Regel/Datei/
    Zeile/Commit). --exit-code 0 sorgt dafuer, dass Gitleaks bei
    GEFUNDENEN Leaks (normalerweise Exit-Code 1) trotzdem mit 0
    endet - wir werten den JSON-Report selbst aus und behandeln
    Funde nicht als Skript-Fehler, sondern als Ergebnis.
    """
    report_path = WORKDIR / f"{repo_name}__gitleaks_report.json"

    def _attempt():
        cmd = [
            GITLEAKS_BIN, "detect",
            "--source", str(bare_path),
            "--report-format", "json",
            "--report-path", str(report_path),
            "--redact",
            "--no-banner",
            "--exit-code", "0",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=GITLEAKS_TIMEOUT_SECONDS)
        if result.returncode != 0:
            raise RuntimeError(redact(f"gitleaks-Ausfuehrungsfehler (Code {result.returncode}): {result.stderr}"))
        return True

    with_retry(_attempt, f"gitleaks-Scan ({repo_name})")

    findings = []
    if report_path.exists():
        try:
            text = report_path.read_text(encoding="utf-8").strip()
            findings = json.loads(text) if text else []
        except json.JSONDecodeError:
            findings = []
        finally:
            report_path.unlink(missing_ok=True)
    return findings


def summarize_findings(findings):
    by_rule = {}
    items = []
    for f in findings:
        rule = f.get("RuleID", "unknown")
        by_rule[rule] = by_rule.get(rule, 0) + 1
        items.append({
            "rule": rule,
            "file": f.get("File", "?"),
            "line": f.get("StartLine", "?"),
            "commit": (f.get("Commit", "") or "")[:12],
            "author": f.get("Author", "?"),
            "date": f.get("Date", "?"),
        })
    return by_rule, items


# ====================================================================
#  4) PRO REPO: klonen -> scannen -> aufraeumen
# ====================================================================

def process_repo(repo: dict):
    name = repo["name"]
    bare_path = None

    try:
        source_url = repo["clone_url"].replace("https://", f"https://{SRC_GH_TOKEN}@")
        bare_path = clone_bare(name, source_url)
    except Exception as e:  # noqa: BLE001
        summary_log(f"--- {name} ---")
        summary_log(f"  !! FEHLER beim Klonen: {e}")
        return None, True

    try:
        findings = run_gitleaks(bare_path, name)
    except Exception as e:  # noqa: BLE001
        summary_log(f"--- {name} ---")
        summary_log(f"  !! FEHLER beim Scannen: {e}")
        return None, True
    finally:
        cleanup_local_mirror(bare_path)

    if findings:
        by_rule, items = summarize_findings(findings)
        summary_log(f"--- {name} ---")
        summary_log(f"  {len(findings)} Fund(e): " +
                    ", ".join(f"{r}={c}" for r, c in sorted(by_rule.items(), key=lambda x: -x[1])))
        for it in items[:MAX_DETAILS_PER_REPO]:
            summary_log(f"    [{it['rule']}] {it['file']}:{it['line']} "
                        f"(Commit {it['commit']}, Autor {it['author']}, {it['date']})")
        if len(items) > MAX_DETAILS_PER_REPO:
            summary_log(f"    ... und {len(items) - MAX_DETAILS_PER_REPO} weitere Fund(e)")
        return {"repo": name, "count": len(findings), "by_rule": by_rule}, False

    return {"repo": name, "count": 0, "by_rule": {}}, False


# ====================================================================
#  HAUPTPROGRAMM
# ====================================================================

def main():
    global _repo_total, _repo_index

    start_time = datetime.now(timezone.utc)
    console_heartbeat("Secret-Scan gestartet.")
    summary_log("===== Secret-Scan (Gitleaks) gestartet =====")

    total_findings = 0
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
            result, had_error = process_repo(repo)

            if had_error:
                error_repos.append(repo["name"])
                continue

            total_findings += result["count"]
            if result["count"] > 0:
                repos_with_findings.append((result["repo"], result["count"], result["by_rule"]))

    except Exception as e:  # noqa: BLE001
        summary_log(f"!! SCHWERWIEGENDER FEHLER, Lauf abgebrochen: {e}")
        fatal_error = True

    duration = (datetime.now(timezone.utc) - start_time).total_seconds()

    summary_line = f"===== Fertig: {total_findings} Fund(e) in {len(repos_with_findings)} Repo(s). Dauer: {int(duration)}s ====="
    summary_log(summary_line)
    console_heartbeat("Secret-Scan beendet.")

    header = (
        f"FINDINGS_COUNT: {total_findings}\n"
        f"Secret-Scan Zusammenfassung (Gitleaks, Secret-Werte niemals im Klartext enthalten)\n"
        f"Repos gescannt: {_repo_total} | mit Fund(en): {len(repos_with_findings)} | "
        f"Fehler: {len(error_repos)}\n"
        f"Funde gesamt: {total_findings}\n"
        f"Dauer: {int(duration)} Sekunden\n"
    )

    if repos_with_findings:
        repos_with_findings.sort(key=lambda x: -x[1])
        top = ", ".join(f"{n}({c})" for n, c, _ in repos_with_findings[:MAX_TOP_REPOS])
        header += f"Betroffene Repos (Top {MAX_TOP_REPOS}, nach Fund-Anzahl): {top}\n"
        if len(repos_with_findings) > MAX_TOP_REPOS:
            header += f"... und {len(repos_with_findings) - MAX_TOP_REPOS} weitere Repo(s) mit Fund(en)\n"

    if error_repos:
        header += "Repos mit Scan-Fehlern: " + ", ".join(error_repos) + "\n"

    header += "\n----- Vollstaendiges Protokoll -----\n"

    SUMMARY_FILE.write_text(header + "\n".join(SUMMARY_LINES) + "\n", encoding="utf-8")

    # Exit-Code spiegelt NUR technische Fehler wider, nicht die Anzahl
    # gefundener Secrets (siehe Modul-Docstring oben).
    sys.exit(1 if (fatal_error or error_repos) else 0)


if __name__ == "__main__":
    main()
