#!/usr/bin/env python3
"""
====================================================================
  DEPENDENCY-GUARD  (Zero-Leak-Fassung fuer oeffentliche Repos)
--------------------------------------------------------------------
  WAS DIESES SKRIPT MACHT
  -----------------------
  Geht ueber ALLE Repos eines GitHub-Accounts und prueft die dort
  tatsaechlich verwendeten Abhaengigkeiten - unabhaengig davon, ob
  Dependabot im jeweiligen Repo aktiv, pausiert oder nie eingerichtet
  wurde.

    1) SCHWACHSTELLEN-SCAN mit OSV-Scanner. OSV.dev buendelt u.a.
       GitHub Security Advisories, NVD/CVE, PyPA, RustSec, Go Vulndb
       sowie Distro-Advisories - deutlich breiter als Dependabot.
    2) VERALTETE-PAKETE-CHECK gegen die offiziellen Registries.
    3) OPTIONALE KORREKTUR: Fix-Branch + Pull Request, wo das sicher
       automatisierbar ist; sonst ein Issue im betroffenen Repo.

  ================================================================
   ZERO-LEAK-DESIGN - warum hier so viel Aufwand getrieben wird
  ================================================================
  Dieses Skript laeuft in einem OEFFENTLICHEN Repo. Die Actions-Logs
  eines oeffentlichen Repos kann JEDER im Internet lesen, ohne
  Account, ohne Spur. Fuer einen Angreifer ist genau das wertvoll:
  er braucht keine Schwachstelle, er muss nur mitlesen.

  Angenommene Angreiferziele und die Gegenmassnahme hier im Code:

  A) "Welche Repos hat das Unternehmen?"
     -> Die Konsole gibt NIEMALS Repo-Namen aus. Sie gibt auch keine
        Repo-ANZAHL und keinen Fortschritt "7/156" aus, weil schon
        die Anzahl verraet, wie gross die Codebasis ist. Es wird nur
        ein inhaltsloses Lebenszeichen gedruckt.

  B) "Welche Technologien und Versionen setzen die ein?"
     -> Paketnamen, Versionen, Manifest-Pfade und CVE-IDs gehen
        AUSSCHLIESSLICH in den Report, der per E-Mail verschickt wird.
        Niemals nach stdout/stderr.

  C) "Wo sind sie gerade verwundbar?" - das gefaehrlichste Ziel.
     Ein oeffentlicher Report waere eine fertige Angriffsanleitung:
     bekannte Luecke, betroffenes Repo, noch kein Fix.
     -> Der Report wird NICHT als Artefakt hochgeladen (Artefakte
        sind in oeffentlichen Repos fuer jeden herunterladbar) und
        nicht in die Job-Summary geschrieben.

  D) "Ich lese die Fehlermeldungen mit."
     Tracebacks sind die klassische Leck-Quelle: sie enthalten
     Dateipfade, und die Pfade enthalten hier Repo-Namen.
     -> Ein globaler Exception-Hook unterdrueckt JEDEN Traceback auf
        der Konsole. Zusaetzlich wird stderr von Subprozessen
        grundsaetzlich eingefangen und nie durchgereicht.

  E) "Ich lese die Konfiguration aus den Logs."
     GitHub maskiert automatisch nur SECRETS, NICHT "vars".
     -> Auch der Kontoname laeuft als Secret, nicht als Variable.

  Grundregel im ganzen Skript: alles, was nach stdout geht, muss
  auch dann harmlos sein, wenn es ein Angreifer liest.
====================================================================
"""

import json
import os
import re
import shutil
import smtplib
import subprocess
import sys
import time
from datetime import datetime, timezone
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from pathlib import Path

import requests

from common import (
    env,
    Redactor,
    SummaryLogger,
    list_github_repos,
    http_get,
    http_post,
    send_google_chat,
    with_retry,
)

# ====================================================================
#  ZERO-LEAK-SCHUTZ  (muss VOR allem anderen greifen)
# ====================================================================


def _silent_excepthook(exc_type, exc_value, exc_tb):
    """
    Gegenmassnahme zu Angreiferziel D.

    Ein normaler Python-Traceback wuerde Zeilen wie
        File "guard_clones/UIID-core/setup.py", line 12
    auf die oeffentlich lesbare Konsole schreiben - und damit
    Repo-Namen verraten, obwohl der restliche Code penibel schweigt.
    Deshalb wird die Ausgabe komplett ersetzt. Die Details stehen im
    Report, der privat per Mail geht.
    """
    print("Unerwarteter Fehler - Details ausschliesslich im privaten Report.", flush=True)
    sys.exit(1)


sys.excepthook = _silent_excepthook


# ====================================================================
#  CONFIG
# ====================================================================
SRC_GH_TOKEN = env("SRC_GH_TOKEN", required=True)
# Bewusst als SECRET uebergeben, nicht als "vars" (Angreiferziel E):
# GitHub maskiert nur Secrets automatisch in Logs.
SRC_GH_OWNER = env("SRC_GH_OWNER", required=True)
SRC_GH_OWNER_TYPE = env("SRC_GH_OWNER_TYPE", default="user")

GOOGLE_CHAT_WEBHOOK = env("GOOGLE_CHAT_WEBHOOK")

# --- E-Mail-Versand des Reports (der einzige Ausgabekanal fuer Details) ---
REPORT_TO = env("REPORT_TO", default="hello@linkspreed.com")
SMTP_HOST = env("SMTP_HOST", default="smtp.gmail.com")
SMTP_PORT = int(env("SMTP_PORT", default="587"))
SMTP_USER = env("SMTP_USER")
SMTP_PASS = env("SMTP_PASS")
SMTP_FROM = env("SMTP_FROM", default=SMTP_USER or "")

# --- Verhalten ---
# "off" | "pr" | "issue" | "pr+issue"
FIX_MODE = env("FIX_MODE", default="pr+issue").lower()
FIX_BRANCH_PREFIX = env("FIX_BRANCH_PREFIX", default="dependency-guard/fix")
MIN_FIX_SEVERITY = env("MIN_FIX_SEVERITY", default="HIGH").upper()

DEPENDABOT_CROSSCHECK = env("DEPENDABOT_CROSSCHECK", default="true").lower() == "true"
CHECK_OUTDATED = env("CHECK_OUTDATED", default="true").lower() == "true"

SKIP_ARCHIVED = env("SKIP_ARCHIVED", default="true").lower() == "true"
SKIP_FORKS = env("SKIP_FORKS", default="true").lower() == "true"
REPO_ALLOWLIST = [r.strip() for r in env("REPO_ALLOWLIST", default="").split(",") if r.strip()]
REPO_DENYLIST = [r.strip() for r in env("REPO_DENYLIST", default="").split(",") if r.strip()]

WORKDIR = Path(env("GUARD_WORKDIR", default="guard_clones"))
REPORT_HTML_FILE = Path(env("REPORT_HTML_FILE", default="dependency_report.html"))
REPORT_TEXT_FILE = Path(env("REPORT_TEXT_FILE", default="dependency_report.txt"))
OSV_TIMEOUT = int(env("OSV_TIMEOUT_SECONDS", default="900"))
MAX_OUTDATED_PER_REPO = int(env("MAX_OUTDATED_PER_REPO", default="25"))

# Der Redactor ist die zweite Verteidigungslinie hinter GitHubs
# eigener Secret-Maskierung - falls ein Token doch mal in einen Text
# geraet, der spaeter irgendwo landet.
redact = Redactor([SRC_GH_TOKEN, SMTP_PASS, GOOGLE_CHAT_WEBHOOK, SRC_GH_OWNER])
log = SummaryLogger(redact)

GH_HEADERS = {
    "Authorization": f"Bearer {SRC_GH_TOKEN}",
    "Accept": "application/vnd.github+json",
    "X-GitHub-Api-Version": "2022-11-28",
}

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNKNOWN": 0}
SEVERITY_ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "⚪", "UNKNOWN": "❔"}


def heartbeat():
    """
    Gegenmassnahme zu Angreiferziel A.

    Bewusst OHNE Zaehler. Ein "Repo 7/156" wuerde die Groesse der
    Codebasis verraten - eine Information, die ein Angreifer fuer die
    Einschaetzung des Ziels gut gebrauchen kann und die uns nichts
    bringt, weil der echte Fortschritt ohnehin im Report steht.
    Der Punkt dient nur dazu, den Runner nicht als haengend gelten
    zu lassen.
    """
    print(".", end="", flush=True)


def safe_console(msg: str):
    """Nur fest verdrahtete, inhaltsleere Statusmeldungen erlaubt."""
    print(msg, flush=True)


# ====================================================================
#  1) OSV-SCANNER
# ====================================================================
def run_osv_scanner(repo_path: Path) -> dict:
    """
    Fuehrt OSV-Scanner rekursiv aus. capture_output=True ist hier
    NICHT optional, sondern Teil des Sicherheitskonzepts: ohne das
    wuerde osv-scanner Pfade (= Repo-Namen) direkt in das oeffentliche
    Log schreiben.

    Exit-Code 1 heisst bei OSV-Scanner "Schwachstellen gefunden" -
    das ist der Normalfall, kein Fehler. 128 = nichts Scannbares.
    """
    out_file = repo_path.parent / "osv_result.json"
    if out_file.exists():
        out_file.unlink()

    proc = subprocess.run(
        ["osv-scanner", "scan", "source", "--recursive",
         "--format", "json", "--output", str(out_file), str(repo_path)],
        capture_output=True, text=True, timeout=OSV_TIMEOUT,
    )

    if proc.returncode not in (0, 1) and not out_file.exists():
        if proc.returncode == 128:
            return {"results": []}
        # stderr wird bewusst nur gekuerzt und redigiert weitergereicht -
        # und landet ausschliesslich im privaten Report.
        raise RuntimeError(redact(f"Scanner-Exit {proc.returncode}: {proc.stderr[:300]}"))

    if not out_file.exists():
        return {"results": []}
    return json.loads(out_file.read_text(encoding="utf-8") or "{}")


def _severity_from_vuln(vuln: dict) -> str:
    """Erst die GHSA-Angabe, sonst CVSS-Score in eine Stufe uebersetzen."""
    db = vuln.get("database_specific") or {}
    sev = (db.get("severity") or "").upper()
    if sev in SEVERITY_ORDER:
        return sev

    score = None
    for s in vuln.get("severity") or []:
        try:
            score = float(s.get("score"))
        except (TypeError, ValueError):
            continue
    if score is None:
        return "UNKNOWN"
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    return "LOW"


def _fixed_versions(vuln: dict, package_name: str) -> list:
    fixed = []
    for affected in vuln.get("affected") or []:
        pkg = (affected.get("package") or {}).get("name", "")
        if pkg.lower() != package_name.lower():
            continue
        for rng in affected.get("ranges") or []:
            for event in rng.get("events") or []:
                if event.get("fixed"):
                    fixed.append(event["fixed"])
    return fixed


def parse_osv_results(data: dict) -> list:
    """Defensiv geschrieben, damit Schema-Aenderungen den Lauf nicht kippen."""
    findings = []
    for result in data.get("results") or []:
        source = ((result.get("source") or {}).get("path")) or "?"
        for pkg_entry in result.get("packages") or []:
            pkg = pkg_entry.get("package") or {}
            name = pkg.get("name", "?")
            for vuln in pkg_entry.get("vulnerabilities") or []:
                findings.append({
                    "manifest": os.path.basename(source),
                    "ecosystem": pkg.get("ecosystem", "?"),
                    "package": name,
                    "version": pkg.get("version", "?"),
                    "id": vuln.get("id", "?"),
                    "summary": (vuln.get("summary") or "").strip(),
                    "severity": _severity_from_vuln(vuln),
                    "fixed": _fixed_versions(vuln, name),
                })
    return findings


# ====================================================================
#  2) VERALTETE PAKETE
# ====================================================================
_latest_cache = {}


def _registry_latest(ecosystem: str, name: str):
    key = f"{ecosystem}:{name}"
    if key in _latest_cache:
        return _latest_cache[key]

    url = None
    if ecosystem == "npm":
        url = f"https://registry.npmjs.org/{requests.utils.quote(name, safe='@/')}/latest"
    elif ecosystem == "PyPI":
        url = f"https://pypi.org/pypi/{name}/json"
    elif ecosystem == "crates.io":
        url = f"https://crates.io/api/v1/crates/{name}"
    elif ecosystem == "Go":
        url = f"https://proxy.golang.org/{name.lower()}/@latest"
    elif ecosystem == "Packagist":
        url = f"https://repo.packagist.org/p2/{name}.json"

    latest = None
    if url:
        try:
            # Neutraler User-Agent: verraet gegenueber der Registry nicht,
            # von welchem Unternehmen die Abfragen kommen.
            r = requests.get(url, timeout=20, headers={"User-Agent": "dependency-check"})
            if r.status_code == 200:
                d = r.json()
                if ecosystem == "npm":
                    latest = d.get("version")
                elif ecosystem == "PyPI":
                    latest = (d.get("info") or {}).get("version")
                elif ecosystem == "crates.io":
                    latest = (d.get("crate") or {}).get("max_stable_version")
                elif ecosystem == "Go":
                    latest = d.get("Version")
                elif ecosystem == "Packagist":
                    versions = (d.get("packages") or {}).get(name) or []
                    stable = [v.get("version") for v in versions
                              if v.get("version")
                              and not re.search(r"(dev|alpha|beta|RC)", v["version"], re.I)]
                    latest = stable[0] if stable else None
        except Exception:  # noqa: BLE001 - Registry-Ausfall darf nie den Lauf stoppen
            latest = None

    _latest_cache[key] = latest
    return latest


def _clean_version(raw: str) -> str:
    return re.sub(r"^[\^~>=<\s v]+", "", (raw or "").strip()).strip()


def collect_direct_dependencies(repo_path: Path) -> list:
    deps = []

    pkg_json = repo_path / "package.json"
    if pkg_json.exists():
        try:
            d = json.loads(pkg_json.read_text(encoding="utf-8"))
            for section in ("dependencies", "devDependencies"):
                for name, ver in (d.get(section) or {}).items():
                    deps.append({"ecosystem": "npm", "name": name,
                                 "current": _clean_version(str(ver))})
        except Exception:  # noqa: BLE001
            pass

    for req in ("requirements.txt", "requirements-dev.txt"):
        f = repo_path / req
        if f.exists():
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.split("#")[0].strip()
                m = re.match(r"^([A-Za-z0-9._\-\[\]]+)\s*==\s*([0-9A-Za-z.\-+]+)$", line)
                if m:
                    deps.append({"ecosystem": "PyPI", "name": m.group(1).split("[")[0],
                                 "current": m.group(2)})

    go_mod = repo_path / "go.mod"
    if go_mod.exists():
        for line in go_mod.read_text(encoding="utf-8", errors="ignore").splitlines():
            m = re.match(r"^\s*([a-z0-9./\-_]+)\s+(v[0-9][^\s]*)", line.strip())
            if m and "=>" not in line:
                deps.append({"ecosystem": "Go", "name": m.group(1), "current": m.group(2)})

    composer = repo_path / "composer.json"
    if composer.exists():
        try:
            d = json.loads(composer.read_text(encoding="utf-8"))
            for name, ver in (d.get("require") or {}).items():
                if "/" in name:
                    deps.append({"ecosystem": "Packagist", "name": name,
                                 "current": _clean_version(str(ver))})
        except Exception:  # noqa: BLE001
            pass

    cargo = repo_path / "Cargo.toml"
    if cargo.exists():
        in_deps = False
        for line in cargo.read_text(encoding="utf-8", errors="ignore").splitlines():
            s = line.strip()
            if s.startswith("["):
                in_deps = s in ("[dependencies]", "[dev-dependencies]")
                continue
            if in_deps:
                m = re.match(r'^([A-Za-z0-9._\-]+)\s*=\s*"([^"]+)"', s)
                if m:
                    deps.append({"ecosystem": "crates.io", "name": m.group(1),
                                 "current": _clean_version(m.group(2))})

    seen, unique = set(), []
    for d in deps:
        k = (d["ecosystem"], d["name"])
        if k not in seen:
            seen.add(k)
            unique.append(d)
    return unique


def check_outdated(repo_path: Path) -> list:
    outdated = []
    for dep in collect_direct_dependencies(repo_path):
        if not dep["current"] or not re.match(r"^\d", dep["current"].lstrip("v")):
            continue  # Ranges wie "*" sind nicht sinnvoll vergleichbar
        latest = _registry_latest(dep["ecosystem"], dep["name"])
        if latest and latest.lstrip("v") != dep["current"].lstrip("v"):
            outdated.append({**dep, "latest": latest})
        if len(outdated) >= MAX_OUTDATED_PER_REPO:
            break
    return outdated


# ====================================================================
#  3) DEPENDABOT-GEGENPROBE
# ====================================================================
def dependabot_alert_count(owner: str, repo: str):
    """None = Dependabot hier nicht aktiv oder kein Zugriff."""
    url = f"https://api.github.com/repos/{owner}/{repo}/dependabot/alerts"
    r = http_get(url, headers=GH_HEADERS, params={"state": "open", "per_page": 100},
                 timeout=30, description="Dependabot-Alerts", logger=log)
    if r.status_code in (403, 404):
        return None
    r.raise_for_status()
    return len(r.json())


# ====================================================================
#  4) KORREKTUR + PULL REQUEST
# ====================================================================
def git(args, cwd, check=True):
    """capture_output=True ist auch hier Sicherheitsmassnahme, nicht Kosmetik."""
    return subprocess.run(["git"] + args, cwd=str(cwd), capture_output=True,
                          text=True, check=check, timeout=300)


def try_fix_npm(repo_path: Path) -> bool:
    """
    Guided Remediation: hebt im package-lock.json verwundbare
    Versionen an, ohne vorhandene Constraints zu verletzen
    (Strategie "in-place" = die risikoaermste Variante).
    """
    lock = repo_path / "package-lock.json"
    if not lock.exists():
        return False
    proc = subprocess.run(
        ["osv-scanner", "fix", "--non-interactive", "--strategy=in-place", "-L", str(lock)],
        capture_output=True, text=True, timeout=OSV_TIMEOUT,
    )
    if proc.returncode not in (0, 1):
        log.log(f"     (Fix-Lauf meldete Exit {proc.returncode})")
    return bool(git(["status", "--porcelain"], repo_path).stdout.strip())


def try_fix_pip(repo_path: Path, findings: list) -> bool:
    """
    Hebt NUR exakt gepinnte Versionen ("paket==1.2.3") an. Ranges
    bleiben unberuehrt - eine automatische Aenderung an einem Range
    koennte unbemerkt etwas brechen, und das Risiko ist hier nicht
    gerechtfertigt.
    """
    req = repo_path / "requirements.txt"
    if not req.exists():
        return False

    wanted = {}
    for f in findings:
        if f["ecosystem"] != "PyPI" or not f["fixed"]:
            continue
        best = sorted(f["fixed"])[-1]
        name = f["package"].lower()
        if name not in wanted or best > wanted[name]:
            wanted[name] = best
    if not wanted:
        return False

    lines, changed = [], False
    for line in req.read_text(encoding="utf-8").splitlines():
        m = re.match(r"^([A-Za-z0-9._\-\[\]]+)\s*==\s*([0-9A-Za-z.\-+]+)\s*$", line.strip())
        if m:
            base = m.group(1).split("[")[0].lower()
            if base in wanted and wanted[base] != m.group(2):
                lines.append(f"{m.group(1)}=={wanted[base]}")
                changed = True
                continue
        lines.append(line)

    if changed:
        req.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return changed


def open_pull_request(owner: str, repo: str, branch: str, base: str, title: str, body: str):
    r = http_post(f"https://api.github.com/repos/{owner}/{repo}/pulls",
                  headers=GH_HEADERS,
                  json_body={"title": title, "head": branch, "base": base, "body": body},
                  timeout=30, description="Pull Request anlegen", logger=log)
    if r.status_code == 201:
        return r.json().get("html_url")
    if r.status_code == 422:
        return "(PR existiert bereits oder keine Aenderung)"
    raise RuntimeError(redact(f"PR fehlgeschlagen: HTTP {r.status_code}"))


def open_issue(owner: str, repo: str, title: str, body: str):
    r = http_post(f"https://api.github.com/repos/{owner}/{repo}/issues",
                  headers=GH_HEADERS,
                  json_body={"title": title, "body": body,
                             "labels": ["security", "dependencies"]},
                  timeout=30, description="Issue anlegen", logger=log)
    if r.status_code == 201:
        return r.json().get("html_url")
    raise RuntimeError(redact(f"Issue fehlgeschlagen: HTTP {r.status_code}"))


def findings_markdown(findings: list) -> str:
    rows = ["| Schweregrad | Paket | Version | ID | Fix ab |", "|---|---|---|---|---|"]
    for f in sorted(findings, key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0))[:40]:
        fixed = ", ".join(f["fixed"][:3]) if f["fixed"] else "kein Fix bekannt"
        rows.append(f"| {f['severity']} | `{f['ecosystem']}/{f['package']}` | {f['version']} "
                    f"| [{f['id']}](https://osv.dev/vulnerability/{f['id']}) | {fixed} |")
    return "\n".join(rows)


def remediate(repo_path: Path, owner: str, repo: str, default_branch: str,
              findings: list) -> dict:
    """
    Wichtig fuer die Sicherheit: PR und Issue entstehen im BETROFFENEN
    (privaten) Repo, nicht im oeffentlichen Steuer-Repo. Die Befunde
    bleiben damit im geschuetzten Bereich.
    """
    result = {"pr": None, "issue": None}
    threshold = SEVERITY_ORDER.get(MIN_FIX_SEVERITY, 3)
    relevant = [f for f in findings if SEVERITY_ORDER.get(f["severity"], 0) >= threshold]
    if not relevant or FIX_MODE == "off":
        return result

    changed = False
    if FIX_MODE in ("pr", "pr+issue"):
        try:
            changed = try_fix_npm(repo_path) or try_fix_pip(repo_path, relevant)
        except Exception as e:  # noqa: BLE001
            log.log(f"     (automatische Korrektur nicht moeglich: {redact(str(e))[:200]})")

    if changed:
        branch = f"{FIX_BRANCH_PREFIX}-{datetime.now(timezone.utc).strftime('%Y%m%d')}"
        try:
            git(["config", "user.name", "Dependency Guard Bot"], repo_path)
            git(["config", "user.email", "bot@users.noreply.github.com"], repo_path)
            git(["checkout", "-B", branch], repo_path)
            git(["add", "-A"], repo_path)
            git(["commit", "-m",
                 "fix(deps): bekannte Schwachstellen in Abhaengigkeiten beheben"], repo_path)
            git(["push", "--force", "origin", branch], repo_path)
            body = ("Automatisch erzeugt vom zentralen **Dependency Guard**.\n\n"
                    "Grundlage ist ein OSV-Scan. Bitte CI abwarten und vor dem Merge "
                    "pruefen.\n\n" + findings_markdown(relevant))
            result["pr"] = open_pull_request(
                owner, repo, branch, default_branch,
                "fix(deps): Schwachstellen in Abhaengigkeiten beheben", body)
            log.log(f"     (Pull Request: {result['pr']})")
            return result
        except Exception as e:  # noqa: BLE001
            log.log(f"     !! PR-Erstellung fehlgeschlagen: {redact(str(e))[:200]}")

    if FIX_MODE in ("issue", "pr+issue"):
        try:
            body = ("Der zentrale **Dependency Guard** hat Schwachstellen gefunden, die "
                    "sich nicht automatisch beheben liessen (Oekosystem nicht unterstuetzt, "
                    "kein Fix verfuegbar oder Lockfile fehlt).\n\n"
                    + findings_markdown(relevant))
            result["issue"] = open_issue(
                owner, repo,
                "Schwachstellen in Abhaengigkeiten gefunden (Dependency Guard)", body)
            log.log(f"     (Issue: {result['issue']})")
        except Exception as e:  # noqa: BLE001
            log.log(f"     !! Issue-Erstellung fehlgeschlagen: {redact(str(e))[:200]}")
    return result


# ====================================================================
#  5) REPORT  (einziger Kanal, der Details enthaelt)
# ====================================================================
def build_report(repo_reports: list, stats: dict, duration: int) -> tuple:
    ts = datetime.now(timezone.utc).strftime("%d.%m.%Y %H:%M UTC")
    level = stats["level"]

    text = [
        f"SEVERITY_LEVEL: {level}",
        f"Dependency-Guard-Report vom {ts}",
        f"Repos geprueft: {stats['repos']} | mit Schwachstellen: {stats['repos_vuln']} "
        f"| mit Fehlern: {stats['repos_error']}",
        f"Schwachstellen gesamt: kritisch={stats['CRITICAL']} hoch={stats['HIGH']} "
        f"mittel={stats['MEDIUM']} niedrig={stats['LOW']}",
        f"Erstellte Pull Requests: {stats['prs']} | erstellte Issues: {stats['issues']}",
        f"Dauer: {duration}s",
        "",
    ]

    html = [
        "<html><body style='font-family:Segoe UI,Arial,sans-serif;font-size:14px;color:#222'>",
        f"<h2>{SEVERITY_ICON.get(level, 'GB')} Dependency-Guard-Report</h2>",
        f"<p><b>{ts}</b><br>",
        f"Repos geprueft: <b>{stats['repos']}</b> &middot; mit Schwachstellen: "
        f"<b>{stats['repos_vuln']}</b> &middot; Fehler: <b>{stats['repos_error']}</b><br>",
        f"Kritisch: <b style='color:#b00'>{stats['CRITICAL']}</b> &middot; "
        f"Hoch: <b style='color:#d60'>{stats['HIGH']}</b> &middot; "
        f"Mittel: {stats['MEDIUM']} &middot; Niedrig: {stats['LOW']}<br>",
        f"Pull Requests: <b>{stats['prs']}</b> &middot; Issues: <b>{stats['issues']}</b> "
        f"&middot; Dauer: {duration}s</p>",
    ]

    for rep in repo_reports:
        if not rep["findings"] and not rep["outdated"] and not rep["error"]:
            continue
        text.append(f"--- {rep['repo']} ---")
        html.append(f"<h3 style='margin-bottom:4px'>{rep['repo']}</h3>")

        if rep["error"]:
            text.append(f"  !! Fehler: {rep['error']}")
            html.append(f"<p style='color:#b00'>Fehler: {rep['error']}</p>")

        if rep["findings"]:
            html.append("<table cellpadding='5' cellspacing='0' border='1' "
                        "style='border-collapse:collapse;border-color:#ddd;font-size:13px'>"
                        "<tr style='background:#f4f4f4'><th>Schwere</th><th>Paket</th>"
                        "<th>Version</th><th>ID</th><th>Fix ab</th><th>Beschreibung</th></tr>")
            for f in sorted(rep["findings"],
                            key=lambda x: -SEVERITY_ORDER.get(x["severity"], 0))[:30]:
                fixed = ", ".join(f["fixed"][:2]) if f["fixed"] else "-"
                text.append(f"  {SEVERITY_ICON.get(f['severity'], '❔')} [{f['severity']}] "
                            f"{f['ecosystem']}/{f['package']} {f['version']} -> {f['id']} "
                            f"(Fix ab: {fixed})")
                html.append(
                    f"<tr><td>{SEVERITY_ICON.get(f['severity'], '')} {f['severity']}</td>"
                    f"<td>{f['ecosystem']}/{f['package']}</td><td>{f['version']}</td>"
                    f"<td><a href='https://osv.dev/vulnerability/{f['id']}'>{f['id']}</a></td>"
                    f"<td>{fixed}</td><td>{(f['summary'] or '')[:160]}</td></tr>")
            html.append("</table>")

        if rep["outdated"]:
            names = ", ".join(f"{o['name']} {o['current']}→{o['latest']}"
                              for o in rep["outdated"][:15])
            text.append(f"  Veraltet ({len(rep['outdated'])}): {names}")
            html.append(f"<p style='color:#555'><b>Veraltet ({len(rep['outdated'])}):</b> "
                        f"{names}</p>")

        if rep["dependabot"] is None:
            text.append("  Hinweis: Dependabot fuer dieses Repo NICHT aktiv.")
            html.append("<p style='color:#a60'>Hinweis: Dependabot ist hier nicht aktiv – "
                        "dieser Scan ist die einzige Absicherung.</p>")

        if rep["pr"]:
            text.append(f"  Pull Request: {rep['pr']}")
            html.append(f"<p>✅ Pull Request: <a href='{rep['pr']}'>{rep['pr']}</a></p>")
        if rep["issue"]:
            text.append(f"  Issue: {rep['issue']}")
            html.append(f"<p>📌 Issue: <a href='{rep['issue']}'>{rep['issue']}</a></p>")
        text.append("")

    html.append("<hr><p style='color:#888;font-size:12px'>Automatisch erzeugt vom Dependency "
                "Guard. Datenbasis: OSV.dev sowie die offiziellen Paket-Registries. "
                "<b>Vertraulich - enthaelt ausnutzbare Schwachstellen.</b></p></body></html>")
    return "\n".join(text), "\n".join(html)


def send_report_mail(subject: str, text_body: str, html_body: str) -> bool:
    if not (SMTP_USER and SMTP_PASS and REPORT_TO):
        return False
    msg = MIMEMultipart("alternative")
    msg["Subject"] = subject
    msg["From"] = SMTP_FROM or SMTP_USER
    msg["To"] = REPORT_TO
    msg.attach(MIMEText(text_body, "plain", "utf-8"))
    msg.attach(MIMEText(html_body, "html", "utf-8"))

    def _send():
        with smtplib.SMTP(SMTP_HOST, SMTP_PORT, timeout=60) as server:
            server.starttls()
            server.login(SMTP_USER, SMTP_PASS)
            server.sendmail(msg["From"], [REPORT_TO], msg.as_string())

    with_retry(_send, "Report-Mail senden", logger=log)
    return True


def shred(path: Path):
    """
    Report-Dateien nach dem Versand ueberschreiben und loeschen.
    Reine Vorsichtsmassnahme fuer den Fall, dass irgendwann doch
    einmal jemand einen Artefakt-Upload-Schritt ergaenzt: dann liegt
    zu diesem Zeitpunkt nichts Verwertbares mehr auf der Platte.
    """
    try:
        if path.exists():
            size = path.stat().st_size
            path.write_bytes(b"0" * size)
            path.unlink()
    except Exception:  # noqa: BLE001
        pass


# ====================================================================
#  HAUPTPROGRAMM
# ====================================================================
def process_repo(repo: dict) -> dict:
    name = repo["name"]
    owner = repo["owner"]["login"]
    default_branch = repo.get("default_branch") or "main"
    report = {"repo": name, "findings": [], "outdated": [], "dependabot": None,
              "pr": None, "issue": None, "error": None}

    WORKDIR.mkdir(parents=True, exist_ok=True)
    dest = WORKDIR / name
    if dest.exists():
        shutil.rmtree(dest, ignore_errors=True)

    clone_url = repo["clone_url"].replace("https://", f"https://x-access-token:{SRC_GH_TOKEN}@")
    try:
        subprocess.run(["git", "clone", "--depth", "1", "--quiet", clone_url, str(dest)],
                       check=True, capture_output=True, text=True, timeout=600)
    except subprocess.CalledProcessError as e:
        report["error"] = redact(f"Klonen fehlgeschlagen: {e.stderr[:200]}")
        log.log(f"--- {name} ---")
        log.log(f"  !! {report['error']}")
        return report
    except subprocess.TimeoutExpired:
        report["error"] = "Klonen: Zeitueberschreitung"
        return report

    try:
        report["findings"] = parse_osv_results(run_osv_scanner(dest))
        if CHECK_OUTDATED:
            report["outdated"] = check_outdated(dest)
        if DEPENDABOT_CROSSCHECK:
            report["dependabot"] = dependabot_alert_count(owner, name)

        if report["findings"]:
            log.log(f"--- {name} ---")
            for f in report["findings"][:15]:
                log.log(f"  {SEVERITY_ICON.get(f['severity'], '❔')} [{f['severity']}] "
                        f"{f['ecosystem']}/{f['package']} {f['version']} -> {f['id']}")
            fixes = remediate(dest, owner, name, default_branch, report["findings"])
            report["pr"], report["issue"] = fixes["pr"], fixes["issue"]
    except Exception as e:  # noqa: BLE001
        report["error"] = redact(str(e))[:300]
        log.log(f"--- {name} ---")
        log.log(f"  !! FEHLER: {report['error']}")
    finally:
        shutil.rmtree(dest, ignore_errors=True)

    return report


def main():
    start = datetime.now(timezone.utc)
    safe_console("Dependency Guard gestartet.")

    if shutil.which("osv-scanner") is None:
        safe_console("Voraussetzung fehlt - Abbruch.")
        sys.exit(1)

    try:
        repos = list_github_repos(SRC_GH_TOKEN, SRC_GH_OWNER, SRC_GH_OWNER_TYPE, logger=log)
    except Exception:  # noqa: BLE001
        safe_console("Konfigurationsquelle nicht erreichbar - Abbruch.")
        sys.exit(1)

    filtered = []
    for r in repos:
        if SKIP_ARCHIVED and r.get("archived"):
            continue
        if SKIP_FORKS and r.get("fork"):
            continue
        if REPO_ALLOWLIST and r["name"] not in REPO_ALLOWLIST:
            continue
        if r["name"] in REPO_DENYLIST:
            continue
        filtered.append(r)

    log.log(f"{len(filtered)} Repos werden geprueft (von {len(repos)} insgesamt).")

    reports = []
    stats = {"repos": len(filtered), "repos_vuln": 0, "repos_error": 0, "prs": 0, "issues": 0,
             "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "UNKNOWN": 0, "level": "NONE"}

    for repo in filtered:
        heartbeat()
        rep = process_repo(repo)
        reports.append(rep)
        if rep["error"]:
            stats["repos_error"] += 1
        if rep["findings"]:
            stats["repos_vuln"] += 1
            for f in rep["findings"]:
                stats[f["severity"]] = stats.get(f["severity"], 0) + 1
        if rep["pr"]:
            stats["prs"] += 1
        if rep["issue"]:
            stats["issues"] += 1
        time.sleep(0.3)  # Rate-Limits schonen

    print("", flush=True)  # Zeilenumbruch nach den Heartbeat-Punkten

    for lvl in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        if stats[lvl] > 0:
            stats["level"] = lvl
            break

    duration = int((datetime.now(timezone.utc) - start).total_seconds())
    text_report, html_report = build_report(reports, stats, duration)

    REPORT_TEXT_FILE.write_text(text_report, encoding="utf-8")
    REPORT_HTML_FILE.write_text(html_report, encoding="utf-8")

    subject = (f"{SEVERITY_ICON.get(stats['level'], '✅')} Dependency-Report "
               f"{datetime.now(timezone.utc).strftime('%d.%m.%Y %H:%M')} UTC – "
               f"{stats['CRITICAL']} kritisch / {stats['HIGH']} hoch")

    mail_ok = False
    try:
        mail_ok = send_report_mail(subject, text_report, html_report)
    except Exception:  # noqa: BLE001
        mail_ok = False

    chat_ok = False
    if GOOGLE_CHAT_WEBHOOK:
        try:
            send_google_chat(GOOGLE_CHAT_WEBHOOK, f"{subject}\n\n{text_report[:3000]}")
            chat_ok = True
        except Exception:  # noqa: BLE001
            chat_ok = False

    # Erst NACH erfolgreichem Versand vernichten - sonst waere der
    # Report bei einem Mailfehler ersatzlos verloren.
    if mail_ok or chat_ok:
        shred(REPORT_TEXT_FILE)
        shred(REPORT_HTML_FILE)
        safe_console("Lauf abgeschlossen. Report zugestellt.")
    else:
        safe_console("Lauf abgeschlossen. ACHTUNG: Report konnte nicht zugestellt werden.")

    # Bewusst OHNE Zahlen: weder Trefferquote noch Repo-Anzahl
    # gehoeren in ein oeffentlich lesbares Log.
    sys.exit(1 if (stats["repos_error"] or not (mail_ok or chat_ok)) else 0)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        sys.exit(1)
