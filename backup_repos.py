#!/usr/bin/env python3
"""
====================================================================
  PATCH: VOLLSTAENDIGKEIT & VERIFIKATION
--------------------------------------------------------------------
  Drop-in-Ersatz fuer die betroffenen Funktionen aus backup.py.
  Behebt die Ursachen fuer "Repo ist da, aber nicht alle Branches"
  und "Repo fehlt komplett".

  FIX H) ATOMARER PUSH
    Ohne --atomic verarbeitet der Server jede Ref EINZELN. Scheitern
    3 von 40 Branches, werden die anderen 37 trotzdem geschrieben und
    der Befehl endet mit Fehler. Das Ziel sieht befuellt aus, ist aber
    unvollstaendig - und der Retry aendert daran nichts, weil dieselben
    3 Refs erneut scheitern. Mit --atomic gilt: alles oder nichts.

  FIX I) VERIFIKATION NACH DEM PUSH
    Bisher wurde NIE geprueft, ob das Ziel wirklich hat, was die Quelle
    hat. verify_refs() vergleicht Ref-Name UND Commit-SHA zwischen
    lokalem Mirror und Ziel (via git ls-remote) und meldet fehlende
    bzw. abweichende Refs NAMENTLICH. Ohne diesen Schritt ist jede
    weitere Fehlersuche Raterei.

  FIX J) RATE-LIMITS (429 / 403 secondary) WERDEN WIEDERHOLT
    Bisher wurde nur bei HTTP >= 500 wiederholt. Rate-Limits kommen
    aber als 429 bzw. bei GitHub als 403 mit Retry-After-Header und
    fielen komplett durch das Raster: Eine gedrosselte Existenzpruefung
    lieferte "nicht 200" -> das Skript hielt das Projekt fuer nicht
    vorhanden -> Anlage scheiterte -> Repo fehlte im Ziel.

  FIX K) KOLLISIONSSICHERE GITLAB-PFADE
    sanitize_gitlab_path() bildete verschiedene Repos auf denselben
    Pfad ab ("World-ID-" und "World-ID" -> beide "World-ID"). Das
    zweite Repo pushte mit force+prune ueber das erste. Jetzt haengt
    bei jeder Aenderung ein kurzer Hash des Originalnamens an -> die
    Abbildung ist wieder eindeutig und stabil ueber alle Laeufe.

  FIX L) GIT-LFS-OBJEKTE
    `git clone --mirror` kopiert nur LFS-Pointer, nicht die Inhalte.
    fetch_lfs_objects() holt sie nach, sofern das Repo LFS nutzt.

  FIX M) ROBUSTERE GIT-UEBERTRAGUNG GROSSER REPOS
    postBuffer hochgesetzt und Kompression reduziert - beugt
    Abbruechen ("RPC failed", "early EOF") bei grossen Pushes vor.

  FIX N) DEFAULT-BRANCH IM ZIEL SETZEN
    Neu angelegte GitHub-Repos haben HEAD auf 'main'. Heisst der
    Quell-Default 'master', zeigt HEAD im Backup ins Leere und das
    Repo wirkt leer, obwohl alle Daten da sind.

  FIX O) PLATTENPLATZ-WAECHTER
    Mirror + ZIP liegen gleichzeitig auf derselben Disk (~2x
    Repogroesse). Laeuft sie voll, scheitert schon der Klon und das
    Repo fehlt in ALLEN Zielen. Wird jetzt vorher geprueft und
    geloggt.
====================================================================
"""

import hashlib
import re
import shutil
import subprocess
import time

import requests

# --------------------------------------------------------------------
# Diese Namen kommen aus backup.py. Beim Einbau des Patches direkt
# dort ersetzen; der Import hier dient nur der Eigenstaendigkeit.
# --------------------------------------------------------------------
try:
    from backup import (  # noqa: F401
        summary_log, redact, with_retry, run,
        MAX_RETRIES, RETRY_BASE_DELAY_SECONDS, GIT_TIMEOUT_SECONDS,
    )
except ImportError:  # Patch wird als Referenz gelesen, nicht importiert
    pass


# ====================================================================
#  FIX J: HTTP-Helfer mit Rate-Limit-Behandlung
# ====================================================================

RETRYABLE_STATUS = {408, 409, 425, 429, 500, 502, 503, 504}


def _retry_after_seconds(response, attempt: int) -> float:
    """
    Liest Retry-After bzw. die GitHub-/GitLab-RateLimit-Header aus und
    leitet daraus die Wartezeit ab. Fallback: exponentielles Backoff.
    """
    header = response.headers.get("Retry-After")
    if header:
        try:
            return min(float(header), 120.0)
        except ValueError:
            pass

    remaining = response.headers.get("X-RateLimit-Remaining")
    reset = response.headers.get("X-RateLimit-Reset")
    if remaining == "0" and reset:
        try:
            wait = float(reset) - time.time()
            if 0 < wait < 300:
                return wait + 1
        except ValueError:
            pass

    return min(RETRY_BASE_DELAY_SECONDS * (2 ** (attempt - 1)), 120.0)


def _is_secondary_rate_limit(response) -> bool:
    """GitHub meldet das Secondary Rate Limit als 403 mit Hinweistext im Body."""
    if response.status_code != 403:
        return False
    body = (response.text or "").lower()
    return "secondary rate limit" in body or "abuse detection" in body


def http_request(method, url, *, headers=None, params=None, json_body=None,
                 auth=None, timeout=30, description=None):
    """
    Ersetzt http_get() und http_post().
    Wiederholt jetzt auch bei 429 und bei GitHubs 403-Secondary-Limit -
    und respektiert dabei den Retry-After-Header, statt blind zu warten.
    """
    label = description or f"{method} {url}"
    last_error = None

    for attempt in range(1, MAX_RETRIES + 1):
        try:
            r = requests.request(
                method, url, headers=headers, params=params,
                json=json_body, auth=auth, timeout=timeout,
            )
        except requests.RequestException as e:
            last_error = e
            if attempt < MAX_RETRIES:
                delay = RETRY_BASE_DELAY_SECONDS * attempt
                summary_log(f"     (Netzwerkfehler bei '{label}': {e} - neuer Versuch in {delay:.0f}s)")
                time.sleep(delay)
                continue
            raise RuntimeError(redact(f"Netzwerkfehler bei '{label}': {e}"))

        if r.status_code in RETRYABLE_STATUS or _is_secondary_rate_limit(r):
            if attempt < MAX_RETRIES:
                delay = _retry_after_seconds(r, attempt)
                summary_log(f"     (HTTP {r.status_code} bei '{label}' - warte {delay:.0f}s "
                            f"und versuche erneut, Versuch {attempt}/{MAX_RETRIES})")
                time.sleep(delay)
                continue
            summary_log(f"     (HTTP {r.status_code} bei '{label}' auch nach {MAX_RETRIES} Versuchen)")

        return r

    raise RuntimeError(redact(f"Fehlgeschlagen: {label} ({last_error})"))


def http_get(url, headers=None, params=None, timeout=30, description=None):
    return http_request("GET", url, headers=headers, params=params,
                        timeout=timeout, description=description)


def http_post(url, headers=None, json_body=None, auth=None, timeout=30, description=None):
    return http_request("POST", url, headers=headers, json_body=json_body,
                        auth=auth, timeout=timeout, description=description)


def http_patch(url, headers=None, json_body=None, timeout=30, description=None):
    return http_request("PATCH", url, headers=headers, json_body=json_body,
                        timeout=timeout, description=description)


# ====================================================================
#  FIX K: kollisionssichere GitLab-Pfade
# ====================================================================

def sanitize_gitlab_path(name: str) -> str:
    """
    Wie vorher, ABER: Sobald der Name veraendert werden muss, wird ein
    kurzer, stabiler Hash des Originalnamens angehaengt. Damit koennen
    zwei verschiedene Repos nicht mehr auf denselben Pfad fallen und
    sich gegenseitig ueberschreiben.

      "World-ID-"  -> "World-ID-a3f19c"
      "World-ID"   -> "World-ID"          (unveraendert, kein Hash)
    """
    cleaned = re.sub(r"[^a-zA-Z0-9_.\-]", "-", name)
    cleaned = cleaned.strip("-_.")
    for suffix in (".git", ".atom"):
        if cleaned.lower().endswith(suffix):
            cleaned = cleaned[: -len(suffix)]
            cleaned = cleaned.strip("-_.")
    if not cleaned:
        cleaned = "repo"

    if cleaned != name:
        digest = hashlib.sha1(name.encode("utf-8")).hexdigest()[:6]
        cleaned = f"{cleaned}-{digest}".strip("-_.")

    return cleaned[:200]


# ====================================================================
#  FIX M: Git-Optionen fuer grosse Repos
# ====================================================================

GIT_BIG_REPO_OPTS = [
    "-c", "http.postBuffer=524288000",      # 500 MB statt 1 MB Default
    "-c", "http.lowSpeedLimit=1000",        # Abbruch erst bei echtem Stillstand
    "-c", "http.lowSpeedTime=300",
    "-c", "pack.threads=1",                 # weniger RAM-Spitzen auf dem Runner
    "-c", "core.compression=1",             # schneller, weniger CPU-Timeout-Risiko
]


# ====================================================================
#  FIX H + I: atomarer Push MIT Verifikation
# ====================================================================

def local_refs(bare_path) -> dict:
    """Alle Branches und Tags des lokalen Mirrors als {refname: sha}."""
    out = run(
        ["git", "--git-dir", str(bare_path), "for-each-ref",
         "--format=%(refname) %(objectname)", "refs/heads/", "refs/tags/"],
        description="lokale Refs auflisten",
    )
    refs = {}
    for line in out.splitlines():
        parts = line.strip().split(" ", 1)
        if len(parts) == 2:
            refs[parts[0]] = parts[1]
    return refs


def remote_refs(target_url_with_token: str, label: str) -> dict:
    """
    Alle Branches und Tags des ZIELS als {refname: sha}.
    Dereferenzierte Tags (^{}) werden ignoriert, damit annotierte Tags
    nicht faelschlich als Abweichung gelten.
    """
    out = run(
        ["git"] + GIT_BIG_REPO_OPTS + ["ls-remote", "--heads", "--tags", target_url_with_token],
        description=f"Refs im Ziel auflisten ({label})",
    )
    refs = {}
    for line in out.splitlines():
        parts = line.strip().split("\t")
        if len(parts) == 2 and not parts[1].endswith("^{}"):
            refs[parts[1]] = parts[0]
    return refs


def verify_refs(bare_path, target_url_with_token: str, label: str, repo_name: str) -> bool:
    """
    FIX I - der eigentlich entscheidende Baustein.

    Vergleicht Quelle und Ziel Ref fuer Ref. Meldet FEHLENDE und
    ABWEICHENDE Refs namentlich in die Zusammenfassung. Ohne diese
    Pruefung bleibt ein unvollstaendiges Backup unsichtbar - genau
    das war das Kernproblem.
    """
    src = local_refs(bare_path)
    dst = remote_refs(target_url_with_token, label)

    missing = sorted(set(src) - set(dst))
    mismatched = sorted(r for r in set(src) & set(dst) if src[r] != dst[r])

    if not missing and not mismatched:
        summary_log(f"     (VERIFIZIERT {label}: {len(src)} Refs vollstaendig und identisch)")
        return True

    if missing:
        summary_log(f"  !! UNVOLLSTAENDIG {label} bei {repo_name}: "
                    f"{len(missing)} von {len(src)} Refs FEHLEN: {', '.join(missing[:20])}"
                    + (" ..." if len(missing) > 20 else ""))
    if mismatched:
        summary_log(f"  !! ABWEICHEND {label} bei {repo_name}: "
                    f"{len(mismatched)} Refs zeigen auf anderen Commit: {', '.join(mismatched[:20])}"
                    + (" ..." if len(mismatched) > 20 else ""))
    return False


def push_branches_and_tags(bare_path, target_url_with_token: str, label: str, repo_name: str = "") -> bool:
    """
    Ersetzt die alte push_branches_and_tags().

    FIX H: --atomic. Damit gibt es keinen halb uebertragenen Zustand
    mehr. Entweder alle Refs kommen an, oder keine - und der Fehler
    ist dann eindeutig sichtbar statt als scheinbar befuelltes Repo
    getarnt.

    FIX I: Nach dem Push wird IMMER verifiziert - auch wenn der Push
    "Everything up-to-date" meldete. Denn genau dieser Fall hat
    bisher unvollstaendige Ziele als in Ordnung durchgewunken.

    Rueckgabewert: True nur, wenn Push UND Verifikation sauber sind.
    """
    summary_log(f"  -> spiegle nach {label}")
    push_ok = True

    try:
        run(
            ["git"] + GIT_BIG_REPO_OPTS + [
                "--git-dir", str(bare_path), "push", "--atomic", "--prune",
                target_url_with_token,
                "+refs/heads/*:refs/heads/*",
                "+refs/tags/*:refs/tags/*",
            ],
            description=f"push (atomar, heads+tags) nach {label}",
        )
    except RuntimeError as e:
        text = str(e).lower()
        if "up-to-date" in text:
            summary_log(f"     ({label}: bereits aktuell)")
        else:
            summary_log(f"  !! PUSH-FEHLER {label} bei {repo_name}: {e}")
            push_ok = False

    # Verifikation laeuft IMMER - auch nach fehlgeschlagenem Push,
    # damit im Protokoll steht, was tatsaechlich im Ziel liegt.
    try:
        verify_ok = verify_refs(bare_path, target_url_with_token, label, repo_name)
    except Exception as e:  # noqa: BLE001
        summary_log(f"  !! VERIFIKATION {label} bei {repo_name} nicht moeglich: {e}")
        verify_ok = False

    return push_ok and verify_ok


# ====================================================================
#  FIX L: Git-LFS-Objekte mitsichern
# ====================================================================

def fetch_lfs_objects(bare_path, source_url_with_token: str, repo_name: str):
    """
    `git clone --mirror` kopiert nur die LFS-POINTER, nicht die
    Dateiinhalte. Ohne diesen Schritt ist das Backup bei LFS-Repos
    in allen vier Zielen unvollstaendig - ohne jede Fehlermeldung.
    """
    if shutil.which("git-lfs") is None:
        return

    try:
        run(["git", "--git-dir", str(bare_path), "lfs", "fetch", "--all", source_url_with_token],
            description=f"LFS-Objekte holen ({repo_name})")
        summary_log(f"     (LFS-Objekte gesichert)")
    except RuntimeError as e:
        text = str(e).lower()
        if "not a valid" in text or "no lfs" in text or "does not appear" in text:
            return  # Repo nutzt kein LFS - voellig normal
        summary_log(f"  !! LFS-Warnung bei {repo_name}: {e}")


def push_lfs_objects(bare_path, target_url_with_token: str, label: str, repo_name: str):
    if shutil.which("git-lfs") is None:
        return
    try:
        run(["git", "--git-dir", str(bare_path), "lfs", "push", "--all", target_url_with_token],
            description=f"LFS-Objekte pushen nach {label}")
    except RuntimeError as e:
        summary_log(f"  !! LFS-Push-Warnung {label} bei {repo_name}: {e}")


# ====================================================================
#  FIX N: Default-Branch im GitHub-Ziel setzen
# ====================================================================

def sync_github_default_branch(backup_token: str, backup_owner: str,
                               name: str, source_default_branch: str):
    """
    Neu angelegte GitHub-Repos haben HEAD auf 'main'. Heisst der
    Quell-Default 'master', zeigt HEAD im Backup ins Leere - das Repo
    wirkt leer, obwohl alle Refs vorhanden sind.
    """
    if not source_default_branch:
        return
    headers = {"Authorization": f"token {backup_token}", "Accept": "application/vnd.github+json"}
    r = http_patch(
        f"https://api.github.com/repos/{backup_owner}/{name}",
        headers=headers,
        json_body={"default_branch": source_default_branch},
        description=f"Default-Branch setzen ({name})",
    )
    if r.status_code == 200:
        summary_log(f"     (Default-Branch im Backup auf '{source_default_branch}' gesetzt)")


# ====================================================================
#  FIX O: Plattenplatz-Waechter
# ====================================================================

def check_disk_space(workdir, repo_size_kb: int, repo_name: str) -> bool:
    """
    Mirror + ZIP liegen gleichzeitig auf derselben Disk, also grob
    2x Repogroesse. Laeuft sie voll, scheitert schon der Klon - und
    dann fehlt das Repo in ALLEN Zielen gleichzeitig.
    """
    try:
        usage = shutil.disk_usage(workdir if workdir.exists() else ".")
    except OSError:
        return True

    free_mb = usage.free / (1024 * 1024)
    needed_mb = (repo_size_kb / 1024) * 2.5  # Mirror + ZIP + Puffer

    if free_mb < needed_mb:
        summary_log(f"  !! ZU WENIG PLATTENPLATZ fuer {repo_name}: "
                    f"{free_mb:.0f} MB frei, ca. {needed_mb:.0f} MB noetig - Repo wird UEBERSPRUNGEN")
        return False

    if free_mb < 2048:
        summary_log(f"     (Warnung: nur noch {free_mb:.0f} MB Plattenplatz frei)")
    return True


# ====================================================================
#  ANGEPASSTE process_repo() - so wird alles zusammengesteckt
# ====================================================================

def process_repo(repo: dict, run_timestamp_suffix: str) -> bool:
    """
    Ersetzt die bisherige process_repo(). Wesentliche Aenderungen:
      - Plattenplatz wird VOR dem Klonen geprueft
      - LFS-Objekte werden mitgeholt
      - jeder Push ist atomar UND wird verifiziert
      - der Default-Branch wird im GitHub-Ziel gesetzt
      - overall_ok wird nur True, wenn die VERIFIKATION sauber war,
        nicht schon dann, wenn der Push-Befehl nicht gemeckert hat
    """
    from backup import (
        WORKDIR, SRC_GH_TOKEN,
        BACKUP_GH_TOKEN, BACKUP_GH_OWNER,
        GITLAB_TOKEN, GITLAB_NAMESPACE, GITLAB_URL,
        GITLAB2_TOKEN, GITLAB2_NAMESPACE, GITLAB2_URL,
        GDRIVE_SA_JSON, GDRIVE_FOLDER_ID,
        mirror_clone_local, cleanup_local_mirror, backup_to_drive,
        ensure_github_target_repo, ensure_gitlab_target_repo,
        create_gitlab2_dated_project,
    )

    name = repo["name"]
    default_branch = repo.get("default_branch") or ""
    size_kb = int(repo.get("size") or 0)
    summary_log(f"--- {name} (Default-Branch: {default_branch or 'unbekannt'}, ca. {size_kb / 1024:.0f} MB) ---")

    if not check_disk_space(WORKDIR, size_kb, name):
        return False

    bare_path = None
    overall_ok = True
    source_url = repo["clone_url"].replace("https://", f"https://{SRC_GH_TOKEN}@")

    try:
        bare_path = mirror_clone_local(name, source_url)
        fetch_lfs_objects(bare_path, source_url, name)
        src_ref_count = len(local_refs(bare_path))
        summary_log(f"     (Quelle enthaelt {src_ref_count} Refs)")
    except Exception as e:  # noqa: BLE001
        summary_log(f"  !! FEHLER beim Klonen von {name}: {e}")
        cleanup_local_mirror(bare_path)
        return False

    # --- Ziel 1: zweiter GitHub-Account ---
    if BACKUP_GH_TOKEN and BACKUP_GH_OWNER:
        try:
            ensure_github_target_repo(name)
            target = f"https://{BACKUP_GH_TOKEN}@github.com/{BACKUP_GH_OWNER}/{name}.git"
            if not push_branches_and_tags(bare_path, target, "GitHub-Backup-Account", name):
                overall_ok = False
            push_lfs_objects(bare_path, target, "GitHub-Backup-Account", name)
            sync_github_default_branch(BACKUP_GH_TOKEN, BACKUP_GH_OWNER, name, default_branch)
        except Exception as e:  # noqa: BLE001
            summary_log(f"  !! FEHLER (GitHub-Backup) bei {name}: {e}")
            overall_ok = False

    # --- Ziel 2: GitLab-Account #1 ---
    if GITLAB_TOKEN and GITLAB_NAMESPACE:
        try:
            safe_path = ensure_gitlab_target_repo(name)
            host = GITLAB_URL.replace("https://", "")
            target = f"https://oauth2:{GITLAB_TOKEN}@{host}/{GITLAB_NAMESPACE}/{safe_path}.git"
            if not push_branches_and_tags(bare_path, target, "GitLab-Account-#1", name):
                overall_ok = False
            push_lfs_objects(bare_path, target, "GitLab-Account-#1", name)
        except Exception as e:  # noqa: BLE001
            summary_log(f"  !! FEHLER (GitLab-Account-#1) bei {name}: {e}")
            overall_ok = False

    # --- Ziel 3: GitLab-Account #2 (datiert) ---
    if GITLAB2_TOKEN and GITLAB2_NAMESPACE:
        try:
            dated_name = f"{name}_{run_timestamp_suffix}"
            safe_dated_path = create_gitlab2_dated_project(dated_name)
            host = GITLAB2_URL.replace("https://", "")
            target = f"https://oauth2:{GITLAB2_TOKEN}@{host}/{GITLAB2_NAMESPACE}/{safe_dated_path}.git"
            if not push_branches_and_tags(bare_path, target, "GitLab-Account-#2 (datiert)", name):
                overall_ok = False
        except Exception as e:  # noqa: BLE001
            summary_log(f"  !! FEHLER (GitLab-Account-#2) bei {name}: {e}")
            overall_ok = False

    # --- Ziel 4: Google Drive ---
    if GDRIVE_SA_JSON and GDRIVE_FOLDER_ID:
        try:
            backup_to_drive(bare_path, name)
        except Exception as e:  # noqa: BLE001
            summary_log(f"  !! FEHLER (Google Drive) bei {name}: {e}")
            overall_ok = False

    cleanup_local_mirror(bare_path)

    if overall_ok:
        summary_log(f"  OK ({name}) - alle Ziele verifiziert vollstaendig")
    else:
        summary_log(f"  UNVOLLSTAENDIG ({name}) - siehe Details oben")
    return overall_ok
