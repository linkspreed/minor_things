# GitHub Repo Super-Backup (öffentlich, minimale Logs, per E-Mail benachrichtigt)

Spiegelt automatisch **alle** Repos deines GitHub-Accounts (volle
Commit-Historie, alle Branches, alle Tags) zweimal täglich nach:

1. einem **zweiten GitHub-Account**
2. **GitLab**
3. **Google Drive** (als ZIP mit dem kompletten `.git`-Ordner)

**Bitbucket ist bewusst NICHT enthalten:** Bitbucket hat seinen
kostenlosen Plan seit April 2025 auf nur **1 GB Speicher für den
gesamten Workspace** begrenzt — nicht pro Repo, sondern summiert über
alle Repos zusammen. Bei 155+ teils großen Repos wäre das nahezu
garantiert sofort ausgeschöpft und würde zu Zahlungsaufforderungen
oder blockierten Pushes führen.

Dieses Steuerungs-Repo (das hier, mit Skript + Workflow) ist als
**öffentlich** gedacht, damit die Actions-Minuten unbegrenzt und
kostenlos sind. Damit dabei trotzdem **niemand** sehen kann, welche
Repos du hast:

- Die Konsole (= öffentlich sichtbares Actions-Log) zeigt nur neutrale
  Zeilen wie `... Verarbeite Repo 3/155 ...` — nie einen echten Namen.
- Alle Details (Namen, Fehler, Erfolge) landen ausschließlich in einer
  E-Mail, die nach **jedem** Lauf verschickt wird (egal ob Erfolg oder
  Fehler) — nirgendwo sonst.
- Es wird **nichts** ins Repo zurückgeschrieben und **kein**
  Actions-Artifact hochgeladen (Artifacts sind bei öffentlichen Repos
  für jeden herunterladbar — deshalb bewusst nicht genutzt).
- Sogar die **Ziel-E-Mail-Adresse** ist ein Secret, genau wie ein
  API-Key — sie steht nirgendwo im Klartext in diesem Repo.

---

## Warum kein Google Apps Script? Warum GitHub Actions?

Apps Script hat kein Git installiert und ein hartes 6-Minuten-Limit
pro Lauf (unabhängig vom Google-Konto) — für 150+ teils große Repos
nicht praktikabel. GitHub Actions stellt einen echten Linux-Server mit
Git zur Verfügung und läuft, genau wie Apps Script, zeitgesteuert und
automatisch in der Cloud, ohne dass du etwas anklicken musst.

## Warum Linux-Runner und nicht Mac (obwohl "stärker" klingt)?

Ist es nicht. Die Standard-Runner-Hardware (Stand 2026):

| Runner | CPU-Kerne | RAM | SSD |
|---|---|---|---|
| **Linux (`ubuntu-latest`)** | **4** | **16 GB** | 14 GB |
| Windows (`windows-latest`) | 4 | 16 GB | 14 GB |
| macOS Intel (`macos-15-intel`) | 4 | 14 GB | 14 GB |
| macOS Apple Silicon (`macos-latest`) | nur 3 | nur 7 GB | 14 GB |

Linux ist bereits das stärkste kostenlose Angebot, dazu die natürliche
Wahl für Git/Bash. Der eigentliche Engpass ist bei **allen** Runnern
gleich: nur **14 GB SSD**, unabhängig vom Betriebssystem. Deshalb klont
dieses Skript jedes Repo einzeln, spiegelt es, und löscht es danach
sofort wieder von der Festplatte — so reicht der Platz auch bei sehr
vielen/großen Repos, egal wie sehr die Zahl 155 noch wächst.

## Limits, die auf öffentlichen Repos trotzdem gelten

Unbegrenzt sind nur die **Minuten** der Standard-Runner. Diese harten
technischen Grenzen bleiben (public wie private):

| Limit | Wert |
|---|---|
| Max. Laufzeit pro Job | 6 Stunden |
| Max. Laufzeit ganzer Workflow | 35 Tage |
| API-Anfragen an GitHub | 1.000/Stunde/Repo |
| Gleichzeitige Jobs (Free-Plan) | 20 |
| Festplatte pro Runner | 14 GB SSD |

Für 2× täglich mit sequentieller Verarbeitung (klonen → spiegeln →
löschen, Repo für Repo) ist das bei 155 Repos in aller Regel kein
Problem — nur der aller erste Lauf kann je nach Gesamtgröße deiner
Repos eine Weile dauern.

## Ziel-Limits bei GitHub und GitLab (Free-Plan)

- **GitHub:** Unbegrenzt viele private Repos im kostenlosen Plan —
  kein praktisches Limit für dein Vorhaben.
- **GitLab:** 10 GiB Speicher **pro einzelnem Projekt** (nicht
  summiert über alle Repos), max. 5 Nutzer pro Namespace. Da du allein
  Zugriff brauchst und nur einzelne, nicht alle Repos zusammen unter
  10 GB bleiben müssen, ist das für dich in aller Regel unkritisch.
  Falls du extra für dieses Backup einen neuen GitLab-Account anlegst:
  Repos direkt im **persönlichen Namespace** anlegen, nicht in einer
  Gruppe (neue Accounts ab 27.1.2026 sind auf 3 Top-Level-Gruppen
  begrenzt — betrifft dich nicht, wenn du im persönlichen Namespace
  bleibst).

---

# Komplette Einrichtung, Schritt für Schritt

## Schritt 0: Dieses Steuerungs-Repo anlegen

1. Auf GitHub ein **neues Repository** anlegen, z. B. `repo-backup-runner`.
   Sichtbarkeit vorerst **Private** lassen (wird erst ganz am Ende auf
   Public gestellt, siehe Schritt 6).
2. Die Dateien aus diesem Projekt hochladen: `backup_repos.py`,
   `requirements.txt`, `.github/workflows/backup.yml`. (`.env.example`
   ist nur eine Vorlage/Dokumentation, nicht zwingend nötig im Repo.)

## Schritt 1: Quelle konfigurieren (dein Haupt-GitHub-Account)

1. Gehe zu **GitHub → Settings → Developer settings → Personal access
   tokens → Fine-grained tokens → Generate new token**.
2. Repository access: "All repositories" (damit alle 155 erfasst werden).
3. Permissions: **Contents: Read-only** reicht hier (wir lesen nur).
4. Token kopieren.
5. Im Steuerungs-Repo unter **Settings → Secrets and variables →
   Actions**:
   - Secret `GITHUB_SOURCE_TOKEN` = der eben erstellte Token
   - Variable `GITHUB_SOURCE_OWNER` = dein Benutzername (oder Org-Name)
   - Variable `GITHUB_SOURCE_OWNER_TYPE` = `user` (oder `org`, falls
     die Repos in einer Organisation liegen)

## Schritt 2: Ziel 1 — Zweiter GitHub-Account

1. Bei deinem **zweiten** GitHub-Account einloggen.
2. Dort ebenfalls unter Settings → Developer settings ein Fine-grained
   Token erstellen — Permissions: **Contents: Read and write**,
   **Administration: Read and write** (damit das Skript neue Repos
   anlegen darf).
3. Im Steuerungs-Repo:
   - Secret `GITHUB_BACKUP_TOKEN` = dieser Token
   - Variable `GITHUB_BACKUP_OWNER` = Benutzername des zweiten Accounts
   - Variable `GITHUB_BACKUP_OWNER_TYPE` = `user`

## Schritt 3: Ziel 2 — GitLab

1. In GitLab: **Avatar → Edit profile → Access Tokens**.
2. Neuen Token erstellen mit Scope **`api`**.
3. Im Steuerungs-Repo:
   - Secret `GITLAB_TOKEN` = dieser Token
   - Variable `GITLAB_NAMESPACE` = dein GitLab-Benutzername (oder
     Gruppen-Pfad, falls die Repos in eine Gruppe sollen)
   - Variable `GITLAB_URL` = `https://gitlab.com` (oder deine
     Selbst-gehostete GitLab-URL)

## Schritt 4: Ziel 3 — Google Drive

1. In der [Google Cloud Console](https://console.cloud.google.com) ein
   Projekt anlegen (oder ein vorhandenes nutzen) und die **Drive API**
   aktivieren.
2. Unter **IAM & Verwaltung → Dienstkonten** ein neues Dienstkonto
   anlegen → **Schlüssel → Neuer Schlüssel → JSON** → Datei herunterladen.
3. In Google Drive einen Ordner für die Backups anlegen. Da du einen
   **Google-Workspace-Account** hast: Am einfachsten in einer
   **geteilten Ablage (Shared Drive)** anlegen — dort funktioniert der
   Dienstkonto-Zugriff zuverlässiger als in "Meine Ablage".
4. Diesen Ordner **mit der E-Mail-Adresse des Dienstkontos teilen**
   (steht in der JSON-Datei als `client_email`), Rolle: **Bearbeiter**.
5. Die Ordner-ID aus der URL kopieren (`.../folders/DIESE_ID_HIER`).
6. Im Steuerungs-Repo:
   - Secret `GDRIVE_SA_JSON` = **kompletter Inhalt** der JSON-Datei
     (die ganze Datei als Text reinkopieren)
   - Variable `GDRIVE_FOLDER_ID` = die Ordner-ID

## Schritt 4b: E-Mail-Benachrichtigung einrichten

Empfehlung: ein **Gmail-Konto mit App-Passwort** (funktioniert auch mit
jedem anderen SMTP-Anbieter, z. B. Outlook/deinem eigenen Mailserver).

1. Bei Gmail: **Zwei-Faktor-Authentifizierung aktivieren** (falls noch
   nicht geschehen), dann unter **Google-Konto → Sicherheit → App-
   Passwörter** ein neues App-Passwort erstellen.
2. Im Steuerungs-Repo:
   - Secret `MAIL_CONNECTION_URL` = `smtp://DEINE-ADRESSE@gmail.com:APP_PASSWORT@smtp.gmail.com:465`
     (ersetze `DEINE-ADRESSE` und `APP_PASSWORT` durch deine echten Werte)
   - Secret `NOTIFY_EMAIL` = die Adresse, an die die Benachrichtigung
     gehen soll (kann dieselbe oder eine andere sein — **auch das ist
     ein Secret**, damit sie im öffentlichen Repo nicht sichtbar ist)

## Schritt 5: Testen (Repo bleibt noch privat)

1. Im Steuerungs-Repo → Tab **Actions** → Workflow "Repo Super-Backup"
   → **Run workflow** (manueller Start).
2. Prüfe: Kommt eine E-Mail an? Steht darin die erwartete Anzahl
   Repos, ok/Fehler? Falls Fehler auftauchen, stehen die Details in der
   E-Mail (nicht im Actions-Log).
3. Erst wenn das zuverlässig funktioniert: weiter zu Schritt 6.

## Schritt 6: Repo auf "Public" stellen

1. Im Steuerungs-Repo: **Settings → General → Danger Zone → Change
   visibility → Make public**.
2. Ab sofort: unbegrenzte, kostenlose Actions-Minuten. Die Konsole
   zeigt weiterhin nur anonyme Zahlen, alle Details kommen nur noch
   per E-Mail.
3. **Wichtige Sicherheitsregel:** Aktiviere in den Repo-Einstellungen
   am besten **keine** Issues/Pull Requests von Fremden (oder
   deaktiviere sie ganz unter Settings → General), damit niemand
   versucht, über einen Pull Request Änderungen am Workflow
   einzuschleusen. Der Workflow reagiert ohnehin nur auf `schedule`
   und `workflow_dispatch` (nicht auf `pull_request`), das Risiko ist
   also ohnehin gering.

---

## Was passiert bei jedem Lauf, im Detail

1. Holt sich über die GitHub-API die Liste **aller** Quell-Repos (inkl.
   Pagination, funktioniert auch bei 1000+ Repos).
2. Für jedes Repo, **einzeln nacheinander**:
   - `git clone --mirror` — kompletter frischer Klon (Historie, alle
     Branches/Tags).
   - Legt bei jedem aktivierten Ziel (GitHub/GitLab) das Ziel-Repo an,
     **falls es noch nicht existiert** — danach nur noch
     `git push --mirror` (überträgt alles 1:1, inkl. gelöschter
     Branches).
   - Bei Google Drive: packt den `.git`-Ordner in eine ZIP-Datei,
     löscht die alte Version im Zielordner, lädt die neue hoch.
   - Löscht danach sofort den lokalen Mirror-Ordner wieder (wegen der
     14-GB-Festplattengrenze).
3. Sammelt währenddessen ein **vollständiges** Protokoll (nur im
   Arbeitsspeicher/lokal auf dem Runner, nie auf der Konsole sichtbar).
4. Am Ende: eine E-Mail mit Zusammenfassung (Anzahl ok/Fehler,
   betroffene Repo-Namen bei Fehlern, komplettes Detail-Protokoll) wird
   **immer** verschickt — auch wenn mittendrin ein schwerer Fehler
   auftrat.

## Ehrliche Grenzen, die du kennen solltest

- **Kein 100%iges Garantie-Versprechen bei Fremd-Actions:** Die
  E-Mail-Versand-Action (`dawidd6/action-send-mail`) ist ein
  Drittanbieter-Tool. Sie loggt nach aktuellem Stand keine Mail-Inhalte
  in die Konsole — ich kann das aber nicht zu 100 % für alle Zukunft
  garantieren, da es fremder Code ist. Teste einmal mit einem
  unkritischen Test-Repo-Namen, bevor du dich darauf verlässt.
- **Erster Lauf dauert am längsten**, weil alle Repos komplett neu
  geklont werden (kein Cache mehr, siehe oben). Das ist bei
  unbegrenzten Minuten aber unkritisch.
- **Google Drive Dateigröße:** Bei Repos mit sehr vielen GB an Git-LFS-
  Objekten können die ZIP-Dateien entsprechend groß werden.
- Gelöschte Quell-Repos werden **nicht automatisch** aus den
  Backup-Zielen entfernt (bewusst so — ein Backup soll nichts
  automatisch löschen, das nicht ausdrücklich gewollt ist).
- **Bitbucket ist nicht enthalten** (siehe Begründung ganz oben). Falls
  du es später doch willst: technisch möglich, aber du müsstest dann
  entweder einen kostenpflichtigen Bitbucket-Plan nutzen oder nur eine
  Teilmenge kleinerer Repos dorthin spiegeln.
