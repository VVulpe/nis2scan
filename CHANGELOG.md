# Changelog

Alle nennenswerten Änderungen an nis2scan werden hier dokumentiert. Das Format
orientiert sich an [Keep a Changelog](https://keepachangelog.com/de/1.1.0/).
Die vollständige Commit-Historie und die Release-Artefakte (Wheels, sdists)
stehen in den [GitHub Releases](https://github.com/letaible/nis2scan/releases).

## Unveröffentlicht

### Geändert

- Deutlich weniger Cloud-API-Aufrufe pro Scan: Die Provider-Session wird
  einmal pro Scan statt einmal pro Check aufgebaut (spart bei AssumeRole
  und Subscription-/Projekt-Erkennung bis zu rund 50 Netzwerk-Aufrufe pro
  Provider), und die AWS-Konto-ID wird pro Session zwischengespeichert
  (spart bis zu 180 STS-Aufrufe pro Scan).
- GCP-NR4-001: Der Evidence-Schlüssel für projektfremde IAM-Mitglieder
  heißt jetzt `external_member_email` statt `external_members_sample`,
  damit das Extern-Report-Profil diese Werte zuverlässig pseudonymisiert.
  Prüftexte und Prüflogik sind unverändert (Delta-Rechtsreview, siehe
  `docs/rechtsgrundlagen-review.md`).
- CI misst jetzt Testabdeckung und prüft das gebaute Paket zusätzlich über
  einen CLI-Smoke-Test (Installation aus dem Wheel, Exit-Code-Prüfungen).

### Dokumentation

- Neue Anleitung `docs/gcp-zugang.md`; Findings-Exceptions und die
  Exit-Codes sind jetzt in `docs/getting-started.md` dokumentiert; drei
  fehlerhafte Kommandos im README korrigiert; dieses CHANGELOG ergänzt.

## 0.1.5 - 2026-07-24

### Hinzugefügt

- Findings-Exceptions (ADR-0026): dokumentierte, befristete Ausnahmen für
  Befunde, die eine Einrichtung bewusst nicht sofort beheben will. Neue
  YAML-Ausnahmen-Datei über das CLI-Flag `--exceptions`. Eine Ausnahme
  löscht einen Befund nicht: er bleibt sichtbar, zählt in allen bestehenden
  Kennzahlen weiter voll als Mangel und erscheint zusätzlich in einer
  eigenen Report-Sektion mit Vermerk, Frist und Autor. Nach Ablauf der
  Frist zählt der Befund automatisch wieder uneingeschränkt. Schema 1.1.0
  (rein additiv, siehe `docs/schema-changelog.md`).

### Behoben

CLI-Fail-safe-Hotfix, mehrere seit 0.1.0 bestehende Fehler:

- `--profile` wirkte sich seit der ersten Version nie aus: eine intern
  gleichnamige Variable überschrieb den AWS-Profilnamen, jeder CLI-Scan lief
  effektiv ohne das gewählte Profil.
- Exit-Code 3 für einen nicht aussagekräftigen Scan: endeten ausschließlich
  Checks mit Fehlern und konnte kein einziger Check erfolgreich (bestanden
  oder nicht bestanden) ausgewertet werden, meldete der Scan bisher
  fälschlich Exit-Code 0.
- `--provider` wird jetzt gegen `aws`/`azure`/`gcp` geprüft; ein Tippfehler
  lieferte vorher stillschweigend einen leeren 0/0-Report bei Exit-Code 0.
- stdout/stderr werden beim Start auf UTF-8 umgestellt, damit Umlaute und §
  auf Windows-Konsolen auch ohne gesetztes `PYTHONUTF8` korrekt erscheinen.

## 0.1.4 - 2026-07-14

### Geändert

- msgraph-sdk vollständig abgelöst: alle Microsoft-Graph-Aufrufe laufen
  jetzt über eine eigene REST-Schicht (`nis2scan/engine/providers/azure/graph.py`).
  Das entfernt rund 25.000 Dateien und 26 MB an Abhängigkeiten, wodurch
  `pip install nis2scan` in einem Standard-Windows-venv auch ohne
  `LongPathsEnabled` funktioniert.
- Die Paketversion wird jetzt ausschließlich in `nis2scan/__init__.py`
  gepflegt; `pyproject.toml` liest sie dynamisch über Hatch. Vorher meldeten
  `nis2scan --version` und der Plugin-Loader ab 0.1.1 fälschlich weiterhin
  0.1.0.

## 0.1.3 - 2026-07-14

### Behoben

- AZ-NR9-007 (verwaiste Service Principals) auf den Microsoft-Graph-Beta-
  Report `servicePrincipalSignInActivities` per direktem REST-Zugriff
  umgestellt. Das bisher gelesene SDK-Attribut existiert im aktuellen
  msgraph-sdk nicht mehr, wodurch der Check nie ein Ergebnis lieferte,
  sondern immer mit einem Laufzeitfehler endete. Erster Schritt der neuen
  Graph-REST-Schicht, die in 0.1.4 vollständig ausgebaut wurde.

## 0.1.2 - 2026-07-14

### Behoben

- Projekt-Links in der README für die PyPI-Projektbeschreibung korrigiert:
  PyPI löst repo-relative Links (`docs/`, `LICENSE`) nicht auf, jetzt
  absolute GitHub-URLs. Tote `nis2scan.de`-Links durch einen ehrlichen
  Hinweis "in Vorbereitung" mit Kontakt über GitHub Issues ersetzt.

## 0.1.1 - 2026-07-14

### Behoben

- Azure-Laufzeitbruch bei frischen Installationen behoben: ab
  azure-mgmt-resource 26 fehlt der Top-Level-Re-Export, sodass
  `from azure.mgmt.resource import ResourceManagementClient` mit einem
  ImportError scheiterte und sieben Check-Module nur noch einen CheckError
  statt eines Ergebnisses lieferten. Import jetzt über den stabilen
  Submodul-Pfad `azure.mgmt.resource.resources`.

## 0.1.0 - 2026-07-14

Erstveröffentlichung.

### Hinzugefügt

- 154 Checks über AWS, Azure und GCP, verteilt auf alle 10 Bereiche von §30
  Abs. 2 BSIG.
- Rechts-Mapping jedes Findings auf §30 BSIG und ISO 27001:2022.
- JSON- und Markdown-Reports in den Profilen `intern` (Klardaten) und
  `extern` (pseudonymisierte Identifier, ADR-0011).
- Attestierungs-Checkliste.
- Permissions-Generator (`nis2scan permissions`) für minimale IAM-/RBAC-
  Policies je Cloud-Provider.
