# ADR-0014: Premium-Code in separatem privatem Repo

Status: Akzeptiert (2026-07-04, Grilling-Runde 3)

Der frühere Plan im nis2-licensing-Skill („Model 1 — Single Repo, Feature Flags")
kollidierte mit ADR-0005: Ein `premium/`-Verzeichnis unter Apache 2.0 darf jeder
Fork legal um die `require()`-Zeile erleichtern und das Ergebnis kommerziell
vertreiben. Deshalb:

Premium-Code lebt in einem **separaten privaten Repository** (`nis2scan-premium`)
und wird Lizenzkunden als installierbares Plugin-Package ausgeliefert, das das
freie CLI erweitert. Das öffentliche Repo enthält keinerlei Premium-Code und keine
Paywall-Logik außer dem Plugin-Loader — ein Fork kann keine Paywall entfernen,
weil dort keine ist.

## Verworfene Alternativen

- **Feature-Flags im Apache-Repo** (ursprünglicher Skill-Plan): per Fork trivial
  entfernbar.
- **GitLab-Modell** (ein Repo, `premium/` unter kommerzieller Zweitlizenz):
  rechtlich tragfähig, aber verwechslungsanfällig (Beiträge/Vendoring landen
  „versehentlich" unter Apache-Annahme) und erklärungsbedürftig gegenüber der
  Community.

## Konsequenzen

- Plugin-Mechanik ist zu entwerfen: Entry-Points, Distribution an Lizenzkunden,
  Versionskopplung frei ↔ premium (Backlog, Runde 4).
- Korrekturen am Licensing-Entwurf: `LicenseManager` ist kein globales Singleton
  (CLAUDE.md-Regel) — im CLI-Entrypoint konstruieren und injizieren; die
  Offline-Signaturprüfung ist asymmetrisch (Ed25519) zu implementieren, ein
  Platzhalter `return True` darf nie ausgeliefert werden.
