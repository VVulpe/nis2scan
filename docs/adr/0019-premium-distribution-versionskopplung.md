# ADR-0019: Premium-Distribution, Rollout und Versionskopplung

Status: Akzeptiert (2026-07-05, Grilling-Runde 4)

Konkretisierung von ADR-0014 (Premium in separatem privatem Repo):

- **Discovery:** Das freie CLI findet Premium-Funktionen über Python-Entry-Points
  (Gruppe `nis2scan.plugins`). Ohne installiertes Plugin existiert im freien Code
  nur der Loader.
- **Distribution:** Zwei gleichwertige Wege für Lizenzkunden — `pip install` aus
  einem privaten Package-Index (Zugriff per Lizenz-Token) und ein herunterladbares
  Wheel (für Umgebungen mit restriktivem Outbound-Internet, typisch Mittelstand).
- **Automatischer Rollout:** CI/CD-Pipeline (GitHub Actions) veröffentlicht bei
  jedem Git-Tag automatisch: freies Package → PyPI; Premium-Package → privater
  Index + Wheel-Artefakt im Kundenportal. Kein manuelles Bauen. Beim Kunden gibt
  es bewusst **keine** Auto-Updates — der Mittelstand will kontrollierte Rollouts.
- **Versionskopplung:** Das Premium-Plugin pinnt eine kompatible Minor-Range des
  freien Pakets (`nis2scan>=X.Y,<X.Y+1`, SemVer). Der Plugin-Loader prüft die
  Kompatibilität beim Laden und bricht mit einer klaren deutschen Fehlermeldung
  ab („Premium-Plugin 0.2 benötigt nis2scan 0.4.x — bitte aktualisieren"), statt
  zur Laufzeit zu crashen. Frei- und Premium-Releases laufen durch dieselbe
  Pipeline, damit kompatible Paare immer gemeinsam erscheinen.

## Konsequenzen

- Die Release-Pipeline ist Teil des MVP-Aufwands (einmalig aufsetzen, dann
  automatisch), inkl. Signierung der Artefakte.
- Support-Fälle „Version passt nicht" enden in einer verständlichen Meldung
  statt in Stacktraces.
