# ADR-0001: Engine als Library, Interfaces als Consumer

Status: Akzeptiert (nachträglich dokumentiert, 2026-07-04)

## Kontext

Phase 1 ist ein CLI-Tool, Phase 2 ergänzt FastAPI-Backend und Dashboard. Wird die
Scan-Logik als CLI-Anwendung gebaut, muss sie für Phase 2 herausoperiert werden.

## Entscheidung

Die Scan-Engine (`nis2scan/engine/`) ist eine reine Library: kennt kein CLI, kein
HTTP, keine DB, keine Side-Effects (kein Print, kein File-Write). Zentraler
Einstieg ist `run_scan(config: ScanConfig) -> ScanResult`. CLI (Phase 1) und API
(Phase 2) sind gleichrangige Consumer. `api/` bleibt in Phase 1 ein leeres
Package als Platzhalter.

## Konsequenzen

- Checks sind stateless (Config rein, Findings raus), keine Globals/Singletons.
- Fortschrittsanzeige läuft über den EventBus, nicht über Prints in der Engine.
- Phase 2 kann die Engine unverändert einbetten.
