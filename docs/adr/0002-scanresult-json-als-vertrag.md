# ADR-0002: ScanResult-JSON als kanonischer Vertrag

Status: Akzeptiert (nachträglich dokumentiert, 2026-07-04)

## Kontext

Mehrere Abnehmer (Markdown/PDF-Report, spätere API, Dashboard) brauchen dieselben
Scan-Ergebnisse. Werden Reports direkt aus Check-Objekten generiert, driften
Formate auseinander und der spätere API-Vertrag entsteht ad hoc.

## Entscheidung

Jeder Scan produziert genau ein vollständiges `ScanResult`-JSON (Pydantic-Modell,
`to_json`/`from_json`). Alle Reports werden ausschließlich aus diesem JSON
generiert, nie direkt aus Check-Ergebnissen. Das JSON ist der API-Vertrag —
auch solange es noch keine API gibt.

## Konsequenzen

- JSON und Report können nicht inkonsistent sein.
- Schema-Änderungen sind Vertragsänderungen und brauchen ab Veröffentlichung
  Versionierung (Feld `schema_version` — noch festzulegen, siehe Grilling-Backlog
  Punkt 5: Finding-Identität gehört in denselben Vertrag).
- Reporter sind trivial testbar (JSON rein, Text raus).
