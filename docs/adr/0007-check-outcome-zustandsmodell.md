# ADR-0007: Check-Outcome-Zustandsmodell statt `skipped: bool`

Status: Akzeptiert (2026-07-04, Grilling-Runde 1)

Ein Auditor behandelt „bestanden", „durchgefallen", „nicht anwendbar", „nur manuell
prüfbar", „Prüfung gescheitert" und „bewusst ausgeschlossen" jeweils unterschiedlich;
`skipped: bool` konnte vier davon nicht ausdrücken. Jeder Check-Lauf endet deshalb in
genau einem von sechs Outcomes:

| Outcome | Bedeutung |
|---|---|
| `PASSED` | ≥ 1 Prüfobjekt, alle Findings konform |
| `FAILED` | ≥ 1 Mangel |
| `NOT_APPLICABLE` | keine Prüfobjekte dieses Typs in der Umgebung |
| `MANUAL_REQUIRED` | nicht automatisierbar → erzeugt Attestierungspunkte |
| `ERROR` | Prüfung gescheitert (API/Permissions), Ergebnis unbekannt |
| `NOT_IN_SCOPE` | per Config ausgeschlossen |

Das Outcome wird deterministisch aus Findings und Fehlern abgeleitet, nie unabhängig
gesetzt — Inkonsistenz zwischen Outcome und Findings ist damit konstruktiv unmöglich.
`ERROR` erscheint immer sichtbar im Report, niemals stillschweigend.

## Verworfene Alternative

`NOT_APPLICABLE` als Bestehen werten (so machen es manche CSPM-Tools). Verworfen:
„kein RDS vorhanden" ist kein Nachweis für ein Backup-Konzept — der Auditor muss die
Nicht-Anwendbarkeit selbst beurteilen können.
