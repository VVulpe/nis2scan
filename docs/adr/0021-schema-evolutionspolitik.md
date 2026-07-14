# ADR-0021: Schema-Evolutionspolitik für den ScanResult-Vertrag

Status: Akzeptiert (2026-07-05, Grilling-Runde 5)

> **Freeze vollzogen (2026-07-13):** Schema-Review-Session durchgeführt,
> `schema_version` = **1.0.0**. Änderungen und der Deprecated-Bestand
> (score_percent/overall_status — Entfernung in 2.0) sind in
> `docs/schema-changelog.md` dokumentiert. Ab jetzt gelten die
> untenstehenden SemVer-Regeln verbindlich.

Ab `schema_version` 1.0 (Freeze mit Release 0.1, ADR-0020) ist das ScanResult-JSON
ein öffentlicher Vertrag. Damit spätere Migrationen billig bleiben:

- **SemVer für `schema_version`.** Minor-Versionen sind ausschließlich **additiv**:
  neue, optionale Felder — nie umbenennen, nie entfernen, nie Bedeutung ändern.
- **Tolerante Leser:** Alle Konsumenten (Reporter, spätere API) ignorieren
  unbekannte Felder, statt sie abzulehnen. Unbekannte Enum-Werte (aus neueren
  Minors) werden sichtbar als „unbekannt — neuere Schema-Version" gerendert,
  nie stillschweigend verschluckt und nie als Crash (fail-safe, ADR-0016).
- **Breaking Changes = Major** mit dokumentiertem Migrationspfad;
  `ScanResult.from_json` liest mindestens die Vorgänger-Major-Version
  (N−1-Garantie), damit gespeicherte Scan-Historien lesbar bleiben.
- **Vor dem 1.0-Freeze** eine dedizierte Schema-Review-Session gegen die bekannten
  Phase-2-Bedürfnisse (DB-Persistenz, Trend-Tracking über finding_key,
  Export-Profile), damit absehbare Felder von Anfang an drin oder als optional
  vorgesehen sind — das ist der billigste Zeitpunkt, Migrationsaufwand zu
  vermeiden.

## Konsequenz

Ein `schema_version`-Bump ist Teil des Release-Reviews: Jede PR, die Modelle in
`engine/models/` ändert, muss deklarieren, ob sie additiv (minor) oder breaking
(major) ist.
