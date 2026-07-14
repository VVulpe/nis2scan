# Schema-Changelog — ScanResult-JSON-Vertrag (ADR-0021)

Jede Änderung an Modellen in `nis2scan/engine/models/` wird hier deklariert:
additiv (Minor) oder breaking (Major). Ab 1.0.0 gilt SemVer strikt.

## 1.0.0 — 2026-07-13 (FREEZE, Release 0.1)

Dedizierte Schema-Review-Session (ADR-0021) gegen die Phase-2-Bedürfnisse
(DB-Persistenz, Trend-Tracking über `finding_key`, Export-Profile).
Änderungen gegenüber 0.9.0 (pre-1.0, breaking erlaubt):

**Entfernt:**
- `ScanConfig.severity_threshold` — tote Config, wurde nie angewendet
  (Audit-Befund zu ADR-0008). Unbekannte Schlüssel in geladenen Configs
  werden von Pydantic ignoriert; alte Payloads bleiben ladbar.
- `Finding.nis2umsvo_ref` — totes Feld (wurde von keinem Check gesetzt,
  stets `null`); die referenzierte Verordnung existiert nicht als
  verkündete Norm (Rechts-Review 2026-07-13, beide ADR-0018-Vermerke).

**Neu (optional/mit Default):**
- `ScanResult.report_profile` (`"intern"` | `"extern"`, Default `"intern"`) —
  Export-Profil-Marker (ADR-0011): gespeichertes/exportiertes JSON ist jetzt
  selbstbeschreibend; gesetzt durch `reporting.pseudonymize.apply_profile`.
- `CheckError.check_id`, `CheckError.region` (optional) — Kontextfelder;
  wurden von Checks bereits übergeben, aber vom Modell still verworfen.
- `ScanMetadata.gcp_sdk_version` (optional) — Parität zu boto3/azure.

**Geändert:**
- `ScanResult.scan_timestamp` ist jetzt zeitzonenbewusst (UTC, ISO-8601 mit
  Offset) statt naiv (`datetime.utcnow()` entfernt).

**Beibehalten als DEPRECATED (Gründer-Entscheid 2026-07-13):**
- `ComplianceScore.score_percent`, `ComplianceSummary.overall_status`,
  `ComplianceSummary.overall_score_percent` — abgeleitete Werte, das
  SaaS-Repo nutzt sie noch (DB-Spalten, Router). Maßgeblich sind
  `erfuellungsgrad`/`erfuellungsgrad_gesamt` (ADR-0008).
  **Entfernung fest eingeplant für Schema 2.0** (Breaking, mit
  Migrationspfad nach ADR-0021).

## 0.9.0 — Vertragsstand der W1-Vertrags-Welle (2026-07)

Basis: Outcome-Modell (ADR-0007), Positivnachweise (ADR-0006),
Erfüllungsgrad (ADR-0008), `finding_key` (ADR-0010), Prüfgrenzen und
NA-Transparenz (ADR-0016), Rechtsstand-Versionierung (ADR-0013).
