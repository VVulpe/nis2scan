# DoD-Status Release 0.1 (ADR-0020)

Stand: 2026-07-12. Gate-Kriterien aus ADR-0020 mit ehrlichem Ist-Stand.

| # | Kriterium | Status | Anmerkung |
|---|---|---|---|
| 1a | Checks AWS + Azure × Nr. 8/9/10 implementiert | ✅ | Sogar alle Nr. 1–10 × drei Provider (154 Checks, GCP „experimental" per ADR-0022) |
| 1b | … jeder per Integrationstest gegen echte teil-nicht-konforme Infra verifiziert | ✅ | **Abnahme-Läufe aller drei Provider grün (13.07.2026)** nach W4: AWS Run 29262668396, Azure 29263719549, GCP 29263721381 — voller Zyklus Deploy→Checks→Destroy→Nuke→Post-Verify. 14 veraltete Test-Assertions (Positivnachweis-Welle/W4) zuvor angepasst; keine Check-Defekte auf Live-Infra |
| 1c | … rechtsgeprüft im Vier-Augen-Review (ADR-0018) | ✅ | **Alle 154 Checks mit beiden Vermerken durch das Vier-Augen-Gate (13.07.2026)** — 128 Beanstandungen umgesetzt und nachgeprüft; nach main gemergt. `nis2umsvo_refs` als unbelegt entfernt (keine verkündete Konkretisierungs-VO existent) |
| 2 | Permissions-Generator AWS IAM + Azure RBAC | ✅ | plus GCP-Custom-Role; Graph-Permissions separat ausgewiesen |
| 3 | Attestierungs-Checkliste (MANUAL/NOT_IN_SCOPE) | ✅ | In Markdown- und PDF-Report je gescanntem Bereich (W3) |
| 4a | Markdown-/JSON-Report vollständig deutsch | ✅ | |
| 4b | `schema_version` 1.0 eingefroren | ✅ | **FREEZE 13.07.2026: 1.0.0** nach Schema-Review-Session (severity_threshold entfernt, report_profile-Marker + CheckError-Kontext + gcp_sdk_version ergänzt, Timestamps UTC-bewusst; Deprecated-Felder bleiben bis 2.0 — Gründer-Entscheid). Changelog: `docs/schema-changelog.md` |

**Fazit (Stand 13.07.2026): ALLE Gate-Kriterien aus ADR-0020 erfüllt.**
Release 0.1 ist frei: Git-Tag auf `main` → `release.yml` → PyPI
(Trusted Publishing). Launch-Kommunikation gemäß ADR-0017/0022:
AWS + Azure im Vordergrund.
