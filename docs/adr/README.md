# Architecture Decision Records

Format: kurz (Kontext → Entscheidung → ggf. Konsequenzen), fortlaufend nummeriert.
Entscheidungen werden in Grilling-Sessions geprüft, bevor sie hier landen.
Domänensprache: siehe [CONTEXT.md](../../CONTEXT.md).

## Index

| ADR | Titel | Status |
|---|---|---|
| [0001](0001-engine-als-library.md) | Engine als Library, Interfaces als Consumer | Akzeptiert (nachträglich dokumentiert) |
| [0002](0002-scanresult-json-als-vertrag.md) | ScanResult-JSON als kanonischer Vertrag | Akzeptiert (nachträglich dokumentiert) |
| [0003](0003-scanner-strikt-read-only.md) | Scanner strikt read-only | Akzeptiert (nachträglich dokumentiert) |
| [0004](0004-sprachtrennung-code-output.md) | Sprachtrennung: Code Englisch, Output Deutsch | Akzeptiert (nachträglich dokumentiert) |
| [0005](0005-open-core-apache-2.md) | Open Core unter Apache 2.0 | Akzeptiert (nachträglich dokumentiert) |
| [0006](0006-finding-als-bewertete-feststellung.md) | Finding als bewertete Feststellung, nicht nur Mangel | Akzeptiert (Runde 1) |
| [0007](0007-check-outcome-zustandsmodell.md) | Check-Outcome-Zustandsmodell statt `skipped: bool` | Akzeptiert (Runde 1) |
| [0008](0008-erfuellungsgrad-statt-score.md) | Erfüllungsgrad statt Prozent-Score; Report ungefiltert | Akzeptiert (Runde 1) |
| [0009](0009-abdeckungsmodell-teilaspekt.md) | Report bewertet nur den cloud-technischen Teilaspekt | Akzeptiert (Runde 1) |
| [0010](0010-finding-fingerprint.md) | Stabiler Finding-Fingerprint ab Phase 1 | Akzeptiert (Runde 2) |
| [0011](0011-pseudonymisierung-als-export-konzept.md) | Pseudonymisierung als Export-Konzept; Evidence als Allow-List-Extrakt | Akzeptiert (Runde 2) |
| [0012](0012-keine-betroffenheitspruefung.md) | Keine Betroffenheitsprüfung — Kategorie ist Selbsteinstufung | Akzeptiert (Runde 2) |
| [0013](0013-rechtsstand-versionierung.md) | Rechtsstand-Versionierung des Mappings | Akzeptiert (Runde 2) |
| [0014](0014-premium-in-separatem-repo.md) | Premium-Code in separatem privatem Repo | Akzeptiert (Runde 3) |
| [0015](0015-rechts-mapping-bleibt-frei.md) | Rechts-Mapping bleibt dauerhaft frei | Akzeptiert (Runde 3) |
| [0016](0016-fail-safe-ergebnispolitik.md) | Fail-Safe-Ergebnispolitik — im Zweifel nie PASSED | Akzeptiert (Runde 3) |
| [0017](0017-mvp-release-schnitt.md) | Release-Schnitt: 0.1 = AWS + Azure × Nr. 8/9/10 | Akzeptiert (Runde 5, Option B) |
| [0018](0018-rechtsgrundlagen-review.md) | Rechtsgrundlagen-Review mit Quellenpflicht | Akzeptiert (Runde 4) |
| [0019](0019-premium-distribution-versionskopplung.md) | Premium-Distribution, Rollout und Versionskopplung | Akzeptiert (Runde 4) |
| [0020](0020-definition-of-done-0-1.md) | Launch-Definition & Definition of Done für 0.1 | Akzeptiert (Runde 5) |
| [0021](0021-schema-evolutionspolitik.md) | Schema-Evolutionspolitik für den ScanResult-Vertrag | Akzeptiert (Runde 5) |
| [0022](0022-gcp-experimenteller-provider.md) | GCP als experimenteller Provider | Akzeptiert (Runde 6) |
| [0023](0023-konsolidierte-feature-matrix.md) | Konsolidierte Feature-Matrix | Akzeptiert (Runde 6) |
| [0024](0024-m365-provider.md) | Microsoft 365 als vierter Provider | Akzeptiert (Chat-Grilling 23.07.2026) |
| [0025](0025-meldehilfe-p32.md) | Meldehilfe für §32 BSIG (PRO) | Akzeptiert (Chat-Grilling 23.07.2026) |
| [0026](0026-findings-exceptions.md) | Ausnahmen für Findings (FREE) | Akzeptiert (Chat-Grilling 23.07.2026) |

## Offene Entscheidungen (Grilling-Backlog)

1. **GTM-Timeline neu schneiden** — der 30-Tage-Plan ist durch ADR-0017/0020
   obsolet; neuer Plan mit Build-in-Public-Start, Design-Partner-Meilenstein
   (2–3 Pilotkunden vor 0.1, Kanäle: IHK/LinkedIn) und Launch bei 0.1. (Runde 6)
2. **Geschäftsform & Haftungsrahmen** — VERTAGT auf Gründer-Entscheid: erst bei
   Aussicht auf ersten zahlenden Kunden. **Protokollierter Einwand:** Der
   richtige Trigger ist „bevor der Kaufen-Button live geht" (Gumroad-Templates!),
   nicht „nach dem ersten Kunden"; UG-Gründung und Versicherung haben Wochen
   Vorlauf. Fail-Safe (ADR-0016) und Disclaimer (ADR-0012) sind Teil der
   Risikominderung, ersetzen aber weder Haftungsschirm noch AGB noch Police.
3. **Schema-Review-Session vor 1.0-Freeze** — Pflichttermin aus ADR-0021,
   vor Release 0.1.

Erledigt in Runde 1: Finding-Semantik (→ 0006), Outcome-Zustandsmodell (→ 0007),
Score-Semantik & Report-Filterung (→ 0008), Abdeckungsanspruch (→ 0009),
Kategorie-Terminologie (→ CONTEXT.md, Anwendung von 0004).
Erledigt in Runde 2: Finding-Identität (→ 0010), Pseudonymisierung & Evidence
(→ 0011), Kategorie-Zweck (→ 0012), Rechtsstand (→ 0013).
Erledigt in Runde 3: Open-Core-Schnittlinie (→ 0014), Rechts-Mapping frei
(→ 0015), False-Positive-Politik (→ 0016), MVP-Schnitt (→ 0017, vorgeschlagen).
Erledigt in Runde 4: Offenlegung Apache bestätigt (→ 0005), Rechtsgrundlagen-Review
(→ 0018, inkl. Skill `nis2-legal-review`), Premium-Distribution & Versionskopplung
(→ 0019).
Erledigt in Runde 5: MVP-Schnitt Option B (→ 0017), Launch-Entkopplung & DoD 0.1
(→ 0020), Schema-Evolutionspolitik (→ 0021), Vier-Augen-Review mit Agent
`legal-reviewer` (→ 0018 erweitert), Repo-Landschaft angelegt.
