# ADR-0006: Finding als bewertete Feststellung, nicht nur als Mangel

Status: Akzeptiert (2026-07-04, Grilling-Runde 1)

Ein auditfähiger Report braucht Positivnachweise („geprüft, konform") — eine reine
Mängelliste kann nicht belegen, dass etwas in Ordnung war, und eine leere
Finding-Liste wäre mehrdeutig (konform? nicht geprüft? keine Ressourcen?).
Ein Finding ist deshalb eine bewertete Feststellung pro Check × Prüfobjekt mit
Status `compliant | non_compliant`; nur nicht-konforme Findings tragen Severity
und Remediation.

## Verworfene Alternative

Die CSPM-Konvention „Finding = Mangel" (Wiz, Prowler-Default-Sicht). Verworfen,
weil das Produktversprechen Nachweisführung ist, nicht nur Mängelsuche — und weil
das Phase-2-Verlaufstracking (open/resolved) den Statuswechsel desselben Findings
über Scans hinweg braucht, also auch den konformen Zustand kennen muss.

## Konsequenzen

- Das Phase-2-Schema trennt `compliance_status` (compliant/non_compliant) vom
  Lebenszyklus (`open | resolved | accepted | false_positive`).
- Findings brauchen eine stabile Identität über Scans hinweg (offen,
  Grilling-Backlog).
