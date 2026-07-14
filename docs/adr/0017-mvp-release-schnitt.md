# ADR-0017: Release-Schnitt — 0.1 = AWS und Azure × Nr. 8/9/10

Status: Akzeptiert (2026-07-05, Grilling-Runde 5 — Option B)

> **Revision (2026-07-05, Audit/ADR-0022):** Die Prämisse ist überholt — es
> existieren bereits 154 Checks für AWS, Azure **und GCP** über alle Nr. 1–10.
> Lesart seither: Zielbild = volle Abdeckung für drei Provider; der
> 0.1-Launch-Anspruch und die Review-Reihenfolge (W4) bleiben AWS + Azure
> zuerst, GCP läuft als „experimental" mit Banner bis zum GCP-Rechts-Review.
> Siehe [ADR-0022](0022-gcp-experimenteller-provider.md).

Es wird nichts gestrichen: Das verbindliche Zielbild ist die volle Check-Abdeckung
für AWS **und** Azure über alle §30-Maßnahmen Nr. 1–10. Dieses ADR regelt die
Release-Reihenfolge dorthin.

**Release 0.1 (öffentlicher Launch): AWS und Azure × Nr. 8/9/10** (Kryptographie,
Zugriffskontrolle, MFA/Kommunikation) — beide Provider von Tag 1, weil der deutsche
Mittelstand stark Microsoft-lastig ist und ein AWS-only-Launch die halbe Zielgruppe
ausschlösse. Danach Nr. 1–7 sukzessive, **pro Release eine Maßnahme für beide
Provider gleichzeitig** (Parität bleibt Invariante: nie wieder ein Provider-Gefälle
im Funktionsumfang).

Nicht abgedeckte Maßnahmen erscheinen ehrlich im Report: `NOT_IN_SCOPE` bzw.
`MANUAL_REQUIRED` mit Attestierungspunkten (ADR-0007/0009) — der Launch-Report
lügt nie über seinen Umfang.

## Verworfene Alternative

Option A (0.1 = AWS only, Azure in 0.2): halbierte Verifikations- und
Review-Fläche bis zum Launch, aber schwächeres Launch-Statement. Verworfen durch
Gründer-Entscheidung — Marktabdeckung vor Launch-Tempo.

## Konsequenzen (bewusst akzeptiert)

- Vor 0.1 braucht es Terraform-Testfixtures mit absichtlichen Compliance-Lücken
  für **beide** Clouds (nis2-inttest, Release-Gate aus ADR-0016) und
  Rechtsgrundlagen-Reviews (ADR-0018) für die Checks beider Provider — der
  Launch-Termin wird von Verifikation und Review getrieben, nicht vom Code.
- Die 30-Tage-GTM-Timeline („Tag 1–7: CLI MVP") ist mit diesem Umfang nicht
  haltbar und muss neu geplant werden (Grilling-Backlog).
- Der Permissions-Generator (`nis2scan permissions`) muss ab 0.1 beide Provider
  können (IAM Policy und Azure RBAC), sonst scheitert das Onboarding der
  Azure-Hälfte der Zielgruppe.
