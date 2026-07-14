# ADR-0005: Open Core unter Apache 2.0

Status: Akzeptiert (nachträglich dokumentiert 2026-07-04; ausdrücklich bestätigt in Grilling-Runde 4, 2026-07-05 — „Transparenz auf GitHub ist zu Beginn das wertvollste Gut")

## Kontext

Das Geschäftsmodell braucht Reichweite (Vertrauen, GitHub als Vertriebskanal)
und gleichzeitig Revenue-Streams (Templates, SaaS, Consulting). Ein reines
Closed-Source-Tool bekäme in der Security-Community keine Adoption.

## Entscheidung

CLI und Engine sind Open Source unter Apache 2.0 und bleiben dauerhaft
kostenlos. Premium-Features (Phase 2: SaaS-Tiers, Scheduled Scans, Dashboard)
werden später kostenpflichtig angeboten. ISMS-Templates sind ein separates
kommerzielles Produkt außerhalb des Repos (abgespeckte Markdown-Fassung im
Free Tier).

## Konsequenzen

- Apache 2.0 erlaubt Forks inkl. kommerzieller Nutzung durch Dritte
  (z. B. Systemhäuser) — gewollt für das White-Label-Modell, aber die
  Schnittlinie frei/bezahlt muss so liegen, dass ein Fork das Geschäftsmodell
  nicht trivial repliziert (offen, Grilling-Backlog Punkt 8).
- Die Paywall-Mechanik darf nicht im Apache-lizenzierten Code liegen, sonst
  ist sie per Fork entfernbar.
