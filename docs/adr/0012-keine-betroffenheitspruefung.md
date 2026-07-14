# ADR-0012: Keine Betroffenheitsprüfung — NIS2-Kategorie ist Selbsteinstufung

Status: Akzeptiert (2026-07-04, Grilling-Runde 2)

Das Tool leitet **niemals** die NIS2-Kategorie oder die Betroffenheit eines
Unternehmens aus Sektor, Größe oder anderen Daten ab — das wäre faktisch
Rechtsberatung mit persönlichem Haftungsrisiko für den Anbieter. Stattdessen:

- `nis2_category` ist eine **optionale Selbsteinstufung des Kunden** und reine
  Report-Metadata („Selbsteinstufung des Unternehmens: …"). Sie steuert nichts am
  Scanverhalten — die 10 Maßnahmen aus §30 Abs. 2 gelten für beide Kategorien.
- `sector` bleibt optionale Beschreibungs-Metadata; der frühere Config-Kommentar
  „Für NIS2-Kategorie-Bestimmung" ist gestrichen.
- Report und README tragen einen ständigen Disclaimer (keine Rechtsberatung) und
  verweisen für die Betroffenheitsfrage auf die offizielle
  NIS-2-Betroffenheitsprüfung des BSI.

## Konsequenzen

- Feature-Wünsche „sagt mir, ob ich unter NIS2 falle" werden abgelehnt und auf das
  BSI-Tool verwiesen — das explizite Nein ist Teil der Produktgrenze.
- Reports bleiben rechtlich verteidigbar; der Anbieter macht Technik-Aussagen,
  keine Rechtsaussagen.
