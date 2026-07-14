# ADR-0016: Fail-Safe-Ergebnispolitik — im Zweifel nie PASSED

Status: Akzeptiert (2026-07-04, Grilling-Runde 3)

Das Produktversprechen ist der Positivnachweis (ADR-0006); die gefährlichste
Fehlerklasse ist deshalb nicht der Fehlalarm, sondern der **falsche
Positivnachweis** — „konform", obwohl nicht, vorgelegt beim Auditor. Transparenz
ist explizites Produktmerkmal. Drei verbindliche Regeln:

1. **Konservative Ableitung:** `PASSED` gibt es nur nach vollständiger, fehlerfreier
   Bewertung aller Prüfobjekte. Jeder Zweifel — abgebrochene Pagination, Teilfehler,
   unbekannte Konfigurationszustände — ergibt `ERROR` mit Begründung, nie `PASSED`.
   Lieber „konnte nicht bewertet werden" als ein falsches Testat.
2. **Prüfgrenzen:** Jeder Check deklariert seine Known Limitations („geprüft wurde X,
   nicht Y"); der Report druckt sie direkt beim Ergebnis.
3. **Release-Gate:** Vor jedem Release läuft der Integrationstest (nis2-inttest)
   gegen einen echten, absichtlich teilweise nicht-konformen Test-Account.
   moto-Mocks testen nur unsere Annahmen über die Cloud-APIs, nicht die APIs.

## Konsequenz

Reports sehen im Fehlerfall „schlechter" aus als bei Konkurrenz-Tools, die stumm
überspringen — das ist gewollt und wird als Vertrauensmerkmal vermarktet.
