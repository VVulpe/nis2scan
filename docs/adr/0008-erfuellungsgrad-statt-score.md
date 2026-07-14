# ADR-0008: Erfüllungsgrad statt Prozent-Score; Report niemals gefiltert

Status: Akzeptiert (2026-07-04, Grilling-Runde 1)

§30 BSIG ist eine Rechtspflicht — ein Prozentwert („Nr. 3: 73 %") suggeriert eine
rechtlich nicht existente Teilerfüllung, ist ohne definierte Formel nicht
verteidigbar und angesichts §38 BSIG (Geschäftsführerhaftung) gefährlich, wenn sich
Geschäftsleitung darauf verlässt. Pro §30-Maßnahme gibt es stattdessen einen
ordinalen Erfüllungsgrad des cloud-technischen Teilaspekts —
`erfüllt | teilweise erfüllt | nicht erfüllt | nicht bewertbar` — plus nachprüfbare
Rohzahlen (x von y Checks bestanden, n Prüfobjekte mangelhaft).

Außerdem: JSON und Report enthalten immer alle Findings. Der Severity-Filter aus
der Config wirkt ausschließlich auf die CLI-Konsolenanzeige (`cli_min_severity`) —
ein Audit-Report, der Befunde unterdrückt, ist kein Audit-Report.

## Konsequenzen

- Die Phase-2-Tabelle `compliance_scores` (DECIMAL 0–100) wird durch Erfüllungsgrad
  plus Zählwerte ersetzt; Trend-Charts im Dashboard zeigen Zählwerte, keine Prozente.
- Marketing und Content versprechen keine Compliance-Prozentzahlen.
