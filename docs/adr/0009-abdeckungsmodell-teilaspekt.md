# ADR-0009: Report bewertet nur den cloud-technischen Teilaspekt

Status: Akzeptiert (2026-07-04, Grilling-Runde 1)

Die Maßnahmen §30 Abs. 2 Nr. 1–7 sind überwiegend organisatorisch; eine Cloud-API
sieht davon strukturell nichts (Nr. 1 verlangt Risikoanalyse-Konzepte — aktivierte
AWS-Services sind dafür ein Indiz, kein Nachweis). Ein Report, der „Nr. 1: erfüllt"
ausgibt, weil fünf Services aktiviert sind, wäre inhaltlich falsch und für die
Zielgruppe (kein GRC-Wissen, vertraut dem Tool) haftungsrelevant irreführend.

Deshalb: Jede §30-Maßnahme trägt im Mapping eine Abdeckungsangabe — die Beschreibung
ihres automatisiert prüfbaren Teilaspekts plus die offenen Attestierungspunkte, die
das Tool als Checkliste ausgibt (Anknüpfungspunkt für die ISMS-Templates). Sprachregel
im Report: Bewertet wird ausdrücklich und ausschließlich der cloud-technische
Teilaspekt; daneben stehen sichtbar die manuell zu erbringenden Nachweise.

## Konsequenzen

- „Audit-ready" heißt in Marketing und README immer: auditfähige Nachweise für den
  geprüften cloud-technischen Teilaspekt — nie NIS2-Konformität als Ganzes.
- Die Attestierungs-Checkliste ist zugleich der ehrliche Upsell-Pfad zu den
  ISMS-Templates (Mangel an Konzept-Dokumenten → Template-Angebot).
