# ADR-0018: Rechtsgrundlagen-Review mit Quellenpflicht

Status: Akzeptiert (2026-07-05, Grilling-Runde 4)

Anforderung des Gründers: Die Entwicklung darf nie an den gesetzlichen Vorgaben
vorbei laufen. Deshalb zwei verbindliche Mechanismen:

1. **Quellenpflicht als Daten:** Jeder Mapping-Eintrag und jeder Check trägt seine
   Rechtsgrundlage als strukturierte Daten — Fundstelle (z. B. „§30 Abs. 2 Nr. 8
   BSIG"), URL der Primärquelle, Abrufdatum und wörtliches Normtext-Zitat.
   Zulässige Quellen in dieser Rangfolge: Primärquellen
   (gesetze-im-internet.de, Bundesgesetzblatt, EUR-Lex), dann behördliche
   Sekundärquellen (BSI). Blogposts, Berater-Whitepaper oder KI-Wissen ohne
   Quelle sind nie alleinige Grundlage.
2. **Review-Gate im Vier-Augen-Prinzip:** Jede Änderung an Mapping, Checks oder
   rechtlich formulierenden Reporttexten durchläuft vor dem Merge **zwei
   unabhängige Reviews**: (a) den menschlichen Review durch den Gründer und
   (b) eine Zweitprüfung durch den Agent `legal-reviewer` (Claude Fable,
   `.claude/agents/legal-reviewer.md`) — beide nach derselben Checkliste (Skill
   `nis2-legal-review`): Normtext-Abgleich gegen die Primärquelle,
   Rechtsstand-Prüfung (ADR-0013), Kontrolle, dass keine Aussage über den
   cloud-technischen Teilaspekt hinausgeht (ADR-0009/0012). Der Agent sichert
   den Menschen ab, ersetzt ihn nie; er winkt bei Unsicherheit nie durch
   (im Zweifel FAIL, analog ADR-0016). Ohne **beide** Review-Vermerke kein Merge.

## Konsequenzen

- Entwicklung wird langsamer — bewusst: Korrektheit vor Geschwindigkeit ist bei
  einem Compliance-Tool das Produkt selbst (vgl. ADR-0016).
- Der Quellennachweis ist zugleich Report-Material: Findings können ihre
  Fundstelle mitdrucken — ein Differenzierungsmerkmal gegenüber CSPM-Tools.
