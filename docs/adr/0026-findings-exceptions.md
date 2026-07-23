# ADR-0026: Ausnahmen für Findings (Exceptions)

Status: Akzeptiert (2026-07-23, Chat-Grilling; Entwurf:
nis2scan-planning/11-findings-exceptions-entwurf.md)

## Kontext

Jeder Scanner produziert Befunde, die eine Einrichtung bewusst nicht
beheben will: False Positives, akzeptierte Risiken, Sonderfälle (etwa ein
absichtlich öffentlicher S3-Bucket für eine Website). Ohne Ausnahme-
Mechanismus verrauschen solche Befunde jeden Folge-Report. Umgekehrt darf
ein Ausnahme-Mechanismus kein Löschknopf sein: Für ein Audit-Werkzeug muss
jede Ausnahme selbst nachweisfähig sein (wer, warum, bis wann).

## Entscheidung (Gründer-Entscheide 23.07.2026)

1. **Tier: FREE.** Der Umgang mit False Positives gehört zur Korrektheit
   der Compliance-Aussage (ADR-0023-Grundsatz) und ist in freien Scannern
   Standard.
2. **Ausnahmen-Datei beim Kunden** (YAML, Pfad per `--exceptions`):
   Einträge matchen auf `check_id` + `resource_id` (optional zusätzlich
   Account/Subscription/Projekt und Region). Pflichtfelder: `reason`
   (Vermerk) und `expires` (Due Date). Optional: `author`, `ticket`.
   Keine implizite Standard-Datei — Ausnahmen wirken nur bei expliziter
   Angabe (keine überraschende Unterdrückung).
3. **Keine unbefristeten Ausnahmen:** `expires` ist Pflicht; bei Laufzeit
   über 12 Monaten warnt das Tool (Wiedervorlage-Prinzip), lehnt aber
   nicht ab. Nach Ablauf greift die Ausnahme nicht mehr; der Befund zählt
   wieder voll und der Report weist auf die abgelaufene Ausnahme hin.
4. **Transparenz statt Unterdrückung:** Ausgenommene Befunde verschwinden
   nicht, sondern erscheinen in einer eigenen Report-Sektion „Ausnahmen"
   mit Vermerk, Frist und Autor. Der Erfüllungsgrad wird zweigleisig
   ausgewiesen („X von Y erfüllt, davon Z per dokumentierter Ausnahme
   akzeptiert") — keine stille Herausrechnung.
5. **Fail-safe unberührt (ADR-0016):** Ausnahmen wirken nur auf Befunde
   (Mängel). Positivnachweise, CheckError und NOT_APPLICABLE lassen sich
   nicht ausnehmen.
6. **Schema additiv (ADR-0021):** Findings erhalten ein optionales
   `exception`-Feld, ScanResult-Metadaten vermerken die verwendete
   Ausnahmen-Datei; Eintrag im Schema-Changelog, Minor-Bump.
7. **ADR-0018:** Die neuen Report-Texte (Sektion „Ausnahmen",
   Zweigleisigkeit, Ablauf-Hinweise) durchlaufen die volle Review.

## Konsequenzen

- Engine-seitige Annotation (nicht Reporter-only), damit JSON, Markdown,
  PDF und SaaS dieselbe Ausnahme-Sicht haben.
- SaaS/Premium können später Komfort darauf bauen (UI-Verwaltung,
  Ablauf-Erinnerungen) — der Mechanismus selbst bleibt frei.

## Nachtrag (2026-07-24): Zusatzsicht der Report-Schicht

Ergänzung zu Entscheidung 4, damit ein dokumentiert ausgenommener False
Positive den ausgewiesenen Stand nicht dauerhaft drückt:

- Der Report zeigt zusätzlich eine rein ABGELEITETE **Zusatzsicht** auf
  Bereichsebene. Ein §30-Bereich erscheint darin nur dann als „alle Mängel
  per dokumentierter Ausnahme akzeptiert", wenn (a) sein striktes Ergebnis
  NICHT_ERFUELLT oder TEILWEISE_ERFUELLT ist, (b) sämtliche Mangel-Findings
  des Bereichs eine aktive (nicht abgelaufene) Ausnahme tragen und (c) kein
  Check des Bereichs einen Fehler produziert hat. NICHT_BEWERTBAR wird nie
  aufgewertet (ADR-0016).
- Die Zusatzsicht existiert AUSSCHLIESSLICH in der Report-Darstellung
  (Markdown/PDF), nicht im JSON-Vertrag; alle strikten Werte
  (Erfüllungsgrad, failed_checks, Outcomes) bleiben unverändert gültig
  und sichtbar.
- Wortwahl-Vorgabe (Befund F1 der Zweitprüfung vom 24.07.2026): Die
  Zusatzsicht verwendet NICHT das reservierte Ordinal-Label „erfüllt"
  (ADR-0008) als Quasi-Bewertung. Sie wird als „Zusatzsicht" mit
  ausgeschriebener Bedingung formuliert und stellt klar, dass eine
  Ausnahme eine Risikoentscheidung der Einrichtung ist, den Mangel nicht
  beseitigt und eine Bewertung durch Auditor oder Aufsicht nicht
  vorwegnimmt.
