# Arbeitsweise: Orchestrator + Worker (Kostenmodell)

Beschluss des Gründers vom 12.07.2026. Ziel: Token-Kosten deutlich senken
(Wochenlimit wurde real erreicht), ohne Qualitätsverlust bei Urteilen.
Verbindlich für alle Claude-Code-Sessions in diesem Repo.

## Rollen

| Rolle | Modell | Zuständig für |
|---|---|---|
| **Orchestrator** (Hauptsession) | **Fable 5** (bevorzugt); **Opus 4.8** als gleichwertiger Ersatz, wenn Fable nicht verfügbar ist oder umgeschaltet wurde | Planung, Architektur, Aufgaben-Zerlegung, Review der Worker-Ergebnisse, **Code-Review**, rechtliche Einordnung, Commits |
| **Worker** | **Sonnet 5** — `Agent`-Tool mit `subagent_type="general-purpose"`, `model="sonnet"` | Mechanische, klar spezifizierte Ausführung: Check-Wellen, Testgerüste, Extraktions-Dossiers, Doku-Mechanik, Migrationsschritte, Massen-Refactorings nach Spezifikation |
| **`legal-reviewer`** | Fable (fest verdrahtet in `.claude/agents/legal-reviewer.md`) | Unabhängige Zweitprüfung nach ADR-0018 (Vier-Augen-Prinzip mit dem Gründer) |

Die Wahl des Hauptsession-Modells trifft der Gründer im Modell-Selector der
Claude-Code-UI (Claude kann es nicht selbst umschalten). Default: Fable 5.

## Regeln

1. **Delegierbar** ist nur, was ein in sich vollständiger Prompt beschreibt:
   betroffene Dateien, Zielformat, Abnahmekriterien, Verbote. Der Worker startet
   mit frischem Kontext und weiß nichts aus der Hauptsession.
2. **Nicht delegierbar** an Sonnet-Worker:
   - **Rechts-Urteile** (ADR-0018) — bleiben bei Orchestrator + Gründer +
     `legal-reviewer`. Worker dürfen dafür nur *mechanische Dossiers* zuliefern
     (wörtliche Extraktion, ausdrücklich ohne Bewertung).
   - **Code-Review** — das Urteil bleibt beim Orchestrator-Modell. Reviews lesen
     fokussiert und schreiben wenig; sie sind kein Token-Treiber, aber
     urteilskritisch.
   - Architektur- und Produktentscheidungen, Commits, heikle Merges.
3. Jedes Worker-Ergebnis wird vom Orchestrator **geprüft, bevor** es committet
   wird. Der Worker committet nie selbst.
4. Worker laufen mit eigenem Kontext/Cache — große mechanische Diffs entstehen
   im Worker, nicht in der Hauptsession. Hauptsession-Kontext klein halten.
5. **Splitting-Muster für W4-Rechts-Reviews:** Sonnet-Worker extrahiert je
   §30-Nr. das Prüf-Dossier (`docs/review/w4-batch-nr<N>-dossier.md`) →
   `legal-reviewer` und Gründer fällen das Urteil → Vermerke ins Protokoll
   `docs/rechtsgrundlagen-review.md`.

## Warum

Anthropic-Messung (via the-decoder): Fable-Orchestrator + Sonnet-Worker liefert
ca. **96 % der Leistung bei 46 % der Kosten** gegenüber „Fable macht alles".
Für **Opus 4.8 als Orchestrator** gilt dieselbe Mechanik — Opus ist die teuerste
Stufe, Delegation der mechanischen Masse lohnt dort erst recht; gemessene
Prozentwerte liegen für diese Kombination nicht vor.
