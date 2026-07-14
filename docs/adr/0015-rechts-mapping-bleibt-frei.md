# ADR-0015: Das Rechts-Mapping bleibt dauerhaft frei

Status: Akzeptiert (2026-07-04, Grilling-Runde 3)

Das gepflegte §30/NIS2UmsVO/ISO-Mapping (ADR-0013) liegt dauerhaft im freien Teil —
es wird nie Premium-Feature. Begründung: Korrektheit ist Grundfunktion, kein
Komfort. Ein Compliance-Tool, dessen Free-Tier gegen veralteten Rechtsstand prüft,
erzeugt falsche Sicherheit genau bei der Zielgruppe, die es nicht merkt, und der
Reputationsschaden träfe auch die zahlenden Kunden. Monetarisiert werden Skala und
Komfort (Multi-Account, Trend, PDF, Scheduling, Dashboard — siehe Feature-Matrix),
nie die fachliche Richtigkeit.

Die Aktualitäts-Sorge („top aktuell auch bei Urlaub/Krankheit") wird zweifach
entschärft: Die Überwachung von Rechtsänderungen ist automatisiert (ADR-0013,
Monitoring + Entwurf, nie Auto-Merge), und jeder Report weist seinen Rechtsstand
sichtbar aus — ein veraltetes Mapping ist damit transparent, nie still gefährlich.
