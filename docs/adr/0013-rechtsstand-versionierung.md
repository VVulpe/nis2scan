# ADR-0013: Rechtsstand-Versionierung des Mappings

Status: Akzeptiert (2026-07-04, Grilling-Runde 2)

Ein Report muss auch Jahre später belegen, gegen welche Fassung von BSIG und
NIS2UmsVO geprüft wurde — Gesetze, Verordnung und das Mapping ändern sich. Deshalb:

- Das §30/NIS2UmsVO/ISO-Mapping ist **versionierte Daten** mit eigener
  `mapping_version` und einem `rechtsstand` (Fassungsdatum der Rechtsgrundlagen,
  z. B. „BSIG i. d. F. vom 06.12.2025").
- Jedes ScanResult trägt beide Felder (neben `schema_version`); jeder Report druckt
  sichtbar „Geprüft gegen Rechtsstand …".
- Checks referenzieren Mapping-Einträge; Gesetzestext steht nie direkt im Check-Code.
  Eine Rechtsänderung ist damit ein Daten-Release, kein Code-Release.

## Pflegeprozess (Kontext, keine Architektur)

Quartalsweiser Review der Rechtsgrundlagen durch den Maintainer (mit Claude als
Recherchewerkzeug); Quellen: BSI-Veröffentlichungen, Bundesgesetzblatt,
NIS2UmsVO-Novellen. Community-Korrekturen per PR willkommen, Merge-Entscheidung
bleibt beim Maintainer.

**Automatisiert wird die Überwachung, nie die Entscheidung:** Ein geplanter Job
(z. B. GitHub Action) beobachtet BSI-Veröffentlichungen, Bundesgesetzblatt und
EUR-Lex und eröffnet bei Treffern ein Issue; Claude entwirft den Mapping-Diff als
PR; Review und Merge bleiben beim Menschen — ein automatisch gemergtes
Rechts-Mapping wäre selbst ein Haftungsrisiko. Verzögerungen (Urlaub, Krankheit)
sind tolerierbar, weil jeder Report seinen Rechtsstand ausweist: Veraltung ist
sichtbar, nie still. Das Mapping bleibt dauerhaft frei (ADR-0015).
