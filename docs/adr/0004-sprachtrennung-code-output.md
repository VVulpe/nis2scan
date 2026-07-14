# ADR-0004: Sprachtrennung — Code Englisch, Output Deutsch

Status: Akzeptiert (nachträglich dokumentiert, 2026-07-04)

## Kontext

Zielgruppe sind deutsche IT-Leiter und Auditoren; die Rechtsgrundlage (§30 BSIG)
existiert nur auf Deutsch. Gleichzeitig soll das Open-Source-Projekt
internationale Contributor gewinnen können.

## Entscheidung

Sämtlicher Code (Variablen, Kommentare, Docstrings) ist Englisch. Sämtlicher
fachlicher Output (Reports, Finding-Beschreibungen, Remediation-Texte) ist
Deutsch. Rechtsbegriffe (§30-Nummern, NIS2UmsVO-Referenzen) werden nicht
übersetzt.

## Konsequenzen

- Das Glossar ([glossary.md](../glossary.md)) pflegt die Begriffspaare
  Deutsch ↔ Codename; neue Fachbegriffe werden dort zuerst eingetragen.
- Finding-Texte leben als deutsche Daten (Mapping-Dateien), nicht als Strings
  im Check-Code.
- Eine spätere Internationalisierung (EU-weit) erfordert nur neue Textdaten,
  keine Code-Änderung.
