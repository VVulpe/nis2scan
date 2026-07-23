# ADR-0025: Meldehilfe für §32 BSIG (Meldepflichten)

Status: Akzeptiert (2026-07-23, Grilling im Chat; Entwurf + Norm-Dossier:
nis2scan-planning/10-meldehilfe-p32-entwurf.md)

## Kontext

§32 BSIG verpflichtet besonders wichtige und wichtige Einrichtungen zu
gestuften Meldungen erheblicher Sicherheitsvorfälle an die gemeinsame
Meldestelle von BSI und BBK: frühe Erstmeldung binnen 24 Stunden,
Folgemeldung binnen 72 Stunden, Abschluss- oder Fortschrittsmeldung nach
einem Monat (§32 Abs. 1 und 2). Verstöße sind bußgeldbewehrt (§65 Abs. 2
Nr. 4/5; bis 10 Mio. € bzw. 2 % des Gesamtumsatzes). Im Ernstfall fehlt
Teams eine strukturierte Zuarbeit entlang der gesetzlichen Meldungsinhalte.

## Entscheidung (Gründer-Entscheide 23.07.2026)

1. **Tier: PROFESSIONAL** (Workflow-Komfort, keine Scan-Korrektheit;
   ADR-0023-Linie). Code-Heimat: nis2scan-premium.
2. **Welle 1 als CLI-Kommando `nis2scan meldung`**, SaaS-Oberfläche später.
   Funktionsumfang: Fristenrechner ab nutzergesetztem Zeitpunkt der
   Kenntniserlangung (24 h / 72 h / 1 Monat, mit Normzitat);
   Sachverhalts-Sammler exakt entlang §32 Abs. 1 Nr. 1, 2 und 4 lit. a–d
   (inkl. optionalem Block für Betreiber kritischer Anlagen, §32 Abs. 3);
   optionale technische Anlage aus referenzierten Scan-Findings; Export
   als Markdown (PDF über den Premium-Reporter). Kein automatischer
   Versand an das BSI.
3. **Rechtsberatungsgrenze als tragende Säule:** Das Tool bewertet weder,
   ob ein Vorfall „erheblich" (§2 Nr. 11) ist, noch ob die Einrichtung
   meldepflichtig (§28) ist. Beides verbleibt ausdrücklich beim Kunden;
   die Oberfläche sagt das an den entscheidenden Stellen wörtlich.
4. **Fristen zusätzlich als ICS-Kalender-Export.**
5. Nächster Schritt vor Implementierung: Auswertung der drei öffentlichen
   BSI-Dokumente (Meldepflicht-Onepager, Meldeprozess, Portal-Anleitung),
   damit der Export der Feldstruktur des BSI-Portals folgt.
6. ADR-0018 gilt voll: Jeder Text des Features formuliert rechtlich und
   durchläuft legal-reviewer plus Gründer-Vermerk.

## Konsequenzen

- Eigener Textbestand mit Rechtsstand-Vermerk (unabhängig vom Check-Mapping).
- Die im Norm-Dossier dokumentierte Verweis-Anomalie (§65 Abs. 2 Nr. 7 →
  „§33 Abs. 2 Satz 2" existiert im abgerufenen Normtext nicht) wird im
  Rechtsreview-Protokoll festgehalten und bei Gesetzesänderungen beobachtet.
- Die Portal-Feldstruktur ist öffentlich nicht abschließend belegt; der
  Export erhebt daher den Anspruch „vollständige gesetzliche Inhalte",
  nicht „identisches Portal-Formular".
