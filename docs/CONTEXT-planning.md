# nis2scan

Automatisierte, rein lesende Prüfung von AWS/Azure-Umgebungen gegen die 10 Kernmaßnahmen
des §30 Abs. 2 BSIG, mit auditfähigen Nachweisen für den cloud-technischen Teilaspekt
jeder Maßnahme. Sprachregel: Code Englisch, Fachsprache/Output Deutsch, Rechtsbegriffe
unübersetzt (ADR-0004).

## Language

### Rechtsrahmen

**§30-Maßnahme**:
Eine der 10 Kernmaßnahmen aus §30 Abs. 2 BSIG (Nr. 1–10); fachlicher Anker jedes Checks.
_Avoid_: Control, Requirement, Bereich

**NIS2-Kategorie**:
Einstufung einer Einrichtung nach §28 BSIG als `wichtig` oder `besonders_wichtig`;
Rechtsbegriffe, die auch in Config und Code unübersetzt bleiben. (EU-Sprech zur
Orientierung: essential entity = besonders wichtige Einrichtung, important = wichtige.)
_Avoid_: important, essential, Tier

**ISO-Cross-Referenz**:
Informative Zuordnung eines Checks zu ISO 27001:2022 Controls; ausdrücklich keine
Konformitätsaussage.
_Avoid_: ISO-Compliance, ISO-zertifiziert

**Selbsteinstufung**:
Die vom Kunden selbst erklärte NIS2-Kategorie; optionale Report-Metadata, steuert
nichts am Scanverhalten und wird nie vom Tool abgeleitet (ADR-0012).
_Avoid_: Betroffenheitsprüfung (macht das offizielle BSI-Tool, nicht wir)

**Rechtsstand**:
Fassung des BSIG, gegen die eine Mapping-Version prüft; steht in jedem
ScanResult und sichtbar auf jedem Report (ADR-0013).
_Avoid_: Gesetzesversion

**Rechtsgrundlagen-Review**:
Pflicht-Reviewschritt vor jeder Änderung an Mapping, Checks oder rechtlich
formulierenden Reporttexten: Normtext-Abgleich mit Primärquellen samt
Quellennachweis (Fundstelle, URL, Abrufdatum, Zitat) (ADR-0018).
_Avoid_: Legal-Check

**Quellennachweis**:
Die strukturierte Rechtsgrundlage eines Mapping-Eintrags oder Checks: Fundstelle,
Primärquellen-URL, Abrufdatum und wörtliches Normtext-Zitat (ADR-0018).
_Avoid_: Referenz (zu unscharf), Link

### Prüfmodell

**Scan**:
Ein kompletter Prüflauf über alle konfigurierten Provider; Ergebnis ist genau ein
ScanResult-JSON — der Vertrag für alle Abnehmer (ADR-0002).
_Avoid_: Check (das ist die Einzelprüfung), Audit

**Check**:
Kleinste automatisierte Prüfeinheit; stateless, deklariert ihre benötigten
Cloud-Permissions und genau eine §30-Maßnahme.
_Avoid_: Rule, Test, Scan

**Manueller Check**:
Prüfpunkt einer §30-Maßnahme, den keine Cloud-API sehen kann; erzeugt
Attestierungspunkte statt automatischer Findings.

**Attestierungspunkt**:
Einzelner, manuell zu bestätigender Nachweis (z. B. Schulungsnachweis) auf der vom
Tool erzeugten Checkliste.
_Avoid_: manuelles Finding

**Prüfobjekt**:
Das, worauf sich ein Finding bezieht — eine konkrete Cloud-Ressource oder die
Account-/Subscription-Ebene. Kanonische ID ist die unveränderliche native
Ressourcen-ID (ARN / Azure Resource ID), nie der Anzeigename.
_Avoid_: Asset, Target

**Finding**:
Eine bewertete Feststellung pro Check × Prüfobjekt — konform oder nicht konform.
Positivnachweise sind vollwertige Findings (ADR-0006).
_Avoid_: Issue, Violation, Mangel (nur die nicht-konforme Teilmenge)

**Mangel**:
Nicht-konformes Finding; trägt Severity und deutsche Remediation.
_Avoid_: Fehler (das ist ERROR: die Prüfung selbst ist gescheitert)

**Check-Outcome**:
Abgeleiteter Gesamtzustand eines Check-Laufs: PASSED, FAILED, NOT_APPLICABLE,
MANUAL_REQUIRED, ERROR oder NOT_IN_SCOPE; wird deterministisch aus Findings und
Fehlern abgeleitet, nie unabhängig gesetzt (ADR-0007).
_Avoid_: skipped, Status (kollidiert mit Finding-Status)

**Evidence**:
Kuratierter Beleg zu jedem Finding — auch zu konformen: nur die pro Check per
Allow-List deklarierten, entscheidungsrelevanten Felder, nie der rohe API-Dump
(ADR-0011); deutsch im Report: Nachweis.
_Avoid_: Log, Beweis, Roh-Response

**Finding-Fingerprint**:
Stabile Identität eines Findings über Scans hinweg: HMAC (Kunden-Secret) über
Provider, Account, check_id und kanonische Prüfobjekt-ID (ADR-0010).
_Avoid_: finding_id (das ist die UUID eines einzelnen Vorkommens)

**Pseudonymisierung**:
Ersetzen personenbezogener Identifikatoren durch stabile HMAC-Pseudonyme
(Kunden-Secret) beim externen Report-Export; ein Export-Konzept, keine
Scan-Eigenschaft (ADR-0011).
_Avoid_: Anonymisierung (wäre irreversibel — ist es nicht)

**Export-Profil**:
Empfängerbezogene Reporter-Einstellung: `intern` (vollständig, Klarnamen) oder
`extern` (pseudonymisiert und redigiert) (ADR-0011).

**Redaction**:
Maskieren personenbezogener Felder in der Export-Kopie von Evidence; verändert
nie das ScanResult selbst.
_Avoid_: Löschen

### Bewertung & Report

**Severity**:
Gewicht eines Mangels: CRITICAL, HIGH, MEDIUM, LOW, INFO; statisch pro Check.
Beeinflusst niemals, ob ein Finding im Report erscheint (ADR-0008).
_Avoid_: Priorität, Risiko

**Erfüllungsgrad**:
Ordinale Bewertung des cloud-technischen Teilaspekts einer §30-Maßnahme:
erfüllt, teilweise erfüllt, nicht erfüllt oder nicht bewertbar (ADR-0008).
_Avoid_: Score, Compliance-Prozent

**Cloud-technischer Teilaspekt**:
Der automatisiert prüfbare Ausschnitt einer §30-Maßnahme. Der Report bewertet immer
nur diesen, nie die Maßnahme als Ganzes (ADR-0009).
_Avoid_: „Nr. X erfüllt" ohne Teilaspekt-Einschränkung

**Abdeckung**:
Angabe im Mapping, welchen Teilaspekt einer §30-Maßnahme die automatisierten Checks
erfassen und welche Attestierungspunkte offen bleiben.
_Avoid_: Coverage-Prozent

**Prüfgrenzen**:
Die pro Check deklarierten Grenzen der automatisierten Prüfung („geprüft wurde X,
nicht Y"); erscheinen im Report direkt beim Ergebnis (ADR-0016).
_Avoid_: Known Limitations (im deutschen Report), Disclaimer
