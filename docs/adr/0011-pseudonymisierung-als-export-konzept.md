# ADR-0011: Pseudonymisierung als Export-Konzept; Evidence als Allow-List-Extrakt

Status: Akzeptiert (2026-07-04, Grilling-Runde 2)

Das Schutzziel der Pseudonymisierung ist die **Weitergabe an Externe** (Auditor,
Berater, BSI) — nicht der Kunde selbst: Der ist Verantwortlicher seiner eigenen
IAM-Daten und braucht intern Klarnamen, sonst kann er Mängel niemandem zuordnen.
Pseudonymisierung wandert deshalb vom Scan (bisher `pseudonymize_users` in der
Scan-Config) in den Reporter:

1. **Scan und interner Report enthalten Klarnamen.** Das ScanResult wird nie mutiert.
2. **Export-Profile im Reporter:** `intern` (vollständig) und `extern` — dort werden
   personenbezogene Identifikatoren durch stabile HMAC-Pseudonyme (Kunden-Secret,
   siehe ADR-0010) ersetzt, konsistent in Findings **und** Evidence. Stabil, damit
   derselbe User über Reports hinweg denselben Pseudonym behält (Tracking bleibt
   möglich); der Kunde kann jederzeit selbst de-pseudonymisieren.
3. **Evidence ist nie der rohe API-Dump**, sondern ein Allow-List-Extrakt: Jeder Check
   deklariert, welche Felder den Beleg ausmachen (z. B. Bucket-Name,
   Encryption-Status, Key-ID). Personenbezogene Nebendaten (Resource-Tags mit Namen,
   E-Mail-Adressen) gelangen strukturell gar nicht erst in den Nachweis — Redaction
   beim externen Export betrifft dann nur noch die deklarierten Identifikatoren.

## Verworfene Alternativen

- **Rohe API-Antworten als Evidence** (ursprünglicher Plan): unterläuft jede
  Pseudonymisierung und zieht Secrets/PII in Reports.
- **Pseudonymisierung als Scan-Option**: mutiert Daten vor dem JSON-Vertrag; interner
  Report wäre unbrauchbar („pseudo-7f3a hat kein MFA" — wer?), Tracking bei
  Zufallspseudonymen tot.

## Konsequenzen

- DSGVO-Argumentation: intern kein Pseudonymisierungsbedarf (Verantwortlicher),
  extern Datenminimierung durch Allow-List + Pseudonyme.
- Braucht der Auditor Echtdaten, legt der Kunde den internen Report vor oder löst
  Pseudonyme selbst auf — das Tool muss dafür nichts können.
