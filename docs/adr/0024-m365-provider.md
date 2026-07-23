# ADR-0024: Microsoft 365 als vierter Provider

Status: Akzeptiert (2026-07-23, Grilling im Chat; Entwurf + Recherche-Dossier:
nis2scan-planning/09-m365-provider-entwurf.md)

## Kontext

Viele NIS2-betroffene Unternehmen sind M365-lastiger als infrastrukturlastig;
Exchange Online, SharePoint, OneDrive und Teams sind für sie „die Cloud".
Ein Recherche-Dossier (41 Kandidaten, verifiziert gegen learn.microsoft.com)
zeigt: Microsoft Graph v1.0 deckt SharePoint-/OneDrive-Tenant-Settings,
Secure Score, Auth-Methoden-Policies, Cross-Tenant-Access und App-Consent
gut ab. Exchange Online ist dagegen fast vollständig Graph-frei (Transport-
regeln, DKIM, SMTP-AUTH, Safe Links/Attachments, Anti-Phishing: nur Exchange
Online PowerShell); Teams-Meeting-/Messaging-Policies ebenso. Mehrere
attraktive Endpunkte sind nur Beta.

## Entscheidung (Gründer-Entscheide 23.07.2026)

1. Neuer Provider `m365` (CloudProvider.M365, CLI `--provider m365`),
   Check-IDs `M365-NRx-NNN`, gleiches BaseCheck-/Finding-/Evidence-Muster,
   Graph-REST über das graph.py-Muster.
2. **Nur Graph v1.0** für Checks mit Rechtsaussage; Beta-Endpunkte kommen
   auf eine Warteliste (Lehre aus AZ-NR9-007).
3. **Neue Prüfkategorie „extern beobachtbar"** ist zugelassen: Checks dürfen
   öffentlich beobachtbare Zustände per echter Abfrage prüfen (erster Fall:
   SPF/DMARC-Ist-Zustand per DNS-Abfrage, M365-NR8-002). Die Kategorie
   erhält einen eigenen Prüfgrenzen-Textbaustein („von außen beobachtbarer
   Zustand zum Scan-Zeitpunkt"), der der ADR-0018-Review unterliegt.
4. **Abgrenzung:** Entra-Directory-Themen (Conditional Access, PIM,
   Gastkonten, Legacy Auth, riskyUsers, signInActivity) bleiben beim
   Azure-Provider. M365-Provider = Workload-Einstellungen (SharePoint/
   OneDrive/Teams/Secure Score/Domains/App-Consent). Keine Doppel-Checks;
   der M365-Report empfiehlt den ergänzenden Azure-Scan.
5. **Welle 1: ~17 Checks** (Katalog im Planning-Entwurf), Bereiche Nr. 2
   und Nr. 7 bewusst dünn mit ausgewiesener Prüfgrenze (Exchange- bzw.
   Beta-Lücke). Ein Passwort-Ablauf-Check geht vor Aufnahme zur
   Ersteinschätzung an den legal-reviewer.
6. **Separate App-Registration „nis2scan-m365"** (eigenes Terraform-Modul,
   minimale Application Permissions, Admin-Consent-Anleitung über den
   Permissions-Generator) statt Erweiterung der Azure-Provider-App; reine
   M365-Kunden ohne Azure-Ressourcen bekommen ein sauberes Setup.
7. **Exchange-REST-Spike** (zeitbox: 1 Tag) nach Welle 1: Machbarkeit, die
   Exchange-Admin-Einstellungen ohne PowerShell-Modul per REST aus Python
   zu lesen. Ausgang offen; bei Nichtmachbarkeit dauerhafte Prüfgrenze.
8. Tier: **FREE** (ADR-0023-Grundsatz). ADR-0018 gilt voll für alle Checks
   und die Mapping-Erweiterung (MAPPING_VERSION-Bump). Kommunikation nach
   ADR-0022-Muster: M365 wird erst beworben, wenn rechtsgeprüft und live
   getestet; der Launch bleibt AWS + Azure.

## Konsequenzen

- Neue Session-Klasse M365Session (Client-Credentials, eigener Tenant-Scan
  ohne Azure-Subscription möglich); graph.py wird provider-neutral nutzbar.
- Integrationstests benötigen einen M365-Testtenant (Microsoft 365
  Developer- oder eigener Kauf-Tenant) — vor Implementierungsstart klären.
- Die Exchange-Lücke steht in Prüfgrenzen und Attestierungs-Checkliste,
  bis der Spike ein anderes Ergebnis liefert.
