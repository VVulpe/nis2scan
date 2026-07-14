# nis2scan — NIS2 Cloud Compliance Scanner

**Automatisierte §30 BSIG Compliance-Prüfung für AWS, Azure & GCP**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/VVulpe/nis2scan/blob/main/LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)

nis2scan prüft Ihre Cloud-Umgebung (AWS, Azure, GCP) automatisiert gegen die 10 Kernmaßnahmen des §30 Abs. 2 BSIG (NIS2-Umsetzungsgesetz). Jedes Finding wird direkt auf den Gesetzestext und ISO 27001:2022 gemappt — auditfähig dokumentiert.

## Quickstart

```bash
pip install nis2scan

# AWS
nis2scan scan --provider aws --config config.yaml

# Azure
nis2scan scan --provider azure

# GCP
nis2scan scan --provider gcp
```

**Detaillierte Anleitung:** [docs/getting-started.md](https://github.com/VVulpe/nis2scan/blob/main/docs/getting-started.md) — Installation, Cloud-Setup (AWS/Azure/GCP), Konfiguration, CLI-Referenz, Troubleshooting.

> **Windows:** Die Installation benötigt aktivierten Long-Path-Support
> (einmalige Registry-Einstellung, siehe
> [Getting Started → Installation](https://github.com/VVulpe/nis2scan/blob/main/docs/getting-started.md#installation)).

---

## Gesetzliche Grundlagen

Das NIS2-Umsetzungsgesetz (NIS2UmsuCG) ist am 06.12.2025 in Kraft getreten. Es ändert primär das BSI-Gesetz (BSIG). Keine Übergangsfristen — die Pflichten gelten sofort.

### Relevante Gesetze & Verordnungen

| Dokument | Beschreibung | Link |
|----------|-------------|------|
| **BSIG (BSI-Gesetz)** | Kerngesetz — enthält alle NIS2-Pflichten für Unternehmen | [gesetze-im-internet.de](https://www.gesetze-im-internet.de/bsig_2025/) |
| **§28 BSIG** | Wer ist betroffen? Definition "besonders wichtige" und "wichtige" Einrichtungen | [§28 Volltext](https://www.gesetze-im-internet.de/bsig_2025/__28.html) |
| **§30 BSIG** | **DIE zentrale Norm**: 10 Risikomanagement-Maßnahmen (unser Scan-Scope) | [§30 Volltext](https://www.gesetze-im-internet.de/bsig_2025/__30.html) |
| **§31 BSIG** | Zusätzliche Anforderungen für Betreiber kritischer Anlagen (KRITIS) | [§31 Volltext](https://www.gesetze-im-internet.de/bsig_2025/__31.html) |
| **§32 BSIG** | Meldepflichten: 24h Erstmeldung, 72h Folgemeldung, 1 Monat Abschluss | [§32 Volltext](https://www.gesetze-im-internet.de/bsig_2025/__32.html) |
| **§33 BSIG** | Registrierungspflicht beim BSI | [§33 Volltext](https://www.gesetze-im-internet.de/bsig_2025/__33.html) |
| **§38 BSIG** | Persönliche Haftung der Geschäftsführung + Schulungspflicht | [§38 Volltext](https://www.gesetze-im-internet.de/bsig_2025/__38.html) |
| **§39 BSIG** | Nachweispflichten für KRITIS-Betreiber (Audit alle 3 Jahre) | [§39 Volltext](https://www.gesetze-im-internet.de/bsig_2025/__39.html) |
| **§65 BSIG** | Bußgelder: bis 10 Mio € oder 2% Jahresumsatz | [§65 Volltext](https://www.gesetze-im-internet.de/bsig_2025/__65.html) |
| **NIS2-Richtlinie (EU)** | EU-Richtlinie 2022/2555 — die europäische Grundlage | [EUR-Lex](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/deu) |
| **Durchführungsverordnung (EU) 2024/2690** | Gilt nur für bestimmte digitale Anbieter (z. B. Cloud-, DNS-, Rechenzentrumsdienste) — keine allgemeine Konkretisierung von §30 BSIG | [EUR-Lex](https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/deu) |
| **NIS2UmsuCG (Änderungsgesetz)** | Das eigentliche Umsetzungsgesetz (ändert BSIG + weitere Gesetze) | [BGBl Nr. 301/2025](https://www.recht.bund.de/bgbl/1/2025/301/VO.html) |
| **ISO/IEC 27001:2022** | Internationaler ISMS-Standard — NIS2 orientiert sich daran | [ISO.org](https://www.iso.org/standard/27001) |
| **BSI IT-Grundschutz** | BSI-eigener Standard, insb. für Bundesverwaltung relevant | [BSI](https://www.bsi.bund.de/grundschutz) |

### Betroffenheitsschwellen (§28 BSIG)

| Kategorie | Kriterien | Bußgeld-Risiko |
|-----------|-----------|---------------|
| **Besonders wichtige Einrichtung** | ≥250 MA oder >50 Mio € Umsatz in kritischem Sektor | Bis 10 Mio € oder 2% Jahresumsatz |
| **Wichtige Einrichtung** | ≥50 MA oder >10 Mio € Umsatz in reguliertem Sektor | Bis 7 Mio € oder 1,4% Jahresumsatz |
| **Indirekt betroffen** | Lieferant/Dienstleister einer betroffenen Einrichtung | Vertragliche Haftung |

---

## §30 BSIG → Scan-Mapping

Die zentrale Tabelle: Welcher Check prüft welche gesetzliche Anforderung?

### Übersicht

| §30 Nr. | Maßnahme | Gesetzestext (gekürzt) | AWS | Azure | GCP | ISMS-Dokument |
|----------|----------|----------------------|-----|-------|-----|---------------|
| **1** | Risikoanalyse | Konzepte in Bezug auf die Risikoanalyse und auf die Sicherheit in der Informationstechnik | ✅ 5 | ✅ 5 | ✅ 5 | IS-Leitlinie + Risikoanalyse |
| **2** | Incident Response | Bewältigung von Sicherheitsvorfällen | ✅ 5 | ✅ 5 | ✅ 5 | Incident-Response-Plan |
| **3** | Business Continuity | Aufrechterhaltung des Betriebs, Backup-Management, Wiederherstellung, Krisenmanagement | ✅ 7 | ✅ 7 | ✅ 7 | BC/DR-Plan |
| **4** | Lieferkettensicherheit | Sicherheit der Lieferkette einschl. sicherheitsbezogener Aspekte der Beziehungen zu Anbietern | ✅ 5 | ✅ 5 | ✅ 5 | Lieferketten-Konzept |
| **5** | Vulnerability Management | Sicherheitsmaßnahmen bei Erwerb, Entwicklung und Wartung, einschl. Schwachstellenmanagement | ✅ 5 | ✅ 5 | ✅ 5 | SDL + Patch-Richtlinie |
| **6** | Wirksamkeitsbewertung | Konzepte und Verfahren zur Bewertung der Wirksamkeit von Risikomanagementmaßnahmen | ✅ 4 | ✅ 4 | ✅ 4 | Audit-Programm + KPIs |
| **7** | Cyberhygiene | Grundlegende Schulungen und Cyberhygiene | ✅ 2 | ✅ 2 | ✅ 2 | Schulungskonzept |
| **8** | Kryptographie | Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren | ✅ 7 | ✅ 6 | ✅ 6 | Kryptographie-Richtlinie |
| **9** | Zugriffskontrolle | Personalsicherheit, Zugriffskontrolle, Verwaltung von IKT-Systemen | ✅ 7 | ✅ 7 | ✅ 7 | Zugriffskontroll-Richtlinie |
| **10** | MFA & Kommunikation | MFA, gesicherte Sprach-/Video-/Textkommunikation, Notfallkommunikation | ✅ 5 | ✅ 5 | ✅ 5 | MFA-Policy + Komm.-Richtlinie |

**Legende:** ✅ = implementiert & getestet

### Detail-Mapping: Jeder Check → Gesetzestext

#### §30 Abs. 2 Nr. 1 — Risikoanalyse und IT-Sicherheitskonzepte

| Status | Check-ID | Beschreibung | Schweregrad | §30 Text-Referenz | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR1-001 | AWS Config Recorder aktiv (alle Regionen) | HIGH | §30(2) Nr.1: "Konzepte in Bezug auf die Risikoanalyse" — Risikoanalyse setzt Sichtbarkeit aller Assets voraus | A.5.1, A.8.9 |
| ✅ | AWS-NR1-002 | Security Hub mit CIS/Foundational Benchmarks aktiviert | HIGH | §30(2) Nr.1: Sicherheitskonzept muss "Stand der Technik einhalten" (§30(2) S.1) | A.5.1 |
| ✅ | AWS-NR1-003 | AWS Organizations mit SCPs vorhanden | MEDIUM | §30(2) Nr.1: Organisationsweite Sicherheitsarchitektur | A.5.1, A.5.2 |
| ✅ | AWS-NR1-004 | CloudTrail aktiv in allen Regionen, Log-Validation | CRITICAL | §30(2) Nr.1 + Nr.6: Nachvollziehbarkeit ist Voraussetzung für Risikoanalyse und Wirksamkeitsbewertung | A.8.15 |
| ✅ | AWS-NR1-005 | GuardDuty aktiviert | HIGH | §30(2) Nr.1: Bedrohungserkennung als Teil der Risikoanalyse | A.5.7 |
| ✅ | AZ-NR1-001 | Defender for Cloud aktiviert (alle Subscriptions) | HIGH | §30(2) Nr.1: Zentrale Sicherheitsbewertung | A.5.1 |
| ✅ | AZ-NR1-002 | Azure Policy Assignments vorhanden | HIGH | §30(2) Nr.1: Durchsetzung von Sicherheitsstandards | A.5.1, A.5.2 |
| ✅ | AZ-NR1-003 | Management Groups konfiguriert | MEDIUM | §30(2) Nr.1: Organisationsweite Governance | A.5.1 |
| ✅ | AZ-NR1-004 | Activity Log → Log Analytics/Storage | CRITICAL | §30(2) Nr.1 + Nr.6: Audit-Trail | A.8.15 |
| ✅ | AZ-NR1-005 | Sentinel oder equivalent SIEM | HIGH | §30(2) Nr.1: Bedrohungserkennung | A.5.7 |

#### §30 Abs. 2 Nr. 2 — Bewältigung von Sicherheitsvorfällen

| Status | Check-ID | Beschreibung | Schweregrad | §30 Text-Referenz | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR2-001 | GuardDuty aktiviert (Bedrohungserkennung) | CRITICAL | §30(2) Nr.2: "Bewältigung von Sicherheitsvorfällen" — Erkennung + automatische Weiterleitung | A.5.24 |
| ✅ | AWS-NR2-002 | Security Hub Findings aggregiert | MEDIUM | §30(2) Nr.2: Zentrale Sicht auf Sicherheitsvorfälle | A.5.25 |
| ✅ | AWS-NR2-003 | Incident Manager / OpsCenter konfiguriert | MEDIUM | §30(2) Nr.2: Strukturierte Incident-Bewältigung mit Eskalationswegen | A.5.26 |
| ✅ | AWS-NR2-004 | CloudWatch Alarms für kritische Metriken | HIGH | §30(2) Nr.2: Proaktive Erkennung von Anomalien | A.5.24, A.8.16 |
| ✅ | AWS-NR2-005 | Detective aktiviert (Forensik) | LOW | §30(2) Nr.2: Forensische Analysefähigkeit | A.5.27 |
| ✅ | AZ-NR2-001 | Defender Alert Notifications konfiguriert | HIGH | §30(2) Nr.2: Automatische Benachrichtigung | A.5.24 |
| ✅ | AZ-NR2-002 | Sentinel Analytics Rules aktiv | HIGH | §30(2) Nr.2: Regelbasierte Erkennung | A.5.24, A.8.16 |
| ✅ | AZ-NR2-003 | Sentinel Playbooks/Logic Apps für Auto-Response | MEDIUM | §30(2) Nr.2: Automatisierte Eindämmung | A.5.26 |
| ✅ | AZ-NR2-004 | Action Groups für Alerting | HIGH | §30(2) Nr.2: Eskalationswege | A.5.24 |
| ✅ | AZ-NR2-005 | Alert Processing Rules definiert | MEDIUM | §30(2) Nr.2: Priorisierung und Routing | A.5.25 |

#### §30 Abs. 2 Nr. 3 — Aufrechterhaltung des Betriebs (BCM)

| Status | Check-ID | Beschreibung | Schweregrad | §30 Text-Referenz | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR3-001 | RDS automated backups + Retention ≥7d | HIGH | §30(2) Nr.3: "Backup-Management und Wiederherstellung nach einem Notfall" | A.8.13 |
| ✅ | AWS-NR3-002 | S3 Versioning auf kritischen Buckets | MEDIUM | §30(2) Nr.3: Datenwiederherstellung | A.8.13 |
| ✅ | AWS-NR3-003 | S3 Object Lock / Glacier Vault Lock | HIGH | §30(2) Nr.3: Schutz gegen Ransomware (Unveränderbarkeit) | A.8.13 |
| ✅ | AWS-NR3-004 | Multi-AZ für Produktions-Workloads | HIGH | §30(2) Nr.3: "Aufrechterhaltung des Betriebs" — Verfügbarkeit | A.5.29, A.8.14 |
| ✅ | AWS-NR3-005 | AWS Backup Pläne mit Cross-Region-Copy | HIGH | §30(2) Nr.3: "Wiederherstellung nach einem Notfall" — Geo-Redundanz | A.8.13 |
| ✅ | AWS-NR3-006 | EBS Snapshots regelmäßig + verschlüsselt | MEDIUM | §30(2) Nr.3 + Nr.8: Backup + Verschlüsselung | A.8.13, A.8.24 |
| ✅ | AWS-NR3-007 | Route 53 Health Checks | LOW | §30(2) Nr.3: Monitoring der Verfügbarkeit | A.8.14 |
| ✅ | AZ-NR3-001 | Azure Backup Vaults mit Policies | HIGH | §30(2) Nr.3: Backup-Management | A.8.13 |
| ✅ | AZ-NR3-002 | SQL DB Backup Retention ≥7d | HIGH | §30(2) Nr.3: Datenbank-Sicherung | A.8.13 |
| ✅ | AZ-NR3-003 | Geo-Redundant Storage (GRS) | HIGH | §30(2) Nr.3: Geo-Redundanz | A.8.13 |
| ✅ | AZ-NR3-004 | Availability Zones für Produktion | HIGH | §30(2) Nr.3: Verfügbarkeit | A.5.29, A.8.14 |
| ✅ | AZ-NR3-005 | Azure Site Recovery konfiguriert | HIGH | §30(2) Nr.3: Disaster Recovery | A.5.30 |
| ✅ | AZ-NR3-006 | Immutable Blob Storage | HIGH | §30(2) Nr.3: Ransomware-Schutz | A.8.13 |
| ✅ | AZ-NR3-007 | Traffic Manager / Front Door | LOW | §30(2) Nr.3: Redundanz | A.8.14 |

#### §30 Abs. 2 Nr. 8 — Kryptographie *(Phase 1 — AWS implementiert)*

| Status | Check-ID | Beschreibung | Schweregrad | §30 Text-Referenz | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR8-001 | S3 Default Encryption (SSE-S3/SSE-KMS) | HIGH | §30(2) Nr.8: "Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren" | A.8.24 |
| ✅ | AWS-NR8-002 | EBS Volumes verschlüsselt | HIGH | §30(2) Nr.8: Verschlüsselung ruhender Daten | A.8.24 |
| ✅ | AWS-NR8-003 | RDS Storage Encryption aktiv | HIGH | §30(2) Nr.8: Datenbank-Verschlüsselung | A.8.24 |
| ✅ | AWS-NR8-004 | KMS Key Rotation aktiviert | MEDIUM | §30(2) Nr.8: Schlüssel-Management | A.8.24 |
| ✅ | AWS-NR8-005 | CloudFront/ELB HTTPS-Only, TLS ≥1.2 | HIGH | §30(2) Nr.8: Verschlüsselung in Transit | A.8.24 |
| ✅ | AWS-NR8-006 | ELB/ALB TLS Policy ≥ TLS 1.2 | HIGH | §30(2) Nr.8 + "Stand der Technik" (§30(2) S.1) — TLS 1.0/1.1 ist nicht mehr Stand der Technik | A.8.24 |
| ✅ | AWS-NR8-007 | ACM Zertifikate nicht abgelaufen | CRITICAL | §30(2) Nr.8: Zertifikats-Management | A.8.24 |
| ✅ | AZ-NR8-001 | Storage Account Encryption (CMK preferred) | HIGH | §30(2) Nr.8: Verschlüsselung ruhender Daten | A.8.24 |
| ✅ | AZ-NR8-002 | Disk Encryption / SSE | HIGH | §30(2) Nr.8: Disk-Verschlüsselung | A.8.24 |
| ✅ | AZ-NR8-003 | SQL TDE aktiviert | HIGH | §30(2) Nr.8: Datenbank-Verschlüsselung | A.8.24 |
| ✅ | AZ-NR8-004 | Key Vault Rotation Policy | MEDIUM | §30(2) Nr.8: Schlüssel-Rotation | A.8.24 |
| ✅ | AZ-NR8-005 | App Service HTTPS Only + TLS 1.2+ | HIGH | §30(2) Nr.8: Transport-Verschlüsselung | A.8.24 |
| ✅ | AZ-NR8-006 | Application Gateway TLS Policy | HIGH | §30(2) Nr.8: "Stand der Technik" | A.8.24 |

#### §30 Abs. 2 Nr. 4 — Sicherheit der Lieferkette

| Status | Check-ID | Beschreibung | Schweregrad | §30 Text-Referenz | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR4-001 | Trusted Advisor Zugang (Business/Enterprise Support) | MEDIUM | §30(2) Nr.4: "Sicherheit der Lieferkette einschl. sicherheitsbezogener Aspekte der Beziehungen zwischen den einzelnen Einrichtungen und ihren unmittelbaren Anbietern oder Diensteanbietern" | A.5.19, A.5.21 |
| ✅ | AWS-NR4-002 | RAM (Resource Access Manager) Sharing-Policies | HIGH | §30(2) Nr.4: Kontrolle geteilter Ressourcen mit Dritten | A.5.20 |
| ✅ | AWS-NR4-003 | Organizations — externe Konten isoliert | HIGH | §30(2) Nr.4: Trennung von Drittanbieter-Zugriffen | A.5.19 |
| ✅ | AWS-NR4-004 | IAM Cross-Account Roles auditiert | HIGH | §30(2) Nr.4: Zugriffsrechte von Dienstleistern prüfen | A.5.20, A.8.3 |
| ✅ | AWS-NR4-005 | Service Control Policies für Drittanbieter-OUs | MEDIUM | §30(2) Nr.4: Einschränkung der Dienstleister-Berechtigungen | A.5.19 |
| ✅ | AZ-NR4-001 | Lighthouse Delegations geprüft | HIGH | §30(2) Nr.4: Delegierte Verwaltung durch MSPs | A.5.19 |
| ✅ | AZ-NR4-002 | Guest Users (B2B) mit Conditional Access | HIGH | §30(2) Nr.4: Externe Benutzer kontrolliert | A.5.20 |
| ✅ | AZ-NR4-003 | Private Endpoints für PaaS-Dienste | HIGH | §30(2) Nr.4: Netzwerk-Isolation von Diensten | A.5.19, A.8.22 |
| ✅ | AZ-NR4-004 | Service Principal Credentials rotiert | MEDIUM | §30(2) Nr.4: Automatisierte Zugriffe Dritter absichern | A.5.20 |
| ✅ | AZ-NR4-005 | Marketplace Image Trust Policy | MEDIUM | §30(2) Nr.4: Software-Lieferkette — nur vertrauenswürdige Quellen | A.5.19 |

#### §30 Abs. 2 Nr. 5 — Sicherheitsmaßnahmen bei Erwerb, Entwicklung, Wartung & Schwachstellenmanagement

| Status | Check-ID | Beschreibung | Schweregrad | §30 Text-Referenz | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR5-001 | ECR Image Scanning aktiviert | HIGH | §30(2) Nr.5: "Sicherheitsmaßnahmen bei Erwerb, Entwicklung und Wartung" — Container-Schwachstellenprüfung | A.8.8 |
| ✅ | AWS-NR5-002 | SSM Managed Instances (Patch Management) | HIGH | §30(2) Nr.5: "einschl. Management und Offenlegung von Schwachstellen" | A.8.8 |
| ✅ | AWS-NR5-003 | SSM Patch Manager Compliance | HIGH | §30(2) Nr.5: Wartung — Patches zeitnah einspielen, "Stand der Technik" (§30(2) S.1) | A.8.8, A.8.9 |
| ✅ | AWS-NR5-004 | Lambda Runtime-Versionen aktuell | MEDIUM | §30(2) Nr.5: Veraltete Laufzeitumgebungen = Schwachstelle | A.8.8 |
| ✅ | AWS-NR5-005 | AMI-Alter < 90 Tage für Produktionsinstanzen | MEDIUM | §30(2) Nr.5: Regelmäßige Aktualisierung der Betriebsumgebung | A.8.8 |
| ✅ | AZ-NR5-001 | Defender for Cloud — Vulnerability Assessment | HIGH | §30(2) Nr.5: Schwachstellenerkennung | A.8.8 |
| ✅ | AZ-NR5-002 | Update Management Center konfiguriert | HIGH | §30(2) Nr.5: Patch-Management | A.8.8, A.8.9 |
| ✅ | AZ-NR5-003 | Container Registry Image Scan | HIGH | §30(2) Nr.5: Container-Schwachstellen | A.8.8 |
| ✅ | AZ-NR5-004 | App Service Runtime aktuell | MEDIUM | §30(2) Nr.5: Laufzeitumgebung | A.8.8 |
| ✅ | AZ-NR5-005 | SQL Vulnerability Assessment aktiviert | HIGH | §30(2) Nr.5: Datenbank-Schwachstellen | A.8.8 |

#### §30 Abs. 2 Nr. 6 — Bewertung der Wirksamkeit von Risikomanagementmaßnahmen

| Status | Check-ID | Beschreibung | Schweregrad | §30 Text-Referenz | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR6-001 | CloudTrail Betriebliche Wirksamkeit (Log-Zustellung) | HIGH | §30(2) Nr.6: "Konzepte und Verfahren zur Bewertung der Wirksamkeit" — Manipulationsschutz für Audit-Logs | A.5.35, A.8.15 |
| ✅ | AWS-NR6-002 | Config Rules Compliance-Status | HIGH | §30(2) Nr.6: Automatisierte Compliance-Bewertung als Wirksamkeitsnachweis | A.5.35 |
| ✅ | AWS-NR6-003 | Security Hub Compliance Score ≥80% | HIGH | §30(2) Nr.6: Aggregierte Wirksamkeitsbewertung | A.5.35 |
| ✅ | AWS-NR6-004 | CloudWatch Log Retention ≥1 Jahr | MEDIUM | §30(2) Nr.6: Langfristige Nachvollziehbarkeit für Audits | A.8.15 |
| ✅ | AZ-NR6-001 | Defender Secure Score ≥70% | HIGH | §30(2) Nr.6: Aggregierter Wirksamkeitsindikator | A.5.35 |
| ✅ | AZ-NR6-002 | Azure Policy Compliance State | HIGH | §30(2) Nr.6: Automatisierte Compliance-Messung | A.5.35 |
| ✅ | AZ-NR6-003 | Activity Log Retention ≥365 Tage | MEDIUM | §30(2) Nr.6: Audit-Trail-Aufbewahrung | A.8.15 |
| ✅ | AZ-NR6-004 | Diagnostic Settings auf allen kritischen Ressourcen | HIGH | §30(2) Nr.6: Messbarer Nachweis aktiver Überwachung | A.5.35, A.8.15 |

#### §30 Abs. 2 Nr. 7 — Grundlegende Schulungen und Sensibilisierung

| Status | Check-ID | Beschreibung | Schweregrad | §30 Text-Referenz | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR7-001 | IAM Password Policy ≥14 Zeichen, Komplexität | HIGH | §30(2) Nr.7: "grundlegende Verfahren der Cyberhygiene" — Passwort-Mindeststandards | A.5.17 |
| ✅ | AWS-NR7-002 | Root-Account keine Access Keys | CRITICAL | §30(2) Nr.7: Basale Sicherheitshygiene — Root-Nutzung minimieren | A.5.17, A.8.2 |
| ✅ | AZ-NR7-001 | Entra ID Password Protection konfiguriert | HIGH | §30(2) Nr.7: Passwort-Hygiene | A.5.17 |
| ✅ | AZ-NR7-002 | Security Defaults oder Conditional Access Baseline | HIGH | §30(2) Nr.7: Grundlegende Sicherheitsstandards durchgesetzt | A.5.17 |

#### §30 Abs. 2 Nr. 9 — Personalsicherheit, Zugriffskontrolle und IKT-Verwaltung *(Phase 1 — AWS implementiert)*

| Status | Check-ID | Beschreibung | Schweregrad | §30 Text-Referenz | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR9-001 | IAM-User ohne MFA | HIGH | §30(2) Nr.9: "Zugriffskontrollkonzepte" — Identitätssicherung | A.5.15, A.8.5 |
| ✅ | AWS-NR9-002 | Access Keys älter als 90 Tage | HIGH | §30(2) Nr.9: "Verwaltung von Anlagen" — Credential-Lifecycle | A.5.15, A.8.5 |
| ✅ | AWS-NR9-003 | S3 Account-Level Public Access Block | CRITICAL | §30(2) Nr.9: Zugriffskontrolle — öffentlicher Zugriff verhindern | A.5.15, A.8.3 |
| ✅ | AWS-NR9-004 | Security Groups mit 0.0.0.0/0 (offene Ports) | HIGH | §30(2) Nr.9: Netzwerk-Zugriffskontrolle — Least-Privilege | A.8.20, A.8.22 |
| ✅ | AWS-NR9-005 | IAM Policies — keine wildcard (*) Berechtigungen | HIGH | §30(2) Nr.9: Zugriffskontrolle nach Least-Privilege-Prinzip | A.5.15, A.8.3 |
| ✅ | AWS-NR9-006 | S3 Bucket Policies — kein Principal: * | CRITICAL | §30(2) Nr.9: Keine anonymen Zugriffe auf Datenbestände | A.5.15, A.8.3 |
| ✅ | AWS-NR9-007 | Unused IAM Credentials (>90d inactive) | MEDIUM | §30(2) Nr.9: "Personalsicherheit" — Leaver-Prozess | A.5.15, A.6.5 |
| ✅ | AZ-NR9-001 | Entra ID Conditional Access Policies | HIGH | §30(2) Nr.9: Zugriffskontrolle | A.5.15 |
| ✅ | AZ-NR9-002 | Entra ID Privileged Identity Management (PIM) | HIGH | §30(2) Nr.9: Privilegierte Zugangsrechte zeitlich begrenzt | A.8.2, A.8.18 |
| ✅ | AZ-NR9-003 | NSG Rules — keine offenen Ports zu Internet | HIGH | §30(2) Nr.9: Netzwerk-Zugriffskontrolle | A.8.20, A.8.22 |
| ✅ | AZ-NR9-004 | Storage Account — Private Access Only | HIGH | §30(2) Nr.9: Kein öffentlicher Zugriff auf Speicher | A.5.15, A.8.3 |
| ✅ | AZ-NR9-005 | RBAC statt klassischer Subscription-Admin-Rollen | HIGH | §30(2) Nr.9: Rollenbasierte Zugriffskontrolle | A.5.15 |
| ✅ | AZ-NR9-006 | Entra ID Guest Access Restrictions | MEDIUM | §30(2) Nr.9: Externe Zugriffe kontrollieren | A.5.15, A.6.5 |
| ✅ | AZ-NR9-007 | Stale Service Principals (>90d inactive) | MEDIUM | §30(2) Nr.9: Nicht genutzte Identitäten entfernen | A.5.15 |

#### §30 Abs. 2 Nr. 10 — MFA, gesicherte Kommunikation und Notfallkommunikation *(Phase 1 — AWS implementiert)*

| Status | Check-ID | Beschreibung | Schweregrad | §30 Text-Referenz | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR10-001 | Root-Account MFA aktiviert | CRITICAL | §30(2) Nr.10: "Verwendung von Lösungen zur Multi-Faktor-Authentifizierung" — Root = höchste Privilegien | A.8.5 |
| ✅ | AWS-NR10-002 | Alle IAM-User mit MFA | HIGH | §30(2) Nr.10: MFA für alle Benutzer durchsetzen | A.8.5 |
| ✅ | AWS-NR10-003 | VPN / Client VPN für Admin-Zugriff | HIGH | §30(2) Nr.10: "gesicherte Sprach-, Video- und Textkommunikation" | A.8.20 |
| ✅ | AWS-NR10-004 | SES/SNS TLS-Erzwingung | MEDIUM | §30(2) Nr.10: Kommunikationsverschlüsselung | A.8.20 |
| ✅ | AWS-NR10-005 | Notfall-IAM-Break-Glass-Verfahren | HIGH | §30(2) Nr.10: "gesicherte Notfallkommunikationssysteme" — Zugriff bei Incident | A.5.30, A.8.5 |
| ✅ | AZ-NR10-001 | Entra ID MFA für alle Benutzer | CRITICAL | §30(2) Nr.10: MFA durchsetzen | A.8.5 |
| ✅ | AZ-NR10-002 | Entra ID — Phishing-resistant MFA (FIDO2/Windows Hello) | HIGH | §30(2) Nr.10: "Stand der Technik" — Phishing-resistente MFA | A.8.5 |
| ✅ | AZ-NR10-003 | VPN Gateway / Bastion Host für Admin-Zugriff | HIGH | §30(2) Nr.10: Gesicherte Admin-Kommunikation | A.8.20 |
| ✅ | AZ-NR10-004 | Teams/Exchange — TLS erzwungen | MEDIUM | §30(2) Nr.10: Gesicherte Kommunikation | A.8.20 |
| ✅ | AZ-NR10-005 | Emergency Access Accounts (Break Glass) | HIGH | §30(2) Nr.10: Notfallzugriff gesichert | A.5.30, A.8.5 |

---

## ISMS-Dokumentenstruktur

nis2scan prüft technische Controls. Aber §30 BSIG verlangt auch **dokumentierte organisatorische Maßnahmen** — ein ISMS. Die folgende Struktur orientiert sich an der **4-Ebenen-Hierarchie** (ISO 27001 Annex A + BSI IT-Grundschutz) und mappt jedes Dokument auf die konkreten Anforderungen von §30 BSIG und ISO 27001:2022.

### ISMS-Dokumentenhierarchie (4 Ebenen)

```
Ebene 1: Leitlinie (strategisch — §30(1) BSIG)
├── Informationssicherheits-Leitlinie (IS-Policy)
│   └── Gilt für: Alle §30-Bereiche. Vom GF unterschrieben.
│
Ebene 2: Richtlinien (taktisch — je §30-Bereich eine Richtlinie)
├── [§30 Nr.1]  Risikomanagement-Richtlinie
├── [§30 Nr.2]  Incident-Response-Richtlinie
├── [§30 Nr.3]  Business-Continuity-Richtlinie
├── [§30 Nr.4]  Lieferketten-Sicherheitsrichtlinie
├── [§30 Nr.5]  Sichere Entwicklung & Patch-Richtlinie
├── [§30 Nr.6]  Audit- & Wirksamkeitsbewertungsrichtlinie
├── [§30 Nr.7]  Schulungs- & Awareness-Richtlinie
├── [§30 Nr.8]  Kryptographie-Richtlinie
├── [§30 Nr.9]  Zugriffskontroll- & Asset-Richtlinie
├── [§30 Nr.10] MFA- & Kommunikationssicherheitsrichtlinie
│
Ebene 3: Konzepte & Pläne (operativ)
├── [§30 Nr.1]  Risiko-Register + Risikobehandlungsplan
├── [§30 Nr.1]  Scope-Definition & Asset-Register
├── [§30 Nr.2]  Incident-Response-Plan mit Eskalationsmatrix
├── [§30 Nr.2]  BSI-Meldevorlagen (24h/72h/1M nach §32)
├── [§30 Nr.2]  Forensik-Leitfaden
├── [§30 Nr.3]  Business-Impact-Analyse (BIA)
├── [§30 Nr.3]  Disaster-Recovery-Plan (je Standort/Cloud-Region)
├── [§30 Nr.3]  Krisenmanagement-Handbuch
├── [§30 Nr.4]  Lieferanten-Register mit Kritikalitätsbewertung
├── [§30 Nr.4]  Muster-Sicherheitsklauseln für Verträge
├── [§30 Nr.4]  Cloud-Provider Shared-Responsibility-Matrix
├── [§30 Nr.5]  Patch-Management-Prozess
├── [§30 Nr.5]  Secure-Development-Lifecycle (SDL)
├── [§30 Nr.5]  Vulnerability-Disclosure-Policy
├── [§30 Nr.5]  Change-Management-Prozess
├── [§30 Nr.6]  ISMS-KPI-Dashboard
├── [§30 Nr.6]  Internes Audit-Programm (Jahresplan)
├── [§30 Nr.7]  Schulungsplan mit Zielgruppen × Themen
├── [§30 Nr.7]  Phishing-Simulations-Fahrplan
├── [§30 Nr.8]  Erlaubte Algorithmen & Schlüssellängen
├── [§30 Nr.8]  Key-Management-Prozess
├── [§30 Nr.8]  Zertifikats-Inventar & Renewal-Prozess
├── [§30 Nr.9]  Joiner/Mover/Leaver-Prozess
├── [§30 Nr.9]  Privileged-Access-Management (PAM) Konzept
├── [§30 Nr.9]  Hardware/Software/Daten-Inventar
├── [§30 Nr.10] MFA-Rollout-Plan
├── [§30 Nr.10] Notfallkommunikationsplan (Out-of-Band)
│
Ebene 4: Nachweise & Records (Audit-Trail)
├── [§30 Nr.1]  Risikobewertungs-Protokolle (mind. jährlich)
├── [§30 Nr.2]  Incident-Tickets & Post-Mortem-Reports
├── [§30 Nr.2]  BSI-Meldebelege (Ticket-Nr. + Zeitstempel)
├── [§30 Nr.3]  DR-Test-Protokolle (mind. jährlich)
├── [§30 Nr.3]  Backup-Restore-Testprotokolle
├── [§30 Nr.4]  Lieferanten-Assessment-Ergebnisse
├── [§30 Nr.5]  Patch-Compliance-Reports
├── [§30 Nr.5]  Vulnerability-Scan-Berichte
├── [§30 Nr.6]  Interne Audit-Berichte
├── [§30 Nr.6]  Management-Review-Protokolle (mind. jährlich, §38!)
├── [§30 Nr.6]  nis2scan Compliance-Reports (automatisiert!)
├── [§30 Nr.7]  Schulungsnachweise pro Mitarbeiter
├── [§30 Nr.7]  Phishing-Simulations-Ergebnisse
├── [§30 Nr.7]  GF-Schulungsnachweis (§38 BSIG — Pflicht!)
├── [§30 Nr.8]  Key-Rotation-Logs
├── [§30 Nr.9]  Access-Review-Protokolle (quartalsweise)
├── [§30 Nr.10] MFA-Enrollment-Status-Reports
│
Querschnittsdokumente (nicht §30-spezifisch)
├── [§33]        BSI-Registrierungsbestätigung
├── [§38]        Geschäftsführer-Schulungsnachweis + Billigungsprotokoll
├── [§30(1) S.3] Dokumentation aller Maßnahmen (Pflicht — "verhältnismäßig")
├── ISMS-Geltungsbereich & Organisationsstruktur
├── RACI-Matrix für Informationssicherheit
├── Statement of Applicability (SoA — bei ISO 27001 Zertifizierung)
└── Kontinuierlicher Verbesserungsprozess (KVP / PDCA-Zyklus)
```

### Ebene 2: Richtlinien — was muss je §30-Bereich drinstehen?

Jede Richtlinie auf Ebene 2 muss über den reinen Gesetzestext hinausgehen und die Anforderungen aus §30 BSIG und ISO 27001 operationalisieren:

| §30 Nr. | Richtlinie | Pflichtinhalte (Auszug) | ISO 27001 |
|----------|-----------|------------------------|-----------|
| **1** | Risikomanagement-RL | Methodik (NIST/ISO 27005), Risikokategorien, Bewertungskriterien, Risikoappetit, Eskalationsschwellen | 6.1.2, A.5.1 |
| **2** | Incident-Response-RL | Vorfallkategorien (P1-P4), Eskalationsstufen, §32-Meldefristen (24h/72h/1M), Forensik, Lessons Learned | A.5.24-A.5.28 |
| **3** | Business-Continuity-RL | RTO/RPO je Kritikalität, Backup-Strategie (3-2-1-Regel), DR-Szenarien, Krisenorganisation, Testrhythmus | A.5.29-A.5.30, A.8.13 |
| **4** | Lieferketten-Sicherheits-RL | Lieferantenkategorisierung, Mindestklauseln (SLA, Audit-Recht, Subunternehmer), Shared-Responsibility-Matrix | A.5.19-A.5.23 |
| **5** | SDL & Patch-RL | SDL-Phasen, Patch-SLAs (Critical: 24h, High: 72h), VDP, Change-Management (CAB), SBOM-Pflicht | A.8.8-A.8.9, A.8.25 |
| **6** | Audit & Wirksamkeits-RL | Audit-Programm (Frequenz, Scope), KPIs (MTTD, Patch-Rate, MFA-Coverage), Management-Review (§38!) | 9.2, 9.3, A.5.35 |
| **7** | Schulungs & Awareness-RL | Zielgruppen (GF §38, Admins, Devs, alle MA), Pflichtmodule, Frequenz, Phishing-Simulation, Erfolgsmessung | A.6.3, A.5.17 |
| **8** | Kryptographie-RL | Erlaubte Algorithmen (BSI TR-02102), Verbotene Verfahren, Schlüssel-Lifecycle, HSM/KMS-Pflicht, Crypto-Agility | A.8.24 |
| **9** | Zugriffskontroll & Asset-RL | Need-to-Know, RBAC, JML-Prozess, PAM (Just-in-Time), Access Reviews, Asset-Klassifikation (C/I/A), CMDB | A.5.15-A.5.18, A.8.1-A.8.5 |
| **10** | MFA & Kommunikations-RL | MFA-Pflicht (FIDO2 bevorzugt), E2E-Verschlüsselung, Notfallkommunikation (Out-of-Band), Break-Glass-Verfahren | A.8.5, A.8.20 |

### Verbindung Scanner → ISMS-Dokumente

nis2scan-Reports dienen als **automatisierte Nachweise auf Ebene 4**. Der Scanner ersetzt nicht die Dokumente auf Ebene 1-3 (die muss der Mensch schreiben/ausfüllen), aber er liefert:

| Was nis2scan liefert | Ersetzt welches Dokument? | ISMS-Ebene |
|---------------------|--------------------------|------------|
| Compliance-Report als JSON/MD/PDF | Technischer Prüfbericht für internes Audit | Ebene 4 |
| Findings pro §30-Bereich | Input für Risiko-Register (Ebene 3) | Ebene 3 → 4 |
| Compliance-Score über Zeit | KPI-Input für ISMS-Dashboard (Ebene 3) | Ebene 3 |
| Remediation-as-Code | Maßnahmenplan-Anhang (Ebene 3) | Ebene 3 |
| Permission-Policy Export | Dokumentation der technischen Controls | Ebene 3 |
| Drift-Detection (Continuous Monitoring) | Regressionswarnung bei Verschlechterung | Ebene 4 |

### Was der Scanner NICHT ersetzt

- **Ebene 1:** Die IS-Leitlinie muss vom GF unterschrieben werden (§38 BSIG)
- **Ebene 2:** Richtlinien müssen unternehmensspezifisch formuliert sein
- **Ebene 3:** BIA, DR-Pläne, Schulungspläne sind organisatorische Prozesse
- **§32-Meldungen:** Der Scanner meldet keine Vorfälle ans BSI — das ist ein manueller Pflichtprozess
- **§38 GF-Schulung:** Die Geschäftsführer-Schulung muss tatsächlich stattfinden (persönliche Pflicht)
- **§39 KRITIS-Audit:** Für KRITIS-Betreiber: BSI-Audit alle 3 Jahre — nis2scan kann vorbereiten, nicht ersetzen

→ **Für die Dokumente auf Ebene 1-3 ist ein NIS2 ISMS Starter Kit in Vorbereitung — vorgefertigte, an §30 BSIG und ISO 27001 orientierte Templates mit Ausfüllhilfen. Interesse? [GitHub-Issue öffnen](https://github.com/VVulpe/nis2scan/issues).**

---

## Installation

```bash
# Von PyPI
pip install nis2scan

# Oder aus dem Repo
git clone https://github.com/VVulpe/nis2scan.git
cd nis2scan
pip install -e .
```

## Konfiguration

```yaml
# config/default.yaml
company:
  name: "Ihre GmbH"
  sector: "manufacturing"
  nis2_category: "important"

scan:
  providers:
    aws:
      enabled: true
      profile: "nis2scan-readonly"
      regions: ["eu-central-1", "eu-west-1"]
    azure:
      enabled: false
  bsig_30_scope: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]
```

## Benötigte Permissions

Detaillierte Dokumentation aller benötigten Permissions:
**[docs/permissions.md](https://github.com/VVulpe/nis2scan/blob/main/docs/permissions.md)** — AWS IAM Policies, Azure RBAC + Graph API, Service Principal Setup, OIDC CI/CD Setup.

```bash
# Minimale IAM Policy automatisch generieren
nis2scan permissions --provider aws --format terraform
nis2scan permissions --provider azure --format azurecli
```

## Nutzung

```bash
# Vollständiger Scan
nis2scan scan --provider aws --config config.yaml

# Nur bestimmte §30-Bereiche
nis2scan scan --provider aws --bsig-nr 8,9,10

# Output als JSON
nis2scan scan --provider aws --format json --output report.json
```

## Contributing

Beiträge willkommen! Besonders gesucht:
- Neue Check-Module (siehe `.claude/skills/nis2-check/SKILL.md` für Patterns)
- Übersetzungen (EN)
- Bug Reports & Feature Requests

## Lizenz

Apache License 2.0 — siehe [LICENSE](https://github.com/VVulpe/nis2scan/blob/main/LICENSE).
Dieses Repository enthält den vollständigen freien Scanner (alle Checks, alle
Provider). Premium-Features (PDF-Export, Remediation-as-Code, Continuous
Monitoring, SaaS-Dashboard) sind proprietäre Erweiterungen in separaten
Repositories und erfordern eine Lizenz. Anfragen: [GitHub Issues](https://github.com/VVulpe/nis2scan/issues).

---

*nis2scan ist ein unabhängiges Open-Source-Projekt und steht in keiner Verbindung zum BSI, zur Bundesregierung oder zu Cloud-Anbietern.*
