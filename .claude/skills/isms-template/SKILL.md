---
name: isms-template
description: Create ISMS document templates for NIS2 §30 BSIG compliance. Use when writing policy documents, risk analysis templates, incident response plans, or any ISMS documentation. Triggers on ISMS, template, policy, Richtlinie, Konzept, Leitlinie, Vorlage, §30, NIS2 Dokument, Audit, Nachweis.
allowed-tools: Read, Write, Edit, Bash, Grep
---

# ISMS Template Creation for NIS2

## Core Principle: Beyond Minimum Compliance

§30 BSIG defines 10 mandatory measures in one sentence each. That's the MINIMUM. Our templates go further, operationalizing each measure against ISO 27001:2022 controls — structured so a company could also pursue ISO 27001 certification without major rework.

## ISMS Document Hierarchy (4 Levels)

Every template must declare its level:

```
Level 1: Leitlinie    — Strategic, signed by CEO/GF. Says WHAT and WHY.
Level 2: Richtlinie   — Tactical, per §30 area. Says WHAT is required.
Level 3: Konzept/Plan — Operational, working documents. Says HOW.
Level 4: Nachweis      — Evidence/records. Says WHEN and BY WHOM.
```

nis2scan generates Level 4 (compliance reports). Templates cover Levels 1-3.

## Template Document Structure (MANDATORY for all templates)

```markdown
# [Document Title]
## [§30 Abs. 2 Nr. X — German title]

### Dokumenteninformationen
| Feld | Wert |
|------|------|
| Dokumentenklassifikation | [Vertraulich / Intern / Öffentlich] |
| ISMS-Ebene | [Leitlinie / Richtlinie / Konzept] |
| §30 BSIG Referenz | §30 Abs. 2 Nr. [X] |
| ISO 27001:2022 | [A.X.X] |
| Version | 1.0 |
| Nächste Überprüfung | [DATUM + 12 Monate] |
| Verantwortlich | [ROLLE] |
| Freigabe durch | [GF / ISB] |

### Änderungshistorie
| Version | Datum | Autor | Änderung |
|---------|-------|-------|----------|

### 1. Zweck und Geltungsbereich
### 2. Gesetzliche Grundlage (exakter §30-Text + ISO)
### 3. Begriffsdefinitionen
### 4. Rollen und Verantwortlichkeiten
### 5. [Content sections — see per-area specs below]
### 6. Ausnahmen und Eskalation
### 7. Sanktionen bei Verstößen
### 8. Inkrafttreten und Überprüfung
### Anhang A: Selbstbewertungs-Checkliste
### Anhang B: Zugehörige nis2scan-Checks (Check-IDs + was sie prüfen)
```

## Per-§30-Area: What Goes Beyond the Law

### Nr. 1 — Risikoanalyse
§30 says: "Konzepte in Bezug auf die Risikoanalyse"
Template adds: Risk appetite definition, 5×5 matrix + quantitative ALE option, risk ownership model, asset classification (4 tiers), threat intelligence integration, treatment options with approval matrix, pre-populated cloud risk register (20 entries).

### Nr. 2 — Incident Response
§30 says: "Bewältigung von Sicherheitsvorfällen"
Template adds: Full lifecycle (detect→triage→contain→eradicate→recover→review), S1-S4 classification with response time SLAs, §32 BSI notification templates (24h/72h/1M), communication plan (press, customers, regulators, insurance), 5 specific scenario runbooks (ransomware, data breach, DDoS, IAM compromise, supply chain), tabletop exercise script, law enforcement coordination (LKA ZAC).

### Nr. 3 — Business Continuity
§30 says: "Aufrechterhaltung des Betriebs, Backup-Management, Wiederherstellung, Krisenmanagement"
Template adds: BIA methodology with predefined criteria, RTO/RPO tier system (4 tiers), Krisenstab composition and roles, crisis communication plan, return-to-normal criteria, testing requirements (annual DR + quarterly backup restore), cloud-specific DR procedures per region.

### Nr. 4 — Lieferkettensicherheit
§30 says: "Sicherheit der Lieferkette einschließlich sicherheitsbezogener Aspekte"
Template adds: ABC supplier classification, due diligence per tier, 30-question assessment questionnaire, ready-to-use contract security clauses, AWS/Azure Shared Responsibility Model mapped to §30, vendor exit strategy, incident notification chain from suppliers.

### Nr. 5 — Vulnerability Management
§30 says: "Sicherheitsmaßnahmen bei Erwerb, Entwicklung und Wartung, einschl. Schwachstellenmanagement"
Template adds: Patch SLAs (Critical 24h, High 7d, Medium 30d, Low 90d), exception process, scanning frequency, SDL for custom software, change management, hardening checklists (EC2, Azure VM, Container), Vulnerability Disclosure Policy.

### Nr. 6 — Wirksamkeitsbewertung
§30 says: "Bewertung der Wirksamkeit von Risikomanagementmaßnahmen"
Template adds: 10 quantitative KPIs with targets (MTTP, encryption %, MFA %, open findings, backup success rate, phishing click rate, detection time), internal audit program (annual per §30 area), nis2scan as continuous assessment, management review template (§38!), PDCA cycle.

### Nr. 7 — Cyberhygiene & Schulungen
§30 says: "Grundlegende Schulungen und Cyberhygiene"
Template adds: Training matrix (role × topic × frequency), MANDATORY §38 GF training documented, phishing simulation program (monthly, increasing difficulty), knowledge verification (quiz), training delivery methods, complete documentation trail for audit.

### Nr. 8 — Kryptographie
§30 says: "Konzepte für den Einsatz kryptographischer Verfahren"
Template adds: Allowed algorithms whitelist (AES-256, TLS 1.2+, RSA-2048+, Ed25519), explicit blacklist (DES, RC4, MD5, SHA-1, TLS 1.0/1.1), key management lifecycle, cloud decision matrix (KMS CMK vs SSE-S3, Key Vault vs Microsoft-managed), certificate inventory and renewal, crypto-agility for post-quantum.

### Nr. 9 — Zugriffskontrolle
§30 says: "Personalsicherheit, Zugriffskontrolle, Verwaltung von IKT-Systemen"
Template adds: THREE sub-documents: Asset Management (HW/SW/Data inventory, classification, ownership), Personnel Security (background checks, NDAs, JML process), Access Control (RBAC, least privilege, admin separation, quarterly access reviews), cloud-specific IAM governance.

### Nr. 10 — MFA & Kommunikation
§30 says: "MFA, gesicherte Kommunikation, Notfallkommunikation"
Template adds: MFA method hierarchy (FIDO2 > TOTP > SMS), MFA scope definition, secure channel per data class, Notfallkommunikation plan (Signal group, satellite phone, predefined out-of-band when primary channels compromised).

## Cross-Cutting Templates (not §30-specific)

Always create these as part of a complete ISMS package:
- Informationssicherheits-Leitlinie (Level 1, signed by GF)
- ISMS Geltungsbereich & Scope
- RACI-Matrix für Informationssicherheit
- GF-Billigungsprotokoll (§38 proof)
- GF-Schulungsnachweis (§38 proof)
- NIS2-Betroffenheitsanalyse (§28 self-assessment)
- BSI-Registrierungs-Checkliste (§33)
- Statement of Applicability (ISO 27001 ready)
- NIS2-Maßnahmen-Tracker (Excel, all 10 areas)

## Writing Rules
- Language: German, formal ("Sie")
- Placeholders: [UNTERNEHMENSNAME], [DATUM], [VERANTWORTLICHER], [GELTUNGSBEREICH], [BRANCHE], [NIS2-KATEGORIE]
- Add "(Ausfüllhinweis: ...)" in italics at every placeholder
- Include cloud examples (AWS/Azure) where relevant
- Self-contained: no mandatory cross-references to other templates
- Target audience: IT-Leiter without GRC background
- Mark "Mindestanforderung" (legal min) vs "Empfehlung" (best practice) where they differ
- Reference nis2scan Check-IDs in Anhang B of every template

## Quality Criteria
- Usable within 2 hours of filling in placeholders
- Passes "would an auditor accept this?" test
- Includes review cycle (annually + after significant changes)
- Includes version control and approval workflow
- References §30 BSIG AND ISO 27001 for each section
