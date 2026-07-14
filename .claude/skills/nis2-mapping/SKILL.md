---
name: nis2-mapping
description: Reference for §30 BSIG legal mapping and ISO 27001 controls. Use when creating or verifying compliance mappings, writing Finding descriptions, or generating report sections that reference the legal basis. Triggers on §30, BSIG, NIS2UmsVO, ISO 27001, mapping, legal, Gesetzestext, Maßnahme.
allowed-tools: Read, Grep
---

# §30 BSIG Compliance Mapping Reference

## The 10 Mandatory Measures (§30 Abs. 2 BSIG)

| Nr. | German Title | ISO 27001:2022 | Key Cloud Services |
|-----|-------------|----------------|-------------------|
| 1 | Risikoanalyse und IT-Sicherheitskonzepte | A.5.1, A.6.1 | Config, Security Hub, Defender for Cloud |
| 2 | Bewältigung von Sicherheitsvorfällen | A.5.24-A.5.28 | GuardDuty, Detective, Sentinel |
| 3 | Aufrechterhaltung des Betriebs (BCM) | A.5.29-A.5.30 | AWS Backup, Azure Site Recovery |
| 4 | Sicherheit der Lieferkette | A.5.19-A.5.23 | Cross-account IAM, External Identities |
| 5 | Sicherheit bei Erwerb/Entwicklung/Wartung | A.8.25-A.8.31 | Inspector, Patch Manager, Defender |
| 6 | Wirksamkeitsbewertung | A.5.35-A.5.36 | Security Hub Score, Secure Score |
| 7 | Grundlegende Schulungen und Sensibilisierung | A.6.3 | IAM Credential Report, Risky Sign-ins |
| 8 | Kryptographische Verfahren | A.8.24 | KMS, ACM, Key Vault, TDE |
| 9 | Personalsicherheit, Zugriffskontrolle und IKT-Verwaltung | A.5.9-A.5.18, A.6.1-A.6.6 | IAM, Entra ID, Conditional Access |
| 10 | MFA und gesicherte Kommunikation | A.8.5, A.5.14 | MFA, VPN, PrivateLink, Private Endpoints |

## Report Text Templates

When generating Finding descriptions or report sections, always include:
- The exact §30 reference: "§30 Abs. 2 Nr. {N} BSIG"
- The German title of the measure
- The ISO 27001 cross-reference where applicable

## Severity Mapping to §30 Compliance Impact

- CRITICAL = Fundamental gap: the measure is effectively not implemented
- HIGH = Significant gap: core requirements of the measure are not met  
- MEDIUM = Partial: measure is partially implemented but has material gaps
- LOW = Minor: measure is implemented but could be improved
- INFO = Compliant, informational note only

## Important Legal Context

- §32 BSIG: Meldepflichten (24h Erstmeldung, 72h Folgemeldung, 1 Monat Abschluss)
- §38 BSIG: Geschäftsführer haften persönlich für Umsetzung und Überwachung
- §39 BSIG: KRITIS-Betreiber müssen Nachweis alle 3 Jahre erbringen
- Keine Übergangsfrist: Pflichten gelten seit 06.12.2025 sofort
