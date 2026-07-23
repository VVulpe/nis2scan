# nis2scan: NIS2 Cloud Compliance Scanner

*Deutsche Version: [README.md](README.md)*

**Automated §30 BSIG compliance scanning for AWS, Azure & GCP**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache%202.0-blue.svg)](https://github.com/VVulpe/nis2scan/blob/main/LICENSE)
[![Python 3.12+](https://img.shields.io/badge/python-3.12+-blue.svg)](https://www.python.org/)

nis2scan automatically scans your cloud environment (AWS, Azure, GCP) against the 10 core measures of §30 Abs. 2 BSIG (part of the NIS2UmsuCG). Every finding is mapped directly to the legal text and ISO 27001:2022, making it audit-ready.

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

**Detailed guide:** [docs/getting-started.md](https://github.com/VVulpe/nis2scan/blob/main/docs/getting-started.md): installation, cloud setup (AWS/Azure/GCP), configuration, CLI reference, troubleshooting.

> **Windows:** Please install into a venv (short path; Python 3.12+).
> For details and troubleshooting, see
> [Getting Started → Installation](https://github.com/VVulpe/nis2scan/blob/main/docs/getting-started.md#installation).

---

## Legal basis

The NIS2-Umsetzungsgesetz (NIS2UmsuCG, the German NIS2 implementation act amending the BSI Act) took effect on 06.12.2025. It primarily amends the BSI-Gesetz (BSIG, Germany's Federal Office for Information Security Act). There is no transition period: the obligations apply immediately.

### Relevant laws & regulations

| Document | Description | Link |
|----------|-------------|------|
| **BSIG (BSI-Gesetz)** | Core law with all NIS2 obligations for companies | [gesetze-im-internet.de](https://www.gesetze-im-internet.de/bsig_2025/) |
| **§28 BSIG** | Who is in scope? Definition of "besonders wichtige Einrichtungen" (essential entities) and "wichtige Einrichtungen" (important entities) | [§28 full text](https://www.gesetze-im-internet.de/bsig_2025/__28.html) |
| **§30 BSIG** | **THE core provision**: 10 risk management measures (our scan scope) | [§30 full text](https://www.gesetze-im-internet.de/bsig_2025/__30.html) |
| **§31 BSIG** | Additional requirements for operators of critical facilities ("KRITIS", Germany's critical infrastructure regime) | [§31 full text](https://www.gesetze-im-internet.de/bsig_2025/__31.html) |
| **§32 BSIG** | Reporting obligations: 24h initial report, 72h follow-up report, 1 month final report | [§32 full text](https://www.gesetze-im-internet.de/bsig_2025/__32.html) |
| **§33 BSIG** | Registration obligation with the BSI | [§33 full text](https://www.gesetze-im-internet.de/bsig_2025/__33.html) |
| **§38 BSIG** | Personal liability of management + mandatory training | [§38 full text](https://www.gesetze-im-internet.de/bsig_2025/__38.html) |
| **§39 BSIG** | Evidence obligations for KRITIS operators (audit every 3 years) | [§39 full text](https://www.gesetze-im-internet.de/bsig_2025/__39.html) |
| **§65 BSIG** | Fines: up to EUR 10 million or 2% of annual turnover | [§65 full text](https://www.gesetze-im-internet.de/bsig_2025/__65.html) |
| **NIS2 Directive (EU)** | EU Directive 2022/2555, the European legal basis | [EUR-Lex](https://eur-lex.europa.eu/eli/dir/2022/2555/oj/deu) |
| **Implementing Regulation (EU) 2024/2690** | Applies only to certain digital providers (e.g. cloud, DNS, data center services); does not generally specify §30 BSIG | [EUR-Lex](https://eur-lex.europa.eu/eli/reg_impl/2024/2690/oj/deu) |
| **NIS2UmsuCG (amending act)** | The actual transposition act (amends the BSIG and other laws) | [BGBl Nr. 301/2025](https://www.recht.bund.de/bgbl/1/2025/301/VO.html) |
| **ISO/IEC 27001:2022** | International ISMS standard that NIS2 is modeled on | [ISO.org](https://www.iso.org/standard/27001) |
| **BSI IT-Grundschutz** | BSI's own standard, particularly relevant for federal administration | [BSI](https://www.bsi.bund.de/grundschutz) |

### Applicability thresholds (§28 BSIG)

| Category | Criteria | Fine risk |
|-----------|-----------|---------------|
| **"Besonders wichtige Einrichtung" (essential entity)** | ≥250 employees or >EUR 50 million turnover in a critical sector | Up to EUR 10 million or 2% of annual turnover |
| **"Wichtige Einrichtung" (important entity)** | ≥50 employees or >EUR 10 million turnover in a regulated sector | Up to EUR 7 million or 1.4% of annual turnover |
| **Indirectly affected** | Supplier/service provider to an in-scope entity | Contractual liability |

---

## §30 BSIG → scan mapping

The central table: which check verifies which legal requirement?

### Overview

| §30 No. | Measure | Legal text (abridged) | AWS | Azure | GCP | ISMS document |
|----------|----------|----------------------|-----|-------|-----|---------------|
| **1** | Risk analysis | Concepts for risk analysis and information technology security | ✅ 5 | ✅ 5 | ✅ 5 | IS policy + risk analysis |
| **2** | Incident response | Handling of security incidents | ✅ 5 | ✅ 5 | ✅ 5 | Incident response plan |
| **3** | Business continuity | Maintaining operations, backup management, recovery, crisis management | ✅ 7 | ✅ 7 | ✅ 7 | BC/DR plan |
| **4** | Supply chain security | Supply chain security incl. security-related aspects of relationships with suppliers | ✅ 5 | ✅ 5 | ✅ 5 | Supply chain concept |
| **5** | Vulnerability management | Security measures in acquisition, development and maintenance, incl. vulnerability management | ✅ 5 | ✅ 5 | ✅ 5 | SDL + patch policy |
| **6** | Effectiveness assessment | Concepts and procedures for assessing the effectiveness of risk management measures | ✅ 4 | ✅ 4 | ✅ 4 | Audit program + KPIs |
| **7** | Cyber hygiene | Basic training and cyber hygiene | ✅ 2 | ✅ 2 | ✅ 2 | Training concept |
| **8** | Cryptography | Concepts and processes for the use of cryptographic methods | ✅ 7 | ✅ 6 | ✅ 6 | Cryptography policy |
| **9** | Access control | Personnel security, access control, management of ICT systems | ✅ 7 | ✅ 7 | ✅ 7 | Access control policy |
| **10** | MFA & communication | MFA, secure voice/video/text communication, emergency communication | ✅ 5 | ✅ 5 | ✅ 5 | MFA policy + comms policy |

**Legend:** ✅ = implemented & tested

### Detailed mapping: every check → legal text

#### §30 Abs. 2 Nr. 1: Risk analysis and IT security concepts

| Status | Check ID | Description | Severity | §30 text reference | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR1-001 | AWS Config Recorder active (all regions) | HIGH | §30(2) Nr.1: "Konzepte in Bezug auf die Risikoanalyse" (concepts for risk analysis), because risk analysis requires visibility into all assets | A.5.1, A.8.9 |
| ✅ | AWS-NR1-002 | Security Hub enabled with CIS/Foundational Benchmarks | HIGH | §30(2) Nr.1: the security concept must "Stand der Technik einhalten" (keep up with the state of the art) (§30(2) S.1) | A.5.1 |
| ✅ | AWS-NR1-003 | AWS Organizations with SCPs in place | MEDIUM | §30(2) Nr.1: organization-wide security architecture | A.5.1, A.5.2 |
| ✅ | AWS-NR1-004 | CloudTrail active in all regions, log validation | CRITICAL | §30(2) Nr.1 + Nr.6: traceability is a prerequisite for risk analysis and effectiveness assessment | A.8.15 |
| ✅ | AWS-NR1-005 | GuardDuty enabled | HIGH | §30(2) Nr.1: threat detection as part of risk analysis | A.5.7 |
| ✅ | AZ-NR1-001 | Defender for Cloud enabled (all subscriptions) | HIGH | §30(2) Nr.1: central security assessment | A.5.1 |
| ✅ | AZ-NR1-002 | Azure Policy assignments in place | HIGH | §30(2) Nr.1: enforcement of security standards | A.5.1, A.5.2 |
| ✅ | AZ-NR1-003 | Management groups configured | MEDIUM | §30(2) Nr.1: organization-wide governance | A.5.1 |
| ✅ | AZ-NR1-004 | Activity Log to Log Analytics/Storage | CRITICAL | §30(2) Nr.1 + Nr.6: audit trail | A.8.15 |
| ✅ | AZ-NR1-005 | Sentinel or equivalent SIEM | HIGH | §30(2) Nr.1: threat detection | A.5.7 |

#### §30 Abs. 2 Nr. 2: Handling of security incidents

| Status | Check ID | Description | Severity | §30 text reference | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR2-001 | GuardDuty enabled (threat detection) | CRITICAL | §30(2) Nr.2: "Bewältigung von Sicherheitsvorfällen" (handling of security incidents): detection + automatic routing | A.5.24 |
| ✅ | AWS-NR2-002 | Security Hub findings aggregated | MEDIUM | §30(2) Nr.2: central view of security incidents | A.5.25 |
| ✅ | AWS-NR2-003 | Incident Manager / OpsCenter configured | MEDIUM | §30(2) Nr.2: structured incident handling with escalation paths | A.5.26 |
| ✅ | AWS-NR2-004 | CloudWatch alarms for critical metrics | HIGH | §30(2) Nr.2: proactive detection of anomalies | A.5.24, A.8.16 |
| ✅ | AWS-NR2-005 | Detective enabled (forensics) | LOW | §30(2) Nr.2: forensic analysis capability | A.5.27 |
| ✅ | AZ-NR2-001 | Defender alert notifications configured | HIGH | §30(2) Nr.2: automatic notification | A.5.24 |
| ✅ | AZ-NR2-002 | Sentinel analytics rules active | HIGH | §30(2) Nr.2: rule-based detection | A.5.24, A.8.16 |
| ✅ | AZ-NR2-003 | Sentinel playbooks/Logic Apps for auto-response | MEDIUM | §30(2) Nr.2: automated containment | A.5.26 |
| ✅ | AZ-NR2-004 | Action groups for alerting | HIGH | §30(2) Nr.2: escalation paths | A.5.24 |
| ✅ | AZ-NR2-005 | Alert processing rules defined | MEDIUM | §30(2) Nr.2: prioritization and routing | A.5.25 |

#### §30 Abs. 2 Nr. 3: Maintaining operations (business continuity management)

| Status | Check ID | Description | Severity | §30 text reference | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR3-001 | RDS automated backups + retention ≥7d | HIGH | §30(2) Nr.3: "Backup-Management und Wiederherstellung nach einem Notfall" (backup management and disaster recovery) | A.8.13 |
| ✅ | AWS-NR3-002 | S3 versioning on critical buckets | MEDIUM | §30(2) Nr.3: data recovery | A.8.13 |
| ✅ | AWS-NR3-003 | S3 Object Lock / Glacier Vault Lock | HIGH | §30(2) Nr.3: ransomware protection (immutability) | A.8.13 |
| ✅ | AWS-NR3-004 | Multi-AZ for production workloads | HIGH | §30(2) Nr.3: "Aufrechterhaltung des Betriebs" (maintaining operations): availability | A.5.29, A.8.14 |
| ✅ | AWS-NR3-005 | AWS Backup plans with cross-region copy | HIGH | §30(2) Nr.3: "Wiederherstellung nach einem Notfall" (disaster recovery): geo-redundancy | A.8.13 |
| ✅ | AWS-NR3-006 | EBS snapshots taken regularly + encrypted | MEDIUM | §30(2) Nr.3 + Nr.8: backup + encryption | A.8.13, A.8.24 |
| ✅ | AWS-NR3-007 | Route 53 health checks | LOW | §30(2) Nr.3: availability monitoring | A.8.14 |
| ✅ | AZ-NR3-001 | Azure Backup vaults with policies | HIGH | §30(2) Nr.3: backup management | A.8.13 |
| ✅ | AZ-NR3-002 | SQL DB backup retention ≥7d | HIGH | §30(2) Nr.3: database backup | A.8.13 |
| ✅ | AZ-NR3-003 | Geo-redundant storage (GRS) | HIGH | §30(2) Nr.3: geo-redundancy | A.8.13 |
| ✅ | AZ-NR3-004 | Availability zones for production | HIGH | §30(2) Nr.3: availability | A.5.29, A.8.14 |
| ✅ | AZ-NR3-005 | Azure Site Recovery configured | HIGH | §30(2) Nr.3: disaster recovery | A.5.30 |
| ✅ | AZ-NR3-006 | Immutable blob storage | HIGH | §30(2) Nr.3: ransomware protection | A.8.13 |
| ✅ | AZ-NR3-007 | Traffic Manager / Front Door | LOW | §30(2) Nr.3: redundancy | A.8.14 |

#### §30 Abs. 2 Nr. 8: Cryptography *(Phase 1, implemented for AWS)*

| Status | Check ID | Description | Severity | §30 text reference | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR8-001 | S3 default encryption (SSE-S3/SSE-KMS) | HIGH | §30(2) Nr.8: "Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren" (concepts and processes for the use of cryptographic methods) | A.8.24 |
| ✅ | AWS-NR8-002 | EBS volumes encrypted | HIGH | §30(2) Nr.8: encryption of data at rest | A.8.24 |
| ✅ | AWS-NR8-003 | RDS storage encryption active | HIGH | §30(2) Nr.8: database encryption | A.8.24 |
| ✅ | AWS-NR8-004 | KMS key rotation enabled | MEDIUM | §30(2) Nr.8: key management | A.8.24 |
| ✅ | AWS-NR8-005 | CloudFront/ELB HTTPS-only, TLS ≥1.2 | HIGH | §30(2) Nr.8: encryption in transit | A.8.24 |
| ✅ | AWS-NR8-006 | ELB/ALB TLS policy ≥ TLS 1.2 | HIGH | §30(2) Nr.8 + "Stand der Technik" (state of the art) (§30(2) S.1), because TLS 1.0/1.1 is no longer state of the art | A.8.24 |
| ✅ | AWS-NR8-007 | ACM certificates not expired | CRITICAL | §30(2) Nr.8: certificate management | A.8.24 |
| ✅ | AZ-NR8-001 | Storage account encryption (CMK preferred) | HIGH | §30(2) Nr.8: encryption of data at rest | A.8.24 |
| ✅ | AZ-NR8-002 | Disk encryption / SSE | HIGH | §30(2) Nr.8: disk encryption | A.8.24 |
| ✅ | AZ-NR8-003 | SQL TDE enabled | HIGH | §30(2) Nr.8: database encryption | A.8.24 |
| ✅ | AZ-NR8-004 | Key Vault rotation policy | MEDIUM | §30(2) Nr.8: key rotation | A.8.24 |
| ✅ | AZ-NR8-005 | App Service HTTPS-only + TLS 1.2+ | HIGH | §30(2) Nr.8: transport encryption | A.8.24 |
| ✅ | AZ-NR8-006 | Application Gateway TLS policy | HIGH | §30(2) Nr.8: "Stand der Technik" (state of the art) | A.8.24 |

#### §30 Abs. 2 Nr. 4: Supply chain security

| Status | Check ID | Description | Severity | §30 text reference | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR4-001 | Trusted Advisor access (Business/Enterprise Support) | MEDIUM | §30(2) Nr.4: "Sicherheit der Lieferkette einschl. sicherheitsbezogener Aspekte der Beziehungen zwischen den einzelnen Einrichtungen und ihren unmittelbaren Anbietern oder Diensteanbietern" (supply chain security incl. security-related aspects of the relationships between entities and their direct suppliers or service providers) | A.5.19, A.5.21 |
| ✅ | AWS-NR4-002 | RAM (Resource Access Manager) sharing policies | HIGH | §30(2) Nr.4: control of resources shared with third parties | A.5.20 |
| ✅ | AWS-NR4-003 | Organizations: external accounts isolated | HIGH | §30(2) Nr.4: separation of third-party access | A.5.19 |
| ✅ | AWS-NR4-004 | IAM cross-account roles audited | HIGH | §30(2) Nr.4: review access rights of service providers | A.5.20, A.8.3 |
| ✅ | AWS-NR4-005 | Service control policies for third-party OUs | MEDIUM | §30(2) Nr.4: restriction of service provider permissions | A.5.19 |
| ✅ | AZ-NR4-001 | Lighthouse delegations reviewed | HIGH | §30(2) Nr.4: delegated management by MSPs | A.5.19 |
| ✅ | AZ-NR4-002 | Guest users (B2B) with Conditional Access | HIGH | §30(2) Nr.4: external users controlled | A.5.20 |
| ✅ | AZ-NR4-003 | Private Endpoints for PaaS services | HIGH | §30(2) Nr.4: network isolation of services | A.5.19, A.8.22 |
| ✅ | AZ-NR4-004 | Service principal credentials rotated | MEDIUM | §30(2) Nr.4: secure automated third-party access | A.5.20 |
| ✅ | AZ-NR4-005 | Marketplace image trust policy | MEDIUM | §30(2) Nr.4: software supply chain, trusted sources only | A.5.19 |

#### §30 Abs. 2 Nr. 5: Security measures for acquisition, development, maintenance & vulnerability management

| Status | Check ID | Description | Severity | §30 text reference | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR5-001 | ECR image scanning enabled | HIGH | §30(2) Nr.5: "Sicherheitsmaßnahmen bei Erwerb, Entwicklung und Wartung" (security measures in acquisition, development and maintenance): container vulnerability scanning | A.8.8 |
| ✅ | AWS-NR5-002 | SSM managed instances (patch management) | HIGH | §30(2) Nr.5: "einschl. Management und Offenlegung von Schwachstellen" (incl. management and disclosure of vulnerabilities) | A.8.8 |
| ✅ | AWS-NR5-003 | SSM Patch Manager compliance | HIGH | §30(2) Nr.5: maintenance, meaning timely patching, "Stand der Technik" (state of the art) (§30(2) S.1) | A.8.8, A.8.9 |
| ✅ | AWS-NR5-004 | Lambda runtime versions current | MEDIUM | §30(2) Nr.5: outdated runtimes are a vulnerability | A.8.8 |
| ✅ | AWS-NR5-005 | AMI age < 90 days for production instances | MEDIUM | §30(2) Nr.5: regular updating of the operating environment | A.8.8 |
| ✅ | AZ-NR5-001 | Defender for Cloud: vulnerability assessment | HIGH | §30(2) Nr.5: vulnerability detection | A.8.8 |
| ✅ | AZ-NR5-002 | Update Management Center configured | HIGH | §30(2) Nr.5: patch management | A.8.8, A.8.9 |
| ✅ | AZ-NR5-003 | Container Registry image scan | HIGH | §30(2) Nr.5: container vulnerabilities | A.8.8 |
| ✅ | AZ-NR5-004 | App Service runtime current | MEDIUM | §30(2) Nr.5: runtime environment | A.8.8 |
| ✅ | AZ-NR5-005 | SQL Vulnerability Assessment enabled | HIGH | §30(2) Nr.5: database vulnerabilities | A.8.8 |

#### §30 Abs. 2 Nr. 6: Assessing the effectiveness of risk management measures

| Status | Check ID | Description | Severity | §30 text reference | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR6-001 | CloudTrail operational effectiveness (log delivery) | HIGH | §30(2) Nr.6: "Konzepte und Verfahren zur Bewertung der Wirksamkeit" (concepts and procedures for assessing effectiveness): tamper protection for audit logs | A.5.35, A.8.15 |
| ✅ | AWS-NR6-002 | Config Rules compliance status | HIGH | §30(2) Nr.6: automated compliance assessment as evidence of effectiveness | A.5.35 |
| ✅ | AWS-NR6-003 | Security Hub compliance score ≥80% | HIGH | §30(2) Nr.6: aggregated effectiveness assessment | A.5.35 |
| ✅ | AWS-NR6-004 | CloudWatch log retention ≥1 year | MEDIUM | §30(2) Nr.6: long-term traceability for audits | A.8.15 |
| ✅ | AZ-NR6-001 | Defender Secure Score ≥70% | HIGH | §30(2) Nr.6: aggregated effectiveness indicator | A.5.35 |
| ✅ | AZ-NR6-002 | Azure Policy compliance state | HIGH | §30(2) Nr.6: automated compliance measurement | A.5.35 |
| ✅ | AZ-NR6-003 | Activity Log retention ≥365 days | MEDIUM | §30(2) Nr.6: audit trail retention | A.8.15 |
| ✅ | AZ-NR6-004 | Diagnostic settings on all critical resources | HIGH | §30(2) Nr.6: measurable evidence of active monitoring | A.5.35, A.8.15 |

#### §30 Abs. 2 Nr. 7: Basic training and awareness

| Status | Check ID | Description | Severity | §30 text reference | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR7-001 | IAM password policy ≥14 characters, complexity | HIGH | §30(2) Nr.7: "grundlegende Verfahren der Cyberhygiene" (basic cyber hygiene practices): minimum password standards | A.5.17 |
| ✅ | AWS-NR7-002 | Root account has no access keys | CRITICAL | §30(2) Nr.7: basic security hygiene, minimize root usage | A.5.17, A.8.2 |
| ✅ | AZ-NR7-001 | Entra ID Password Protection configured | HIGH | §30(2) Nr.7: password hygiene | A.5.17 |
| ✅ | AZ-NR7-002 | Security Defaults or Conditional Access baseline | HIGH | §30(2) Nr.7: baseline security standards enforced | A.5.17 |

#### §30 Abs. 2 Nr. 9: Personnel security, access control and ICT management *(Phase 1, implemented for AWS)*

| Status | Check ID | Description | Severity | §30 text reference | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR9-001 | IAM users without MFA | HIGH | §30(2) Nr.9: "Zugriffskontrollkonzepte" (access control concepts): identity assurance | A.5.15, A.8.5 |
| ✅ | AWS-NR9-002 | Access keys older than 90 days | HIGH | §30(2) Nr.9: "Verwaltung von Anlagen" (management of assets): credential lifecycle | A.5.15, A.8.5 |
| ✅ | AWS-NR9-003 | S3 account-level Public Access Block | CRITICAL | §30(2) Nr.9: access control, prevent public access | A.5.15, A.8.3 |
| ✅ | AWS-NR9-004 | Security groups with 0.0.0.0/0 (open ports) | HIGH | §30(2) Nr.9: network access control: least privilege | A.8.20, A.8.22 |
| ✅ | AWS-NR9-005 | IAM policies without wildcard (*) permissions | HIGH | §30(2) Nr.9: access control following the least-privilege principle | A.5.15, A.8.3 |
| ✅ | AWS-NR9-006 | S3 bucket policies without Principal: * | CRITICAL | §30(2) Nr.9: no anonymous access to data stores | A.5.15, A.8.3 |
| ✅ | AWS-NR9-007 | Unused IAM credentials (>90d inactive) | MEDIUM | §30(2) Nr.9: "Personalsicherheit" (personnel security): leaver process | A.5.15, A.6.5 |
| ✅ | AZ-NR9-001 | Entra ID Conditional Access policies | HIGH | §30(2) Nr.9: access control | A.5.15 |
| ✅ | AZ-NR9-002 | Entra ID Privileged Identity Management (PIM) | HIGH | §30(2) Nr.9: time-limited privileged access rights | A.8.2, A.8.18 |
| ✅ | AZ-NR9-003 | NSG rules without open ports to the internet | HIGH | §30(2) Nr.9: network access control | A.8.20, A.8.22 |
| ✅ | AZ-NR9-004 | Storage account: private access only | HIGH | §30(2) Nr.9: no public access to storage | A.5.15, A.8.3 |
| ✅ | AZ-NR9-005 | RBAC instead of classic subscription admin roles | HIGH | §30(2) Nr.9: role-based access control | A.5.15 |
| ✅ | AZ-NR9-006 | Entra ID guest access restrictions | MEDIUM | §30(2) Nr.9: control external access | A.5.15, A.6.5 |
| ✅ | AZ-NR9-007 | Stale service principals (>90d inactive) | MEDIUM | §30(2) Nr.9: remove unused identities | A.5.15 |

#### §30 Abs. 2 Nr. 10: MFA, secure communication and emergency communication *(Phase 1, implemented for AWS)*

| Status | Check ID | Description | Severity | §30 text reference | ISO 27001 |
|--------|----------|-------------|-------------|-------------------|-----------|
| ✅ | AWS-NR10-001 | Root account MFA enabled | CRITICAL | §30(2) Nr.10: "Verwendung von Lösungen zur Multi-Faktor-Authentifizierung" (use of multi-factor authentication solutions), because root has the highest privileges | A.8.5 |
| ✅ | AWS-NR10-002 | All IAM users have MFA | HIGH | §30(2) Nr.10: enforce MFA for all users | A.8.5 |
| ✅ | AWS-NR10-003 | VPN / Client VPN for admin access | HIGH | §30(2) Nr.10: "gesicherte Sprach-, Video- und Textkommunikation" (secure voice, video and text communication) | A.8.20 |
| ✅ | AWS-NR10-004 | SES/SNS TLS enforcement | MEDIUM | §30(2) Nr.10: communication encryption | A.8.20 |
| ✅ | AWS-NR10-005 | Emergency IAM break-glass procedure | HIGH | §30(2) Nr.10: "gesicherte Notfallkommunikationssysteme" (secure emergency communication systems): access during an incident | A.5.30, A.8.5 |
| ✅ | AZ-NR10-001 | Entra ID MFA for all users | CRITICAL | §30(2) Nr.10: enforce MFA | A.8.5 |
| ✅ | AZ-NR10-002 | Entra ID: phishing-resistant MFA (FIDO2/Windows Hello) | HIGH | §30(2) Nr.10: "Stand der Technik" (state of the art): phishing-resistant MFA | A.8.5 |
| ✅ | AZ-NR10-003 | VPN Gateway / Bastion Host for admin access | HIGH | §30(2) Nr.10: secure admin communication | A.8.20 |
| ✅ | AZ-NR10-004 | Teams/Exchange: TLS enforced | MEDIUM | §30(2) Nr.10: secure communication | A.8.20 |
| ✅ | AZ-NR10-005 | Emergency access accounts (break glass) | HIGH | §30(2) Nr.10: secured emergency access | A.5.30, A.8.5 |

---

## ISMS document structure

nis2scan checks technical controls. But §30 BSIG also requires **documented organizational measures**: an ISMS. The following structure follows the **4-level hierarchy** (ISO 27001 Annex A + BSI IT-Grundschutz) and maps each document to the concrete requirements of §30 BSIG and ISO 27001:2022.

### ISMS document hierarchy (4 levels)

```
Level 1: Policy (strategic, §30(1) BSIG)
├── Information security policy (IS policy)
│   └── Applies to: all §30 areas. Signed by management.
│
Level 2: Policies (tactical, one policy per §30 area)
├── [§30 No.1]  Risk management policy
├── [§30 No.2]  Incident response policy
├── [§30 No.3]  Business continuity policy
├── [§30 No.4]  Supply chain security policy
├── [§30 No.5]  Secure development & patch policy
├── [§30 No.6]  Audit & effectiveness assessment policy
├── [§30 No.7]  Training & awareness policy
├── [§30 No.8]  Cryptography policy
├── [§30 No.9]  Access control & asset policy
├── [§30 No.10] MFA & communication security policy
│
Level 3: Concepts & plans (operational)
├── [§30 No.1]  Risk register + risk treatment plan
├── [§30 No.1]  Scope definition & asset register
├── [§30 No.2]  Incident response plan with escalation matrix
├── [§30 No.2]  BSI reporting templates (24h/72h/1M per §32)
├── [§30 No.2]  Forensics guide
├── [§30 No.3]  Business impact analysis (BIA)
├── [§30 No.3]  Disaster recovery plan (per site/cloud region)
├── [§30 No.3]  Crisis management handbook
├── [§30 No.4]  Supplier register with criticality rating
├── [§30 No.4]  Standard security clauses for contracts
├── [§30 No.4]  Cloud provider shared-responsibility matrix
├── [§30 No.5]  Patch management process
├── [§30 No.5]  Secure development lifecycle (SDL)
├── [§30 No.5]  Vulnerability disclosure policy
├── [§30 No.5]  Change management process
├── [§30 No.6]  ISMS KPI dashboard
├── [§30 No.6]  Internal audit program (annual plan)
├── [§30 No.7]  Training plan by target group × topic
├── [§30 No.7]  Phishing simulation schedule
├── [§30 No.8]  Approved algorithms & key lengths
├── [§30 No.8]  Key management process
├── [§30 No.8]  Certificate inventory & renewal process
├── [§30 No.9]  Joiner/mover/leaver process
├── [§30 No.9]  Privileged access management (PAM) concept
├── [§30 No.9]  Hardware/software/data inventory
├── [§30 No.10] MFA rollout plan
├── [§30 No.10] Emergency communication plan (out-of-band)
│
Level 4: Evidence & records (audit trail)
├── [§30 No.1]  Risk assessment logs (at least annually)
├── [§30 No.2]  Incident tickets & post-mortem reports
├── [§30 No.2]  BSI report receipts (ticket no. + timestamp)
├── [§30 No.3]  DR test logs (at least annually)
├── [§30 No.3]  Backup restore test logs
├── [§30 No.4]  Supplier assessment results
├── [§30 No.5]  Patch compliance reports
├── [§30 No.5]  Vulnerability scan reports
├── [§30 No.6]  Internal audit reports
├── [§30 No.6]  Management review minutes (at least annually, §38!)
├── [§30 No.6]  nis2scan compliance reports (automated!)
├── [§30 No.7]  Training records per employee
├── [§30 No.7]  Phishing simulation results
├── [§30 No.7]  Management training record (mandatory under §38 BSIG!)
├── [§30 No.8]  Key rotation logs
├── [§30 No.9]  Access review logs (quarterly)
├── [§30 No.10] MFA enrollment status reports
│
Cross-cutting documents (not §30-specific)
├── [§33]        BSI registration confirmation
├── [§38]        Management training record + approval minutes
├── [§30(1) S.3] Documentation of all measures (mandatory, "verhältnismäßig" (proportionate))
├── ISMS scope & organizational structure
├── RACI matrix for information security
├── Statement of Applicability (SoA, for ISO 27001 certification)
└── Continuous improvement process (CIP / PDCA cycle)
```

### Level 2: what must each §30-area policy contain?

Each level-2 policy must go beyond the bare legal text and operationalize the requirements from §30 BSIG and ISO 27001:

| §30 No. | Policy | Mandatory content (excerpt) | ISO 27001 |
|----------|-----------|------------------------|-----------|
| **1** | Risk management policy | Methodology (NIST/ISO 27005), risk categories, assessment criteria, risk appetite, escalation thresholds | 6.1.2, A.5.1 |
| **2** | Incident response policy | Incident categories (P1-P4), escalation levels, §32 reporting deadlines (24h/72h/1M), forensics, lessons learned | A.5.24-A.5.28 |
| **3** | Business continuity policy | RTO/RPO by criticality, backup strategy (3-2-1 rule), DR scenarios, crisis organization, test cadence | A.5.29-A.5.30, A.8.13 |
| **4** | Supply chain security policy | Supplier categorization, minimum contract clauses (SLA, audit rights, subcontractors), shared-responsibility matrix | A.5.19-A.5.23 |
| **5** | SDL & patch policy | SDL phases, patch SLAs (Critical: 24h, High: 72h), VDP, change management (CAB), mandatory SBOM | A.8.8-A.8.9, A.8.25 |
| **6** | Audit & effectiveness policy | Audit program (frequency, scope), KPIs (MTTD, patch rate, MFA coverage), management review (§38!) | 9.2, 9.3, A.5.35 |
| **7** | Training & awareness policy | Target groups (management under §38, admins, developers, all staff), mandatory modules, frequency, phishing simulation, success measurement | A.6.3, A.5.17 |
| **8** | Cryptography policy | Approved algorithms (BSI TR-02102), prohibited methods, key lifecycle, mandatory HSM/KMS, crypto agility | A.8.24 |
| **9** | Access control & asset policy | Need-to-know, RBAC, JML process, PAM (just-in-time), access reviews, asset classification (C/I/A), CMDB | A.5.15-A.5.18, A.8.1-A.8.5 |
| **10** | MFA & communication policy | Mandatory MFA (FIDO2 preferred), end-to-end encryption, emergency communication (out-of-band), break-glass procedure | A.8.5, A.8.20 |

### Connecting the scanner to ISMS documents

nis2scan reports serve as **automated evidence at level 4**. The scanner does not replace the documents at levels 1-3 (a human still has to write/fill those in), but it provides:

| What nis2scan provides | Replaces which document? | ISMS level |
|---------------------|--------------------------|------------|
| Compliance report as JSON/MD/PDF | Technical audit report for internal audit | Level 4 |
| Findings per §30 area | Input for the risk register (level 3) | Level 3 to 4 |
| Compliance score over time | KPI input for the ISMS dashboard (level 3) | Level 3 |
| Remediation-as-code | Appendix to the action plan (level 3) | Level 3 |
| Permission policy export | Documentation of technical controls | Level 3 |
| Drift detection (continuous monitoring) | Regression alert on deterioration | Level 4 |

### What the scanner does NOT replace

- **Level 1:** The IS policy must be signed by management (§38 BSIG)
- **Level 2:** Policies must be written specifically for the company
- **Level 3:** BIA, DR plans, training plans are organizational processes
- **§32 reports:** The scanner does not report incidents to the BSI; that is a mandatory manual process
- **§38 management training:** The management training must actually take place (a personal obligation)
- **§39 KRITIS audit:** For KRITIS operators: BSI audit every 3 years; nis2scan can help prepare for it, not replace it

→ **A NIS2 ISMS Starter Kit is in preparation for the level 1-3 documents: ready-made templates aligned with §30 BSIG and ISO 27001, with fill-in guidance. Interested? [Open a GitHub issue](https://github.com/VVulpe/nis2scan/issues).**

---

## Installation

```bash
# From PyPI
pip install nis2scan

# Or from the repo
git clone https://github.com/VVulpe/nis2scan.git
cd nis2scan
pip install -e .
```

## Configuration

```yaml
# config/default.yaml
company:
  name: "Your Company"
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

## Required permissions

Detailed documentation of all required permissions:
**[docs/permissions.md](https://github.com/VVulpe/nis2scan/blob/main/docs/permissions.md)**: AWS IAM policies, Azure RBAC + Graph API, service principal setup, OIDC CI/CD setup.

```bash
# Automatically generate a minimal IAM policy
nis2scan permissions --provider aws --format terraform
nis2scan permissions --provider azure --format azurecli
```

## Usage

```bash
# Full scan
nis2scan scan --provider aws --config config.yaml

# Only specific §30 areas
nis2scan scan --provider aws --bsig-nr 8,9,10

# Output as JSON
nis2scan scan --provider aws --format json --output report.json
```

## Contributing

Contributions welcome! Especially looking for:
- New check modules (see `.claude/skills/nis2-check/SKILL.md` for patterns)
- Translations (EN)
- Bug reports & feature requests

## License

Apache License 2.0, see [LICENSE](https://github.com/VVulpe/nis2scan/blob/main/LICENSE).
This repository contains the complete free scanner (all checks, all
providers). Premium features (PDF export, remediation-as-code, continuous
monitoring, SaaS dashboard) are proprietary extensions in separate
repositories and require a license. Inquiries: [GitHub Issues](https://github.com/VVulpe/nis2scan/issues).

---

*nis2scan is an independent open source project and is not affiliated with the BSI, the German federal government, or any cloud provider.*
