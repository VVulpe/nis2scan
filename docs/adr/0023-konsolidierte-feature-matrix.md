# ADR-0023: Konsolidierte Feature-Matrix (Free / Professional / Enterprise)

Status: Akzeptiert (2026-07-05, Grilling-Runde 6 / Audit)

Der nis2-licensing-Skill und das Code-Repo-CLAUDE.md führten zwei divergierende
Feature-Matrizen. Diese hier ersetzt beide (Basis: Repo-Tabelle, ergänzt um die
Skill-Punkte):

| Feature | Free | Professional | Enterprise |
|---|---|---|---|
| CLI-Scan, **alle** Checks, **alle** Provider | ✅ | ✅ | ✅ |
| Aktuell gepflegtes Rechts-Mapping (ADR-0015) | ✅ | ✅ | ✅ |
| JSON- + Markdown-Report (Export-Profile intern/extern) | ✅ | ✅ | ✅ |
| Attestierungs-Checkliste | ✅ | ✅ | ✅ |
| Permissions-Generator (IAM / RBAC / GCP) | ✅ | ✅ | ✅ |
| PDF-Report (branded) | — | ✅ | ✅ |
| Remediation-as-Code (Terraform/CloudFormation) | — | ✅ | ✅ |
| Multi-Account-/Multi-Subscription-Scan | — | ✅ | ✅ |
| Compliance-Trend / Historie (finding_key-basiert) | — | ✅ | ✅ |
| Scheduled Scans | — | ✅ | ✅ |
| E-Mail-Alerts bei Regression | — | ✅ | ✅ |
| SaaS-Dashboard (Web) | — | — | ✅ |
| Multi-Tenant + RBAC | — | — | ✅ |
| REST-API-Zugriff | — | — | ✅ |
| SSO (SAML/OIDC) | — | — | ✅ |
| Custom Check-Mappings | — | — | ✅ |
| Audit-Log | — | — | ✅ |
| SLA + Priority Support | — | — | ✅ |

**Code-Heimat:** Free = Repo `nis2scan` (Apache). Professional-Features = Repo
`nis2scan-premium` (Plugin, ADR-0014/0019). Enterprise-/SaaS-Features = Repo
`nis2scan-saas` (eigene Deploy-Einheit).

## Konsequenzen

- Der nis2-licensing-Skill und das Repo-CLAUDE.md werden auf diese Matrix
  angepasst (Audit-Wellen W2/W5).
- Grundsatz aus dem Skill bleibt verbindlich: Der Free-Tier ist ein vollständig
  nützliches Werkzeug; Premium verkauft Komfort und Skala, nie Korrektheit.
