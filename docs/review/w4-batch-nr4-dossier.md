# W4 Batch-Review-Dossier — §30 Abs. 2 Nr. 4 BSIG (Sicherheit der Lieferkette)

> Mechanisch extrahiert am 2026-07-12 (Worker, ohne rechtliche Bewertung).
> Prüfgegenstand für: Gründer + Agent legal-reviewer (ADR-0018).

Quelldateien:
- `nis2scan/engine/providers/aws/checks/nr4_lieferkette.py`
- `nis2scan/engine/providers/azure/checks/nr4_lieferkette.py`
- `nis2scan/engine/providers/gcp/checks/nr4_lieferkette.py`

Ist-Zahl erfasster Checks: **15** (AWS: 5, Azure: 5, GCP: 5) — entspricht der erwarteten Zahl.

## Modul-Konstanten je Provider

### AWS (`nr4_lieferkette.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 4 — Sicherheit der Lieferkette checks for AWS.

  Checks Trusted Advisor access (requires Business/Enterprise support plan).
  ```
- `BSIG_30_NR = 4`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 4 BSIG — Sicherheit der Lieferkette einschließlich sicherheitsbezogener Aspekte der Beziehungen zu unmittelbaren Anbietern oder Diensteanbietern"
- `ISO_CONTROL` (wörtlich): "A.5.19-A.5.23 Supplier relationships" — wird nur in AWS-NR4-001 verwendet.

### Azure (`nr4_lieferkette.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 4 — Sicherheit der Lieferkette checks for Azure.

  Checks Lighthouse Delegations, Guest Users with Conditional Access,
  Private Endpoints, Service Principal Credentials, and Marketplace Image Trust.
  ```
- `BSIG_30_NR = 4`
- `BSIG_30_TEXT` (wörtlich): identisch zu AWS (siehe oben).
- `MAX_CREDENTIAL_AGE_DAYS = 90` — wird nur in AZ-NR4-004 verwendet.

### GCP (`nr4_lieferkette.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 4 — Sicherheit der Lieferkette checks for GCP.

  Checks Cross-Project IAM Bindings, Service Account Keys, GKE Workload Identity,
  Binary Authorization, and VPC Service Controls for supply chain security.
  ```
- `BSIG_30_NR = 4`
- `BSIG_30_TEXT` (wörtlich): identisch zu AWS/Azure (siehe oben).
- Keine weiteren Modul-Konstanten.

---

## Checks

### AWS-NR4-001 — Trusted Advisor Zugang

Klassen-Docstring (wörtlich): "Check that AWS Trusted Advisor is accessible (Business/Enterprise support). Trusted Advisor provides automated best-practice checks for security, cost optimization, and reliability. Full access requires a Business or Enterprise support plan. Basic/Developer plans only get limited checks."

| Feld | Wert |
|---|---|
| Klasse | `CheckTrustedAdvisorAccess` |
| description | "Prüft ob AWS Trusted Advisor vollständig zugänglich ist (erfordert Business- oder Enterprise-Support-Plan)." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: MEDIUM (beide Mangel-Findings). |
| iso27001_control | Modul-Konstante `ISO_CONTROL` = "A.5.19-A.5.23 Supplier relationships" (identisch in Positiv- und beiden Mangel-Pfaden) |
| required_permissions | `["support:DescribeTrustedAdvisorChecks"]` |
| pruefgrenzen | "Prüft nur, ob Trusted Advisor per API zugänglich ist (erfordert Business/Enterprise Support). Fehlender Zugang ist ein Hinweis, kein Lieferketten-Mangel im engeren Sinne." |
| Prüflogik (deskriptiv) | `support.describe_trusted_advisor_checks(language="en")` auf Client-Region us-east-1; Anzahl zurückgegebener Checks wird gegen den Schwellwert 20 verglichen: `>= 20` → Positivnachweis, `< 20` → Mangel "Eingeschränkter Zugang"; wirft die API `SubscriptionRequiredException`, wird dies als eigener Mangel "Kein Zugang (Basic Support)" gewertet; andere Exceptions werden als `CheckError` erfasst. |

**Finding-Texte (Mangel-Pfad):**

1. title: "Eingeschränkter Trusted Advisor Zugang"
   - description (Template): `f"AWS Trusted Advisor hat nur Zugriff auf {len(checks)} Checks. Ein Business- oder Enterprise-Support-Plan bietet Zugriff auf alle Sicherheits- und Best-Practice-Checks."`
   - expected_state: "Vollständiger Trusted Advisor Zugang (50+ Checks, Business/Enterprise Support)"
   - remediation: "Upgrade auf einen AWS Business- oder Enterprise-Support-Plan für vollständigen Trusted Advisor Zugang mit automatisierten Sicherheits- und Compliance-Checks."
   - remediation_effort: HIGH
   - audit_evidence (Template): `f"DescribeTrustedAdvisorChecks returned {len(checks)} checks"`

2. title: "Kein Trusted Advisor Zugang (Basic Support)"
   - description: "AWS Trusted Advisor ist nicht verfügbar. Der Account verwendet den Basic-Support-Plan, der keinen API-Zugriff auf Trusted Advisor bietet."
   - expected_state: "Business oder Enterprise Support Plan mit Trusted Advisor Zugang"
   - remediation: "Upgrade auf einen AWS Business- oder Enterprise-Support-Plan für automatisierte Sicherheits- und Best-Practice-Checks."
   - remediation_effort: HIGH
   - audit_evidence: "SubscriptionRequiredException — Basic support plan detected"

**Positivnachweis (compliant_finding):**
- title: "Trusted Advisor vollständig zugänglich"
- description (Template): `f"AWS Trusted Advisor bietet Zugriff auf {len(checks)} Checks — automatisierte Best-Practice-Prüfungen sind verfügbar."`
- expected_state: "Vollständiger Trusted Advisor Zugang (50+ Checks, Business/Enterprise Support)"
- audit_evidence (Template): `f"DescribeTrustedAdvisorChecks returned {len(checks)} checks"`

---

### AWS-NR4-002 — RAM Sharing-Policies

Klassen-Docstring (wörtlich): "Check that AWS RAM (Resource Access Manager) sharing is controlled. RAM allows sharing resources across accounts. Without proper governance, sensitive resources could be shared with unauthorized external accounts."

| Feld | Wert |
|---|---|
| Klasse | `CheckRamSharingPolicies` |
| description | "Prüft ob AWS Resource Access Manager (RAM) Sharing-Policies konfiguriert sind, um die Kontrolle über geteilte Ressourcen mit Dritten sicherzustellen." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: HIGH. |
| iso27001_control | Inline Literal "A.5.20 Addressing information security within supplier agreements" (identisch in Positiv- und Mangel-Pfad) |
| required_permissions | `["ram:GetResourceShares"]` |
| pruefgrenzen | "Prüft nur aktive RAM-Ressourcenfreigaben. Nicht geprüft wird, an wen geteilt wird und ob die Freigaben geschäftlich begründet sind — das erfordert organisatorische Bewertung." |
| Prüflogik (deskriptiv) | `ram.get_resource_shares(resourceOwner="SELF")` auf Client-Region us-east-1; aus der Ergebnisliste werden Shares mit `allowExternalPrincipals=True` und `status="ACTIVE"` gefiltert (`external_active`); leere Liste → ein aggregierter Positivnachweis; sonst ein Mangel-Finding je betroffenem Share. |

**Finding-Texte (Mangel-Pfad, je Share):**
- title: "RAM-Share erlaubt externe Principals"
- description (Template): `f"Die RAM Resource Share '{share_name}' erlaubt externe Principals. Ressourcen können mit AWS-Konten außerhalb der Organisation geteilt werden."`
- expected_state: "RAM Sharing nur innerhalb der Organisation (allowExternalPrincipals=false)"
- remediation: "Beschränken Sie RAM-Shares auf die Organisation: aws ram update-resource-share --resource-share-arn <arn> --no-allow-external-principals"
- remediation_effort: LOW
- audit_evidence (Template): `f"GetResourceShares: {share_name} allowExternalPrincipals=true"`

**Positivnachweis (compliant_finding):**
- title: "Keine RAM-Shares mit externen Principals"
- description: "Es sind keine aktiven RAM Resource Shares vorhanden, die externe Principals erlauben — geteilte Ressourcen bleiben in der Organisation."
- expected_state: "RAM Sharing nur innerhalb der Organisation (allowExternalPrincipals=false)"
- audit_evidence (Template): `f"GetResourceShares: {len(external_shares)} share(s), 0 active with external principals"`

---

### AWS-NR4-003 — Organizations — externe Konten isoliert

Klassen-Docstring (wörtlich): "Check that AWS Organizations properly isolates external accounts. Without Organizations, there's no centralized governance for multi-account environments, making it impossible to enforce supply chain security policies."

| Feld | Wert |
|---|---|
| Klasse | `CheckOrganizationsExternalAccounts` |
| description | "Prüft ob AWS Organizations konfiguriert ist, um externe Konten zu isolieren und Drittanbieter-Zugriffen kontrolliert zu begrenzen." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: HIGH (beide Mangel-Findings). |
| iso27001_control | Inline Literal "A.5.19 Information security in supplier relationships" (identisch in allen drei Pfaden) |
| required_permissions | `["organizations:DescribeOrganization"]` |
| pruefgrenzen | "Prüft nur, ob der Account Teil einer Organization ist. Die Isolation externer Konten selbst (OU-Struktur, Trennung) wird nicht inhaltlich bewertet." |
| Prüflogik (deskriptiv) | `orgs.describe_organization()` auf Client-Region us-east-1; `FeatureSet == "ALL"` → Positivnachweis; jeder andere Wert → Mangel "nicht mit allen Features aktiviert"; wirft der Aufruf `AWSOrganizationsNotInUseException` → eigener Mangel "Organizations nicht aktiviert"; andere Exceptions → `CheckError`. |

**Finding-Texte (Mangel-Pfad):**

1. title: "Organizations nicht mit allen Features aktiviert"
   - description (Template): `f"AWS Organizations hat FeatureSet='{feature_set}' statt 'ALL'. Ohne vollständige Features können SCPs und andere Sicherheitskontrollen nicht durchgesetzt werden."`
   - expected_state: "Organizations mit FeatureSet=ALL für vollständige Sicherheitskontrollen"
   - remediation: "Aktivieren Sie alle Features in AWS Organizations: AWS Console → Organizations → Settings → Enable all features"
   - remediation_effort: MEDIUM
   - audit_evidence (Template): `f"DescribeOrganization: FeatureSet={feature_set}"`

2. title: "AWS Organizations nicht aktiviert"
   - description: "AWS Organizations ist nicht aktiviert. Ohne Organizations fehlt die zentrale Governance für Multi-Account-Umgebungen und die Isolation externer Konten ist nicht gewährleistet."
   - expected_state: "AWS Organizations aktiviert mit Account-Isolation"
   - remediation: "Erstellen Sie eine AWS Organization: aws organizations create-organization --feature-set ALL"
   - remediation_effort: HIGH
   - audit_evidence: "DescribeOrganization: AWSOrganizationsNotInUseException"

**Positivnachweis (compliant_finding):**
- title: "Organizations mit allen Features aktiviert"
- description: "AWS Organizations ist mit FeatureSet=ALL aktiviert — SCPs und zentrale Sicherheitskontrollen sind durchsetzbar."
- expected_state: "Organizations mit FeatureSet=ALL für vollständige Sicherheitskontrollen"
- audit_evidence: "DescribeOrganization: FeatureSet=ALL"

---

### AWS-NR4-004 — IAM Cross-Account Roles auditiert

Klassen-Docstring (wörtlich): "Check that IAM cross-account roles are audited and controlled. Cross-account roles allow external AWS accounts to assume roles in this account. These must be documented and reviewed as part of supply chain security."

| Feld | Wert |
|---|---|
| Klasse | `CheckCrossAccountRoles` |
| description | "Prüft ob IAM-Rollen mit Cross-Account Trust Relationships identifiziert und kontrolliert werden." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: HIGH. |
| iso27001_control | Inline Literal "A.5.20, A.8.3 Information access restriction" (identisch in beiden Pfaden) |
| required_permissions | `["iam:ListRoles", "iam:GetRole"]` |
| pruefgrenzen | "Prüft IAM-Rollen mit Cross-Account-Trust auf externe Account-IDs. Nicht bewertet wird, ob ein externer Trust legitim ist (z. B. beauftragter Dienstleister) — die Liste dient als Audit-Grundlage." |
| Prüflogik (deskriptiv) | `iam.get_paginator("list_roles")`, paginiert über alle Rollen; Rollen mit Pfad `/aws-service-role/` werden übersprungen; je Rolle werden `AssumeRolePolicyDocument`-Statements mit `Effect == "Allow"` durchsucht, `Principal.AWS`-Einträge (String oder Liste) extrahiert; ein Principal zählt als Cross-Account, wenn er `"::"` enthält und die eigene `session.account_id` NICHT enthält; leere Trefferliste → ein aggregierter Positivnachweis; sonst ein Mangel-Finding je betroffener Rolle. |

**Finding-Texte (Mangel-Pfad, je Rolle):**
- title: "IAM-Rolle mit Cross-Account Trust"
- description (Template): `f"Die IAM-Rolle '{xar['role_name']}' erlaubt einem externen AWS-Konto die Rollenübernahme. Cross-Account Rollen müssen als Lieferkettenabhängigkeit dokumentiert und regelmäßig auditiert werden."`
- expected_state: "Cross-Account Rollen dokumentiert, mit ExternalId und minimalem Berechtigungsumfang"
- remediation: "1. Dokumentieren Sie alle Cross-Account Rollen als Lieferkettenabhängigkeit. 2. Stellen Sie sicher, dass ExternalId als Condition gesetzt ist. 3. Wenden Sie Least-Privilege-Prinzip auf die Rollenberechtigungen an. 4. Überprüfen Sie regelmäßig die Trust Relationships."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"ListRoles/GetRole: {xar['role_name']} has cross-account trust"`

**Positivnachweis (compliant_finding):**
- title: "Keine Cross-Account Trust Relationships"
- description: "Keine IAM-Rolle erlaubt externen AWS-Konten die Rollenübernahme — es bestehen keine undokumentierten Lieferkettenabhängigkeiten über IAM."
- expected_state: "Cross-Account Rollen dokumentiert, mit ExternalId und minimalem Berechtigungsumfang"
- audit_evidence: "ListRoles: no roles with cross-account trust found"

---

### AWS-NR4-005 — SCPs für Drittanbieter-OUs

Klassen-Docstring (wörtlich): "Check that Service Control Policies exist for third-party OUs. Without SCPs, accounts in organizational units designated for third-party access have unrestricted permissions, violating supply chain security."

| Feld | Wert |
|---|---|
| Klasse | `CheckScpForThirdPartyOus` |
| description | "Prüft ob Service Control Policies (SCPs) für die Einschränkung von Drittanbieter-Berechtigungen in AWS Organizations vorhanden sind." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: MEDIUM (alle drei Mangel-Findings). |
| iso27001_control | Inline Literal "A.5.19 Information security in supplier relationships" (identisch in allen vier Pfaden) |
| required_permissions | `["organizations:DescribeOrganization", "organizations:ListPolicies"]` |
| pruefgrenzen | "Prüft nur die Existenz benutzerdefinierter SCPs in der Organization. Ob SCPs Drittanbieter-OUs tatsächlich einschränken (Inhalt, Zuordnung), wird nicht bewertet." |
| Prüflogik (deskriptiv) | `orgs.describe_organization()` (nur zur Existenzprüfung, Ergebnis wird nicht ausgewertet) gefolgt von `orgs.list_policies(Filter="SERVICE_CONTROL_POLICY")`; die Default-Policy mit Name "FullAWSAccess" wird herausgefiltert (`custom_scps`); nicht-leere Liste → Positivnachweis; leere Liste → Mangel "keine benutzerdefinierten SCPs"; wirft der Aufruf `AWSOrganizationsNotInUseException` → Mangel "keine Organizations"; wirft er `AccessDeniedException` → Mangel "kein Zugriff"; andere Exceptions → `CheckError`. |

**Finding-Texte (Mangel-Pfad):**

1. title: "Keine benutzerdefinierten SCPs für Drittanbieter"
   - description: "Es sind keine benutzerdefinierten Service Control Policies (SCPs) konfiguriert. Ohne SCPs können Drittanbieter-Konten in der Organisation uneingeschränkte Berechtigungen haben."
   - expected_state: "Benutzerdefinierte SCPs für Drittanbieter-OUs konfiguriert"
   - remediation: "Erstellen Sie SCPs zur Einschränkung von Drittanbieter-Berechtigungen: aws organizations create-policy --name 'ThirdPartyRestrictions' --type SERVICE_CONTROL_POLICY --content '<policy-json>'"
   - remediation_effort: MEDIUM
   - audit_evidence: "ListPolicies: no custom SCPs found"

2. title: "Keine Organizations — SCPs nicht möglich"
   - description: "AWS Organizations ist nicht aktiviert. Ohne Organizations können keine SCPs zur Einschränkung von Drittanbieter-Berechtigungen konfiguriert werden."
   - expected_state: "Organizations aktiviert mit SCPs für Drittanbieter"
   - remediation: "Aktivieren Sie AWS Organizations mit allen Features: aws organizations create-organization --feature-set ALL"
   - remediation_effort: HIGH
   - audit_evidence: "AWSOrganizationsNotInUseException — no SCPs possible"

3. title: "Kein Zugriff auf Organizations SCPs"
   - description: "Der aktuelle Account hat keinen Zugriff auf Organizations SCPs. Dies könnte bedeuten, dass der Account kein Management-Account ist."
   - expected_state: "Zugriff auf Organizations SCPs für Audit-Zwecke"
   - remediation: "Stellen Sie sicher, dass der Scan-Account Zugriff auf Organizations APIs hat (management account oder delegated admin)."
   - remediation_effort: MEDIUM
   - audit_evidence: "AccessDeniedException when accessing Organizations policies"

**Positivnachweis (compliant_finding):**
- title: "Benutzerdefinierte SCPs vorhanden"
- description (Template): `f"Es sind {len(custom_scps)} benutzerdefinierte Service Control Policies konfiguriert — Drittanbieter-Berechtigungen können organisationsweit eingeschränkt werden."`
- expected_state: "Benutzerdefinierte SCPs für Drittanbieter-OUs konfiguriert"
- audit_evidence (Template): `f"ListPolicies: {len(custom_scps)} custom SCP(s) found"`

---

### AZ-NR4-001 — Lighthouse Delegations geprüft

Klassen-Docstring (wörtlich): "Check that Azure Lighthouse delegations are audited."

| Feld | Wert |
|---|---|
| Klasse | `CheckLighthouseDelegations` |
| description | "Prüft ob Azure Lighthouse-Delegierungen für verwaltete Dienstleister kontrolliert werden." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: HIGH. |
| iso27001_control | Inline Literal "A.5.19 Informationssicherheit in Lieferantenbeziehungen" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.ManagedServices/registrationAssignments/read"]` |
| pruefgrenzen | "Prüft nur registrierte Lighthouse-Delegationen. Ob eine Delegation an einen Dienstleister legitim und vertraglich geregelt ist, ist organisatorisch zu bewerten." |
| Prüflogik (deskriptiv) | Für jede `session.subscription_ids`: `ResourceManagementClient.resources.list(filter="resourceType eq 'Microsoft.ManagedServices/registrationAssignments'")`; leere Liste → Positivnachweis je Subscription; sonst ein aggregiertes Mangel-Finding je Subscription (Anzahl der Delegierungen, keine Einzelaufschlüsselung). Exceptions je Subscription führen zu `CheckError` (mit `check_id` und `region="global"`). |

**Finding-Texte (Mangel-Pfad):**
- title: "Lighthouse-Delegierungen vorhanden"
- description (Template): `f"Subscription {sub_id} hat {len(delegations)} Lighthouse-Delegierungen. Diese ermöglichen externen Dienstleistern Zugriff und sollten regelmäßig überprüft werden."`
- expected_state: "Alle Lighthouse-Delegierungen dokumentiert und genehmigt"
- remediation: "Überprüfen Sie alle Lighthouse-Delegierungen: Azure Portal → Dienstanbieter → Delegierungen prüfen. Entfernen Sie nicht autorisierte Delegierungen."
- remediation_effort: LOW
- audit_evidence (Template): `f"resources.list(): {len(delegations)} Lighthouse delegations found"`

**Positivnachweis (compliant_finding):**
- title: "Keine Lighthouse-Delegierungen"
- description (Template): `f"Subscription {sub_id} hat keine Azure Lighthouse-Delegierungen — kein externer Dienstleister-Zugriff über Lighthouse."`
- expected_state: "Alle Lighthouse-Delegierungen dokumentiert und genehmigt"
- audit_evidence: "resources.list(): 0 Lighthouse delegations found"

---

### AZ-NR4-002 — Guest Users (B2B) mit Conditional Access

Klassen-Docstring (wörtlich): "Check that guest users are covered by Conditional Access policies."

| Feld | Wert |
|---|---|
| Klasse | `CheckGuestUsersConditionalAccess` |
| description | "Prüft ob B2B-Gastbenutzer durch Conditional Access Policies abgesichert sind." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: HIGH. |
| iso27001_control | Inline Literal "A.5.20 Berücksichtigung der Informationssicherheit in Lieferantenvereinbarungen" (identisch in beiden Pfaden) |
| required_permissions | `["User.Read.All", "Policy.Read.All"]` |
| pruefgrenzen | "Prüft Gastkonten gegen Conditional-Access-Policies. Ohne Gastkonten liefert der Check kein Ergebnis (Nicht anwendbar). Die inhaltliche Angemessenheit der Policies wird nicht bewertet." |
| Prüflogik (deskriptiv) | MS Graph `graph_client.users.get()`, Filter auf `user_type == "guest"`; sind keine Gastbenutzer vorhanden, endet die Ausführung per frühem `return` ohne Finding oder Error; andernfalls `graph_client.identity.conditional_access.policies.get()`; über aktivierte Policies (`state == "enabled"`) wird geprüft, ob `conditions.users.include_users` "All" oder "GuestsOrExternalUsers" enthält, `include_guests_or_external_users` gesetzt ist, oder `include_groups` nicht leer ist — jede dieser drei Bedingungen setzt `guest_ca_found = True`. |

**Finding-Texte (Mangel-Pfad):**
- title: "Gastbenutzer ohne Conditional Access"
- description (Template): `f"Es gibt {len(guest_users)} Gastbenutzer, aber keine Conditional Access Policy, die explizit Gastbenutzer einschließt. Externe Benutzer müssen denselben Sicherheitsanforderungen unterliegen."`
- expected_state: "Conditional Access Policy für Gastbenutzer"
- remediation: "Erstellen Sie eine CA-Policy für Gastbenutzer: Entra Admin Center → Schutz → Bedingter Zugriff → Neue Richtlinie → Benutzer: Gäste und externe Benutzer"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"Graph API: {len(guest_users)} guest users, no CA policy targeting guests"`

**Positivnachweis (compliant_finding):**
- title: "Gastbenutzer durch Conditional Access abgesichert"
- description (Template): `f"Es gibt {len(guest_users)} Gastbenutzer und mindestens eine aktive Conditional Access Policy, die Gastbenutzer einschließt."`
- expected_state: "Conditional Access Policy für Gastbenutzer"
- audit_evidence (Template): `f"Graph API: {len(guest_users)} guest users, CA policy targeting guests active"`

---

### AZ-NR4-003 — Private Endpoints für PaaS-Dienste

Klassen-Docstring (wörtlich): "Check that PaaS services use private endpoints."

| Feld | Wert |
|---|---|
| Klasse | `CheckPrivateEndpoints` |
| description | "Prüft ob PaaS-Dienste über Private Endpoints abgesichert sind." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: HIGH. |
| iso27001_control | Inline Literal "A.5.19, A.8.22 Netzwerk-Isolation" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Network/privateEndpoints/read"]` |
| pruefgrenzen | "Prüft nur, ob PaaS-Dienste Private Endpoints nutzen. Nicht jede öffentliche PaaS-Anbindung ist ein Lieferketten-Risiko — Bewertung im Kontext nötig." |
| Prüflogik (deskriptiv) | Für jede `session.subscription_ids`: `NetworkManagementClient.private_endpoints.list_by_subscription()`; nicht-leere Liste → Positivnachweis (Gesamtzahl); leere Liste → Mangel-Finding — dieser Zweig feuert unabhängig davon, ob überhaupt PaaS-Ressourcen (Storage, SQL, Key Vault etc.) in der Subscription existieren. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Private Endpoints konfiguriert"
- description (Template): `f"Subscription {sub_id} hat keine Private Endpoints. PaaS-Dienste (Storage, SQL, Key Vault) sind ohne Private Endpoints über das öffentliche Internet erreichbar."`
- expected_state: "Private Endpoints für kritische PaaS-Dienste"
- remediation: "Erstellen Sie Private Endpoints für PaaS-Dienste: az network private-endpoint create --name <pe-name> --resource-group <rg> --vnet-name <vnet> --subnet <subnet> --private-connection-resource-id <resource-id>"
- remediation_effort: HIGH
- audit_evidence: "private_endpoints.list_by_subscription() returned 0 endpoints"

**Positivnachweis (compliant_finding):**
- title: "Private Endpoints konfiguriert"
- description (Template): `f"Subscription {sub_id} hat {len(private_endpoints)} Private Endpoint(s) für die Absicherung von PaaS-Diensten."`
- expected_state: "Private Endpoints für kritische PaaS-Dienste"
- audit_evidence (Template): `f"private_endpoints.list_by_subscription() returned {len(private_endpoints)} endpoint(s)"`

---

### AZ-NR4-004 — Service Principal Credentials rotiert

Klassen-Docstring (wörtlich): "Check that service principal credentials are rotated regularly."

| Feld | Wert |
|---|---|
| Klasse | `CheckServicePrincipalCredentials` |
| description | "Prüft ob Service Principal Credentials regelmäßig rotiert werden." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: MEDIUM. |
| iso27001_control | Inline Literal "A.5.20 Berücksichtigung der Informationssicherheit in Lieferantenvereinbarungen" (identisch in beiden Pfaden) |
| required_permissions | `["Application.Read.All"]` |
| pruefgrenzen | "Prüft nur das Alter der Service-Principal-Credentials (Secrets/Zertifikate). Workload Identity Federation ohne Secrets wird als konform gewertet." |
| Prüflogik (deskriptiv) | MS Graph `graph_client.applications.get()`; Schwellwert `threshold = now(UTC) - 90 Tage` (`MAX_CREDENTIAL_AGE_DAYS`); je Anwendung wird geprüft, ob mindestens ein `password_credentials`-Eintrag ein `start_date_time` vor dem Schwellwert hat (`old_creds_count`, je App höchstens einmal gezählt); `applications` nicht leer UND `old_creds_count == 0` → Positivnachweis; `old_creds_count > 0` → Mangel-Finding (aggregiert, mit Anzahl betroffener Apps). Ist `applications` leer, greift keiner der beiden Zweige — es wird kein Finding erzeugt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Service Principal Credentials nicht rotiert"
- description (Template): `f"Es gibt {old_creds_count} Anwendungen mit Credentials älter als {MAX_CREDENTIAL_AGE_DAYS} Tage. Langlebige Credentials erhöhen das Kompromittierungsrisiko."`
- expected_state (Template): `f"Alle Credentials jünger als {MAX_CREDENTIAL_AGE_DAYS} Tage"`
- remediation: "Rotieren Sie abgelaufene Credentials: az ad app credential reset --id <app-id> --years 1. Verwenden Sie Managed Identities wo möglich."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"Graph API: {old_creds_count}/{len(applications)} apps with credentials > {MAX_CREDENTIAL_AGE_DAYS} days"`

**Positivnachweis (compliant_finding):**
- title: "Service Principal Credentials aktuell"
- description (Template): `f"Alle {len(applications)} Anwendungen haben Credentials jünger als {MAX_CREDENTIAL_AGE_DAYS} Tage."`
- expected_state (Template): `f"Alle Credentials jünger als {MAX_CREDENTIAL_AGE_DAYS} Tage"`
- audit_evidence (Template): `f"Graph API: 0/{len(applications)} apps with credentials > {MAX_CREDENTIAL_AGE_DAYS} days"`

---

### AZ-NR4-005 — Marketplace Image Trust Policy

Klassen-Docstring (wörtlich): "Check that VMs use trusted marketplace images."

| Feld | Wert |
|---|---|
| Klasse | `CheckMarketplaceImageTrust` |
| description | "Prüft ob VMs nur vertrauenswürdige Marketplace-Images verwenden." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: MEDIUM. |
| iso27001_control | Inline Literal "A.5.19 Informationssicherheit in Lieferantenbeziehungen" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Compute/virtualMachines/read"]` |
| pruefgrenzen | "Prüft nur, ob eine Policy den Bezug von Marketplace-Images einschränkt. Die Vertrauenswürdigkeit einzelner Images wird nicht bewertet." |
| Klassenattribut `TRUSTED_PUBLISHERS` | `{"Canonical", "MicrosoftWindowsServer", "MicrosoftWindowsDesktop", "RedHat", "SUSE", "Oracle", "center-for-internet-security-inc", "microsoftcblmariner"}` |
| Prüflogik (deskriptiv) | Für jede `session.subscription_ids`: `ComputeManagementClient.virtual_machines.list_all()`; je VM mit gesetztem `storage_profile.image_reference` wird der `publisher` gegen `TRUSTED_PUBLISHERS` geprüft — ein nicht-leerer Publisher außerhalb der Liste zählt als "untrusted" (leerer/`None`-Publisher wird nicht gezählt); `vms` nicht leer UND keine untrusted VMs → Positivnachweis; mindestens eine untrusted VM → Mangel-Finding (aggregiert, mit Kurzliste der ersten 5 VM/Publisher-Paare). Ist `vms` leer, greift keiner der beiden Zweige — es wird kein Finding erzeugt. |

**Finding-Texte (Mangel-Pfad):**
- title: "VMs mit nicht-vertrauenswürdigen Images"
- description (Template): `f"Subscription {sub_id} hat {len(untrusted_vms)} VMs mit Marketplace-Images von unbekannten Publishern: {vm_summary}."` mit `vm_summary = ", ".join(f"{v['name']} ({v['publisher']})" for v in untrusted_vms[:5])`
- expected_state: "Nur VMs mit Images von vertrauenswürdigen Publishern"
- remediation: "Überprüfen Sie die Image-Quellen und verwenden Sie nur vertrauenswürdige Publisher. Setzen Sie Azure Policy für erlaubte VM-Images ein."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"virtual_machines.list_all(): {len(untrusted_vms)}/{len(vms)} with untrusted publishers"`

**Positivnachweis (compliant_finding):**
- title: "VMs mit vertrauenswürdigen Images"
- description (Template): `f"Alle {len(vms)} VMs in Subscription {sub_id} verwenden Marketplace-Images von vertrauenswürdigen Publishern."`
- expected_state: "Nur VMs mit Images von vertrauenswürdigen Publishern"
- audit_evidence (Template): `f"virtual_machines.list_all(): 0/{len(vms)} with untrusted publishers"`

---

### GCP-NR4-001 — Externe IAM-Bindungen prüfen

Klassen-Docstring (wörtlich): "Prüft ob IAM-Bindungen externe Prinzipale enthalten."

| Feld | Wert |
|---|---|
| Klasse | `CheckCrossProjectBindings` |
| description | "Prüft ob die IAM-Policy des Projekts Bindungen für externe Prinzipale (außerhalb der eigenen Organisation) enthält." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: HIGH. |
| iso27001_control | Inline Literal "A.5.19 Informationssicherheit in Lieferantenbeziehungen" (identisch in beiden Pfaden) |
| required_permissions | `["resourcemanager.projects.getIamPolicy"]` |
| pruefgrenzen | "Prüft IAM-Bindungen auf Mitglieder außerhalb der eigenen Domain. Ob ein externer Zugriff legitim ist (Dienstleister), ist organisatorisch zu bewerten." |
| Prüflogik (deskriptiv) | Je `session.project_ids`: `cloudresourcemanager v1 projects().getIamPolicy(resource=project_id, body={"options": {"requestedPolicyVersion": 3}})`; über alle `bindings[].members` werden nur Einträge mit Präfix `"serviceAccount:"` betrachtet, bei denen die eigene `project_id` NICHT als Teilstring im Member-String enthalten ist (`external_members`); leere Liste → Positivnachweis; sonst ein aggregiertes Mangel-Finding je Projekt (Anzahl + Stichprobe der ersten 5 Members). |

**Finding-Texte (Mangel-Pfad):**
- title: "Externe IAM-Bindungen gefunden"
- description (Template): `f"Projekt {project_id} hat {len(external_members)} IAM-Bindung(en) für externe Prinzipale. Externe Zugriffe erhöhen das Risiko in der Lieferkette."`
- expected_state: "Keine externen IAM-Bindungen oder nur dokumentierte und genehmigte Lieferantenzugriffe"
- remediation: "Überprüfen Sie externe IAM-Bindungen: gcloud projects get-iam-policy <PROJECT_ID> --format=json | Entfernen Sie nicht autorisierte externe Zugriffe mit: gcloud projects remove-iam-policy-binding <PROJECT_ID> --member=<MEMBER> --role=<ROLE>"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"getIamPolicy() found {len(external_members)} external member(s)"`

**Positivnachweis (compliant_finding):**
- title: "Keine externen IAM-Bindungen"
- description (Template): `f"Die IAM-Policy von Projekt {project_id} enthält keine Bindungen für externe Service Accounts."`
- expected_state: "Keine externen IAM-Bindungen oder nur dokumentierte und genehmigte Lieferantenzugriffe"
- audit_evidence: "getIamPolicy() found 0 external members"

---

### GCP-NR4-002 — Benutzerverwaltete Service-Account-Schlüssel

Klassen-Docstring (wörtlich): "Prüft ob benutzerverwaltete Service-Account-Schlüssel existieren."

| Feld | Wert |
|---|---|
| Klasse | `CheckServiceAccountKeys` |
| description | "Prüft ob Service Accounts benutzerverwaltete Schlüssel haben, die ein Sicherheitsrisiko in der Lieferkette darstellen." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: HIGH. |
| iso27001_control | Inline Literal "A.5.20 Berücksichtigung der Informationssicherheit in Lieferantenvereinbarungen" (identisch in beiden Pfaden) |
| required_permissions | `["iam.serviceAccountKeys.list", "iam.serviceAccounts.list"]` |
| pruefgrenzen | "Prüft nur die Existenz nutzerverwalteter Service-Account-Schlüssel. Schlüsselalter wird in GCP-NR9-002 geprüft." |
| Prüflogik (deskriptiv) | Je `session.project_ids`: `iam v1 projects().serviceAccounts().list()`; je Service Account `projects().serviceAccounts().keys().list(keyTypes=["USER_MANAGED"])`; keine Treffer → Positivnachweis je Service Account; mindestens ein Treffer → Mangel-Finding je Service Account (Anzahl der Schlüssel). Granularität: ein Finding pro Service Account, nicht pro einzelnem Schlüssel. |

**Finding-Texte (Mangel-Pfad, je Service Account):**
- title: "Benutzerverwaltete SA-Schlüssel gefunden"
- description (Template): `f"Service Account {sa_email} in Projekt {project_id} hat {len(user_keys)} benutzerverwaltete(n) Schlüssel. Benutzerverwaltete Schlüssel stellen ein erhöhtes Sicherheitsrisiko dar und sollten vermieden werden."`
- expected_state: "Keine benutzerverwalteten Schlüssel; stattdessen Workload Identity oder kurzlebige Tokens verwenden"
- remediation: "Löschen Sie benutzerverwaltete Schlüssel: gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<SA_EMAIL> --project=<PROJECT_ID>. Verwenden Sie stattdessen Workload Identity Federation."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"keys.list() found {len(user_keys)} USER_MANAGED key(s) for {sa_email}"`

**Positivnachweis (compliant_finding, je Service Account):**
- title: "Keine benutzerverwalteten SA-Schlüssel"
- description (Template): `f"Service Account {sa_email} in Projekt {project_id} hat keine benutzerverwalteten Schlüssel."`
- expected_state: "Keine benutzerverwalteten Schlüssel; stattdessen Workload Identity oder kurzlebige Tokens verwenden"
- audit_evidence (Template): `f"keys.list() found 0 USER_MANAGED keys for {sa_email}"`

---

### GCP-NR4-003 — GKE Workload Identity konfiguriert

Klassen-Docstring (wörtlich): "Prüft ob GKE-Cluster Workload Identity konfiguriert haben."

| Feld | Wert |
|---|---|
| Klasse | `CheckWorkloadIdentity` |
| description | "Prüft ob GKE-Cluster Workload Identity für sichere Dienstkontozuordnung konfiguriert haben." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: MEDIUM. |
| iso27001_control | Inline Literal "A.5.19 Informationssicherheit in Lieferantenbeziehungen" (identisch in beiden Pfaden) |
| required_permissions | `["container.clusters.list"]` |
| pruefgrenzen | "Prüft nur, ob GKE-Cluster Workload Identity aktiviert haben. Projekte ohne GKE liefern kein Ergebnis (Nicht anwendbar)." |
| Prüflogik (deskriptiv) | Je `session.project_ids`: `container_v1.ClusterManagerClient.list_clusters(parent="projects/{project_id}/locations/-")`; je Cluster wird `workload_identity_config.workload_pool` geprüft — gesetzt → Positivnachweis je Cluster, nicht gesetzt → Mangel-Finding je Cluster. Leere Cluster-Liste erzeugt kein Finding für das Projekt (kein expliziter "Nicht anwendbar"-Nachweis). |

**Finding-Texte (Mangel-Pfad, je Cluster):**
- title: "GKE-Cluster ohne Workload Identity"
- description (Template): `f"GKE-Cluster {cluster.name} in Projekt {project_id} hat keine Workload Identity konfiguriert. Ohne Workload Identity müssen Pods Service-Account-Schlüssel verwenden, was ein Lieferkettenrisiko darstellt."`
- expected_state: "Workload Identity für den GKE-Cluster aktiviert"
- remediation: "Aktivieren Sie Workload Identity: gcloud container clusters update <CLUSTER_NAME> --workload-pool=<PROJECT_ID>.svc.id.goog --zone=<ZONE> --project=<PROJECT_ID>"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"list_clusters() cluster {cluster.name} workload_identity_config=None"`

**Positivnachweis (compliant_finding, je Cluster):**
- title: "GKE-Cluster mit Workload Identity"
- description (Template): `f"GKE-Cluster {cluster.name} in Projekt {project_id} hat Workload Identity konfiguriert."`
- expected_state: "Workload Identity für den GKE-Cluster aktiviert"
- audit_evidence (Template): `f"list_clusters() cluster {cluster.name} workload_pool configured"`

---

### GCP-NR4-004 — Binary Authorization konfiguriert

Klassen-Docstring (wörtlich): "Prüft ob Binary Authorization aktiviert ist."

| Feld | Wert |
|---|---|
| Klasse | `CheckBinaryAuthorization` |
| description | "Prüft ob Binary Authorization für die Überprüfung von Container-Images vor dem Deployment konfiguriert ist." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: MEDIUM. |
| iso27001_control | Inline Literal "A.5.19 Informationssicherheit in Lieferantenbeziehungen" (identisch in beiden Pfaden) |
| required_permissions | `["binaryauthorization.policy.get"]` |
| pruefgrenzen | "Prüft nur, ob eine Binary-Authorization-Policy existiert. Ihre Strenge (z. B. Always-Allow) wird nicht inhaltlich bewertet." |
| Prüflogik (deskriptiv) | Je `session.project_ids`: `binaryauthorization v1 projects().getPolicy(name="projects/{project_id}")`; `evaluation_mode = defaultAdmissionRule.get("evaluationMode", "ALWAYS_ALLOW")`; ungleich "ALWAYS_ALLOW" → Positivnachweis; gleich "ALWAYS_ALLOW" → Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Binary Authorization erlaubt alle Images"
- description (Template): `f"Projekt {project_id} hat Binary Authorization mit evaluationMode=ALWAYS_ALLOW konfiguriert. Ohne Überprüfung können unsichere Container-Images deployed werden."`
- expected_state: "Binary Authorization mit evaluationMode REQUIRE_ATTESTATION oder ALWAYS_DENY"
- remediation: "Konfigurieren Sie Binary Authorization: gcloud container binauthz policy export > policy.yaml # Ändern Sie evaluationMode auf REQUIRE_ATTESTATION gcloud container binauthz policy import policy.yaml --project=<PROJECT_ID>"
- remediation_effort: HIGH
- audit_evidence (Template): `f"getPolicy() defaultAdmissionRule.evaluationMode={evaluation_mode}"`

**Positivnachweis (compliant_finding):**
- title: "Binary Authorization aktiv"
- description (Template): `f"Projekt {project_id} prüft Container-Images vor dem Deployment (evaluationMode={evaluation_mode})."`
- expected_state: "Binary Authorization mit evaluationMode REQUIRE_ATTESTATION oder ALWAYS_DENY"
- audit_evidence (Template): `f"getPolicy() defaultAdmissionRule.evaluationMode={evaluation_mode}"`

---

### GCP-NR4-005 — VPC Service Controls für Lieferkettensicherheit

Klassen-Docstring (wörtlich): "Prüft ob VPC Service Controls gegen Datenexfiltration in der Lieferkette konfiguriert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckVpcServiceControlsSupplyChain` |
| description | "Prüft ob VPC Service Controls konfiguriert sind, um Datenexfiltration durch Drittanbieter-Zugriffe zu verhindern." |
| severity | Kein Klassenattribut. Inline im Mangel-Pfad: MEDIUM. |
| iso27001_control | Inline Literal "A.5.19, A.8.22 Netzwerksegmentierung" (identisch in beiden Pfaden) |
| required_permissions | `["accesscontextmanager.accessPolicies.list"]` |
| pruefgrenzen | "Prüft nur die Existenz von VPC-Service-Controls-Perimetern (wie GCP-NR9-008, hier unter Lieferketten-Blickwinkel). Erfordert Organisations-Berechtigung." |
| Prüflogik (deskriptiv) | Einzige Ausführung ohne Schleife über `session.project_ids` (siehe Auffälligkeiten): `accesscontextmanager v1 accessPolicies().list()`; für jede Policy `accessPolicies().servicePerimeters().list(parent=policy_name)`; sobald eine Policy mindestens einen Perimeter hat, wird `has_perimeters = True` gesetzt und die Schleife abgebrochen; Positivnachweis bzw. Mangel-Finding referenzieren `session.project_id` (Singular-Attribut). Bei jeder Exception wird zusätzlich `logger.warning("VPC Service Controls supply chain check skipped", error=str(exc), hint="VPC SC requires organization-level access")` protokolliert, bevor ein `CheckError` angehängt wird. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine VPC Service Controls für Lieferkettensicherheit"
- description (Template): `f"Projekt {project_id} hat keine VPC Service Controls Perimeter. Ohne VPC SC können Lieferanten mit Projektzugriff Daten aus GCP-Diensten exfiltrieren."`
- expected_state: "VPC Service Controls Perimeter zum Schutz vor Datenexfiltration durch Drittanbieter"
- remediation: "Erstellen Sie einen VPC Service Controls Perimeter: gcloud access-context-manager perimeters create <NAME> --title='Lieferkettenperimeter' --resources=projects/<PROJECT_NUMBER> --restricted-services='storage.googleapis.com,bigquery.googleapis.com' --policy=<POLICY_ID>"
- remediation_effort: HIGH
- audit_evidence: "accessPolicies.servicePerimeters.list() returned 0 perimeters"

**Positivnachweis (compliant_finding):**
- title: "VPC Service Controls für Lieferkettensicherheit aktiv"
- description: "Mindestens ein VPC Service Controls Perimeter schützt vor Datenexfiltration durch Drittanbieter-Zugriffe."
- expected_state: "VPC Service Controls Perimeter zum Schutz vor Datenexfiltration durch Drittanbieter"
- audit_evidence: "accessPolicies.servicePerimeters.list() returned >=1 perimeter"

---

## Mechanische Auffälligkeiten (ohne Bewertung)

1. Keine der 15 Check-Klassen in diesem Batch definiert ein Klassenattribut `severity` (abweichend vom Muster im Repo-`CLAUDE.md`) — severity wird stattdessen pro `Finding()`-Aufruf im Mangel-Pfad als Parameter gesetzt (je Check konsistent, aber teils unterschiedlich zwischen den Mangel-Varianten desselben Checks, z. B. AWS-NR4-001: MEDIUM in beiden Varianten; AWS-NR4-002/003: HIGH; AWS-NR4-005: MEDIUM in allen drei Varianten).
2. Keine der 15 Check-Klassen definiert ein Klassenattribut `iso_27001_ref`; `iso27001_control` wird stattdessen pro `Finding()`/`compliant_finding()`-Aufruf als Parameter übergeben. Nur AWS-NR4-001 nutzt dafür die Modul-Konstante `ISO_CONTROL`; alle anderen 14 Checks (AWS-002 bis 005, alle Azure- und GCP-Checks) wiederholen den ISO-Text als String-Literal an jeder Aufrufstelle.
3. AWS-NR4-001: Der Schwellwert `len(checks) >= 20` zur Unterscheidung von Support-Plänen ist hart codiert; der zugehörige Kommentar nennt als Referenzwerte "< 10" (Basic) und "50+" (Business/Enterprise) — der tatsächliche Code-Schwellwert 20 liegt dazwischen und wird im Code nicht weiter begründet.
4. AWS-NR4-002: Der `except`-Zweig für `"UnknownEndpoint" in error_str or "Could not connect" in error_str` führt ein stilles `pass` aus — weder Finding noch `CheckError` wird erzeugt. Der zugehörige Kommentar "RAM not available in region, try default region" beschreibt keinen im Code tatsächlich vorhandenen Retry-Mechanismus.
5. AWS-NR4-002: Die Variable `external_shares` enthält trotz ihres Namens alle über `get_resource_shares(resourceOwner="SELF")` zurückgegebenen Shares (nicht nur externe); die Filterung auf tatsächlich externe/aktive Shares erfolgt erst in der separaten Variable `external_active`. Der `total_shares`-Wert im `current_state` des Positivnachweises basiert entsprechend auf der ungefilterten Liste.
6. AWS-NR4-004: `required_permissions` listet `iam:GetRole`, im Code wird jedoch nur `iam:ListRoles` über `get_paginator("list_roles")` aufgerufen; ein separater `GetRole`-API-Aufruf ist im Modul nicht vorhanden (die Trust-Policy wird direkt aus dem `list_roles`-Response gelesen).
7. AZ-NR4-002: Sind keine Gastbenutzer vorhanden, liefert der Check per frühem `return` weder ein Finding noch einen Error (leere `findings`- und `errors`-Listen zurückgegeben) — für diesen Scan-Lauf entsteht zu diesem Check kein Nachweis (weder Mangel noch Positivnachweis).
8. AZ-NR4-002: Die Bedingung `if include_groups: guest_ca_found = True; break` wertet bereits das bloße Vorhandensein einer nicht-leeren `include_groups`-Liste in einer aktivierten Conditional-Access-Policy als hinreichend, unabhängig davon, ob die referenzierten Gruppen tatsächlich Gastbenutzer enthalten.
9. AZ-NR4-003: Die Prüflogik zählt die Gesamtzahl der Private Endpoints je Subscription, ohne festzustellen, welche konkreten PaaS-Ressourcen dadurch abgesichert sind; Titel und description sprechen allgemein von "PaaS-Diensten".
10. AZ-NR4-004: Ist `applications` leer (keine App-Registrierungen in der Subscription), greift weder der Positiv- (`if applications and old_creds_count == 0`) noch der Mangel-Zweig (`elif old_creds_count > 0`) — es wird kein Finding erzeugt.
11. AZ-NR4-005: Ist `vms` leer (keine VMs in der Subscription), greift ebenfalls weder der Positiv- (`if vms and not untrusted_vms`) noch der Mangel-Zweig (`elif untrusted_vms`) — es wird kein Finding erzeugt.
12. AZ-NR4-005: `TRUSTED_PUBLISHERS` ist eine im Code fest hinterlegte, nicht konfigurierbare Publisher-Liste; eine VM ohne gesetzten `publisher`-Wert (leerer String) wird durch die Bedingung `if publisher and publisher not in self.TRUSTED_PUBLISHERS` nicht als "untrusted" gezählt.
13. GCP-NR4-001: Die Prüfung auf externe Prinzipale erfasst ausschließlich Members mit Präfix `"serviceAccount:"`; Members vom Typ `user:`, `group:` oder `domain:` werden nicht auf externe Herkunft geprüft, obwohl Titel und description allgemein von "externen Prinzipalen" bzw. "externen IAM-Bindungen" sprechen.
14. GCP-NR4-001: Externe Herkunft wird über den String-Test `project_id not in member` bestimmt (Teilstring-Vergleich der Projekt-ID im vollständigen Member-String), kein strukturierter Vergleich gegen das Projekt-Suffix der Service-Account-E-Mail.
15. GCP-NR4-003: Ist die `clusters`-Liste eines Projekts leer, wird für dieses Projekt kein Finding erzeugt — konsistent mit der dokumentierten `pruefgrenzen`-Aussage "Projekte ohne GKE liefern kein Ergebnis (Nicht anwendbar)".
16. GCP-NR4-005 ist der einzige Nr.-4-Check aller drei Provider, der NICHT über `session.project_ids` iteriert, sondern die Prüfung einmalig ausführt und für Resource-ID/Account-ID das Singular-Attribut `session.project_id` verwendet.
17. Die Exception-Behandlung unterscheidet sich zwischen den Providern in diesem Batch: AWS-NR4-001, -003 und -005 differenzieren nach spezifischem AWS-Exception-Typ (`SubscriptionRequiredException`, `AWSOrganizationsNotInUseException`, `AccessDeniedException`) und erzeugen dafür jeweils eigene Findings statt Errors; alle fünf Azure-Checks sowie GCP-NR4-005 fangen Exceptions durchgängig generisch (`except Exception as exc`) und erzeugen in jedem Fall einen `CheckError`, ohne nach Fehlerursache zu unterscheiden.
18. `CheckError()`-Aufrufe unterscheiden sich zwischen Providern: AWS und GCP übergeben nur `message` und `error_type`; Azure übergibt zusätzlich `check_id` und `region="global"`.
19. AWS-NR4-002 und AWS-NR4-004 setzen `error_type="CheckError"` im äußeren Except-Block, obwohl der Fehlertext jeweils inhaltlich denselben Sachverhalt wie im inneren Block (`error_type="AWSClientError"`, sofern vorhanden) beschreibt — die beiden `error_type`-Werte innerhalb eines Checks sind nicht einheitlich benannt.
20. Granularität der Findings ist zwischen den Checks uneinheitlich: AWS-NR4-002 und -004 erzeugen ein Finding je Einzelressource (Share bzw. Rolle), AWS-NR4-001, -003 und -005 je ein aggregiertes Finding je Account; Azure erzeugt bei allen fünf Checks je ein aggregiertes Finding je Subscription; GCP erzeugt bei GCP-NR4-002 und -003 je ein Finding pro Einzelressource (Service Account bzw. Cluster), bei GCP-NR4-001, -004 und -005 je ein aggregiertes Finding je Projekt.
