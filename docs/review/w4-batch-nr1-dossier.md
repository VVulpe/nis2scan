# W4 Batch-Review-Dossier — §30 Abs. 2 Nr. 1 BSIG (Risikoanalyse)

> Mechanisch extrahiert am 2026-07-12 (Worker, ohne rechtliche Bewertung).
> Prüfgegenstand für: Gründer + Agent legal-reviewer (ADR-0018).

Quelldateien:
- `nis2scan/engine/providers/aws/checks/nr1_risikoanalyse.py`
- `nis2scan/engine/providers/azure/checks/nr1_risikoanalyse.py`
- `nis2scan/engine/providers/gcp/checks/nr1_risikoanalyse.py`

Ist-Zahl erfasster Checks: **15** (AWS: 5, Azure: 5, GCP: 5) — entspricht der erwarteten Zahl.

## Modul-Konstanten je Provider

### AWS (`nr1_risikoanalyse.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 1 — Risikoanalyse & IT-Sicherheitskonzepte checks for AWS.

  Checks CloudTrail configuration for audit trail and log integrity.
  ```
- `BSIG_30_NR = 1`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 1 BSIG — Konzepte in Bezug auf die Risikoanalyse und auf die Sicherheit in der Informationstechnik"
- `ISO_CONTROL` (wörtlich): "A.8.15 Logging"

### Azure (`nr1_risikoanalyse.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 1 — Risikoanalyse & IT-Sicherheitskonzepte checks for Azure.

  Checks Defender for Cloud, Azure Policy, Management Groups, Activity Logs, and Sentinel.
  ```
- `BSIG_30_NR = 1`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 1 BSIG — Konzepte in Bezug auf die Risikoanalyse und auf die Sicherheit in der Informationstechnik"
- Kein Modul-Äquivalent zu `ISO_CONTROL`.

### GCP (`nr1_risikoanalyse.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 1 — Risikoanalyse & IT-Sicherheitskonzepte checks for GCP.

  Checks Security Command Center, Organization Policies, Audit Logging,
  Cloud Asset Inventory, and VPC Service Controls.
  ```
- `BSIG_30_NR = 1`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 1 BSIG — Konzepte in Bezug auf die Risikoanalyse und auf die Sicherheit in der Informationstechnik"
- Kein Modul-Äquivalent zu `ISO_CONTROL`.

---

## Checks

### AWS-NR1-001 — AWS Config Recorder

Klassen-Docstring (wörtlich): "Check that AWS Config Recorder is active in all regions."

| Feld | Wert |
|---|---|
| Klasse | `CheckConfigRecorder` |
| description | "Prüft ob AWS Config Recorder in allen Regionen aktiv ist." |
| severity | HIGH (bei allen Findings dieses Checks) |
| iso_27001_ref | "A.5.1, A.8.9" (inline, kein Klassenattribut) |
| required_permissions | `["config:DescribeConfigurationRecorders", "config:DescribeConfigurationRecorderStatus"]` |
| pruefgrenzen | "Prüft nur, ob ein Config Recorder in den gescannten Regionen aufzeichnet. Nicht geprüft werden der Aufzeichnungsumfang (alle Ressourcentypen?) und ob die aufgezeichneten Daten ausgewertet werden." |

**Finding-Texte (Mangel-Pfad):**

1. Kein Recorder konfiguriert (pro Region):
   - title: "Kein AWS Config Recorder konfiguriert"
   - description (Template): `f"In der Region '{region}' ist kein AWS Config Recorder konfiguriert. Ohne Config Recorder werden Konfigurationsänderungen nicht aufgezeichnet."`
   - expected_state: "Mindestens ein Config Recorder aktiv"
   - remediation: "Aktivieren Sie AWS Config in allen Regionen: aws configservice put-configuration-recorder --configuration-recorder name=default,roleARN=<role-arn> --recording-group allSupported=true,includeGlobalResourceTypes=true"

2. Recorder vorhanden, aber nicht aufzeichnend:
   - title: "Config Recorder nicht aktiv"
   - description (Template): `f"Der Config Recorder '{recorder_name}' in Region '{region}' zeichnet derzeit nicht auf."`
   - expected_state: "Config Recorder recording=true"
   - remediation: "Starten Sie den Config Recorder: aws configservice start-configuration-recorder --configuration-recorder-name <recorder-name>"

**Positivnachweis (compliant_finding):**
- title: "Config Recorder aktiv"
- description (Template): `f"Der Config Recorder '{recorder_name}' in Region '{region}' zeichnet Konfigurationsänderungen auf."`
- expected_state: "Config Recorder recording=true"
- audit_evidence (Template): `f"DescribeConfigurationRecorderStatus: recording=true for {recorder_name} in {region}"`

---

### AWS-NR1-002 — AWS Security Hub

Klassen-Docstring (wörtlich): "Check that AWS Security Hub is enabled with CIS/Foundational Benchmarks."

| Feld | Wert |
|---|---|
| Klasse | `CheckSecurityHub` |
| description | "Prüft ob AWS Security Hub mit CIS/Foundational Benchmarks aktiviert ist." |
| severity | HIGH |
| iso_27001_ref | "A.5.1" (inline) |
| required_permissions | `["securityhub:DescribeHub"]` |
| pruefgrenzen | "Prüft nur, ob Security Hub aktiviert ist — nicht, welche Standards (CIS/Foundational) tatsächlich aktiviert sind und ob Befunde bearbeitet werden." |

**Finding-Texte (Mangel-Pfad):**
- title: "Security Hub nicht aktiviert"
- description (Template): `f"AWS Security Hub ist in Region '{region}' nicht aktiviert. Ohne Security Hub fehlt eine zentrale Übersicht über Sicherheitsbefunde."`
- expected_state: "Security Hub mit CIS/Foundational Benchmarks aktiviert"
- remediation: "Aktivieren Sie Security Hub: aws securityhub enable-security-hub --enable-default-standards"
- (ausgelöst im except-Zweig für `sh_client.exceptions.InvalidAccessException`)

**Positivnachweis (compliant_finding):**
- title: "Security Hub aktiviert"
- description (Template): `f"AWS Security Hub ist in Region '{region}' aktiviert."`
- expected_state: "Security Hub aktiviert"
- audit_evidence (Template): `f"DescribeHub succeeded in {region}"`

---

### AWS-NR1-003 — AWS Organizations mit SCPs

Klassen-Docstring (wörtlich): "Check that AWS Organizations with SCPs is configured."

| Feld | Wert |
|---|---|
| Klasse | `CheckOrganizationsScp` |
| description | "Prüft ob AWS Organizations mit Service Control Policies (SCPs) konfiguriert ist." |
| severity | MEDIUM (bei allen Findings dieses Checks) |
| iso_27001_ref | "A.5.1, A.5.2" (inline) |
| required_permissions | `["organizations:DescribeOrganization", "organizations:ListPolicies"]` |
| pruefgrenzen | "Prüft nur Existenz der Organization und benutzerdefinierter SCPs. Nicht geprüft werden Inhalt und Wirksamkeit der SCPs sowie deren tatsächliche Zuordnung zu Accounts/OUs. Einzelaccounts ohne Organizations erhalten einen Mangel, obwohl SCPs dort nicht anwendbar sind." |

**Finding-Texte (Mangel-Pfad):**

1. Keine Organization vorhanden:
   - title: "Kein AWS Organizations konfiguriert"
   - description: "AWS Organizations ist in diesem Account nicht konfiguriert. Ohne Organizations können keine zentralen Service Control Policies durchgesetzt werden."
   - expected_state: "AWS Organizations mit SCPs aktiviert"
   - remediation: "Erstellen Sie eine AWS Organization: aws organizations create-organization --feature-set ALL"

2. Organization vorhanden, aber keine eigenen SCPs (nur Standard-FullAWSAccess):
   - title: "Keine benutzerdefinierten SCPs"
   - description: "AWS Organizations ist aktiv, aber es sind keine benutzerdefinierten Service Control Policies konfiguriert. Nur die Standard-FullAWSAccess-Policy ist vorhanden."
   - expected_state: "Mindestens eine benutzerdefinierte SCP konfiguriert"
   - remediation: "Erstellen Sie SCPs zur Einschränkung von Berechtigungen: aws organizations create-policy --name <policy-name> --type SERVICE_CONTROL_POLICY --content <policy-json>"

**Positivnachweis (compliant_finding):**
- title: "AWS Organizations mit benutzerdefinierten SCPs"
- description (Template): `f"AWS Organizations ist aktiv und es sind {len(custom_policies)} benutzerdefinierte Service Control Policies konfiguriert."`
- expected_state: "Mindestens eine benutzerdefinierte SCP konfiguriert"
- audit_evidence (Template): `f"ListPolicies: {len(policies)} policies, {len(custom_policies)} custom SCPs"`

---

### AWS-NR1-004 — CloudTrail Log-Integrität

Klassen-Docstring (wörtlich): "Check that CloudTrail is active with log file validation enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckCloudTrail` |
| description | "Prüft ob CloudTrail in allen Regionen aktiv ist und Log-File-Validation aktiviert hat." |
| severity | CRITICAL (bei allen Findings dieses Checks) |
| iso_27001_ref | "A.8.15 Logging" (Modul-Konstante `ISO_CONTROL`) |
| required_permissions | `["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"]` |
| pruefgrenzen | "Prüft nur Existenz, Logging-Status und Log-File-Validation der Trails. Nicht geprüft werden Vollständigkeit der aufgezeichneten Events, S3-Bucket-Schutz der Logs und ob die Logs tatsächlich ausgewertet werden." |

**Finding-Texte (Mangel-Pfad):**

1. Kein Trail vorhanden:
   - title: "Kein CloudTrail konfiguriert"
   - description: "Es ist kein CloudTrail in diesem Account konfiguriert. Ohne CloudTrail gibt es keinen Audit-Trail für API-Aktivitäten."
   - expected_state: "Mindestens ein CloudTrail mit Multi-Region und Log-Validation aktiv"
   - remediation: "Erstellen Sie einen CloudTrail mit Multi-Region-Logging und Log-File-Validation: aws cloudtrail create-trail --name main-trail --s3-bucket-name <bucket> --is-multi-region-trail --enable-log-file-validation"

2. Trail ohne Log-File-Validation:
   - title: "CloudTrail ohne Log-File-Validation"
   - description (Template): `f"Der CloudTrail '{trail_name}' hat keine Log-File-Validation aktiviert. Ohne Validation können Log-Dateien unbemerkt manipuliert werden."`
   - expected_state: "LogFileValidationEnabled=true"
   - remediation: "Aktivieren Sie die Log-File-Validation: aws cloudtrail update-trail --name <trail-name> --enable-log-file-validation"

3. Trail konfiguriert, aber Logging deaktiviert:
   - title: "CloudTrail Logging deaktiviert"
   - description (Template): `f"Der CloudTrail '{trail_name}' ist konfiguriert aber das Logging ist deaktiviert."`
   - expected_state: "CloudTrail Logging aktiv"
   - remediation: "Aktivieren Sie das Logging: aws cloudtrail start-logging --name <trail-name>"

**Positivnachweis (compliant_finding):**
- title: "CloudTrail mit Log-Integrität aktiv"
- description (Template): `f"Der CloudTrail '{trail_name}' ist aktiv und hat Log-File-Validation aktiviert."`
- expected_state: "CloudTrail aktiv mit LogFileValidationEnabled=true"
- audit_evidence (Template): `f"DescribeTrails/GetTrailStatus: IsLogging=true, LogFileValidationEnabled=true for trail {trail_name}"`

---

### AWS-NR1-005 — GuardDuty für Risikoanalyse

Klassen-Docstring (wörtlich): "Check that GuardDuty is enabled for risk analysis."

| Feld | Wert |
|---|---|
| Klasse | `CheckGuardDutyRiskAnalysis` |
| description | "Prüft ob Amazon GuardDuty als Bedrohungserkennungsdienst für die Risikoanalyse aktiviert ist." |
| severity | HIGH (bei allen Findings dieses Checks) |
| iso_27001_ref | "A.5.7" (inline) |
| required_permissions | `["guardduty:ListDetectors", "guardduty:GetDetector"]` |
| pruefgrenzen | "Prüft nur den Detector-Status in den gescannten Regionen. Nicht geprüft werden aktivierte Schutz-Features (S3/EKS/Malware Protection) und ob GuardDuty-Befunde tatsächlich bearbeitet werden." |

**Finding-Texte (Mangel-Pfad):**

1. Kein Detector vorhanden:
   - title: "GuardDuty nicht aktiviert"
   - description (Template): `f"Amazon GuardDuty ist in Region '{region}' nicht aktiviert. Ohne GuardDuty fehlt eine automatische Bedrohungserkennung für die Risikoanalyse."`
   - expected_state: "GuardDuty Detector aktiv"
   - remediation: "Aktivieren Sie GuardDuty: aws guardduty create-detector --enable"

2. Detector vorhanden, aber Status ≠ ENABLED:
   - title: "GuardDuty Detector nicht aktiv"
   - description (Template): `f"Der GuardDuty Detector '{detector_id}' in Region '{region}' ist nicht aktiv (Status: {status})."`
   - expected_state: "GuardDuty Status=ENABLED"
   - remediation: "Aktivieren Sie den Detector: aws guardduty update-detector --detector-id <detector-id> --enable"

**Positivnachweis (compliant_finding):**
- title: "GuardDuty aktiv"
- description (Template): `f"Amazon GuardDuty ist in Region '{region}' aktiv und überwacht auf Bedrohungen."`
- expected_state: "GuardDuty Status=ENABLED"
- audit_evidence (Template): `f"GetDetector: Status=ENABLED for {detector_id} in {region}"`

---

### AZ-NR1-001 — Defender for Cloud aktiviert

Klassen-Docstring (wörtlich): "Check that Microsoft Defender for Cloud is enabled across subscriptions."

| Feld | Wert |
|---|---|
| Klasse | `CheckDefenderForCloud` |
| description | "Prüft ob Microsoft Defender for Cloud in allen Subscriptions aktiviert ist." |
| severity | HIGH |
| iso_27001_ref | "A.5.1 Informationssicherheitsrichtlinien" (inline) |
| required_permissions | `["Microsoft.Security/pricings/read"]` |
| pruefgrenzen | "Prüft nur, ob Defender-for-Cloud-Pläne aktiviert sind. Nicht geprüft wird, ob die Empfehlungen bearbeitet werden." |

**Finding-Texte (Mangel-Pfad):**
- title: "Defender-Pläne nicht aktiviert"
- description (Template): `f"Subscription {sub_id} hat Defender-Pläne im Free-Tier: {plan_names}. Ohne Defender fehlt die zentrale Sicherheitsbewertung."`
- expected_state: "Alle Defender-Pläne auf Standard-Tier"
- remediation: "Aktivieren Sie Defender for Cloud Standard-Tier: az security pricing create --name VirtualMachines --tier Standard"

**Positivnachweis (compliant_finding):**
- title: "Defender for Cloud aktiviert"
- description (Template): `f"Subscription {sub_id} hat alle {len(pricings)} Defender-Pläne im Standard-Tier aktiviert."`
- expected_state: "Alle Defender-Pläne auf Standard-Tier"
- audit_evidence (Template): `f"pricings.list() returned {len(pricings)} plans, 0 Free-Tier"`

---

### AZ-NR1-002 — Azure Policy Assignments vorhanden

Klassen-Docstring (wörtlich): "Check that Azure Policy assignments exist for governance."

| Feld | Wert |
|---|---|
| Klasse | `CheckAzurePolicyAssignments` |
| description | "Prüft ob Azure Policy Assignments für die Durchsetzung von Sicherheitsstandards existieren." |
| severity | HIGH |
| iso_27001_ref | "A.5.1, A.5.2 Informationssicherheitsrichtlinien" (inline) |
| required_permissions | `["Microsoft.Authorization/policyAssignments/read"]` |
| pruefgrenzen | "Prüft nur die Existenz von Policy-Zuweisungen. Inhalt und Angemessenheit der Policies werden nicht bewertet." |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine benutzerdefinierten Policy Assignments"
- description (Template): `f"Subscription {sub_id} hat keine benutzerdefinierten Azure Policy Assignments. Ohne Policies werden Sicherheitsstandards nicht automatisch durchgesetzt."`
- expected_state: "Mindestens eine benutzerdefinierte Policy Assignment"
- remediation: "Erstellen Sie Azure Policy Assignments für CIS Benchmark oder ISO 27001: az policy assignment create --name 'cis-benchmark' --policy-set-definition 'CIS Microsoft Azure Foundations'"

**Positivnachweis (compliant_finding):**
- title: "Azure Policy Assignments vorhanden"
- description (Template): `f"Subscription {sub_id} hat {len(custom_assignments)} benutzerdefinierte Azure Policy Assignments."`
- expected_state: "Mindestens eine benutzerdefinierte Policy Assignment"
- audit_evidence (Template): `f"policy_assignments.list() returned {len(assignments)} total, {len(custom_assignments)} custom"`

---

### AZ-NR1-003 — Management Groups konfiguriert

Klassen-Docstring (wörtlich): "Check that Azure Management Groups are configured for governance."

| Feld | Wert |
|---|---|
| Klasse | `CheckManagementGroups` |
| description | "Prüft ob Azure Management Groups für organisationsweite Governance konfiguriert sind." |
| severity | MEDIUM |
| iso_27001_ref | "A.5.1 Informationssicherheitsrichtlinien" (inline) |
| required_permissions | `["Microsoft.Management/managementGroups/read"]` |
| pruefgrenzen | "Prüft nur die Existenz von Management Groups. Ob die Hierarchie sinnvoll strukturiert ist, wird nicht bewertet. Einzel-Subscriptions ohne Management Groups erhalten einen Mangel, obwohl diese dort wenig Nutzen stiften." |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine benutzerdefinierten Management Groups"
- description: "Es sind keine benutzerdefinierten Management Groups konfiguriert. Ohne Management Groups kann keine organisationsweite Governance umgesetzt werden."
- expected_state: "Mindestens eine benutzerdefinierte Management Group"
- remediation: "Erstellen Sie Management Groups für Ihre Organisation: az account management-group create --name 'Production' --display-name 'Production Workloads'"

**Positivnachweis (compliant_finding):**
- title: "Management Groups konfiguriert"
- description (Template): `f"Es sind {len(custom_groups)} benutzerdefinierte Management Groups für organisationsweite Governance konfiguriert."`
- expected_state: "Mindestens eine benutzerdefinierte Management Group"
- audit_evidence (Template): `f"management_groups.list() returned {len(groups)} total, {len(custom_groups)} custom"`

---

### AZ-NR1-004 — Activity Log Export konfiguriert

Klassen-Docstring (wörtlich): "Check that Activity Logs are exported to Log Analytics or Storage."

| Feld | Wert |
|---|---|
| Klasse | `CheckActivityLogRetention` |
| description | "Prüft ob Azure Activity Logs an Log Analytics oder Storage Account exportiert werden." |
| severity | CRITICAL |
| iso_27001_ref | "A.8.15 Logging" (inline) |
| required_permissions | `["Microsoft.Insights/diagnosticSettings/read"]` |
| pruefgrenzen | "Prüft nur, ob ein Activity-Log-Export (Diagnostic Setting) konfiguriert ist. Vollständigkeit der Kategorien und Auswertung der Logs werden nicht geprüft." |

**Finding-Texte (Mangel-Pfad):**
- title: "Activity Log nicht exportiert"
- description (Template): `f"Subscription {sub_id} exportiert Activity Logs nicht an Log Analytics oder Storage. Ohne Export fehlt der Audit-Trail."`
- expected_state: "Mindestens ein Diagnostic Setting für Activity Log Export"
- remediation: "Konfigurieren Sie Activity Log Export: az monitor diagnostic-settings create --name 'activity-log-export' --resource '/subscriptions/<sub>' --workspace <log-analytics-id>"

**Positivnachweis (compliant_finding):**
- title: "Activity Log Export konfiguriert"
- description (Template): `f"Subscription {sub_id} exportiert Activity Logs über {len(settings)} Diagnostic Setting(s)."`
- expected_state: "Mindestens ein Diagnostic Setting für Activity Log Export"
- audit_evidence (Template): `f"diagnostic_settings.list() returned {len(settings)} setting(s)"`

---

### AZ-NR1-005 — Sentinel / SIEM Workspace

Klassen-Docstring (wörtlich): "Check that a SIEM (Microsoft Sentinel) workspace exists."

| Feld | Wert |
|---|---|
| Klasse | `CheckSentinelWorkspace` |
| description | "Prüft ob ein Microsoft Sentinel oder äquivalentes SIEM konfiguriert ist." |
| severity | HIGH |
| iso_27001_ref | "A.5.7 Threat Intelligence" (inline) |
| required_permissions | `["Microsoft.OperationalInsights/workspaces/read", "Microsoft.SecurityInsights/operations/read"]` |
| pruefgrenzen | "Prüft nur, ob ein Sentinel-fähiger Log-Analytics-Workspace existiert. Ein SIEM außerhalb von Azure (Splunk, Elastic u. a.) wird nicht erkannt." |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein SIEM / Sentinel Workspace"
- description (Template): `f"Subscription {sub_id} hat keinen aktiven Log Analytics Workspace für Bedrohungserkennung. Ohne SIEM fehlt die zentrale Bedrohungserkennung."`
- expected_state: "Mindestens ein aktiver Log Analytics Workspace mit Sentinel"
- remediation: "Erstellen Sie einen Log Analytics Workspace und aktivieren Sie Sentinel: az monitor log-analytics workspace create --resource-group <rg> --workspace-name sentinel-ws"

**Positivnachweis (compliant_finding):**
- title: "SIEM / Log Analytics Workspace aktiv"
- description (Template): `f"Subscription {sub_id} hat einen aktiven Log Analytics Workspace für Bedrohungserkennung."`
- expected_state: "Mindestens ein aktiver Log Analytics Workspace mit Sentinel"
- audit_evidence (Template): `f"workspaces.list() returned {len(workspaces)} workspace(s), >=1 active"`

Anmerkung zur Erkennungslogik (mechanisch, ohne Bewertung): Ein Workspace gilt als "Sentinel gefunden", sobald `ws.provisioning_state == "Succeeded"` — der Code-Kommentar dazu lautet wörtlich: "Sentinel workspaces typically have SecurityInsights solution / We check if there are any Log Analytics workspaces as a proxy".

---

### GCP-NR1-001 — Security Command Center aktiviert

Klassen-Docstring (wörtlich): "Prüft ob Security Command Center in GCP-Projekten aktiviert ist."

| Feld | Wert |
|---|---|
| Klasse | `CheckSecurityCommandCenter` |
| description | "Prüft ob das Google Cloud Security Command Center (SCC) aktiviert ist und Sicherheitsquellen konfiguriert sind." |
| severity | HIGH |
| iso_27001_ref | "A.5.1 Informationssicherheitsrichtlinien" (inline) |
| required_permissions | `["securitycenter.sources.list"]` |
| pruefgrenzen | "Prüft nur, ob das Security Command Center per API zugänglich ist. Aktivierte Tier-Stufe (Standard/Premium) und Bearbeitung der Befunde werden nicht bewertet." |

**Finding-Texte (Mangel-Pfad):**
- title: "Security Command Center nicht aktiviert"
- description (Template): `f"Projekt {project_id} hat keine SCC-Quellen konfiguriert. Ohne SCC fehlt die zentrale Sicherheitsbewertung und Bedrohungserkennung."`
- expected_state: "Security Command Center mit mindestens einer aktiven Quelle"
- remediation: "Aktivieren Sie das Security Command Center: gcloud scc settings update --project=<PROJECT_ID> --enable-scc"

**Positivnachweis (compliant_finding):**
- title: "Security Command Center aktiviert"
- description (Template): `f"Projekt {project_id} hat {len(sources)} SCC-Quelle(n) — zentrale Sicherheitsbewertung ist aktiv."`
- expected_state: "Security Command Center mit mindestens einer aktiven Quelle"
- audit_evidence (Template): `f"list_sources() returned {len(sources)} source(s)"`

---

### GCP-NR1-002 — Organisationsrichtlinien vorhanden

Klassen-Docstring (wörtlich): "Prüft ob Organisationsrichtlinien für das Projekt definiert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckOrgPolicies` |
| description | "Prüft ob GCP Organization Policies für die Durchsetzung von Sicherheitsstandards konfiguriert sind." |
| severity | HIGH |
| iso_27001_ref | "A.5.1, A.5.2 Informationssicherheitsrichtlinien" (inline) |
| required_permissions | `["orgpolicy.policy.get"]` |
| pruefgrenzen | "Prüft nur die Existenz von Organisationsrichtlinien. Inhalt und Angemessenheit werden nicht bewertet." |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Organisationsrichtlinien definiert"
- description (Template): `f"Projekt {project_id} hat keine Organization Policies. Ohne Richtlinien werden Sicherheitsstandards nicht automatisch durchgesetzt."`
- expected_state: "Mindestens eine Organisationsrichtlinie konfiguriert"
- remediation: "Erstellen Sie Organization Policies: gcloud org-policies set-policy policy.yaml --project=<PROJECT_ID>"

**Positivnachweis (compliant_finding):**
- title: "Organisationsrichtlinien vorhanden"
- description (Template): `f"Projekt {project_id} hat {len(policies)} Organization Policies zur Durchsetzung von Sicherheitsstandards."`
- expected_state: "Mindestens eine Organisationsrichtlinie konfiguriert"
- audit_evidence (Template): `f"policies.list() returned {len(policies)} policies"`

---

### GCP-NR1-003 — Audit-Logging konfiguriert

Klassen-Docstring (wörtlich): "Prüft ob Audit-Logging für das Projekt konfiguriert ist."

| Feld | Wert |
|---|---|
| Klasse | `CheckAuditLogConfig` |
| description | "Prüft ob Cloud Audit Logs für alle Dienste in der IAM-Policy des Projekts aktiviert sind." |
| severity | CRITICAL |
| iso_27001_ref | "A.8.15 Logging" (inline) |
| required_permissions | `["resourcemanager.projects.getIamPolicy"]` |
| pruefgrenzen | "Prüft nur die Audit-Logging-Konfiguration der IAM-Policy. Ob die Logs ausgewertet werden, ist nicht prüfbar." |

**Finding-Texte (Mangel-Pfad):**
- title: "Audit-Logging nicht konfiguriert"
- description (Template): `f"Projekt {project_id} hat keine Audit-Log-Konfiguration in der IAM-Policy. Ohne Audit-Logs fehlt der vollständige Prüfpfad."`
- expected_state: "Audit-Log-Konfiguration für alle Dienste in der IAM-Policy aktiviert"
- remediation: "Aktivieren Sie Data Access Audit Logs: gcloud projects set-iam-policy <PROJECT_ID> policy.json (mit auditConfigs für allServices)"

**Positivnachweis (compliant_finding):**
- title: "Audit-Logging konfiguriert"
- description (Template): `f"Projekt {project_id} hat {len(audit_configs)} Audit-Log-Konfiguration(en) in der IAM-Policy."`
- expected_state: "Audit-Log-Konfiguration für alle Dienste in der IAM-Policy aktiviert"
- audit_evidence (Template): `f"getIamPolicy() returned {len(audit_configs)} auditConfigs"`

---

### GCP-NR1-004 — Cloud Asset Inventory Feeds konfiguriert

Klassen-Docstring (wörtlich): "Prüft ob Cloud Asset Inventory Feeds konfiguriert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckAssetInventory` |
| description | "Prüft ob Cloud Asset Inventory Feeds für die kontinuierliche Überwachung von Ressourcenänderungen eingerichtet sind." |
| severity | MEDIUM |
| iso_27001_ref | "A.8.9 Konfigurationsmanagement" (inline) |
| required_permissions | `["cloudasset.feeds.list"]` |
| pruefgrenzen | "Prüft nur die Existenz von Asset-Inventory-Feeds. Ob die Feeds in eine Risikoanalyse einfließen, ist organisatorisch nachzuweisen." |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Cloud Asset Inventory Feeds"
- description (Template): `f"Projekt {project_id} hat keine Asset Inventory Feeds. Ohne Feeds werden Ressourcenänderungen nicht automatisch überwacht."`
- expected_state: "Mindestens ein Asset Inventory Feed konfiguriert"
- remediation: "Erstellen Sie einen Asset Inventory Feed: gcloud asset feeds create <FEED_ID> --project=<PROJECT_ID> --asset-types='compute.googleapis.com/Instance' --pubsub-topic=projects/<PROJECT_ID>/topics/<TOPIC>"

**Positivnachweis (compliant_finding):**
- title: "Cloud Asset Inventory Feeds konfiguriert"
- description (Template): `f"Projekt {project_id} hat {len(feeds)} Asset Inventory Feed(s) — Ressourcenänderungen werden kontinuierlich überwacht."`
- expected_state: "Mindestens ein Asset Inventory Feed konfiguriert"
- audit_evidence (Template): `f"list_feeds() returned {len(feeds)} feed(s)"`

---

### GCP-NR1-005 — VPC Service Controls Perimeter vorhanden

Klassen-Docstring (wörtlich): "Prüft ob VPC Service Controls Perimeter konfiguriert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckVpcServiceControls` |
| description | "Prüft ob VPC Service Controls konfiguriert sind, um den Zugriff auf GCP-Dienste einzuschränken und Datenexfiltration zu verhindern." |
| severity | MEDIUM |
| iso_27001_ref | "A.8.22 Netzwerksegmentierung" (inline) |
| required_permissions | `["accesscontextmanager.accessPolicies.list"]` |
| pruefgrenzen | "Prüft nur die Existenz von VPC-Service-Controls-Perimetern. Ohne Organisations-Berechtigung ist die Prüfung nicht möglich; die Perimeter-Konfiguration selbst wird nicht inhaltlich bewertet." |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine VPC Service Controls Perimeter"
- description (Template): `f"Projekt {project_id} hat keine VPC Service Controls Perimeter. Ohne VPC SC können Daten ungehindert aus GCP-Diensten exfiltriert werden."`
- expected_state: "Mindestens ein VPC Service Controls Perimeter konfiguriert"
- remediation: "Erstellen Sie einen VPC Service Controls Perimeter: gcloud access-context-manager perimeters create <NAME> --title='Produktionsperimeter' --resources=projects/<PROJECT_NUMBER> --restricted-services='storage.googleapis.com' --policy=<POLICY_ID>"

**Positivnachweis (compliant_finding):**
- title: "VPC Service Controls Perimeter vorhanden"
- description: "Es ist mindestens ein VPC Service Controls Perimeter konfiguriert — Datenexfiltration aus GCP-Diensten wird eingeschränkt."
- expected_state: "Mindestens ein VPC Service Controls Perimeter konfiguriert"
- audit_evidence: "accessPolicies.servicePerimeters.list() returned >=1 perimeter"

---

## Mechanische Auffälligkeiten (ohne Bewertung)

1. Keine der 15 Check-Klassen definiert ein Klassenattribut `severity` (abweichend vom Muster im Repo-`CLAUDE.md`) — severity wird stattdessen pro `Finding()`-Aufruf als Parameter gesetzt (innerhalb desselben Checks jeweils konsistent).
2. Keine der 15 Check-Klassen definiert ein Klassenattribut `iso_27001_ref` — `iso27001_control` wird stattdessen pro `Finding()`/`compliant_finding()`-Aufruf als Parameter übergeben (innerhalb desselben Checks jeweils konsistent).
3. Nur das AWS-Modul definiert eine Modul-Konstante `ISO_CONTROL` ("A.8.15 Logging"); sie wird ausschließlich von `CheckCloudTrail` (AWS-NR1-004) verwendet. Alle anderen 14 Checks übergeben `iso27001_control` als Inline-String-Literal.
4. Die Azure- und GCP-Module definieren kein Äquivalent zur AWS-Modul-Konstante `ISO_CONTROL`.
5. Klassendocstrings sind sprachlich uneinheitlich: Alle fünf AWS- und alle fünf Azure-Klassendocstrings sind auf Englisch; alle fünf GCP-Klassendocstrings sind auf Deutsch.
6. AWS-NR1-003 (`CheckOrganizationsScp`) und AZ-NR1-003 (`CheckManagementGroups`) vermerken jeweils im eigenen `pruefgrenzen`-Feld, dass Konstellationen ohne Organizations bzw. Management Groups einen Mangel erhalten, obwohl das jeweilige Feature dort laut Feldtext ggf. nicht anwendbar bzw. wenig nützlich ist.
7. GCP-NR1-005 (`CheckVpcServiceControls`) iteriert — anders als die übrigen vier GCP-Nr.-1-Checks — nicht über `session.project_ids`, sondern führt einen einzigen Try-Block aus und verwendet `session.project_id` (Singular) für `resource_id`/`account_id`.
8. Die Klassenreihenfolge in der AWS-Datei entspricht nicht der aufsteigenden Check-ID-Reihenfolge (Datei-Reihenfolge: NR1-004, NR1-001, NR1-002, NR1-003, NR1-005).
9. AWS-NR1-002 (`CheckSecurityHub`) erkennt "nicht aktiviert" über einen spezifischen Exception-Typ (`sh_client.exceptions.InvalidAccessException`); alle anderen 14 Checks werten stattdessen leere Listen/Dictionaries aus der API-Antwort aus.
10. `CheckError()`-Aufrufe unterscheiden sich zwischen Providern: AWS und GCP übergeben nur `message` und `error_type`; Azure übergibt zusätzlich `check_id` und `region="global"`.
11. AZ-NR1-005 (`CheckSentinelWorkspace`) erkennt Sentinel-Aktivität als Proxy über `ws.provisioning_state == "Succeeded"` eines Log-Analytics-Workspace; der Code-Kommentar dazu lautet wörtlich: "Sentinel workspaces typically have SecurityInsights solution / We check if there are any Log Analytics workspaces as a proxy".
12. GCP-NR1-005 (`CheckVpcServiceControls`) loggt im except-Zweig zusätzlich eine strukturierte Warnung (`logger.warning`) mit Hinweis "VPC SC requires organization-level access" — als einziger Check im Nr.-1-Batch.
