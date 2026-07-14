# W4 Batch-Review-Dossier — §30 Abs. 2 Nr. 2 BSIG (Bewältigung von Sicherheitsvorfällen)

> Mechanisch extrahiert am 2026-07-12 (Worker, ohne rechtliche Bewertung).
> Prüfgegenstand für: Gründer + Agent legal-reviewer (ADR-0018).

Quelldateien:
- `nis2scan/engine/providers/aws/checks/nr2_vorfallsbewaltigung.py`
- `nis2scan/engine/providers/azure/checks/nr2_vorfallsbewaltigung.py`
- `nis2scan/engine/providers/gcp/checks/nr2_vorfallsbewaltigung.py`

Ist-Zahl erfasster Checks: **15** (AWS: 5, Azure: 5, GCP: 5) — entspricht der erwarteten Zahl.

## Modul-Konstanten je Provider

### AWS (`nr2_vorfallsbewaltigung.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 2 — Bewältigung von Sicherheitsvorfällen checks for AWS.

  Checks GuardDuty enablement and CloudWatch alarm configuration.
  ```
- `BSIG_30_NR = 2`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 2 BSIG — Bewältigung von Sicherheitsvorfällen"
- `ISO_CONTROL` (wörtlich): "A.5.24-A.5.28 Incident management"

### Azure (`nr2_vorfallsbewaltigung.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 2 — Bewältigung von Sicherheitsvorfällen checks for Azure.

  Checks Defender alerting, Sentinel analytics, playbooks, action groups, and alert processing.
  ```
- `BSIG_30_NR = 2`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 2 BSIG — Bewältigung von Sicherheitsvorfällen"
- Kein Modul-Äquivalent zu `ISO_CONTROL`.

### GCP (`nr2_vorfallsbewaltigung.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 2 — Bewältigung von Sicherheitsvorfällen checks for GCP.

  Checks SCC Notification Configs, Monitoring Alert Policies, Notification Channels,
  Log-Based Metrics, and Logging Sinks.
  ```
- `BSIG_30_NR = 2`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 2 BSIG — Bewältigung von Sicherheitsvorfällen"
- Kein Modul-Äquivalent zu `ISO_CONTROL`.

---

## Checks

### AWS-NR2-001 — GuardDuty Aktivierung

Klassen-Docstring (wörtlich): "Check that Amazon GuardDuty is enabled in the account region."

| Feld | Wert |
|---|---|
| Klasse | `CheckGuardDutyEnabled` |
| description | "Prüft ob Amazon GuardDuty in der Region aktiviert ist, um Bedrohungserkennung für AWS-Ressourcen zu gewährleisten." |
| severity | CRITICAL (bei beiden Mangel-Pfaden dieses Checks) |
| iso_27001_ref | `ISO_CONTROL` = "A.5.24-A.5.28 Incident management" (Modul-Konstante, kein Klassenattribut) |
| required_permissions | `["guardduty:ListDetectors", "guardduty:GetDetector"]` |
| pruefgrenzen | "Prüft nur den Detector-Status je Region. Nicht geprüft werden aktivierte Schutzmodule und ob GuardDuty-Befunde in einen Incident-Prozess münden." |
| Prüflogik (deskriptiv) | Ruft je Region `guardduty.list_detectors()` auf; ist die Liste leer, entsteht ein Mangel-Finding ("GuardDuty nicht aktiviert"); für jede zurückgegebene Detector-ID wird `get_detector()` aufgerufen — bei `Status == "ENABLED"` entsteht ein Positivnachweis, bei jedem anderen Status ein Mangel-Finding ("GuardDuty Detector deaktiviert"). |

**Finding-Texte (Mangel-Pfad):**

1. Kein Detector vorhanden (pro Region):
   - title: "GuardDuty nicht aktiviert"
   - description (Template): `f"Amazon GuardDuty ist in der Region {region} nicht aktiviert. Ohne GuardDuty fehlt die automatische Bedrohungserkennung für AWS-Ressourcen."`
   - expected_state: "GuardDuty Detector aktiviert mit allen Schutzmodulen"
   - remediation: "Aktivieren Sie Amazon GuardDuty: aws guardduty create-detector --enable --finding-publishing-frequency FIFTEEN_MINUTES"
   - audit_evidence (Template): `f"ListDetectors returned 0 detectors in {region}"`

2. Detector vorhanden, aber Status ≠ ENABLED:
   - title: "GuardDuty Detector deaktiviert"
   - description (Template): `f"Der GuardDuty Detector in Region {region} hat den Status '{status}' statt 'ENABLED'."`
   - expected_state: "GuardDuty Detector Status=ENABLED"
   - remediation: "Aktivieren Sie den GuardDuty Detector: aws guardduty update-detector --detector-id <id> --enable"
   - audit_evidence (Template): `f"GetDetector: Status={status}"`

**Positivnachweis (compliant_finding):**
- title: "GuardDuty aktiviert"
- description (Template): `f"Amazon GuardDuty ist in der Region {region} aktiviert und liefert Bedrohungserkennung für die Vorfallsbewältigung."`
- expected_state: "GuardDuty Detector Status=ENABLED"
- audit_evidence (Template): `f"GetDetector: Status=ENABLED in {region}"`

---

### AWS-NR2-002 — Security Hub Findings Aggregation

Klassen-Docstring (wörtlich): "Check that AWS Security Hub is enabled and aggregating findings."

| Feld | Wert |
|---|---|
| Klasse | `CheckSecurityHubFindings` |
| description | "Prüft ob AWS Security Hub aktiviert ist und Sicherheitsbefunde zentral aggregiert." |
| severity | MEDIUM |
| iso_27001_ref | "A.5.25" (inline, kein Klassenattribut, weicht von der Modul-Konstante `ISO_CONTROL` ab) |
| required_permissions | `["securityhub:GetFindings"]` |
| pruefgrenzen | "Prüft nur, ob Security Hub erreichbar ist und Befunde liefert. Nicht geprüft werden Multi-Account-Aggregation und ob Befunde triagiert und behoben werden." |
| Prüflogik (deskriptiv) | Ruft je Region `securityhub.get_findings(MaxResults=1)` auf; gelingt der Aufruf, entsteht ein Positivnachweis; wird die Exception `InvalidAccessException` geworfen, entsteht ein Mangel-Finding; jede andere Exception wird als `CheckError` erfasst (kein Finding). |

**Finding-Texte (Mangel-Pfad):**
- title: "Security Hub nicht aktiviert"
- description (Template): `f"AWS Security Hub ist in der Region {region} nicht aktiviert. Ohne Security Hub fehlt die zentrale Aggregation von Sicherheitsbefunden."`
- expected_state: "Security Hub aktiviert mit zentraler Befundaggregation"
- remediation: "Aktivieren Sie AWS Security Hub: aws securityhub enable-security-hub"
- audit_evidence (Template): `f"GetFindings raised InvalidAccessException in {region}"`
- (ausgelöst im except-Zweig für `sh_client.exceptions.InvalidAccessException`)

**Positivnachweis (compliant_finding):**
- title: "Security Hub aggregiert Befunde"
- description (Template): `f"AWS Security Hub ist in der Region {region} aktiviert und aggregiert Sicherheitsbefunde zentral."`
- expected_state: "Security Hub aktiviert mit zentraler Befundaggregation"
- audit_evidence (Template): `f"GetFindings succeeded in {region}"`

---

### AWS-NR2-003 — Incident Manager Response Plans

Klassen-Docstring (wörtlich): "Check that Incident Manager Response Plans are configured."

| Feld | Wert |
|---|---|
| Klasse | `CheckIncidentManagerResponsePlans` |
| description | "Prüft ob AWS Systems Manager Incident Manager mit Response Plans konfiguriert ist." |
| severity | MEDIUM |
| iso_27001_ref | "A.5.26" (inline, kein Klassenattribut, weicht von der Modul-Konstante `ISO_CONTROL` ab) |
| required_permissions | `["ssm-incidents:ListResponsePlans"]` |
| pruefgrenzen | "Prüft nur die Existenz von Response Plans im AWS Incident Manager. Ein außerhalb von AWS geführter Incident-Response-Plan wird nicht erkannt — dieser ist über die Attestierungs-Checkliste nachzuweisen." |
| Prüflogik (deskriptiv) | Ruft je Region `ssm-incidents.list_response_plans()` auf; ist `responsePlanSummaries` leer, entsteht ein Mangel-Finding, sonst ein Positivnachweis mit der Anzahl gefundener Pläne. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Incident Manager Response Plans"
- description (Template): `f"In der Region {region} sind keine Incident Manager Response Plans konfiguriert. Ohne Response Plans fehlt ein strukturierter Prozess zur Vorfallsbewältigung."`
- expected_state: "Mindestens ein Incident Manager Response Plan konfiguriert"
- remediation: "Erstellen Sie einen Incident Manager Response Plan: aws ssm-incidents create-response-plan --name <plan-name>"
- audit_evidence (Template): `f"ListResponsePlans returned 0 plans in {region}"`

**Positivnachweis (compliant_finding):**
- title: "Incident Manager Response Plans konfiguriert"
- description (Template): `f"In der Region {region} sind {len(plans)} Incident Manager Response Plans konfiguriert — ein strukturierter Prozess zur Vorfallsbewältigung ist hinterlegt."`
- expected_state: "Mindestens ein Incident Manager Response Plan konfiguriert"
- audit_evidence (Template): `f"ListResponsePlans returned {len(plans)} plan(s) in {region}"`

---

### AWS-NR2-004 — CloudWatch Alarms Konfiguration

Klassen-Docstring (wörtlich): "Check that CloudWatch Alarms are configured for monitoring."

| Feld | Wert |
|---|---|
| Klasse | `CheckCloudWatchAlarms` |
| description | "Prüft ob CloudWatch Alarms konfiguriert sind, um auf Sicherheitsvorfälle und Anomalien reagieren zu können." |
| severity | HIGH |
| iso_27001_ref | `ISO_CONTROL` = "A.5.24-A.5.28 Incident management" (Modul-Konstante, kein Klassenattribut) |
| required_permissions | `["cloudwatch:DescribeAlarms"]` |
| pruefgrenzen | "Prüft nur, ob überhaupt mindestens ein CloudWatch-Alarm existiert. Nicht geprüft werden Abdeckung sicherheitsrelevanter Metriken, Alarmziele (Benachrichtigungswege) und ob Alarme funktionieren." |
| Prüflogik (deskriptiv) | Ruft je Region `cloudwatch.describe_alarms(MaxRecords=1)` auf; ist `MetricAlarms` leer, wird zusätzlich `describe_alarms(AlarmTypes=["CompositeAlarm"], MaxRecords=1)` abgefragt; ist mindestens ein Metric- oder Composite-Alarm vorhanden, entsteht ein Positivnachweis, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine CloudWatch Alarms konfiguriert"
- description (Template): `f"In der Region {region} sind keine CloudWatch Alarms konfiguriert. Ohne Alarms fehlt die automatische Benachrichtigung bei Sicherheitsvorfällen."`
- expected_state: "Mindestens ein CloudWatch Alarm für Sicherheitsüberwachung"
- remediation: "Erstellen Sie CloudWatch Alarms für kritische Metriken wie unerlaubte API-Aufrufe, Root-Account-Nutzung und Billing-Anomalien."
- audit_evidence (Template): `f"DescribeAlarms returned 0 alarms in {region}"`

**Positivnachweis (compliant_finding):**
- title: "CloudWatch Alarms konfiguriert"
- description (Template): `f"In der Region {region} sind CloudWatch Alarms konfiguriert — automatische Benachrichtigung bei Vorfällen ist möglich."`
- expected_state: "Mindestens ein CloudWatch Alarm für Sicherheitsüberwachung"
- audit_evidence (Template): `f"DescribeAlarms returned >=1 alarm in {region}"`

---

### AWS-NR2-005 — Detective Aktivierung (Forensik)

Klassen-Docstring (wörtlich): "Check that Amazon Detective is enabled for forensic analysis.

Detective provides automated security investigation capabilities
to analyze, investigate, and identify root causes of security findings."

| Feld | Wert |
|---|---|
| Klasse | `CheckDetectiveEnabled` |
| description | "Prüft ob Amazon Detective für forensische Analysen aktiviert ist, um Sicherheitsvorfälle untersuchen und Ursachen identifizieren zu können." |
| severity | LOW |
| iso_27001_ref | "A.5.27 Learning from information security incidents" (inline, kein Klassenattribut, weicht von der Modul-Konstante `ISO_CONTROL` ab) |
| required_permissions | `["detective:ListGraphs"]` |
| pruefgrenzen | "Prüft nur, ob ein Detective-Verhaltensgraph existiert. Nicht geprüft wird, ob Detective bei Vorfällen tatsächlich zur Ursachenanalyse genutzt wird. Detective ist eine von mehreren möglichen Forensik-Lösungen — der Einsatz eines anderen Werkzeugs wird nicht erkannt." |
| Prüflogik (deskriptiv) | Ruft je Region `detective.list_graphs()` auf; ist `GraphList` nicht leer, entsteht ein Positivnachweis mit der Graphenanzahl, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Detective nicht aktiviert"
- description (Template): `f"Amazon Detective ist in der Region {region} nicht aktiviert. Ohne Detective fehlt die automatisierte forensische Analysefähigkeit zur Untersuchung von Sicherheitsvorfällen."`
- expected_state: "Amazon Detective aktiviert mit mindestens einem Behavior Graph"
- remediation: "Aktivieren Sie Amazon Detective: aws detective create-graph. Detective benötigt GuardDuty als Datenquelle."
- audit_evidence (Template): `f"ListGraphs returned 0 graphs in {region}"`

**Positivnachweis (compliant_finding):**
- title: "Detective aktiviert"
- description (Template): `f"Amazon Detective ist in der Region {region} aktiviert — forensische Analyse von Sicherheitsvorfällen ist möglich."`
- expected_state: "Amazon Detective aktiviert mit mindestens einem Behavior Graph"
- audit_evidence (Template): `f"ListGraphs returned {len(graphs)} graph(s) in {region}"`

---

### AZ-NR2-001 — Defender Alert-Benachrichtigungen konfiguriert

Klassen-Docstring (wörtlich): "Check that Defender alert notifications are configured."

| Feld | Wert |
|---|---|
| Klasse | `CheckDefenderAlertNotifications` |
| description | "Prüft ob Microsoft Defender for Cloud Alert-Benachrichtigungen konfiguriert sind." |
| severity | HIGH |
| iso_27001_ref | "A.5.24 Incident Management" (inline) |
| required_permissions | `["Microsoft.Security/securityContacts/read"]` |
| pruefgrenzen | "Prüft nur, ob Defender-Sicherheitskontakte mit Benachrichtigung konfiguriert sind. Ob Alarme gelesen und bearbeitet werden, ist nicht prüfbar." |
| Prüflogik (deskriptiv) | Ruft je Subscription `SecurityCenter.security_contacts.list()` auf und prüft, ob mindestens ein Kontakt `alert_notifications.state == "On"` hat; trifft das zu, entsteht ein Positivnachweis, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Defender Alert-Benachrichtigungen nicht konfiguriert"
- description (Template): `f"Subscription {sub_id} hat keine aktiven Defender Alert-Benachrichtigungen. Ohne Benachrichtigungen werden Sicherheitsvorfälle nicht zeitnah erkannt."`
- expected_state: "Mindestens ein Security Contact mit Alert-Benachrichtigungen"
- remediation: "Konfigurieren Sie Defender Alert-Benachrichtigungen: az security contact create --name default --email security@company.com --alert-notifications on --alerts-admins on"
- audit_evidence (Template): `f"security_contacts.list() returned {len(contacts)} contacts"`

**Positivnachweis (compliant_finding):**
- title: "Defender Alert-Benachrichtigungen aktiv"
- description (Template): `f"Subscription {sub_id} hat {len(contacts)} Security Contact(s) mit aktiven Alert-Benachrichtigungen."`
- expected_state: "Mindestens ein Security Contact mit Alert-Benachrichtigungen"
- audit_evidence (Template): `f"security_contacts.list() returned {len(contacts)} contact(s), alert_notifications=On"`

---

### AZ-NR2-002 — Sentinel Analytics Rules aktiv

Klassen-Docstring (wörtlich): "Check that Sentinel analytics rules are active for threat detection."

| Feld | Wert |
|---|---|
| Klasse | `CheckSentinelAnalyticsRules` |
| description | "Prüft ob Microsoft Sentinel Analytics Rules für regelbasierte Erkennung aktiv sind." |
| severity | HIGH |
| iso_27001_ref | "A.5.24, A.8.16 Incident Detection" (inline) |
| required_permissions | `["Microsoft.OperationalInsights/workspaces/read", "Microsoft.SecurityInsights/alertRules/read"]` |
| pruefgrenzen | "Prüft nur, ob aktive Sentinel-Analytics-Regeln existieren. Abdeckung und Qualität der Erkennungsregeln werden nicht bewertet." |
| Prüflogik (deskriptiv) | Ruft je Subscription `LogAnalyticsManagementClient.workspaces.list()` auf; existiert mindestens ein Log-Analytics-Workspace, entsteht ein Positivnachweis, sonst ein Mangel-Finding. Ein Aufruf gegen eine Sentinel- bzw. AlertRules-spezifische API erfolgt im Code nicht. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Sentinel Analytics Rules"
- description (Template): `f"Subscription {sub_id} hat keinen Log Analytics Workspace. Ohne Workspace können keine Sentinel Analytics Rules für Bedrohungserkennung konfiguriert werden."`
- expected_state: "Mindestens ein Workspace mit aktiven Analytics Rules"
- remediation: "Erstellen Sie einen Sentinel Workspace und aktivieren Sie Analytics Rules: az sentinel alert-rule list --workspace-name <ws> --resource-group <rg>"
- audit_evidence: "No Log Analytics workspaces found" (kein Template — Literal)

**Positivnachweis (compliant_finding):**
- title: "Log Analytics Workspace für Analytics Rules vorhanden"
- description (Template): `f"Subscription {sub_id} hat {len(workspaces)} Log Analytics Workspace(s) als Grundlage für Sentinel Analytics Rules."`
- expected_state: "Mindestens ein Workspace mit aktiven Analytics Rules"
- audit_evidence (Template): `f"workspaces.list() returned {len(workspaces)} workspace(s)"`
- resource_type (beide Pfade): "Microsoft.SecurityInsights/alertRules"

---

### AZ-NR2-003 — Sentinel Playbooks / Logic Apps

Klassen-Docstring (wörtlich): "Check that Sentinel playbooks (Logic Apps) are configured for auto-response."

| Feld | Wert |
|---|---|
| Klasse | `CheckSentinelPlaybooks` |
| description | "Prüft ob Sentinel Playbooks (Logic Apps) für automatisierte Reaktion konfiguriert sind." |
| severity | MEDIUM |
| iso_27001_ref | "A.5.26 Response to Incidents" (inline) |
| required_permissions | `["Microsoft.Logic/workflows/read"]` |
| pruefgrenzen | "Prüft nur die Existenz von Logic-App-Playbooks. Ob sie an Vorfälle gekoppelt sind und funktionieren, wird nicht geprüft." |
| Prüflogik (deskriptiv) | Ruft je Subscription `ResourceManagementClient.resources.list(filter="resourceType eq 'Microsoft.Logic/workflows'")` auf und filtert die zurückgegebenen Logic Apps clientseitig auf Namen, die eines der Schlüsselwörter "sentinel", "security", "incident", "alert", "playbook" enthalten; ist die gefilterte Liste nicht leer, entsteht ein Positivnachweis, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Sentinel Playbooks konfiguriert"
- description (Template): `f"Subscription {sub_id} hat keine sicherheitsbezogenen Logic Apps / Playbooks. Ohne automatisierte Reaktion müssen Vorfälle manuell bearbeitet werden."`
- expected_state: "Mindestens ein Sentinel Playbook für automatisierte Reaktion"
- remediation: "Erstellen Sie Sentinel Playbooks für automatisierte Incident-Response: Azure Portal → Sentinel → Automation → Create Playbook"
- audit_evidence (Template): `f"resources.list() returned {len(logic_apps)} Logic Apps, 0 security-related"`

**Positivnachweis (compliant_finding):**
- title: "Sentinel Playbooks konfiguriert"
- description (Template): `f"Subscription {sub_id} hat {len(sentinel_playbooks)} sicherheitsbezogene Logic Apps / Playbooks für automatisierte Reaktion."`
- expected_state: "Mindestens ein Sentinel Playbook für automatisierte Reaktion"
- audit_evidence (Template): `f"resources.list() returned {len(logic_apps)} Logic Apps, {len(sentinel_playbooks)} security-related"`

---

### AZ-NR2-004 — Action Groups für Alerting

Klassen-Docstring (wörtlich): "Check that Azure Monitor Action Groups are configured for alerting."

| Feld | Wert |
|---|---|
| Klasse | `CheckActionGroups` |
| description | "Prüft ob Azure Monitor Action Groups für Alerting-Eskalation konfiguriert sind." |
| severity | HIGH |
| iso_27001_ref | "A.5.24 Incident Management" (inline) |
| required_permissions | `["Microsoft.Insights/actionGroups/read"]` |
| pruefgrenzen | "Prüft nur die Existenz von Action Groups. Erreichbarkeit der hinterlegten Kontakte und tatsächliche Alarm-Zustellung werden nicht geprüft." |
| Prüflogik (deskriptiv) | Ruft je Subscription `MonitorManagementClient.action_groups.list_by_subscription_id()` auf; ist die Liste nicht leer, entsteht ein Positivnachweis, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Action Groups konfiguriert"
- description (Template): `f"Subscription {sub_id} hat keine Azure Monitor Action Groups. Ohne Action Groups können Alerts nicht an Verantwortliche weitergeleitet werden."`
- expected_state: "Mindestens eine Action Group mit E-Mail/SMS-Empfänger"
- remediation: "Erstellen Sie eine Action Group: az monitor action-group create --name 'SecurityTeam' --resource-group <rg> --short-name 'SecTeam' --action email security security@company.com"
- audit_evidence: "action_groups.list_by_subscription_id() returned 0 groups" (kein Template — Literal)

**Positivnachweis (compliant_finding):**
- title: "Action Groups konfiguriert"
- description (Template): `f"Subscription {sub_id} hat {len(action_groups)} Azure Monitor Action Group(s) für Alerting-Eskalation."`
- expected_state: "Mindestens eine Action Group mit E-Mail/SMS-Empfänger"
- audit_evidence (Template): `f"action_groups.list_by_subscription_id() returned {len(action_groups)} group(s)"`

---

### AZ-NR2-005 — Alert Processing Rules definiert

Klassen-Docstring (wörtlich): "Check that Alert Processing Rules are defined for alert routing."

| Feld | Wert |
|---|---|
| Klasse | `CheckAlertProcessingRules` |
| description | "Prüft ob Alert Processing Rules für Priorisierung und Routing von Alerts definiert sind." |
| severity | MEDIUM |
| iso_27001_ref | "A.5.25 Assessment and Decision on Events" (inline) |
| required_permissions | `["Microsoft.AlertsManagement/actionRules/read"]` |
| pruefgrenzen | "Prüft nur die Existenz von Alert Processing Rules. Ob die Regeln Alarme sinnvoll routen (statt zu unterdrücken), wird nicht inhaltlich bewertet." |
| Prüflogik (deskriptiv) | Ruft je Subscription `ResourceManagementClient.resources.list(filter="resourceType eq 'Microsoft.AlertsManagement/actionRules'")` auf; ist die Liste nicht leer, entsteht ein Positivnachweis, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Alert Processing Rules"
- description (Template): `f"Subscription {sub_id} hat keine Alert Processing Rules. Ohne Routing-Regeln werden Alerts nicht priorisiert oder an die richtigen Teams weitergeleitet."`
- expected_state: "Mindestens eine Alert Processing Rule für Routing"
- remediation: "Erstellen Sie Alert Processing Rules: Azure Portal → Monitor → Alerts → Alert processing rules → Create"
- audit_evidence: "resources.list() returned 0 alert processing rules" (kein Template — Literal)

**Positivnachweis (compliant_finding):**
- title: "Alert Processing Rules definiert"
- description (Template): `f"Subscription {sub_id} hat {len(rules)} Alert Processing Rule(s) für Priorisierung und Routing."`
- expected_state: "Mindestens eine Alert Processing Rule für Routing"
- audit_evidence (Template): `f"resources.list() returned {len(rules)} alert processing rule(s)"`

---

### GCP-NR2-001 — SCC-Benachrichtigungen konfiguriert

Klassen-Docstring (wörtlich): "Prüft ob SCC-Benachrichtigungskonfigurationen vorhanden sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckSccNotifications` |
| description | "Prüft ob Security Command Center Benachrichtigungskonfigurationen für die automatische Alarmierung bei Sicherheitsvorfällen eingerichtet sind." |
| severity | HIGH |
| iso_27001_ref | "A.5.24 Planung der Informationssicherheitsvorfallsreaktion" (inline) |
| required_permissions | `["securitycenter.notificationconfig.list"]` |
| pruefgrenzen | "Prüft nur konfigurierte SCC-Benachrichtigungen. Zustellung und Bearbeitung der Meldungen werden nicht geprüft." |
| Prüflogik (deskriptiv) | Ruft je Projekt `SecurityCenterClient.list_notification_configs(parent=f"projects/{project_id}")` auf; ist die Liste nicht leer, entsteht ein Positivnachweis, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine SCC-Benachrichtigungen konfiguriert"
- description (Template): `f"Projekt {project_id} hat keine SCC-Benachrichtigungskonfigurationen. Ohne Benachrichtigungen werden Sicherheitsvorfälle nicht automatisch gemeldet."`
- expected_state: "Mindestens eine SCC-Benachrichtigungskonfiguration"
- remediation: `"Erstellen Sie eine SCC-Benachrichtigung: gcloud scc notifications create <NAME> --project=<PROJECT_ID> --pubsub-topic=projects/<PROJECT_ID>/topics/<TOPIC> --filter='state=\"ACTIVE\"'"`
- audit_evidence: "list_notification_configs() returned 0 configs" (kein Template — Literal)

**Positivnachweis (compliant_finding):**
- title: "SCC-Benachrichtigungen konfiguriert"
- description (Template): `f"Projekt {project_id} hat {len(configs)} SCC-Benachrichtigungskonfiguration(en) für automatische Alarmierung."`
- expected_state: "Mindestens eine SCC-Benachrichtigungskonfiguration"
- audit_evidence (Template): `f"list_notification_configs() returned {len(configs)} config(s)"`

---

### GCP-NR2-002 — Monitoring-Alarmrichtlinien vorhanden

Klassen-Docstring (wörtlich): "Prüft ob Cloud Monitoring Alarmrichtlinien konfiguriert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckMonitoringAlertPolicies` |
| description | "Prüft ob Google Cloud Monitoring Alarmrichtlinien für die Erkennung von Sicherheitsvorfällen konfiguriert sind." |
| severity | HIGH |
| iso_27001_ref | "A.5.24, A.8.16 Überwachung von Aktivitäten" (inline) |
| required_permissions | `["monitoring.alertPolicies.list"]` |
| pruefgrenzen | "Prüft nur die Existenz von Alarmrichtlinien. Abdeckung sicherheitsrelevanter Metriken wird nicht bewertet." |
| Prüflogik (deskriptiv) | Ruft je Projekt `AlertPolicyServiceClient.list_alert_policies(name=f"projects/{project_id}")` auf; ist die Liste nicht leer, entsteht ein Positivnachweis, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Monitoring-Alarmrichtlinien vorhanden"
- description (Template): `f"Projekt {project_id} hat keine Cloud Monitoring Alarmrichtlinien. Ohne Alarme werden Anomalien und Sicherheitsvorfälle nicht automatisch erkannt."`
- expected_state: "Mindestens eine Alarmrichtlinie für Sicherheitsvorfälle"
- remediation: "Erstellen Sie eine Alarmrichtlinie: gcloud alpha monitoring policies create --policy-from-file=alert-policy.json --project=<PROJECT_ID>"
- audit_evidence: "list_alert_policies() returned 0 policies" (kein Template — Literal)

**Positivnachweis (compliant_finding):**
- title: "Monitoring-Alarmrichtlinien vorhanden"
- description (Template): `f"Projekt {project_id} hat {len(policies)} Cloud Monitoring Alarmrichtlinie(n) für die Vorfallserkennung."`
- expected_state: "Mindestens eine Alarmrichtlinie für Sicherheitsvorfälle"
- audit_evidence (Template): `f"list_alert_policies() returned {len(policies)} policies"`

---

### GCP-NR2-003 — Benachrichtigungskanäle konfiguriert

Klassen-Docstring (wörtlich): "Prüft ob Benachrichtigungskanäle in Cloud Monitoring konfiguriert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckNotificationChannels` |
| description | "Prüft ob Benachrichtigungskanäle (E-Mail, PagerDuty, Slack etc.) in Cloud Monitoring eingerichtet sind." |
| severity | HIGH |
| iso_27001_ref | "A.5.24 Planung der Informationssicherheitsvorfallsreaktion" (inline) |
| required_permissions | `["monitoring.notificationChannels.list"]` |
| pruefgrenzen | "Prüft nur die Existenz von Benachrichtigungskanälen. Erreichbarkeit der hinterlegten Kontakte wird nicht verifiziert." |
| Prüflogik (deskriptiv) | Ruft je Projekt `NotificationChannelServiceClient.list_notification_channels(name=f"projects/{project_id}")` auf; ist die Liste nicht leer, entsteht ein Positivnachweis, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Benachrichtigungskanäle konfiguriert"
- description (Template): `f"Projekt {project_id} hat keine Benachrichtigungskanäle in Cloud Monitoring. Ohne Kanäle können Alarme nicht zugestellt werden."`
- expected_state: "Mindestens ein Benachrichtigungskanal konfiguriert"
- remediation: "Erstellen Sie einen Benachrichtigungskanal: gcloud alpha monitoring channels create --type=email --display-name='Security Team' --channel-labels=email_address=security@example.com --project=<PROJECT_ID>"
- audit_evidence: "list_notification_channels() returned 0 channels" (kein Template — Literal)

**Positivnachweis (compliant_finding):**
- title: "Benachrichtigungskanäle konfiguriert"
- description (Template): `f"Projekt {project_id} hat {len(channels)} Benachrichtigungskanal/-kanäle in Cloud Monitoring für die Alarmzustellung."`
- expected_state: "Mindestens ein Benachrichtigungskanal konfiguriert"
- audit_evidence (Template): `f"list_notification_channels() returned {len(channels)} channel(s)"`

---

### GCP-NR2-004 — Logbasierte Metriken vorhanden

Klassen-Docstring (wörtlich): "Prüft ob logbasierte Metriken für Sicherheitsereignisse existieren."

| Feld | Wert |
|---|---|
| Klasse | `CheckLogBasedAlerts` |
| description | "Prüft ob logbasierte Metriken in Cloud Logging für die Erkennung sicherheitsrelevanter Ereignisse konfiguriert sind." |
| severity | MEDIUM |
| iso_27001_ref | "A.5.24, A.8.16 Überwachung von Aktivitäten" (inline) |
| required_permissions | `["logging.logMetrics.list"]` |
| pruefgrenzen | "Prüft nur die Existenz logbasierter Metriken. Ob sicherheitsrelevante Ereignisse abgedeckt sind, wird nicht inhaltlich bewertet." |
| Prüflogik (deskriptiv) | Ruft je Projekt `MetricsServiceV2Client.list_log_metrics(parent=f"projects/{project_id}")` auf; ist die Liste nicht leer, entsteht ein Positivnachweis, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine logbasierten Metriken vorhanden"
- description (Template): `f"Projekt {project_id} hat keine logbasierten Metriken. Ohne Metriken werden sicherheitsrelevante Log-Einträge nicht automatisch in Alarme umgewandelt."`
- expected_state: "Logbasierte Metriken für sicherheitsrelevante Ereignisse (z.B. IAM-Änderungen, Firewall-Änderungen)"
- remediation: `"Erstellen Sie logbasierte Metriken: gcloud logging metrics create iam-policy-changes --description='IAM Policy Änderungen' --log-filter='protoPayload.methodName=\"SetIamPolicy\"' --project=<PROJECT_ID>"`
- audit_evidence: "list_log_metrics() returned 0 metrics" (kein Template — Literal)

**Positivnachweis (compliant_finding):**
- title: "Logbasierte Metriken vorhanden"
- description (Template): `f"Projekt {project_id} hat {len(metrics)} logbasierte Metrik(en) für die Erkennung sicherheitsrelevanter Ereignisse."`
- expected_state: "Logbasierte Metriken für sicherheitsrelevante Ereignisse (z.B. IAM-Änderungen, Firewall-Änderungen)" (identisch zum Mangel-Pfad)
- audit_evidence (Template): `f"list_log_metrics() returned {len(metrics)} metric(s)"`

---

### GCP-NR2-005 — Log-Sinks für SIEM-Export vorhanden

Klassen-Docstring (wörtlich): "Prüft ob Log-Sinks für den SIEM-Export konfiguriert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckLoggingSinks` |
| description | "Prüft ob Cloud Logging Sinks für den Export von Logs an ein SIEM-System oder langfristige Speicherung konfiguriert sind." |
| severity | MEDIUM |
| iso_27001_ref | "A.5.25 Bewertung und Entscheidung zu Informationssicherheitsereignissen" (inline) |
| required_permissions | `["logging.sinks.list"]` |
| pruefgrenzen | "Prüft nur die Existenz von Log-Sinks. Ob das Ziel ein SIEM ist und die Auswertung stattfindet, wird nicht geprüft." |
| Prüflogik (deskriptiv) | Ruft je Projekt `ConfigServiceV2Client.list_sinks(parent=f"projects/{project_id}")` auf; ist die Liste nicht leer, entsteht ein Positivnachweis, sonst ein Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Log-Sinks konfiguriert"
- description (Template): `f"Projekt {project_id} hat keine Log-Sinks. Ohne Sinks werden Logs nicht an ein SIEM-System oder langfristigen Speicher exportiert."`
- expected_state: "Mindestens ein Log-Sink für den Export an SIEM oder Cloud Storage"
- remediation: "Erstellen Sie einen Log-Sink: gcloud logging sinks create siem-export storage.googleapis.com/<BUCKET_NAME> --project=<PROJECT_ID> --log-filter='severity>=WARNING'"
- audit_evidence: "list_sinks() returned 0 sinks" (kein Template — Literal)

**Positivnachweis (compliant_finding):**
- title: "Log-Sinks konfiguriert"
- description (Template): `f"Projekt {project_id} hat {len(sinks)} Log-Sink(s) für den Export an SIEM oder langfristige Speicherung."`
- expected_state: "Mindestens ein Log-Sink für den Export an SIEM oder Cloud Storage"
- audit_evidence (Template): `f"list_sinks() returned {len(sinks)} sink(s)"`

---

## Mechanische Auffälligkeiten (ohne Bewertung)

1. Keine der 15 Check-Klassen definiert ein Klassenattribut `severity` — severity wird stattdessen pro `Finding()`-Aufruf als Parameter gesetzt (innerhalb desselben Checks jeweils konsistent).
2. Keine der 15 Check-Klassen definiert ein Klassenattribut `iso_27001_ref` — `iso27001_control` wird stattdessen pro `Finding()`/`compliant_finding()`-Aufruf als Parameter übergeben.
3. Nur das AWS-Modul definiert eine Modul-Konstante `ISO_CONTROL` ("A.5.24-A.5.28 Incident management"); sie wird von 2 der 5 AWS-Checks verwendet (AWS-NR2-001 GuardDuty, AWS-NR2-004 CloudWatchAlarms). Die übrigen 3 AWS-Checks (AWS-NR2-002, AWS-NR2-003, AWS-NR2-005) übergeben stattdessen jeweils eigene, spezifischere Inline-Strings ("A.5.25", "A.5.26", "A.5.27 Learning from information security incidents").
4. Die Azure- und GCP-Module definieren kein Äquivalent zur AWS-Modul-Konstante `ISO_CONTROL`; jeder Check übergibt `iso27001_control` als eigenes Inline-String-Literal.
5. Der AWS-Modul-Docstring nennt wörtlich nur "GuardDuty enablement and CloudWatch alarm configuration"; das Modul enthält daneben die Checks `CheckSecurityHubFindings` (AWS-NR2-002), `CheckIncidentManagerResponsePlans` (AWS-NR2-003) und `CheckDetectiveEnabled` (AWS-NR2-005), die im Docstring nicht erwähnt werden. Die Azure- und GCP-Modul-Docstrings nennen dagegen jeweils alle fünf Checks ihres Moduls.
6. Klassendocstrings sind sprachlich uneinheitlich: alle fünf AWS- und alle fünf Azure-Klassendocstrings sind auf Englisch verfasst; alle fünf GCP-Klassendocstrings sind auf Deutsch verfasst.
7. Die Klassenreihenfolge in der AWS-Datei entspricht nicht der aufsteigenden Check-ID-Reihenfolge (Datei-Reihenfolge: AWS-NR2-001 GuardDuty, AWS-NR2-004 CloudWatchAlarms, AWS-NR2-002 SecurityHub, AWS-NR2-005 Detective, AWS-NR2-003 IncidentManager).
8. AWS-NR2-002 (`CheckSecurityHubFindings`) erkennt "nicht aktiviert" ausschließlich über den spezifischen Exception-Typ `sh_client.exceptions.InvalidAccessException`; alle anderen 14 Checks des Batches werten stattdessen leere Listen aus der API-Antwort aus, um zwischen Mangel- und Positivpfad zu unterscheiden.
9. `CheckError()`-Aufrufe unterscheiden sich zwischen Providern: AWS und GCP übergeben nur `message` und `error_type`; Azure übergibt zusätzlich `check_id` und `region="global"`.
10. AZ-NR2-002 (`CheckSentinelAnalyticsRules`): Titel ("Sentinel Analytics Rules aktiv"), `description` und das eigene `pruefgrenzen`-Feld ("Prüft nur, ob aktive Sentinel-Analytics-Regeln existieren.") beziehen sich wörtlich auf Sentinel Analytics Rules; die Prüflogik ruft jedoch ausschließlich `LogAnalyticsManagementClient.workspaces.list()` auf und wertet die Existenz irgendeines Log-Analytics-Workspace aus. Ein Aufruf gegen eine Sentinel- bzw. AlertRules-spezifische API ist im Code nicht vorhanden, obwohl `required_permissions` den Eintrag `Microsoft.SecurityInsights/alertRules/read` enthält.
11. AZ-NR2-002: `resource_type` ist in Positiv- und Mangel-Finding jeweils `"Microsoft.SecurityInsights/alertRules"`, obwohl die tatsächlich abgefragte und gezählte Ressource ein Log-Analytics-Workspace (`Microsoft.OperationalInsights/workspaces`) ist.
12. AZ-NR2-003 (`CheckSentinelPlaybooks`) identifiziert "sicherheitsbezogene" Logic Apps über einen clientseitigen Schlüsselwortabgleich im Ressourcennamen (`sentinel`, `security`, `incident`, `alert`, `playbook`, Kleinschreibung) unter allen Logic Apps der Subscription. Eine inhaltliche Prüfung, ob die Logic App tatsächlich als Sentinel-Automatisierungsregel/-Playbook registriert oder mit einem Incident verknüpft ist, findet im Code nicht statt.
13. AZ-NR2-003 und AZ-NR2-005 fragen ihre jeweilige Ressourcenart nicht über einen dedizierten SDK-Client ab, sondern über die generische Ressourcenliste `ResourceManagementClient.resources.list(filter="resourceType eq '...'")`.
14. AWS-NR2-005 (`CheckDetectiveEnabled`) vermerkt im eigenen `pruefgrenzen`-Feld, dass Detective "eine von mehreren möglichen Forensik-Lösungen" ist und der Einsatz eines anderen Werkzeugs nicht erkannt wird; dieser Check hat mit LOW die niedrigste Severity aller 15 Checks im Batch.
15. AWS-NR2-003 (`CheckIncidentManagerResponsePlans`) vermerkt im eigenen `pruefgrenzen`-Feld, dass ein außerhalb von AWS geführter Incident-Response-Plan nicht erkannt wird und "über die Attestierungs-Checkliste nachzuweisen" ist.
16. GCP-NR2-004 (`CheckLogBasedAlerts`) verwendet für `expected_state` denselben Textbaustein ("Logbasierte Metriken für sicherheitsrelevante Ereignisse (z.B. IAM-Änderungen, Firewall-Änderungen)") sowohl im Mangel- als auch im Positivpfad, obwohl die konkret gefundenen Metriken inhaltlich nicht auf IAM-/Firewall-Bezug geprüft werden (vgl. eigenes `pruefgrenzen`-Feld).
