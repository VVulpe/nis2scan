# W4 Batch-Review-Dossier — §30 Abs. 2 Nr. 6 BSIG (Bewertung der Wirksamkeit)

> Mechanisch extrahiert am 2026-07-13 (Worker, ohne rechtliche Bewertung).
> Prüfgegenstand für: Gründer + Agent legal-reviewer (ADR-0018).

Quelldateien:
- `nis2scan/engine/providers/aws/checks/nr6_wirksamkeit.py`
- `nis2scan/engine/providers/azure/checks/nr6_wirksamkeit.py`
- `nis2scan/engine/providers/gcp/checks/nr6_wirksamkeit.py`

Ist-Zahl erfasster Checks: **12** (AWS: 4, Azure: 4, GCP: 4) — entspricht der erwarteten Zahl.

## Modul-Konstanten je Provider

### AWS (`nr6_wirksamkeit.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 6 — Wirksamkeit von Risikomanagementmaßnahmen checks for AWS.

  Checks CloudTrail operational effectiveness by verifying recent log delivery.
  ```
- `BSIG_30_NR = 6`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 6 BSIG — Konzepte und Verfahren zur Bewertung der Wirksamkeit von Risikomanagementmaßnahmen im Bereich der Sicherheit in der Informationstechnik"
- `ISO_CONTROL` (wörtlich): "A.5.36 Compliance with policies, rules and standards" (englisch) — nur von `CheckCloudTrailLogIntegrity` (AWS-NR6-001) verwendet; die übrigen drei AWS-Checks verwenden stattdessen inline-Literale.
- `MAX_DELIVERY_AGE_HOURS = 24` (nur von AWS-NR6-001 verwendet)
- `MIN_RETENTION_DAYS = 365` (nicht am Modulanfang, sondern unmittelbar vor der Klasse `CheckCloudWatchLogRetention` definiert; nur von AWS-NR6-004 verwendet)

### Azure (`nr6_wirksamkeit.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 6 — Bewertung der Wirksamkeit von Risikomanagementmaßnahmen checks for Azure.

  Checks Defender Secure Score, Policy Compliance, Log Retention, and Diagnostic Settings.
  ```
- `BSIG_30_NR = 6`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS): "§30 Abs. 2 Nr. 6 BSIG — Konzepte und Verfahren zur Bewertung der Wirksamkeit von Risikomanagementmaßnahmen im Bereich der Sicherheit in der Informationstechnik"
- `MIN_SECURE_SCORE_PERCENT = 70`
- `MIN_LOG_RETENTION_DAYS = 365`
- `CRITICAL_RESOURCE_TYPES` (wörtlich, Liste):
  ```python
  CRITICAL_RESOURCE_TYPES = [
      "Microsoft.KeyVault/vaults",
      "Microsoft.Sql/servers",
      "Microsoft.Storage/storageAccounts",
      "Microsoft.Network/networkSecurityGroups",
  ]
  ```
- Kein Modul-Äquivalent zu `ISO_CONTROL`.

### GCP (`nr6_wirksamkeit.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 6 — Wirksamkeit von Risikomanagementmaßnahmen checks for GCP.

  Checks Cloud Logging Sinks, Security Command Center Health Analytics,
  IAM Policy Intelligence (Recommender), and Monitoring Dashboards.
  ```
- `BSIG_30_NR = 6`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS/Azure): "§30 Abs. 2 Nr. 6 BSIG — Konzepte und Verfahren zur Bewertung der Wirksamkeit von Risikomanagementmaßnahmen im Bereich der Sicherheit in der Informationstechnik"
- Keine weiteren Modul-Konstanten.

---

## Checks

### AWS-NR6-001 — CloudTrail Betriebliche Wirksamkeit

Klassen-Docstring (wörtlich): "Check that CloudTrail is actively delivering logs (operational effectiveness).\n\nThis goes beyond checking if CloudTrail is configured (NR1-004) by verifying that log delivery is actually happening recently, demonstrating operational effectiveness of the audit trail."

| Feld | Wert |
|---|---|
| Klasse | `CheckCloudTrailLogIntegrity` |
| description | (Template, als Klassenattribut mit f-String aus Teilstrings zusammengesetzt, referenziert `MAX_DELIVERY_AGE_HOURS`): "Prüft ob CloudTrail-Logs tatsächlich zugestellt werden (letzte Zustellung innerhalb von 24 Stunden) und die Digest-Validierung funktioniert." |
| severity | HIGH (beide Mangel-Pfade, inline im jeweiligen `Finding()`-Aufruf) |
| iso27001_control | `ISO_CONTROL` = "A.5.36 Compliance with policies, rules and standards" (identisch in Positiv- und beiden Mangel-Pfaden) |
| required_permissions | `["cloudtrail:DescribeTrails", "cloudtrail:GetTrailStatus"]` |
| pruefgrenzen | "Prüft nur, ob CloudTrail aktiv Ereignisse liefert (betriebliche Funktion). Nicht geprüft wird, ob die Ereignisse ausgewertet werden." |
| Prüflogik (deskriptiv) | `cloudtrail.describe_trails(includeShadowTrails=False)` ermittelt alle Trails; je Trail liefert `cloudtrail.get_trail_status(Name=trail_arn)` den Status — ist `IsLogging` False, wird der Trail übersprungen (kein Finding, Verweis im Code-Kommentar auf NR1-004); andernfalls wird das Alter von `LatestDeliveryTime` gegen `MAX_DELIVERY_AGE_HOURS` (24) geprüft (>24h ergibt ein Mangel-Finding "Log-Zustellung veraltet") und, sofern `LogFileValidationEnabled` True ist, zusätzlich das Alter von `LatestDigestDeliveryTime` (>24h ergibt ein weiteres Mangel-Finding "Digest-Zustellung veraltet"); sind sowohl Zustellung als auch (falls zutreffend) Digest innerhalb der Frist, wird ein einziges kombiniertes Positiv-Finding je Trail erzeugt. |

**Finding-Texte (Mangel-Pfad — Log-Zustellung veraltet):**
- title: "CloudTrail Log-Zustellung veraltet"
- description (Template): `f"Der CloudTrail '{trail_name}' hat seit {int(hours_since_delivery)} Stunden keine Logs zugestellt. Dies deutet auf ein operatives Problem mit dem Audit-Trail hin."`
- expected_state (Template): `f"Log-Zustellung innerhalb der letzten {MAX_DELIVERY_AGE_HOURS} Stunden"`
- remediation: "Überprüfen Sie den S3-Bucket und die IAM-Berechtigungen des CloudTrail. Prüfen Sie LatestDeliveryError für Details."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"GetTrailStatus: LatestDeliveryTime={last_delivery.isoformat()}, hours_ago={round(hours_since_delivery, 1)}"`

**Finding-Texte (Mangel-Pfad — Digest-Zustellung veraltet):**
- title: "CloudTrail Digest-Zustellung veraltet"
- description (Template): `f"Der CloudTrail '{trail_name}' hat seit {int(hours_since_digest)} Stunden keinen Log-Digest zugestellt. Die Log-Integritätsvalidierung ist beeinträchtigt."`
- expected_state (Template): `f"Digest-Zustellung innerhalb der letzten {MAX_DELIVERY_AGE_HOURS} Stunden"`
- remediation: "Überprüfen Sie die CloudTrail-Konfiguration und S3-Bucket-Berechtigungen für die Digest-Zustellung."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"GetTrailStatus: LatestDigestDeliveryTime={last_digest.isoformat()}, hours_ago={round(hours_since_digest, 1)}"`

**Positivnachweis (compliant_finding, kombiniert für Zustellung + Digest):**
- title: "CloudTrail-Zustellung betrieblich wirksam"
- description (Template): `f"Der CloudTrail '{trail_name}' stellt Logs aktuell zu (letzte Zustellung innerhalb von {MAX_DELIVERY_AGE_HOURS} Stunden)."`
- expected_state (Template, identisch zum Mangel-Pfad "Log-Zustellung veraltet"): `f"Log-Zustellung innerhalb der letzten {MAX_DELIVERY_AGE_HOURS} Stunden"`
- audit_evidence (Template): `f"GetTrailStatus: delivery and digest within {MAX_DELIVERY_AGE_HOURS}h for trail {trail_name}"`

---

### AWS-NR6-002 — Config Rules Compliance

Klassen-Docstring (wörtlich): "Check that AWS Config Rules are configured for automated compliance evaluation.\n\nVerifies that AWS Config is active and Config Rules exist to provide automated compliance assessment of infrastructure resources."

| Feld | Wert |
|---|---|
| Klasse | `CheckConfigRulesCompliance` |
| description | "Prüft ob AWS Config Rules für automatisierte Compliance-Bewertung konfiguriert sind." |
| severity | HIGH (beide Mangel-Pfade, inline) |
| iso27001_control | inline Literal "A.5.35 Independent review of information security" (identisch in Positiv- und beiden Mangel-Pfaden) |
| required_permissions | `["config:DescribeConfigRules", "config:DescribeComplianceByConfigRule"]` |
| pruefgrenzen | "Prüft nur Existenz und Compliance-Stand der AWS-Config-Rules. Nicht geprüft wird, ob die Regelabdeckung für die Umgebung angemessen ist." |
| Prüflogik (deskriptiv) | `config.describe_config_rules()` wird je Region aufgerufen; keine Rules ergibt ein Mangel-Finding "Keine AWS Config Rules konfiguriert"; ≥1 Rule ergibt ein Positiv-Finding "AWS Config Rules konfiguriert" (je aggregiert pro Region) und löst zusätzlich `config.describe_compliance_by_config_rule()` aus, dessen Ergebnis (Anzahl NON_COMPLIANT-Regeln) nur per `logger.info`/`logger.warning` protokolliert wird, ohne in ein Finding einzufließen; wirft der erste Aufruf `NoAvailableConfigurationRecorderException`, wird stattdessen ein separates Mangel-Finding "AWS Config nicht aktiviert" erzeugt. |

**Finding-Texte (Mangel-Pfad — keine Config Rules):**
- title: "Keine AWS Config Rules konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): `f"In Region '{region}' sind keine AWS Config Rules konfiguriert. Ohne Config Rules fehlt eine automatisierte Compliance-Bewertung."`
- expected_state: "AWS Config Rules konfiguriert für automatisierte Compliance-Bewertung"
- remediation (Teilstrings): "Aktivieren Sie AWS Config und erstellen Sie Config Rules: aws configservice put-config-rule ..."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribeConfigRules: 0 rules found in region {region}"`

**Positivnachweis (compliant_finding):**
- title: "AWS Config Rules konfiguriert"
- description (Template): `f"In Region '{region}' sind {len(config_rules)} AWS Config Rules konfiguriert — automatisierte Compliance-Bewertung ist aktiv."`
- expected_state (identisch zum Mangel-Pfad "keine Config Rules"): "AWS Config Rules konfiguriert für automatisierte Compliance-Bewertung"
- audit_evidence (Template): `f"DescribeConfigRules: {len(config_rules)} rules in region {region}"`

**Finding-Texte (Mangel-Pfad — Config nicht aktiviert, `NoAvailableConfigurationRecorderException`):**
- title: "AWS Config nicht aktiviert"
- description (Teilstrings): `f"In Region '{region}' ist AWS Config nicht aktiviert. Ohne Config Recorder ist keine automatisierte Compliance-Bewertung möglich."`
- expected_state (identisch zu den beiden anderen Findings dieses Checks): "AWS Config Rules konfiguriert für automatisierte Compliance-Bewertung"
- remediation (Teilstrings, identisch zum ersten Mangel-Pfad): "Aktivieren Sie AWS Config und erstellen Sie Config Rules: aws configservice put-config-rule ..."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"NoAvailableConfigurationRecorderException in region {region}"`

---

### AWS-NR6-003 — Security Hub Compliance Score

Klassen-Docstring (wörtlich): "Check that AWS Security Hub is enabled with adequate compliance score.\n\nVerifies that Security Hub is activated and maintains a compliance score of at least 80% to demonstrate effective risk management assessment."

| Feld | Wert |
|---|---|
| Klasse | `CheckSecurityHubComplianceScore` |
| description | "Prüft ob AWS Security Hub aktiviert ist und einen Compliance-Score ≥80% aufweist." |
| severity | HIGH (beide Mangel-Pfade, inline) |
| iso27001_control | inline Literal "A.5.35" (ohne Beschreibungstext; identisch in Positiv- und beiden Mangel-Pfaden) |
| required_permissions | `["securityhub:DescribeHub", "securityhub:GetFindings"]` |
| pruefgrenzen | "Liest nur den von Security Hub berechneten Compliance-Score der aktivierten Standards. Deaktivierte Standards und unterdrückte Befunde fließen nicht ein." |
| Prüflogik (deskriptiv) | Je Region wird zunächst der Security-Hub-Client erzeugt (Fehler → CheckError, Region übersprungen), dann `sh_client.describe_hub()` aufgerufen — wirft dies `InvalidAccessException`, ergibt das ein Mangel-Finding "Security Hub nicht aktiviert"; ist Security Hub aktiviert, wird `sh_client.get_findings(Filters={"ComplianceStatus":[{"Value":"FAILED","Comparison":"EQUALS"}]}, MaxResults=100)` aufgerufen und die Anzahl der zurückgegebenen FAILED-Findings ausgewertet — `<=20` ergibt ein Positiv-Finding, `>20` ein Mangel-Finding "Security Hub Compliance-Score unzureichend"; ein numerischer Compliance-Score-Wert wird an keiner Stelle abgefragt oder berechnet. |

**Finding-Texte (Mangel-Pfad — Security Hub nicht aktiviert):**
- title: "Security Hub nicht aktiviert"
- description (Template, aus vielen Teilstrings über mehrere Zeilen zusammengesetzt): `f"In Region '{region}' ist AWS Security Hub nicht aktiviert — keine Wirksamkeitsbewertung möglich."`
- expected_state: "Security Hub aktiviert mit Compliance-Score ≥80%"
- remediation: "Aktivieren Sie AWS Security Hub: aws securityhub enable-security-hub"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribeHub: InvalidAccessException in region {region}"`

**Positivnachweis (compliant_finding):**
- title: "Security Hub Compliance-Score ausreichend"
- description (Template): `f"In Region '{region}' ist Security Hub aktiviert und hat nur {failed_count} fehlgeschlagene Findings (Grenze: 20)."`
- expected_state: "Security Hub Compliance-Score ≥80% (maximal 20 fehlgeschlagene Findings)"
- audit_evidence (Template): `f"GetFindings: {failed_count} FAILED findings in region {region}"`

**Finding-Texte (Mangel-Pfad — Compliance-Score unzureichend):**
- title: "Security Hub Compliance-Score unzureichend"
- description (Template, aus vielen Teilstrings über mehrere Zeilen zusammengesetzt): `f"In Region '{region}' hat Security Hub {failed_count} fehlgeschlagene Findings. Dies deutet auf einen Compliance-Score <80% hin."`
- expected_state (identisch zum Positivnachweis, abweichend vom Mangel-Pfad "nicht aktiviert"): "Security Hub Compliance-Score ≥80% (maximal 20 fehlgeschlagene Findings)"
- remediation (Teilstrings): "Beheben Sie die fehlgeschlagenen Security Hub Findings und überprüfen Sie den Compliance-Status."
- remediation_effort: MEDIUM
- audit_evidence (Template, identisches Template wie Positivnachweis): `f"GetFindings: {failed_count} FAILED findings in region {region}"`

---

### AWS-NR6-004 — CloudWatch Log Retention

Klassen-Docstring (wörtlich): "Check that CloudWatch Log Groups have sufficient retention periods.\n\nVerifies that all CloudWatch Log Groups retain logs for at least 365 days to meet NIS2 audit and compliance requirements."

| Feld | Wert |
|---|---|
| Klasse | `CheckCloudWatchLogRetention` |
| description | "Prüft ob CloudWatch Log Groups eine Aufbewahrungsfrist von mindestens 365 Tagen haben." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.15 Logging" (identisch in beiden Pfaden) |
| required_permissions | `["logs:DescribeLogGroups"]` |
| pruefgrenzen | "Prüft nur die Retention-Einstellung der CloudWatch-Log-Gruppen. Nicht geprüft werden Vollständigkeit der Log-Quellen und Archivierung außerhalb von CloudWatch." |
| Klassenkonstante | `MIN_RETENTION_DAYS = 365` (Modul-Ebene, direkt vor der Klasse definiert) |
| Prüflogik (deskriptiv) | `logs.describe_log_groups()` (paginiert) je Region; Feld `retentionInDays` jeder Log Group wird ausgelesen — `None` ("never expire") oder `>= MIN_RETENTION_DAYS` (365) ergibt Positivnachweis, ein numerischer Wert `< 365` ergibt Mangel-Finding, je Log Group. |

**Finding-Texte (Mangel-Pfad):**
- title: "CloudWatch Log Retention zu kurz"
- description (Template, aus vielen Teilstrings über mehrere Zeilen zusammengesetzt): `f"Die Log Group '{lg_name}' hat eine Aufbewahrungsfrist von nur {retention} Tagen. Mindestens {MIN_RETENTION_DAYS} Tage sind erforderlich."`
- expected_state (Template): `f"CloudWatch Log Retention ≥ {MIN_RETENTION_DAYS} Tage (oder 'Never expire')"`
- remediation (Template, aus Teilstrings über mehrere Zeilen zusammengesetzt): "Setzen Sie die Aufbewahrungsfrist: aws logs put-retention-policy --log-group-name <name> --retention-in-days 365"
- remediation_effort: LOW
- audit_evidence (Template): `f"DescribeLogGroups: retentionInDays={retention} for {lg_name}"`

**Positivnachweis (compliant_finding):**
- title: "CloudWatch Log Retention ausreichend"
- description (Template): `f"Die Log Group '{lg_name}' hat eine Aufbewahrungsfrist von {'unbegrenzt' if retention is None else f'{retention} Tagen'} (Minimum: {MIN_RETENTION_DAYS} Tage)."`
- expected_state (Template, identisch zum Mangel-Pfad): `f"CloudWatch Log Retention ≥ {MIN_RETENTION_DAYS} Tage (oder 'Never expire')"`
- audit_evidence (Template, identisches Template wie Mangel-Pfad): `f"DescribeLogGroups: retentionInDays={retention} for {lg_name}"`

---

### AZ-NR6-001 — Defender Secure Score ≥70%

Klassen-Docstring (wörtlich): "Check that Defender Secure Score is at least 70%."

| Feld | Wert |
|---|---|
| Klasse | `CheckDefenderSecureScore` |
| description | "Prüft ob der Microsoft Defender Secure Score mindestens 70% beträgt." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.35 Unabhängige Überprüfung der Informationssicherheit" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Security/secureScores/read"]` |
| pruefgrenzen | "Liest nur den von Defender berechneten Secure Score. Der Schwellwert 70% ist eine Tool-Konvention, kein gesetzlicher Grenzwert." |
| Klassenkonstante | `MIN_SECURE_SCORE_PERCENT = 70` (Modul-Ebene) |
| Prüflogik (deskriptiv) | `SecurityCenter.secure_scores.list()` je Subscription; je Score-Objekt wird aus `current_score`/`max_score` (bei `None` auf 0 bzw. 1 substituiert) ein Prozentsatz berechnet (bei `max_score<=0` wird 0 verwendet) — `>= MIN_SECURE_SCORE_PERCENT` (70) ergibt Positivnachweis, sonst Mangel-Finding, je Score-Objekt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Defender Secure Score unter 70%"
- description (Template): `f"Subscription {sub_id} hat einen Secure Score von {percentage:.0f}% ({current}/{max_score}). Mindestens {MIN_SECURE_SCORE_PERCENT}% wird empfohlen."`
- expected_state (Template): `f"Secure Score ≥ {MIN_SECURE_SCORE_PERCENT}%"`
- remediation: "Befolgen Sie die Empfehlungen in Microsoft Defender for Cloud, um den Secure Score zu verbessern. Priorisieren Sie Empfehlungen mit hoher Auswirkung."
- remediation_effort: HIGH
- audit_evidence (Template): `f"secure_scores.list(): score={current}/{max_score} ({percentage:.0f}%)"`

**Positivnachweis (compliant_finding):**
- title: "Defender Secure Score ausreichend"
- description (Template): `f"Subscription {sub_id} hat einen Secure Score von {percentage:.0f}% ({current}/{max_score}) — Minimum {MIN_SECURE_SCORE_PERCENT}% ist erreicht."`
- expected_state (Template, identisch zum Mangel-Pfad): `f"Secure Score ≥ {MIN_SECURE_SCORE_PERCENT}%"`
- audit_evidence (Template, identisches Template wie Mangel-Pfad): `f"secure_scores.list(): score={current}/{max_score} ({percentage:.0f}%)"`

---

### AZ-NR6-002 — Azure Policy Compliance State

Klassen-Docstring (wörtlich): "Check Azure Policy compliance state."

| Feld | Wert |
|---|---|
| Klasse | `CheckPolicyComplianceState` |
| description | "Prüft den Azure Policy Compliance-Status der Subscription." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.35 Unabhängige Überprüfung der Informationssicherheit" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.PolicyInsights/policyStates/queryResults/action"]` |
| pruefgrenzen | "Liest nur den Azure-Policy-Compliance-Stand. Aussagekraft hängt von der Abdeckung der zugewiesenen Policies ab (siehe AZ-NR1-002)." |
| Prüflogik (deskriptiv) | `PolicyInsightsClient.policy_states.list_query_results_for_subscription(policy_states_resource="latest", subscription_id=sub_id)` je Subscription; die Ergebnisliste wird nach `compliance_state == "NonCompliant"` gefiltert — liegen Ergebnisse vor und keines ist NonCompliant, ergibt dies ein aggregiertes Positiv-Finding je Subscription; liegt mindestens ein NonCompliant-Ergebnis vor, ergibt dies ein aggregiertes Mangel-Finding je Subscription; ist die Ergebnisliste leer, wird weder ein Positiv- noch ein Mangel-Finding erzeugt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Nicht-konforme Azure Policies"
- description (Template): `f"Subscription {sub_id} hat {len(non_compliant)} nicht-konforme Policy-Ergebnisse von insgesamt {len(query_results)}. Nicht-konforme Policies deuten auf Sicherheitslücken hin."`
- expected_state: "Alle Policy-Assignments im Status 'Compliant'"
- remediation (Template, aus Literal + f-String zusammengesetzt): "Beheben Sie die nicht-konformen Policy-Ergebnisse: az policy state list --filter \"complianceState eq 'NonCompliant'\" und folgen Sie den Empfehlungen zur Remediation."
- remediation_effort: HIGH
- audit_evidence (Template): `f"policy_states.list_query_results_for_subscription(): {len(non_compliant)}/{len(query_results)} non-compliant"`

**Positivnachweis (compliant_finding):**
- title: "Azure Policies vollständig konform"
- description (Template): `f"Subscription {sub_id} hat {len(query_results)} Policy-Ergebnisse, alle im Status 'Compliant'."`
- expected_state (identisch zum Mangel-Pfad): "Alle Policy-Assignments im Status 'Compliant'"
- audit_evidence (Template): `f"policy_states.list_query_results_for_subscription(): 0/{len(query_results)} non-compliant"`

---

### AZ-NR6-003 — Activity Log Retention ≥365 Tage

Klassen-Docstring (wörtlich): "Check that Activity Log retention is at least 365 days."

| Feld | Wert |
|---|---|
| Klasse | `CheckLogRetention` |
| description | "Prüft ob Activity Logs mindestens 365 Tage aufbewahrt werden (via Log Analytics Workspace Retention)." |
| severity | MEDIUM (beide Mangel-Pfade, inline) |
| iso27001_control | inline Literal "A.8.15 Logging" (identisch in allen drei Pfaden) |
| required_permissions | `["Microsoft.Insights/diagnosticSettings/read", "Microsoft.OperationalInsights/workspaces/read"]` |
| pruefgrenzen | "Prüft nur die konfigurierte Aufbewahrung des Activity Logs. Externe Archivierung (Storage/SIEM) mit kürzerer nativer Retention wird als Mangel gewertet, obwohl sie gleichwertig sein kann." |
| Klassenkonstante | `MIN_LOG_RETENTION_DAYS = 365` (Modul-Ebene) |
| Prüflogik (deskriptiv) | `LogAnalyticsManagementClient.workspaces.list()` je Subscription; keine Workspaces ergibt ein aggregiertes Mangel-Finding je Subscription ("Keine Log Analytics Workspaces"), danach wird die Subscription nicht weiter geprüft (`continue`); existieren Workspaces, wird je Workspace `ws.retention_in_days` ausgelesen (fehlender Wert wird als 30 angenommen) — `>= MIN_LOG_RETENTION_DAYS` (365) ergibt Positivnachweis, sonst Mangel-Finding, je Workspace. |

**Finding-Texte (Mangel-Pfad — keine Workspaces):**
- title: "Keine Log Analytics Workspaces"
- description (Template): `f"Subscription {sub_id} hat keine Log Analytics Workspaces. Ohne Workspaces können Activity Logs nicht langfristig aufbewahrt werden."`
- expected_state: "Log Analytics Workspace mit Retention ≥ 365 Tage"
- remediation (Template): `f"Erstellen Sie einen Log Analytics Workspace: az monitor log-analytics workspace create --resource-group <rg> --workspace-name <name> --retention-time 365"`
- remediation_effort: MEDIUM
- audit_evidence: "workspaces.list() returned 0 workspaces" (Literal, kein f-String)

**Finding-Texte (Mangel-Pfad — Retention unter 365 Tage):**
- title: "Log Retention unter 365 Tage"
- description (Template): `f"Log Analytics Workspace {ws.name} in Subscription {sub_id} hat nur {retention} Tage Retention."`
- expected_state (Template, abweichend formuliert vom Mangel-Pfad "keine Workspaces"): `f"Retention ≥ {MIN_LOG_RETENTION_DAYS} Tage"`
- remediation (Template): `f"Erhöhen Sie die Retention: az monitor log-analytics workspace update --resource-group <rg> --workspace-name {ws.name} --retention-time {MIN_LOG_RETENTION_DAYS}"`
- remediation_effort: LOW
- audit_evidence (Template): `f"workspaces: {ws.name} retention_in_days={retention}"`

**Positivnachweis (compliant_finding):**
- title: "Log Retention ausreichend"
- description (Template): `f"Log Analytics Workspace {ws.name} hat {retention} Tage Retention (Minimum: {MIN_LOG_RETENTION_DAYS})."`
- expected_state (Template, identisch zum Mangel-Pfad "Retention unter 365 Tage"): `f"Retention ≥ {MIN_LOG_RETENTION_DAYS} Tage"`
- audit_evidence (Template, identisches Template wie Mangel-Pfad "Retention unter 365 Tage"): `f"workspaces: {ws.name} retention_in_days={retention}"`

---

### AZ-NR6-004 — Diagnostic Settings auf kritischen Ressourcen

Klassen-Docstring (wörtlich): "Check that Diagnostic Settings are configured on critical resources."

| Feld | Wert |
|---|---|
| Klasse | `CheckDiagnosticSettings` |
| description | "Prüft ob Diagnostic Settings auf kritischen Ressourcen konfiguriert sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.35, A.8.15 Logging und Überprüfung" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Insights/diagnosticSettings/read", "Microsoft.Resources/subscriptions/resources/read"]` |
| pruefgrenzen | "Prüft Diagnostic Settings nur auf den erfassten Ressourcentypen. Welche Ressourcen als kritisch gelten, ist eine organisatorische Festlegung." |
| Code-Kommentar (wörtlich) | "# Positive evidence only when every critical resource was verifiable (ADR-0016)" |
| Prüflogik (deskriptiv) | `ResourceManagementClient.resources.list()` je Subscription, gefiltert auf `r.type in CRITICAL_RESOURCE_TYPES`; je gefundener kritischer Ressource wird `MonitorManagementClient.diagnostic_settings.list(resource_uri=resource.id)` aufgerufen (Einzelfehler werden mit `except Exception: pass` verschluckt, Ressource zählt dann weder als geprüft noch als ohne Settings); sind alle kritischen Ressourcen erfolgreich geprüft und keine ohne Diagnostic Settings, ergibt dies ein aggregiertes Positiv-Finding je Subscription; existiert mindestens eine Ressource ohne Diagnostic Settings, ergibt dies ein aggregiertes Mangel-Finding je Subscription mit einer auf die ersten 5 Ressourcen gekürzten Aufzählung. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kritische Ressourcen ohne Diagnostic Settings"
- description (Template, mit auf 5 Einträge gekürzter Ressourcenliste `resource_summary = ", ".join(f"{r['name']} ({r['type'].split('/')[-1]})" for r in resources_without_diag[:5])`): `f"Subscription {sub_id} hat {len(resources_without_diag)} kritische Ressourcen ohne Diagnostic Settings: {resource_summary}{'...' if len(resources_without_diag) > 5 else ''}."`
- expected_state: "Alle kritischen Ressourcen mit Diagnostic Settings"
- remediation (Template): `f"Konfigurieren Sie Diagnostic Settings für jede kritische Ressource: az monitor diagnostic-settings create --resource <resource-id> --name <diag-name> --workspace <workspace-id>"`
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"Checked {len(critical_resources)} critical resources, {len(resources_without_diag)} without diagnostic settings"`

**Positivnachweis (compliant_finding):**
- title: "Kritische Ressourcen mit Diagnostic Settings"
- description (Template): `f"Alle {len(critical_resources)} kritischen Ressourcen in Subscription {sub_id} haben Diagnostic Settings konfiguriert."`
- expected_state (identisch zum Mangel-Pfad): "Alle kritischen Ressourcen mit Diagnostic Settings"
- audit_evidence (Template): `f"Checked {len(critical_resources)} critical resources, all with settings"`

---

### GCP-NR6-001 — Audit-Log-Integrität mit gesperrten Retention-Buckets

Klassen-Docstring (wörtlich): "Prüft ob Log-Sinks mit gesperrten Retention-Buckets konfiguriert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckAuditLogIntegrity` |
| description | "Prüft ob Cloud Logging Sinks konfiguriert sind, die Logs in Buckets mit gesperrter Aufbewahrungsrichtlinie exportieren, um die Unveränderlichkeit der Audit-Logs sicherzustellen." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.35 Unabhängige Überprüfung, A.8.15 Logging" (identisch in beiden Pfaden) |
| required_permissions | `["logging.sinks.list"]` |
| pruefgrenzen | "Prüft nur Log-Sinks mit gesperrten Retention-Buckets. Andere Integritätssicherungen für Logs werden nicht erkannt." |
| Code-Kommentar (wörtlich) | "# Check if sink destination is a storage bucket / # Locked retention must be verified separately but / # having a sink to a bucket is the baseline requirement" |
| Prüflogik (deskriptiv) | `logging_v2.ConfigServiceV2Client.list_sinks(request={"parent": f"projects/{project_id}"})` je Projekt; je Sink wird nur geprüft, ob `sink.destination` den Substring "storage.googleapis.com/" enthält (Schleife bricht beim ersten Treffer per `break` ab) — Treffer ergibt ein aggregiertes Positiv-Finding je Projekt, kein Treffer ein aggregiertes Mangel-Finding je Projekt; ob die Aufbewahrungsrichtlinie des Ziel-Buckets tatsächlich gesperrt ist, wird laut Code-Kommentar nicht geprüft. |

**Positivnachweis (compliant_finding):**
- title: "Log-Sink mit Storage-Bucket-Export vorhanden"
- description (Template): `f"Projekt {project_id} exportiert Logs über mindestens einen Sink in einen Storage-Bucket — Grundlage für unveränderliche Audit-Logs."`
- expected_state: "Mindestens ein Log-Sink mit Export in einen Storage-Bucket mit gesperrter Aufbewahrungsrichtlinie"
- audit_evidence (Template): `f"list_sinks() returned {len(sinks)} sink(s), >=1 with storage destination"`

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Log-Sinks mit gesperrter Aufbewahrung"
- description (Teilstrings, mehrzeilig zusammengesetzt): `f"Projekt {project_id} hat keine Logging-Sinks, die Logs in Storage-Buckets mit gesperrter Aufbewahrungsrichtlinie exportieren. Ohne unveränderliche Log-Speicherung kann die Integrität von Audit-Logs nicht gewährleistet werden."`
- expected_state (identisch zum Positivnachweis): "Mindestens ein Log-Sink mit Export in einen Storage-Bucket mit gesperrter Aufbewahrungsrichtlinie"
- remediation (wörtlich, mehrzeilig mit `\n`): "Erstellen Sie einen Log-Sink mit gesperrtem Bucket:\n1. gcloud storage buckets create gs://<BUCKET_NAME> --retention-period=2592000 --locked\n2. gcloud logging sinks create <SINK_NAME> storage.googleapis.com/<BUCKET_NAME> --project=<PROJECT_ID>"
- remediation_effort: MEDIUM
- audit_evidence (Teilstrings): `f"list_sinks() returned {len(sinks)} sinks, none with locked retention bucket destination"`

---

### GCP-NR6-002 — Security Health Analytics aktiviert

Klassen-Docstring (wörtlich): "Prüft ob SCC Security Health Analytics aktiviert und zugänglich ist."

| Feld | Wert |
|---|---|
| Klasse | `CheckSecurityHealthAnalytics` |
| description | "Prüft ob Security Command Center Security Health Analytics aktiviert ist und Sicherheitserkenntnisse liefert." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.35 Unabhängige Überprüfung der Informationssicherheit" (identisch in beiden Pfaden) |
| required_permissions | `["securitycenter.findings.list"]` |
| pruefgrenzen | "Prüft nur, ob Security Health Analytics per API erreichbar ist. Bei fehlender Berechtigung wird dies als Mangel gewertet — SCC-Premium-Features werden nicht unterschieden." |
| Prüflogik (deskriptiv) | `securitycenter_v1.SecurityCenterClient.list_findings(ListFindingsRequest(parent=f"projects/{project_id}/sources/-"))` je Projekt; gelingt der Aufruf, wird dies unabhängig von der Anzahl zurückgegebener Findings (`finding_count`) als Positivnachweis gewertet; wirft der Aufruf eine Exception, deren kleingeschriebener Text "permission", "403" oder "not enabled" enthält, wird ein Mangel-Finding erzeugt, jede andere Exception wird als `CheckError` erfasst. |

**Positivnachweis (compliant_finding):**
- title: "Security Health Analytics zugänglich"
- description (Template): `f"Projekt {project_id} hat ein zugängliches Security Command Center — die Wirksamkeit der Maßnahmen wird automatisch bewertet."`
- expected_state: "Security Command Center aktiviert mit Security Health Analytics"
- audit_evidence (Template): `f"list_findings() succeeded with {finding_count} finding(s)"`

**Finding-Texte (Mangel-Pfad):**
- title: "Security Health Analytics nicht zugänglich"
- description (Teilstrings): `f"Projekt {project_id} hat kein zugängliches Security Command Center. Ohne SCC fehlt die automatische Bewertung der Wirksamkeit von Sicherheitsmaßnahmen."`
- expected_state (identisch zum Positivnachweis): "Security Command Center aktiviert mit Security Health Analytics"
- remediation (wörtlich, mehrzeilig mit `\n`): "Aktivieren Sie das Security Command Center:\ngcloud scc settings update --project=<PROJECT_ID> --enable-scc\nOder aktivieren Sie SCC Premium in der Google Cloud Console unter Sicherheit > Security Command Center."
- remediation_effort: LOW
- audit_evidence (Template): `f"SCC API returned error: {type(exc).__name__}"`

---

### GCP-NR6-003 — IAM Policy Intelligence aktiviert

Klassen-Docstring (wörtlich): "Prüft ob IAM Policy Intelligence (Recommender) aktiviert ist."

| Feld | Wert |
|---|---|
| Klasse | `CheckPolicyIntelligence` |
| description | "Prüft ob der IAM Recommender aktiviert ist und Empfehlungen zur Verbesserung der IAM-Richtlinien liefert." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.35 Unabhängige Überprüfung der Informationssicherheit" (identisch in beiden Pfaden) |
| required_permissions | `["recommender.iamPolicyRecommendations.list"]` |
| pruefgrenzen | "Prüft nur, ob die Recommender-API zugänglich ist. Ob Empfehlungen umgesetzt werden, wird nicht bewertet." |
| Prüflogik (deskriptiv) | `recommender`-API v1 (discovery-basiert via `session.service("recommender", "v1")`): `projects().locations().recommenders().recommendations().list(parent=f"projects/{project_id}/locations/-/recommenders/google.iam.policy.Recommender").execute()` je Projekt; gelingt der Aufruf, wird dies unabhängig von der Anzahl zurückgegebener Empfehlungen als Positivnachweis gewertet; wirft der Aufruf eine Exception, deren kleingeschriebener Text "not enabled", "403" oder "permission" enthält, wird ein Mangel-Finding erzeugt, jede andere Exception wird als `CheckError` erfasst. |

**Positivnachweis (compliant_finding):**
- title: "IAM Policy Intelligence aktiviert"
- description (Template): `f"Projekt {project_id} hat einen zugänglichen IAM Recommender — Empfehlungen zur Verbesserung der IAM-Richtlinien sind verfügbar."`
- expected_state: "IAM Recommender API aktiviert und zugänglich"
- audit_evidence (Template): `f"recommendations.list() succeeded with {len(recommendations)} recommendation(s)"`

**Finding-Texte (Mangel-Pfad):**
- title: "IAM Policy Intelligence nicht aktiviert"
- description (Teilstrings): `f"Projekt {project_id} hat keinen zugänglichen IAM Recommender. Ohne Policy Intelligence fehlen automatische Empfehlungen zur Verbesserung der Zugriffskontrollrichtlinien."`
- expected_state (identisch zum Positivnachweis): "IAM Recommender API aktiviert und zugänglich"
- remediation (wörtlich, mehrzeilig mit `\n`): "Aktivieren Sie die Recommender API:\ngcloud services enable recommender.googleapis.com --project=<PROJECT_ID>"
- remediation_effort: LOW
- audit_evidence (Template): `f"Recommender API returned error: {type(exc).__name__}"`

---

### GCP-NR6-004 — Monitoring-Dashboards vorhanden

Klassen-Docstring (wörtlich): "Prüft ob benutzerdefinierte Monitoring-Dashboards existieren."

| Feld | Wert |
|---|---|
| Klasse | `CheckMonitoringDashboards` |
| description | "Prüft ob benutzerdefinierte Cloud Monitoring Dashboards eingerichtet sind, um die Wirksamkeit von Sicherheitsmaßnahmen visuell zu überwachen." |
| severity | LOW (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.35 Unabhängige Überprüfung der Informationssicherheit" (identisch in beiden Pfaden) |
| required_permissions | `["monitoring.dashboards.list"]` |
| pruefgrenzen | "Prüft nur die Existenz von Monitoring-Dashboards. Ob sie sicherheitsrelevante Inhalte zeigen, wird nicht bewertet." |
| Prüflogik (deskriptiv) | `monitoring`-API v1 (discovery-basiert via `session.service("monitoring", "v1")`): `projects().dashboards().list(parent=f"projects/{project_id}").execute()` je Projekt; Vorhandensein ≥1 Dashboard ergibt Positivnachweis je Projekt, kein Dashboard ergibt Mangel-Finding je Projekt; jede Exception beim API-Aufruf wird als `CheckError` erfasst (keine fallunterscheidende Textprüfung wie bei GCP-NR6-002/GCP-NR6-003). |

**Positivnachweis (compliant_finding):**
- title: "Monitoring-Dashboards vorhanden"
- description (Template): `f"Projekt {project_id} hat {len(dashboards)} benutzerdefinierte Cloud Monitoring Dashboard(s) zur Sicherheitsüberwachung."`
- expected_state: "Mindestens ein benutzerdefiniertes Monitoring-Dashboard für die Sicherheitsüberwachung"
- audit_evidence (Template): `f"dashboards.list() returned {len(dashboards)} dashboard(s)"`

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Monitoring-Dashboards konfiguriert"
- description (Teilstrings): `f"Projekt {project_id} hat keine benutzerdefinierten Cloud Monitoring Dashboards. Ohne Dashboards fehlt die visuelle Überwachung der Wirksamkeit von Sicherheitsmaßnahmen."`
- expected_state (identisch zum Positivnachweis): "Mindestens ein benutzerdefiniertes Monitoring-Dashboard für die Sicherheitsüberwachung"
- remediation (wörtlich, mehrzeilig mit `\n`): "Erstellen Sie ein Monitoring-Dashboard:\ngcloud monitoring dashboards create --config-from-file=dashboard.json --project=<PROJECT_ID>\nEmpfohlen: Erstellen Sie Dashboards für IAM-Aktivitäten, Netzwerk-Anomalien und Audit-Log-Metriken."
- remediation_effort: LOW
- audit_evidence: "dashboards.list() returned 0 dashboards" (Literal, kein f-String)

---

## Mechanische Auffälligkeiten (ohne Bewertung)

1. Die Klassenreihenfolge in der AWS-Moduldatei entspricht nicht der aufsteigenden Check-ID-Reihenfolge: Datei-Reihenfolge ist 001 (`CheckCloudTrailLogIntegrity`), 002 (`CheckConfigRulesCompliance`), 004 (`CheckCloudWatchLogRetention`), 003 (`CheckSecurityHubComplianceScore`) — AWS-NR6-004 steht vor AWS-NR6-003. Dasselbe Muster wurde bereits im nr5-Dossier für AWS-NR5-003 vermerkt. Azure- und GCP-Module sind numerisch aufsteigend (001–004) geordnet.
2. AWS-NR6-001 (`CheckCloudTrailLogIntegrity`) erzeugt genau ein kombiniertes Positiv-Finding je Trail, das sowohl Zustellungs- als auch (falls Log-File-Validation aktiv) Digest-Frische voraussetzt (`delivery_fresh and digest_fresh`). Fehlt bei einem aktiv loggenden Trail (`IsLogging=True`) der Wert `LatestDeliveryTime` (`last_delivery` falsy), bleibt `delivery_fresh` auf seinem Initialwert `False` stehen; da der Mangel-Finding-Zweig für Zustellung nur innerhalb von `if last_delivery:` ausgelöst wird, entsteht für diesen Trail weder ein Mangel- noch ein Positiv-Finding und auch kein `CheckError` — der Trail erscheint im Scan-Ergebnis für diesen Check nicht.
3. AWS-NR6-001: Das `description`-Klassenattribut wird mit einem f-String zusammengesetzt, der den Modulkonstanten-Wert `MAX_DELIVERY_AGE_HOURS` zur Klassendefinitionszeit einsetzt — abweichend vom sonst im Repo überwiegenden Muster statischer `description`-Strings.
4. AWS-NR6-001: Der `expected_state`-Text des kombinierten Positiv-Findings ("Log-Zustellung innerhalb der letzten 24 Stunden") bezieht sich nur auf die Zustellungsfrische, nicht auf die Digest-Frische, obwohl das Finding genau dann erzeugt wird, wenn beide Bedingungen zutreffen.
5. AWS-NR6-001: Der `CheckError`, der bei einem Fehler auf Trail-Ebene (innerer try/except um `get_trail_status`) erzeugt wird, verwendet `error_type="AWSClientError"`; der `CheckError` für einen Fehler beim äußeren `describe_trails()`-Aufruf verwendet dagegen `error_type="CheckError"` — innerhalb derselben Datei werden für vergleichbare AWS-API-Fehler zwei unterschiedliche `error_type`-Werte verwendet.
6. AWS-NR6-002 (`CheckConfigRulesCompliance`): Dieselbe `expected_state`-Zeichenkette ("AWS Config Rules konfiguriert für automatisierte Compliance-Bewertung") wird für das Positiv-Finding und für beide inhaltlich unterschiedlichen Mangel-Findings verwendet ("Keine AWS Config Rules konfiguriert" mit `current_state={"config_rules_count": 0}` vs. "AWS Config nicht aktiviert" mit `current_state={"config_enabled": False}`).
7. AWS-NR6-002: Der Aufruf `config_client.describe_compliance_by_config_rule()` und die daraus ermittelte Anzahl NON_COMPLIANT-Regeln fließen ausschließlich in `logger.info`/`logger.warning`-Aufrufe ein, nicht in ein Finding, `current_state` oder `audit_evidence`; scheitert dieser Aufruf, wird das nur mit `logger.warning` protokolliert, ohne `CheckError`.
8. AWS-NR6-003 (`CheckSecurityHubComplianceScore`): Weder `description` noch Klassen-Docstring werden durch eine im Code tatsächlich abgefragte Compliance-Score-Kennzahl gedeckt — der Code ruft keinen Score-Wert ab, sondern zählt Findings mit `ComplianceStatus=FAILED` (`get_findings(..., MaxResults=100)`) und wertet `<=20` als Positivnachweis; eine mögliche Untererfassung durch die `MaxResults=100`-Begrenzung wird in keinem Finding-Text erwähnt.
9. AWS-NR6-003: Der `expected_state`-Text unterscheidet sich zwischen dem Mangel-Finding "Security Hub nicht aktiviert" ("Security Hub aktiviert mit Compliance-Score ≥80%") und den beiden anderen Findings desselben Checks ("Security Hub Compliance-Score ≥80% (maximal 20 fehlgeschlagene Findings)").
10. AWS-NR6-004 (`CheckCloudWatchLogRetention`) verwendet für Positiv- und Mangel-Pfad exakt dasselbe `audit_evidence`-Template (`f"DescribeLogGroups: retentionInDays={retention} for {lg_name}"`) — ein bereits im nr5-Dossier für mehrere Checks vermerktes Muster.
11. Klassendocstrings sind sprachlich uneinheitlich: Alle vier AWS-Klassen haben englische Docstrings ("Check that..."). Abweichend vom in den nr1-, nr3- und nr5-Dossiers vermerkten Muster ("Azure-Klassen haben keinen Klassendocstring") haben hier alle vier Azure-Klassen ebenfalls einen (englischen) Klassendocstring. Alle vier GCP-Klassen haben deutsche Docstrings ("Prüft ob...").
12. Keine der 12 Check-Klassen definiert ein Klassenattribut `severity` oder `iso_27001_ref` — beide werden pro `Finding()`/`compliant_finding()`-Aufruf als Parameter übergeben, jeweils innerhalb eines Checks konsistent (Ausnahmen siehe Punkte 6 und 9, die `expected_state` statt `severity`/`iso27001_control` betreffen).
13. `CheckError()`-Aufrufe unterscheiden sich zwischen Providern: AWS übergibt nur `message`/`error_type`; Azure übergibt zusätzlich `check_id` und `region="global"`; GCP übergibt nur `message`/`error_type` (ohne `check_id`) — dasselbe Muster wie in den bereits vorliegenden nr1-, nr3- und nr5-Dossiers vermerkt.
14. AZ-NR6-002 (`CheckPolicyComplianceState`): Liefert `list_query_results_for_subscription()` eine leere Ergebnisliste, wird für diese Subscription weder ein Positiv- noch ein Mangel-Finding erzeugt (weder die Bedingung `query_results and not non_compliant` noch `non_compliant` trifft zu) und kein `CheckError` — die Subscription erscheint im Scan-Ergebnis für diesen Check nicht.
15. AZ-NR6-003 (`CheckLogRetention`): Der `expected_state`-Text unterscheidet sich zwischen dem Mangel-Finding "Keine Log Analytics Workspaces" ("Log Analytics Workspace mit Retention ≥ 365 Tage") und dem Mangel-Finding "Log Retention unter 365 Tage"/dem Positivnachweis ("Retention ≥ 365 Tage") innerhalb desselben check_id.
16. AZ-NR6-003: `remediation_effort` unterscheidet sich zwischen den beiden Mangel-Findings desselben Checks: "Keine Log Analytics Workspaces" = MEDIUM, "Log Retention unter 365 Tage" = LOW.
17. AZ-NR6-003: Fehlt `ws.retention_in_days` (None), wird im Code der Wert 30 als Ersatzwert angenommen (`retention = ws.retention_in_days or 30`) und als tatsächlicher `retention_in_days`-Wert in `current_state`/`audit_evidence` gemeldet; ein "nicht gesetzt"-Zustand wird nicht gesondert ausgewiesen — abweichend von AWS-NR6-004, wo `None` explizit als "unbegrenzt" und als Positivnachweis-Zustand behandelt wird.
18. AZ-NR6-004 (`CheckDiagnosticSettings`): Einzelne fehlgeschlagene `diagnostic_settings.list()`-Aufrufe je Ressource werden mit `except Exception: pass` verschluckt; die betroffene Ressource zählt weder als "mit" noch als "ohne" Diagnostic Settings. Sind alle kritischen Ressourcen einer Subscription auf diese Weise nicht abfragbar (`resources_checked < len(critical_resources)` und `resources_without_diag` bleibt leer), wird für die Subscription weder ein Positiv- noch ein Mangel-Finding erzeugt und kein `CheckError`.
19. AZ-NR6-004: `CRITICAL_RESOURCE_TYPES` ist eine im Tool gepflegte, feste Liste von vier Ressourcentypen (KeyVault, SQL-Server, Storage-Account, NSG); die eigene pruefgrenzen-Angabe weist selbst darauf hin, dass die Auswahl kritischer Ressourcen "eine organisatorische Festlegung" sei.
20. GCP-NR6-001 (`CheckAuditLogIntegrity`): Der Code prüft laut eigenem Kommentar ausdrücklich nur, ob ein Sink in einen Storage-Bucket exportiert ("Locked retention must be verified separately but having a sink to a bucket is the baseline requirement"); ob die Aufbewahrungsrichtlinie des Ziel-Buckets tatsächlich gesperrt ("locked") ist, wird nicht abgefragt — Check-Titel, description, expected_state und Mangel-Finding-Text sprechen dagegen durchgehend von "gesperrter Aufbewahrungsrichtlinie"/"gesperrten Retention-Buckets".
21. GCP-NR6-002 (`CheckSecurityHealthAnalytics`) und GCP-NR6-003 (`CheckPolicyIntelligence`): Der reine API-Erfolg von `list_findings()` bzw. `recommendations.list()` wird unabhängig von der Anzahl zurückgegebener Elemente (auch bei 0 Treffern) als Positivnachweis gewertet; die Trefferzahl fließt nur in `current_state`/`audit_evidence` ein, nicht in die Positiv-/Mangel-Entscheidung.
22. GCP-NR6-002/GCP-NR6-003: Die Fallunterscheidung zwischen Mangel-Finding und `CheckError` erfolgt jeweils über Substring-Matching auf den kleingeschriebenen Exception-Text (`"permission"`, `"403"`, `"not enabled"`). GCP-NR6-004 (`CheckMonitoringDashboards`) hat keine solche Fallunterscheidung — dort führt jede Exception beim API-Aufruf zu einem `CheckError`, nie zu einem Mangel-Finding.
23. Granularität der Findings ist zwischen den Providern innerhalb dieses Batches uneinheitlich: AWS erzeugt bei NR6-001 und NR6-004 je ein Finding pro Einzelressource (Trail/Log Group), bei NR6-002 und NR6-003 je ein aggregiertes Finding pro Region; Azure erzeugt bei AZ-NR6-001, -002 und -004 je ein aggregiertes Finding pro Subscription, bei AZ-NR6-003 je ein Finding pro Einzel-Workspace (plus ein separates aggregiertes Finding bei fehlenden Workspaces); GCP erzeugt bei allen vier Checks (GCP-NR6-001 bis -004) je ein aggregiertes Finding pro Projekt.
24. Alle drei Module (AWS/Azure/GCP) definieren `BSIG_30_TEXT` mit wortidentischem Text (aus denselben drei Teilstrings zusammengesetzt) — anders als bei `ISO_CONTROL`/inline-ISO-Literalen, die je Provider und teils je Check variieren (siehe Modul-Konstanten-Abschnitt und Punkte 5/6/9 oben sowie die in nr5 vermerkten Sprachunterschiede Englisch/Deutsch bei ISO-27001-Texten).
