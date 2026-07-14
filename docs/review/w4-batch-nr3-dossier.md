# W4 Batch-Review-Dossier — §30 Abs. 2 Nr. 3 BSIG (Aufrechterhaltung des Betriebs)

> Mechanisch extrahiert am 2026-07-12 (Worker, ohne rechtliche Bewertung).
> Prüfgegenstand für: Gründer + Agent legal-reviewer (ADR-0018).

Quelldateien:
- `nis2scan/engine/providers/aws/checks/nr3_bcm.py`
- `nis2scan/engine/providers/azure/checks/nr3_bcm.py`
- `nis2scan/engine/providers/gcp/checks/nr3_bcm.py`

Ist-Zahl erfasster Checks: **21** (AWS: 7, Azure: 7, GCP: 7) — entspricht der erwarteten Zahl.

## Modul-Konstanten je Provider

### AWS (`nr3_bcm.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 3 — Aufrechterhaltung des Betriebs (BCM) checks for AWS.

  Checks backup retention, versioning, and data protection configurations.
  ```
- `BSIG_30_NR = 3`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 3 BSIG — Aufrechterhaltung des Betriebs, wie Backup-Management und Wiederherstellung nach einem Notfall, und Krisenmanagement"
- `ISO_CONTROL_BACKUP` (wörtlich): "A.8.13 Information backup"
- `ISO_CONTROL_AVAILABILITY` (wörtlich): "A.5.29 ICT readiness for business continuity"
- `RDS_MIN_BACKUP_RETENTION_DAYS = 7`

### Azure (`nr3_bcm.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 3 — Aufrechterhaltung des Betriebs (BCM) checks for Azure.

  Checks Backup Vaults, SQL Backup Retention, Geo-Redundant Storage, Availability Zones,
  Site Recovery, Immutable Blob Storage, and Traffic Manager / Front Door.
  ```
- `BSIG_30_NR = 3`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 3 BSIG — Aufrechterhaltung des Betriebs, wie Backup-Management und Wiederherstellung nach einem Notfall, und Krisenmanagement"
- Kein Modul-Äquivalent zu `ISO_CONTROL_BACKUP`/`ISO_CONTROL_AVAILABILITY`. `MIN_RETENTION_DAYS = 7` ist als Klassenattribut von `CheckSqlBackupRetention` definiert (nicht auf Modulebene).

### GCP (`nr3_bcm.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 3 — Aufrechterhaltung des Betriebs & Backup-Management checks for GCP.

  Checks Cloud SQL Backups, GCS Versioning, GCS Retention Policies, Multi-Zone Deployments,
  Disk Snapshot Schedules, Cloud SQL High Availability, and DNS Health Checks.
  ```
- `BSIG_30_NR = 3`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 3 BSIG — Aufrechterhaltung des Betriebs, wie Backup-Management und Wiederherstellung nach einem Notfall, und Krisenmanagement"
- Kein Modul-Äquivalent zu `ISO_CONTROL_BACKUP`/`ISO_CONTROL_AVAILABILITY`.

---

## Checks

### AWS-NR3-001 — RDS Backup Retention

Klassen-Docstring (wörtlich): "Check that all RDS instances have backup retention ≥ 7 days."

| Feld | Wert |
|---|---|
| Klasse | `CheckRdsBackupRetention` |
| description | (f-String) `f"Prüft ob alle RDS-Instanzen eine Backup-Aufbewahrung von mindestens {RDS_MIN_BACKUP_RETENTION_DAYS} Tagen konfiguriert haben."` → "Prüft ob alle RDS-Instanzen eine Backup-Aufbewahrung von mindestens 7 Tagen konfiguriert haben." |
| severity | HIGH (Mangel-Pfad, inline im `Finding()`-Aufruf, kein Klassenattribut) |
| iso27001_control | `ISO_CONTROL_BACKUP` = "A.8.13 Information backup" (identisch in Positiv- und Mangel-Pfad) |
| required_permissions | `["rds:DescribeDBInstances"]` |
| pruefgrenzen | "Prüft nur die konfigurierte Backup-Aufbewahrung der RDS-Instanzen. Nicht geprüft werden Backup-Erfolg, Wiederherstellbarkeit und Datenbanken außerhalb von RDS." |
| Prüflogik (deskriptiv) | `rds.describe_db_instances()` (paginiert) je Region; `BackupRetentionPeriod` jeder DB-Instanz wird gegen den Schwellwert 7 verglichen — `>= 7` ergibt Positivnachweis pro Instanz, `< 7` ergibt Mangel-Finding pro Instanz. |

**Finding-Texte (Mangel-Pfad):**
- title: "RDS Backup-Aufbewahrung zu kurz"
- description (Template): `f"Die RDS-Instanz '{db_id}' hat eine Backup-Aufbewahrung von nur {retention} Tagen. Mindestens {RDS_MIN_BACKUP_RETENTION_DAYS} Tage sind für Business Continuity erforderlich."`
- expected_state (Template): `f"BackupRetentionPeriod >= {RDS_MIN_BACKUP_RETENTION_DAYS} Tage"`
- remediation (Template): `"Erhöhen Sie die Backup-Aufbewahrungsfrist: aws rds modify-db-instance --db-instance-identifier <id> --backup-retention-period " + f"{RDS_MIN_BACKUP_RETENTION_DAYS}" + " --apply-immediately"`
- remediation_effort: LOW
- audit_evidence (Template): `f"DescribeDBInstances: BackupRetentionPeriod={retention} for {db_id}"`

**Positivnachweis (compliant_finding):**
- title: "RDS Backup-Aufbewahrung ausreichend"
- description (Template): `f"Die RDS-Instanz '{db_id}' hat eine Backup-Aufbewahrung von {retention} Tagen (Minimum: {RDS_MIN_BACKUP_RETENTION_DAYS})."`
- expected_state (Template): `f"BackupRetentionPeriod >= {RDS_MIN_BACKUP_RETENTION_DAYS} Tage"`
- audit_evidence (Template): `f"DescribeDBInstances: BackupRetentionPeriod={retention} for {db_id}"`

---

### AWS-NR3-002 — S3 Bucket Versioning

Klassen-Docstring (wörtlich): "Check that all S3 buckets have versioning enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckS3Versioning` |
| description | "Prüft ob alle S3-Buckets Versionierung aktiviert haben." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL_BACKUP` = "A.8.13 Information backup" (identisch in beiden Pfaden) |
| required_permissions | `["s3:ListAllMyBuckets", "s3:GetBucketVersioning", "s3:GetBucketLocation"]` |
| pruefgrenzen | "Prüft nur den Versioning-Status der Buckets. Nicht geprüft werden Lifecycle-Regeln, die alte Versionen löschen, und ob Versioning als Wiederherstellungsweg tatsächlich trägt." |
| Prüflogik (deskriptiv) | `s3.list_buckets()`, danach je Bucket `get_bucket_versioning()` und `get_bucket_location()`; bei `Status == "Enabled"` Positivnachweis, bei jedem anderen Status (inkl. "Disabled") Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "S3-Bucket ohne Versionierung"
- description (wörtlich): "Der S3-Bucket hat keine Versionierung aktiviert. Ohne Versionierung können gelöschte oder überschriebene Objekte nicht wiederhergestellt werden."
- expected_state: "Versionierung aktiviert (Status=Enabled)"
- remediation: "Aktivieren Sie die Versionierung: aws s3api put-bucket-versioning --bucket <name> --versioning-configuration Status=Enabled"
- remediation_effort: LOW
- audit_evidence (Template): `f"GetBucketVersioning: Status={status} for bucket"` (kein Bucket-Name im Text interpoliert, nur der Status)

**Positivnachweis (compliant_finding):**
- title: "S3-Bucket mit Versionierung"
- description (Template): `f"Der S3-Bucket '{bucket_name}' hat Versionierung aktiviert — gelöschte oder überschriebene Objekte sind wiederherstellbar."`
- expected_state: "Versionierung aktiviert (Status=Enabled)"
- audit_evidence (Template): `f"GetBucketVersioning: Status=Enabled for {bucket_name}"`

---

### AWS-NR3-003 — S3 Object Lock

Klassen-Docstring (wörtlich): "Check that critical S3 buckets have Object Lock enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckS3ObjectLock` |
| description | "Prüft ob kritische S3-Buckets Object Lock für unveränderlichen Datenschutz aktiviert haben." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL_BACKUP` = "A.8.13 Information backup" (identisch in beiden Pfaden) |
| required_permissions | `["s3:ListAllMyBuckets", "s3:GetBucketObjectLockConfiguration", "s3:GetBucketLocation"]` |
| pruefgrenzen | "Prüft nur, ob Object Lock auf Buckets aktiviert ist. Nicht geprüft werden Retention-Modus und -Dauer je Objekt. Object Lock ist nur für Unveränderlichkeits-Anforderungen relevant — fehlendes Object Lock ist nicht per se ein Mangel für jedes Bucket." |
| Prüflogik (deskriptiv) | `s3.list_buckets()`, danach je Bucket `get_object_lock_configuration()`; wirft der Aufruf keine Exception, gilt Object Lock als aktiviert (Positivnachweis, Antwortinhalt wird nicht weiter ausgewertet); wird eine Exception gefangen, deren Text "ObjectLockConfigurationNotFoundError" enthält, Mangel-Finding; andere Exceptions werden als `CheckError` erfasst. |

**Finding-Texte (Mangel-Pfad):**
- title: "S3-Bucket ohne Object Lock"
- description (wörtlich): "Der S3-Bucket hat kein Object Lock aktiviert. Ohne Object Lock sind Daten nicht vor Ransomware oder versehentlichem Löschen geschützt."
- expected_state: "Object Lock aktiviert (Schutz gegen Ransomware und versehentliches Löschen)"
- remediation (wörtlich): "Object Lock muss bei Bucket-Erstellung aktiviert werden. Erstellen Sie einen neuen Bucket: aws s3api create-bucket --bucket <name> --object-lock-enabled-for-bucket"
- remediation_effort: HIGH
- audit_evidence: "GetObjectLockConfiguration: not configured for bucket"

**Positivnachweis (compliant_finding):**
- title: "S3-Bucket mit Object Lock"
- description (Template): `f"Der S3-Bucket '{bucket_name}' hat Object Lock aktiviert — Daten sind gegen Ransomware und versehentliches Löschen geschützt."`
- expected_state: "Object Lock aktiviert (Schutz gegen Ransomware und versehentliches Löschen)"
- audit_evidence (Template): `f"GetObjectLockConfiguration: configured for {bucket_name}"`

---

### AWS-NR3-004 — RDS Multi-AZ Verfügbarkeit

Klassen-Docstring (wörtlich): "Check that RDS instances have Multi-AZ enabled for high availability."

| Feld | Wert |
|---|---|
| Klasse | `CheckRdsMultiAz` |
| description | "Prüft ob RDS-Instanzen mit Multi-AZ für Hochverfügbarkeit konfiguriert sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.5.29, A.8.14" (inline Literal, identisch in beiden Pfaden, ohne Beschreibungstext) |
| required_permissions | `["rds:DescribeDBInstances"]` |
| pruefgrenzen | "Prüft nur das Multi-AZ-Flag der RDS-Instanzen. Nicht geprüft werden Failover-Funktion, regionsübergreifende Redundanz und Nicht-RDS-Datenbanken." |
| Prüflogik (deskriptiv) | `rds.describe_db_instances()` (paginiert) je Region; DB-Instanzen mit gesetztem `DBClusterIdentifier` (Aurora-Cluster-Mitglieder) werden übersprungen; bei `MultiAZ == True` Positivnachweis, sonst Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "RDS-Instanz ohne Multi-AZ"
- description (Template, aus Teilstrings zusammengesetzt): "Die RDS-Instanz '{db_id}' ist nicht mit Multi-AZ konfiguriert. Ohne Multi-AZ ist keine automatische Failover-Funktion verfügbar."
- expected_state: "MultiAZ=True für Hochverfügbarkeit"
- remediation (Template, aus Teilstrings zusammengesetzt): "Aktivieren Sie Multi-AZ: aws rds modify-db-instance --db-instance-identifier <id> --multi-az --apply-immediately"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribeDBInstances: MultiAZ=False for {db_id}"`

**Positivnachweis (compliant_finding):**
- title: "RDS-Instanz mit Multi-AZ"
- description (Template): `f"Die RDS-Instanz '{db_id}' ist mit Multi-AZ konfiguriert — automatisches Failover ist verfügbar."`
- expected_state: "MultiAZ=True für Hochverfügbarkeit"
- audit_evidence (Template): `f"DescribeDBInstances: MultiAZ=True for {db_id}"`

---

### AWS-NR3-005 — AWS Backup Plans

Klassen-Docstring (wörtlich): "Check that AWS Backup Plans are configured for automated backups."

| Feld | Wert |
|---|---|
| Klasse | `CheckBackupPlans` |
| description | "Prüft ob AWS Backup Plans für automatisierte Datensicherung konfiguriert sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.8.13" (inline Literal, identisch in beiden Pfaden, bloßer Kontrollcode ohne Beschreibungstext) |
| required_permissions | `["backup:ListBackupPlans"]` |
| pruefgrenzen | "Prüft nur die Existenz von AWS-Backup-Plänen. Nicht geprüft werden Ressourcen-Zuordnung (was wird gesichert?), Backup-Erfolg und Wiederherstellungstests. Backup-Lösungen außerhalb von AWS Backup werden nicht erkannt." |
| Prüflogik (deskriptiv) | `backup_client.list_backup_plans()` je Region; bei mindestens einem Plan Positivnachweis pro Region (aggregiert, resource_id = ARN des ersten gefundenen Plans), bei keinem Plan Mangel-Finding pro Region. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine AWS Backup Plans konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "In der Region '{region}' sind keine AWS Backup Plans konfiguriert. Ohne Backup Plans ist keine automatisierte Datensicherung gewährleistet."
- expected_state: "Mindestens ein AWS Backup Plan konfiguriert"
- remediation (Template, aus Teilstrings zusammengesetzt): "Erstellen Sie einen AWS Backup Plan: aws backup create-backup-plan --backup-plan '<plan-json>'. Nutzen Sie die AWS Console für eine geführte Einrichtung."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"ListBackupPlans: no backup plans in region {region}"`

**Positivnachweis (compliant_finding):**
- title: "AWS Backup Plans konfiguriert"
- description (Template): `f"In der Region '{region}' sind {len(plans)} AWS Backup Plans konfiguriert — automatisierte Datensicherung ist eingerichtet."`
- expected_state: "Mindestens ein AWS Backup Plan konfiguriert"
- audit_evidence (Template): `f"ListBackupPlans: {len(plans)} backup plan(s) in region {region}"`
- resource_id: `plans[0].get("BackupPlanArn", f"arn:aws:backup:{region}:{session.account_id}:*")` — nur der erste gefundene Plan wird referenziert, auch wenn mehrere existieren.

---

### AWS-NR3-006 — EBS Snapshot Verschlüsselung

Klassen-Docstring (wörtlich): "Check that EBS volumes have regular, encrypted snapshots."

| Feld | Wert |
|---|---|
| Klasse | `CheckEbsSnapshotEncryption` |
| description | "Prüft ob EBS-Volumes regelmäßige, verschlüsselte Snapshots haben." |
| severity | MEDIUM (beide Mangel-Finding-Varianten dieses Checks, inline) |
| iso27001_control | "A.8.13, A.8.24" (inline Literal, in allen drei Finding-Varianten identisch, ohne Beschreibungstext) |
| required_permissions | `["ec2:DescribeVolumes", "ec2:DescribeSnapshots"]` |
| pruefgrenzen | "Prüft nur das Verschlüsselungs-Flag vorhandener EBS-Snapshots. Nicht geprüft werden Snapshot-Aktualität, Vollständigkeit der Sicherungsabdeckung und Wiederherstellbarkeit." |
| Prüflogik (deskriptiv) | `ec2.describe_volumes()` (paginiert) je Region; für Volumes im Zustand "in-use" oder "available" wird `ec2.describe_snapshots()` gefiltert nach `volume-id` aufgerufen; ohne Treffer Mangel-Finding ("ohne Snapshots"); bei Treffern wird der nach `StartTime` neueste Snapshot auf `Encrypted` geprüft — `True` ergibt Positivnachweis, `False` ergibt ein zweites, inhaltlich anderes Mangel-Finding ("nicht verschlüsselt"). |

**Finding-Texte (Mangel-Pfad, Variante 1 — keine Snapshots vorhanden):**
- title: "EBS-Volume ohne Snapshots"
- description (Template, aus Teilstrings zusammengesetzt): "Das EBS-Volume hat keine Snapshots. Ohne regelmäßige Snapshots ist keine Wiederherstellung möglich."
- expected_state: "Mindestens ein verschlüsselter Snapshot vorhanden"
- remediation (Template, aus Teilstrings zusammengesetzt): "Erstellen Sie verschlüsselte Snapshots: aws ec2 create-snapshot --volume-id <id> --encrypted. Nutzen Sie AWS Backup für automatisierte Snapshot-Pläne."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribeSnapshots: no snapshots for {vol_id}"`
- current_state: `{"snapshots": 0, "volume_state": state}`

**Finding-Texte (Mangel-Pfad, Variante 2 — neuester Snapshot unverschlüsselt):**
- title: "EBS-Snapshot nicht verschlüsselt"
- description (Template, aus Teilstrings zusammengesetzt): "Der neueste Snapshot des EBS-Volumes ist nicht verschlüsselt. Unverschlüsselte Snapshots gefährden die Vertraulichkeit der Daten."
- expected_state: "Neuester Snapshot verschlüsselt (Encrypted=True)"
- remediation: identisch zur Variante 1 (dasselbe Template)
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribeSnapshots: latest snapshot Encrypted=False for {vol_id}"`
- current_state: `{"snapshot_id": latest.get("SnapshotId"), "encrypted": False, "volume_state": state}`

**Positivnachweis (compliant_finding):**
- title: "EBS-Volume mit verschlüsselten Snapshots"
- description (Template): `f"Das EBS-Volume '{vol_id}' hat {len(snaps)} Snapshot(s); der neueste ist verschlüsselt."`
- expected_state: "Neuester Snapshot verschlüsselt (Encrypted=True)"
- audit_evidence (Template): `f"DescribeSnapshots: latest snapshot Encrypted=True for {vol_id}"`
- current_state: `{"snapshot_id": latest.get("SnapshotId"), "encrypted": True, "snapshots": len(snaps)}`

---

### AWS-NR3-007 — Route 53 Health Checks

Klassen-Docstring (wörtlich): "Check that Route 53 Health Checks are configured for availability monitoring."

| Feld | Wert |
|---|---|
| Klasse | `CheckRoute53HealthChecks` |
| description | "Prüft ob Route 53 Health Checks für die Überwachung der Verfügbarkeit kritischer Endpunkte konfiguriert sind." |
| severity | LOW (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL_AVAILABILITY` = "A.5.29 ICT readiness for business continuity" (identisch in beiden Pfaden) |
| required_permissions | `["route53:ListHealthChecks"]` |
| pruefgrenzen | "Prüft nur die Existenz von Route-53-Health-Checks. Nicht geprüft wird, ob kritische Endpunkte abgedeckt sind und ob Failover-Routing konfiguriert ist. Externes Monitoring außerhalb von Route 53 wird nicht erkannt." |
| Prüflogik (deskriptiv) | `route53.list_health_checks()` (globaler Service, Client-Region "us-east-1"); bei mindestens einem Health Check Positivnachweis (aggregiert über den gesamten Account, resource_id referenziert nur den ersten gefundenen Health Check), bei keinem Health Check Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Route 53 Health Checks konfiguriert"
- description (wörtlich): "Es sind keine Route 53 Health Checks konfiguriert. Ohne Health Checks fehlt die automatische Überwachung der Verfügbarkeit kritischer Endpunkte und DNS-Failover."
- expected_state: "Mindestens ein Route 53 Health Check für Verfügbarkeitsüberwachung"
- remediation: "Erstellen Sie Route 53 Health Checks: aws route53 create-health-check --caller-reference <ref> --health-check-config Type=HTTPS,FullyQualifiedDomainName=<domain>,Port=443"
- remediation_effort: LOW
- audit_evidence: "ListHealthChecks returned 0 health checks"

**Positivnachweis (compliant_finding):**
- title: "Route 53 Health Checks konfiguriert"
- description (Template): `f"Es sind {len(health_checks)} Route 53 Health Checks konfiguriert — die Verfügbarkeit kritischer Endpunkte wird überwacht."`
- expected_state: "Mindestens ein Route 53 Health Check für Verfügbarkeitsüberwachung"
- audit_evidence (Template): `f"ListHealthChecks returned {len(health_checks)} health check(s)"`
- resource_id (Template): `f"arn:aws:route53:::healthcheck/{health_checks[0].get('Id', '*')}"`

---

### AZ-NR3-001 — Azure Backup Vaults mit Policies

Klassen-Docstring (wörtlich): "Check that Azure Backup Vaults with backup policies exist."

| Feld | Wert |
|---|---|
| Klasse | `CheckBackupVaults` |
| description | "Prüft ob Azure Recovery Services Vaults mit Backup-Policies konfiguriert sind." |
| severity | HIGH (beide Mangel-Finding-Varianten, inline) |
| iso27001_control | "A.8.13 Informationssicherung" (inline Literal, identisch in allen drei Finding-Varianten) |
| required_permissions | `["Microsoft.RecoveryServices/vaults/read", "Microsoft.RecoveryServices/vaults/backupPolicies/read"]` |
| pruefgrenzen | "Prüft nur Recovery-Services-Vaults und deren Policies. Backup-Erfolg, Abdeckung aller kritischen Ressourcen und Restore-Tests werden nicht geprüft." |
| Prüflogik (deskriptiv) | `RecoveryServicesClient.vaults.list_by_subscription_id()` je Subscription; ohne Vaults Mangel-Finding; bei vorhandenen Vaults wird je Vault `RecoveryServicesBackupClient.backup_policies.list()` abgefragt (Fehler beim Abfragen einzelner Vaults werden mit `except Exception: pass` verworfen, kein Eintrag in `errors`); sind alle erfolgreich geprüften Vaults mit mindestens einer Policy versehen, Positivnachweis (aggregiert je Subscription); gibt es geprüfte Vaults ohne Policy, Mangel-Finding mit Liste der betroffenen Vault-Namen. |

**Finding-Texte (Mangel-Pfad, Variante 1 — keine Vaults):**
- title: "Keine Backup Vaults konfiguriert"
- description (Template): `f"Subscription {sub_id} hat keine Recovery Services Vaults. Ohne Backup-Infrastruktur ist keine Wiederherstellung nach einem Notfall möglich."`
- expected_state: "Mindestens ein Recovery Services Vault mit Backup-Policies"
- remediation: "Erstellen Sie einen Recovery Services Vault: az backup vault create --resource-group <rg> --name <vault-name> --location <loc>"
- remediation_effort: MEDIUM
- audit_evidence: "vaults.list_by_subscription_id() returned 0 vaults"

**Finding-Texte (Mangel-Pfad, Variante 2 — Vaults ohne Policies):**
- title: "Backup Vaults ohne Policies"
- description (Template): `f"Subscription {sub_id} hat Vaults ohne Backup-Policies: {', '.join(vaults_without_policies)}. Ohne Policies werden keine Backups erstellt."`
- expected_state: "Alle Backup Vaults mit mindestens einer Backup-Policy"
- remediation: "Erstellen Sie Backup-Policies für Ihre Vaults: az backup policy create --vault-name <vault> --resource-group <rg> --name <policy-name> --policy <policy-json>"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"Found {len(vaults)} vaults, {len(vaults_without_policies)} without policies"`

**Positivnachweis (compliant_finding):**
- title: "Backup Vaults mit Policies"
- description (Template): `f"Subscription {sub_id} hat {len(vaults)} Recovery Services Vault(s); alle geprüften Vaults haben Backup-Policies."`
- expected_state: "Mindestens ein Recovery Services Vault mit Backup-Policies"
- audit_evidence (Template): `f"Found {len(vaults)} vault(s), {vaults_checked} checked, all with policies"`

---

### AZ-NR3-002 — SQL DB Backup Retention ≥7 Tage

Klassen-Docstring (wörtlich): "Check that SQL Database backup retention is at least 7 days."

| Feld | Wert |
|---|---|
| Klasse | `CheckSqlBackupRetention` |
| description | "Prüft ob Azure SQL Datenbanken eine Backup-Aufbewahrung von mindestens 7 Tagen haben." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.8.13 Informationssicherung" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Sql/servers/read", "Microsoft.Sql/servers/databases/read", "Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies/read"]` |
| pruefgrenzen | "Prüft nur die konfigurierte Retention der SQL-Datenbank-Backups. Wiederherstellbarkeit wird nicht getestet." |
| Klassenattribut `MIN_RETENTION_DAYS` | `7` |
| Prüflogik (deskriptiv) | `SqlManagementClient.servers.list()`, je Server `databases.list_by_server()` (Datenbank mit Namen "master" wird übersprungen), je Datenbank `backup_short_term_retention_policies.list_by_database()` (Fehler werden mit `except Exception: pass` verworfen, kein Eintrag in `errors`); `retention_days >= 7` ergibt Positivnachweis pro Datenbank/Policy, `< 7` ergibt Mangel-Finding pro Datenbank/Policy. |

**Finding-Texte (Mangel-Pfad):**
- title: "SQL Backup Retention zu kurz"
- description (Template): `f"Datenbank {db.name} auf Server {server.name} in Subscription {sub_id} hat nur {policy.retention_days} Tage Backup-Aufbewahrung."`
- expected_state (Template): `f"Backup-Retention ≥ {self.MIN_RETENTION_DAYS} Tage"`
- remediation (Template): `f"Erhöhen Sie die Backup-Aufbewahrung: az sql db str-policy set --resource-group {rg_name} --server {server.name} --name {db.name} --retention-days {self.MIN_RETENTION_DAYS}"`
- remediation_effort: LOW
- audit_evidence (Template): `f"backup_short_term_retention_policies: retention_days={policy.retention_days}"`

**Positivnachweis (compliant_finding):**
- title: "SQL Backup Retention ausreichend"
- description (Template): `f"Datenbank {db.name} auf Server {server.name} hat {policy.retention_days} Tage Backup-Aufbewahrung (Minimum: {self.MIN_RETENTION_DAYS})."`
- expected_state (Template): `f"Backup-Retention ≥ {self.MIN_RETENTION_DAYS} Tage"`
- audit_evidence (Template): `f"backup_short_term_retention_policies: retention_days={policy.retention_days}"`

---

### AZ-NR3-003 — Geo-redundanter Speicher (GRS)

Klassen-Docstring (wörtlich): "Check that Storage Accounts use geo-redundant replication."

| Feld | Wert |
|---|---|
| Klasse | `CheckGeoRedundantStorage` |
| description | "Prüft ob Azure Storage Accounts geo-redundante Replikation verwenden." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.8.13 Informationssicherung" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Storage/storageAccounts/read"]` |
| pruefgrenzen | "Prüft nur die Redundanz-SKU der Storage Accounts. Ob GRS für die jeweilige Datenklasse erforderlich ist, ist eine organisatorische Entscheidung." |
| Klassenattribut `GEO_REDUNDANT_SKUS` | `{"Standard_GRS", "Standard_RAGRS", "Standard_GZRS", "Standard_RAGZRS"}` |
| Prüflogik (deskriptiv) | `StorageManagementClient.storage_accounts.list()` je Subscription; SKU-Name jedes Accounts wird gegen `GEO_REDUNDANT_SKUS` geprüft — sind alle Accounts geo-redundant, Positivnachweis (aggregiert je Subscription), sonst Mangel-Finding mit Liste der nicht-geo-redundanten Accounts inkl. SKU. |

**Finding-Texte (Mangel-Pfad):**
- title: "Storage Accounts ohne Geo-Redundanz"
- description (Template): `f"Subscription {sub_id} hat Storage Accounts ohne geo-redundante Replikation: {account_names}. Ohne Geo-Redundanz droht Datenverlust bei regionalem Ausfall."`
- expected_state: "Alle Storage Accounts mit GRS, RAGRS, GZRS oder RAGZRS"
- remediation: "Ändern Sie die Replikation auf geo-redundant: az storage account update --name <account> --resource-group <rg> --sku Standard_GRS"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"storage_accounts.list() returned {len(accounts)} accounts, {len(non_geo_accounts)} without geo-redundancy"`

**Positivnachweis (compliant_finding):**
- title: "Storage Accounts geo-redundant"
- description (Template): `f"Alle {len(accounts)} Storage Accounts in Subscription {sub_id} verwenden geo-redundante Replikation."`
- expected_state: "Alle Storage Accounts mit GRS, RAGRS, GZRS oder RAGZRS"
- audit_evidence (Template): `f"storage_accounts.list() returned {len(accounts)} accounts, all geo-redundant"`

---

### AZ-NR3-004 — Availability Zones für Produktion

Klassen-Docstring (wörtlich): "Check that VMs are deployed to Availability Zones."

| Feld | Wert |
|---|---|
| Klasse | `CheckAvailabilityZones` |
| description | "Prüft ob VMs in Availability Zones bereitgestellt sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.5.29 Informationssicherheit bei Störungen, A.8.14 Redundanz" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Compute/virtualMachines/read"]` |
| pruefgrenzen | "Prüft nur, ob VMs Availability Zones nutzen. Welche VMs produktionskritisch sind, kann der Scan nicht wissen — die Bewertung gilt allen VMs." |
| Prüflogik (deskriptiv) | `ComputeManagementClient.virtual_machines.list_all()` je Subscription; VMs ohne `zones`-Attribut werden gezählt — sind alle VMs zonenzugewiesen, Positivnachweis (aggregiert je Subscription), sonst Mangel-Finding mit Anzahl betroffener VMs. Bei 0 VMs insgesamt wird weder Positiv- noch Mangel-Finding erzeugt. |

**Finding-Texte (Mangel-Pfad):**
- title: "VMs ohne Availability Zones"
- description (Template): `f"Subscription {sub_id} hat {len(vms_without_zones)} von {len(vms)} VMs ohne Availability-Zone-Zuweisung. Ohne Zonen-Verteilung fehlt Ausfallsicherheit bei Rechenzentrumsausfall."`
- expected_state: "Alle Produktions-VMs in Availability Zones"
- remediation: "Stellen Sie VMs in Availability Zones bereit. Bestehende VMs müssen neu erstellt werden: az vm create --zone 1 --name <vm> ..."
- remediation_effort: HIGH
- audit_evidence (Template): `f"virtual_machines.list_all() returned {len(vms)} VMs, {len(vms_without_zones)} without zone assignment"`

**Positivnachweis (compliant_finding):**
- title: "VMs in Availability Zones"
- description (Template): `f"Alle {len(vms)} VMs in Subscription {sub_id} sind Availability Zones zugewiesen."`
- expected_state: "Alle Produktions-VMs in Availability Zones"
- audit_evidence (Template): `f"virtual_machines.list_all() returned {len(vms)} VMs, all zone-assigned"`

---

### AZ-NR3-005 — Azure Site Recovery konfiguriert

Klassen-Docstring (wörtlich): "Check that Azure Site Recovery is configured for disaster recovery."

| Feld | Wert |
|---|---|
| Klasse | `CheckSiteRecovery` |
| description | "Prüft ob Azure Site Recovery für Disaster-Recovery-Szenarien konfiguriert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.5.30 IKT-Bereitschaft für Business Continuity" (inline Literal, identisch in beiden Pfaden; einzige Verwendung von A.5.30 im gesamten Nr.-3-Batch) |
| required_permissions | `["Microsoft.RecoveryServices/vaults/read"]` |
| pruefgrenzen | "Prüft nur, ob Site-Recovery-Replikation konfiguriert ist. DR-Failover-Tests und Wiederanlaufpläne sind organisatorisch nachzuweisen." |
| Prüflogik (deskriptiv) | `RecoveryServicesClient.vaults.list_by_subscription_id()` je Subscription; Vaults mit `properties.provisioning_state == "Succeeded"` werden als "asr_vaults" gezählt (kein direkter Abruf des tatsächlichen Replikationsstatus/ASR-Konfiguration) — bei mindestens einem solchen Vault Positivnachweis, sonst Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein Azure Site Recovery konfiguriert"
- description (Template): `f"Subscription {sub_id} hat keine Recovery Services Vaults für Site Recovery. Ohne ASR fehlt ein automatisierter Disaster-Recovery-Plan."`
- expected_state: "Mindestens ein Recovery Services Vault mit Site Recovery"
- remediation: "Konfigurieren Sie Azure Site Recovery: az backup vault create --resource-group <rg> --name <vault> --location <loc> && Richten Sie Replikation für kritische VMs ein."
- remediation_effort: HIGH
- audit_evidence (Template): `f"vaults.list_by_subscription_id() returned {len(vaults)} vaults"`

**Positivnachweis (compliant_finding):**
- title: "Site Recovery Vault vorhanden"
- description (Template): `f"Subscription {sub_id} hat {len(asr_vaults)} aktive Recovery Services Vault(s) für Disaster-Recovery-Szenarien."`
- expected_state: "Mindestens ein Recovery Services Vault mit Site Recovery"
- audit_evidence (Template): `f"vaults.list_by_subscription_id() returned {len(asr_vaults)} active vault(s)"`

---

### AZ-NR3-006 — Immutable Blob Storage

Klassen-Docstring (wörtlich): "Check that immutable blob storage is configured for ransomware protection."

| Feld | Wert |
|---|---|
| Klasse | `CheckImmutableBlobStorage` |
| description | "Prüft ob Immutable Blob Storage für Ransomware-Schutz konfiguriert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.8.13 Informationssicherung" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Storage/storageAccounts/read", "Microsoft.Storage/storageAccounts/blobServices/containers/read"]` |
| pruefgrenzen | "Prüft nur Immutability-Policies auf Blob-Containern. Fehlende Unveränderlichkeit ist nur für entsprechende Aufbewahrungsanforderungen ein Mangel." |
| Prüflogik (deskriptiv) | `StorageManagementClient.storage_accounts.list()` je Subscription (bei 0 Accounts wird die Subscription übersprungen, kein Finding); je Account `blob_containers.list()` (Fehler pro Account werden mit `except Exception: pass` verworfen); wird für mindestens einen Container `immutability_policy` oder `immutable_storage_with_versioning` gefunden, Positivnachweis (aggregiert je Subscription, Suche bricht beim ersten Treffer ab), sonst Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein Immutable Blob Storage"
- description (Template): `f"Subscription {sub_id} hat keine Container mit Immutability-Policies. Ohne unveränderlichen Speicher sind Backups nicht vor Ransomware-Verschlüsselung geschützt."`
- expected_state: "Mindestens ein Container mit Immutability-Policy"
- remediation: "Aktivieren Sie Immutable Blob Storage: az storage container immutability-policy create --account-name <acc> --container-name <container> --period 365"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"Checked {len(accounts)} storage accounts, no immutable containers found"`

**Positivnachweis (compliant_finding):**
- title: "Immutable Blob Storage konfiguriert"
- description (Template): `f"Subscription {sub_id} hat mindestens einen Container mit Immutability-Policy — Backups sind vor Ransomware geschützt."`
- expected_state: "Mindestens ein Container mit Immutability-Policy"
- audit_evidence (Template): `f"Checked {len(accounts)} storage account(s), immutable container found"`

---

### AZ-NR3-007 — Traffic Manager / Front Door

Klassen-Docstring (wörtlich): "Check that Traffic Manager or Front Door exists for redundancy."

| Feld | Wert |
|---|---|
| Klasse | `CheckTrafficManagerFrontDoor` |
| description | "Prüft ob Azure Traffic Manager oder Front Door für Traffic-Redundanz vorhanden ist." |
| severity | LOW (Mangel-Pfad, inline) |
| iso27001_control | "A.8.14 Redundanz von Informationsverarbeitungseinrichtungen" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Network/trafficManagerProfiles/read", "Microsoft.Network/frontDoors/read"]` |
| pruefgrenzen | "Prüft nur die Existenz von Traffic Manager/Front Door. Andere Lastverteilungs- oder Failover-Lösungen werden nicht erkannt." |
| Prüflogik (deskriptiv) | `ResourceManagementClient.resources.list()` je Subscription; Ressourcen mit Typ in `{"Microsoft.Network/trafficManagerProfiles", "Microsoft.Network/frontDoors", "Microsoft.Cdn/profiles"}` werden gezählt — bei mindestens einer gefundenen Ressource Positivnachweis, sonst Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein Traffic Manager / Front Door"
- description (Template): `f"Subscription {sub_id} hat weder Traffic Manager, Front Door noch CDN konfiguriert. Ohne Traffic-Redundanz fehlt die Lastverteilung über mehrere Regionen."`
- expected_state: "Traffic Manager, Front Door oder CDN für Traffic-Redundanz"
- remediation: "Erstellen Sie ein Traffic Manager-Profil: az network traffic-manager profile create --name <tm> --resource-group <rg> --routing-method Performance"
- remediation_effort: MEDIUM
- audit_evidence: "resources.list() returned no Traffic Manager, Front Door, or CDN resources"

**Positivnachweis (compliant_finding):**
- title: "Traffic-Redundanz konfiguriert"
- description (Template): `f"Subscription {sub_id} hat {len(found_resources)} Ressource(n) für Traffic-Redundanz (Traffic Manager, Front Door oder CDN)."`
- expected_state: "Traffic Manager, Front Door oder CDN für Traffic-Redundanz"
- audit_evidence (Template): `f"resources.list() returned {len(found_resources)} redundancy resource(s)"`
- resource_type der Meldung ist immer `"Microsoft.Network/trafficManagerProfiles"`, auch wenn die tatsächlich gefundenen Ressourcen vom Typ Front Door oder CDN sind.

---

### GCP-NR3-001 — Cloud SQL automatische Backups aktiviert

Klassen-Docstring (wörtlich): "Prüft ob automatische Backups für Cloud SQL Instanzen aktiviert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckCloudSqlBackups` |
| description | "Prüft ob alle Cloud SQL Instanzen automatische Backups aktiviert haben." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.8.13 Datensicherung" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["cloudsql.instances.list"]` |
| pruefgrenzen | "Prüft nur das Backup-Flag der Cloud-SQL-Instanzen. Backup-Erfolg und Wiederherstellbarkeit werden nicht getestet." |
| Prüflogik (deskriptiv) | `sqladmin` (v1beta4) `instances().list()` je Projekt; `settings.backupConfiguration.enabled` je Instanz geprüft — `True` Positivnachweis, `False`/fehlend Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Cloud SQL Backup nicht aktiviert"
- description (Template, aus Teilstrings zusammengesetzt): "Cloud SQL Instanz {instance_name} in Projekt {project_id} hat keine automatischen Backups aktiviert. Ohne Backups droht Datenverlust bei Ausfällen."
- expected_state: "Automatische Backups für Cloud SQL aktiviert"
- remediation (Template): `"Aktivieren Sie automatische Backups: gcloud sql instances patch <INSTANCE_NAME> --backup-start-time=02:00 --project=<PROJECT_ID>"`
- remediation_effort: LOW
- audit_evidence (Template): `f"instances.list() instance {instance_name} backupConfiguration.enabled=false"`

**Positivnachweis (compliant_finding):**
- title: "Cloud SQL Backups aktiviert"
- description (Template): `f"Cloud SQL Instanz {instance_name} in Projekt {project_id} hat automatische Backups aktiviert."`
- expected_state: "Automatische Backups für Cloud SQL aktiviert"
- audit_evidence (Template): `f"instances.list() instance {instance_name} backupConfiguration.enabled=true"`

---

### GCP-NR3-002 — GCS Bucket-Versionierung aktiviert

Klassen-Docstring (wörtlich): "Prüft ob GCS Buckets Versionierung aktiviert haben."

| Feld | Wert |
|---|---|
| Klasse | `CheckGcsVersioning` |
| description | "Prüft ob Google Cloud Storage Buckets die Objekt-Versionierung für den Schutz vor versehentlichem Löschen aktiviert haben." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.8.13 Datensicherung" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["storage.buckets.list", "storage.buckets.get"]` |
| pruefgrenzen | "Prüft nur den Versionierungs-Status der Buckets. Lifecycle-Regeln, die alte Versionen löschen, werden nicht berücksichtigt." |
| Prüflogik (deskriptiv) | `storage.Client.list_buckets()` je Projekt; `bucket.versioning_enabled` je Bucket geprüft — `True` Positivnachweis, sonst Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "GCS Bucket ohne Versionierung"
- description (Template, aus Teilstrings zusammengesetzt): "Bucket {bucket.name} in Projekt {project_id} hat keine Objekt-Versionierung aktiviert. Ohne Versionierung können gelöschte Objekte nicht wiederhergestellt werden."
- expected_state: "Objekt-Versionierung für den Bucket aktiviert"
- remediation (Template): `"Aktivieren Sie die Versionierung: gcloud storage buckets update gs://<BUCKET_NAME> --versioning"`
- remediation_effort: LOW
- audit_evidence (Template): `f"bucket {bucket.name} versioning_enabled=false"`

**Positivnachweis (compliant_finding):**
- title: "GCS Bucket mit Versionierung"
- description (Template): `f"Bucket {bucket.name} in Projekt {project_id} hat Objekt-Versionierung aktiviert."`
- expected_state: "Objekt-Versionierung für den Bucket aktiviert"
- audit_evidence (Template): `f"bucket {bucket.name} versioning_enabled=true"`

---

### GCP-NR3-003 — GCS Bucket-Aufbewahrungsrichtlinie vorhanden

Klassen-Docstring (wörtlich): "Prüft ob GCS Buckets Aufbewahrungsrichtlinien konfiguriert haben."

| Feld | Wert |
|---|---|
| Klasse | `CheckGcsRetentionPolicy` |
| description | "Prüft ob Google Cloud Storage Buckets Aufbewahrungsrichtlinien (Retention Policies) für den Schutz vor vorzeitigem Löschen haben." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | "A.8.13 Datensicherung" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["storage.buckets.list", "storage.buckets.get"]` |
| pruefgrenzen | "Prüft nur die Existenz von Aufbewahrungsrichtlinien. Ob die Dauer den eigenen Anforderungen entspricht, ist organisatorisch festzulegen." |
| Prüflogik (deskriptiv) | `storage.Client.list_buckets()` je Projekt; `bucket.retention_policy is not None` je Bucket geprüft — vorhanden Positivnachweis, `None` Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "GCS Bucket ohne Aufbewahrungsrichtlinie"
- description (Template, aus Teilstrings zusammengesetzt): "Bucket {bucket.name} in Projekt {project_id} hat keine Aufbewahrungsrichtlinie. Ohne Retention Policy können Objekte jederzeit gelöscht werden."
- expected_state: "Aufbewahrungsrichtlinie mit angemessener Dauer konfiguriert"
- remediation (Template): `"Konfigurieren Sie eine Aufbewahrungsrichtlinie: gcloud storage buckets update gs://<BUCKET_NAME> --retention-period=365d"`
- remediation_effort: LOW
- audit_evidence (Template): `f"bucket {bucket.name} retention_policy=None"`

**Positivnachweis (compliant_finding):**
- title: "GCS Bucket mit Aufbewahrungsrichtlinie"
- description (Template): `f"Bucket {bucket.name} in Projekt {project_id} hat eine Aufbewahrungsrichtlinie konfiguriert."`
- expected_state: "Aufbewahrungsrichtlinie mit angemessener Dauer konfiguriert"
- audit_evidence (Template): `f"bucket {bucket.name} retention_policy configured"`

---

### GCP-NR3-004 — Multi-Zonen-Verteilung der Instanzen

Klassen-Docstring (wörtlich): "Prüft ob Compute-Instanzen über mehrere Zonen verteilt sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckMultiZoneDeployments` |
| description | "Prüft ob Compute Engine Instanzen über mehrere Verfügbarkeitszonen verteilt sind, um Hochverfügbarkeit sicherzustellen." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.5.29, A.8.14 Redundanz von Informationsverarbeitungseinrichtungen" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["compute.instances.list"]` |
| pruefgrenzen | "Prüft nur die Zonenverteilung der Compute-Instanzen. Welche Workloads produktionskritisch sind, kann der Scan nicht wissen." |
| Prüflogik (deskriptiv) | `compute_v1.InstancesClient.aggregated_list()` je Projekt; Zonen mit mindestens einer laufenden ("RUNNING") Instanz werden gesammelt — `>= 2` Zonen ergibt Positivnachweis (aggregiert je Projekt), genau `1` Zone ergibt Mangel-Finding; bei `0` Zonen (keine laufende Instanz im Projekt) wird weder Positiv- noch Mangel-Finding erzeugt (kein `else`-Zweig für diesen Fall im Code). |

**Finding-Texte (Mangel-Pfad):**
- title: "Instanzen nur in einer Zone"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat laufende Instanzen nur in einer einzigen Zone. Bei einem Zonenausfall sind alle Instanzen betroffen."
- expected_state: "Instanzen über mindestens zwei Verfügbarkeitszonen verteilt"
- remediation (Template, aus Teilstrings zusammengesetzt): "Verteilen Sie Instanzen über mehrere Zonen: gcloud compute instances create <NAME> --zone=<ZONE_B> --project=<PROJECT_ID> oder verwenden Sie Managed Instance Groups mit regionaler Verteilung"
- remediation_effort: HIGH
- audit_evidence (Template): `f"aggregated_list() found running instances in {len(zones_with_instances)} zone(s)"`

**Positivnachweis (compliant_finding):**
- title: "Instanzen über mehrere Zonen verteilt"
- description (Template): `f"Projekt {project_id} hat laufende Instanzen in {len(zones_with_instances)} Verfügbarkeitszonen."`
- expected_state: "Instanzen über mindestens zwei Verfügbarkeitszonen verteilt"
- audit_evidence (Template): `f"aggregated_list() found running instances in {len(zones_with_instances)} zone(s)"`

---

### GCP-NR3-005 — Geplante Disk-Snapshot-Richtlinien vorhanden

Klassen-Docstring (wörtlich): "Prüft ob geplante Disk-Snapshot-Richtlinien existieren."

| Feld | Wert |
|---|---|
| Klasse | `CheckDiskSnapshotSchedules` |
| description | "Prüft ob Resource Policies vom Typ SNAPSHOT für die automatische Erstellung von Disk-Snapshots konfiguriert sind." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | "A.8.13 Datensicherung" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["compute.resourcePolicies.list"]` |
| pruefgrenzen | "Prüft nur die Existenz von Snapshot-Zeitplänen. Snapshot-Erfolg und Wiederherstellbarkeit werden nicht getestet." |
| Prüflogik (deskriptiv) | `compute_v1.ResourcePoliciesClient.aggregated_list()` je Projekt; Policies mit gesetztem `snapshot_schedule_policy`-Feld werden gesucht (Suche bricht beim ersten Treffer ab) — mindestens eine gefunden Positivnachweis, keine gefunden Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine geplanten Snapshot-Richtlinien"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keine Resource Policies für geplante Disk-Snapshots. Ohne automatisierte Snapshots fehlt die regelmäßige Datensicherung."
- expected_state: "Mindestens eine geplante Snapshot-Richtlinie konfiguriert"
- remediation (Template): `"Erstellen Sie eine Snapshot-Richtlinie: gcloud compute resource-policies create snapshot-schedule <NAME> --project=<PROJECT_ID> --region=<REGION> --max-retention-days=30 --daily-schedule --start-time=02:00"`
- remediation_effort: LOW
- audit_evidence: "aggregated_list() found 0 snapshot schedule policies"

**Positivnachweis (compliant_finding):**
- title: "Geplante Snapshot-Richtlinien vorhanden"
- description (Template): `f"Projekt {project_id} hat mindestens eine Resource Policy für geplante Disk-Snapshots."`
- expected_state: "Mindestens eine geplante Snapshot-Richtlinie konfiguriert"
- audit_evidence: "aggregated_list() found >=1 snapshot schedule policy"

---

### GCP-NR3-006 — Cloud SQL Hochverfügbarkeit konfiguriert

Klassen-Docstring (wörtlich): "Prüft ob Cloud SQL Instanzen Hochverfügbarkeit konfiguriert haben."

| Feld | Wert |
|---|---|
| Klasse | `CheckCloudSqlHighAvailability` |
| description | "Prüft ob Cloud SQL Instanzen mit regionaler Hochverfügbarkeit (REGIONAL availability type) konfiguriert sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | "A.5.29 Informationssicherheit bei Störungen" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["cloudsql.instances.list"]` |
| pruefgrenzen | "Prüft nur das Hochverfügbarkeits-Flag der Cloud-SQL-Instanzen. Failover-Verhalten wird nicht getestet." |
| Prüflogik (deskriptiv) | `sqladmin` (v1beta4) `instances().list()` je Projekt; `settings.availabilityType` je Instanz geprüft (Default "ZONAL", falls Feld fehlt) — `"REGIONAL"` Positivnachweis, jeder andere Wert Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Cloud SQL ohne Hochverfügbarkeit"
- description (Template, aus Teilstrings zusammengesetzt): "Cloud SQL Instanz {instance_name} in Projekt {project_id} ist nicht für regionale Hochverfügbarkeit konfiguriert. Bei einem Zonenausfall ist die Datenbank nicht erreichbar."
- expected_state: "Cloud SQL Instanz mit availabilityType=REGIONAL"
- remediation (Template): `"Aktivieren Sie Hochverfügbarkeit: gcloud sql instances patch <INSTANCE_NAME> --availability-type=REGIONAL --project=<PROJECT_ID>"`
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"instances.list() instance {instance_name} availabilityType={availability_type}"`

**Positivnachweis (compliant_finding):**
- title: "Cloud SQL mit Hochverfügbarkeit"
- description (Template): `f"Cloud SQL Instanz {instance_name} in Projekt {project_id} ist für regionale Hochverfügbarkeit konfiguriert."`
- expected_state: "Cloud SQL Instanz mit availabilityType=REGIONAL"
- audit_evidence (Template): `f"instances.list() instance {instance_name} availabilityType=REGIONAL"`

---

### GCP-NR3-007 — Cloud DNS verwaltete Zonen vorhanden

Klassen-Docstring (wörtlich): "Prüft ob Cloud DNS verwaltete Zonen mit Routing-Richtlinien existieren."

| Feld | Wert |
|---|---|
| Klasse | `CheckDnsHealthChecks` |
| description | "Prüft ob Cloud DNS verwaltete Zonen für DNS-basiertes Failover und Health Checks konfiguriert sind." |
| severity | LOW (Mangel-Pfad, inline) |
| iso27001_control | "A.8.14 Redundanz von Informationsverarbeitungseinrichtungen" (inline Literal, identisch in beiden Pfaden) |
| required_permissions | `["dns.managedZones.list"]` |
| pruefgrenzen | "Prüft nur die Existenz verwalteter DNS-Zonen als Indiz für gesteuertes Failover. Externe DNS-Anbieter werden nicht erkannt." |
| Prüflogik (deskriptiv) | `dns.Client.list_zones()` je Projekt; bei mindestens einer verwalteten Zone Positivnachweis (aggregiert je Projekt), bei keiner Zone Mangel-Finding. Es wird ausschließlich die Existenz verwalteter Zonen geprüft, keine tatsächliche Health-Check- oder Failover-/Routing-Konfiguration innerhalb der Zone. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Cloud DNS verwalteten Zonen"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keine Cloud DNS verwalteten Zonen. Ohne DNS-Zonen können keine DNS-basierten Failover-Mechanismen genutzt werden."
- expected_state: "Mindestens eine Cloud DNS verwaltete Zone konfiguriert"
- remediation (Template): `"Erstellen Sie eine Cloud DNS Zone: gcloud dns managed-zones create <ZONE_NAME> --dns-name=<DNS_NAME> --description='Produktionszone' --project=<PROJECT_ID>"`
- remediation_effort: MEDIUM
- audit_evidence: "list_zones() returned 0 managed zones"

**Positivnachweis (compliant_finding):**
- title: "Cloud DNS verwaltete Zonen vorhanden"
- description (Template): `f"Projekt {project_id} hat {len(zones)} Cloud DNS verwaltete Zone(n) für DNS-basierte Failover-Mechanismen."`
- expected_state: "Mindestens eine Cloud DNS verwaltete Zone konfiguriert"
- audit_evidence (Template): `f"list_zones() returned {len(zones)} managed zone(s)"`

---

## Mechanische Auffälligkeiten (ohne Bewertung)

1. Keine der 21 Check-Klassen definiert ein Klassenattribut `severity` (abweichend vom Muster im Repo-`CLAUDE.md`) — severity wird stattdessen pro `Finding()`-Aufruf im Mangel-Pfad als Parameter gesetzt (innerhalb desselben Checks jeweils konsistent).
2. Keine der 21 Check-Klassen definiert ein Klassenattribut `iso_27001_ref` — `iso27001_control` wird stattdessen pro `Finding()`/`compliant_finding()`-Aufruf als Parameter übergeben. Innerhalb jedes einzelnen Checks ist der Text zwischen Positiv- und Mangel-Pfad jeweils identisch.
3. Nur das AWS-Modul definiert wiederverwendbare Modulkonstanten (`ISO_CONTROL_BACKUP` = "A.8.13 Information backup", `ISO_CONTROL_AVAILABILITY` = "A.5.29 ICT readiness for business continuity") — beide in englischer Sprache, obwohl der übrige Report-Text laut CLAUDE.md auf Deutsch sein soll. Azure und GCP definieren keine entsprechenden Modulkonstanten und wiederholen den ISO-Text als deutschsprachige String-Literale an jeder Aufrufstelle.
4. Für dieselbe ISO-27001-Kontrollnummer A.8.13 verwenden die drei Provider unterschiedlichen Beschreibungstext: AWS "Information backup" (Englisch), Azure "Informationssicherung", GCP "Datensicherung".
5. Die Zitierweise von ISO-27001-Kontrollen ist zwischen den Checks uneinheitlich: teils bloße Kontrollcodes ohne Beschreibungstext (AWS-NR3-005: "A.8.13"; AWS-NR3-004: "A.5.29, A.8.14"), teils Codes mit Teilbeschreibung (GCP-NR3-004: "A.5.29, A.8.14 Redundanz von Informationsverarbeitungseinrichtungen"), teils vollständige Beschreibungstexte je Code (AZ-NR3-004: "A.5.29 Informationssicherheit bei Störungen, A.8.14 Redundanz").
6. Nur AZ-NR3-005 (`CheckSiteRecovery`) referenziert die ISO-27001-Kontrolle "A.5.30"; kein anderer Nr.-3-Check in AWS oder GCP referenziert A.5.30, obwohl auch dort kontinuitäts-/DR-relevante Prüfgegenstände behandelt werden (z. B. AWS Multi-AZ, GCP Multi-Zone-Verteilung).
7. Klassendocstrings sind sprachlich uneinheitlich: alle sieben AWS- und alle sieben Azure-Klassendocstrings sind auf Englisch, alle sieben GCP-Klassendocstrings sind auf Deutsch — dasselbe Muster wie im bereits vorliegenden Nr.-1-Dossier vermerkt.
8. Die Klassenreihenfolge in der AWS-Moduldatei entspricht nicht der aufsteigenden Check-ID-Reihenfolge: Datei-Reihenfolge ist 001 (RdsBackupRetention), 002 (S3Versioning), 003 (S3ObjectLock), 006 (EbsSnapshotEncryption), 004 (RdsMultiAz), 007 (Route53HealthChecks), 005 (BackupPlans). Azure- und GCP-Module sind numerisch aufsteigend (001–007) geordnet.
9. Der AWS-Moduldocstring nennt nur "backup retention, versioning, and data protection configurations" und erwähnt Multi-AZ (AWS-NR3-004), Backup Plans (AWS-NR3-005) und Route-53-Health-Checks (AWS-NR3-007) nicht namentlich; die Azure- und GCP-Moduldocstrings zählen dagegen alle sieben jeweiligen Checks einzeln auf.
10. GCP-NR3-007 trägt intern den Klassennamen `CheckDnsHealthChecks` und wird im Moduldocstring als "DNS Health Checks" bezeichnet; Check-Titel, description und pruefgrenzen sprechen dagegen ausschließlich von der Existenz verwalteter DNS-Zonen ("Cloud DNS verwaltete Zonen vorhanden"). Die Prüflogik ruft nur `list_zones()` auf und fragt keine Health-Check- oder Routing-Policy-Konfiguration ab; die pruefgrenzen-Angabe des Checks benennt dies selbst ("Prüft nur die Existenz verwalteter DNS-Zonen als Indiz für gesteuertes Failover").
11. AWS-NR3-003 (`CheckS3ObjectLock`) wertet jeden erfolgreichen Aufruf von `get_object_lock_configuration()` als Nachweis für aktiviertes Object Lock, ohne den Inhalt der Antwort (z. B. das Feld `ObjectLockEnabled`) zu prüfen; nur eine Exception mit "ObjectLockConfigurationNotFoundError" im Text wird als Mangel gewertet.
12. AWS-NR3-006 (`CheckEbsSnapshotEncryption`) erzeugt unter derselben check_id zwei inhaltlich unterschiedliche Mangel-Findings ("EBS-Volume ohne Snapshots" bei fehlenden Snapshots, "EBS-Snapshot nicht verschlüsselt" bei vorhandenem, aber unverschlüsseltem neuestem Snapshot) mit unterschiedlicher current_state-Feldstruktur: Variante 1 führt die Schlüssel "snapshots" (Anzahl, hier 0) und "volume_state"; Variante 2 führt "snapshot_id", "encrypted": False und "volume_state"; der Positivpfad führt "snapshot_id", "encrypted": True und "snapshots" (Anzahl) — die drei current_state-Varianten teilen sich keine gemeinsame vollständige Feldmenge.
13. Der Check-Titel/description von AWS-NR3-006 spricht von "regelmäßige[n], verschlüsselte[n] Snapshots"; die pruefgrenzen-Angabe schließt jedoch explizit aus, dass "Snapshot-Aktualität" geprüft wird — die Prüflogik verifiziert nur die Existenz mindestens eines Snapshots und das Verschlüsselungs-Flag des neuesten, nicht Regelmäßigkeit/Alter der Sicherung.
14. Bei aggregierten Positiv-Findings mit mehreren zugrunde liegenden Ressourcen wird jeweils nur eine repräsentative resource_id angegeben: AWS-NR3-005 (`plans[0]`) und AWS-NR3-007 (`health_checks[0]`) referenzieren nur die erste gefundene Ressource, obwohl potenziell mehrere existieren.
15. AZ-NR3-007 (`CheckTrafficManagerFrontDoor`) setzt `resource_type` in beiden Finding-Pfaden fest auf `"Microsoft.Network/trafficManagerProfiles"`, auch wenn die tatsächlich gefundene(n) Ressource(n) vom Typ `Microsoft.Network/frontDoors` oder `Microsoft.Cdn/profiles` sind.
16. In mehreren Azure-Checks werden Exceptions beim Abfragen einzelner Ressourcen mit `except Exception: pass` verworfen, ohne einen Eintrag in `errors` anzulegen: AZ-NR3-001 (`CheckBackupVaults`, per-Vault-Try beim Abrufen der Backup-Policies), AZ-NR3-002 (`CheckSqlBackupRetention`, per-Datenbank-Try), AZ-NR3-006 (`CheckImmutableBlobStorage`, per-Storage-Account-Try). AWS- und GCP-Checks fangen Exceptions in diesem Batch durchgängig über `errors.append(CheckError(...))`.
17. AZ-NR3-002 (`CheckSqlBackupRetention`) überspringt explizit die Datenbank mit dem Namen "master" (`if db.name == "master": continue`); eine analoge Sonderbehandlung für Systemdatenbanken ist bei keinem anderen Nr.-3-Check dokumentiert.
18. GCP-NR3-004 (`CheckMultiZoneDeployments`) behandelt im if/elif nur die Fälle `>= 2` Zonen und `== 1` Zone; der Fall `0` Zonen mit laufenden Instanzen (kein `else`-Zweig) erzeugt weder ein Positiv- noch ein Mangel-Finding.
19. Granularität der Findings ist innerhalb und zwischen den Providern uneinheitlich: AWS erzeugt bei NR3-001, -002, -003, -004, -006 je ein Finding pro Einzelressource, bei NR3-005 und -007 je ein aggregiertes Finding pro Region/Account; Azure erzeugt bei sechs von sieben Checks (alle außer AZ-NR3-002) ein aggregiertes Finding pro Subscription, nur AZ-NR3-002 erzeugt ein Finding pro Einzeldatenbank; GCP erzeugt bei NR3-001, -002, -003, -006 je ein Finding pro Einzelressource und bei NR3-004, -005, -007 je ein aggregiertes Finding pro Projekt.
20. Severity-Werte für konzeptionell vergleichbare Prüfgegenstände unterscheiden sich zwischen den Providern: fehlende Objekt-Versionierung ist bei AWS-NR3-002 (S3Versioning) severity=MEDIUM, bei GCP-NR3-002 (GcsVersioning) severity=HIGH; ein direktes Azure-Äquivalent zur Objekt-Versionierung existiert unter Nr. 3 nicht.
21. AWS-NR3-005 (`CheckBackupPlans`) und AWS-NR3-007 (`CheckRoute53HealthChecks`) verwenden für den inneren und äußeren try/except-Block jeweils denselben Fehlertext ("... Check fehlgeschlagen: {e}"), aber unterschiedliche `error_type`-Werte (innerer Block z. B. "AWSClientError", äußerer Block "CheckError"); bei `CheckRoute53HealthChecks` sind beide Fehlermeldungstexte sogar wortgleich ("Route 53 Health Checks Check fehlgeschlagen: {e}").
22. `CheckError()`-Aufrufe unterscheiden sich zwischen Providern: AWS und GCP übergeben nur `message` und `error_type`; Azure übergibt zusätzlich `check_id` und `region="global"` — dasselbe Muster wie im bereits vorliegenden Nr.-1-Dossier vermerkt.
