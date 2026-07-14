# W4 Batch-Review-Dossier — §30 Abs. 2 Nr. 8 BSIG (Kryptographie)

> Mechanisch extrahiert am 2026-07-13 (Worker, ohne rechtliche Bewertung).
> Prüfgegenstand für: Gründer + Agent legal-reviewer (ADR-0018).

Quelldateien:
- `nis2scan/engine/providers/aws/checks/nr8_kryptographie.py`
- `nis2scan/engine/providers/azure/checks/nr8_kryptographie.py`
- `nis2scan/engine/providers/gcp/checks/nr8_kryptographie.py`

Ist-Zahl erfasster Checks: **19** (AWS: 7, Azure: 6, GCP: 6) — entspricht der erwarteten Zahl.

## Modul-Konstanten je Provider

### AWS (`nr8_kryptographie.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 8 — Kryptographie checks for AWS.

  Checks encryption at rest and in transit across S3, EBS, RDS, KMS, TLS policies, and certificates.
  ```
- `BSIG_30_NR = 8`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 8 BSIG — Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren"
- `ISO_CONTROL` (wörtlich): "A.8.24 Use of cryptography" (englisch)
- `ACM_EXPIRY_WARNING_DAYS = 30` — Modul-Konstante (außerhalb jeder Klasse definiert, unmittelbar vor `CheckAcmCertificateExpiry`), nur von AWS-NR8-007 verwendet.

### Azure (`nr8_kryptographie.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 8 — Kryptographie checks for Azure.

  Checks Storage Encryption, Disk Encryption, SQL TDE, Key Vault,
  App Service HTTPS/TLS, and Application Gateway TLS Policy.
  ```
- `BSIG_30_NR = 8`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS): "§30 Abs. 2 Nr. 8 BSIG — Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren"
- Kein Modul-Äquivalent zu `ISO_CONTROL` — jeder der 6 Checks trägt stattdessen das inline-Literal "A.8.24 Einsatz von Kryptografie" (deutsch) an jeder Aufrufstelle (Positiv- und Mangel-Pfad identisch).

### GCP (`nr8_kryptographie.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 8 — Kryptografie und Verschlüsselung checks for GCP.

  Checks KMS Key Rotation, CMEK Encryption, SSL Policies, Cloud SQL SSL,
  Disk Encryption, and Certificate Manager.
  ```
- `BSIG_30_NR = 8`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS/Azure): "§30 Abs. 2 Nr. 8 BSIG — Konzepte und Prozesse für den Einsatz von kryptographischen Verfahren"
- `MAX_ROTATION_DAYS = 365`
- `MAX_ROTATION_SECONDS = MAX_ROTATION_DAYS * 24 * 3600` (= 31536000), nur von GCP-NR8-001 verwendet.
- Kein Modul-Äquivalent zu `ISO_CONTROL` — jeder der 6 Checks trägt stattdessen das inline-Literal "A.8.24 Verwendung von Kryptografie" (deutsch, abweichender Wortlaut zu Azure) an jeder Aufrufstelle (Positiv- und Mangel-Pfad identisch).

---

## Checks

### AWS-NR8-001 — S3 Default Encryption

Klassen-Docstring (wörtlich): "Check that all S3 buckets have default encryption enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckS3DefaultEncryption` |
| description | "Prüft ob alle S3-Buckets eine Default-Verschlüsselung (SSE-S3 oder SSE-KMS) aktiviert haben." |
| severity | HIGH (Mangel-Pfad, inline im `Finding()`-Aufruf) |
| iso27001_control | `ISO_CONTROL` = "A.8.24 Use of cryptography" (identisch in Positiv- und Mangel-Pfad) |
| required_permissions | `["s3:ListAllMyBuckets", "s3:GetBucketEncryption", "s3:GetBucketLocation"]` |
| pruefgrenzen | "Prüft nur die Default-Encryption-Einstellung der Buckets. Nicht geprüft werden einzelne Objekte, die vor der Aktivierung unverschlüsselt abgelegt wurden." |
| Prüflogik (deskriptiv) | `s3.list_buckets()` liefert alle Buckets; je Bucket wird `s3.get_bucket_encryption()` aufgerufen — gelingt der Aufruf, wird das Feld `Rules[0].ApplyServerSideEncryptionByDefault.SSEAlgorithm` (Default "unknown" falls `Rules` leer) ausgelesen und ein Positivnachweis erzeugt; wirft der Aufruf einen `ClientError` mit Code `ServerSideEncryptionConfigurationNotFoundError`, wird ein Mangel-Finding erzeugt; jeder andere `ClientError` wird als `CheckError` erfasst, ohne Finding für diesen Bucket. |

**Finding-Texte (Mangel-Pfad):**
- title: "S3-Bucket ohne Default-Verschlüsselung"
- description (Literal, kein f-String, ohne Bucket-Namen): "Der S3-Bucket hat keine serverseitige Default-Verschlüsselung konfiguriert. Alle hochgeladenen Objekte sind unverschlüsselt gespeichert."
- expected_state: "SSE-S3 (AES-256) oder SSE-KMS Default-Verschlüsselung aktiviert"
- remediation: "Aktivieren Sie die Default-Verschlüsselung für den S3-Bucket mit SSE-S3 (AES-256) oder SSE-KMS. AWS CLI: aws s3api put-bucket-encryption --bucket <name> --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'"
- remediation_effort: LOW
- audit_evidence (Literal, kein f-String, ohne Bucket-Namen): "GetBucketEncryption returned ServerSideEncryptionConfigurationNotFoundError for bucket"

**Positivnachweis (compliant_finding):**
- title: "S3-Bucket mit Default-Verschlüsselung"
- description (Template): `f"Der S3-Bucket '{bucket_name}' hat serverseitige Default-Verschlüsselung ({sse_algorithm}) aktiviert."`
- expected_state: "SSE-S3 (AES-256) oder SSE-KMS Default-Verschlüsselung aktiviert"
- audit_evidence (Template): `f"GetBucketEncryption: SSEAlgorithm={sse_algorithm} for {bucket_name}"`

---

### AWS-NR8-002 — EBS Volume Encryption

Klassen-Docstring (wörtlich): "Check that all EBS volumes are encrypted."

| Feld | Wert |
|---|---|
| Klasse | `CheckEbsEncryption` |
| description | "Prüft ob alle EBS-Volumes verschlüsselt sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL` (identisch in beiden Pfaden) |
| required_permissions | `["ec2:DescribeVolumes"]` |
| pruefgrenzen | "Prüft nur das Encrypted-Flag der EBS-Volumes in den gescannten Regionen. Die Schlüsselverwaltung (KMS-Key-Policy) wird nicht bewertet." |
| Prüflogik (deskriptiv) | `ec2.describe_volumes()` (paginiert) je Region; Feld `Encrypted` jedes Volumes — `True` ergibt Positivnachweis, `False`/fehlend ergibt Mangel-Finding, je Volume. |

**Finding-Texte (Mangel-Pfad):**
- title: "EBS-Volume ohne Verschlüsselung"
- description (Literal, kein f-String, ohne Volume-ID): "Das EBS-Volume ist nicht verschlüsselt. Daten at Rest sind ungeschützt."
- expected_state: "EBS-Volume mit AES-256 Verschlüsselung (aws/ebs oder CMK)"
- remediation: "Erstellen Sie einen verschlüsselten Snapshot des Volumes und erstellen Sie daraus ein neues verschlüsseltes Volume. Aktivieren Sie die EBS-Verschlüsselung als Default für die Region: aws ec2 enable-ebs-encryption-by-default"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribeVolumes: Encrypted=false for {volume['VolumeId']}"`

**Positivnachweis (compliant_finding):**
- title: "EBS-Volume verschlüsselt"
- description (Template): `f"Das EBS-Volume '{volume['VolumeId']}' ist verschlüsselt."`
- expected_state: "EBS-Volume mit AES-256 Verschlüsselung (aws/ebs oder CMK)"
- audit_evidence (Template): `f"DescribeVolumes: Encrypted=true for {volume['VolumeId']}"`

---

### AWS-NR8-003 — RDS Storage Encryption

Klassen-Docstring (wörtlich): "Check that all RDS instances have storage encryption enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckRdsEncryption` |
| description | "Prüft ob alle RDS-Instanzen Storage-Verschlüsselung aktiviert haben." |
| severity | CRITICAL (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL` (identisch in beiden Pfaden) |
| required_permissions | `["rds:DescribeDBInstances"]` |
| pruefgrenzen | "Prüft nur das StorageEncrypted-Flag der RDS-Instanzen. Verschlüsselung in Transit (TLS zur Datenbank) wird hier nicht geprüft." |
| Prüflogik (deskriptiv) | `rds.describe_db_instances()` (paginiert) je Region; Feld `StorageEncrypted` jeder Instanz — `True` ergibt Positivnachweis, `False`/fehlend ergibt Mangel-Finding, je Instanz. |

**Finding-Texte (Mangel-Pfad):**
- title: "RDS-Instanz ohne Storage-Verschlüsselung"
- description (Literal, kein f-String, ohne Instanz-Identifier): "Die RDS-Datenbankinstanz hat keine Storage-Verschlüsselung aktiviert. Datenbank-Daten at Rest sind ungeschützt."
- expected_state: "RDS Storage Encryption aktiviert mit KMS Key"
- remediation: "RDS-Verschlüsselung kann nur bei der Erstellung aktiviert werden. Erstellen Sie einen Snapshot, kopieren Sie ihn mit Verschlüsselung, und stellen Sie die DB aus dem verschlüsselten Snapshot wieder her."
- remediation_effort: HIGH
- audit_evidence (Template): `f"DescribeDBInstances: StorageEncrypted=false for {db['DBInstanceIdentifier']}"`

**Positivnachweis (compliant_finding):**
- title: "RDS-Instanz mit Storage-Verschlüsselung"
- description (Template): `f"Die RDS-Instanz '{db['DBInstanceIdentifier']}' hat Storage-Verschlüsselung aktiviert."`
- expected_state: "RDS Storage Encryption aktiviert mit KMS Key"
- audit_evidence (Template): `f"DescribeDBInstances: StorageEncrypted=true for {db['DBInstanceIdentifier']}"`

---

### AWS-NR8-004 — KMS Key Rotation

Klassen-Docstring (wörtlich): "Check that all KMS customer-managed keys have automatic rotation enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckKmsKeyRotation` |
| description | "Prüft ob alle KMS Customer-Managed Keys automatische Rotation aktiviert haben." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL` (identisch in beiden Pfaden) |
| required_permissions | `["kms:ListKeys", "kms:GetKeyRotationStatus", "kms:DescribeKey"]` |
| pruefgrenzen | "Prüft nur die automatische Rotation kundenverwalteter KMS-Schlüssel. AWS-verwaltete Schlüssel und importiertes Schlüsselmaterial rotieren anders und werden nicht bewertet." |
| Prüflogik (deskriptiv) | `kms.list_keys()` (paginiert) je Region; je Key `kms.describe_key()` — Keys mit `KeyManager != "CUSTOMER"` oder `KeyState != "Enabled"` werden übersprungen (kein Finding); für verbleibende Keys liefert `kms.get_key_rotation_status()` das Feld `KeyRotationEnabled` — `True` ergibt Positivnachweis, `False` ergibt Mangel-Finding, je Key. Wirft `describe_key`/`get_key_rotation_status` eine Exception, wird ein `CheckError` erfasst, kein Finding für diesen Key. |

**Finding-Texte (Mangel-Pfad):**
- title: "KMS-Key ohne automatische Rotation"
- description (Literal, kein f-String, ohne Key-ID): "Der KMS Customer-Managed Key hat keine automatische Key-Rotation aktiviert. Regelmäßige Key-Rotation ist eine Grundanforderung der Kryptographie-Richtlinie."
- expected_state: "Automatische KMS Key Rotation aktiviert (jährlich)"
- remediation: "Aktivieren Sie die automatische Key-Rotation: aws kms enable-key-rotation --key-id <key-id>"
- remediation_effort: LOW
- audit_evidence (Template): `f"GetKeyRotationStatus: KeyRotationEnabled=false for {key_id}"`

**Positivnachweis (compliant_finding):**
- title: "KMS-Key mit automatischer Rotation"
- description (Literal, kein f-String, ohne Key-ID): "Der KMS Customer-Managed Key hat automatische Key-Rotation aktiviert."
- expected_state: "Automatische KMS Key Rotation aktiviert (jährlich)"
- audit_evidence (Template): `f"GetKeyRotationStatus: KeyRotationEnabled=true for {key_id}"`

---

### AWS-NR8-005 — ELB/ALB TLS Policy

Klassen-Docstring (wörtlich): "Check that ELB/ALB listeners use TLS 1.2+."

| Feld | Wert |
|---|---|
| Klasse | `CheckTlsPolicy` |
| description | "Prüft ob alle Load Balancer HTTPS-Listener TLS 1.2+ verwenden." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL` (identisch in beiden Pfaden) |
| required_permissions | `["elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners"]` |
| pruefgrenzen | "Prüft nur die SSL/TLS-Policy-Namen der Load-Balancer-Listener gegen bekannte veraltete Policies. Eigene benannte Policies werden nicht inhaltlich zerlegt." |
| Klassenkonstante `SECURE_POLICIES` (wörtlich) | `{"ELBSecurityPolicy-TLS13-1-2-2021-06", "ELBSecurityPolicy-TLS13-1-2-Res-2021-06", "ELBSecurityPolicy-TLS-1-2-2017-01", "ELBSecurityPolicy-TLS-1-2-Ext-2018-06", "ELBSecurityPolicy-FS-1-2-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2019-08", "ELBSecurityPolicy-FS-1-2-Res-2020-10"}` |
| Prüflogik (deskriptiv) | `elbv2.describe_load_balancers()` (paginiert) je Region; je Load Balancer `elbv2.describe_listeners()`; je Listener mit `Protocol == "HTTPS"` wird `SslPolicy` gegen `SECURE_POLICIES` geprüft — Policy-Name in der Liste ergibt Positivnachweis, ein nicht-leerer Policy-Name außerhalb der Liste ergibt Mangel-Finding, je Listener. Ein leerer `SslPolicy`-Wert erzeugt weder Positiv- noch Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Load Balancer mit unsicherer TLS-Policy"
- description (Template): `f"Der HTTPS-Listener verwendet die TLS-Policy '{policy}', die möglicherweise TLS < 1.2 erlaubt."`
- expected_state: "TLS Policy mit mindestens TLS 1.2 (z.B. ELBSecurityPolicy-TLS-1-2-2017-01)"
- remediation: "Ändern Sie die TLS-Policy des Listeners auf eine Policy die mindestens TLS 1.2 erzwingt, z.B. ELBSecurityPolicy-TLS-1-2-2017-01 oder neuer."
- remediation_effort: LOW
- audit_evidence (Template): `f"DescribeListeners: SslPolicy={policy}"`

**Positivnachweis (compliant_finding):**
- title: "Load Balancer mit sicherer TLS-Policy"
- description (Template): `f"Der HTTPS-Listener verwendet die TLS-Policy '{policy}' (erzwingt mindestens TLS 1.2)."`
- expected_state: "TLS Policy mit mindestens TLS 1.2 (z.B. ELBSecurityPolicy-TLS-1-2-2017-01)"
- audit_evidence (Template): `f"DescribeListeners: SslPolicy={policy}"` (identisches Template wie im Mangel-Pfad)

---

### AWS-NR8-006 — ELB/ALB TLS Mindestversion

Klassen-Docstring (wörtlich): "Check that ELB/ALB SSL policies enforce at least TLS 1.2 via DescribeSSLPolicies."

| Feld | Wert |
|---|---|
| Klasse | `CheckElbTlsMinVersion` |
| description | "Prüft über DescribeSSLPolicies ob die SSL-Policies der Load Balancer mindestens TLS 1.2 erzwingen." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL` (identisch in beiden Pfaden) |
| required_permissions | `["elasticloadbalancing:DescribeLoadBalancers", "elasticloadbalancing:DescribeListeners", "elasticloadbalancing:DescribeSSLPolicies"]` |
| pruefgrenzen | "Prüft die TLS-Mindestversion der Listener-Policies. Nicht geprüft werden Endpunkte außerhalb von ELB/ALB (z. B. CloudFront, API Gateway, eigene Server)." |
| Klassenkonstante `INSECURE_PROTOCOLS` (wörtlich) | `{"TLSv1", "TLSv1.1"}` |
| Prüflogik (deskriptiv) | `elbv2.describe_load_balancers()` (paginiert) je Region; je Load Balancer `elbv2.describe_listeners()`; je HTTPS-Listener mit gesetztem `SslPolicy` ruft `elbv2.describe_ssl_policies(Names=[policy_name])` die tatsächlich erlaubten `SslProtocols` ab; Schnittmenge mit `INSECURE_PROTOCOLS` — leer ergibt Positivnachweis, nicht-leer ergibt Mangel-Finding, je Listener. Liefert `describe_ssl_policies` keine Policy zurück, wird die Prüfung für diesen Listener übersprungen (kein Finding, kein Error). |

**Finding-Texte (Mangel-Pfad):**
- title: "Load Balancer erlaubt unsichere TLS-Versionen"
- description (Template): `f"Die SSL-Policy '{policy_name}' erlaubt die unsicheren Protokolle: {', '.join(sorted(insecure))}. Nur TLS 1.2+ sollte zugelassen werden."`
- expected_state: "SSL-Policy mit ausschließlich TLS 1.2 und TLS 1.3"
- remediation: "Ändern Sie die SSL-Policy des Listeners auf eine Policy die nur TLS 1.2+ erlaubt, z.B. ELBSecurityPolicy-TLS13-1-2-2021-06."
- remediation_effort: LOW
- audit_evidence (Template): `f"DescribeSSLPolicies: {policy_name} allows {', '.join(sorted(insecure))}"`

**Positivnachweis (compliant_finding):**
- title: "Load Balancer erzwingt TLS 1.2+"
- description (Template): `f"Die SSL-Policy '{policy_name}' erlaubt nur sichere Protokolle: {', '.join(sorted(protocols))}."`
- expected_state: "SSL-Policy mit ausschließlich TLS 1.2 und TLS 1.3"
- audit_evidence (Template): `f"DescribeSSLPolicies: {policy_name} allows only {', '.join(sorted(protocols))}"`

---

### AWS-NR8-007 — ACM Zertifikats-Ablauf

Klassen-Docstring (wörtlich): "Check that ACM certificates are not expired or about to expire."

| Feld | Wert |
|---|---|
| Klasse | `CheckAcmCertificateExpiry` |
| description (Template, mit Modul-Konstante) | `f"Prüft ob ACM-Zertifikate gültig sind und nicht innerhalb von {ACM_EXPIRY_WARNING_DAYS} Tagen ablaufen."` → "Prüft ob ACM-Zertifikate gültig sind und nicht innerhalb von 30 Tagen ablaufen." |
| severity | Dreistufig statt binär: CRITICAL (abgelaufen), HIGH (läuft binnen `ACM_EXPIRY_WARNING_DAYS` Tagen ab), sonst Positivnachweis |
| iso27001_control | `ISO_CONTROL` (identisch in allen drei Pfaden) |
| required_permissions | `["acm:ListCertificates", "acm:DescribeCertificate"]` |
| pruefgrenzen | "Prüft nur in ACM verwaltete Zertifikate auf Ablauf. Extern beschaffte, manuell installierte Zertifikate werden nicht erkannt." |
| Modul-Konstante | `ACM_EXPIRY_WARNING_DAYS = 30` (siehe Modul-Konstanten-Abschnitt) |
| Prüflogik (deskriptiv) | `acm.list_certificates()` (paginiert) je Region; je Zertifikat `acm.describe_certificate()` liefert `NotAfter` — fehlt dieses Feld, wird das Zertifikat übersprungen (kein Finding); `days_remaining = (NotAfter - now).days` wird berechnet: `< 0` ergibt Finding mit severity CRITICAL, `<= ACM_EXPIRY_WARNING_DAYS` (30) ergibt Finding mit severity HIGH, sonst Positivnachweis — je Zertifikat. |

**Finding-Texte (Mangel-Pfad, abgelaufen — severity CRITICAL):**
- title: "ACM-Zertifikat abgelaufen"
- description (Template): `f"Das ACM-Zertifikat für '{domain}' ist seit {abs(days_remaining)} Tagen abgelaufen."`

**Finding-Texte (Mangel-Pfad, läuft bald ab — severity HIGH):**
- title: "ACM-Zertifikat läuft bald ab"
- description (Template): `f"Das ACM-Zertifikat für '{domain}' läuft in {days_remaining} Tagen ab."`

**Gemeinsame Felder beider Mangel-Fälle:**
- expected_state (Template): `f"Zertifikat gültig mit mehr als {ACM_EXPIRY_WARNING_DAYS} Tagen Restlaufzeit"`
- remediation: "Erneuern oder ersetzen Sie das Zertifikat. Für ACM-verwaltete Zertifikate: Prüfen Sie die DNS-Validierung. Für importierte Zertifikate: Importieren Sie ein neues Zertifikat."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribeCertificate: NotAfter={not_after.isoformat()}, DaysRemaining={days_remaining}"`

**Positivnachweis (compliant_finding):**
- title: "ACM-Zertifikat gültig"
- description (Template): `f"Das ACM-Zertifikat für '{domain}' ist noch {days_remaining} Tage gültig."`
- expected_state (Template): `f"Zertifikat gültig mit mehr als {ACM_EXPIRY_WARNING_DAYS} Tagen Restlaufzeit"` (identisch zu beiden Mangel-Fällen)
- audit_evidence (Template): `f"DescribeCertificate: NotAfter={not_after.isoformat()}, DaysRemaining={days_remaining}"` (identisches Template wie im Mangel-Pfad)

---

### AZ-NR8-001 — Storage Account Verschlüsselung (CMK bevorzugt)

Klassen-Docstring (wörtlich): "Check that Storage Accounts use Customer-Managed Keys (CMK)."

| Feld | Wert |
|---|---|
| Klasse | `CheckStorageEncryption` |
| description | "Prüft ob Azure Storage Accounts kundenverwaltete Schlüssel (CMK) verwenden." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Einsatz von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Storage/storageAccounts/read"]` |
| pruefgrenzen | "Storage-Verschlüsselung ist in Azure immer aktiv; bewertet wird nur, ob kundenverwaltete Schlüssel (CMK) genutzt werden. Fehlendes CMK ist eine Härtungsempfehlung, kein Verschlüsselungsmangel." |
| Prüflogik (deskriptiv) | `storage_client.storage_accounts.list()` je Subscription; je Account wird `encryption.key_source` ausgelesen — `!= "Microsoft.Keyvault"` zählt als plattformverwaltet; existieren Accounts und ist keiner plattformverwaltet, ergibt sich ein aggregiertes Positiv-Finding je Subscription; existiert mindestens ein plattformverwalteter Account, ergibt sich ein aggregiertes Mangel-Finding je Subscription (mit Namensliste). Bei null Accounts in der Subscription entsteht kein Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Storage Accounts ohne CMK-Verschlüsselung"
- description (Template): `f"Subscription {sub_id} hat Storage Accounts mit plattformverwalteten Schlüsseln: {names}. CMK bietet mehr Kontrolle über die Verschlüsselungsschlüssel."`
- expected_state: "Alle Storage Accounts mit Customer-Managed Keys (CMK)"
- remediation: "Konfigurieren Sie CMK-Verschlüsselung: az storage account update --name <acc> --resource-group <rg> --encryption-key-source Microsoft.Keyvault --encryption-key-vault <vault-uri> --encryption-key-name <key>"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"storage_accounts.list() returned {len(accounts)} accounts, {len(platform_managed)} with platform-managed keys"`

**Positivnachweis (compliant_finding):**
- title: "Storage Accounts mit CMK-Verschlüsselung"
- description (Template): `f"Alle {len(accounts)} Storage Accounts in Subscription {sub_id} verwenden kundenverwaltete Schlüssel (CMK)."`
- expected_state: "Alle Storage Accounts mit Customer-Managed Keys (CMK)"
- audit_evidence (Template): `f"storage_accounts.list() returned {len(accounts)} accounts, all CMK"`

---

### AZ-NR8-002 — Disk Encryption / SSE

Klassen-Docstring (wörtlich): "Check that managed disks are encrypted."

| Feld | Wert |
|---|---|
| Klasse | `CheckDiskEncryption` |
| description | "Prüft ob verwaltete Disks verschlüsselt sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Einsatz von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Compute/disks/read"]` |
| pruefgrenzen | "Prüft nur die Disk-Verschlüsselungsart (SSE/ADE/CMK). Schlüsselverwahrung und -prozesse werden nicht bewertet." |
| Prüflogik (deskriptiv) | `compute_client.disks.list()` je Subscription; je Disk gilt als unverschlüsselt, wenn `disk.encryption` oder `disk.encryption.type` fehlt; existieren Disks und keine davon unverschlüsselt, ergibt sich ein aggregiertes Positiv-Finding je Subscription; existiert mindestens eine unverschlüsselte Disk, ergibt sich ein aggregiertes Mangel-Finding je Subscription. Bei null Disks in der Subscription entsteht kein Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Nicht verschlüsselte Disks"
- description (Template): `f"Subscription {sub_id} hat {len(unencrypted_disks)} Disks ohne Verschlüsselung. Alle Datenträger müssen verschlüsselt sein."`
- expected_state: "Alle Managed Disks verschlüsselt (SSE oder CMK)"
- remediation: "Aktivieren Sie Disk-Verschlüsselung: az disk update --name <disk> --resource-group <rg> --encryption-type EncryptionAtRestWithPlatformKey"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"disks.list() returned {len(disks)} disks, {len(unencrypted_disks)} without encryption"`

**Positivnachweis (compliant_finding):**
- title: "Alle Disks verschlüsselt"
- description (Template): `f"Alle {len(disks)} Managed Disks in Subscription {sub_id} sind verschlüsselt."`
- expected_state: "Alle Managed Disks verschlüsselt (SSE oder CMK)"
- audit_evidence (Template): `f"disks.list() returned {len(disks)} disks, all encrypted"`

---

### AZ-NR8-003 — SQL TDE aktiviert

Klassen-Docstring (wörtlich): "Check that SQL Transparent Data Encryption (TDE) is enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckSqlTde` |
| description | "Prüft ob Transparent Data Encryption (TDE) für Azure SQL-Datenbanken aktiviert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Einsatz von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Sql/servers/read", "Microsoft.Sql/servers/databases/read", "Microsoft.Sql/servers/databases/transparentDataEncryption/read"]` |
| pruefgrenzen | "Prüft nur das TDE-Flag der SQL-Datenbanken. Verschlüsselung in Transit und Always Encrypted werden nicht geprüft." |
| Prüflogik (deskriptiv) | `sql_client.servers.list()` je Subscription; je Server werden über `databases.list_by_server()` die Datenbanken ermittelt (Datenbank `"master"` wird übersprungen); je Datenbank liefert `transparent_data_encryptions.get(rg, server, db, "current")` das Feld `state` — `"enabled"` (case-insensitive) ergibt Positivnachweis, jeder andere gesetzte Wert ergibt Mangel-Finding, je Datenbank. Wirft der `get()`-Aufruf eine Exception, wird sie mit `except Exception: pass` verworfen — kein Finding, kein `CheckError` für diese Datenbank. |

**Finding-Texte (Mangel-Pfad):**
- title: "SQL TDE nicht aktiviert"
- description (Template): `f"Datenbank {db.name} auf Server {server.name} in Subscription {sub_id} hat TDE nicht aktiviert."`
- expected_state: "TDE aktiviert für alle Datenbanken"
- remediation (Template): `f"Aktivieren Sie TDE: az sql db tde set --resource-group {rg_name} --server {server.name} --database {db.name} --status Enabled"`
- remediation_effort: LOW
- audit_evidence (Template): `f"transparent_data_encryptions.get(): state={tde.state}"`

**Positivnachweis (compliant_finding):**
- title: "SQL TDE aktiviert"
- description (Template): `f"Datenbank {db.name} auf Server {server.name} hat Transparent Data Encryption aktiviert."`
- expected_state: "TDE aktiviert für alle Datenbanken"
- audit_evidence (Template): `f"transparent_data_encryptions.get(): state={tde.state}"` (identisches Template wie im Mangel-Pfad)

---

### AZ-NR8-004 — Key Vault Rotation Policy

Klassen-Docstring (wörtlich): "Check that Key Vaults have soft-delete and purge protection enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckKeyVaultRotation` |
| description | "Prüft ob Key Vaults Soft-Delete und Purge Protection aktiviert haben als Grundlage für sicheres Schlüssel-Management." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Einsatz von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.KeyVault/vaults/read"]` |
| pruefgrenzen | "Prüft nur Rotation-Policies der Key-Vault-Schlüssel. Secrets und Zertifikate im Vault sowie externe Schlüssel werden hier nicht bewertet." |
| Prüflogik (deskriptiv) | `kv_client.vaults.list()` je Subscription; je Vault liefert `vaults.get(rg, name)` die `properties`; fehlt `enable_soft_delete`, wird "Soft-Delete deaktiviert" vermerkt, fehlt `enable_purge_protection`, wird "Purge Protection deaktiviert" vermerkt; keine Vermerke ergeben Positivnachweis, mindestens ein Vermerk ergibt Mangel-Finding, je Vault. Wirft der `get()`-Aufruf eine Exception, wird sie mit `except Exception: pass` verworfen — kein Finding, kein `CheckError` für diesen Vault. |

**Finding-Texte (Mangel-Pfad):**
- title: "Key Vault ohne Schutzfunktionen"
- description (Template): `f"Key Vault {vault.name} in Subscription {sub_id}: {', '.join(issues)}. Ohne diese Funktionen können Schlüssel unwiderruflich gelöscht werden."`
- expected_state: "Soft-Delete und Purge Protection aktiviert"
- remediation (Template): `f"Aktivieren Sie Soft-Delete und Purge Protection: az keyvault update --name {vault.name} --enable-soft-delete true --enable-purge-protection true"`
- remediation_effort: LOW
- audit_evidence (Template): `f"vaults.get(): issues={issues}"`

**Positivnachweis (compliant_finding):**
- title: "Key Vault mit Schutzfunktionen"
- description (Template): `f"Key Vault {vault.name} hat Soft-Delete und Purge Protection aktiviert."`
- expected_state: "Soft-Delete und Purge Protection aktiviert"
- audit_evidence: "vaults.get(): soft-delete and purge protection enabled" (Literal, kein f-String)

---

### AZ-NR8-005 — App Service HTTPS Only + TLS 1.2+

Klassen-Docstring (wörtlich): "Check that App Services enforce HTTPS and TLS 1.2+."

| Feld | Wert |
|---|---|
| Klasse | `CheckAppServiceHttps` |
| description | "Prüft ob App Services HTTPS-Only erzwingen und mindestens TLS 1.2 verwenden." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Einsatz von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Web/sites/read", "Microsoft.Web/sites/config/read"]` |
| pruefgrenzen | "Prüft nur App-Service-Konfiguration (HTTPS-Only, TLS-Mindestversion). Endpunkte außerhalb von App Service sind nicht erfasst." |
| Prüflogik (deskriptiv) | `web_client.web_apps.list()` je Subscription; je App wird "HTTPS-Only nicht aktiviert" vermerkt, falls `app.https_only` falsy ist; ist `site_config.min_tls_version` gesetzt, wird der String-Wert mit `"1.2"` verglichen (`tls_version < "1.2"`) und bei Kleiner-Vergleich "TLS-Version {tls_version} < 1.2" vermerkt; keine Vermerke ergeben Positivnachweis, mindestens ein Vermerk ergibt Mangel-Finding, je App. Ist `site_config` oder `min_tls_version` nicht gesetzt, entfällt der TLS-Teilvermerk ersatzlos. |

**Finding-Texte (Mangel-Pfad):**
- title: "App Service ohne HTTPS/TLS-Enforcement"
- description (Template): `f"App Service {app.name} in Subscription {sub_id}: {', '.join(issues)}."`
- expected_state: "HTTPS-Only aktiviert und TLS ≥ 1.2"
- remediation (Template): `f"az webapp update --name {app.name} --resource-group <rg> --set httpsOnly=true && az webapp config set --name {app.name} --resource-group <rg> --min-tls-version 1.2"`
- remediation_effort: LOW
- audit_evidence (Template): `f"web_apps.list(): {issues}"`

**Positivnachweis (compliant_finding):**
- title: "App Service mit HTTPS/TLS-Enforcement"
- description (Template): `f"App Service {app.name} erzwingt HTTPS-Only und TLS >= 1.2."`
- expected_state: "HTTPS-Only aktiviert und TLS ≥ 1.2"
- audit_evidence (Template): `f"web_apps.list(): {app.name} https_only=true, TLS>=1.2"`

---

### AZ-NR8-006 — Application Gateway TLS Policy

Klassen-Docstring (wörtlich): "Check that Application Gateways enforce TLS 1.2+."

| Feld | Wert |
|---|---|
| Klasse | `CheckAppGatewayTls` |
| description | "Prüft ob Application Gateways eine TLS-Policy mit mindestens TLS 1.2 verwenden." |
| severity | HIGH (beide Mangel-Fälle, inline) |
| iso27001_control | inline Literal "A.8.24 Einsatz von Kryptografie" (identisch in allen drei Pfaden) |
| required_permissions | `["Microsoft.Network/applicationGateways/read"]` |
| pruefgrenzen | "Prüft nur die TLS-Policy der Application Gateways. Eigene Cipher-Suites werden nicht inhaltlich zerlegt." |
| Prüflogik (deskriptiv) | `network_client.application_gateways.list_all()` je Subscription; je Gateway: ist `ssl_policy` gesetzt und `min_protocol_version` vorhanden, wird der String auf `"TLSv1_0"`/`"TLSv1_1"` geprüft — enthält keiner der beiden Substrings, ergibt sich Positivnachweis, enthält einer, ergibt sich Mangel-Finding ("veraltete TLS-Version"); ist `ssl_policy` gar nicht gesetzt, ergibt sich ein separates Mangel-Finding ("ohne TLS-Policy"). Ist `ssl_policy` gesetzt, aber `min_protocol_version` fehlt, entsteht kein Finding (weder Positiv- noch Mangel-Zweig trifft zu). |

**Finding-Texte (Mangel-Pfad, veraltete TLS-Version):**
- title: "Application Gateway mit veralteter TLS-Version"
- description (Template): `f"Application Gateway {gw.name} in Subscription {sub_id} erlaubt TLS-Version {min_version}. TLS 1.0/1.1 ist nicht mehr Stand der Technik."`
- expected_state: "TLS-Policy mit mindestens TLSv1_2"
- remediation (Template): `f"Aktualisieren Sie die TLS-Policy: az network application-gateway ssl-policy set --gateway-name {gw.name} --resource-group <rg> --min-protocol-version TLSv1_2 --policy-type Predefined --name AppGwSslPolicy20220101"`
- remediation_effort: LOW
- audit_evidence (Template): `f"ssl_policy.min_protocol_version={min_version}"`

**Finding-Texte (Mangel-Pfad, ohne TLS-Policy):**
- title: "Application Gateway ohne TLS-Policy"
- description (Template): `f"Application Gateway {gw.name} in Subscription {sub_id} hat keine explizite TLS-Policy konfiguriert."`
- expected_state: "Explizite TLS-Policy mit mindestens TLSv1_2"
- remediation (Template): `f"Konfigurieren Sie eine TLS-Policy: az network application-gateway ssl-policy set --gateway-name {gw.name} --resource-group <rg> --min-protocol-version TLSv1_2"`
- remediation_effort: LOW
- audit_evidence: "No SSL policy configured on application gateway" (Literal, kein f-String)

**Positivnachweis (compliant_finding):**
- title: "Application Gateway mit sicherer TLS-Policy"
- description (Template): `f"Application Gateway {gw.name} erzwingt mindestens TLS-Version {min_version}."`
- expected_state: "TLS-Policy mit mindestens TLSv1_2"
- audit_evidence (Template): `f"ssl_policy.min_protocol_version={min_version}"` (identisches Template wie im ersten Mangel-Fall)

---

### GCP-NR8-001 — KMS-Schlüsselrotation

Klassen-Docstring (wörtlich): "Prüft ob KMS-Schlüssel regelmäßig rotiert werden."

| Feld | Wert |
|---|---|
| Klasse | `CheckKmsKeyRotation` |
| description | "Prüft ob Cloud KMS-Schlüssel eine Rotationsperiode von maximal 365 Tagen haben und die nächste Rotation geplant ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Verwendung von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["cloudkms.cryptoKeys.list", "cloudkms.keyRings.list"]` |
| pruefgrenzen | "Prüft nur symmetrische KMS-Schlüssel (ENCRYPT_DECRYPT) auf Rotation. Asymmetrische Schlüssel und importiertes Material rotieren anders und werden nicht bewertet." |
| Prüflogik (deskriptiv) | `client.list_key_rings()` (alle Locations) je Projekt; je Key Ring `client.list_crypto_keys()`; Keys mit `purpose != ENCRYPT_DECRYPT` werden übersprungen; für verbleibende Keys wird `rotation_period` ausgewertet — vorhanden und `<= MAX_ROTATION_SECONDS` (365 Tage) ergibt Positivnachweis, fehlend oder `> MAX_ROTATION_SECONDS` ergibt Mangel-Finding, je Key. |

**Finding-Texte (Mangel-Pfad):**
- title: "KMS-Schlüssel ohne ausreichende Rotation"
- description (Template): `f"KMS-Schlüssel {key_id} in Projekt {project_id} hat keine Rotationsperiode oder sie überschreitet {MAX_ROTATION_DAYS} Tage."`
- expected_state (Template): `f"Rotationsperiode von maximal {MAX_ROTATION_DAYS} Tagen"`
- remediation (Literal mit eingebettetem Platzhalter-Text): "Setzen Sie eine Rotationsperiode:\ngcloud kms keys update <KEY_NAME> --keyring=<KEYRING> --location=<LOCATION> --rotation-period=90d --next-rotation-time=$(date -u +%Y-%m-%dT%H:%M:%SZ)"
- remediation_effort: LOW
- audit_evidence (Template): `f"CryptoKey rotation_period={rotation_days}d, max_allowed={MAX_ROTATION_DAYS}d"`

**Positivnachweis (compliant_finding):**
- title: "KMS-Schlüssel mit Rotation"
- description (Template): `f"KMS-Schlüssel {key.name} hat eine Rotationsperiode von {rotation_days} Tagen (Maximum: {MAX_ROTATION_DAYS})."`
- expected_state (Template): `f"Rotationsperiode von maximal {MAX_ROTATION_DAYS} Tagen"` (identisch zum Mangel-Pfad)
- audit_evidence (Template): `f"CryptoKey rotation_period={rotation_days}d, max_allowed={MAX_ROTATION_DAYS}d"` (identisches Template wie im Mangel-Pfad)

---

### GCP-NR8-002 — CMEK-Verschlüsselung für Compute-Disks

Klassen-Docstring (wörtlich): "Prüft ob Compute-Disks CMEK-Verschlüsselung verwenden."

| Feld | Wert |
|---|---|
| Klasse | `CheckCmekEncryption` |
| description | "Prüft ob Persistent Disks Customer-Managed Encryption Keys (CMEK) verwenden anstatt der Standard-Google-verwalteten Schlüssel." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Verwendung von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["compute.disks.list"]` |
| pruefgrenzen | "Prüft nur, ob Compute-Disks CMEK nutzen. Fehlendes CMEK ist eine Härtungsempfehlung — die GCP-Standardverschlüsselung ist immer aktiv." |
| Prüflogik (deskriptiv) | `DisksClient.aggregated_list()` je Projekt; je Disk wird geprüft, ob `disk.disk_encryption_key.kms_key_name` gesetzt ist — gesetzt ergibt Positivnachweis, fehlend ergibt Mangel-Finding, je Disk. |

**Finding-Texte (Mangel-Pfad):**
- title: "Disk ohne CMEK-Verschlüsselung"
- description (Template): `f"Disk {disk_id} in Projekt {project_id} verwendet Google-verwaltete Verschlüsselungsschlüssel anstatt CMEK. CMEK bietet zusätzliche Kontrolle über den Schlüssellebenszyklus."`
- expected_state: "Disk mit Customer-Managed Encryption Key (CMEK) verschlüsselt"
- remediation: "Erstellen Sie einen neuen Disk mit CMEK:\ngcloud compute disks create <DISK_NAME> --kms-key=projects/<PROJECT_ID>/locations/<LOCATION>/keyRings/<KEYRING>/cryptoKeys/<KEY> --zone=<ZONE>\nHinweis: Bestehende Disks können nicht nachträglich auf CMEK umgestellt werden."
- remediation_effort: HIGH
- audit_evidence: "disk.disk_encryption_key.kms_key_name is empty" (Literal, kein f-String)

**Positivnachweis (compliant_finding):**
- title: "Disk mit CMEK-Verschlüsselung"
- description (Template): `f"Disk {disk_id} in Projekt {project_id} verwendet einen Customer-Managed Encryption Key."`
- expected_state: "Disk mit Customer-Managed Encryption Key (CMEK) verschlüsselt"
- audit_evidence: "disk.disk_encryption_key.kms_key_name is set" (Literal, kein f-String)

---

### GCP-NR8-003 — SSL-Policy erzwingt TLS 1.2+

Klassen-Docstring (wörtlich): "Prüft ob SSL-Policies TLS 1.2 oder höher erzwingen."

| Feld | Wert |
|---|---|
| Klasse | `CheckSslPolicyLoadBalancer` |
| description | "Prüft ob Load Balancer SSL-Policies eine minimale TLS-Version von 1.2 erzwingen, um unsichere Verschlüsselungsprotokolle zu verhindern." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Verwendung von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["compute.sslPolicies.list"]` |
| pruefgrenzen | "Prüft nur explizit angelegte SSL-Policies. Load Balancer ohne zugewiesene SSL-Policy (GCP-Default) und Policies ohne auslesbare TLS-Mindestversion werden nicht bewertet." |
| Prüflogik (deskriptiv) | `SslPoliciesClient.list()` je Projekt; je Policy wird `min_tls_version` ausgelesen — gesetzt und nicht `"TLS_1_0"`/`"TLS_1_1"` ergibt Positivnachweis, gesetzt und `"TLS_1_0"`/`"TLS_1_1"` ergibt Mangel-Finding, je Policy. Ein leerer `min_tls_version`-Wert erzeugt weder Positiv- noch Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "SSL-Policy erlaubt unsicheres TLS-Protokoll"
- description (Template): `f"SSL-Policy {policy_id} in Projekt {project_id} erlaubt {min_tls}. TLS 1.0 und 1.1 gelten als unsicher und sollten deaktiviert werden."`
- expected_state: "Minimale TLS-Version TLS_1_2"
- remediation: "Aktualisieren Sie die SSL-Policy:\ngcloud compute ssl-policies update <POLICY_NAME> --min-tls-version=1.2 --project=<PROJECT_ID>"
- remediation_effort: LOW
- audit_evidence (Template): `f"SslPolicy.min_tls_version={min_tls}"`

**Positivnachweis (compliant_finding):**
- title: "SSL-Policy erzwingt sicheres TLS"
- description (Template): `f"SSL-Policy {policy_id} in Projekt {project_id} erzwingt mindestens {min_tls}."`
- expected_state: "Minimale TLS-Version TLS_1_2"
- audit_evidence (Template): `f"SslPolicy.min_tls_version={min_tls}"` (identisches Template wie im Mangel-Pfad)

---

### GCP-NR8-004 — Cloud SQL SSL-Verschlüsselung erzwungen

Klassen-Docstring (wörtlich): "Prüft ob Cloud SQL-Instanzen SSL/TLS-Verbindungen erzwingen."

| Feld | Wert |
|---|---|
| Klasse | `CheckCloudSqlSsl` |
| description | "Prüft ob Cloud SQL-Instanzen SSL/TLS-Verbindungen für alle Client-Verbindungen erzwingen." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Verwendung von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["cloudsql.instances.list"]` |
| pruefgrenzen | "Prüft nur die SSL-Erzwingung der Cloud-SQL-Instanzen (requireSsl/sslMode). Client-seitige Konfiguration wird nicht geprüft." |
| Prüflogik (deskriptiv) | `sqladmin`-API v1beta4: `instances().list(project)` je Projekt; je Instanz wird `ipConfiguration.requireSsl` und `ipConfiguration.sslMode` ausgelesen; `ssl_enforced = requireSsl or sslMode in ("ENCRYPTED_ONLY", "TRUSTED_CLIENT_CERTIFICATE_REQUIRED")` — `True` ergibt Positivnachweis, `False` ergibt Mangel-Finding, je Instanz. |

**Finding-Texte (Mangel-Pfad):**
- title: "Cloud SQL ohne SSL-Erzwingung"
- description (Template): `f"Cloud SQL-Instanz {instance_id} in Projekt {project_id} erzwingt keine SSL/TLS-Verbindungen. Unverschlüsselte Datenbankverbindungen ermöglichen das Abfangen von Daten im Transit."`
- expected_state: "SSL/TLS-Verbindungen erzwungen (requireSsl=true oder sslMode=ENCRYPTED_ONLY)"
- remediation: "Erzwingen Sie SSL für die Cloud SQL-Instanz:\ngcloud sql instances patch <INSTANCE_NAME> --require-ssl --project=<PROJECT_ID>"
- remediation_effort: LOW
- audit_evidence (Template): `f"requireSsl={require_ssl}, sslMode={ssl_mode or 'not set'}"`

**Positivnachweis (compliant_finding):**
- title: "Cloud SQL mit SSL-Erzwingung"
- description (Template): `f"Cloud SQL-Instanz {instance_id} in Projekt {project_id} erzwingt SSL/TLS-Verbindungen."`
- expected_state: "SSL/TLS-Verbindungen erzwungen (requireSsl=true oder sslMode=ENCRYPTED_ONLY)"
- audit_evidence (Template): `f"requireSsl={require_ssl}, sslMode={ssl_mode or 'not set'}"` (identisches Template wie im Mangel-Pfad)

---

### GCP-NR8-005 — Persistent Disk Verschlüsselung

Klassen-Docstring (wörtlich): "Prüft ob alle Persistent Disks verschlüsselt sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckDiskEncryption` |
| description | "Prüft ob alle Persistent Disks verschlüsselt sind. GCP verschlüsselt standardmäßig alle Daten, daher wird nur geprüft, ob Disks in einem ungewöhnlichen Zustand sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Verwendung von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["compute.disks.list"]` |
| pruefgrenzen | "GCP verschlüsselt Persistent Disks immer standardmäßig; dieser Check bestätigt nur den Disk-Zustand (READY) als Indiz der aktiven Plattformverschlüsselung. Er prüft keine Schlüsselstärke und keine kundenseitige Schlüsselkontrolle — dafür siehe den CMEK-Check (GCP-NR8-002)." |
| Prüflogik (deskriptiv) | `DisksClient.aggregated_list()` je Projekt; je Disk: `disk.status == "READY"` ergibt Positivnachweis, ein anderer nicht-leerer Status ergibt Mangel-Finding, je Disk. Ein leerer/fehlender `disk.status` erzeugt weder Positiv- noch Mangel-Finding. Zusätzlich wird je Projekt ein strukturierter Log-Eintrag `logger.info("disk.encryption.checked", project=project_id)` erzeugt (kein Finding-Bestandteil). |

**Finding-Texte (Mangel-Pfad):**
- title: "Disk in ungewöhnlichem Zustand"
- description (Template): `f"Disk {disk_id} in Projekt {project_id} befindet sich im Zustand '{disk.status}'. Der Verschlüsselungsstatus kann nicht verifiziert werden."`
- expected_state: "Disk-Status READY mit aktiver Verschlüsselung"
- remediation: "Überprüfen Sie den Disk-Status:\ngcloud compute disks describe <DISK_NAME> --zone=<ZONE> --project=<PROJECT_ID>\nStellen Sie sicher, dass der Disk im READY-Zustand ist."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"disk.status={disk.status}, expected=READY"`

**Positivnachweis (compliant_finding):**
- title: "Disk verschlüsselt (READY)"
- description (Template): `f"Disk {disk_id} in Projekt {project_id} ist im Zustand READY — die GCP-Standardverschlüsselung ist aktiv."`
- expected_state: "Disk-Status READY mit aktiver Verschlüsselung"
- audit_evidence: "disk.status=READY (GCP default encryption)" (Literal, kein f-String)

---

### GCP-NR8-006 — Certificate Manager — Zertifikate nicht abgelaufen

Klassen-Docstring (wörtlich): "Prüft ob verwaltete Zertifikate nicht abgelaufen sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckCertificateManager` |
| description | "Prüft ob über den Certificate Manager verwaltete Zertifikate noch gültig sind und nicht abgelaufen sind." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.24 Verwendung von Kryptografie" (identisch in beiden Pfaden) |
| required_permissions | `["certificatemanager.certs.list"]` |
| pruefgrenzen | "Prüft nur im Certificate Manager verwaltete Zertifikate. Extern verwaltete Zertifikate werden nicht erkannt." |
| Prüflogik (deskriptiv) | `certificatemanager`-API v1: `projects().locations().certificates().list(parent=alle Locations)` je Projekt; je Zertifikat wird `expireTime` (ISO-8601) geparst — fehlt das Feld oder schlägt das Parsen fehl (`ValueError`/`TypeError`), wird das Zertifikat übersprungen (kein Finding, kein Error); `expire_time >= now` ergibt Positivnachweis, sonst Mangel-Finding, je Zertifikat. Binäre Unterscheidung ohne Vorwarnzeitraum. |

**Finding-Texte (Mangel-Pfad):**
- title: "Abgelaufenes Zertifikat im Certificate Manager"
- description (Template): `f"Zertifikat {cert_id} in Projekt {project_id} ist am {expire_time.strftime('%Y-%m-%d')} abgelaufen. Abgelaufene Zertifikate verhindern sichere TLS-Verbindungen."`
- expected_state: "Zertifikat gültig und nicht abgelaufen"
- remediation: "Erneuern Sie das Zertifikat:\ngcloud certificate-manager certificates create <CERT_NAME> --domains=<DOMAIN> --project=<PROJECT_ID>\nOder verwenden Sie verwaltete Zertifikate für automatische Erneuerung."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"certificate.expireTime={expire_time_str}, now={now.isoformat()}"`

**Positivnachweis (compliant_finding):**
- title: "Zertifikat gültig"
- description (Template): `f"Zertifikat {cert_id} in Projekt {project_id} ist bis {expire_time.strftime('%Y-%m-%d')} gültig."`
- expected_state: "Zertifikat gültig und nicht abgelaufen"
- audit_evidence (Template): `f"certificate.expireTime={expire_time_str}, now={now.isoformat()}"` (identisches Template wie im Mangel-Pfad)

---

## Mechanische Auffälligkeiten (ohne Bewertung)

1. Für dieselbe ISO-27001-Kontrollnummer A.8.24 verwenden alle drei Provider unterschiedlichen Wortlaut: AWS `ISO_CONTROL = "A.8.24 Use of cryptography"` (Englisch, Modul-Konstante), Azure inline-Literal "A.8.24 Einsatz von Kryptografie" (Deutsch) und GCP inline-Literal "A.8.24 Verwendung von Kryptografie" (Deutsch, anderer Wortlaut als Azure) — drei verschiedene Texte für dieselbe Kontrolle, obwohl laut CLAUDE.md sämtlicher Report-Text auf Deutsch sein soll.
2. Nur das AWS-Modul definiert eine wiederverwendbare Modulkonstante für den ISO-Text (`ISO_CONTROL`); Azure und GCP wiederholen ihr jeweiliges Literal an allen 6 Aufrufstellen pro Modul einzeln.
3. AWS-NR8-001 (S3): Mangel-Pfad-`description` und -`audit_evidence` sind statische Literale ohne eingebetteten Bucket-Namen ("Der S3-Bucket hat keine..." / "...for bucket"); der Bucket-Name erscheint nur in `resource_id`. Der Positiv-Pfad interpoliert den Bucket-Namen dagegen in beide Felder.
4. AWS-NR8-001: Ein Positivnachweis wird bereits erzeugt, wenn `get_bucket_encryption()` ohne Exception zurückkehrt — auch wenn `Rules` leer ist und `sse_algorithm` auf den Literal-Wert "unknown" zurückfällt; die Positiv-Beschreibung lautet dann wörtlich "...Default-Verschlüsselung (unknown) aktiviert".
5. AWS-NR8-002 (EBS) und AWS-NR8-003 (RDS): wie Punkt 3 sind die Mangel-Pfad-`description`-Texte statische Literale ohne Ressourcen-Identifier ("Das EBS-Volume ist nicht verschlüsselt...", "Die RDS-Datenbankinstanz hat keine Storage-Verschlüsselung..."); der Identifier erscheint nur in `resource_id`/`audit_evidence`.
6. AWS-NR8-004 (KMS Key Rotation): sowohl Mangel- als auch Positiv-Pfad-`description` sind statische Literale ohne `key_id` ("Der KMS Customer-Managed Key hat [keine] automatische Key-Rotation aktiviert."); der Identifier erscheint nur in `resource_id`/`audit_evidence`.
7. AWS-NR8-003 (RDS) vergibt severity CRITICAL für fehlende Storage-Verschlüsselung, während AWS-NR8-002 (EBS) für die strukturell analoge Situation ("Daten at Rest ungeschützt") severity HIGH vergibt.
8. AWS-NR8-007 (ACM) leitet aus einem kontinuierlichen `days_remaining`-Wert mit zwei festen Schwellen (`< 0`, `<= ACM_EXPIRY_WARNING_DAYS = 30`) drei Zustände ab (CRITICAL/HIGH/Positivnachweis) — abweichend vom binären Mangel/Positiv-Muster der übrigen 18 Checks dieses Batches.
9. AWS-NR8-005 (`CheckTlsPolicy`) und AWS-NR8-006 (`CheckElbTlsMinVersion`) bewerten dieselbe Ressourcenklasse (HTTPS-Listener von ELB/ALB) über zwei unterschiedliche Mechanismen: -005 gleicht den `SslPolicy`-Namen gegen eine feste Namensliste (`SECURE_POLICIES`, 7 Einträge) ab, -006 fragt über `DescribeSSLPolicies` die tatsächlich erlaubten `SslProtocols` ab und prüft nur auf Abwesenheit von TLSv1/TLSv1.1. Ein Listener mit unbenannter/unlisted Policy, die de facto nur TLS 1.2+ erlaubt, würde bei -005 als Mangel erscheinen, bei -006 als Positivnachweis; eine Rückkopplung zwischen beiden Checks findet im Code nicht statt.
10. AWS-NR8-005: Ein HTTPS-Listener mit leerem `SslPolicy`-Wert erzeugt weder Positiv- noch Mangel-Finding (der `elif policy:`-Zweig setzt einen nicht-leeren Wert voraus) und erscheint im Scan-Ergebnis für diesen Check nicht.
11. AWS-NR8-006: Liefert `describe_ssl_policies()` für den benannten Policy-Namen eine leere Liste zurück, wird der Listener mit `continue` übersprungen — kein Finding, kein `CheckError`.
12. AZ-NR8-004 (`CheckKeyVaultRotation`): Klassenname, `title` ("Key Vault Rotation Policy") und `pruefgrenzen`-Text ("Prüft nur Rotation-Policies der Key-Vault-Schlüssel...") benennen Schlüsselrotation; der Code selbst prüft ausschließlich `enable_soft_delete` und `enable_purge_protection` der Vault-Eigenschaften — eine Rotationsperiode eines Schlüssels wird an keiner Stelle abgefragt.
13. AZ-NR8-001 und AZ-NR8-002: Hat eine Subscription null Storage Accounts bzw. null Disks, feuert weder der aggregierte Positiv- noch der Mangel-Zweig (`if accounts and not platform_managed` / `elif platform_managed` setzen jeweils eine nicht-leere Liste voraus) — die Subscription erscheint im Scan-Ergebnis für diesen Check nicht.
14. AZ-NR8-003 (`CheckSqlTde`) und AZ-NR8-004 (`CheckKeyVaultRotation`) fangen die pro-Datenbank- bzw. pro-Vault-innere Exception jeweils mit `except Exception: pass` ab — ohne `CheckError` und ohne Finding für die betroffene Datenbank/den betroffenen Vault; sie erscheinen im Scan-Ergebnis für diesen Check gar nicht.
15. AZ-NR8-005 (`CheckAppServiceHttps`): der TLS-Versionsvergleich erfolgt als lexikografischer String-Vergleich (`tls_version < "1.2"`), nicht als semantischer Versionsvergleich. Zusätzlich wird der TLS-Teilvermerk nur gebildet, wenn `site_config.min_tls_version` gesetzt ist; fehlt dieses Feld, erhält eine App mit `https_only=True`, aber unbekannter TLS-Mindestversion, einen Positivnachweis mit dem Wortlaut "erzwingt HTTPS-Only und TLS >= 1.2", ohne dass die TLS-Version tatsächlich ausgelesen wurde.
16. AZ-NR8-006 (`CheckAppGatewayTls`): Für ein Application Gateway mit vorhandenem `ssl_policy`-Objekt, aber ohne gesetztes `min_protocol_version`, trifft weder der `if`- noch der `elif not ssl_policy`-Zweig zu — es entsteht weder Positiv- noch Mangel-Finding, kein `CheckError`; das Gateway erscheint im Scan-Ergebnis für diesen Check nicht.
17. GCP-NR8-001 (`CheckKmsKeyRotation`): die hinterlegte `remediation` empfiehlt `--rotation-period=90d`, während der Check selbst jede Rotationsperiode bis einschließlich `MAX_ROTATION_DAYS = 365` Tagen als Positivnachweis wertet — Prüfschwelle (365 Tage) und Remediation-Empfehlung (90 Tage) weichen voneinander ab.
18. GCP-NR8-003 (`CheckSslPolicyLoadBalancer`) behandelt jeden `min_tls_version`-Wert außer den zwei explizit gelisteten unsicheren Werten (`TLS_1_0`, `TLS_1_1`) implizit als sicher (`if min_tls and min_tls not in (...)`) — auch unbekannte künftige Werte würden als Positivnachweis gewertet.
19. GCP-NR8-004 (`CheckCloudSqlSsl`): `current_state["ssl_mode"]` verwendet für denselben Fall (leerer `sslMode`-String) je nach Pfad einen anderen Default-Wert: im Positivnachweis `ssl_mode or "requireSsl"`, im Mangel-Finding `ssl_mode or "ALLOW_UNENCRYPTED_AND_ENCRYPTED"`.
20. GCP-NR8-005 (`CheckDiskEncryption`) meldet eine Disk im Zustand ungleich `READY` als Mangel-Finding mit severity HIGH und dem Titel "Disk in ungewöhnlichem Zustand"; laut eigener `pruefgrenzen`-Angabe und `description` ist die GCP-Standardverschlüsselung jedoch "immer" aktiv und der Disk-Status dient nur als Indiz — die Mangel-`description` selbst formuliert entsprechend zurückhaltend ("Der Verschlüsselungsstatus kann nicht verifiziert werden"). Bei leerem/fehlendem `disk.status` entsteht weder Positiv- noch Mangel-Finding.
21. GCP-NR8-006 (`CheckCertificateManager`) verwendet eine binäre Unterscheidung (abgelaufen ja/nein) ohne Vorwarnzeitraum — anders als der strukturell vergleichbare AWS-Check AWS-NR8-007 (ACM), der mit `ACM_EXPIRY_WARNING_DAYS = 30` eine dreistufige Bewertung (abgelaufen/CRITICAL, bald ablaufend/HIGH, gültig) vornimmt.
22. Innerhalb dieses Nr.-8-Batches tragen mehrere Check-Klassen in unterschiedlichen Provider-Modulen identische Klassennamen: `CheckKmsKeyRotation` (AWS-NR8-004 und GCP-NR8-001) sowie `CheckDiskEncryption` (AZ-NR8-002 und GCP-NR8-005) — jeweils unterschiedliche Prüflogik unter demselben Klassennamen in unterschiedlichen Modulen.
23. `CheckError()`-Aufrufe unterscheiden sich zwischen Providern: AWS und GCP übergeben nur `message` und `error_type`; Azure übergibt zusätzlich `check_id` und `region="global"` — dasselbe Muster wie in den bereits vorliegenden Nr.-1/3/5-Dossiers vermerkt.
24. Klassendocstrings sind sprachlich uneinheitlich zwischen Providern: alle 7 AWS-Klassen haben englische Docstrings ("Check that..."); keine der 6 Azure-Klassen hat einen Klassen-Docstring; alle 6 GCP-Klassen haben deutsche Docstrings ("Prüft ob...") — dasselbe Sprachmuster wie in den Nr.-1/3/5-Dossiers vermerkt.
25. Granularität der Findings ist zwischen den Providern uneinheitlich: AWS erzeugt bei allen 7 Checks je ein Finding pro Einzelressource (Bucket/Volume/Instanz/Key/Listener/Zertifikat); Azure erzeugt bei AZ-NR8-001 und AZ-NR8-002 je ein aggregiertes Finding pro Subscription, bei AZ-NR8-003 bis -006 je ein Finding pro Einzelressource; GCP erzeugt bei allen 6 Checks je ein Finding pro Einzelressource — AWS und GCP sind durchgängig auf Einzelressourcen-Ebene granular, Azure mischt aggregierte und Einzelressourcen-Findings innerhalb desselben Moduls.
