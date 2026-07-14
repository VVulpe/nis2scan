# W4 Batch-Review-Dossier — §30 Abs. 2 Nr. 9 BSIG (Personalsicherheit, Zugriffskontrolle und IKT-Verwaltung)

> Mechanisch extrahiert am 2026-07-13 (Worker, ohne rechtliche Bewertung).
> Prüfgegenstand für: Gründer + Agent legal-reviewer (ADR-0018).

Quelldateien:
- `nis2scan/engine/providers/aws/checks/nr9_zugriffskontrolle.py`
- `nis2scan/engine/providers/azure/checks/nr9_zugriffskontrolle.py`
- `nis2scan/engine/providers/gcp/checks/nr9_zugriffskontrolle.py`

Ist-Zahl erfasster Checks: **22** (AWS: 7, Azure: 7, GCP: 8) — entspricht der erwarteten Zahl.

Hinweis: GCP-NR9-008 (`CheckVpcServiceControls`, am Dateiende des GCP-Moduls) wurde
**bereits im Nr.-1-Batch zweitgeprüft (Umzug aus Nr. 1), 2026-07-12** — wird hier
dennoch vollständig mit extrahiert.

## Modul-Konstanten je Provider

### AWS (`nr9_zugriffskontrolle.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 9 — Zugriffskontrolle & Asset-Management checks for AWS.

  Checks IAM users, access keys, S3 public access, security group rules,
  IAM policy wildcards, and S3 bucket policies.
  ```
- `BSIG_30_NR = 9`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 9 BSIG — Erstellung von Konzepten für die Sicherheit des Personals, die Zugriffskontrolle und für die Verwaltung von IKT-Systemen, -Produkten und -Prozessen"
- `ISO_CONTROL_ACCESS = "A.5.15-A.5.18 Access control"`
- `ISO_CONTROL_ASSET = "A.5.9-A.5.14 Asset management"` — im gesamten Modul an keiner Aufrufstelle referenziert (siehe Auffälligkeiten).
- `ACCESS_KEY_MAX_AGE_DAYS = 90`
- `UNUSED_CREDENTIAL_DAYS = 90`

### Azure (`nr9_zugriffskontrolle.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 9 — Zugriffskontrolle & Asset-Management checks for Azure.

  Checks Conditional Access, PIM, NSG rules, Storage public access,
  Classic Admins, Guest Access Restrictions, and Stale Service Principals.
  ```
- `BSIG_30_NR = 9`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS): "§30 Abs. 2 Nr. 9 BSIG — Erstellung von Konzepten für die Sicherheit des Personals, die Zugriffskontrolle und für die Verwaltung von IKT-Systemen, -Produkten und -Prozessen"
- `OPEN_SOURCE_PREFIXES = {"*", "0.0.0.0/0", "Internet", "0.0.0.0", "<nw>/0"}`
- `MAX_INACTIVE_DAYS = 90`
- Kein Modul-Äquivalent zu einer ISO-Kontroll-Konstante — jeder Check trägt sein eigenes inline-Literal (sieben unterschiedliche Texte, siehe je Check).

### GCP (`nr9_zugriffskontrolle.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 9 — Zugriffskontrolle und Anlagenmanagement checks for GCP.

  Checks IAM Least Privilege, Service Account Hygiene, Identity-Aware Proxy,
  VPC Firewall Rules, Storage Bucket Public Access, Org Constraints,
  Inactive Principals, and VPC Service Controls.
  ```
- `BSIG_30_NR = 9`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS/Azure): "§30 Abs. 2 Nr. 9 BSIG — Erstellung von Konzepten für die Sicherheit des Personals, die Zugriffskontrolle und für die Verwaltung von IKT-Systemen, -Produkten und -Prozessen"
- `OVERLY_BROAD_ROLES = ["roles/owner", "roles/editor"]`
- `MAX_SA_KEY_AGE_DAYS = 90`
- `IMPORTANT_ORG_CONSTRAINTS` (wörtlich, Liste):
  ```python
  IMPORTANT_ORG_CONSTRAINTS = [
      "iam.allowedPolicyMemberDomains",
      "compute.restrictSharedVpcSubnetworks",
      "compute.disableSerialPortAccess",
      "iam.disableServiceAccountKeyCreation",
      "compute.requireOsLogin",
  ]
  ```
- Kein Modul-Äquivalent zu einer ISO-Kontroll-Konstante — jeder Check trägt sein eigenes inline-Literal.

---

## Checks

### AWS-NR9-001 — IAM User MFA Status

Klassen-Docstring (wörtlich): "Check that all IAM users have MFA enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckIamMfa` |
| description | "Prüft ob alle IAM-Benutzer MFA aktiviert haben." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL_ACCESS` = "A.5.15-A.5.18 Access control" (identisch in beiden Pfaden) |
| required_permissions | `["iam:ListUsers", "iam:ListMFADevices"]` |
| pruefgrenzen | "Prüft nur IAM-Benutzer mit Konsolen-Login. Föderierte Zugänge (SSO/IdP) werden vom Identitätsanbieter durchgesetzt und hier nicht geprüft." |
| Prüflogik (deskriptiv) | `iam.get_paginator("list_users").paginate()` (paginiert) ermittelt alle IAM-Benutzer; je Benutzer liefert `iam.list_mfa_devices(UserName=username)` die MFA-Geräte — mindestens 1 Gerät ergibt Positivnachweis, keine Geräte ergibt Mangel-Finding, je Benutzer. Es erfolgt keine Prüfung, ob der Benutzer überhaupt einen Konsolen-Login (LoginProfile) besitzt. |

**Finding-Texte (Mangel-Pfad):**
- title: "IAM-Benutzer ohne MFA"
- description (Template, aus Teilstrings zusammengesetzt): "Der IAM-Benutzer '{username}' hat keine MFA-Authentifizierung konfiguriert. Ohne MFA ist der Account anfällig für Credential-basierte Angriffe."
- expected_state: "MFA aktiviert (Virtual MFA, Hardware-Token, oder FIDO2)"
- remediation: "Aktivieren Sie MFA für den IAM-Benutzer. Empfohlen: FIDO2 Security Key oder Virtual MFA App. AWS Console: IAM → Users → Security credentials → MFA"
- remediation_effort: LOW
- audit_evidence (Template): `f"ListMFADevices returned 0 devices for user {username}"`

**Positivnachweis (compliant_finding):**
- title: "IAM-Benutzer mit MFA"
- description (Template): `f"Der IAM-Benutzer '{username}' hat MFA-Authentifizierung konfiguriert."`
- expected_state: "MFA aktiviert (Virtual MFA, Hardware-Token, oder FIDO2)"
- audit_evidence (Template): `f"ListMFADevices returned {len(mfa_devices)} device(s) for user {username}"`

---

### AWS-NR9-002 — IAM Access Key Rotation

Klassen-Docstring (wörtlich): "Check that IAM access keys are not older than 90 days."

| Feld | Wert |
|---|---|
| Klasse | `CheckIamAccessKeyAge` |
| description | (Template) `f"Prüft ob IAM Access Keys älter als {ACCESS_KEY_MAX_AGE_DAYS} Tage sind."` |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL_ACCESS` = "A.5.15-A.5.18 Access control" (identisch in beiden Pfaden) |
| required_permissions | `["iam:ListUsers", "iam:ListAccessKeys"]` |
| pruefgrenzen | "Prüft nur das Alter aktiver IAM-Access-Keys. Ob ein Key kompromittiert oder ungenutzt ist, wird in AWS-NR9-007 bzw. gar nicht geprüft." |
| Prüflogik (deskriptiv) | `iam.get_paginator("list_users").paginate()` ermittelt alle IAM-Benutzer; je Benutzer liefert `iam.list_access_keys(UserName=username)` die Access-Key-Metadaten; nur Keys mit `Status=="Active"` werden bewertet (inaktive Keys werden übersprungen); Alter in Tagen (`now - CreateDate`) wird gegen `ACCESS_KEY_MAX_AGE_DAYS` (90) verglichen — `<=90` ergibt Positivnachweis, `>90` ergibt Mangel-Finding, je aktivem Access Key. |

**Finding-Texte (Mangel-Pfad):**
- title: "IAM Access Key älter als 90 Tage"
- description (Template, aus Teilstrings zusammengesetzt): "Der aktive Access Key für Benutzer '{username}' ist {age_days} Tage alt. Access Keys sollten regelmäßig rotiert werden."
- expected_state (Template): `f"Access Key nicht älter als {ACCESS_KEY_MAX_AGE_DAYS} Tage"`
- remediation: "Erstellen Sie einen neuen Access Key und deaktivieren/löschen Sie den alten. Besser: Nutzen Sie IAM Roles statt langlebiger Access Keys."
- remediation_effort: LOW
- audit_evidence (Template): `f"ListAccessKeys: Key age={age_days}d for user {username}"`

**Positivnachweis (compliant_finding):**
- title: "IAM Access Key aktuell rotiert"
- description (Template, aus Teilstrings zusammengesetzt): "Der aktive Access Key für Benutzer '{username}' ist {age_days} Tage alt (Maximum: {ACCESS_KEY_MAX_AGE_DAYS} Tage)."
- expected_state (Template): `f"Access Key nicht älter als {ACCESS_KEY_MAX_AGE_DAYS} Tage"` (identisches Template wie im Mangel-Pfad)
- audit_evidence (Template): `f"ListAccessKeys: Key age={age_days}d for user {username}"` (identisches Template wie im Mangel-Pfad)

---

### AWS-NR9-003 — S3 Account-Level Public Access Block

Klassen-Docstring (wörtlich): "Check that S3 public access block is enabled at account level."

| Feld | Wert |
|---|---|
| Klasse | `CheckS3PublicAccessBlock` |
| description | "Prüft ob der S3 Public Access Block auf Account-Ebene aktiviert ist." |
| severity | CRITICAL (beide Mangel-Pfade, inline) |
| iso27001_control | `ISO_CONTROL_ACCESS` (Positiv- und ein Mangel-Pfad); zweiter Mangel-Pfad ("nicht konfiguriert") ebenfalls `ISO_CONTROL_ACCESS` |
| required_permissions | `["s3:GetAccountPublicAccessBlock"]` |
| pruefgrenzen | "Prüft nur den Account-weiten S3 Public Access Block. Bucket-Ebene wird in AWS-NR9-006 geprüft; andere öffentlich exponierbare Dienste sind nicht erfasst." |
| Prüflogik (deskriptiv) | `s3control.get_public_access_block(AccountId=account_id)` liefert die vier Account-weiten Public-Access-Block-Flags; `all()` aller vier Flags==`True` ergibt einen Positivnachweis, sonst ein Mangel-Finding (je Account, aggregiert); wirft der Aufruf eine Exception mit `"NoSuchPublicAccessBlockConfiguration"` im Text, wird ein gesondertes Mangel-Finding "nicht konfiguriert" erzeugt; jede andere Exception wird als `CheckError` erfasst. |

**Finding-Texte (Mangel-Pfad, Teil 1 — nicht vollständig aktiviert):**
- title: "S3 Public Access Block nicht vollständig aktiviert"
- description: "Der S3 Public Access Block auf Account-Ebene ist nicht vollständig aktiviert. Dies ermöglicht potenziell öffentlichen Zugriff auf S3-Buckets."
- expected_state: "Alle vier Public Access Block Einstellungen auf true"
- remediation: "Aktivieren Sie alle vier S3 Public Access Block Einstellungen auf Account-Ebene: aws s3control put-public-access-block --account-id <id> --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
- remediation_effort: LOW
- audit_evidence (Template): `f"GetPublicAccessBlock: {config}"`

**Finding-Texte (Mangel-Pfad, Teil 2 — nicht konfiguriert):**
- title: "S3 Public Access Block nicht konfiguriert"
- description: "Kein S3 Public Access Block auf Account-Ebene konfiguriert."
- expected_state: "S3 Public Access Block vollständig konfiguriert und aktiviert"
- remediation: "Konfigurieren Sie den S3 Public Access Block auf Account-Ebene. Dies ist eine der wichtigsten Sicherheitsmaßnahmen für S3."
- remediation_effort: LOW
- audit_evidence: "GetPublicAccessBlock: NoSuchPublicAccessBlockConfiguration" (Literal)

**Positivnachweis (compliant_finding):**
- title: "S3 Public Access Block vollständig aktiviert"
- description: "Alle vier S3 Public Access Block Einstellungen sind auf Account-Ebene aktiviert."
- expected_state: "Alle vier Public Access Block Einstellungen auf true"
- audit_evidence (Template): `f"GetPublicAccessBlock: {config}"` (identisches Template wie Mangel-Teil-1)

---

### AWS-NR9-004 — Security Group Open Access

Klassen-Docstring (wörtlich): "Check for security groups with unrestricted inbound access (0.0.0.0/0)."

| Feld | Wert |
|---|---|
| Klasse | `CheckSecurityGroupOpenAccess` |
| description | "Prüft ob Security Groups unrestricted Inbound-Zugriff (0.0.0.0/0) auf kritische Ports erlauben." |
| severity | CRITICAL oder HIGH (Mangel-Pfad, inline, abhängig von Portlage — siehe Prüflogik) |
| iso27001_control | `ISO_CONTROL_ACCESS` (identisch in beiden Pfaden) |
| required_permissions | `["ec2:DescribeSecurityGroups"]` |
| pruefgrenzen | "Prüft Security-Group-Regeln auf offene administrative Ports (SSH/RDP u. a.) von 0.0.0.0/0. Ob hinter einer offenen Regel tatsächlich eine Instanz erreichbar ist (Routing, NACLs), wird nicht geprüft." |
| Klassenkonstante `CRITICAL_PORTS` (wörtlich) | `{22: "SSH", 3389: "RDP", 3306: "MySQL", 5432: "PostgreSQL", 1433: "MSSQL", 27017: "MongoDB"}` |
| Prüflogik (deskriptiv) | Je Region (`session.regions`) liefert `ec2.get_paginator("describe_security_groups").paginate()` alle Security Groups; je Security Group werden alle `IpPermissions`-Regeln und deren `IpRanges` durchsucht — jede Regel mit `CidrIp=="0.0.0.0/0"` erzeugt ein eigenes Mangel-Finding: liegt mindestens ein `CRITICAL_PORTS`-Port im Portbereich → severity CRITICAL; ist der Portbereich exakt 0–65535 → severity CRITICAL; sonst → severity HIGH. IPv6-Bereiche (`Ipv6Ranges`) werden nicht durchsucht. Hat eine Security Group keine einzige 0.0.0.0/0-Regel, wird ein Positivnachweis für die gesamte Security Group erzeugt (mehrere Mangel-Findings pro Security Group möglich, aber nur ein Positivnachweis). |

**Finding-Texte (Mangel-Pfad):**
- title (Template): `f"Security Group mit öffentlichem Zugriff auf {port_desc}"`
- description (Template): `f"Die Security Group '{sg_id}' erlaubt eingehenden Zugriff von 0.0.0.0/0 auf Port(s) {port_desc}."`
- expected_state: "Kein unrestricted Inbound-Zugriff auf kritische Ports"
- remediation: "Beschränken Sie den Zugriff auf spezifische IP-Bereiche oder verwenden Sie AWS Systems Manager Session Manager für SSH-Zugriff anstelle von öffentlichen Security-Group-Regeln."
- remediation_effort: LOW
- audit_evidence (Template): `f"DescribeSecurityGroups: {sg_id} allows 0.0.0.0/0 on {port_desc}"`

**Positivnachweis (compliant_finding):**
- title: "Security Group ohne öffentlichen Zugriff"
- description (Template): `f"Die Security Group '{sg_id}' erlaubt keinen eingehenden Zugriff von 0.0.0.0/0."`
- expected_state: "Kein unrestricted Inbound-Zugriff auf kritische Ports" (identisch zum Mangel-Pfad)
- audit_evidence (Template): `f"DescribeSecurityGroups: {sg_id} has no 0.0.0.0/0 inbound rule"`

---

### AWS-NR9-005 — IAM Wildcard Policies

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckIamWildcardPolicy` |
| description | "Prüft ob IAM-Policies Wildcard-Berechtigungen (Action: * oder Resource: *) enthalten, die gegen das Least-Privilege-Prinzip verstoßen." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL_ACCESS` (identisch in beiden Pfaden) |
| required_permissions | `["iam:ListPolicies", "iam:GetPolicy", "iam:GetPolicyVersion"]` |
| pruefgrenzen | "Prüft kundenverwaltete IAM-Policies auf Wildcard-Berechtigungen (Action/Resource = *). AWS-verwaltete Policies und die effektive Wirkung über Policy-Kombinationen werden nicht bewertet." |
| Prüflogik (deskriptiv) | `iam.get_paginator("list_policies").paginate(Scope="Local", OnlyAttached=False)` ermittelt alle kundenverwalteten (Local) IAM-Policies; je Policy liefert `iam.get_policy_version(PolicyArn=..., VersionId=DefaultVersionId)` das Policy-Dokument (ggf. URL-dekodiert). Je Allow-Statement wird geprüft, ob die Action-Liste exakt das Element `"*"` enthält (→ "Action: *") bzw. ob die Resource-Liste `"*"` enthält UND zugleich die Action-Liste `"*"` enthält (→ "Resource: * with Action: *") — jeweils exakter Listen-Mitgliedschaftsvergleich, kein Substring-/Glob-Vergleich (z. B. `"s3:*"` oder `"arn:aws:s3:::bucket/*"` werden nicht erkannt). Keine Übereinstimmungen ergeben Positivnachweis, mindestens eine ergibt Mangel-Finding, je Policy. |

**Finding-Texte (Mangel-Pfad):**
- title: "IAM-Policy mit Wildcard-Berechtigungen"
- description (Template): `f"Die IAM-Policy '{policy_name}' enthält Wildcard-Berechtigungen: {', '.join(wildcard_issues)}. Dies verstößt gegen das Least-Privilege-Prinzip."`
- expected_state: "IAM-Policies mit spezifischen Actions und Resources nach dem Least-Privilege-Prinzip"
- remediation: "Ersetzen Sie die Wildcard-Berechtigungen durch spezifische Actions und Resources. Verwenden Sie IAM Access Analyzer um die tatsächlich benötigten Berechtigungen zu ermitteln."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"GetPolicyVersion: {', '.join(wildcard_issues)} in policy {policy_name}"`

**Positivnachweis (compliant_finding):**
- title: "IAM-Policy ohne Wildcard-Berechtigungen"
- description (Template): `f"Die IAM-Policy '{policy_name}' enthält keine Wildcard-Berechtigungen (Least-Privilege-Prinzip eingehalten)."`
- expected_state: "IAM-Policies mit spezifischen Actions und Resources nach dem Least-Privilege-Prinzip" (identisch zum Mangel-Pfad)
- audit_evidence (Template): `f"GetPolicyVersion: no wildcards in policy {policy_name}"`

---

### AWS-NR9-006 — S3 Bucket Policy Public Access

Klassen-Docstring (wörtlich): "Check for S3 bucket policies that allow public access (Principal: *)."

| Feld | Wert |
|---|---|
| Klasse | `CheckS3BucketPolicy` |
| description | "Prüft ob S3-Bucket-Policies öffentlichen Zugriff über Principal: * erlauben." |
| severity | CRITICAL (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL_ACCESS` (identisch in beiden Pfaden) |
| required_permissions | `["s3:ListAllMyBuckets", "s3:GetBucketPolicy", "s3:GetBucketLocation"]` |
| pruefgrenzen | "Prüft Bucket-Policies und ACLs auf öffentliche Freigaben. Zugriffe über CloudFront-Distributionen oder vorsignierte URLs sind nicht Gegenstand." |
| Prüflogik (deskriptiv) | `s3.list_buckets()` ermittelt alle Buckets; je Bucket liefert `s3.get_bucket_policy(Bucket=...)` die Bucket-Policy. Je Allow-Statement wird geprüft, ob `Principal=="*"` oder `Principal.AWS=="*"`/die AWS-Principal-Liste `"*"` enthält — trifft dies zu UND das Statement hat kein `Condition`-Element, wird ein Mangel-Finding erzeugt und die Prüfung für den Bucket abgebrochen (`break`, ein Finding pro Bucket); ein vorhandenes `Condition`-Element gilt unabhängig von seinem Inhalt als hinreichend restriktiv und führt zum Überspringen des Statements (`continue`, Code-Kommentar: "Conditional access is acceptable"). Ohne öffentliches Statement bzw. bei `NoSuchBucketPolicy` wird über die Hilfsmethode `_compliant_bucket()` ein Positivnachweis erzeugt. ACLs werden im Code an keiner Stelle abgefragt (kein `get_bucket_acl`-Aufruf). |

**Finding-Texte (Mangel-Pfad):**
- title: "S3-Bucket-Policy erlaubt öffentlichen Zugriff"
- description: "Die Bucket-Policy erlaubt Zugriff für Principal: *. Dies kann zu ungewollter Datenexposition führen."
- expected_state: "Kein Principal: * in Bucket-Policies"
- remediation: "Entfernen Sie den öffentlichen Zugriff aus der Bucket-Policy. Verwenden Sie stattdessen spezifische IAM-Rollen oder Account-IDs als Principal."
- remediation_effort: LOW
- audit_evidence: "GetBucketPolicy: Principal=* with Effect=Allow" (Literal)

**Positivnachweis (`_compliant_bucket()`, aufgerufen mit zwei unterschiedlichen evidence-Texten):**
- title: "S3-Bucket ohne öffentliche Bucket-Policy"
- description (Template): `f"Der S3-Bucket '{bucket_name}' erlaubt keinen öffentlichen Zugriff über die Bucket-Policy."`
- expected_state: "Kein Principal: * in Bucket-Policies"
- audit_evidence (Template): `f"GetBucketPolicy: {evidence}"` — `evidence` ist entweder "Bucket-Policy ohne Principal: *" (kein öffentliches Statement gefunden) oder "Keine Bucket-Policy vorhanden" (`NoSuchBucketPolicy`)

---

### AWS-NR9-007 — Ungenutzte IAM-Zugangsdaten

Klassen-Docstring (wörtlich): "Check for IAM access keys that have not been used in over 90 days."

| Feld | Wert |
|---|---|
| Klasse | `CheckUnusedIamCredentials` |
| description | (Template) `f"Prüft ob IAM Access Keys seit mehr als {UNUSED_CREDENTIAL_DAYS} Tagen nicht verwendet wurden."` |
| severity | MEDIUM (beide Mangel-Pfade, inline) |
| iso27001_control | `ISO_CONTROL_ACCESS` (identisch in allen Pfaden) |
| required_permissions | `["iam:ListUsers", "iam:ListAccessKeys", "iam:GetAccessKeyLastUsed"]` |
| pruefgrenzen | "Bewertet Ungenutztheit anhand der letzten Nutzung laut IAM-Credential-Daten. AWS aktualisiert diese Angaben mit Verzögerung; sehr seltene, legitime Nutzung (z. B. Break-Glass) erscheint ebenfalls als ungenutzt." |
| Prüflogik (deskriptiv) | `iam.get_paginator("list_users").paginate()` ermittelt alle IAM-Benutzer; je aktivem Access Key liefert `iam.get_access_key_last_used(AccessKeyId=...)` das letzte Nutzungsdatum. Ist `LastUsedDate` `None` (nie verwendet) UND das Erstellungsdatum liegt `> UNUSED_CREDENTIAL_DAYS` (90) Tage zurück, wird ein Mangel-Finding erzeugt — ist der Key jünger als 90 Tage und nie verwendet, wird weder Positiv- noch Mangel-Finding erzeugt. Ist `LastUsedDate` gesetzt, wird das Alter der letzten Nutzung gegen 90 Tage verglichen — `<=90` ergibt Positivnachweis, `>90` ergibt Mangel-Finding. |

**Finding-Texte (Mangel-Pfad, Teil 1 — nie verwendet):**
- title: "IAM Access Key nie verwendet"
- description (Template, aus Teilstrings zusammengesetzt): "Der Access Key für Benutzer '{username}' wurde seit der Erstellung vor {days_since_creation} Tagen nie verwendet."
- expected_state (Template, aus Teilstrings zusammengesetzt): "Access Key aktiv genutzt oder deaktiviert/gelöscht wenn > {UNUSED_CREDENTIAL_DAYS} Tage ungenutzt"
- remediation: "Deaktivieren oder löschen Sie ungenutzte Access Keys: aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <username>"
- remediation_effort: LOW
- audit_evidence (Template, aus Teilstrings zusammengesetzt): "GetAccessKeyLastUsed: never used, created {days_since_creation}d ago for {username}"

**Finding-Texte (Mangel-Pfad, Teil 2 — seit X Tagen ungenutzt):**
- title (Template): `f"IAM Access Key seit {days_unused} Tagen ungenutzt"`
- description (Template, aus Teilstrings zusammengesetzt): "Der Access Key für Benutzer '{username}' wurde seit {days_unused} Tagen nicht verwendet."
- expected_state (identisches Template wie Teil 1): "Access Key aktiv genutzt oder deaktiviert/gelöscht wenn > {UNUSED_CREDENTIAL_DAYS} Tage ungenutzt"
- remediation (identisch zu Teil 1): "Deaktivieren oder löschen Sie ungenutzte Access Keys: aws iam update-access-key --access-key-id <key-id> --status Inactive --user-name <username>"
- remediation_effort: LOW
- audit_evidence (Template): `f"GetAccessKeyLastUsed: last used {days_unused}d ago for {username}"`

**Positivnachweis (compliant_finding):**
- title: "IAM Access Key aktiv genutzt"
- description (Template, aus Teilstrings zusammengesetzt): "Der Access Key für Benutzer '{username}' wurde zuletzt vor {days_unused} Tagen verwendet."
- expected_state (identisches Template wie Mangel-Teil 1/2): "Access Key aktiv genutzt oder deaktiviert/gelöscht wenn > {UNUSED_CREDENTIAL_DAYS} Tage ungenutzt"
- audit_evidence (Template): `f"GetAccessKeyLastUsed: last used {days_unused}d ago for {username}"` (identisches Template wie Mangel-Teil 2)

---

### AZ-NR9-001 — Entra ID Conditional Access Policies

Klassen-Docstring (wörtlich): "Check that Entra ID Conditional Access policies exist."

| Feld | Wert |
|---|---|
| Klasse | `CheckConditionalAccess` |
| description | "Prüft ob Conditional Access Policies für Zugriffskontrolle konfiguriert sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.15 Zugriffskontrolle" (identisch in beiden Pfaden) |
| required_permissions | `["Policy.Read.All"]` |
| pruefgrenzen | "Prüft nur die Existenz aktivierter Conditional-Access-Policies (Graph API). Ob die Policies alle Benutzer und Risiken angemessen abdecken, wird nicht bewertet." |
| Prüflogik (deskriptiv) | `graph_client.identity.conditional_access.policies.get()` liefert alle Conditional-Access-Policies; Policies mit `state` in `{"enabled", "enabledforreportingbutnotenforced"}` (case-insensitive) gelten als "aktiv" — auch reine Report-only-Policies (nur Protokollierung, keine Durchsetzung) zählen hier als aktiv. Mindestens eine aktive Policy ergibt einen aggregierten Positivnachweis für den Tenant, keine aktive Policy ein aggregiertes Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine aktiven Conditional Access Policies"
- description: "Es sind keine aktiven Conditional Access Policies konfiguriert. Ohne CA-Policies fehlt eine risikobasierte Zugriffskontrolle."
- expected_state: "Mindestens eine aktive Conditional Access Policy"
- remediation: "Erstellen Sie Conditional Access Policies im Entra Admin Center: Entra Admin Center → Schutz → Bedingter Zugriff → Neue Richtlinie"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"Graph API: {len(policies)} total policies, 0 enabled"`

**Positivnachweis (compliant_finding):**
- title: "Conditional Access Policies aktiv"
- description (Template): `f"Es sind {len(enabled_policies)} aktive Conditional Access Policies für risikobasierte Zugriffskontrolle konfiguriert."`
- expected_state: "Mindestens eine aktive Conditional Access Policy"
- audit_evidence (Template): `f"Graph API: {len(policies)} total policies, {len(enabled_policies)} enabled"`

---

### AZ-NR9-002 — Entra ID Privileged Identity Management (PIM)

Klassen-Docstring (wörtlich): "Check that Privileged Identity Management (PIM) is configured."

| Feld | Wert |
|---|---|
| Klasse | `CheckPim` |
| description | "Prüft ob PIM für zeitlich begrenzte privilegierte Zugänge konfiguriert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.2, A.8.18 Privilegierte Zugangsrechte" (identisch in beiden Pfaden) |
| required_permissions | `["RoleManagement.Read.Directory"]` |
| pruefgrenzen | "Prüft nur, ob PIM-berechtigte Rollenzuweisungen existieren (erfordert Entra ID P2). Ohne P2-Lizenz ist der Check nicht auswertbar." |
| Prüflogik (deskriptiv) | `graph_client.role_management.directory.role_eligibility_schedule_instances.get()` liefert alle PIM-berechtigten (eligible) Rollenzuweisungen; mindestens ein Eintrag ergibt einen aggregierten Positivnachweis für den Tenant, kein Eintrag ein aggregiertes Mangel-Finding. Fehlt die P2-Lizenz, führt der zugrunde liegende API-Aufruf voraussichtlich zu einer Exception, die im generischen `except Exception`-Block als `CheckError` landet — der Code unterscheidet nicht gesondert zwischen "keine P2-Lizenz" und anderen Fehlerursachen. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein PIM konfiguriert"
- description: "Es sind keine PIM-berechtigten Rollenzuweisungen vorhanden. Ohne PIM haben privilegierte Benutzer permanente Admin-Rechte, was das Risiko von Missbrauch erhöht."
- expected_state: "PIM-berechtigte Rollenzuweisungen statt permanenter Admin-Rollen"
- remediation: "Aktivieren Sie PIM im Entra Admin Center: Entra Admin Center → Identitätsgovernance → Privileged Identity Management"
- remediation_effort: HIGH
- audit_evidence: "Graph API: 0 eligible role schedule instances" (Literal)

**Positivnachweis (compliant_finding):**
- title: "PIM konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Es sind {len(eligible)} PIM-berechtigte Rollenzuweisungen vorhanden — privilegierte Zugänge sind zeitlich begrenzt."
- expected_state: "PIM-berechtigte Rollenzuweisungen statt permanenter Admin-Rollen"
- audit_evidence (Template): `f"Graph API: {len(eligible)} eligible role schedule instances"`

---

### AZ-NR9-003 — NSG Rules — keine offenen Ports zu Internet

Klassen-Docstring (wörtlich): "Check that NSG rules don't allow unrestricted inbound access."

| Feld | Wert |
|---|---|
| Klasse | `CheckNsgOpenAccess` |
| description | "Prüft ob Network Security Groups keine offenen Inbound-Regeln aus dem Internet haben." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.20, A.8.22 Netzwerksicherheit" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Network/networkSecurityGroups/read"]` |
| pruefgrenzen | "Prüft NSG-Regeln auf offene administrative Ports von Internet. Effektive Erreichbarkeit (Firewalls, Routing) wird nicht geprüft." |
| Prüflogik (deskriptiv) | Je Subscription (`session.subscription_ids`) liefert `NetworkManagementClient.network_security_groups.list_all()` alle NSGs; je NSG werden alle `security_rules` durchsucht — eine Regel zählt als "offen", wenn `direction=="inbound"` (case-insensitive), `access=="allow"` (case-insensitive) und `source_address_prefix in OPEN_SOURCE_PREFIXES` (`{"*","0.0.0.0/0","Internet","0.0.0.0","<nw>/0"}`); das Plural-Feld `source_address_prefixes` wird nicht geprüft. Keine offene Regel ergibt Positivnachweis je NSG, mindestens eine offene Regel ein aggregiertes Mangel-Finding je NSG (Regel-Zusammenfassung der ersten 5 Regeln im description-Text, der ersten 10 im `current_state`). |

**Finding-Texte (Mangel-Pfad):**
- title: "NSG mit offenen Inbound-Regeln"
- description (Template): `f"NSG {nsg.name} in Subscription {sub_id} hat {len(open_rules)} offene Inbound-Regeln aus dem Internet: {rule_summary}."`
- expected_state: "Keine Inbound-Regeln mit Source 0.0.0.0/0 oder *"
- remediation (Template): `f"Schränken Sie die Quell-IP-Bereiche ein: az network nsg rule update --nsg-name {nsg.name} --resource-group <rg> --name <rule-name> --source-address-prefixes <trusted-ip-range>"`
- remediation_effort: LOW
- audit_evidence (Template): `f"network_security_groups.list_all(): {nsg.name} has {len(open_rules)} open inbound rules"`

**Positivnachweis (compliant_finding):**
- title: "NSG ohne offene Inbound-Regeln"
- description (Template): `f"NSG {nsg.name} hat keine Inbound-Regeln mit offener Quelle (0.0.0.0/0, * oder Internet)."`
- expected_state: "Keine Inbound-Regeln mit Source 0.0.0.0/0 oder *" (identisch zum Mangel-Pfad)
- audit_evidence (Template): `f"network_security_groups.list_all(): {nsg.name} has no open inbound rules"`

---

### AZ-NR9-004 — Storage Account — Private Access Only

Klassen-Docstring (wörtlich): "Check that Storage Accounts have public access disabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckStoragePublicAccess` |
| description | "Prüft ob Storage Accounts keinen öffentlichen Zugriff erlauben." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.15, A.8.3 Zugriffskontrolle" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Storage/storageAccounts/read"]` |
| pruefgrenzen | "Prüft nur die Netzwerkzugriffs-Einstellung der Storage Accounts. Berechtigungen auf Datenebene (SAS, Keys) werden nicht bewertet." |
| Prüflogik (deskriptiv) | Je Subscription liefert `StorageManagementClient.storage_accounts.list()` alle Storage Accounts; ein Account gilt als öffentlich, wenn `public_network_access=="Enabled"` (Default "Enabled" falls `None`) UND `network_rule_set.default_action=="Allow"` (Default "Allow" falls kein `network_rule_set` gesetzt) — beide Bedingungen case-insensitive geprüft. Existieren Accounts und ist keiner öffentlich, wird ein aggregierter Positivnachweis für die Subscription erzeugt; existieren öffentliche Accounts, wird ein aggregiertes Mangel-Finding erzeugt (Auflistung der ersten 5 Kontonamen im description-Text). Existieren keine Accounts in der Subscription, wird kein Finding erzeugt (weder Positiv- noch Mangel-Pfad). |

**Finding-Texte (Mangel-Pfad):**
- title: "Storage Accounts mit öffentlichem Zugriff"
- description (Template): `f"Subscription {sub_id} hat {len(public_accounts)} Storage Accounts mit öffentlichem Netzwerkzugriff: {', '.join(public_accounts[:5])}."`
- expected_state: "Alle Storage Accounts mit deaktiviertem öffentlichen Zugriff"
- remediation: "Deaktivieren Sie öffentlichen Zugriff: az storage account update --name <account> --resource-group <rg> --default-action Deny --public-network-access Disabled"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"storage_accounts.list(): {len(public_accounts)}/{len(accounts)} with public access enabled"`

**Positivnachweis (compliant_finding):**
- title: "Storage Accounts ohne öffentlichen Zugriff"
- description (Template): `f"Alle {len(accounts)} Storage Accounts in Subscription {sub_id} haben öffentlichen Netzwerkzugriff deaktiviert oder eingeschränkt."`
- expected_state: "Alle Storage Accounts mit deaktiviertem öffentlichen Zugriff" (identisch zum Mangel-Pfad)
- audit_evidence (Template): `f"storage_accounts.list(): 0/{len(accounts)} with public access enabled"`

---

### AZ-NR9-005 — RBAC statt klassischer Subscription-Admin-Rollen

Klassen-Docstring (wörtlich): "Check that no classic subscription administrators exist."

| Feld | Wert |
|---|---|
| Klasse | `CheckClassicAdmins` |
| description | "Prüft ob klassische Subscription-Admin-Rollen (Co-Admins) noch verwendet werden." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.15 Zugriffskontrolle" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Authorization/classicAdministrators/read"]` |
| pruefgrenzen | "Prüft nur auf klassische Administratorrollen. Die Angemessenheit der RBAC-Zuweisungen selbst wird nicht bewertet." |
| Prüflogik (deskriptiv) | Je Subscription liefert `AuthorizationManagementClient.classic_administrators.list()` alle klassischen Administratoren; gefiltert wird auf Einträge, bei denen der String `"CoAdministrator"` im (stringifizierten) `role`-Feld enthalten ist (Substring-Vergleich, `in`) — der stets vorhandene Service-Administrator wird dadurch ausgeschlossen. Keine Co-Admins ergeben einen aggregierten Positivnachweis je Subscription, mindestens ein Co-Admin ein aggregiertes Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Klassische Co-Admin-Rollen aktiv"
- description (Template, aus Teilstrings zusammengesetzt): "Subscription {sub_id} hat {len(co_admins)} klassische Co-Administratoren. Diese veralteten Rollen umgehen RBAC und sollten durch moderne Rollenzuweisungen ersetzt werden."
- expected_state: "Keine klassischen Co-Admin-Rollen — nur RBAC"
- remediation: "Entfernen Sie klassische Co-Admins und verwenden Sie RBAC: Azure Portal → Subscriptions → <Sub> → Zugriffssteuerung (IAM) → Klassische Administratoren"
- remediation_effort: LOW
- audit_evidence (Template): `f"classic_administrators.list(): {len(co_admins)} co-administrators found"`

**Positivnachweis (compliant_finding):**
- title: "Keine klassischen Co-Admin-Rollen"
- description (Template, aus Teilstrings zusammengesetzt): "Subscription {sub_id} verwendet keine klassischen Co-Administratoren — Zugriffssteuerung erfolgt über RBAC."
- expected_state: "Keine klassischen Co-Admin-Rollen — nur RBAC" (identisch zum Mangel-Pfad)
- audit_evidence: "classic_administrators.list(): 0 co-administrators found" (Literal)

---

### AZ-NR9-006 — Entra ID Guest Access Restrictions

Klassen-Docstring (wörtlich): "Check that guest user permissions are restricted."

| Feld | Wert |
|---|---|
| Klasse | `CheckGuestAccessRestrictions` |
| description | "Prüft ob Gastbenutzer-Berechtigungen eingeschränkt sind." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.15, A.6.5 Zugriffskontrolle" (identisch in beiden Pfaden) |
| required_permissions | `["Policy.Read.All"]` |
| pruefgrenzen | "Prüft nur die Gastzugriffs-Einstellungen des Tenants (Graph API). Einzelne Gast-Berechtigungen werden in AZ-NR4-002 geprüft." |
| Klassenkonstante | `PERMISSIVE_GUEST_ROLE = "a0b1b346-4d3e-4e8b-98f8-753987be4970"` (Kommentar im Code: "Default role = same as members (most permissive)") |
| Prüflogik (deskriptiv) | `graph_client.policies.authorization_policy.get()` liefert die Tenant-Autorisierungsrichtlinie; deren `guest_user_role_id` wird mit `PERMISSIVE_GUEST_ROLE` verglichen — Ungleichheit ergibt Positivnachweis (unabhängig davon, welche andere Rollen-GUID tatsächlich gesetzt ist, ob "restricted guest" oder "most restricted" oder eine sonstige Rolle), Gleichheit ergibt Mangel-Finding. Ist `guest_user_role_id` nicht gesetzt (Policy oder Feld `None`/leer), wird weder Positiv- noch Mangel-Finding erzeugt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Gastbenutzer mit Mitglieder-Berechtigungen"
- description: "Gastbenutzer haben dieselben Berechtigungen wie Mitglieder. Externe Benutzer sollten eingeschränkte Rechte haben."
- expected_state: "Gastbenutzer-Rolle eingeschränkt (restricted guest oder most restricted)"
- remediation: "Schränken Sie Gastberechtigungen ein: Entra Admin Center → Externe Identitäten → Einstellungen für externe Zusammenarbeit → Gastbenutzer-Zugriff einschränken"
- remediation_effort: LOW
- audit_evidence (Template): `f"Graph API authorizationPolicy: guestUserRoleId={guest_role}"`

**Positivnachweis (compliant_finding):**
- title: "Gastbenutzer-Berechtigungen eingeschränkt"
- description: "Gastbenutzer haben eingeschränkte Berechtigungen (nicht dieselben Rechte wie Mitglieder)."
- expected_state (Template, aus Teilstrings zusammengesetzt): "Gastbenutzer-Rolle eingeschränkt (restricted guest oder most restricted)" (identisch zum Mangel-Pfad)
- audit_evidence (Template): `f"Graph API authorizationPolicy: guestUserRoleId={guest_role}"` (identisches Template wie im Mangel-Pfad)

---

### AZ-NR9-007 — Inaktive Service Principals (>90 Tage)

Klassen-Docstring (wörtlich): "Check for service principals inactive for more than 90 days."

| Feld | Wert |
|---|---|
| Klasse | `CheckStaleServicePrincipals` |
| description | "Prüft ob Service Principals existieren, die seit über 90 Tagen inaktiv sind." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.15 Zugriffskontrolle" (identisch in beiden Pfaden) |
| required_permissions | `["Application.Read.All"]` |
| pruefgrenzen | "Bewertet Inaktivität über das Credential-Alter der Service Principals (Graph API). Die tatsächliche letzte Nutzung ist nur über Sign-in-Logs mit Premium-Lizenz ermittelbar und wird hier nicht geprüft." |
| Prüflogik (deskriptiv) | `graph_client.service_principals.get()` liefert alle Service Principals des Tenants; Service Principals mit `app_owner_organization_id` gleich der fest hinterlegten Microsoft-Tenant-ID (`"f8cdef31-a31e-4b4a-93e4-5f571e91255a"`) werden übersprungen. Für die übrigen wird `sign_in_activity.last_sign_in_date_time` ausgewertet: fehlt dieses Feld, zählt der SP als "unknown"; ist es älter als `MAX_INACTIVE_DAYS` (90 Tage vor jetzt), zählt der SP als "stale"; sonst als regulär ausgewertet ("evaluated"). Ein Positivnachweis wird nur erzeugt, wenn `evaluated_count>0` UND `unknown_count==0` UND `stale_count==0` (Code-Kommentar verweist explizit auf ADR-0016); ein Mangel-Finding wird nur erzeugt, wenn `stale_count>0`. Bei `evaluated_count==0` oder bei `unknown_count>0` und gleichzeitig `stale_count==0` wird kein Finding erzeugt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Inaktive Service Principals gefunden"
- description (Template, aus Teilstrings zusammengesetzt): "Es wurden {stale_count} Service Principals gefunden, die seit über {MAX_INACTIVE_DAYS} Tagen nicht verwendet wurden. Nicht genutzte Identitäten sollten bereinigt werden."
- expected_state (Template): `f"Keine Service Principals > {MAX_INACTIVE_DAYS} Tage inaktiv"`
- remediation: "Überprüfen und entfernen Sie nicht genutzte Service Principals: Entra Admin Center → App-Registrierungen → Nach Inaktivität filtern"
- remediation_effort: MEDIUM
- audit_evidence (Template, aus Teilstrings zusammengesetzt): "Graph API: {stale_count}/{len(service_principals)} service principals inactive > {MAX_INACTIVE_DAYS} days"

**Positivnachweis (compliant_finding):**
- title: "Keine inaktiven Service Principals"
- description (Template, aus Teilstrings zusammengesetzt): "Alle {evaluated_count} geprüften Service Principals wurden innerhalb der letzten {MAX_INACTIVE_DAYS} Tage verwendet."
- expected_state (identisches Template wie Mangel-Pfad): "Keine Service Principals > {MAX_INACTIVE_DAYS} Tage inaktiv"
- audit_evidence (Template, aus Teilstrings zusammengesetzt): "Graph API: 0/{evaluated_count} service principals inactive > {MAX_INACTIVE_DAYS} days"

---

### GCP-NR9-001 — IAM Least-Privilege-Prinzip

Klassen-Docstring (wörtlich): "Prüft ob übermäßig breite IAM-Rollen auf Projektebene vergeben sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckIamLeastPrivilege` |
| description | "Prüft ob auf Projektebene übermäßig breite Rollen wie roles/owner oder roles/editor vergeben sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.15 Zugriffskontrolle, A.8.3 Informationszugriffsbeschränkung" (identisch in beiden Pfaden) |
| required_permissions | `["resourcemanager.projects.getIamPolicy"]` |
| pruefgrenzen | "Prüft nur roles/owner und roles/editor auf Projektebene. Zu breite benutzerdefinierte Rollen und Ordner-/Organisationsebene werden nicht bewertet." |
| Prüflogik (deskriptiv) | Je Projekt (`session.project_ids`) liefert `cloudresourcemanager` v1 `service.projects().getIamPolicy(resource=project_id, body={"options":{"requestedPolicyVersion":3}})` die IAM-Policy-Bindings; Bindings mit `role in OVERLY_BROAD_ROLES` (`["roles/owner","roles/editor"]`) werden gezählt. Keine solchen Bindings ergeben einen aggregierten Positivnachweis für das Projekt; für jedes gefundene breite Binding wird zusätzlich ein eigenes Mangel-Finding erzeugt (je Rolle, mit Mitgliederanzahl) — Positivnachweis und Mangel-Findings schließen sich innerhalb desselben Projekts gegenseitig aus (Positivnachweis nur bei `broad_bindings==[]`). |

**Finding-Texte (Mangel-Pfad):**
- title: "Übermäßig breite IAM-Rolle vergeben"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat {member_count} Mitglieder mit der Rolle '{role}'. Diese Rolle gewährt umfassende Berechtigungen und verstößt gegen das Least-Privilege-Prinzip."
- expected_state (Template, aus Teilstrings zusammengesetzt): "Verwendung spezifischer, eingeschränkter Rollen anstelle von roles/owner oder roles/editor"
- remediation (Template, aus Teilstrings zusammengesetzt): "Ersetzen Sie breite Rollen durch spezifische Rollen:\ngcloud projects remove-iam-policy-binding <PROJECT_ID> --member=<MEMBER> --role=<BROAD_ROLE>\ngcloud projects add-iam-policy-binding <PROJECT_ID> --member=<MEMBER> --role=<SPECIFIC_ROLE>\nNutzen Sie den IAM Recommender für Empfehlungen."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"getIamPolicy() binding: role={role}, members={member_count}"`

**Positivnachweis (compliant_finding):**
- title: "Keine übermäßig breiten IAM-Rollen"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} vergibt weder roles/owner noch roles/editor auf Projektebene ({len(bindings)} Binding(s) geprüft)."
- expected_state (identisches Template wie Mangel-Pfad): "Verwendung spezifischer, eingeschränkter Rollen anstelle von roles/owner oder roles/editor"
- audit_evidence (Template, aus Teilstrings zusammengesetzt): "getIamPolicy() returned {len(bindings)} bindings, none with {', '.join(OVERLY_BROAD_ROLES)}"

---

### GCP-NR9-002 — Service-Account-Schlüsselhygiene

Klassen-Docstring (wörtlich): "Prüft ob Service-Account-Schlüssel älter als 90 Tage sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckServiceAccountHygiene` |
| description | "Prüft ob Service-Account-Schlüssel regelmäßig rotiert werden und nicht älter als 90 Tage sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.15 Zugriffskontrolle" (identisch in allen Pfaden) |
| required_permissions | `["iam.serviceAccounts.list", "iam.serviceAccountKeys.list"]` |
| pruefgrenzen | "Prüft nur das Alter nutzerverwalteter Service-Account-Schlüssel. Google-verwaltete Schlüssel rotieren automatisch und sind nicht Gegenstand." |
| Prüflogik (deskriptiv) | Je Projekt liefert `iam` v1 `serviceAccounts().list()` alle Service Accounts; je Service Account liefert `.keys().list(keyTypes="USER_MANAGED")` die nutzerverwalteten Schlüssel. Keine Schlüssel ergeben einen Positivnachweis für den Service Account (ohne Schlüssel-Ebene). Je Schlüssel: fehlt `validAfterTime` oder ist das Datum nicht parsebar (`except (ValueError, TypeError): continue`), wird der Schlüssel stillschweigend übersprungen (kein Finding, kein `CheckError`); Alter `<= MAX_SA_KEY_AGE_DAYS` (90) ergibt Positivnachweis je Schlüssel, `>90` ergibt Mangel-Finding je Schlüssel. |

**Finding-Texte (Mangel-Pfad):**
- title: "Service-Account-Schlüssel zu alt"
- description (Template, aus Teilstrings zusammengesetzt): "Service-Account {sa_id} in Projekt {project_id} hat einen Schlüssel ({key_id}), der {age_days} Tage alt ist (Grenzwert: {MAX_SA_KEY_AGE_DAYS} Tage)."
- expected_state (Template): `f"Service-Account-Schlüssel nicht älter als {MAX_SA_KEY_AGE_DAYS} Tage"`
- remediation (Template, aus Teilstrings zusammengesetzt): "Rotieren Sie den Service-Account-Schlüssel:\n1. gcloud iam service-accounts keys create new-key.json --iam-account=<SA_EMAIL>\n2. Aktualisieren Sie die Anwendung mit dem neuen Schlüssel\n3. gcloud iam service-accounts keys delete <KEY_ID> --iam-account=<SA_EMAIL>\nEmpfehlung: Verwenden Sie Workload Identity Federation anstelle von Schlüsseln."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"key.validAfterTime={valid_after}, age={age_days}d, max={MAX_SA_KEY_AGE_DAYS}d"`

**Positivnachweis (compliant_finding, Variante A — keine Schlüssel):**
- title: "Service-Account ohne nutzerverwaltete Schlüssel"
- description (Template, aus Teilstrings zusammengesetzt): "Service-Account {sa_email} in Projekt {project_id} hat keine nutzerverwalteten Schlüssel — es besteht kein Rotationsrisiko."
- expected_state (Template, aus Teilstrings zusammengesetzt): "Keine oder regelmäßig rotierte Service-Account-Schlüssel (maximal {MAX_SA_KEY_AGE_DAYS} Tage alt)"
- audit_evidence: "keys.list(keyTypes=USER_MANAGED) returned 0 keys" (Literal)

**Positivnachweis (compliant_finding, Variante B — Schlüssel aktuell):**
- title: "Service-Account-Schlüssel aktuell"
- description (Template, aus Teilstrings zusammengesetzt): "Service-Account {sa_email} in Projekt {project_id} hat einen Schlüssel, der {age_days} Tage alt ist (Grenzwert: {MAX_SA_KEY_AGE_DAYS} Tage)."
- expected_state (Template): `f"Service-Account-Schlüssel nicht älter als {MAX_SA_KEY_AGE_DAYS} Tage"` (identisch zum Mangel-Pfad)
- audit_evidence (Template): `f"key.validAfterTime={valid_after}, age={age_days}d, max={MAX_SA_KEY_AGE_DAYS}d"` (identisches Template wie Mangel-Pfad)

---

### GCP-NR9-003 — Identity-Aware Proxy konfiguriert

Klassen-Docstring (wörtlich): "Prüft ob Identity-Aware Proxy (IAP) aktiviert ist."

| Feld | Wert |
|---|---|
| Klasse | `CheckIdentityAwareProxy` |
| description | "Prüft ob Identity-Aware Proxy (IAP) für das Projekt konfiguriert ist, um kontextabhängige Zugriffskontrolle zu ermöglichen." |
| severity | MEDIUM (beide Mangel-Pfade, inline) |
| iso27001_control | inline Literal "A.5.15 Zugriffskontrolle" (identisch in allen Pfaden) |
| required_permissions | `["iap.tunnelInstances.getIamPolicy"]` |
| pruefgrenzen | "Prüft nur IAP-Tunnelrichtlinien. Andere Zero-Trust-Zugriffslösungen werden nicht erkannt." |
| Prüflogik (deskriptiv) | Je Projekt liefert `iap` v1 `service.projects().iap_tunnel().getIamPolicy(resource="projects/{id}/iap_tunnel", body={})` die IAM-Bindings des IAP-Tunnels; mindestens ein Binding (unabhängig von Rolle oder Mitgliedern, d. h. auch ein Binding mit `allUsers` würde als Nachweis zählen) ergibt einen Positivnachweis, keine Bindings ein Mangel-Finding. Wirft der Aufruf eine Exception, deren (kleingeschriebener) Text `"not enabled"` oder `"403"` enthält, wird ein gesondertes Mangel-Finding "nicht aktiviert" erzeugt; jede andere Exception wird als `CheckError` erfasst. |

**Finding-Texte (Mangel-Pfad, Teil 1 — keine Bindings):**
- title: "Identity-Aware Proxy nicht konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keine IAP-Tunnelrichtlinien konfiguriert. Ohne IAP fehlt die kontextabhängige Zugriffskontrolle für administrative Zugriffe."
- expected_state (Template, aus Teilstrings zusammengesetzt): "IAP-Tunnelrichtlinien konfiguriert für kontextabhängige Zugriffskontrolle"
- remediation (Template, aus Teilstrings zusammengesetzt): "Konfigurieren Sie Identity-Aware Proxy:\ngcloud iap tunnel instances add-iam-policy-binding --project=<PROJECT_ID> --member=user:<EMAIL> --role=roles/iap.tunnelResourceAccessor"
- remediation_effort: MEDIUM
- audit_evidence: "iap_tunnel.getIamPolicy() returned 0 bindings" (Literal)

**Finding-Texte (Mangel-Pfad, Teil 2 — API nicht aktiviert/403):**
- title: "Identity-Aware Proxy nicht aktiviert"
- description (Template): `f"Projekt {project_id} hat IAP nicht aktiviert oder die API ist nicht zugänglich."`
- expected_state: "IAP API aktiviert und konfiguriert"
- remediation (Template, aus Teilstrings zusammengesetzt): "Aktivieren Sie die IAP API:\ngcloud services enable iap.googleapis.com --project=<PROJECT_ID>"
- remediation_effort: LOW
- audit_evidence (Template): `f"IAP API returned error: {type(exc).__name__}"`

**Positivnachweis (compliant_finding):**
- title: "Identity-Aware Proxy konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat {len(bindings)} IAP-Tunnelrichtlinie(n) für kontextabhängige Zugriffskontrolle konfiguriert."
- expected_state (identisches Template wie Mangel-Teil-1): "IAP-Tunnelrichtlinien konfiguriert für kontextabhängige Zugriffskontrolle"
- audit_evidence (Template): `f"iap_tunnel.getIamPolicy() returned {len(bindings)} bindings"`

---

### GCP-NR9-004 — VPC-Firewallregeln restriktiv

Klassen-Docstring (wörtlich): "Prüft ob Firewallregeln zu permissive sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckVpcFirewallRules` |
| description | "Prüft ob VPC-Firewallregeln den SSH- oder RDP-Zugriff von 0.0.0.0/0 erlauben." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.20 Netzwerksicherheit, A.8.22 Netzwerksegmentierung" (identisch in beiden Pfaden) |
| required_permissions | `["compute.firewalls.list"]` |
| pruefgrenzen | "Prüft Ingress-Firewallregeln auf offenes SSH/RDP von 0.0.0.0/0. Effektive Erreichbarkeit (Routing, Ziel-Tags) wird nicht geprüft." |
| Prüflogik (deskriptiv) | Je Projekt liefert `google.cloud.compute_v1.FirewallsClient.list(request={"project": project_id})` alle Firewallregeln; nur Regeln mit `direction=="INGRESS"` werden bewertet. `open_to_world = "0.0.0.0/0" in source_ranges`; ist dies der Fall, werden die `allowed`-Einträge nach Ports 22/3389 durchsucht (exakter String-Vergleich `"22"`/`"3389"` oder Portbereichs-Strings der Form `"low-high"`, geparst mit `int()` unter `except (ValueError, IndexError): pass`, was fehlerhafte Portstrings stillschweigend überspringt). Keine offene Welt-Quelle oder keine SSH/RDP-Exposition ergibt Positivnachweis je Regel; offene Welt-Quelle mit SSH/RDP-Exposition ergibt Mangel-Finding je Regel. Der Code-Kommentar "Only check ALLOW rules" hat keine korrespondierende explizite Prüfung des Regeltyps (ALLOW/DENY) oder des `disabled`-Felds — die Unterscheidung ergibt sich implizit daraus, dass DENY-Regeln typischerweise kein `allowed`-Feld populieren. |

**Finding-Texte (Mangel-Pfad):**
- title: "Firewallregel erlaubt offenen Zugriff"
- description (Template, aus Teilstrings zusammengesetzt): "Firewallregel {fw_id} in Projekt {project_id} erlaubt {exposed} von 0.0.0.0/0. Dies exponiert administrative Zugangspunkte dem gesamten Internet."
- expected_state (Template, aus Teilstrings zusammengesetzt): "SSH- und RDP-Zugriff nur von vertrauenswürdigen IP-Bereichen oder über IAP-Tunnel"
- remediation (Template, aus Teilstrings zusammengesetzt): "Schränken Sie die Firewallregel ein:\ngcloud compute firewall-rules update <RULE_NAME> --source-ranges=<TRUSTED_IP_RANGE> --project=<PROJECT_ID>\nOder verwenden Sie IAP für SSH/RDP-Zugriff:\ngcloud compute ssh <INSTANCE> --tunnel-through-iap"
- remediation_effort: LOW
- audit_evidence (Template): `f"firewall.source_ranges=['0.0.0.0/0'], exposed_ports={sorted(sensitive_ports)}"`

**Positivnachweis (compliant_finding):**
- title: "Firewallregel ohne offenen SSH/RDP-Zugriff"
- description (Template, aus Teilstrings zusammengesetzt): "Firewallregel {fw_id} in Projekt {project_id} erlaubt keinen SSH- oder RDP-Zugriff von 0.0.0.0/0."
- expected_state (identisches Template wie Mangel-Pfad): "SSH- und RDP-Zugriff nur von vertrauenswürdigen IP-Bereichen oder über IAP-Tunnel"
- audit_evidence (Template): `f"firewall ingress rule: 0.0.0.0/0={open_to_world}, no SSH/RDP ports exposed"`

---

### GCP-NR9-005 — Storage-Buckets nicht öffentlich zugänglich

Klassen-Docstring (wörtlich): "Prüft ob Storage-Buckets öffentlich zugänglich sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckStorageBucketPublicAccess` |
| description | "Prüft ob Cloud Storage Buckets IAM-Richtlinien haben, die allUsers oder allAuthenticatedUsers Zugriff gewähren." |
| severity | CRITICAL (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.15 Zugriffskontrolle, A.8.3 Informationszugriffsbeschränkung" (identisch in beiden Pfaden) |
| required_permissions | `["storage.buckets.list", "storage.buckets.getIamPolicy"]` |
| pruefgrenzen | "Prüft Bucket-IAM auf allUsers/allAuthenticatedUsers. Buckets, deren IAM-Policy nicht lesbar ist, werden übersprungen und erscheinen nicht als Ergebnis." |
| Prüflogik (deskriptiv) | Je Projekt liefert `google.cloud.storage.Client.list_buckets()` alle Buckets; je Bucket liefert `bucket.get_iam_policy()` die IAM-Policy — schlägt dieser Aufruf fehl (`except Exception: continue`), wird der Bucket stillschweigend übersprungen (kein Finding, kein `CheckError`; laut pruefgrenzen bewusst dokumentiert). Enthält ein Binding `"allUsers"` oder `"allAuthenticatedUsers"` als Mitglied, ergibt dies ein Mangel-Finding je Bucket; ohne solche Mitglieder ein Positivnachweis je Bucket. |

**Finding-Texte (Mangel-Pfad):**
- title: "Öffentlich zugänglicher Storage-Bucket"
- description (Template, aus Teilstrings zusammengesetzt): "Bucket {bucket_id} in Projekt {project_id} ist öffentlich zugänglich über {', '.join(public_members)}. Öffentliche Buckets können zu Datenverlust führen."
- expected_state (Template, aus Teilstrings zusammengesetzt, wörtlich mit Tippfehler): "Keine öffentlichen Zugriffsberechtungen (weder allUsers noch allAuthenticatedUsers)"
- remediation (Template, aus Teilstrings zusammengesetzt): "Entfernen Sie den öffentlichen Zugriff:\ngcloud storage buckets remove-iam-policy-binding gs://<BUCKET_NAME> --member=allUsers --role=<ROLE>\nAktivieren Sie den Public Access Prevention:\ngcloud storage buckets update gs://<BUCKET_NAME> --public-access-prevention=enforced"
- remediation_effort: LOW
- audit_evidence (Template): `f"bucket.get_iam_policy() contains public members: {sorted(public_members)}"`

**Positivnachweis (compliant_finding):**
- title: "Storage-Bucket nicht öffentlich zugänglich"
- description (Template, aus Teilstrings zusammengesetzt): "Bucket {bucket_id} in Projekt {project_id} gewährt weder allUsers noch allAuthenticatedUsers Zugriff."
- expected_state (Template, aus Teilstrings zusammengesetzt, korrekt geschrieben): "Keine öffentlichen Zugriffsberechtigungen (weder allUsers noch allAuthenticatedUsers)"
- audit_evidence: "bucket.get_iam_policy() contains no public members" (Literal)

---

### GCP-NR9-006 — Organisationsweite Zugriffskontroll-Einschränkungen

Klassen-Docstring (wörtlich): "Prüft ob wichtige organisationsweite Einschränkungen definiert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckOrgConstraints` |
| description | "Prüft ob wichtige Org Policy Constraints für die Zugriffskontrolle wie iam.allowedPolicyMemberDomains und compute.disableSerialPortAccess konfiguriert sind." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.15 Zugriffskontrolle" (identisch in beiden Pfaden) |
| required_permissions | `["orgpolicy.policy.get"]` |
| pruefgrenzen | "Prüft die Projekt-Policies gegen eine feste Liste von Zugriffskontroll-Constraints. Organisationsebene kann unerkannt bleiben (vgl. GCP-NR7-001)." |
| Prüflogik (deskriptiv) | Je Projekt liefert `orgpolicy` v2 `service.projects().policies().list(parent="projects/{id}")` alle gesetzten Org-Policies; deren Constraint-Namen (letztes Segment des `name`-Felds) werden gesammelt. Für jede der 5 Konstanten in `IMPORTANT_ORG_CONSTRAINTS` wird per Substring-Vergleich (`c in ac`) geprüft, ob sie in einem der gesetzten Constraint-Namen enthalten ist — der Enforcement-Wert/Inhalt der jeweiligen Policy wird nicht ausgewertet, nur das Vorhandensein des Constraint-Namens in der Liste. Mindestens eine gefundene Konstante ergibt einen aggregierten Positivnachweis je Projekt, keine ein aggregiertes Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine organisationsweiten Zugriffskontroll-Einschränkungen"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keine der empfohlenen Org Policy Constraints für die Zugriffskontrolle konfiguriert."
- expected_state (Template, aus Teilstrings zusammengesetzt): "Organisationsweite Constraints wie iam.allowedPolicyMemberDomains und compute.disableSerialPortAccess konfiguriert"
- remediation (Template, aus Teilstrings zusammengesetzt): "Setzen Sie Zugriffskontroll-Org Policies:\ngcloud org-policies set-policy policy.yaml --project=<PROJECT_ID>\nEmpfohlene Constraints:\n- constraints/iam.allowedPolicyMemberDomains\n- constraints/compute.disableSerialPortAccess\n- constraints/compute.requireOsLogin" (nennt nur 3 der 5 in `IMPORTANT_ORG_CONSTRAINTS` geprüften Constraints)
- remediation_effort: MEDIUM
- audit_evidence (Template, aus Teilstrings zusammengesetzt): "policies.list() returned {len(policies)} policies, none matching access control constraints"

**Positivnachweis (compliant_finding):**
- title: "Organisationsweite Zugriffskontroll-Einschränkungen aktiv"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} erzwingt {len(found_constraints)} empfohlene Org Policy Constraint(s) für die Zugriffskontrolle: {', '.join(found_constraints)}."
- expected_state (identisches Template wie Mangel-Pfad): "Organisationsweite Constraints wie iam.allowedPolicyMemberDomains und compute.disableSerialPortAccess konfiguriert"
- audit_evidence (Template, aus Teilstrings zusammengesetzt): "policies.list() returned {len(policies)} policies, {len(found_constraints)} matching access control constraints"

---

### GCP-NR9-007 — Inaktive IAM-Principals

Klassen-Docstring (wörtlich): "Prüft ob inaktive IAM-Principals via Recommender identifiziert werden."

| Feld | Wert |
|---|---|
| Klasse | `CheckInactivePrincipals` |
| description | "Prüft über den IAM Recommender, ob inaktive Principals mit ungenutzten Zugriffsberechtigungen identifiziert wurden." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.15 Zugriffskontrolle, A.5.18 Zugriffsrechte" (identisch in beiden Pfaden) |
| required_permissions | `["recommender.iamPolicyRecommendations.list"]` |
| pruefgrenzen | "Stützt sich auf den IAM Recommender von Google. Ist die Recommender-API nicht aktiviert oder nicht zugänglich, liefert der Check kein Ergebnis (Nicht anwendbar) — inaktive Principals sind dann manuell zu prüfen. Bewertet nur, was der Recommender als ungenutzt erkennt." |
| Prüflogik (deskriptiv) | Je Projekt liefert `recommender` v1 `service.projects().locations().recommenders().recommendations().list(parent="projects/{id}/locations/-/recommenders/google.iam.policy.Recommender")` alle Empfehlungen; gefiltert wird per Substring-Heuristik auf Empfehlungen mit `"REMOVE"` (großgeschrieben verglichen) im `recommenderSubtype` oder `"unused"` (kleingeschrieben verglichen) in der `description`. Keine solchen Empfehlungen ergeben einen aggregierten Positivnachweis je Projekt; für jede gefundene Empfehlung wird zusätzlich ein eigenes Mangel-Finding erzeugt. Enthält die Fehlermeldung eines fehlgeschlagenen Aufrufs `"not enabled"` oder `"403"` (kleingeschrieben verglichen), wird dies nur geloggt (`logger.info`) — es entsteht weder ein Finding noch ein `CheckError` für dieses Projekt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Inaktiver IAM-Principal mit ungenutztem Zugriff"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat eine Recommender-Empfehlung ({rec_id}) zum Entfernen ungenutzter Zugriffsberechtigungen. Inaktive Principals erhöhen die Angriffsfläche."
- expected_state: "Keine ungenutzten Zugriffsberechtigungen für inaktive Principals"
- remediation (Template, aus Teilstrings zusammengesetzt): "Überprüfen und entfernen Sie ungenutzte Berechtigungen:\ngcloud recommender recommendations list --recommender=google.iam.policy.Recommender --project=<PROJECT_ID> --location=-\ngcloud recommender recommendations mark-claimed <RECOMMENDATION_ID> --recommender=google.iam.policy.Recommender --project=<PROJECT_ID> --location=<LOCATION>"
- remediation_effort: LOW
- audit_evidence (Template): `f"IAM Recommender found recommendation: subtype={rec.get('recommenderSubtype', '')}"`

**Positivnachweis (compliant_finding):**
- title: "Keine inaktiven IAM-Principals"
- description (Template, aus Teilstrings zusammengesetzt): "Der IAM Recommender meldet für Projekt {project_id} keine Empfehlungen zum Entfernen ungenutzter Zugriffsberechtigungen."
- expected_state: "Keine ungenutzten Zugriffsberechtigungen für inaktive Principals" (identisch zum Mangel-Pfad)
- audit_evidence (Template, aus Teilstrings zusammengesetzt): "IAM Recommender returned {len(recommendations)} recommendations, none about unused access"

---

### GCP-NR9-008 — VPC Service Controls Perimeter vorhanden

*(bereits zweitgeprüft im Nr.-1-Batch, 2026-07-12 — Umzug aus Nr. 1; hier vollständig mitextrahiert)*

Klassen-Docstring (wörtlich): "Prüft ob VPC Service Controls Perimeter konfiguriert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckVpcServiceControls` |
| description | "Prüft ob VPC Service Controls konfiguriert sind, um den Zugriff auf GCP-Dienste einzuschränken und Datenexfiltration zu verhindern." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.22 Netzwerksegmentierung" (identisch in beiden Pfaden) |
| required_permissions | `["accesscontextmanager.accessPolicies.list"]` |
| pruefgrenzen | "Prüft nur die Existenz von VPC-Service-Controls-Perimetern. Ohne Organisations-Berechtigung ist die Prüfung nicht möglich; die Perimeter-Konfiguration selbst wird nicht inhaltlich bewertet." |
| Prüflogik (deskriptiv) | Anders als die übrigen 7 GCP-Nr.-9-Checks iteriert dieser Check NICHT über `session.project_ids`, sondern führt die Prüfung genau einmal für `session.project_id` aus (Code-Kommentar: Access Context Manager sei organisationsweit gültig, "same pattern as GCP-NR4-005" — kein Per-Projekt-Loop, da sonst derselbe Org-Zustand mehrfach berichtet würde). `accesscontextmanager` v1 `service.accessPolicies().list()` liefert alle Access-Policies; je Policy liefert `service.accessPolicies().servicePerimeters().list(parent=policy_name)` die Service-Perimeter — beim ersten gefundenen, nicht-leeren Perimeter-Ergebnis wird die Schleife mit `break` abgebrochen. Mindestens ein Perimeter ergibt einen einzigen Positivnachweis für den gesamten Scan, kein Perimeter ein einziges Mangel-Finding. Jede Exception wird geloggt (`logger.warning`, mit Hinweis "VPC SC requires organization-level access") und zusätzlich als `CheckError` erfasst. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine VPC Service Controls Perimeter"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keine VPC Service Controls Perimeter. Ohne VPC Service Controls fehlt eine zusätzliche Barriere gegen Datenexfiltration über Dienst-APIs."
- expected_state: "Mindestens ein VPC Service Controls Perimeter konfiguriert"
- remediation: "Erstellen Sie einen VPC Service Controls Perimeter: gcloud access-context-manager perimeters create <NAME> --title='Produktionsperimeter' --resources=projects/<PROJECT_NUMBER> --restricted-services='storage.googleapis.com' --policy=<POLICY_ID>"
- remediation_effort: HIGH
- audit_evidence: "accessPolicies.servicePerimeters.list() returned 0 perimeters" (Literal)

**Positivnachweis (compliant_finding):**
- title: "VPC Service Controls Perimeter vorhanden"
- description: "Es ist mindestens ein VPC Service Controls Perimeter konfiguriert — Datenexfiltration aus GCP-Diensten wird eingeschränkt."
- expected_state: "Mindestens ein VPC Service Controls Perimeter konfiguriert" (identisch zum Mangel-Pfad)
- audit_evidence: "accessPolicies.servicePerimeters.list() returned >=1 perimeter" (Literal)

---

## Mechanische Auffälligkeiten (ohne Bewertung)

1. Keine der 22 Check-Klassen definiert ein Klassenattribut `severity` (abweichend vom Muster im Repo-`CLAUDE.md`) — severity wird stattdessen pro `Finding()`-Aufruf im Mangel-Pfad als Parameter gesetzt. Ebenso definiert keine Klasse ein Klassenattribut `iso_27001_ref`; `iso27001_control` wird stattdessen pro `Finding()`/`compliant_finding()`-Aufruf übergeben (identisch zu den bereits vorliegenden Nr.-1/3/5-Dossiers).
2. Die AWS-Modulkonstante `ISO_CONTROL_ASSET = "A.5.9-A.5.14 Asset management"` wird im gesamten Modul an keiner einzigen Aufrufstelle referenziert — alle sieben AWS-Nr.-9-Checks verwenden ausschließlich `ISO_CONTROL_ACCESS`, obwohl der Modul-Docstring/-Titel ausdrücklich "Zugriffskontrolle & Asset-Management" nennt und die BSIG_30_TEXT-Konstante auch "Verwaltung von IKT-Systemen, -Produkten und -Prozessen" (Asset-Management-Bezug) enthält.
3. Nur das AWS-Modul definiert wiederverwendbare ISO-Kontroll-Modulkonstanten (`ISO_CONTROL_ACCESS`, `ISO_CONTROL_ASSET`). Azure und GCP definieren keine solchen Konstanten; jeder der 7 Azure- und 8 GCP-Checks trägt sein eigenes inline-Literal, wobei dieselbe Kontrollnummer (z. B. A.5.15) je nach Check mit unterschiedlichem Zusatztext auftritt (z. B. Azure: "A.5.15 Zugriffskontrolle" vs. "A.5.15, A.6.5 Zugriffskontrolle" vs. "A.5.15, A.8.3 Zugriffskontrolle"; GCP: "A.5.15 Zugriffskontrolle" vs. "A.5.15 Zugriffskontrolle, A.8.3 Informationszugriffsbeschränkung" vs. "A.5.15 Zugriffskontrolle, A.5.18 Zugriffsrechte").
4. Docstring-Sprachmuster weicht vom in den Nr.-1/3/5-Dossiers vermerkten Muster ab: In Nr. 9 haben ALLE sieben Azure-Klassen einen (englischen) Klassen-Docstring ("Check that…"/"Check for…") — anders als in den bisherigen Batches, wo für Azure durchgängig "keine der Klassen hat einen Klassen-Docstring" vermerkt wurde. AWS bleibt beim englischen Muster ("Check that…"/"Check for…", alle 7 Klassen), GCP beim deutschen Muster ("Prüft ob…", alle 8 Klassen).
5. `CheckError()`-Aufrufe unterscheiden sich zwischen Providern wie in den vorherigen Dossiers: Azure übergibt durchgehend `check_id`, `error_type=type(exc).__name__`, `message` und `region="global"`; GCP übergibt durchgehend nur `message` und `error_type=type(exc).__name__` (dynamisch aus dem Exception-Typnamen abgeleitet). AWS übergibt ebenfalls nur `message`/`error_type`, verwendet dafür aber feste String-Literale statt dynamischer Typnamen — und diese Literale sind innerhalb des AWS-Moduls selbst uneinheitlich: äußere (modulweite) Exception-Handler verwenden `error_type="CheckError"`, innere (pro Ressource) Exception-Handler in AWS-NR9-005/006/007 verwenden `error_type="AWSClientError"`, und der innere Handler in AWS-NR9-003 (Zweig `NoSuchPublicAccessBlockConfiguration`-Erkennung, außerhalb dieses Zweigs) übergibt gar kein `error_type` und erhält dadurch den Pydantic-Default `"APIError"` aus `CheckError`.
6. `CheckError` als Pydantic-Modell (`nis2scan/engine/models/check.py`) definiert nur die Felder `message`, `error_type` und `details` — die von Azure zusätzlich übergebenen Kwargs `check_id` und `region` sind keine deklarierten Modellfelder.
7. AWS-NR9-005 (`CheckIamWildcardPolicy`) erkennt Wildcards ausschließlich über exakten Listen-Mitgliedschaftsvergleich (`"*" in actions`, `"*" in resources`) — Teil-Wildcards wie `"s3:*"` in der Action-Liste oder ARN-Präfix-Wildcards wie `"arn:aws:s3:::bucket/*"` in der Resource-Liste erfüllen keine der beiden Bedingungen und werden nicht als `wildcard_issues` erfasst.
8. AWS-NR9-005 kann für dasselbe Statement gleichzeitig sowohl "Action: *" als auch "Resource: * with Action: *" in `wildcard_issues` eintragen, wenn sowohl Action als auch Resource jeweils exakt `"*"` sind — die zweite Bedingung (`"*" in resources and any(a == "*" for a in actions)`) ist bei Action `"*"` durch die erste Bedingung bereits erfüllt und fügt daher keine neue, unabhängige Information hinzu.
9. AWS-NR9-006 (`CheckS3BucketPolicy`) hat eine pruefgrenzen-Angabe, die "Prüft Bucket-Policies und ACLs auf öffentliche Freigaben" behauptet; der Code ruft jedoch an keiner Stelle `get_bucket_acl` oder eine vergleichbare ACL-API auf — es wird ausschließlich die Bucket-Policy geprüft.
10. AWS-NR9-006 behandelt jedes vorhandene `Condition`-Element eines sonst öffentlichen Statements pauschal als hinreichend restriktiv (`continue`, Code-Kommentar "Conditional access is acceptable") — der Inhalt der Condition (z. B. ob sie tatsächlich den Zugriff auf eine nicht-öffentliche Bedingung einschränkt) wird nicht ausgewertet.
11. AWS-NR9-007 (`CheckUnusedIamCredentials`) erzeugt für aktive Access Keys, die jünger als `UNUSED_CREDENTIAL_DAYS` (90 Tage) sind und noch nie verwendet wurden, weder ein Positiv- noch ein Mangel-Finding — dieser Zustand erscheint im Scan-Ergebnis für diesen Check nicht (weder als Nachweis noch als Beanstandung).
12. AWS-NR9-003 (`CheckS3PublicAccessBlock`) verwendet im Positiv-Pfad `current_state=dict(config.items())` und im Mangel-Pfad (Teil 1) `current_state={k: v for k, v in config.items()}` — zwei unterschiedliche, aber funktional äquivalente Schreibweisen derselben Operation innerhalb desselben Checks.
13. AWS-NR9-004 (`CheckSecurityGroupOpenAccess`) prüft nur `IpRanges` (IPv4); `Ipv6Ranges`-Einträge einer Regel werden nicht durchsucht. Die pruefgrenzen-Angabe spricht allgemein von "offenen administrativen Ports", der Code erzeugt aber für JEDE 0.0.0.0/0-Regel ein Mangel-Finding — auch für Ports außerhalb von `CRITICAL_PORTS` und außerhalb des vollen Bereichs 0-65535 (severity dann HIGH statt CRITICAL) —, nicht nur für administrative Ports.
14. AZ-NR9-001 (`CheckConditionalAccess`) zählt Policies mit `state=="enabledForReportingButNotEnforced"` (Report-only, keine tatsächliche Durchsetzung) als "aktiv" gleichwertig zu vollständig durchgesetzten (`"enabled"`) Policies für den Positivnachweis.
15. AZ-NR9-002 (`CheckPim`) unterscheidet im Code nicht zwischen "keine Entra-ID-P2-Lizenz vorhanden" (laut pruefgrenzen ein bekannter Grenzfall: "nicht auswertbar") und sonstigen API-Fehlern — beide Fälle landen im selben generischen `except Exception`-Block als `CheckError`.
16. AZ-NR9-003 (`CheckNsgOpenAccess`) prüft nur das Singular-Feld `source_address_prefix`; das Azure-NSG-Feld `source_address_prefixes` (Plural, Liste mehrerer Quell-Präfixe) wird nicht geprüft. Zudem verwendet die description-Textzusammenfassung die ersten 5 offenen Regeln (`open_rules[:5]`), während `current_state` die ersten 10 (`open_rules[:10]`) enthält — unterschiedliche Trunkierungsgrenzen für denselben zugrunde liegenden Datensatz.
17. AZ-NR9-004 (`CheckStoragePublicAccess`) erzeugt für eine Subscription ganz ohne Storage Accounts (`accounts == []`) weder einen Positivnachweis noch ein Mangel-Finding — die Bedingungen `if accounts and not public_accounts` und `elif public_accounts` sind beide falsch, sodass für diese Subscription kein Finding im Scan-Ergebnis erscheint.
18. AZ-NR9-005 (`CheckClassicAdmins`) filtert Co-Administratoren über einen Substring-Vergleich (`"CoAdministrator" in str(a.role)`) statt über einen exakten Wertevergleich.
19. AZ-NR9-006 (`CheckGuestAccessRestrictions`) vergleicht `guest_user_role_id` ausschließlich gegen die eine fest hinterlegte "schlechteste" Rollen-GUID (`PERMISSIVE_GUEST_ROLE`); jede andere GUID — auch eine unbekannte oder nicht als "restricted guest"/"most restricted" dokumentierte Rolle — gilt als Positivnachweis, ohne dass geprüft wird, ob es sich tatsächlich um eine der beiden von `expected_state` genannten restriktiven Rollen handelt. Ist `guest_user_role_id` nicht gesetzt, wird kein Finding erzeugt.
20. AZ-NR9-007 (`CheckStaleServicePrincipals`) erzeugt bei `unknown_count > 0` und gleichzeitig `stale_count == 0` (d. h. mindestens ein Service Principal ohne auswertbare Sign-in-Daten, aber keiner als "stale" erkannt) weder einen Positivnachweis noch ein Mangel-Finding für den gesamten Check — der Code-Kommentar verweist hierzu explizit auf ADR-0016 ("Positive evidence only when every SP had sign-in data"), das Ergebnis ist aber eine Lücke ganz ohne Finding für diesen Lauf.
21. GCP-NR9-003 (`CheckIdentityAwareProxy`) wertet als Positivnachweis bereits das bloße Vorhandensein irgendeines IAM-Bindings auf dem IAP-Tunnel — unabhängig von Rolle oder Mitgliedschaft der Bindings (z. B. würde auch ein Binding mit `allUsers` als Mitglied als Nachweis "kontextabhängiger Zugriffskontrolle" gelten).
22. GCP-NR9-004 (`CheckVpcFirewallRules`) hat den Code-Kommentar "# Only check ALLOW rules", ohne dass eine explizite Prüfung des Regeltyps (ALLOW vs. DENY) oder des `disabled`-Felds der Firewallregel im Code erfolgt — die faktische Beschränkung auf ALLOW-Regeln ergibt sich implizit daraus, dass DENY-Regeln kein `allowed`-Feld besitzen; eine deaktivierte (`disabled=true`) Regel würde dennoch bewertet.
23. GCP-NR9-005 (`CheckStorageBucketPublicAccess`) hat im description-Text der Mangel-Pfad-`expected_state` einen Tippfehler ("Zugriffsberechtungen") gegenüber der korrekt geschriebenen Positivnachweis-`expected_state` ("Zugriffsberechtigungen").
24. GCP-NR9-006 (`CheckOrgConstraints`) prüft Zugehörigkeit über Substring-Vergleich (`c in ac` für jedes `c` in `IMPORTANT_ORG_CONSTRAINTS` gegen jeden gefundenen Constraint-Namen `ac`) statt über exakten Wertevergleich, und bewertet nur das Vorhandensein eines Constraint-Namens in der Policy-Liste, nicht dessen tatsächlichen Enforcement-Wert/-Inhalt. Die Mangel-Pfad-remediation nennt zudem nur 3 der 5 in `IMPORTANT_ORG_CONSTRAINTS` tatsächlich geprüften Constraints (fehlend: `compute.restrictSharedVpcSubnetworks`, `iam.disableServiceAccountKeyCreation`).
25. GCP-NR9-007 (`CheckInactivePrincipals`) filtert Empfehlungen über eine Substring-/Schlüsselwort-Heuristik (`"REMOVE" in recommenderSubtype.upper()` oder `"unused" in description.lower()`) statt über einen definierten Recommender-Subtyp-Abgleich. Bei einer Fehlermeldung mit `"not enabled"` oder `"403"` wird nur geloggt (`logger.info`, keine Finding-/CheckError-Erzeugung) — abweichend von GCP-NR9-003, das für dieselbe Fehlerklasse ("not enabled"/"403") ein eigenes Mangel-Finding erzeugt.
26. GCP-NR9-008 iteriert als einziger der 8 GCP-Nr.-9-Checks nicht über `session.project_ids`, sondern nutzt einmalig `session.project_id` (Singular) — mit explizitem Code-Kommentar zur Begründung (Organisationsebene, Vermeidung von Mehrfachberichten). Die übrigen 7 GCP-Checks iterieren durchgehend über `session.project_ids` (Plural, je Projekt).
27. GCP-NR9-008 deklariert `required_permissions = ["accesscontextmanager.accessPolicies.list"]`; der Code ruft zusätzlich `service.accessPolicies().servicePerimeters().list(parent=policy_name)` auf, eine separate, nicht gesondert deklarierte Berechtigung für das Auflisten von Service-Perimetern.
28. GCP-NR9-006 deklariert `required_permissions = ["orgpolicy.policy.get"]` (Singular "get"), während der Code tatsächlich eine Listen-Operation (`service.projects().policies().list(...)`) aufruft.
29. AZ-NR9-001 und AZ-NR9-006 deklarieren identisch `required_permissions = ["Policy.Read.All"]`, obwohl sie unterschiedliche Graph-Ressourcen abfragen (`identity.conditional_access.policies` bzw. `policies.authorization_policy`).
30. AZ-NR9-007 deklariert `required_permissions = ["Application.Read.All"]`; der Code liest zusätzlich das Feld `sign_in_activity` (Sign-in-Aktivität) aus den zurückgegebenen Service-Principal-Objekten, ohne dass eine dafür ggf. zusätzlich erforderliche Berechtigung gesondert in `required_permissions` aufgeführt wird.
31. Granularität der Findings ist zwischen den Providern und teils innerhalb eines Providers uneinheitlich: AWS erzeugt bei NR9-001/002/004(Mangel)/005/007 je ein Finding pro Einzelressource, bei NR9-003/004(Positiv)/006 teils aggregiert (Account bzw. Security Group als Ganzes) und teils je Regel/Statement; Azure erzeugt bei AZ-NR9-001/002/004/005/007 je ein aggregiertes Finding pro Tenant/Subscription, bei AZ-NR9-003/006 gemischt (NSG- bzw. Statement-Ebene innerhalb aggregierter Zählung); GCP erzeugt bei GCP-NR9-001(Positiv)/003/006/007(Positiv)/008 aggregierte Findings pro Projekt bzw. Scan, bei GCP-NR9-001(Mangel)/002/004/005/007(Mangel) je Einzelressource.
32. `current_state` führt bei mehreren Checks Schlüssel mit dem Suffix `_name` (z. B. `user_name` bei AWS-NR9-001/002/007), deren Wert jedoch die technische Kennung (username/ARN-Bestandteil), nicht ein frei vergebener Anzeigename ist — wie bereits in den Nr.-1/3/5-Dossiers vermerkt, stehen `_name`- und `_id`-Suffixe laut ADR-0011 gleichermaßen auf der Pseudonymisierungs-Deny-List, die Feldbezeichnung ist inhaltlich dennoch ungenau.
