# W4 Batch-Review-Dossier — §30 Abs. 2 Nr. 10 BSIG (MFA und gesicherte Kommunikation)

> Mechanisch extrahiert am 2026-07-13 (Worker, ohne rechtliche Bewertung).
> Prüfgegenstand für: Gründer + Agent legal-reviewer (ADR-0018).

Quelldateien:
- `nis2scan/engine/providers/aws/checks/nr10_mfa_kommunikation.py`
- `nis2scan/engine/providers/azure/checks/nr10_mfa_kommunikation.py`
- `nis2scan/engine/providers/gcp/checks/nr10_mfa_kommunikation.py`

Ist-Zahl erfasster Checks: **15** (AWS: 5, Azure: 5, GCP: 5) — entspricht der erwarteten Zahl.

## Modul-Konstanten je Provider

### AWS (`nr10_mfa_kommunikation.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 10 — MFA & gesicherte Kommunikation checks for AWS.

  Checks root account MFA and IAM user MFA enforcement.
  ```
- `BSIG_30_NR = 10`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 10 BSIG — Verwendung von Lösungen zur Multi-Faktor-Authentifizierung oder kontinuierlichen Authentifizierung, gesicherte Sprach-, Video- und Textkommunikation sowie gegebenenfalls gesicherte Notfallkommunikationssysteme innerhalb der Einrichtung"
- `ISO_CONTROL` (wörtlich): "A.8.5 Secure authentication" (englisch)

### Azure (`nr10_mfa_kommunikation.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 10 — MFA & gesicherte Kommunikation checks for Azure.

  Checks MFA enforcement, phishing-resistant MFA, VPN/Bastion,
  O365 TLS enforcement, and break-glass accounts.
  ```
- `BSIG_30_NR = 10`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS)
- `GLOBAL_ADMIN_ROLE_ID = "62e90394-69f5-4237-9190-012177145e10"` (Modul-Kommentar wörtlich: "# Global Admin role template ID")
- Kein Modul-Äquivalent zu `ISO_CONTROL`.

### GCP (`nr10_mfa_kommunikation.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 10 — Multi-Faktor-Authentifizierung und gesicherte Kommunikation checks for GCP.

  Checks Two-Step Verification, IAP Admin Access, VPN Gateways,
  OS Login 2FA, and Secure Identity (LDAP).
  ```
- `BSIG_30_NR = 10`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS/Azure)
- Keine weiteren Modul-Konstanten.

---

## Checks

### AWS-NR10-001 — Root Account MFA

Klassen-Docstring (wörtlich): "Check that the AWS root account has MFA enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckRootMfa` |
| description | "Prüft ob der AWS Root-Account MFA aktiviert hat." |
| severity | CRITICAL (Mangel-Pfad, inline im `Finding()`-Aufruf, kein Klassenattribut) |
| iso27001_control | `ISO_CONTROL` = "A.8.5 Secure authentication" (identisch in Positiv- und Mangel-Pfad) |
| required_permissions | `["iam:GetAccountSummary"]` |
| pruefgrenzen | "Prüft nur, ob Root-MFA aktiviert ist. Art des zweiten Faktors (Hardware vs. virtuell) und die sichere Verwahrung werden nicht geprüft." |
| Prüflogik (deskriptiv) | `iam.get_account_summary()` → `SummaryMap`; Feld `AccountMFAEnabled` (truthy `1`/`0`) ergibt bei Truthy einen Positivnachweis, bei Falsy ein Mangel-Finding — je ein aggregiertes Finding auf Account-Ebene (`region="global"`, resource_id = Root-ARN). |

**Finding-Texte (Mangel-Pfad):**
- title: "AWS Root-Account ohne MFA"
- description (Template, aus Teilstrings zusammengesetzt): "Der AWS Root-Account hat keine Multi-Faktor-Authentifizierung aktiviert. Der Root-Account hat uneingeschränkte Rechte und ist das höchste Angriffsziel."
- expected_state: "Root Account MFA aktiviert (Hardware-Token empfohlen)"
- remediation: "Aktivieren Sie SOFORT MFA für den Root-Account. Empfohlen: Hardware-Token (YubiKey). AWS Console: Account → Security credentials → MFA → Assign MFA device. Der Root-Account sollte nach MFA-Aktivierung nicht für den täglichen Betrieb verwendet werden."
- remediation_effort: LOW
- audit_evidence: "GetAccountSummary: AccountMFAEnabled=0" (Literal, kein f-String)

**Positivnachweis (compliant_finding):**
- title: "AWS Root-Account mit MFA"
- description: "Der AWS Root-Account hat Multi-Faktor-Authentifizierung aktiviert." (Literal)
- expected_state: "Root Account MFA aktiviert (Hardware-Token empfohlen)"
- audit_evidence: "GetAccountSummary: AccountMFAEnabled=1" (Literal)

---

### AWS-NR10-002 — IAM User MFA Enforcement

Klassen-Docstring (wörtlich): "Check that IAM users with console access have MFA enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckIamUserMfaEnforcement` |
| description | "Prüft ob alle IAM-Benutzer mit Konsolen-Zugang MFA aktiviert haben." |
| severity | CRITICAL (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL` = "A.8.5 Secure authentication" (identisch in beiden Pfaden) |
| required_permissions | `["iam:ListUsers", "iam:ListMFADevices", "iam:GetLoginProfile"]` |
| pruefgrenzen | "Prüft MFA nur für IAM-Benutzer mit Konsolen-Login. Föderierte Zugänge (SSO/IdP) und programmatische Zugriffe (Access Keys) sind nicht erfasst." |
| Prüflogik (deskriptiv) | `iam.list_users()` (paginiert); je Benutzer wird `iam.get_login_profile()` versucht — wirft dieser Aufruf eine Exception, wird der Benutzer per `continue` komplett übersprungen (als "kein Konsolen-Zugang" gewertet, kein Finding). Bei vorhandenem Login-Profil liefert `iam.list_mfa_devices()` die MFA-Geräte: nicht-leere Liste ergibt Positivnachweis, leere Liste ergibt Mangel-Finding, je Benutzer. |

**Finding-Texte (Mangel-Pfad):**
- title: "IAM-Benutzer mit Konsolen-Zugang ohne MFA"
- description (Template, aus Teilstrings zusammengesetzt): "Der IAM-Benutzer '{username}' hat Konsolen-Zugang aber keine MFA konfiguriert. Dies verstößt gegen die Anforderung zur Multi-Faktor-Authentifizierung nach §30 Abs. 2 Nr. 10."
- expected_state: "MFA für alle Benutzer mit Konsolen-Zugang erzwungen"
- remediation: "Erzwingen Sie MFA für alle IAM-Benutzer mit Konsolen-Zugang. Empfohlen: Erstellen Sie eine IAM Policy die API-Aktionen ohne MFA verweigert (aws:MultiFactorAuthPresent condition). Migrieren Sie auf AWS IAM Identity Center (SSO) mit MFA-Pflicht für eine zentralisierte Lösung."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"User {username}: has_console=true, mfa_devices=0"`

**Positivnachweis (compliant_finding):**
- title: "IAM-Benutzer mit Konsolen-Zugang und MFA"
- description (Template): `f"Der IAM-Benutzer '{username}' hat Konsolen-Zugang und MFA konfiguriert."`
- expected_state: "MFA für alle Benutzer mit Konsolen-Zugang erzwungen"
- audit_evidence (Template): `f"User {username}: has_console=true, mfa_devices={len(mfa_devices)}"`

---

### AWS-NR10-003 — VPN / Client VPN für Admin-Zugriff

Klassen-Docstring (wörtlich): "Check that VPN or Client VPN is configured for admin access.\n\nAdministrative access to AWS resources should be protected by VPN connections to ensure secure communication channels."

| Feld | Wert |
|---|---|
| Klasse | `CheckVpnAdminAccess` |
| description | "Prüft ob AWS VPN oder Client VPN für gesicherten administrativen Zugriff konfiguriert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.20 Networks security" (englisch; identisch in beiden Pfaden) |
| required_permissions | `["ec2:DescribeVpnGateways", "ec2:DescribeClientVpnEndpoints"]` |
| pruefgrenzen | "Prüft nur, ob AWS-eigene VPN-Lösungen (Site-to-Site/Client VPN) konfiguriert sind. Drittanbieter-VPNs, Zero-Trust-Zugänge oder SSM Session Manager als Admin-Zugriffsweg werden nicht erkannt." |
| Prüflogik (deskriptiv) | Iteriert über `session.regions`; je Region `ec2.describe_vpn_gateways()` (Filter `State=="available"`) und `ec2.describe_client_vpn_endpoints()` (Filter `Status.Code=="available"`) — sobald in einer Region ein aktives Gateway/Endpoint gefunden wird, wird `vpn_found=True` gesetzt und die Regionsschleife per `break` sofort verlassen (weitere Regionen werden nicht mehr geprüft). Bei einer Exception je Region wird ein `CheckError` angehängt, die Schleife läuft aber weiter. Nach der Schleife: `vpn_found` → ein aggregiertes Positiv-Finding (global); sonst nur falls `not errors` → ein aggregiertes Mangel-Finding (global). Ist `vpn_found` False und liegt mindestens ein regionaler Fehler vor, wird für diesen Check weder Positiv- noch Mangel-Finding erzeugt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein VPN für Admin-Zugriff konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Weder AWS Site-to-Site VPN noch Client VPN Endpoints sind konfiguriert. Ohne VPN fehlt ein gesicherter Kommunikationskanal für den administrativen Zugriff auf AWS-Ressourcen."
- expected_state: "VPN oder Client VPN für gesicherten Admin-Zugriff konfiguriert"
- remediation: "Konfigurieren Sie AWS Client VPN für administrativen Zugriff: aws ec2 create-client-vpn-endpoint --client-cidr-block 10.0.0.0/16 --server-certificate-arn <arn> --authentication-options <options>. Alternativ: AWS Site-to-Site VPN für Standortanbindung."
- remediation_effort: HIGH
- audit_evidence: "DescribeVpnGateways + DescribeClientVpnEndpoints: no VPN found" (Literal)

**Positivnachweis (compliant_finding):**
- title: "VPN für Admin-Zugriff konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "AWS Site-to-Site VPN oder Client VPN ist konfiguriert — ein gesicherter Kommunikationskanal für den administrativen Zugriff besteht."
- expected_state: "VPN oder Client VPN für gesicherten Admin-Zugriff konfiguriert"
- audit_evidence: "DescribeVpnGateways/DescribeClientVpnEndpoints: active VPN found" (Literal)

---

### AWS-NR10-004 — SES/SNS TLS-Erzwingung

Klassen-Docstring (wörtlich): "Check that SES and SNS enforce TLS for communications.\n\nEmail and notification services must use TLS to ensure encrypted communication channels as required by §30 Abs. 2 Nr. 10."

| Feld | Wert |
|---|---|
| Klasse | `CheckSesSnsTls` |
| description | "Prüft ob AWS SES und SNS TLS für die Kommunikationsverschlüsselung erzwingen." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.20 Networks security" (identisch in beiden Pfaden) |
| required_permissions | `["ses:GetAccount", "sns:ListTopics", "sns:GetTopicAttributes"]` |
| pruefgrenzen | "Prüft nur TLS-Erzwingung in SES-Konfigurationen und SNS-Subscriptions. Die übrige Unternehmenskommunikation (E-Mail-Server, Messenger, Video) liegt außerhalb des Scans." |
| Prüflogik (deskriptiv) | Iteriert über `session.regions`; je Region `sns.list_topics()`, danach je Topic `sns.get_topic_attributes()` → Feld `Policy` (JSON-String, Default `"{}"`); der rohe String wird per `"aws:SecureTransport" in policy_str` auf Teilstring-Vorkommen geprüft — Treffer ergibt Positivnachweis, kein Treffer ergibt Mangel-Finding, je Topic. Bei Exception je Topic wird ein `CheckError` angehängt, kein Finding. Bei Exception auf Regions-/`list_topics`-Ebene: enthält die Fehlermeldung "AuthorizationError" oder "AccessDenied", wird sie stillschweigend ignoriert (`pass`, kein `CheckError`); andernfalls `CheckError`. SES wird im gesamten Check-Code an keiner Stelle aufgerufen. |

**Finding-Texte (Mangel-Pfad):**
- title: "SNS-Topic ohne TLS-Erzwingung"
- description (Template): `f"Das SNS-Topic '{topic_name}' erzwingt nicht TLS (aws:SecureTransport) in seiner Access Policy. Benachrichtigungen könnten unverschlüsselt übertragen werden."`
- expected_state: "SNS Topic Policy mit aws:SecureTransport Condition"
- remediation: `'Fügen Sie eine Condition zur SNS Topic Policy hinzu: "Condition": {"Bool": {"aws:SecureTransport": "true"}}'`
- remediation_effort: LOW
- audit_evidence (Template): `f"GetTopicAttributes: {topic_name} policy missing aws:SecureTransport"`

**Positivnachweis (compliant_finding):**
- title: "SNS-Topic mit TLS-Erzwingung"
- description (Template): `f"Das SNS-Topic '{topic_name}' erzwingt TLS (aws:SecureTransport) in seiner Access Policy."`
- expected_state: "SNS Topic Policy mit aws:SecureTransport Condition"
- audit_evidence (Template): `f"GetTopicAttributes: {topic_name} policy contains aws:SecureTransport"`

---

### AWS-NR10-005 — Notfall-Break-Glass-Verfahren

Klassen-Docstring (wörtlich): "Check that a break-glass emergency IAM user is configured."

| Feld | Wert |
|---|---|
| Klasse | `CheckBreakGlassProcedure` |
| description | "Prüft ob ein Break-Glass-Notfallzugang konfiguriert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.30, A.8.5" (ohne Beschreibungstext; identisch in beiden Pfaden) |
| required_permissions | `["iam:ListUsers", "iam:ListUserTags"]` |
| pruefgrenzen | "Heuristik: sucht nach Break-Glass-Indikatoren (benannte Notfall-Benutzer/-Rollen). Ein anders organisiertes Notfallzugriffsverfahren wird nicht erkannt und ist über die Attestierungs-Checkliste nachzuweisen." |
| Klassenkonstanten (wörtlich) | `_BREAK_GLASS_NAME_PATTERNS = ("break-glass", "breakglass", "emergency", "notfall")`; `_BREAK_GLASS_TAG_KEYS = ("Purpose", "Role")`; `_BREAK_GLASS_TAG_VALUES = ("break-glass", "emergency")` |
| Prüflogik (deskriptiv) | `iam.list_users()` (paginiert); je Benutzer wird zunächst der (lowercased) Username per Teilstring gegen `_BREAK_GLASS_NAME_PATTERNS` geprüft — Treffer setzt `break_glass_found=True` und bricht alle Schleifen ab. Ohne Namenstreffer wird `iam.list_user_tags()` je Benutzer aufgerufen; ein Tag mit Key in `_BREAK_GLASS_TAG_KEYS` und (lowercased) Value, der einen der `_BREAK_GLASS_TAG_VALUES` enthält, setzt ebenfalls `break_glass_found=True`. Ergebnis: genau ein aggregiertes Finding auf Account-Ebene — Positivnachweis bei Treffer, sonst Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein Break-Glass-Notfallzugang konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Es wurde kein Break-Glass-Notfallzugang im AWS-Account gefunden. Organisationen sollten einen dokumentierten Notfall-IAM-Benutzer mit starker MFA für den Notfall vorhalten."
- expected_state: "Break-Glass-Notfallzugang konfiguriert mit starker MFA"
- remediation (Template, aus Teilstrings zusammengesetzt): "Erstellen Sie einen Break-Glass-IAM-Benutzer für Notfälle: 1. IAM-User 'break-glass-admin' anlegen 2. Hardware-MFA zuweisen 3. AdminAccess-Policy anhängen 4. Credentials sicher verwahren (Tresor) 5. Nutzung per CloudWatch Alarm überwachen"
- remediation_effort: MEDIUM
- audit_evidence: "Kein IAM-User mit Break-Glass-Namenskonvention oder entsprechenden Tags gefunden" (Literal)

**Positivnachweis (compliant_finding):**
- title: "Break-Glass-Notfallzugang konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Ein Break-Glass-Notfallzugang wurde im AWS-Account gefunden (Namenskonvention oder Tags)."
- expected_state: "Break-Glass-Notfallzugang konfiguriert mit starker MFA"
- audit_evidence: "IAM-User mit Break-Glass-Namenskonvention oder entsprechenden Tags gefunden" (Literal)

---

### AZ-NR10-001 — Entra ID MFA für alle Benutzer

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckMfaAllUsers` |
| description | "Prüft ob Multi-Faktor-Authentifizierung für alle Benutzer durchgesetzt wird." |
| severity | CRITICAL (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.5 Sichere Authentifizierung" (identisch in beiden Pfaden) |
| required_permissions | `["Policy.Read.All"]` |
| pruefgrenzen | "Prüft die MFA-Registrierung der Entra-ID-Benutzer (Graph API). Erzwingung im Anmeldefluss hängt von Conditional Access ab (AZ-NR9-001)." |
| Prüflogik (deskriptiv) | `GraphServiceClient.identity.conditional_access.policies.get()` → Policies; je Policy: nicht `enabled` → übersprungen; `grant_controls.built_in_controls` enthält (lowercased) "mfa" → sonst übersprungen; `conditions.users.include_users` enthält `"All"` → `mfa_all_users=True`, Schleife bricht ab. `conditions.users.exclude_users` dieser Policy wird nicht ausgewertet. Ein aggregiertes Finding (tenant-weit): Positivnachweis bei Treffer, sonst Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "MFA nicht für alle Benutzer durchgesetzt"
- description (Template, aus Teilstrings zusammengesetzt): "Es gibt keine aktive Conditional Access Policy, die MFA für alle Benutzer erzwingt. MFA ist eine der wirksamsten Maßnahmen gegen Kontoübernahmen."
- expected_state: "Conditional Access Policy mit MFA für alle Benutzer"
- remediation: "Erstellen Sie eine CA-Policy mit MFA-Anforderung für alle Benutzer: Entra Admin Center → Schutz → Bedingter Zugriff → Neue Richtlinie → Alle Benutzer → Gewähren: MFA erforderlich"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"Graph API: {len(policies)} CA policies, none requiring MFA for all users"`

**Positivnachweis (compliant_finding):**
- title: "MFA für alle Benutzer durchgesetzt"
- description: "Eine aktive Conditional Access Policy erzwingt MFA für alle Benutzer." (Literal)
- expected_state: "Conditional Access Policy mit MFA für alle Benutzer"
- audit_evidence (Template): `f"Graph API: {len(policies)} CA policies, MFA-for-all-users policy active"`

---

### AZ-NR10-002 — Phishing-resistente MFA (FIDO2/Windows Hello)

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckPhishingResistantMfa` |
| description | "Prüft ob FIDO2 oder Windows Hello for Business als Authentifizierungsmethode aktiviert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.5 Sichere Authentifizierung" (identisch in beiden Pfaden) |
| required_permissions | `["Policy.Read.All"]` |
| pruefgrenzen | "Prüft nur, ob phishing-resistente Methoden (FIDO2/Windows Hello) registriert sind. Ob sie bevorzugt erzwungen werden, wird nicht geprüft." |
| Prüflogik (deskriptiv) | `GraphServiceClient.policies.authentication_methods_policy.get()` → `authentication_method_configurations`; je Konfiguration wird (lowercased) `id == "fido2"` oder `id == "windowshelloforbusiness"` jeweils mit `state == "enabled"` geprüft — erster Treffer setzt die (einzige) Variable `fido2_enabled=True` und bricht die Schleife ab. Ein aggregiertes Finding (tenant-weit): Positivnachweis bei Treffer, sonst Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Phishing-resistente MFA aktiviert"
- description (Template, aus Teilstrings zusammengesetzt): "Weder FIDO2 noch Windows Hello for Business ist als Authentifizierungsmethode aktiviert. Phishing-resistente MFA bietet höheren Schutz als SMS/App-basierte MFA."
- expected_state: "FIDO2 oder Windows Hello for Business aktiviert"
- remediation: "Aktivieren Sie FIDO2: Entra Admin Center → Schutz → Authentifizierungsmethoden → FIDO2-Sicherheitsschlüssel → Aktivieren"
- remediation_effort: MEDIUM
- audit_evidence: "Graph API: FIDO2 and WHfB both disabled/not found" (Literal)

**Positivnachweis (compliant_finding):**
- title: "Phishing-resistente MFA aktiviert"
- description (Template, aus Teilstrings zusammengesetzt): "FIDO2 oder Windows Hello for Business ist als Authentifizierungsmethode aktiviert."
- expected_state: "FIDO2 oder Windows Hello for Business aktiviert"
- audit_evidence: "Graph API: FIDO2 or WHfB enabled" (Literal)

---

### AZ-NR10-003 — VPN Gateway / Bastion Host für Admin-Zugriff

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckVpnBastion` |
| description | "Prüft ob ein VPN Gateway oder Bastion Host für gesicherten Admin-Zugriff vorhanden ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.20 Netzwerksicherheit" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Network/virtualNetworkGateways/read", "Microsoft.Network/bastionHosts/read"]` |
| pruefgrenzen | "Prüft nur Azure-eigene Zugangswege (VPN Gateway, Bastion). Drittanbieter-VPNs und Zero-Trust-Lösungen werden nicht erkannt." |
| Prüflogik (deskriptiv) | Je Subscription: `NetworkManagementClient.virtual_network_gateways.list_all()` sowie `ResourceManagementClient.resources.list(filter="resourceType eq 'Microsoft.Network/bastionHosts'")`; ist mindestens eine der beiden Listen nicht leer → aggregierter Positivnachweis je Subscription, sind beide leer → aggregiertes Mangel-Finding je Subscription. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein VPN Gateway / Bastion Host"
- description (Template, aus Teilstrings zusammengesetzt): "Subscription {sub_id} hat weder ein VPN Gateway noch einen Bastion Host. Ohne gesicherten Admin-Zugang sind Management-Verbindungen über das öffentliche Internet exponiert."
- expected_state: "VPN Gateway oder Bastion Host für Admin-Zugriff"
- remediation: "Erstellen Sie einen Bastion Host: az network bastion create --name <bastion> --resource-group <rg> --vnet-name <vnet> --location <loc>"
- remediation_effort: HIGH
- audit_evidence: "virtual_network_gateways.list_all(): 0 gateways, resources.list(bastionHosts): 0 hosts" (Literal)

**Positivnachweis (compliant_finding):**
- title: "VPN Gateway / Bastion Host vorhanden"
- description (Template): `f"Subscription {sub_id} hat {len(vpn_gateways)} VPN Gateway(s) und {len(bastion_hosts)} Bastion Host(s) für gesicherten Admin-Zugriff."`
- expected_state: "VPN Gateway oder Bastion Host für Admin-Zugriff"
- audit_evidence (Template): `f"virtual_network_gateways/bastionHosts: {len(vpn_gateways)} gateway(s), {len(bastion_hosts)} bastion host(s)"`

---

### AZ-NR10-004 — Teams/Exchange — TLS erzwungen

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckO365TlsEnforcement` |
| description | "Prüft ob Conditional Access Policies TLS-Verschlüsselung für Office 365 Kommunikationsdienste erzwingen." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.20 Netzwerksicherheit" (identisch in beiden Pfaden) |
| required_permissions | `["Policy.Read.All"]` |
| pruefgrenzen | "Prüft nur tenant-seitige TLS-Indikatoren für Teams/Exchange Online. Die übrige Unternehmenskommunikation liegt außerhalb des Scans." |
| Klassenkonstante `O365_APP_IDS` (wörtlich, mit Inline-Kommentaren) | `{"00000002-0000-0ff1-ce00-000000000000",  # Exchange Online / "cc15fd57-2c6c-4117-a88c-83b1d56b4bbe",  # Teams / "Office365",  # All O365 apps}` |
| Prüflogik (deskriptiv) | `GraphServiceClient.identity.conditional_access.policies.get()` → Policies; je enabled Policy mit gesetzten `conditions.applications`: `include_applications` enthält `"All"` oder einen Eintrag aus `O365_APP_IDS` → Policy zielt auf O365; falls zusätzlich `grant_controls.built_in_controls` (lowercased) eine der Zeichenketten "compliantdevice", "approvedapplication" oder "mfa" enthält → `o365_ca_found=True`, Schleife bricht ab. Ein aggregiertes Finding (tenant-weit): Positivnachweis bei Treffer, sonst Mangel-Finding. Kein TLS-spezifisches Feld wird an irgendeiner Stelle des Codes gelesen. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine CA-Policy für O365-Kommunikation"
- description (Template, aus Teilstrings zusammengesetzt): "Es gibt keine Conditional Access Policy, die Sicherheitsanforderungen (Geräte-Compliance, genehmigte Apps, MFA) für Office 365 Kommunikationsdienste erzwingt."
- expected_state: "CA-Policy mit Sicherheitsanforderungen für O365-Dienste"
- remediation: "Erstellen Sie eine CA-Policy für O365: Entra Admin Center → Bedingter Zugriff → Neue Richtlinie → Cloud-Apps: Office 365 → Gewähren: Gerätekonformität erforderlich"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"Graph API: {len(policies)} CA policies, none targeting O365"`

**Positivnachweis (compliant_finding):**
- title: "CA-Policy für O365-Kommunikation aktiv"
- description (Template, aus Teilstrings zusammengesetzt): "Eine aktive Conditional Access Policy erzwingt Sicherheitsanforderungen für Office 365 Kommunikationsdienste."
- expected_state: "CA-Policy mit Sicherheitsanforderungen für O365-Dienste"
- audit_evidence (Template): `f"Graph API: {len(policies)} CA policies, O365-targeting policy active"`

---

### AZ-NR10-005 — Emergency Access Accounts (Break Glass)

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckBreakGlassAccounts` |
| description | "Prüft ob Notfallzugangs-Konten (Break Glass) für den Notfall konfiguriert sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.30, A.8.5 Notfallzugang" (identisch in beiden Pfaden) |
| required_permissions | `["User.Read.All", "RoleManagement.Read.Directory"]` |
| pruefgrenzen | "Heuristik: sucht nach benannten Break-Glass-Konten. Ein anders organisiertes Notfallzugriffsverfahren wird nicht erkannt und ist über die Attestierungs-Checkliste nachzuweisen." |
| Klassenkonstante (wörtlich) | `BREAK_GLASS_PATTERNS = {"breakglass", "emergency", "break-glass", "break_glass", "notfall"}` |
| Prüflogik (deskriptiv) | `role_management.directory.role_assignments.get()` → Assignments, gefiltert auf `role_definition_id == GLOBAL_ADMIN_ROLE_ID` → `global_admin_assignments`. `identity.conditional_access.policies.get()` → Policies; je Policy werden `conditions.users.exclude_users`-IDs in `excluded_user_ids` gesammelt. `break_glass_found=True`, sobald ein `assignment.principal_id` aus `global_admin_assignments` in `excluded_user_ids` enthalten ist (erster Treffer bricht die Schleife ab). `BREAK_GLASS_PATTERNS` wird im `execute()`-Code an keiner Stelle referenziert. Ein aggregiertes Finding (tenant-weit): Positivnachweis bei Treffer, sonst Mangel-Finding. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Break-Glass-Konten erkannt"
- description (Template, aus Teilstrings zusammengesetzt): "Es wurden keine Notfallzugangs-Konten (Break Glass) erkannt. Break-Glass-Konten sind permanente Global Admins, die von allen Conditional Access Policies ausgeschlossen sind — für den Notfall."
- expected_state: "Mindestens zwei Break-Glass-Konten (permanente Global Admins, CA-ausgeschlossen)"
- remediation (Template, aus Teilstrings zusammengesetzt): "Erstellen Sie Break-Glass-Konten: 1. Erstellen Sie 2 Cloud-only-Konten mit starken Passwörtern 2. Weisen Sie permanente Global-Admin-Rolle zu 3. Schließen Sie sie von allen CA-Policies aus 4. Überwachen Sie Anmeldungen via Alert"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"Graph API: {len(global_admin_assignments)} Global Admin assignments, {len(excluded_user_ids)} CA-excluded users, no break-glass pattern found"`

**Positivnachweis (compliant_finding):**
- title: "Break-Glass-Konto erkannt"
- description (Template, aus Teilstrings zusammengesetzt): "Mindestens ein Notfallzugangs-Konto (permanenter Global Admin, von CA-Policies ausgeschlossen) ist konfiguriert."
- expected_state: "Mindestens zwei Break-Glass-Konten (permanente Global Admins, CA-ausgeschlossen)"
- audit_evidence (Template): `f"Graph API: {len(global_admin_assignments)} Global Admin assignments, break-glass pattern found"`

---

### GCP-NR10-001 — Zwei-Faktor-Authentifizierung (2SV) erzwungen

Klassen-Docstring (wörtlich): "Prüft ob Zwei-Faktor-Authentifizierung erzwungen wird."

| Feld | Wert |
|---|---|
| Klasse | `CheckTwoStepVerification` |
| description | "Prüft ob die Zwei-Faktor-Authentifizierung für Google Workspace oder Cloud Identity Benutzer erzwungen wird." |
| severity | CRITICAL (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.5 Sichere Authentifizierung" (identisch in beiden Pfaden) |
| required_permissions | `["admin.directory.users.list"]` |
| pruefgrenzen | "Prüft nur Google-Workspace-/Cloud-Identity-Benutzer über das Admin SDK. Ohne Workspace-Admin-Berechtigung ist die Prüfung nicht möglich und liefert kein Ergebnis (Nicht anwendbar) — die 2FA-Durchsetzung ist dann manuell nachzuweisen. MFA außerhalb von Google (VPN, lokale Systeme) wird nie geprüft." |
| Prüflogik (deskriptiv) | Je Projekt: `admin`-API `directory_v1`: `users().list(customer="my_customer", maxResults=100, projection="full")` — ein einzelner Aufruf ohne `nextPageToken`-Verfolgung; Feld `isEnforcedIn2Sv` je Benutzer (Default `False`, falls fehlend) ergibt `users_without_2sv`. Sind Benutzer vorhanden und keiner ohne 2SV → aggregierter Positivnachweis je Projekt; sind Benutzer ohne 2SV vorhanden → aggregiertes Mangel-Finding je Projekt. Ist `users` leer, wird weder ein Positiv- noch ein Mangel-Finding erzeugt. Bei Exception mit "not enabled"/"403"/"permission"/"not found" in der Fehlermeldung wird nur `logger.info()` aufgerufen (kein Finding, kein `CheckError`); andernfalls `CheckError`. |

**Finding-Texte (Mangel-Pfad):**
- title: "Benutzer ohne erzwungene 2-Faktor-Authentifizierung"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id}: {len(users_without_2sv)} von {len(users)} Benutzern haben keine erzwungene Zwei-Faktor-Authentifizierung. Ohne MFA sind Konten anfällig für Credential-basierte Angriffe."
- expected_state: "Alle Benutzer mit erzwungener Zwei-Faktor-Authentifizierung (2SV)"
- remediation (Template, aus Teilstrings zusammengesetzt): "Erzwingen Sie 2SV in der Google Admin Console:\n1. Öffnen Sie admin.google.com > Sicherheit > Authentifizierung > 2-Faktor-Authentifizierung\n2. Aktivieren Sie 'Erzwingen' für alle Organisationseinheiten\n3. Setzen Sie eine Frist für die 2SV-Registrierung"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"admin.users.list(): {len(users_without_2sv)}/{len(users)} users without enforced 2SV"`

**Positivnachweis (compliant_finding):**
- title: "Zwei-Faktor-Authentifizierung für alle Benutzer erzwungen"
- description (Template): `f"Projekt {project_id}: Alle {len(users)} Benutzer haben eine erzwungene Zwei-Faktor-Authentifizierung (2SV)."`
- expected_state: "Alle Benutzer mit erzwungener Zwei-Faktor-Authentifizierung (2SV)"
- audit_evidence (Template): `f"admin.users.list(): 0/{len(users)} users without enforced 2SV"`

---

### GCP-NR10-002 — IAP für administrativen Zugriff

Klassen-Docstring (wörtlich): "Prüft ob IAP für administrativen Zugriff konfiguriert ist."

| Feld | Wert |
|---|---|
| Klasse | `CheckIapAdminAccess` |
| description | "Prüft ob Identity-Aware Proxy (IAP) für den administrativen Zugriff auf Ressourcen konfiguriert ist, anstatt direkten SSH- oder VPN-Zugriff zu verwenden." |
| severity | HIGH (beide Mangel-Pfade, inline) |
| iso27001_control | inline Literal "A.8.5 Sichere Authentifizierung" (identisch in allen drei Pfaden) |
| required_permissions | `["iap.tunnelInstances.getIamPolicy"]` |
| pruefgrenzen | "Prüft nur IAP-Tunnelrichtlinien für Admin-Zugriff. Andere MFA-gesicherte Zugriffswege werden nicht erkannt." |
| Prüflogik (deskriptiv) | Je Projekt: `iap`-API v1: `projects().iap_tunnel().getIamPolicy(resource=f"projects/{project_id}/iap_tunnel", body={})`; nicht-leere `bindings` ergibt einen aggregierten Positivnachweis je Projekt (Vorhandensein irgendeiner IAM-Policy-Bindung wird bereits als Nachweis gewertet, ohne die gebundenen Mitglieder oder deren MFA-Konfiguration zu prüfen); leere `bindings` ergibt ein aggregiertes Mangel-Finding ("Kein IAP..."). Wirft der API-Aufruf eine Exception mit "not enabled" oder "403" in der Fehlermeldung, wird stattdessen ein strukturell anderes Mangel-Finding ("IAP API nicht aktiviert") erzeugt; andere Exceptions ergeben einen `CheckError`. |

**Finding-Texte (Mangel-Pfad, Teil 1 — keine Bindings):**
- title: "Kein IAP für administrativen Zugriff konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keine IAP-Tunnel-Richtlinien für administrativen Zugriff. IAP bietet Multi-Faktor-Authentifizierung und kontextabhängige Zugriffskontrolle für SSH/RDP."
- expected_state: "IAP-Tunnel konfiguriert für administrativen Zugriff mit Multi-Faktor-Authentifizierung"
- remediation (Template, aus Teilstrings zusammengesetzt): "Konfigurieren Sie IAP für administrativen Zugriff:\n1. gcloud services enable iap.googleapis.com --project=<PROJECT_ID>\n2. gcloud iap tunnel instances add-iam-policy-binding --project=<PROJECT_ID> --member=user:<ADMIN_EMAIL> --role=roles/iap.tunnelResourceAccessor\n3. Verwenden Sie 'gcloud compute ssh <INSTANCE> --tunnel-through-iap' für SSH-Zugriff"
- remediation_effort: MEDIUM
- audit_evidence: "iap_tunnel.getIamPolicy() returned 0 bindings" (Literal)

**Finding-Texte (Mangel-Pfad, Teil 2 — IAP API nicht aktiviert, Exception-Pfad):**
- title: "IAP API nicht aktiviert"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat die IAP API nicht aktiviert. Ohne IAP fehlt die Möglichkeit zur Multi-Faktor-Authentifizierung für administrative Zugriffe."
- expected_state: "IAP API aktiviert und konfiguriert"
- remediation (Template, aus Teilstrings zusammengesetzt): "Aktivieren Sie die IAP API:\ngcloud services enable iap.googleapis.com --project=<PROJECT_ID>"
- remediation_effort: LOW
- audit_evidence (Template): `f"IAP API returned error: {type(exc).__name__}"`

**Positivnachweis (compliant_finding):**
- title: "IAP für administrativen Zugriff konfiguriert"
- description (Template): `f"Projekt {project_id} hat {len(bindings)} IAP-Tunnel-Richtlinie(n) für administrativen Zugriff mit Multi-Faktor-Authentifizierung."`
- expected_state: "IAP-Tunnel konfiguriert für administrativen Zugriff mit Multi-Faktor-Authentifizierung"
- audit_evidence (Template): `f"iap_tunnel.getIamPolicy() returned {len(bindings)} bindings"`

---

### GCP-NR10-003 — VPN-Gateways für sichere Konnektivität

Klassen-Docstring (wörtlich): "Prüft ob VPN-Gateways für sichere Konnektivität vorhanden sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckVpnGateways` |
| description | "Prüft ob VPN-Gateways oder IAP für sichere Konnektivität konfiguriert sind, um verschlüsselte Kommunikationskanäle sicherzustellen." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.20 Netzwerksicherheit" (identisch in allen drei Pfaden) |
| required_permissions | `["compute.vpnGateways.list"]` |
| pruefgrenzen | "Prüft nur GCP-eigene VPN-Gateways und IAP-Tunnel. Drittanbieter-VPNs werden nicht erkannt." |
| Prüflogik (deskriptiv) | Je Projekt: `VpnGatewaysClient.aggregated_list()` ermittelt `vpn_count`/`has_vpn`; ist `has_vpn` True → aggregierter Positivnachweis ("VPN-Gateways ... vorhanden"). Ist `has_vpn` False, wird als Fallback `iap.projects().iap_tunnel().getIamPolicy()` versucht — jede Exception dabei wird mit `except Exception: pass` verschluckt (kein `CheckError`), `has_iap` bleibt dann False. Ist `has_iap` True → aggregierter Positivnachweis mit abweichendem Titel ("IAP-Tunnel als sichere Konnektivitätslösung vorhanden"). Sind weder VPN noch IAP vorhanden → aggregiertes Mangel-Finding. Fehler beim VPN-Gateway-Aufruf selbst (äußerer try/except) ergeben einen `CheckError`. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine VPN-Gateways oder IAP konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat weder VPN-Gateways noch IAP-Tunnel konfiguriert. Ohne sichere Konnektivitätslösungen sind administrative Zugriffe nicht verschlüsselt."
- expected_state: "VPN-Gateways oder IAP-Tunnel für sichere Konnektivität konfiguriert"
- remediation (Template, aus Teilstrings zusammengesetzt): "Konfigurieren Sie ein VPN-Gateway:\ngcloud compute vpn-gateways create <GATEWAY_NAME> --network=<NETWORK> --region=<REGION> --project=<PROJECT_ID>\nOder verwenden Sie IAP-Tunnel als Alternative:\ngcloud services enable iap.googleapis.com --project=<PROJECT_ID>"
- remediation_effort: HIGH
- audit_evidence: "vpnGateways.aggregated_list() returned 0 gateways, IAP tunnel not configured" (Literal)

**Positivnachweis (compliant_finding, Teil 1 — VPN vorhanden):**
- title: "VPN-Gateways für sichere Konnektivität vorhanden"
- description (Template): `f"Projekt {project_id} hat {vpn_count} VPN-Gateway(s) für verschlüsselte Kommunikationskanäle konfiguriert."`
- expected_state: "VPN-Gateways oder IAP-Tunnel für sichere Konnektivität konfiguriert"
- audit_evidence (Template): `f"vpnGateways.aggregated_list() returned {vpn_count} gateways"`

**Positivnachweis (compliant_finding, Teil 2 — IAP als Fallback):**
- title: "IAP-Tunnel als sichere Konnektivitätslösung vorhanden"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat zwar keine VPN-Gateways, aber IAP-Tunnel für verschlüsselte administrative Zugriffe konfiguriert."
- expected_state: "VPN-Gateways oder IAP-Tunnel für sichere Konnektivität konfiguriert"
- audit_evidence: "vpnGateways.aggregated_list() returned 0 gateways, IAP tunnel bindings present" (Literal)

---

### GCP-NR10-004 — OS Login mit Zwei-Faktor-Authentifizierung

Klassen-Docstring (wörtlich): "Prüft ob OS Login mit 2FA aktiviert ist."

| Feld | Wert |
|---|---|
| Klasse | `CheckOsLoginWith2fa` |
| description | "Prüft ob OS Login und OS Login 2FA in den Projekt-Metadaten aktiviert sind, um Multi-Faktor-Authentifizierung für SSH-Zugriff auf VMs zu erzwingen." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.5 Sichere Authentifizierung" (identisch in beiden Pfaden) |
| required_permissions | `["compute.projects.get"]` |
| pruefgrenzen | "Prüft nur die Projekt-Metadaten (enable-oslogin/-2fa). Instanz-Metadaten können die Projekteinstellung überschreiben und werden nicht einzeln geprüft." |
| Prüflogik (deskriptiv) | Je Projekt: `ProjectsClient.get()` → `common_instance_metadata.items_` wird in ein Dict überführt; `enable-oslogin` und `enable-oslogin-2fa` werden (uppercased) ausgelesen. Beide `== "TRUE"` → aggregierter Positivnachweis je Projekt; sonst aggregiertes Mangel-Finding je Projekt (keine Prüfung auf Instanz-Ebene). |

**Finding-Texte (Mangel-Pfad):**
- title: "OS Login 2FA nicht aktiviert"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat enable-oslogin={'aktiviert' if os_login=='TRUE' else 'deaktiviert'} und enable-oslogin-2fa={'aktiviert' if os_login_2fa=='TRUE' else 'deaktiviert'}. Ohne OS Login 2FA fehlt die Multi-Faktor-Authentifizierung für SSH-Zugriff auf VMs."
- expected_state: "enable-oslogin=TRUE und enable-oslogin-2fa=TRUE in den Projekt-Metadaten"
- remediation (Template, aus Teilstrings zusammengesetzt): "Aktivieren Sie OS Login mit 2FA:\ngcloud compute project-info add-metadata --metadata enable-oslogin=TRUE,enable-oslogin-2fa=TRUE --project=<PROJECT_ID>"
- remediation_effort: LOW
- audit_evidence (Template): `f"project.commonInstanceMetadata: enable-oslogin={os_login or 'not set'}, enable-oslogin-2fa={os_login_2fa or 'not set'}"`

**Positivnachweis (compliant_finding):**
- title: "OS Login mit 2FA aktiviert"
- description (Template): `f"Projekt {project_id} erzwingt OS Login mit Zwei-Faktor-Authentifizierung für SSH-Zugriff auf VMs."`
- expected_state: "enable-oslogin=TRUE und enable-oslogin-2fa=TRUE in den Projekt-Metadaten"
- audit_evidence: "project.commonInstanceMetadata: enable-oslogin=TRUE, enable-oslogin-2fa=TRUE" (Literal)

---

### GCP-NR10-005 — Sichere Identitätskonfiguration (Cloud Identity)

Klassen-Docstring (wörtlich): "Prüft ob eine sichere Identitätskonfiguration vorhanden ist."

| Feld | Wert |
|---|---|
| Klasse | `CheckSecureLdap` |
| description | "Prüft ob Cloud Identity für die zentrale Identitätsverwaltung konfiguriert ist. Secure LDAP erfordert Cloud Identity Premium." |
| severity | MEDIUM (Mangel-Pfad, inline; nur im "nicht zugänglich"-Pfad) |
| iso27001_control | inline Literal "A.8.5 Sichere Authentifizierung, A.8.20 Netzwerksicherheit" (identisch in beiden definierten Pfaden) |
| required_permissions | `["cloudidentity.groups.list"]` |
| pruefgrenzen | "Heuristische Prüfung: erkennt nur, ob Cloud Identity zugänglich ist und sicherheitsbezogen benannte Gruppen existieren. Ob Secure LDAP oder eine zentrale Identitätsverwaltung tatsächlich konfiguriert ist, wird nicht geprüft. Ohne Treffer wird kein Ergebnis ausgegeben (Nicht anwendbar)." |
| Prüflogik (deskriptiv) | Je Projekt: `cloudidentity`-API v1: `groups().list(parent="customers/my_customer")` → `groups`; gefiltert auf `security_groups`, deren (lowercased) `displayName` eines der Schlüsselwörter "security", "sicherheit", "admin" oder "mfa" enthält. Nicht-leere `security_groups` → aggregierter Positivnachweis je Projekt. Leere `security_groups` (unabhängig davon, ob `groups` selbst leer ist) → nur `logger.info()`, kein Finding. Wirft der API-Aufruf eine Exception mit "not enabled"/"403"/"permission"/"not found" in der Fehlermeldung → Mangel-Finding "Cloud Identity nicht zugänglich"; andere Exceptions → `CheckError`. Secure LDAP selbst wird an keiner Stelle abgefragt. |

**Finding-Texte (Mangel-Pfad, nur bei API-Zugriffsfehler):**
- title: "Cloud Identity nicht zugänglich"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keinen Zugriff auf die Cloud Identity API. Ohne zentrale Identitätsverwaltung können Authentifizierungs- und Gruppenmitgliedschaftsrichtlinien nicht zentral gesteuert werden."
- expected_state: "Cloud Identity API zugänglich für zentrale Identitätsverwaltung und sichere Authentifizierung"
- remediation (Template, aus Teilstrings zusammengesetzt): "Aktivieren Sie Cloud Identity:\n1. gcloud services enable cloudidentity.googleapis.com --project=<PROJECT_ID>\n2. Konfigurieren Sie Cloud Identity Premium für Secure LDAP: admin.google.com > Apps > LDAP\nHinweis: Secure LDAP erfordert Cloud Identity Premium oder Google Workspace Business Plus."
- remediation_effort: HIGH
- audit_evidence (Template): `f"Cloud Identity API returned error: {type(exc).__name__}"`

**Positivnachweis (compliant_finding):**
- title: "Cloud Identity mit Sicherheitsgruppen konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id}: Cloud Identity ist zugänglich und enthält {len(security_groups)} sicherheitsbezogene Gruppe(n) für zentrale Identitätsverwaltung."
- expected_state: "Cloud Identity API zugänglich für zentrale Identitätsverwaltung und sichere Authentifizierung"
- audit_evidence (Template): `f"groups.list() returned {len(groups)} groups, {len(security_groups)} security-related"`

---

## Mechanische Auffälligkeiten (ohne Bewertung)

1. Keine der 15 Check-Klassen definiert ein Klassenattribut `severity` — severity wird stattdessen pro `Finding()`-Aufruf im Mangel-Pfad als Parameter gesetzt (innerhalb desselben Checks jeweils konsistent, mit Ausnahme von GCP-NR10-002/-003/-005, die mehrere strukturell unterschiedliche Mangel-/Positiv-Varianten unter derselben check_id erzeugen, siehe Punkte 20-21).
2. Keine der 15 Check-Klassen definiert ein Klassenattribut `iso_27001_ref` — `iso27001_control` wird pro `Finding()`/`compliant_finding()`-Aufruf als Parameter übergeben. Nur das AWS-Modul definiert eine wiederverwendbare Modulkonstante (`ISO_CONTROL = "A.8.5 Secure authentication"`, englisch); Azure und GCP wiederholen stattdessen den deutschsprachigen Text "A.8.5 Sichere Authentifizierung" als String-Literal an jeder Aufrufstelle. Für A.8.20 verwenden AWS-NR10-003/-004 die englische Bezeichnung "A.8.20 Networks security", während AZ-NR10-003/-004 und GCP-NR10-003 die deutsche Bezeichnung "A.8.20 Netzwerksicherheit" verwenden — dieselbe Sprachaufteilung wie im Nr.-5-Dossier vermerkt.
3. AWS-NR10-004 (`CheckSesSnsTls`) deklariert `required_permissions = ["ses:GetAccount", "sns:ListTopics", "sns:GetTopicAttributes"]`, der Checkcode ruft jedoch an keiner Stelle eine SES-API auf — ausschließlich SNS (`list_topics`, `get_topic_attributes`) wird abgefragt. Titel ("SES/SNS TLS-Erzwingung"), description und pruefgrenzen benennen dagegen beide Dienste.
4. AWS-NR10-004 prüft TLS-Erzwingung ausschließlich über einen rohen Teilstring-Test `"aws:SecureTransport" in policy_str` auf dem JSON-serialisierten SNS-Topic-Policy-String — die Policy wird nicht geparst; ein Policy-String, der die Zeichenkette `aws:SecureTransport` lediglich enthält (z. B. mit Wert `"false"` oder in einer `Allow`-Anweisung ohne Deny-Wirkung), würde ebenfalls als Treffer gewertet und als "TLS-Erzwingung" (Positivnachweis) gemeldet.
5. AWS-NR10-003 (`CheckVpnAdminAccess`) bricht die Regionsschleife per `break` ab, sobald in einer Region ein aktives VPN-Gateway oder ein aktiver Client-VPN-Endpoint gefunden wird — weitere Regionen werden dann nicht mehr geprüft. Bei einem regionalen API-Fehler läuft die Schleife dagegen weiter und ein `CheckError` wird angehängt. Ist am Ende `vpn_found` False und liegt mindestens ein `CheckError` vor, greift die Bedingung `elif not errors` nicht — für diesen Scan-Lauf wird dann weder ein Positiv- noch ein Mangel-Finding erzeugt, nur der/die `CheckError`.
6. AWS-NR10-002 (`CheckIamUserMfaEnforcement`) überspringt (per `continue`) jeden Benutzer, für den `get_login_profile()` eine Exception wirft — dies dient zur Erkennung von "kein Konsolen-Zugang", erfasst aber ebenso jede andere Exception-Ursache (z. B. Throttling) identisch, ohne Finding oder `CheckError` für den betroffenen Benutzer.
7. AWS-NR10-005 (`CheckBreakGlassProcedure`) erkennt Break-Glass-Namensmuster per Teilstring gegen `_BREAK_GLASS_NAME_PATTERNS = ("break-glass", "breakglass", "emergency", "notfall")`, Tag-Werte dagegen nur gegen `_BREAK_GLASS_TAG_VALUES = ("break-glass", "emergency")` — "notfall"/"break_glass" sind in der Tag-Werte-Liste nicht enthalten, obwohl sie (bzw. eine Schreibvariante davon) in der Namensmuster-Liste vorkommen. Ein einziger Treffer irgendeines Benutzers genügt, um den gesamten Account als compliant zu werten; resource_id in Positiv- wie Mangel-Pfad ist der Root-Account-ARN, nicht der tatsächlich gefundene Benutzer.
8. AZ-NR10-001 (`CheckMfaAllUsers`) — die pruefgrenzen-Angabe lautet "Prüft die MFA-Registrierung der Entra-ID-Benutzer (Graph API)"; der ausgeführte Code fragt jedoch ausschließlich Conditional-Access-Policies ab (`identity.conditional_access.policies.get()`) — eine benutzerbezogene MFA-Registrierungsabfrage findet im Checkcode nicht statt.
9. AZ-NR10-001 prüft nur, ob eine Policy `include_users` mit `"All"` und eine MFA-Grant-Control besitzt; `conditions.users.exclude_users` derselben Policy wird nicht ausgewertet (anders als in AZ-NR10-005, wo `exclude_users` gelesen wird). Eine Policy mit `include_users=["All"]`, die zusätzlich einzelne Benutzer ausschließt, würde den Check dennoch als "MFA für alle Benutzer durchgesetzt" (compliant) werten.
10. AZ-NR10-002 (`CheckPhishingResistantMfa`) verwendet eine einzige Boolean-Variable `fido2_enabled`, die sowohl "FIDO2 aktiviert" als auch "Windows Hello for Business aktiviert" repräsentiert — der Variablenname bildet nur eine der beiden Bedingungen ab, die er tatsächlich tragen kann.
11. AZ-NR10-003 deklariert `required_permissions` inkl. `Microsoft.Network/bastionHosts/read`, der Code fragt Bastion Hosts jedoch über die generische `ResourceManagementClient.resources.list(filter="resourceType eq '...'")`-API ab statt über eine Bastion-spezifische API — dasselbe generische-Listing-vs-spezifische-Permission-Muster wie bei AZ-NR5-002 im Nr.-5-Dossier vermerkt.
12. AZ-NR10-004 (`CheckO365TlsEnforcement`) — Check-Titel ("Teams/Exchange — TLS erzwungen"), description ("TLS-Verschlüsselung ... erzwingen") und Finding-Texte ("Sicherheitsanforderungen") benennen TLS, der ausgeführte Code prüft aber ausschließlich, ob eine auf O365-Apps zielende Policy eine der Grant-Controls "compliantdevice", "approvedapplication" oder "mfa" (irgendeine davon) besitzt — keines dieser drei Felder ist eine TLS-spezifische Einstellung, und kein TLS-bezogenes Feld wird an irgendeiner Stelle des Codes gelesen.
13. AZ-NR10-005 (`CheckBreakGlassAccounts`) definiert die Klassenkonstante `BREAK_GLASS_PATTERNS = {"breakglass", "emergency", "break-glass", "break_glass", "notfall"}`, die im gesamten `execute()`-Code nicht referenziert wird — die tatsächliche Erkennungslogik basiert ausschließlich auf "permanente Global-Admin-Rollenzuweisung, deren principal_id von mindestens einer Conditional-Access-Policy ausgeschlossen ist", nicht auf Namensmustern. Die eigene pruefgrenzen-Angabe ("sucht nach benannten Break-Glass-Konten") und der audit_evidence-Text des Mangel-Pfads ("no break-glass pattern found") beschreiben beide eine Namensmuster-Erkennung, die im Code nicht stattfindet.
14. AZ-NR10-005 Positivnachweis `expected_state` lautet "Mindestens zwei Break-Glass-Konten (permanente Global Admins, CA-ausgeschlossen)" (mindestens zwei); die Schleife `for assignment in global_admin_assignments: ...; break_glass_found = True; break` bricht jedoch bereits beim ersten Treffer ab und meldet dann compliant — der Check kann nicht zwischen einem und mehreren solchen Konten unterscheiden.
15. GCP-NR10-001 (`CheckTwoStepVerification`) ruft `users().list(customer="my_customer", maxResults=100, projection="full")` genau einmal je Projekt auf, ohne `nextPageToken` zu verfolgen — bei mehr als 100 Benutzern im Workspace-/Cloud-Identity-Kunden werden Benutzer jenseits der ersten Seite stillschweigend nicht geprüft, ohne `CheckError`.
16. GCP-NR10-001: Ist `users` eine leere Liste (API-Erfolg, aber null Benutzer zurückgegeben), greift weder die Positiv-Bedingung (`if users and not users_without_2sv`) noch die Mangel-Bedingung (`elif users_without_2sv`) — für dieses Projekt wird kein Finding und kein `CheckError` erzeugt.
17. GCP-NR10-002 (`CheckIapAdminAccess`) wertet bereits das bloße Vorhandensein von ≥1 IAM-Policy-Bindung auf der Ressource `iap_tunnel` als Nachweis für "administrativen Zugriff mit Multi-Faktor-Authentifizierung" — ob die gebundenen Mitglieder tatsächlich über IAP zugreifen müssen oder eine MFA-Konfiguration haben, wird nicht geprüft (API-Erfolg mit nicht-leerem Ergebnis als alleiniger Positivnachweis).
18. GCP-NR10-003 (`CheckVpnGateways`) verschluckt Fehler bei der IAP-Fallback-Abfrage mit `except Exception: pass` — jeder Fehler (Auth-Fehler, API nicht aktiviert, transienter Fehler) wird dabei identisch zu "kein IAP konfiguriert" behandelt, ohne `CheckError` für das betroffene Projekt.
19. GCP-NR10-003 deklariert `required_permissions = ["compute.vpnGateways.list"]`; der Code fragt als Fallback zusätzlich dieselbe IAP-Tunnel-IAM-Policy ab wie GCP-NR10-002 (dessen `required_permissions` `iap.tunnelInstances.getIamPolicy` deklariert) — diese Permission ist bei GCP-NR10-003 nicht gelistet.
20. GCP-NR10-002 erzeugt unter derselben check_id zwei strukturell unterschiedliche Mangel-Findings je nach Codepfad: "Kein IAP für administrativen Zugriff konfiguriert" (bindings leer, remediation_effort MEDIUM, resource_id `.../iap_tunnel`) vs. "IAP API nicht aktiviert" (Exception-Pfad bei "not enabled"/"403", remediation_effort LOW, resource_id `.../iap`, abweichendes `current_state`-Schema).
21. GCP-NR10-003 erzeugt unter derselben check_id zwei strukturell unterschiedliche Positivnachweis-Varianten: "VPN-Gateways für sichere Konnektivität vorhanden" (VPN-Pfad) vs. "IAP-Tunnel als sichere Konnektivitätslösung vorhanden" (IAP-Fallback-Pfad) — unterschiedliche Titel/descriptions/`current_state`-Schema (`vpn_gateways`+`iap_configured` vs. nur `vpn_gateways`) bei gemeinsamem `expected_state`-Text.
22. GCP-NR10-005 (`CheckSecureLdap`) — Check-Titel ("Sichere Identitätskonfiguration (Cloud Identity)"), description und remediation stellen "Secure LDAP" in den Vordergrund; die ausgeführte Prüflogik listet jedoch nur Cloud-Identity-Gruppen und wertet eine Gruppe, deren `displayName` eines der Schlüsselwörter "security", "sicherheit", "admin" oder "mfa" enthält, als Nachweis — Secure LDAP selbst (ein admin.google.com > Apps > LDAP Feature) wird an keiner Stelle abgefragt oder verifiziert.
23. GCP-NR10-005: Ist `groups` zugänglich, aber `security_groups` leer (unabhängig davon, ob `groups` selbst leer oder nicht-leer ist), wird nur `logger.info(...)` aufgerufen — es entsteht kein Finding (weder Positivnachweis noch Mangel) für dieses Projekt, was der eigenen pruefgrenzen-Angabe entspricht ("Ohne Treffer wird kein Ergebnis ausgegeben (Nicht anwendbar)").
24. `CheckError()`-Aufrufe unterscheiden sich zwischen Providern: AWS und GCP übergeben nur `message` und `error_type`; Azure übergibt zusätzlich `check_id` und `region="global"` — dasselbe Muster wie in den bereits vorliegenden Nr.-1-, Nr.-3- und Nr.-5-Dossiers vermerkt.
25. Klassendocstrings sind sprachlich uneinheitlich: alle 5 AWS-Klassen haben englische Docstrings ("Check that..."); alle 5 Azure-Klassen, die einen Docstring haben (`CheckMfaAllUsers`, `CheckPhishingResistantMfa`, `CheckVpnBastion`, `CheckO365TlsEnforcement`, `CheckBreakGlassAccounts`), haben ebenfalls englische Docstrings — abweichend vom Nr.-5-Dossier, wo keine der Azure-Klassen einen Docstring hatte; alle 5 GCP-Klassen haben deutsche Docstrings ("Prüft ob...").
26. Granularität der Findings ist zwischen Providern und teils innerhalb eines Providers uneinheitlich: AWS erzeugt bei NR10-002 (je IAM-Benutzer) und NR10-004 (je SNS-Topic) Findings pro Einzelressource, bei NR10-001/-003/-005 dagegen je ein aggregiertes Finding auf Account-Ebene; Azure erzeugt bei AZ-NR10-003 ein aggregiertes Finding je Subscription, bei AZ-NR10-001/-002/-004/-005 je ein aggregiertes Finding tenant-weit; GCP erzeugt bei allen fünf Checks (GCP-NR10-001 bis -005) je ein aggregiertes Finding pro Projekt, keine Findings pro Einzelressource (z. B. je Benutzer oder je VM).
27. AZ-NR10-002 und AZ-NR10-005 setzen `account_id=session.subscription_id`, obwohl die geprüfte Ressource (Authentication-Methods-Policy bzw. Rollenzuweisungen) ein tenant-weites Entra-ID-Objekt ist, nicht auf eine Azure-Subscription bezogen — ebenso bei AZ-NR10-001/-004.
28. Severity-Werte innerhalb des Themas MFA/Notfallzugang sind uneinheitlich: AWS-NR10-001 (Root-MFA) und AWS-NR10-002 (IAM-User-MFA) sind CRITICAL, AWS-NR10-005 (Break-Glass, dessen eigene remediation "starke MFA" für den Notfall-Account fordert, ohne dass MFA für den erkannten Account tatsächlich geprüft wird) ist HIGH; GCP-NR10-001 (2SV) ist CRITICAL, während das analoge AZ-NR10-001 (MFA für alle Benutzer) ebenfalls CRITICAL ist, AZ-NR10-002 (phishing-resistente MFA) und GCP-NR10-004 (OS-Login-2FA) dagegen HIGH.
