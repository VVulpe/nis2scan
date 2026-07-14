# W4 Batch-Review-Dossier — §30 Abs. 2 Nr. 7 BSIG (Grundlegende Schulungen und Sensibilisierung)

> Mechanisch extrahiert am 2026-07-13 (Worker, ohne rechtliche Bewertung).
> Prüfgegenstand für: Gründer + Agent legal-reviewer (ADR-0018).

Quelldateien:
- `nis2scan/engine/providers/aws/checks/nr7_cyberhygiene.py`
- `nis2scan/engine/providers/azure/checks/nr7_cyberhygiene.py`
- `nis2scan/engine/providers/gcp/checks/nr7_cyberhygiene.py`

Ist-Zahl erfasster Checks: **6** (AWS: 2, Azure: 2, GCP: 2) — entspricht der erwarteten Zahl.

## Modul-Konstanten je Provider

### AWS (`nr7_cyberhygiene.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 7 — Grundlegende Verfahren der Cyberhygiene und Schulungen checks for AWS.

  Checks IAM password policy and root account security hygiene.
  ```
- `BSIG_30_NR = 7`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 7 BSIG — grundlegende Schulungen und Sensibilisierungsmaßnahmen im Bereich der Sicherheit in der Informationstechnik"
- `ISO_CONTROL` (wörtlich): "A.5.17 Authentication information" (englisch)
- `MIN_PASSWORD_LENGTH = 14`

### Azure (`nr7_cyberhygiene.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 7 — Cyberhygiene & Schulungen checks for Azure.

  Checks Entra ID Password Protection and Security Defaults / Conditional Access Baseline.
  ```
- `BSIG_30_NR = 7`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS): "§30 Abs. 2 Nr. 7 BSIG — grundlegende Schulungen und Sensibilisierungsmaßnahmen im Bereich der Sicherheit in der Informationstechnik"
- Kein Modul-Äquivalent zu `ISO_CONTROL`.

### GCP (`nr7_cyberhygiene.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 7 — Cyberhygiene und Cybersicherheitsschulungen checks for GCP.

  Checks Organization Security Policies and Essential Contacts.
  ```
- `BSIG_30_NR = 7`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS/Azure): "§30 Abs. 2 Nr. 7 BSIG — grundlegende Schulungen und Sensibilisierungsmaßnahmen im Bereich der Sicherheit in der Informationstechnik"
- `SECURITY_CONSTRAINTS` (wörtlich, Liste):
  ```python
  SECURITY_CONSTRAINTS = [
      "iam.disableServiceAccountKeyCreation",
      "compute.requireOsLogin",
      "storage.uniformBucketLevelAccess",
      "iam.disableServiceAccountKeyUpload",
      "compute.disableSerialPortAccess",
      "compute.disableNestedVirtualization",
      "sql.restrictPublicIp",
  ]
  ```
- Kein Modul-Äquivalent zu `ISO_CONTROL`.

---

## Checks

### AWS-NR7-001 — IAM Password Policy

Klassen-Docstring (wörtlich): "Check that IAM account password policy meets minimum security requirements."

| Feld | Wert |
|---|---|
| Klasse | `CheckIamPasswordPolicy` |
| description | f-String, zur Klassendefinitionszeit mit `MIN_PASSWORD_LENGTH=14` ausgewertet: "Prüft ob die IAM-Passwort-Richtlinie Mindestanforderungen erfüllt (≥14 Zeichen, Komplexität)." |
| severity | HIGH (beide Mangel-Pfade, inline im jeweiligen `Finding()`-Aufruf, kein Klassenattribut) |
| iso27001_control | `ISO_CONTROL` = "A.5.17 Authentication information" (identisch in Positiv- und beiden Mangel-Pfaden) |
| required_permissions | `["iam:GetAccountPasswordPolicy"]` |
| pruefgrenzen | "Prüft nur die IAM-Passwort-Richtlinie des Accounts. Föderierte Identitäten (SSO/IdP) unterliegen der Richtlinie des Identitätsanbieters und werden hier nicht geprüft." |
| Prüflogik (deskriptiv) | `iam.get_account_password_policy()` wird aufgerufen; bei Erfolg werden fünf Policy-Felder (`MinimumPasswordLength`, `RequireUppercaseCharacters`, `RequireLowercaseCharacters`, `RequireNumbers`, `RequireSymbols`) gegen feste Mindestwerte geprüft (Länge ≥ 14, die übrigen vier `== True`); keine Verstöße ergibt Positivnachweis, mindestens ein Verstoß ergibt ein Mangel-Finding mit Auflistung der Verstöße. Wirft der API-Aufruf `NoSuchEntityException` (keine Richtlinie konfiguriert), wird ein separates Mangel-Finding mit eigenem Titel/eigener Textfassung erzeugt. |

**Finding-Texte (Mangel-Pfad A — Policy vorhanden, aber unzureichend):**
- title: "IAM-Passwort-Richtlinie unzureichend"
- description (Template): `f"Die IAM-Passwort-Richtlinie erfüllt nicht die Mindestanforderungen: {'; '.join(issues)}"`
- expected_state (Template, `MIN_PASSWORD_LENGTH` eingesetzt): `f"MinimumPasswordLength>={MIN_PASSWORD_LENGTH}, RequireUppercase=true, RequireLowercase=true, RequireNumbers=true, RequireSymbols=true"`
- remediation (Template, aus Teilstrings zusammengesetzt): "Aktualisieren Sie die IAM-Passwort-Richtlinie: aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols"
- remediation_effort: LOW
- audit_evidence (Template): `f"GetAccountPasswordPolicy: {'; '.join(issues)}"`

**Finding-Texte (Mangel-Pfad B — keine benutzerdefinierte Policy, `NoSuchEntityException`):**
- title: "Keine IAM-Passwort-Richtlinie konfiguriert"
- description: "Es ist keine benutzerdefinierte IAM-Passwort-Richtlinie konfiguriert. Es gelten die AWS-Standardeinstellungen mit minimaler Komplexität."
- expected_state: "Benutzerdefinierte Passwort-Richtlinie mit Komplexitätsanforderungen"
- remediation (Template, aus Teilstrings zusammengesetzt): "Erstellen Sie eine IAM-Passwort-Richtlinie: aws iam update-account-password-policy --minimum-password-length 14 --require-uppercase-characters --require-lowercase-characters --require-numbers --require-symbols"
- remediation_effort: LOW
- audit_evidence: "GetAccountPasswordPolicy: NoSuchEntity" (Literal, kein f-String)

**Positivnachweis (compliant_finding):**
- title: "IAM-Passwort-Richtlinie erfüllt Anforderungen"
- description (Template): `f"Die IAM-Passwort-Richtlinie erfüllt die Mindestanforderungen (Länge >= {MIN_PASSWORD_LENGTH}, Komplexität aktiviert)."`
- expected_state (Template, identisch zu Mangel-Pfad A): `f"MinimumPasswordLength>={MIN_PASSWORD_LENGTH}, RequireUppercase=true, RequireLowercase=true, RequireNumbers=true, RequireSymbols=true"`
- audit_evidence (Template): `f"GetAccountPasswordPolicy: all requirements met (length={min_length})"`
- `current_state` setzt `require_uppercase`/`require_lowercase`/`require_numbers`/`require_symbols` als hartkodierte `True`-Literale (nicht direkt aus `policy.get(...)` gelesen); im Mangel-Pfad A werden dieselben Felder direkt aus `policy.get(...)` gelesen.

---

### AWS-NR7-002 — Root Account Access Keys

Klassen-Docstring (wörtlich): "Check that the root account has no access keys."

| Feld | Wert |
|---|---|
| Klasse | `CheckRootAccessKeys` |
| description | "Prüft ob der Root-Account keine Access Keys besitzt." |
| severity | CRITICAL (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.17, A.8.2" (identisch in Positiv- und Mangel-Pfad; nicht über die Modulkonstante `ISO_CONTROL`) |
| required_permissions | `["iam:GetAccountSummary"]` |
| pruefgrenzen | "Prüft nur, ob Root-Access-Keys existieren. Root-MFA und Root-Nutzung werden in den NR10-Checks geprüft." |
| Prüflogik (deskriptiv) | `iam.get_account_summary()` liefert `SummaryMap["AccountAccessKeysPresent"]`; Wert `0` ergibt Positivnachweis, jeder andere Wert ergibt ein Mangel-Finding mit severity CRITICAL — jeweils genau ein Finding pro Scan (kein Pro-Key-Finding, da die API nur einen aggregierten Zähler liefert). |

**Finding-Texte (Mangel-Pfad):**
- title: "Root-Account hat Access Keys"
- description (Template, aus Teilstrings zusammengesetzt): `f"Der Root-Account besitzt {access_keys} Access Key(s). Root Access Keys stellen ein erhebliches Sicherheitsrisiko dar, da sie uneingeschränkte Rechte haben und nicht durch IAM-Policies eingeschränkt werden können."`
- expected_state: "Keine Access Keys für den Root-Account (AccountAccessKeysPresent=0)"
- remediation: "Löschen Sie SOFORT alle Root Access Keys. AWS Console: Account → Security credentials → Access keys → Delete. Verwenden Sie stattdessen IAM-Benutzer oder IAM-Rollen mit minimalen Berechtigungen."
- remediation_effort: LOW
- audit_evidence (Template): `f"GetAccountSummary: AccountAccessKeysPresent={access_keys}"`

**Positivnachweis (compliant_finding):**
- title: "Root-Account ohne Access Keys"
- description: "Der Root-Account besitzt keine Access Keys."
- expected_state: "Keine Access Keys für den Root-Account (AccountAccessKeysPresent=0)" (identisch zum Mangel-Pfad)
- audit_evidence: "GetAccountSummary: AccountAccessKeysPresent=0" (Literal, kein f-String)

---

### AZ-NR7-001 — Entra ID Password Protection konfiguriert

Klassen-Docstring (wörtlich): "Check that Entra ID Password Protection is configured."

| Feld | Wert |
|---|---|
| Klasse | `CheckPasswordProtection` |
| description | "Prüft ob Entra ID Password Protection mit benutzerdefinierter Liste verbotener Passwörter konfiguriert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.17 Authentifizierungsinformationen" (identisch in beiden Pfaden) |
| required_permissions | `["Policy.Read.All"]` |
| pruefgrenzen | "Prüft nur die Entra-ID-Password-Protection-Einstellungen (Graph API). Lokale AD-Passwortrichtlinien ohne Entra-Anbindung werden nicht erfasst." |
| Prüflogik (deskriptiv) | Graph API `policies.authentication_methods_policy.get()` wird aufgerufen; über `authentication_method_configurations` wird iteriert — sobald eine Konfiguration existiert, deren (kleingeschriebene) `id` den Teilstring "password" enthält, wird `password_protection_configured=True` gesetzt (Schleife bricht beim ersten Treffer ab). `True` ergibt Positivnachweis, `False` (keine Konfigurationsliste vorhanden oder kein Treffer) ergibt Mangel-Finding. Der Inhalt einer etwaigen benutzerdefinierten Liste verbotener Passwörter wird nicht ausgelesen. |

**Finding-Texte (Mangel-Pfad):**
- title: "Password Protection nicht konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Entra ID Password Protection mit benutzerdefinierter Liste verbotener Passwörter ist nicht konfiguriert. Ohne benutzerdefinierte Passwortliste können Benutzer schwache, unternehmensspezifische Passwörter verwenden."
- expected_state: "Password Protection mit benutzerdefinierter Liste verbotener Passwörter"
- remediation (Template, aus Teilstrings zusammengesetzt): "Konfigurieren Sie Password Protection: Entra Admin Center → Schutz → Authentifizierungsmethoden → Kennwortschutz → Benutzerdefinierte Liste verbotener Kennwörter aktivieren"
- remediation_effort: LOW
- audit_evidence: "Graph API: no password protection configuration found" (Literal, kein f-String)

**Positivnachweis (compliant_finding):**
- title: "Password Protection konfiguriert"
- description: "Entra ID Password Protection ist in den Authentifizierungsmethoden konfiguriert."
- expected_state: "Password Protection mit benutzerdefinierter Liste verbotener Passwörter" (identisch zum Mangel-Pfad)
- audit_evidence: "Graph API: password protection configuration found" (Literal, kein f-String)

---

### AZ-NR7-002 — Security Defaults oder Conditional Access Baseline

Klassen-Docstring (wörtlich): "Check that Security Defaults or Conditional Access baseline is active."

| Feld | Wert |
|---|---|
| Klasse | `CheckSecurityDefaults` |
| description | "Prüft ob Security Defaults aktiviert sind oder eine äquivalente Conditional Access Baseline-Konfiguration besteht." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.5.17 Authentifizierungsinformationen" (identisch in allen drei Pfaden: Security Defaults aktiv / CA-Baseline aktiv / Mangel) |
| required_permissions | `["Policy.Read.All"]` |
| pruefgrenzen | "Prüft nur, ob Security Defaults oder Conditional-Access-Grundschutz aktiv ist. Die inhaltliche Güte der CA-Policies wird nicht bewertet." |
| Prüflogik (deskriptiv) | Graph API `policies.identity_security_defaults_enforcement_policy.get()` liefert `is_enabled`; `True` ergibt sofortigen Positivnachweis mit vorzeitigem Return (kein weiterer API-Aufruf). Bei `False` folgt ein weiterer Aufruf `identity.conditional_access.policies.get()`; die zurückgegebenen Policies werden auf `state == "enabled"` (case-insensitiver Stringvergleich) gefiltert — mindestens eine aktivierte CA-Policy ergibt Positivnachweis ("Baseline aktiv"), keine aktivierte CA-Policy ergibt Mangel-Finding. Scope, Bedingungen und Grant-Controls der CA-Policies werden nicht ausgewertet. |

**Finding-Texte (Mangel-Pfad):**
- title: "Weder Security Defaults noch Conditional Access aktiv"
- description (Template, aus Teilstrings zusammengesetzt): "Security Defaults sind deaktiviert und es gibt keine aktiven Conditional Access Policies. Ohne grundlegende Sicherheitsstandards fehlen MFA-Enforcement, Legacy-Auth-Blockierung und weitere Baselines."
- expected_state: "Security Defaults aktiviert ODER äquivalente CA-Policies" (identisch in allen drei Pfaden)
- remediation (Template, aus Teilstrings zusammengesetzt): "Aktivieren Sie Security Defaults: Entra Admin Center → Identität → Übersicht → Eigenschaften → Sicherheitsstandards verwalten → Aktiviert. Oder erstellen Sie äquivalente Conditional Access Policies."
- remediation_effort: LOW
- audit_evidence: "Graph API: Security Defaults disabled, 0 CA policies enabled" (Literal, kein f-String)

**Positivnachweis A (compliant_finding, Security Defaults aktiviert):**
- title: "Security Defaults aktiviert"
- description: "Security Defaults sind aktiviert — MFA-Enforcement, Legacy-Auth-Blockierung und weitere Baselines greifen."
- expected_state: "Security Defaults aktiviert ODER äquivalente CA-Policies"
- audit_evidence: "Graph API: Security Defaults enabled" (Literal, kein f-String)

**Positivnachweis B (compliant_finding, Conditional Access Baseline aktiv):**
- title: "Conditional Access Baseline aktiv"
- description (Template): `f"Security Defaults sind deaktiviert, aber {len(enabled_policies)} aktive Conditional Access Policies bilden die Baseline."`
- expected_state: "Security Defaults aktiviert ODER äquivalente CA-Policies"
- audit_evidence (Template): `f"Graph API: Security Defaults disabled, {len(enabled_policies)} CA policies enabled"`

---

### GCP-NR7-001 — Sicherheitsrelevante Organisationsrichtlinien

Klassen-Docstring (wörtlich): "Prüft ob sicherheitsrelevante Organisationsrichtlinien gesetzt sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckOrgSecurityPolicies` |
| description | statischer Text, aus Teilstrings zusammengesetzt (keine Variablen): "Prüft ob Org Policy sicherheitsrelevante Einschränkungen wie Deaktivierung von Service-Account-Schlüsseln, OS Login-Pflicht und einheitliche Bucket-Zugriffssteuerung erzwingt." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.6.3 Informationssicherheitsbewusstsein, -ausbildung und -schulung" (identisch in beiden Pfaden) |
| required_permissions | `["orgpolicy.policy.get"]` |
| pruefgrenzen | "Prüft die Projekt-Policies gegen eine feste Liste sicherheitsrelevanter Constraints. Auf Organisationsebene gesetzte Policies, die nicht auf Projektebene sichtbar sind, können unerkannt bleiben." |
| Prüflogik (deskriptiv) | Je `project_id`: `orgpolicy` API v2 `projects().policies().list(parent="projects/{project_id}")`; aus jedem zurückgegebenen Policy-Objekt wird nur das Feld `name` (letztes Segment nach "/") als Constraint-Name extrahiert und in eine Menge `active_constraints` aufgenommen. Für jeden Eintrag der Modulkonstante `SECURITY_CONSTRAINTS` wird per Substring-Test (`c in ac`) geprüft, ob er in einem der aktiven Constraint-Namen enthalten ist — mindestens ein Treffer ergibt ein aggregiertes Positiv-Finding je Projekt, kein Treffer ein aggregiertes Mangel-Finding je Projekt. Der Regelwert/die Durchsetzungseinstellung (`spec`/`rules`/`enforce`) der gefundenen Policy wird nicht ausgelesen. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine sicherheitsrelevanten Organisationsrichtlinien"
- description (Template, aus Teilstrings zusammengesetzt): `f"Projekt {project_id} hat keine sicherheitsrelevanten Organization Policy Constraints konfiguriert. Grundlegende Cyberhygiene erfordert die Durchsetzung von Sicherheitsrichtlinien auf Organisationsebene."`
- expected_state (Template, aus Teilstrings zusammengesetzt, identisch zum Positivnachweis): "Sicherheitsrelevante Org Policy Constraints wie iam.disableServiceAccountKeyCreation, compute.requireOsLogin und storage.uniformBucketLevelAccess aktiviert"
- remediation (Template, aus Teilstrings zusammengesetzt): "Setzen Sie sicherheitsrelevante Org Policies:\ngcloud org-policies set-policy policy.yaml --project=<PROJECT_ID>\nEmpfohlene Constraints:\n- constraints/iam.disableServiceAccountKeyCreation\n- constraints/compute.requireOsLogin\n- constraints/storage.uniformBucketLevelAccess"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"policies.list() returned {len(policies)} policies, none matching security constraints"`

**Positivnachweis (compliant_finding):**
- title: "Sicherheitsrelevante Organisationsrichtlinien aktiv"
- description (Template): `f"Projekt {project_id} erzwingt {len(found_security)} sicherheitsrelevante Org Policy Constraint(s): {', '.join(found_security)}."`
- expected_state (identisch zum Mangel-Pfad, Template aus Teilstrings zusammengesetzt): "Sicherheitsrelevante Org Policy Constraints wie iam.disableServiceAccountKeyCreation, compute.requireOsLogin und storage.uniformBucketLevelAccess aktiviert"
- audit_evidence (Template): `f"policies.list() returned {len(policies)} policies, {len(found_security)} matching security constraints"`

---

### GCP-NR7-002 — Essential Contacts für Sicherheitsbenachrichtigungen

Klassen-Docstring (wörtlich): "Prüft ob Essential Contacts für Sicherheitsbenachrichtigungen konfiguriert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckEssentialContacts` |
| description | statischer Text, aus Teilstrings zusammengesetzt (keine Variablen): "Prüft ob Essential Contacts mit der Kategorie SECURITY konfiguriert sind, um sicherheitsrelevante Benachrichtigungen an die zuständigen Personen zu senden." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.6.3 Informationssicherheitsbewusstsein, -ausbildung und -schulung" (identisch in beiden Pfaden, identisch zu GCP-NR7-001) |
| required_permissions | `["essentialcontacts.contacts.list"]` |
| pruefgrenzen | "Prüft nur Essential Contacts der Kategorie SECURITY auf Projektebene. Organisationsweite Kontakte werden nicht geprüft." |
| Prüflogik (deskriptiv) | Je `project_id`: `essentialcontacts` API v1 `projects().contacts().list(parent="projects/{project_id}")`; gefiltert werden Kontakte, bei denen der String "SECURITY" in deren `notificationCategorySubscriptions`-Liste enthalten ist — mindestens ein solcher Kontakt ergibt ein aggregiertes Positiv-Finding je Projekt, keiner ein aggregiertes Mangel-Finding je Projekt. Das Feld `validationState` (Bestätigungsstatus der Kontakt-E-Mail-Adresse) wird im Filter nicht berücksichtigt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Sicherheits-Ansprechpartner konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): `f"Projekt {project_id} hat keine Essential Contacts für die Kategorie SECURITY. Ohne Sicherheits-Ansprechpartner werden kritische Sicherheitsbenachrichtigungen nicht zugestellt."`
- expected_state: "Mindestens ein Essential Contact mit der Kategorie SECURITY konfiguriert" (identisch zum Positivnachweis)
- remediation (Template, aus Teilstrings zusammengesetzt): "Fügen Sie einen Sicherheits-Ansprechpartner hinzu:\ngcloud essential-contacts create --email=security@example.com --notification-categories=SECURITY --project=<PROJECT_ID>"
- remediation_effort: LOW
- audit_evidence (Template): `f"contacts.list() returned {len(contacts)} contacts, none with SECURITY category"`

**Positivnachweis (compliant_finding):**
- title: "Sicherheits-Ansprechpartner konfiguriert"
- description (Template): `f"Projekt {project_id} hat {len(security_contacts)} Essential Contact(s) für die Kategorie SECURITY."`
- expected_state: "Mindestens ein Essential Contact mit der Kategorie SECURITY konfiguriert"
- audit_evidence (Template): `f"contacts.list() returned {len(contacts)} contacts, {len(security_contacts)} with SECURITY category"`

---

## Mechanische Auffälligkeiten (ohne Bewertung)

1. Keine der 6 Check-Klassen definiert ein Klassenattribut `severity` (abweichend vom Muster im Repo-`CLAUDE.md`) — severity wird stattdessen pro `Finding()`-Aufruf im Mangel-Pfad als Parameter gesetzt (innerhalb desselben Checks jeweils konsistent).
2. Keine der 6 Check-Klassen definiert ein Klassenattribut `iso_27001_ref` — `iso27001_control` wird stattdessen pro `Finding()`/`compliant_finding()`-Aufruf als Parameter übergeben.
3. Nur das AWS-Modul definiert eine wiederverwendbare Modulkonstante für den ISO-Text (`ISO_CONTROL = "A.5.17 Authentication information"`, englisch); Azure und GCP wiederholen stattdessen deutschsprachige String-Literale ("A.5.17 Authentifizierungsinformationen" bzw. "A.6.3 Informationssicherheitsbewusstsein, -ausbildung und -schulung") an jeder Aufrufstelle.
4. AWS-NR7-002 (`CheckRootAccessKeys`) verwendet nicht die Modulkonstante `ISO_CONTROL`, sondern das inline-Literal "A.5.17, A.8.2" — abweichend von AWS-NR7-001 in derselben Datei, das durchgängig `ISO_CONTROL` referenziert.
5. Für die Kontroll-Nr. A.5.17 verwenden AWS ("Authentication information", Englisch) und Azure ("Authentifizierungsinformationen", Deutsch) unterschiedliche Sprache, obwohl laut CLAUDE.md sämtlicher Report-Text auf Deutsch sein soll.
6. Die beiden GCP-Checks (Org Security Policies, Essential Contacts) sind auf ISO-Kontrolle "A.6.3 Informationssicherheitsbewusstsein, -ausbildung und -schulung" gemappt, während die AWS- und Azure-Checks in diesem Batch (Passwort-Policy, Root-Keys, Password Protection, Security Defaults/CA) auf "A.5.17" gemappt sind — die drei Provider referenzieren für nominell demselben §30-Nr.-7-Bereich zugeordnete Checks unterschiedliche ISO-27001-Kontrollen.
7. Keiner der 6 Checks in diesem Batch prüft eine tatsächliche Schulungs- oder Sensibilisierungsaktivität (z. B. Abschluss von Security-Awareness-Schulungen, Phishing-Simulationsergebnisse, dokumentiertes Sensibilisierungsprogramm) — `BSIG_30_TEXT` für Nr. 7 beschreibt wörtlich "grundlegende Schulungen und Sensibilisierungsmaßnahmen im Bereich der Sicherheit in der Informationstechnik"; alle 6 Checks bewerten stattdessen technische Konfigurationszustände (Passwort-Policy, Root-Access-Keys, Vorhandensein einer Password-Protection-Konfiguration, Security Defaults/CA, Org-Policy-Constraints, Essential Contacts).
8. Das AWS-Modul weicht bei der Fehlerbehandlung vom in CLAUDE.md dokumentierten Muster (`CheckError(message=str(e), error_type=type(e).__name__)`) ab: sowohl AWS-NR7-001 als auch AWS-NR7-002 verwenden eine angepasste Message mit Präfix (z. B. `f"IAM Password Policy Check fehlgeschlagen: {e}"`) und ein hartkodiertes Literal `error_type="CheckError"` anstelle des tatsächlichen Exception-Klassennamens. Das GCP-Modul in diesem Batch verwendet dagegen `error_type=type(exc).__name__` (Standardmuster).
9. AWS-NR7-001 erzeugt unter derselben check_id zwei inhaltlich unterschiedliche Mangel-Finding-Varianten ("Policy vorhanden, aber unzureichend" vs. "keine benutzerdefinierte Policy / NoSuchEntityException") mit unterschiedlichem `expected_state`-Text ("MinimumPasswordLength>=14, RequireUppercase=true, ..." vs. "Benutzerdefinierte Passwort-Richtlinie mit Komplexitätsanforderungen") für dieselbe zugrunde liegende Feststellung (kein ausreichender benutzerdefinierter Passwort-Policy).
10. AWS-NR7-001 setzt im Positivnachweis (`compliant_finding`) die `current_state`-Felder `require_uppercase`/`require_lowercase`/`require_numbers`/`require_symbols` als hartkodierte `True`-Literale, statt sie wie im Mangel-Pfad direkt aus dem `policy`-Objekt zu lesen.
11. AZ-NR7-001 (`CheckPasswordProtection`): Titel und description behaupten die Prüfung einer "benutzerdefinierten Liste verbotener Passwörter"; der Code prüft jedoch ausschließlich, ob irgendeine Konfiguration in `authentication_method_configurations` eine `id` mit dem Teilstring "password" enthält — der Inhalt einer etwaigen Sperrliste wird nicht ausgelesen oder bewertet.
12. AZ-NR7-002 (`CheckSecurityDefaults`) akzeptiert bei deaktivierten Security Defaults jede Conditional-Access-Policy mit `state == "enabled"` als ausreichend für "äquivalente CA-Policies"/"Baseline" — Scope, Bedingungen und Grant-Controls der Policy werden nicht geprüft. Die eigene pruefgrenzen-Angabe weist darauf hin ("Die inhaltliche Güte der CA-Policies wird nicht bewertet"), während Titel ("Conditional Access Baseline aktiv") und description ("bilden die Baseline") dies nicht einschränken.
13. GCP-NR7-001 (`CheckOrgSecurityPolicies`) vergleicht Constraint-Namen per Python-Substring-Test (`c in ac`), nicht per Gleichheitsvergleich, zwischen den Einträgen der Modulkonstante `SECURITY_CONSTRAINTS` und den aus der API extrahierten Constraint-Namen.
14. GCP-NR7-001 prüft nur die Existenz eines Policy-Objekts für einen passenden Constraint-Namen (`policies().list()`); der Regelwert/die Durchsetzungseinstellung (`spec`/`rules`/`enforce`) der gefundenen Policy wird nicht ausgelesen — ein Policy-Objekt, das den Constraint z. B. mit `enforce=false` oder einem permissiven Regelsatz versieht, würde ebenfalls als Treffer zählen.
15. GCP-NR7-001 deklariert `required_permissions = ["orgpolicy.policy.get"]` (Singular "get"), während der Code die `list`-Methode aufruft (`projects().policies().list(...)`).
16. GCP-NR7-002 (`CheckEssentialContacts`) filtert Kontakte ausschließlich über die Kategorie-Mitgliedschaft (`"SECURITY" in notificationCategorySubscriptions`); das Feld `validationState` (Bestätigungsstatus der Kontakt-E-Mail-Adresse) wird nicht berücksichtigt — ein nicht bestätigter oder bouncender Kontakt zählt ebenfalls als Treffer.
17. In beiden GCP-Checks wird die Exception-Behandlung je `project_id` innerhalb der Schleife durchgeführt (`except Exception as exc: errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))`); der erzeugte `CheckError` trägt weder `check_id` noch die betroffene `project_id` — bei einem Scan über mehrere Projekte lässt sich ein Fehler allein aus dem `CheckError`-Objekt nicht einem bestimmten Projekt zuordnen.
18. `CheckError()`-Aufrufe unterscheiden sich zwischen Providern: AWS und GCP übergeben nur `message` und `error_type` (bei AWS mit den in Punkt 8 beschriebenen Abweichungen); Azure übergibt zusätzlich `check_id` und `region="global"` — dasselbe Providermuster wie in den bereits vorliegenden Nr.-1-, Nr.-3- und Nr.-5-Dossiers vermerkt.
19. Klassendocstrings sind sprachlich uneinheitlich: beide AWS-Klassen haben englische Docstrings ("Check that..."), beide Azure-Klassen haben ebenfalls englische Docstrings ("Check that..."), beide GCP-Klassen haben deutsche Docstrings ("Prüft ob...") — dasselbe Sprachmuster wie in den bereits vorliegenden Nr.-1-, Nr.-3- und Nr.-5-Dossiers vermerkt (dort hatte Azure keine Klassendocstrings; in diesem Batch hat Azure englische).
20. Granularität der Findings ist innerhalb des Batches einheitlich: alle 6 Checks erzeugen genau ein aggregiertes Finding je Prüfziel (AWS: je Account/global; Azure: je Subscription/global; GCP: je Projekt) — im Gegensatz zu Nr. 5, wo einzelne Checks je Einzelressource iterierten.
