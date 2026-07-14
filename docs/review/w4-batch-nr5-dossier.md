# W4 Batch-Review-Dossier — §30 Abs. 2 Nr. 5 BSIG (Sicherheit bei Erwerb, Entwicklung und Wartung)

> Mechanisch extrahiert am 2026-07-12 (Worker, ohne rechtliche Bewertung).
> Prüfgegenstand für: Gründer + Agent legal-reviewer (ADR-0018).

Quelldateien:
- `nis2scan/engine/providers/aws/checks/nr5_schwachstellen.py`
- `nis2scan/engine/providers/azure/checks/nr5_schwachstellen.py`
- `nis2scan/engine/providers/gcp/checks/nr5_schwachstellen.py`

Ist-Zahl erfasster Checks: **15** (AWS: 5, Azure: 5, GCP: 5) — entspricht der erwarteten Zahl.

## Modul-Konstanten je Provider

### AWS (`nr5_schwachstellen.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 5 — Schwachstellenmanagement checks for AWS.

  Checks ECR image scanning configuration and SSM patch compliance.
  ```
- `BSIG_30_NR = 5`
- `BSIG_30_TEXT` (wörtlich): "§30 Abs. 2 Nr. 5 BSIG — Sicherheitsmaßnahmen bei Erwerb, Entwicklung und Wartung von informationstechnischen Systemen, Komponenten und Prozessen, einschließlich Management und Offenlegung von Schwachstellen"
- `ISO_CONTROL` (wörtlich): "A.8.8 Management of technical vulnerabilities" (englisch)

### Azure (`nr5_schwachstellen.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 5 — Schwachstellenmanagement checks for Azure.

  Checks Defender Vulnerability Assessment, Update Management, Container Registry Scan,
  App Service Runtime, and SQL Vulnerability Assessment.
  ```
- `BSIG_30_NR = 5`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS): "§30 Abs. 2 Nr. 5 BSIG — Sicherheitsmaßnahmen bei Erwerb, Entwicklung und Wartung von informationstechnischen Systemen, Komponenten und Prozessen, einschließlich Management und Offenlegung von Schwachstellen"
- `OUTDATED_RUNTIMES` (wörtlich, dict):
  ```python
  OUTDATED_RUNTIMES = {
      "DOTNET": ["3.1", "5.0", "6.0"],
      "NODE": ["12", "14", "16"],
      "PYTHON": ["3.7", "3.8", "3.9"],
      "JAVA": ["8", "11"],
      "PHP": ["7.4", "8.0"],
  }
  ```
- Kein Modul-Äquivalent zu `ISO_CONTROL`.

### GCP (`nr5_schwachstellen.py`)
- Modul-Docstring (wörtlich):
  ```
  §30 Abs. 2 Nr. 5 — Schwachstellenmanagement checks for GCP.

  Checks Container Analysis, OS Config Patch Management, Web Security Scanner,
  Artifact Registry Scanning, and GKE Node Versions.
  ```
- `BSIG_30_NR = 5`
- `BSIG_30_TEXT` (wörtlich, identisch zu AWS/Azure): "§30 Abs. 2 Nr. 5 BSIG — Sicherheitsmaßnahmen bei Erwerb, Entwicklung und Wartung von informationstechnischen Systemen, Komponenten und Prozessen, einschließlich Management und Offenlegung von Schwachstellen"
- Keine weiteren Modul-Konstanten.

---

## Checks

### AWS-NR5-001 — ECR Image Scanning

Klassen-Docstring (wörtlich): "Check that ECR repositories have scan-on-push enabled."

| Feld | Wert |
|---|---|
| Klasse | `CheckEcrImageScanning` |
| description | "Prüft ob ECR-Repositories automatisches Image-Scanning bei Push aktiviert haben." |
| severity | HIGH (Mangel-Pfad, inline im `Finding()`-Aufruf, kein Klassenattribut) |
| iso27001_control | `ISO_CONTROL` = "A.8.8 Management of technical vulnerabilities" (identisch in Positiv- und Mangel-Pfad) |
| required_permissions | `["ecr:DescribeRepositories"]` |
| pruefgrenzen | "Prüft nur, ob scanOnPush für ECR-Repositories aktiviert ist. Nicht geprüft werden Scan-Ergebnisse, deren Behebung und Container-Registries außerhalb von ECR." |
| Prüflogik (deskriptiv) | `ecr.describe_repositories()` (paginiert) je Region; Feld `imageScanningConfiguration.scanOnPush` jedes Repositories wird ausgelesen — `True` ergibt Positivnachweis, `False`/fehlend ergibt Mangel-Finding, je Repository. |

**Finding-Texte (Mangel-Pfad):**
- title: "ECR-Repository ohne automatisches Image-Scanning"
- description (Template, aus Teilstrings zusammengesetzt): "Das ECR-Repository '{repo_name}' hat kein automatisches Image-Scanning bei Push aktiviert. Ohne Scanning werden Schwachstellen in Container-Images nicht erkannt."
- expected_state: "ECR Image Scanning bei Push aktiviert (scanOnPush=true)"
- remediation: "Aktivieren Sie das automatische Image-Scanning: aws ecr put-image-scanning-configuration --repository-name <name> --image-scanning-configuration scanOnPush=true"
- remediation_effort: LOW
- audit_evidence (Template): `f"DescribeRepositories: scanOnPush=false for {repo_name}"`

**Positivnachweis (compliant_finding):**
- title: "ECR-Repository mit Image-Scanning"
- description (Template): `f"Das ECR-Repository '{repo_name}' hat automatisches Image-Scanning bei Push aktiviert."`
- expected_state: "ECR Image Scanning bei Push aktiviert (scanOnPush=true)"
- audit_evidence (Template): `f"DescribeRepositories: scanOnPush=true for {repo_name}"`

---

### AWS-NR5-002 — SSM Patch Management

Klassen-Docstring (wörtlich): "Check that EC2 instances are managed by SSM for patch management."

| Feld | Wert |
|---|---|
| Klasse | `CheckSsmPatchCompliance` |
| description | "Prüft ob EC2-Instanzen von AWS Systems Manager verwaltet werden und damit zentrales Patch-Management möglich ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL` = "A.8.8 Management of technical vulnerabilities" (identisch in beiden Pfaden) |
| required_permissions | `["ssm:DescribeInstanceInformation", "ec2:DescribeInstances"]` |
| pruefgrenzen | "Prüft nur, ob SSM Patch-Baselines/Patch-Gruppen konfiguriert sind. Nicht geprüft wird, ob Patches tatsächlich installiert werden und ob alle Instanzen von SSM verwaltet werden." |
| Prüflogik (deskriptiv) | `ec2.describe_instances()` (paginiert, gefiltert auf `instance-state-name=running`) ermittelt laufende Instanzen je Region; `ssm.describe_instance_information()` (paginiert) ermittelt SSM-verwaltete Instanzen; Mengendifferenz `running - managed` ergibt je Instanz ein Mangel-Finding, Schnittmenge `running ∩ managed` ergibt je Instanz einen Positivnachweis. |

**Finding-Texte (Mangel-Pfad):**
- title: "EC2-Instanz nicht von SSM verwaltet"
- description (Template, aus Teilstrings zusammengesetzt): "Die EC2-Instanz '{instance_id}' wird nicht von AWS Systems Manager verwaltet. Ohne SSM ist kein zentrales Patch-Management möglich."
- expected_state: "EC2-Instanz von SSM verwaltet mit SSM Agent aktiv"
- remediation: "Installieren und aktivieren Sie den SSM Agent auf der Instanz und stellen Sie sicher, dass die Instanz eine IAM-Rolle mit AmazonSSMManagedInstanceCore Policy hat."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribeInstanceInformation: {instance_id} not in SSM managed list"`

**Positivnachweis (compliant_finding):**
- title: "EC2-Instanz von SSM verwaltet"
- description (Template): `f"Die EC2-Instanz '{instance_id}' wird von AWS Systems Manager verwaltet — zentrales Patch-Management ist möglich."`
- expected_state: "EC2-Instanz von SSM verwaltet mit SSM Agent aktiv"
- audit_evidence (Template): `f"DescribeInstanceInformation: {instance_id} is SSM-managed"`

---

### AWS-NR5-003 — SSM Patch Manager Compliance

Klassen-Docstring (wörtlich): "Check that SSM Patch Manager has custom patch baselines configured."

| Feld | Wert |
|---|---|
| Klasse | `CheckSsmPatchManagerCompliance` |
| description | "Prüft ob AWS Systems Manager Patch Manager mit benutzerdefinierten Patch-Baselines konfiguriert ist." |
| severity | HIGH (beide Mangel-Pfade, inline) |
| iso27001_control | inline Literal "A.8.8, A.8.9" (nicht über `ISO_CONTROL`-Konstante; identisch in Positiv- und Mangel-Pfad je Teil-Prüfung) |
| required_permissions | `["ssm:DescribePatchBaselines", "ssm:DescribeInstancePatchStates"]` |
| pruefgrenzen | "Stützt sich auf die von SSM gemeldete Patch-Compliance. Instanzen ohne SSM-Agent oder ohne Patch-Gruppe erscheinen hier nicht — fehlende Abdeckung ist gesondert nachzuweisen." |
| Prüflogik (deskriptiv) | Zwei Teil-Prüfungen je Region unter derselben check_id: (1) `ssm.describe_patch_baselines(Filters=[{"Key":"OWNER","Values":["Self"]}])` — Vorhandensein ≥1 benutzerdefinierter Baseline ergibt ein aggregiertes Positiv-Finding je Region, keine Baseline ein aggregiertes Mangel-Finding je Region; (2) für alle über `ssm.describe_instance_information()` ermittelten verwalteten Instanzen liefert `ssm.describe_instance_patch_states()` je Instanz `MissingCount`/`FailedCount` — beide `0` ergibt Positivnachweis je Instanz, sonst Mangel-Finding je Instanz. |

**Finding-Texte (Mangel-Pfad, Teil 1 — Baselines):**
- title: "Keine benutzerdefinierten Patch-Baselines konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "In der Region '{region}' sind keine benutzerdefinierten Patch-Baselines konfiguriert. Ohne individuelle Baselines werden nur AWS-Standardregeln angewendet."
- expected_state: "Mindestens eine benutzerdefinierte Patch-Baseline konfiguriert"
- remediation (Template, aus Teilstrings zusammengesetzt): "Erstellen Sie eine benutzerdefinierte Patch-Baseline: aws ssm create-patch-baseline --name <name> --operating-system <os> --approval-rules <rules>"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribePatchBaselines: no custom baselines in {region}"`

**Positivnachweis (compliant_finding, Teil 1 — Baselines):**
- title: "Benutzerdefinierte Patch-Baselines konfiguriert"
- description (Template): `f"In der Region '{region}' sind {len(custom_baselines)} benutzerdefinierte Patch-Baselines konfiguriert."`
- expected_state: "Mindestens eine benutzerdefinierte Patch-Baseline konfiguriert"
- audit_evidence (Template): `f"DescribePatchBaselines: {len(custom_baselines)} custom baseline(s) in {region}"`

**Finding-Texte (Mangel-Pfad, Teil 2 — Patch-Status je Instanz):**
- title: "Instanz mit fehlenden oder fehlgeschlagenen Patches"
- description (Template, aus Teilstrings zusammengesetzt): "Die Instanz '{instance_id}' hat {missing} fehlende und {failed} fehlgeschlagene Patches."
- expected_state: "Alle Patches erfolgreich installiert (MissingCount=0, FailedCount=0)"
- remediation (Template, aus Teilstrings zusammengesetzt): "Führen Sie ausstehende Patches aus: aws ssm send-command --document-name AWS-RunPatchBaseline --instance-ids <id>"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribeInstancePatchStates: {instance_id} missing={missing}, failed={failed}"`

**Positivnachweis (compliant_finding, Teil 2 — Patch-Status je Instanz):**
- title: "Instanz vollständig gepatcht"
- description (Template): `f"Die Instanz '{instance_id}' hat keine fehlenden oder fehlgeschlagenen Patches."`
- expected_state: "Alle Patches erfolgreich installiert (MissingCount=0, FailedCount=0)"
- audit_evidence (Template): `f"DescribeInstancePatchStates: {instance_id} missing=0, failed=0"`

---

### AWS-NR5-004 — Lambda Runtime-Versionen

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckLambdaRuntimeDeprecation` |
| description | "Prüft ob Lambda-Funktionen aktuelle, nicht-veraltete Laufzeitumgebungen verwenden." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL` = "A.8.8 Management of technical vulnerabilities" (identisch in beiden Pfaden) |
| required_permissions | `["lambda:ListFunctions"]` |
| pruefgrenzen | "Prüft nur Lambda-Runtimes gegen eine im Tool gepflegte Liste veralteter Versionen. Neue Deprecations nach Mapping-Stand werden erst mit einem Tool-Update erkannt; Anwendungsabhängigkeiten werden nicht geprüft." |
| Klassenkonstante `DEPRECATED_RUNTIMES` (wörtlich) | `{"python2.7", "python3.6", "python3.7", "python3.8", "nodejs10.x", "nodejs12.x", "nodejs14.x", "nodejs16.x", "dotnetcore2.1", "dotnetcore3.1", "dotnet6", "ruby2.5", "ruby2.7", "java8", "go1.x"}` |
| Prüflogik (deskriptiv) | `lambda.list_functions()` (paginiert) je Region; Feld `Runtime` jeder Funktion wird gegen `DEPRECATED_RUNTIMES` geprüft — Runtime vorhanden und nicht in der Liste ergibt Positivnachweis, Runtime in der Liste ergibt Mangel-Finding, je Funktion. |

**Finding-Texte (Mangel-Pfad):**
- title: "Lambda-Funktion mit veralteter Runtime"
- description (Template, aus Teilstrings zusammengesetzt): "Die Lambda-Funktion '{func_name}' verwendet die veraltete Runtime '{runtime}'. Veraltete Runtimes erhalten keine Sicherheitsupdates mehr."
- expected_state: "Aktuelle, unterstützte Lambda Runtime-Version"
- remediation (Template, aus Teilstrings zusammengesetzt): "Aktualisieren Sie die Lambda Runtime: aws lambda update-function-configuration --function-name <name> --runtime <new-runtime>"
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"ListFunctions: {func_name} uses deprecated runtime '{runtime}'"`

**Positivnachweis (compliant_finding):**
- title: "Lambda-Funktion mit aktueller Runtime"
- description (Template): `f"Die Lambda-Funktion '{func_name}' verwendet die unterstützte Runtime '{runtime}'."`
- expected_state: "Aktuelle, unterstützte Lambda Runtime-Version"
- audit_evidence (Template): `f"ListFunctions: {func_name} uses supported runtime '{runtime}'"`

---

### AWS-NR5-005 — AMI-Alter für Produktionsinstanzen

Klassen-Docstring (wörtlich): "Check that EC2 instances use AMIs younger than 90 days.\n\nInstances running old AMIs may contain unpatched vulnerabilities and outdated software that poses security risks."

| Feld | Wert |
|---|---|
| Klasse | `CheckAmiAge` |
| description | "Prüft ob EC2-Instanzen AMIs verwenden, die nicht älter als 90 Tage sind, um sicherzustellen, dass die Betriebsumgebung regelmäßig aktualisiert wird." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | `ISO_CONTROL` = "A.8.8 Management of technical vulnerabilities" (identisch in beiden Pfaden) |
| required_permissions | `["ec2:DescribeInstances", "ec2:DescribeImages"]` |
| pruefgrenzen | "Bewertet nur das Erstellungsdatum der AMIs laufender Instanzen als Indiz. Ein altes AMI kann durch Laufzeit-Patching aktuell sein — der tatsächliche Patchstand der Instanz wird hier nicht geprüft (siehe SSM-Checks)." |
| Klassenkonstante | `MAX_AMI_AGE_DAYS = 90` |
| Prüflogik (deskriptiv) | `ec2.describe_instances()` (paginiert, gefiltert auf `running`) ermittelt AMI-IDs laufender Instanzen je Region; `ec2.describe_images()` liefert `CreationDate` je AMI; Alter in Tagen (`now - creation_date`) wird gegen `MAX_AMI_AGE_DAYS` (90) verglichen — `<= 90` ergibt Positivnachweis, `> 90` ergibt Mangel-Finding, je Instanz (mehrere Instanzen können dasselbe AMI referenzieren). |

**Finding-Texte (Mangel-Pfad):**
- title: "EC2-Instanz mit veraltetem AMI"
- description (Template, aus Teilstrings zusammengesetzt): "Die EC2-Instanz '{instance_id}' verwendet ein AMI, das {age_days} Tage alt ist. AMIs sollten nicht älter als {self.MAX_AMI_AGE_DAYS} Tage sein."
- expected_state (Template): `f"AMI-Alter < {self.MAX_AMI_AGE_DAYS} Tage"`
- remediation: "Aktualisieren Sie das AMI der Instanz: 1. Erstellen Sie ein neues AMI mit aktuellen Patches. 2. Starten Sie die Instanz mit dem neuen AMI. Nutzen Sie EC2 Image Builder für automatisierte AMI-Erstellung."
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"DescribeImages: AMI {ami_id} created {age_days} days ago for {instance_id}"`

**Positivnachweis (compliant_finding):**
- title: "EC2-Instanz mit aktuellem AMI"
- description (Template, aus Teilstrings zusammengesetzt): "Die EC2-Instanz '{instance_id}' verwendet ein AMI, das {age_days} Tage alt ist (Maximum: {self.MAX_AMI_AGE_DAYS} Tage)."
- expected_state (Template): `f"AMI-Alter < {self.MAX_AMI_AGE_DAYS} Tage"`
- audit_evidence (Template): `f"DescribeImages: AMI {ami_id} created {age_days} days ago for {instance_id}"` (identisches Template wie im Mangel-Pfad)

---

### AZ-NR5-001 — Defender for Cloud — Vulnerability Assessment

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckDefenderVulnAssessment` |
| description | "Prüft ob Defender for Cloud Schwachstellenbewertung aktiviert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.8 Management technischer Schwachstellen" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Security/pricings/read", "Microsoft.Security/autoProvisioningSettings/read"]` |
| pruefgrenzen | "Prüft nur, ob Vulnerability Assessment in Defender aktiviert ist. Scan-Ergebnisse und deren Behebung werden nicht bewertet." |
| Prüflogik (deskriptiv) | `SecurityCenter.pricings.list()` je Subscription; das Element mit `name == "VirtualMachines"` wird gesucht; `pricing_tier != "Free"` (und Plan vorhanden) ergibt ein aggregiertes Positiv-Finding je Subscription, sonst (kein Plan oder `pricing_tier == "Free"`) ein aggregiertes Mangel-Finding je Subscription. |

**Finding-Texte (Mangel-Pfad):**
- title: "Defender Vulnerability Assessment nicht aktiviert"
- description (Template, aus Teilstrings zusammengesetzt): "Subscription {sub_id} hat Defender for Servers nicht aktiviert. Ohne Vulnerability Assessment werden Schwachstellen in VMs nicht automatisch erkannt."
- expected_state: "Defender for Servers (Standard-Tier) mit Vulnerability Assessment"
- remediation: "Aktivieren Sie Defender for Servers: az security pricing create --name VirtualMachines --tier Standard"
- remediation_effort: LOW
- audit_evidence (Template): `f"pricings.list(): VirtualMachines plan tier={vm_plan.pricing_tier if vm_plan else 'missing'}"`

**Positivnachweis (compliant_finding):**
- title: "Defender Vulnerability Assessment aktiviert"
- description (Template, aus Teilstrings zusammengesetzt): "Subscription {sub_id} hat Defender for Servers ({vm_plan.pricing_tier}-Tier) aktiviert — Schwachstellen in VMs werden automatisch erkannt."
- expected_state: "Defender for Servers (Standard-Tier) mit Vulnerability Assessment"
- audit_evidence (Template): `f"pricings.list(): VirtualMachines plan tier={vm_plan.pricing_tier}"`

---

### AZ-NR5-002 — Update Management Center konfiguriert

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckUpdateManagement` |
| description | "Prüft ob Azure Update Management Center für Patch-Management konfiguriert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.8, A.8.9 Management technischer Schwachstellen" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Maintenance/maintenanceConfigurations/read"]` |
| pruefgrenzen | "Prüft nur die Patch-Einstellungen der VMs (Update Management). Ob Patches tatsächlich zeitnah installiert werden, wird nicht verifiziert." |
| Prüflogik (deskriptiv) | `ResourceManagementClient.resources.list(filter="resourceType eq 'Microsoft.Maintenance/maintenanceConfigurations'")` je Subscription; Vorhandensein ≥1 Ressource dieses Typs ergibt ein aggregiertes Positiv-Finding je Subscription, keine Ressource ein aggregiertes Mangel-Finding je Subscription. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein Update Management konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Subscription {sub_id} hat keine Maintenance-Konfigurationen. Ohne Update Management werden Sicherheitspatches nicht systematisch eingespielt."
- expected_state: "Mindestens eine Maintenance-Konfiguration für Patch-Management"
- remediation: "Konfigurieren Sie Update Management Center im Azure Portal oder via CLI: az maintenance configuration create --resource-group <rg> --name <config-name> --maintenance-scope InGuestPatch"
- remediation_effort: MEDIUM
- audit_evidence: "resources.list() returned 0 maintenanceConfigurations" (Literal, kein f-String)

**Positivnachweis (compliant_finding):**
- title: "Update Management konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Subscription {sub_id} hat {len(maintenance_configs)} Maintenance-Konfiguration(en) für systematisches Patch-Management."
- expected_state: "Mindestens eine Maintenance-Konfiguration für Patch-Management"
- audit_evidence (Template): `f"resources.list() returned {len(maintenance_configs)} maintenanceConfigurations"`

---

### AZ-NR5-003 — Container Registry Image Scan

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckContainerRegistryScan` |
| description | "Prüft ob Azure Container Registry Schwachstellen-Scans für Images aktiviert hat." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.8 Management technischer Schwachstellen" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.ContainerRegistry/registries/read"]` |
| pruefgrenzen | "Prüft nur, ob Defender für Container Registries aktiviert ist. Registries außerhalb von ACR werden nicht erfasst." |
| Prüflogik (deskriptiv) | `ContainerRegistryManagementClient.registries.list()` je Subscription; Feld `sku.name` jeder Registry wird ausgelesen — `"Premium"` oder `"Standard"` ergibt Positivnachweis, jeder andere Wert (u. a. `"Basic"`, `"Unknown"`) ergibt Mangel-Finding, je Registry. |

**Finding-Texte (Mangel-Pfad):**
- title: "Container Registry ohne Image-Scanning"
- description (Template): `f"Container Registry {registry.name} in Subscription {sub_id} verwendet SKU {sku_name}. Für vollständige Schwachstellen-Scans wird mindestens Standard-SKU benötigt."`
- expected_state: "Container Registry mit Standard- oder Premium-SKU und Image-Scanning"
- remediation (Template): `"Upgraden Sie die Registry-SKU: " + f"az acr update --name {registry.name} --sku Standard"`
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"registries.list(): {registry.name} sku={sku_name}"`

**Positivnachweis (compliant_finding):**
- title: "Container Registry mit Scan-fähiger SKU"
- description (Template): `f"Container Registry {registry.name} verwendet SKU {sku_name} — Schwachstellen-Scans für Images sind möglich."`
- expected_state: "Container Registry mit Standard- oder Premium-SKU und Image-Scanning"
- audit_evidence (Template): `f"registries.list(): {registry.name} sku={sku_name}"` (identisches Template wie im Mangel-Pfad)

---

### AZ-NR5-004 — App Service Runtime aktuell

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckAppServiceRuntime` |
| description | "Prüft ob App Service Laufzeitumgebungen aktuell sind." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.8 Management technischer Schwachstellen" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Web/sites/read", "Microsoft.Web/sites/config/read"]` |
| pruefgrenzen | "Prüft App-Service-Runtimes gegen eine im Tool gepflegte Liste veralteter Versionen — neue Deprecations erfordern ein Tool-Update." |
| Prüflogik (deskriptiv) | `WebSiteManagementClient.web_apps.list()` je Subscription; bei Linux-Apps wird `site_config.linux_fx_version` (Format `RUNTIME|VERSION`) gegen `OUTDATED_RUNTIMES[RUNTIME]` per `str.startswith` geprüft; bei .NET-Apps wird `site_config.net_framework_version` gegen feste Präfixe `("v2.", "v3.", "v4.0", "v4.5", "v4.6", "v4.7")` per `str.startswith` geprüft. Ist eine Runtime identifizierbar und nicht als veraltet erkannt → Positivnachweis; ist sie als veraltet erkannt → Mangel-Finding. Ist keine Runtime identifizierbar (kein `site_config`, kein `linux_fx_version` und kein `net_framework_version`, oder `linux_fx_version` nicht im Format `RUNTIME|VERSION`), wird weder ein Positiv- noch ein Mangel-Finding erzeugt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Veraltete App Service Runtime"
- description (Template): `f"App Service {app.name} in Subscription {sub_id} verwendet veraltete Runtime {runtime_info}."`
- expected_state: "Aktuelle, unterstützte Laufzeitversion"
- remediation (Template): `f"Aktualisieren Sie die Runtime für {app.name}: " + "az webapp config set --linux-fx-version '<RUNTIME>|<VERSION>' " + f"--name {app.name} --resource-group <rg>"`
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"web_apps.list(): {app.name} runtime={runtime_info}"`

**Positivnachweis (compliant_finding):**
- title: "App Service Runtime aktuell"
- description (Template): `f"App Service {app.name} verwendet die aktuelle Runtime {runtime_info}."`
- expected_state: "Aktuelle, unterstützte Laufzeitversion"
- audit_evidence (Template): `f"web_apps.list(): {app.name} runtime={runtime_info}"` (identisches Template wie im Mangel-Pfad)

---

### AZ-NR5-005 — SQL Vulnerability Assessment aktiviert

(kein Klassen-Docstring)

| Feld | Wert |
|---|---|
| Klasse | `CheckSqlVulnAssessment` |
| description | "Prüft ob SQL Server Vulnerability Assessment für automatische Schwachstellenerkennung aktiviert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.8 Management technischer Schwachstellen" (identisch in beiden Pfaden) |
| required_permissions | `["Microsoft.Sql/servers/read", "Microsoft.Sql/servers/vulnerabilityAssessments/read"]` |
| pruefgrenzen | "Prüft nur, ob SQL Vulnerability Assessment aktiviert ist. Befunde und deren Behebung werden nicht bewertet." |
| Prüflogik (deskriptiv) | `SqlManagementClient.servers.list()` je Subscription; je Server wird die Resource-Group aus `server.id` extrahiert und `server_vulnerability_assessments.list_by_server(rg_name, server.name)` aufgerufen — nicht-leere Liste ergibt Positivnachweis, leere Liste ergibt Mangel-Finding, je Server. Wirft der innere `list_by_server`-Aufruf eine Exception, wird für diesen Server weder ein Finding noch ein `CheckError` erzeugt (siehe Auffälligkeiten). |

**Finding-Texte (Mangel-Pfad):**
- title: "SQL Vulnerability Assessment nicht aktiviert"
- description (Template): `f"SQL Server {server.name} in Subscription {sub_id} hat Vulnerability Assessment nicht aktiviert."`
- expected_state: "Vulnerability Assessment aktiviert mit periodischen Scans"
- remediation (Template): `"Aktivieren Sie Vulnerability Assessment: " + f"az sql server va-setting update --resource-group {rg_name} " + f"--server-name {server.name} --storage-account <storage>"`
- remediation_effort: MEDIUM
- audit_evidence (Template): `f"server_vulnerability_assessments.list_by_server(): 0 assessments for {server.name}"`

**Positivnachweis (compliant_finding):**
- title: "SQL Vulnerability Assessment aktiviert"
- description (Template): `f"SQL Server {server.name} hat Vulnerability Assessment aktiviert."`
- expected_state: "Vulnerability Assessment aktiviert mit periodischen Scans"
- audit_evidence (Template): `f"server_vulnerability_assessments.list_by_server(): {len(va_list)} assessment(s) for {server.name}"`

---

### GCP-NR5-001 — Container Analysis aktiviert

Klassen-Docstring (wörtlich): "Prüft ob Container Analysis / Artifact Analysis aktiviert ist."

| Feld | Wert |
|---|---|
| Klasse | `CheckContainerAnalysis` |
| description | "Prüft ob Container Analysis (Artifact Analysis) für die automatische Schwachstellenerkennung in Container-Images aktiviert ist." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.8 Management technischer Schwachstellen" (identisch in beiden Pfaden) |
| required_permissions | `["containeranalysis.occurrences.list"]` |
| pruefgrenzen | "Prüft nur, ob die Container-Analysis-API aktiviert ist. Scan-Ergebnisse und deren Behebung werden nicht bewertet." |
| Prüflogik (deskriptiv) | `containeranalysis`-API v1: `projects().occurrences().list(parent=..., filter='kind="VULNERABILITY"', pageSize=1)` je Projekt; mindestens ein Treffer ergibt ein aggregiertes Positiv-Finding je Projekt, kein Treffer ein aggregiertes Mangel-Finding je Projekt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Container Analysis nicht aktiv"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keine Container Analysis Schwachstellenberichte. Entweder ist die API nicht aktiviert oder es werden keine Container-Images gescannt."
- expected_state: "Container Analysis aktiviert mit automatischem Schwachstellenscan für Container-Images"
- remediation (Template, aus Teilstrings zusammengesetzt): "Aktivieren Sie die Container Analysis API: gcloud services enable containeranalysis.googleapis.com --project=<PROJECT_ID>. Aktivieren Sie automatisches Scanning in Artifact Registry."
- remediation_effort: LOW
- audit_evidence: "occurrences.list(kind=VULNERABILITY) returned 0 results" (Literal, kein f-String)

**Positivnachweis (compliant_finding):**
- title: "Container Analysis aktiv"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat Container Analysis Schwachstellenberichte — Images werden gescannt."
- expected_state: "Container Analysis aktiviert mit automatischem Schwachstellenscan für Container-Images"
- audit_evidence: "occurrences.list(kind=VULNERABILITY) returned >=1 result" (Literal, kein f-String)

---

### GCP-NR5-002 — OS Config Patch-Management konfiguriert

Klassen-Docstring (wörtlich): "Prüft ob OS Config Patch-Deployments konfiguriert sind."

| Feld | Wert |
|---|---|
| Klasse | `CheckOsConfigPatchManagement` |
| description | "Prüft ob OS Config Patch-Deployments für die automatische Aktualisierung von VM-Instanzen konfiguriert sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.8, A.8.9 Management technischer Schwachstellen" (identisch in beiden Pfaden) |
| required_permissions | `["osconfig.patchDeployments.list"]` |
| pruefgrenzen | "Prüft nur, ob OS-Config-Patch-Deployments existieren. Ob Patches tatsächlich zeitnah installiert werden, wird nicht verifiziert." |
| Prüflogik (deskriptiv) | `osconfig`-API v1: `projects().patchDeployments().list(parent=...)` je Projekt; Vorhandensein ≥1 Deployment ergibt ein aggregiertes Positiv-Finding je Projekt, kein Deployment ein aggregiertes Mangel-Finding je Projekt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein automatisches Patch-Management"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keine OS Config Patch-Deployments. Ohne automatisches Patch-Management bleiben Schwachstellen in VM-Betriebssystemen unbehoben."
- expected_state: "Mindestens ein Patch-Deployment für die regelmäßige Aktualisierung von VMs"
- remediation (Template, aus Teilstrings zusammengesetzt): "Erstellen Sie ein Patch-Deployment: gcloud compute os-config patch-deployments create <NAME> --project=<PROJECT_ID> --instance-filter-all --recurring-schedule-frequency=weekly --recurring-schedule-day-of-week=SUNDAY --recurring-schedule-time-of-day='02:00'"
- remediation_effort: MEDIUM
- audit_evidence: "patchDeployments.list() returned 0 deployments" (Literal, kein f-String)

**Positivnachweis (compliant_finding):**
- title: "Automatisches Patch-Management konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat {len(deployments)} OS Config Patch-Deployment(s) für die automatische VM-Aktualisierung."
- expected_state: "Mindestens ein Patch-Deployment für die regelmäßige Aktualisierung von VMs"
- audit_evidence (Template): `f"patchDeployments.list() returned {len(deployments)} deployment(s)"`

---

### GCP-NR5-003 — Web Security Scanner konfiguriert

Klassen-Docstring (wörtlich): "Prüft ob Web Security Scanner Konfigurationen existieren."

| Feld | Wert |
|---|---|
| Klasse | `CheckWebSecurityScanner` |
| description | "Prüft ob Web Security Scanner für die automatische Schwachstellenerkennung in Webanwendungen konfiguriert ist." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.8 Management technischer Schwachstellen" (identisch in beiden Pfaden) |
| required_permissions | `["websecurityscanner.scanconfigs.list"]` |
| pruefgrenzen | "Prüft nur, ob Web-Security-Scanner-Konfigurationen existieren. Nur für App-Engine-/Compute-Web-Workloads relevant; Scan-Ergebnisse werden nicht bewertet." |
| Prüflogik (deskriptiv) | `websecurityscanner`-API v1: `projects().scanConfigs().list(parent=...)` je Projekt; Vorhandensein ≥1 Scan-Konfiguration ergibt ein aggregiertes Positiv-Finding je Projekt, keine Konfiguration ein aggregiertes Mangel-Finding je Projekt — unabhängig davon, ob das Projekt überhaupt App-Engine-/Compute-Web-Workloads betreibt. |

**Finding-Texte (Mangel-Pfad):**
- title: "Kein Web Security Scanner konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keine Web Security Scanner Konfigurationen. Ohne automatisches Scanning werden Schwachstellen in Webanwendungen nicht erkannt."
- expected_state: "Mindestens eine Web Security Scanner Konfiguration für Webanwendungen"
- remediation (Template, aus Teilstrings zusammengesetzt): "Erstellen Sie eine Scan-Konfiguration: gcloud alpha web-security-scanner scan-configs create --display-name='Webapp Scan' --starting-urls='https://app.example.com' --project=<PROJECT_ID>"
- remediation_effort: LOW
- audit_evidence: "scanConfigs.list() returned 0 configs" (Literal, kein f-String)

**Positivnachweis (compliant_finding):**
- title: "Web Security Scanner konfiguriert"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat {len(scan_configs)} Web Security Scanner Konfiguration(en) für Webanwendungs-Scans."
- expected_state: "Mindestens eine Web Security Scanner Konfiguration für Webanwendungen"
- audit_evidence (Template): `f"scanConfigs.list() returned {len(scan_configs)} config(s)"`

---

### GCP-NR5-004 — Artifact Registry Repositories vorhanden

Klassen-Docstring (wörtlich): "Prüft ob Artifact Registry Repositories mit Scanning existieren."

| Feld | Wert |
|---|---|
| Klasse | `CheckArtifactRegistryScanning` |
| description | "Prüft ob Artifact Registry Repositories für die zentrale Verwaltung und das Scanning von Artefakten konfiguriert sind." |
| severity | HIGH (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.8 Management technischer Schwachstellen" (identisch in beiden Pfaden) |
| required_permissions | `["artifactregistry.repositories.list"]` |
| pruefgrenzen | "Prüft nur die Nutzung von Artifact Registry (statt veralteter Container Registry). Die Sicherheit der abgelegten Artefakte wird nicht bewertet." |
| Prüflogik (deskriptiv) | `artifactregistry`-API v1: `projects().locations().repositories().list(parent="projects/{project_id}/locations/-")` je Projekt; Vorhandensein ≥1 Repository ergibt ein aggregiertes Positiv-Finding je Projekt, kein Repository ein aggregiertes Mangel-Finding je Projekt. Es wird nur die Existenz eines Repositories geprüft, keine Scanning-Konfiguration einzelner Repositories. |

**Finding-Texte (Mangel-Pfad):**
- title: "Keine Artifact Registry Repositories"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat keine Artifact Registry Repositories. Ohne zentrale Artefaktverwaltung fehlt die Kontrolle über verwendete Container-Images und Pakete."
- expected_state: "Mindestens ein Artifact Registry Repository mit aktiviertem Vulnerability Scanning"
- remediation (Template, aus Teilstrings zusammengesetzt): "Erstellen Sie ein Artifact Registry Repository: gcloud artifacts repositories create <NAME> --repository-format=docker --location=europe-west3 --project=<PROJECT_ID>. Aktivieren Sie Container Analysis für automatisches Scanning."
- remediation_effort: LOW
- audit_evidence: "repositories.list() returned 0 repositories" (Literal, kein f-String)

**Positivnachweis (compliant_finding):**
- title: "Artifact Registry Repositories vorhanden"
- description (Template, aus Teilstrings zusammengesetzt): "Projekt {project_id} hat {len(repositories)} Artifact Registry Repository/Repositories für zentrale Artefaktverwaltung."
- expected_state: "Mindestens ein Artifact Registry Repository mit aktiviertem Vulnerability Scanning"
- audit_evidence (Template): `f"repositories.list() returned {len(repositories)} repositories"`

---

### GCP-NR5-005 — GKE Node-Versionen aktuell

Klassen-Docstring (wörtlich): "Prüft ob GKE-Cluster und Nodes aktuelle Versionen verwenden."

| Feld | Wert |
|---|---|
| Klasse | `CheckGkeNodeVersions` |
| description | "Prüft ob GKE-Cluster Node-Versionen verwenden, die nicht älter als die Master-Version sind, um bekannte Schwachstellen zu vermeiden." |
| severity | MEDIUM (Mangel-Pfad, inline) |
| iso27001_control | inline Literal "A.8.8 Management technischer Schwachstellen" (identisch in beiden Pfaden) |
| required_permissions | `["container.clusters.list"]` |
| pruefgrenzen | "Prüft GKE-Node-Versionen gegen die Master-Version. Projekte ohne GKE liefern kein Ergebnis (Nicht anwendbar)." |
| Prüflogik (deskriptiv) | `container_v1.ClusterManagerClient.list_clusters(parent="projects/{project_id}/locations/-")` je Projekt; je Cluster werden `current_master_version` und `current_node_version` als Strings mit den Python-Operatoren `>=`/`<` lexikografisch verglichen — `node_version >= master_version` ergibt Positivnachweis, `node_version < master_version` ergibt Mangel-Finding, je Cluster. Fehlt eine der beiden Versionsangaben, wird weder ein Positiv- noch ein Mangel-Finding erzeugt. |

**Finding-Texte (Mangel-Pfad):**
- title: "GKE Node-Version veraltet"
- description (Template, aus Teilstrings zusammengesetzt): "GKE-Cluster {cluster.name} in Projekt {project_id} hat eine Node-Version die älter als die Master-Version ist. Veraltete Node-Versionen können bekannte Schwachstellen enthalten."
- expected_state: "Node-Version entspricht mindestens der Master-Version des Clusters"
- remediation (Template, aus Teilstrings zusammengesetzt): "Aktualisieren Sie die Node-Version: gcloud container clusters upgrade <CLUSTER_NAME> --node-pool=default-pool --cluster-version=<MASTER_VERSION> --zone=<ZONE> --project=<PROJECT_ID>"
- remediation_effort: MEDIUM
- audit_evidence (Template, aus Teilstrings zusammengesetzt): "list_clusters() cluster {cluster.name} master={master_version} node={node_version}"

**Positivnachweis (compliant_finding):**
- title: "GKE Node-Version aktuell"
- description (Template): `f"GKE-Cluster {cluster.name} in Projekt {project_id} hat eine aktuelle Node-Version ({node_version})."`
- expected_state: "Node-Version entspricht mindestens der Master-Version des Clusters"
- audit_evidence (Template, aus Teilstrings zusammengesetzt): "list_clusters() cluster {cluster.name} master={master_version} node={node_version}" (identisches Template wie im Mangel-Pfad)

---

## Mechanische Auffälligkeiten (ohne Bewertung)

1. Keine der 15 Check-Klassen definiert ein Klassenattribut `severity` (abweichend vom Muster im Repo-`CLAUDE.md`) — severity wird stattdessen pro `Finding()`-Aufruf im Mangel-Pfad als Parameter gesetzt (innerhalb desselben Checks jeweils konsistent).
2. Keine der 15 Check-Klassen definiert ein Klassenattribut `iso_27001_ref` — `iso27001_control` wird stattdessen pro `Finding()`/`compliant_finding()`-Aufruf als Parameter übergeben. Innerhalb jedes einzelnen Checks ist der Text zwischen Positiv- und Mangel-Pfad jeweils identisch (Ausnahme: AWS-NR5-003, siehe Punkt 5).
3. Nur das AWS-Modul definiert eine wiederverwendbare Modulkonstante für den ISO-Text (`ISO_CONTROL = "A.8.8 Management of technical vulnerabilities"`, englisch), verwendet sie aber nicht in allen eigenen Checks (siehe Punkt 5). Azure und GCP definieren keine entsprechende Modulkonstante und wiederholen stattdessen den deutschsprachigen Text "A.8.8 Management technischer Schwachstellen" (bzw. bei AZ-NR5-002/GCP-NR5-002: "A.8.8, A.8.9 Management technischer Schwachstellen") als String-Literal an jeder Aufrufstelle.
4. Für dieselbe ISO-27001-Kontrollnummer A.8.8 verwenden AWS (bis auf AWS-NR5-003) und Azure/GCP unterschiedliche Sprache: AWS "Management of technical vulnerabilities" (Englisch) vs. Azure/GCP "Management technischer Schwachstellen" (Deutsch), obwohl laut CLAUDE.md sämtlicher Report-Text auf Deutsch sein soll.
5. AWS-NR5-003 (`CheckSsmPatchManagerCompliance`) verwendet als einziger AWS-Nr.-5-Check nicht die Modulkonstante `ISO_CONTROL`, sondern das inline-Literal "A.8.8, A.8.9" (ohne Beschreibungstext) — abweichend von den übrigen vier AWS-Checks in derselben Datei, die durchgängig `ISO_CONTROL` referenzieren.
6. Die Klassenreihenfolge in der AWS-Moduldatei entspricht nicht der aufsteigenden Check-ID-Reihenfolge: Datei-Reihenfolge ist 001 (EcrImageScanning), 002 (SsmPatchCompliance), 004 (LambdaRuntimeDeprecation), 005 (AmiAge), 003 (SsmPatchManagerCompliance) — AWS-NR5-003 steht am Dateiende statt an dritter Stelle. Azure- und GCP-Module sind numerisch aufsteigend (001–005) geordnet.
7. AWS-NR5-002 (`CheckSsmPatchCompliance`) trägt die pruefgrenzen-Angabe "Prüft nur, ob SSM Patch-Baselines/Patch-Gruppen konfiguriert sind. Nicht geprüft wird, ob Patches tatsächlich installiert werden und ob alle Instanzen von SSM verwaltet werden." Der tatsächliche Code des Checks ruft jedoch weder `describe_patch_baselines` noch etwas zu Patch-Gruppen auf; er vergleicht ausschließlich laufende EC2-Instanzen gegen SSM-verwaltete Instanzen und meldet nicht verwaltete Instanzen als Mangel — also exakt das, was der Text als "nicht geprüft" bezeichnet ("ob alle Instanzen von SSM verwaltet werden"). Patch-Baselines werden stattdessen im separaten Check AWS-NR5-003 geprüft, dessen eigene pruefgrenzen-Angabe ("Stützt sich auf die von SSM gemeldete Patch-Compliance...") inhaltlich eher zu AWS-NR5-002 passen würde als die dort hinterlegte.
8. AWS-NR5-003 deklariert `required_permissions = ["ssm:DescribePatchBaselines", "ssm:DescribeInstancePatchStates"]`, der Code ruft jedoch zusätzlich `ssm.get_paginator("describe_instance_information")` auf (zur Ermittlung der verwalteten Instanzen für die Patch-Status-Abfrage) — die dafür nötige Permission `ssm:DescribeInstanceInformation` ist in `required_permissions` dieses Checks nicht gelistet (sie ist nur bei AWS-NR5-002 deklariert).
9. AWS-NR5-003 erzeugt unter derselben check_id zwei inhaltlich unterschiedliche Paare von Positiv-/Mangel-Findings (Patch-Baselines je Region vs. Patch-Status je Instanz) mit unterschiedlichem `expected_state`-Text ("Mindestens eine benutzerdefinierte Patch-Baseline konfiguriert" vs. "Alle Patches erfolgreich installiert (MissingCount=0, FailedCount=0)") und unterschiedlicher `resource_type`/`resource_id`-Struktur (aggregierte Baseline-ARN mit Wildcard `patchbaseline/*` vs. einzelne Instance-ID).
10. AWS-NR5-004 (`CheckLambdaRuntimeDeprecation`) behandelt im `if`/`elif` nur die Fälle "Runtime gesetzt und nicht in `DEPRECATED_RUNTIMES`" sowie "Runtime in `DEPRECATED_RUNTIMES`"; eine leere/fehlende `Runtime` (z. B. bei bestimmten Lambda-Paketierungsarten) erzeugt weder ein Positiv- noch ein Mangel-Finding und wird auch nicht als `CheckError` erfasst.
11. AWS-NR5-005 (`CheckAmiAge`) fängt Fehler beim `describe_images`-Aufruf mit einem bloßen `except Exception: images = []` ab, ohne einen `CheckError` anzulegen; betroffene Instanzen erscheinen dadurch stillschweigend in keinem Finding. Ebenso werden nicht auflösbare AMI-Erstellungsdaten mit `except (ValueError, TypeError): continue` übersprungen, ebenfalls ohne `CheckError`.
12. AWS-NR5-005 verwendet für Positiv- und Mangel-Pfad exakt dasselbe `audit_evidence`-Template (`f"DescribeImages: AMI {ami_id} created {age_days} days ago for {instance_id}"`); ebenso AZ-NR5-003, AZ-NR5-004 und GCP-NR5-005 (jeweils identisches Template in beiden Pfaden).
13. `current_state` bei AWS-NR5-002 (`{"ssm_managed": ..., "instance_name": instance_id}`) und AWS-NR5-005 (`{..., "instance_name": instance_id}`) führt den Schlüssel `instance_name`, dessen Wert jedoch die technische `instance_id` ist, nicht ein benutzerdefinierter Name — beide Suffixe (`_name`, `_id`) stehen laut CLAUDE.md/ADR-0011 zwar gleichermaßen auf der Pseudonymisierungs-Deny-List, die Feldbezeichnung ist inhaltlich dennoch ungenau.
14. AZ-NR5-001 deklariert `required_permissions = ["Microsoft.Security/pricings/read", "Microsoft.Security/autoProvisioningSettings/read"]`; der Code ruft ausschließlich `security_client.pricings.list()` auf. `Microsoft.Security/autoProvisioningSettings/read` wird im Checkcode nicht verwendet (deklarierte, aber ungenutzte Permission).
15. AZ-NR5-002 deklariert die spezifische Permission `Microsoft.Maintenance/maintenanceConfigurations/read`, der Code ruft jedoch die generische `ResourceManagementClient.resources.list()`-API mit einem `resourceType`-Filter auf — ob die deklarierte, ressourcentyp-spezifische Permission für diesen generischen Listenaufruf technisch ausreicht bzw. die tatsächlich benötigte Permission korrekt wiedergibt, ist aus dem Code allein nicht zu bestimmen.
16. AZ-NR5-002 prüft ausschließlich die Existenz von Ressourcen des Typs `Microsoft.Maintenance/maintenanceConfigurations` in der Subscription; ob eine gefundene Konfiguration tatsächlich einen `maintenanceScope` wie `InGuestPatch` hat oder überhaupt VMs zugeordnet ist, wird nicht geprüft — der Check-Titel "Update Management Center konfiguriert" und `expected_state` ("Mindestens eine Maintenance-Konfiguration für Patch-Management") suggerieren dagegen aktive Nutzung für Patch-Management.
17. AZ-NR5-003 (`CheckContainerRegistryScan`) prüft ausschließlich die SKU-Stufe (`Premium`/`Standard`) der Container Registry; ob ein Scanning-Dienst (z. B. Microsoft Defender for Containers) für die Registry tatsächlich aktiviert/verknüpft ist, wird im Code nicht abgefragt. Check-Titel ("Container Registry Image Scan"), description ("Schwachstellen-Scans für Images aktiviert") und `expected_state` ("...und Image-Scanning") sprechen dagegen von aktivem Scanning.
18. AZ-NR5-004 (`CheckAppServiceRuntime`) markiert eine .NET-Framework-Version nur dann als veraltet, wenn sie mit einem der festen Präfixe `"v2.", "v3.", "v4.0", "v4.5", "v4.6", "v4.7"` beginnt; Versionen außerhalb dieser Liste (z. B. `"v4.8"` oder unbekannte künftige Werte) werden implizit als nicht veraltet (`is_outdated = False`) behandelt, da die Variable mit `False` initialisiert und nur bei Match auf `True` gesetzt wird.
19. AZ-NR5-004 erzeugt für eine App ohne identifizierbare Runtime (kein `site_config`, oder `linux_fx_version` nicht im Format `RUNTIME|VERSION`, oder weder `linux_fx_version` noch `net_framework_version` gesetzt) weder ein Positiv- noch ein Mangel-Finding und keinen `CheckError` — die App erscheint im Scan-Ergebnis für diesen Check nicht.
20. AZ-NR5-005 (`CheckSqlVulnAssessment`) fängt Exceptions beim Aufruf von `server_vulnerability_assessments.list_by_server()` je Server mit `except Exception: pass` ab — ohne `CheckError`-Eintrag und ohne Finding (weder Positiv- noch Mangel-Pfad) für den betroffenen Server; ein Server, für den die API-Abfrage fehlschlägt, taucht im Scan-Ergebnis für diesen Check gar nicht auf.
21. GCP-NR5-001 (`CheckContainerAnalysis`) kann strukturell nicht zwischen drei unterschiedlichen Ursachen für "keine VULNERABILITY-Occurrences" unterscheiden: (a) Container-Analysis-API nicht aktiviert, (b) API aktiviert, aber keine Container-Images vorhanden/gescannt, (c) API aktiviert, Images gescannt, aber keine Schwachstellen gefunden (sauberer Zustand). Alle drei Fälle führen zum selben Mangel-Finding mit severity HIGH; die description benennt selbst nur die ersten beiden Ursachen ("Entweder ist die API nicht aktiviert oder es werden keine Container-Images gescannt"), nicht den dritten (sauberer Scan-Befund).
22. GCP-NR5-003 (`CheckWebSecurityScanner`) erzeugt für jedes Projekt ohne Scan-Konfiguration ein Mangel-Finding, unabhängig davon, ob das Projekt überhaupt App-Engine-/Compute-Web-Workloads betreibt — die eigene pruefgrenzen-Angabe weist zwar darauf hin, dass der Check "Nur für App-Engine-/Compute-Web-Workloads relevant" sei, der Code selbst enthält aber keine Bedingung, die ein Projekt ohne solche Workloads als "nicht anwendbar" ausschließt oder anders behandelt.
23. GCP-NR5-004 (`CheckArtifactRegistryScanning`) prüft ausschließlich die Existenz mindestens eines Artifact-Registry-Repositories; ob für ein gefundenes Repository tatsächlich Vulnerability Scanning (Container Analysis) aktiviert ist, wird nicht abgefragt. `expected_state` behauptet dagegen "Mindestens ein Artifact Registry Repository mit aktiviertem Vulnerability Scanning" — die pruefgrenzen-Angabe des Checks selbst schränkt dies korrekt ein ("Die Sicherheit der abgelegten Artefakte wird nicht bewertet").
24. GCP-NR5-005 (`CheckGkeNodeVersions`) vergleicht `current_master_version` und `current_node_version` mittels der Python-String-Operatoren `>=`/`<` (lexikografischer Stringvergleich), nicht mittels semantischer Versionsvergleichslogik. Bei GKE-Versionsstrings unterschiedlicher Ziffernlänge in einzelnen Komponenten (z. B. einstellige vs. zweistellige Patch-/Build-Nummern) kann ein lexikografischer Vergleich zu einer anderen Ordnung führen als ein semantischer Versionsvergleich.
25. `CheckError()`-Aufrufe unterscheiden sich zwischen Providern: AWS und GCP übergeben nur `message` und `error_type`; Azure übergibt zusätzlich `check_id` und `region="global"` — dasselbe Muster wie in den bereits vorliegenden Nr.-1- und Nr.-3-Dossiers vermerkt.
26. Klassendocstrings sind sprachlich uneinheitlich: die AWS-Klassen `CheckEcrImageScanning` und `CheckSsmPatchCompliance` sowie `CheckSsmPatchManagerCompliance` haben englische Docstrings ("Check that..."), `CheckLambdaRuntimeDeprecation` (004) hat gar keinen Klassen-Docstring; keine der fünf Azure-Klassen hat einen Klassen-Docstring; alle fünf GCP-Klassen haben deutsche Docstrings ("Prüft ob...") — dasselbe Sprachmuster (Englisch/keiner/Deutsch je Provider) wie in den bereits vorliegenden Nr.-1- und Nr.-3-Dossiers vermerkt.
27. Granularität der Findings ist zwischen den Providern uneinheitlich: AWS erzeugt bei NR5-001, -002, -004, -005 je ein Finding pro Einzelressource (Repository/Instanz/Funktion), bei NR5-003 teils aggregiert je Region (Baselines) und teils je Einzelinstanz (Patch-Status); Azure erzeugt bei AZ-NR5-001 und AZ-NR5-002 je ein aggregiertes Finding pro Subscription, bei AZ-NR5-003, -004, -005 je ein Finding pro Einzelressource; GCP erzeugt bei allen fünf Checks (GCP-NR5-001 bis -005) je ein aggregiertes Finding pro Projekt — mit Ausnahme von GCP-NR5-005, das je Einzel-Cluster ein Finding erzeugt.
