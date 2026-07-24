# GCP-Zugang für nis2scan

nis2scan ist **read-only** und speichert keine Kunden-Secrets. Der Scanner
authentifiziert sich über die Standard-Google-Mechanismen (Application
Default Credentials, kurz ADC) und unterscheidet nicht zwischen "eigenem" und
"fremdem" Projekt: Zugriff hat, wer der verwendeten Identität in der Google
Cloud IAM die passenden Rollen zuweist.

## Überblick

| Betriebsart | Empfohlener Zugang | Warum |
|---|---|---|
| Interaktiver Scan durch einen Menschen (CLI) | Application Default Credentials über `gcloud auth application-default login` | Login über den vorhandenen Google-Account inkl. der dort geltenden Organisationsrichtlinien; keine dauerhaften Schlüssel auf der Platte |
| Unbeaufsichtigter Scan (Server, Scheduled Scan) | Service Account mit minimaler Rolle | Kein Mensch im Loop; Rechte lassen sich exakt auf die Checks zuschneiden |
| CI/CD (GitHub Actions) | Workload Identity Federation | Keine Service-Account-Schlüssel als Secret hinterlegt |

Die minimale Read-Only-Rolle erzeugt der Permissions-Generator:

```bash
python -m nis2scan permissions --provider gcp --format terraform > nis2scan-gcp-role.tf
# oder als Liste:
python -m nis2scan permissions --provider gcp --format list
```

Volle Liste aller GCP-Rollen und -Permissions je Check: [docs/permissions.md](permissions.md).

---

## Weg A: Application Default Credentials (interaktiv)

Für lokale Scans reicht ein normaler Google-Login, keine Service-Account-
Einrichtung nötig:

```bash
gcloud auth application-default login
python -m nis2scan scan --provider gcp
```

`gcloud` legt die Credentials unter `~/.config/gcloud/application_default_credentials.json`
ab (Windows: `%APPDATA%\gcloud\...`); die Google-Auth-Bibliothek in nis2scan
findet sie dort automatisch, ohne dass eine Umgebungsvariable gesetzt werden
muss.

## Weg B: Service Account mit minimaler Rolle (unbeaufsichtigt)

1. **Service Account anlegen:**

   ```bash
   gcloud iam service-accounts create nis2scan-scanner \
     --display-name="nis2scan Scanner"
   ```

2. **Minimale Rollen zuweisen** (Ausgabe des Permissions-Generators von oben,
   oder manuell die in [docs/permissions.md](permissions.md#gcp) gelistete
   Rollen-Tabelle):

   ```bash
   PROJECT_ID="ihr-projekt-id"
   SA_EMAIL="nis2scan-scanner@${PROJECT_ID}.iam.gserviceaccount.com"

   for ROLE in roles/viewer roles/securitycenter.sourcesViewer \
     roles/iam.securityReviewer roles/monitoring.viewer \
     roles/logging.viewer roles/compute.viewer \
     roles/container.clusterViewer; do
     gcloud projects add-iam-policy-binding "$PROJECT_ID" \
       --member="serviceAccount:${SA_EMAIL}" \
       --role="$ROLE"
   done
   ```

3. **Zugangsdaten erzeugen und referenzieren:**

   ```bash
   gcloud iam service-accounts keys create nis2scan-key.json \
     --iam-account="$SA_EMAIL"

   export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/nis2scan-key.json"
   python -m nis2scan scan --provider gcp
   ```

   Statt eines langlebigen Schlüssels ist auf einer GCE-VM oder in Cloud Run
   auch **Workload Identity** bzw. die angehängte Service-Account-Identität
   der Instanz nutzbar; dann entfällt Schritt 3 komplett, ADC greift
   automatisch auf die Metadaten der Instanz zu.

## Weg C: Workload Identity Federation (CI/CD)

Für GitHub Actions ohne dauerhafte Service-Account-Schlüssel: Terraform unter
[infra/gcp/oidc/main.tf](../infra/gcp/oidc/main.tf) legt einen Workload
Identity Pool samt GitHub-OIDC-Provider und Service Account an.

```bash
cd infra/gcp/oidc
terraform init
terraform apply -var="project_id=ihr-projekt-id" -var="github_repo=ihre-org/ihr-repo"
```

Die Outputs als GitHub-Secrets hinterlegen:
- `GCP_PROJECT_ID`
- `GCP_WORKLOAD_IDENTITY_PROVIDER` (Output `workload_identity_provider`)
- `GCP_SERVICE_ACCOUNT` (Output `service_account_email`)

Im Workflow übernimmt `google-github-actions/auth@v2` die Anmeldung:

```yaml
permissions:
  id-token: write
  contents: read

steps:
  - uses: google-github-actions/auth@v2
    with:
      workload_identity_provider: ${{ secrets.GCP_WORKLOAD_IDENTITY_PROVIDER }}
      service_account: ${{ secrets.GCP_SERVICE_ACCOUNT }}
  - run: python -m nis2scan scan --provider gcp
```

Die restlichen Schritte des Beispiel-Workflows [.github/workflows/integration-tests-gcp.yml](../.github/workflows/integration-tests-gcp.yml)
zeigen das vollständige Muster (inkl. Aufräumen der Testinfrastruktur).

---

## Projektübergreifendes Scannen

nis2scan kann mit einer einzigen Credential-Quelle mehrere GCP-Projekte in
einem Lauf scannen. Die Projekt-Auswahl (`GcpSession` in
[nis2scan/engine/providers/gcp/session.py](../nis2scan/engine/providers/gcp/session.py))
funktioniert in dieser Reihenfolge:

1. **Explizite Liste:** Ist in der Konfigurationsdatei `gcp.accounts` gesetzt,
   scannt nis2scan genau diese Projekt-IDs, unabhängig davon, was die
   Credentials sonst noch sehen könnten.

   ```yaml
   scan:
     providers:
       gcp:
         enabled: true
         accounts: ["projekt-a", "projekt-b"]
   ```

2. **ADC-Default-Projekt:** Ist `gcp.accounts` leer, aber die Credentials
   selbst tragen ein Default-Projekt (z. B. über `gcloud config set project`
   oder die Umgebungsvariable `GOOGLE_CLOUD_PROJECT` gesetzt), scannt
   nis2scan genau dieses eine Projekt.

3. **Automatische Erkennung:** Ist beides leer, fragt nis2scan über die
   Cloud Resource Manager API (`cloudresourcemanager.googleapis.com`,
   `ProjectsClient.search_projects`) **alle aktiven Projekte ab, die die
   verwendete Identität sehen kann**, und scannt sie alle in einem Lauf.

Für ein bewusst eingegrenztes, vorhersagbares Scan-Ergebnis empfiehlt sich
daher, `gcp.accounts` in der Konfigurationsdatei explizit zu setzen, statt
sich auf die automatische Erkennung zu verlassen: eine Service-Account-
Identität mit Viewer-Rolle auf Ordner- oder Organisationsebene würde sonst
beim nächsten Scan automatisch auch neu hinzugekommene Projekte mit
einschließen.

Innerhalb eines Scans bleibt das erste Element der aufgelösten Projektliste
das "primäre" Projekt (`GcpSession.project_id`); die restlichen Projekte
werden je Check über den optionalen `project_id`-Parameter von
`GcpSession.client()` bzw. `GcpSession.service()` adressiert.
