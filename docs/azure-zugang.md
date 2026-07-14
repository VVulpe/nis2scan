# Azure-Zugang für nis2scan

nis2scan ist **read-only** und speichert **keine Kunden-Secrets**. Für
unbeaufsichtigte Azure-Scans gilt das etablierte SaaS-Muster: eine
**Multi-Tenant-App-Registrierung** des Scanners, der der Kunde einmalig per
**Admin-Consent** Reader-Rechte erteilt.

## Warum dieses Muster

- **Kein geteiltes Secret beim Kunden:** Der Client-Secret der App gehört dem
  Scanner-Betreiber (Env: `NIS2SCAN_AZURE_CLIENT_ID` / `NIS2SCAN_AZURE_CLIENT_SECRET`)
  und liegt nie beim Kunden.
- **Kunde speichert nichts Geheimes bei uns:** Wir merken uns nur seine
  **Tenant-ID** und die **Subscription-IDs** — keine Credentials.
- **Widerrufbar:** Der Kunde entzieht den Zugang jederzeit, indem er die
  App/Enterprise-Application in seinem Entra ID entfernt.

## Einrichtung

### Einmalig beim Scanner-Betreiber

1. In Entra ID eine **App-Registrierung** anlegen, **multi-tenant**
   („Accounts in any organizational directory").
2. Ein **Client-Secret** erzeugen und als
   `NIS2SCAN_AZURE_CLIENT_ID` / `NIS2SCAN_AZURE_CLIENT_SECRET` beim SaaS-Worker
   (bzw. für die CLI in der Umgebung) hinterlegen.
3. Die benötigten Rollen-/Graph-Berechtigungen dokumentieren
   (`nis2scan permissions --provider azure` — ARM-Rolle „Reader" plus die
   separat via App-Registrierung zu erteilenden Microsoft-Graph-Application-
   Permissions; siehe ADR-0020: Graph ist **nicht** per RBAC vergebbar).

### Pro Kunde (durch den Kunden-Admin)

1. **Admin-Consent** erteilen (Portal-Link:
   `https://login.microsoftonline.com/<TENANT_ID>/adminconsent?client_id=<APP_ID>`).
   Das legt im Kunden-Tenant eine **Enterprise-Application** (Service Principal)
   für die nis2scan-App an.
2. Dem Service Principal die Rolle **Reader** auf den zu scannenden
   **Subscriptions** (oder einer Management Group) zuweisen. Für die Checks, die
   Entra-ID-/Graph-Daten lesen (z. B. MFA-Status, Conditional Access), die
   entsprechenden Graph-Application-Permissions mit Admin-Consent freigeben.
3. Im nis2scan-SaaS unter **Einstellungen › Cloud-Zugänge** einen Azure-Zugang
   verbinden: **Tenant-ID** + **Subscription-IDs**.

## Ablauf beim Scan

- SaaS: Der Tenant wählt beim „Neuer Scan" den Azure-Cloud-Zugang. Der Worker
  authentifiziert die Scanner-App gegen den **Kunden-Tenant**
  (`ClientSecretCredential(tenant_id=<Kunde>, client_id=<App>, secret=<App>)`)
  und scannt die hinterlegten Subscriptions.
- CLI (Betreiber-seitig, unbeaufsichtigt): App-Credentials als Env-Variablen
  setzen, dann implizit über `DefaultAzureCredential` **oder** — für den
  Cross-Tenant-Fall — die SaaS-Wiring-Felder nutzen. Für interaktive Einzelscans
  genügt `az login` (DefaultAzureCredential greift automatisch).

## Grenzen (ehrlich)

- **GCP** nutzt weiterhin Application Default Credentials / Workload Identity
  Federation; ein per-Tenant-GCP-Zugang analog zu AWS/Azure ist noch offen.
- Graph-Berechtigungen sind mächtig — Least Privilege einhalten und nur die
  von den Checks tatsächlich benötigten Application-Permissions freigeben.
