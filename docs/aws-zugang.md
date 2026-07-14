# AWS-Zugang für nis2scan

nis2scan ist **read-only** und speichert selbst keine Credentials. Es gibt zwei
Zugangswege — je nach Betriebsart.

## Überblick

| Betriebsart | Empfohlener Zugang | Warum |
|---|---|---|
| Interaktiver Scan durch einen Menschen (CLI) | AWS IAM Identity Center + Entra ID (SAML/OIDC), SSO-Profil | Login über den vorhandenen IdP inkl. MFA/Conditional Access; nur temporäre Credentials |
| Unbeaufsichtigter Scan (SaaS-Worker, Scheduled Scan, Multi-Account) | Cross-Account-IAM-Rolle mit ExternalId (STS AssumeRole) | Kein Mensch im Loop; keine dauerhaften Schlüssel; Confused-Deputy-Schutz |

Die minimale Read-Only-Policy erzeugt der Permissions-Generator:

```bash
nis2scan permissions --provider aws --format terraform > nis2scan-policy.tf
# oder als Liste:
nis2scan permissions --provider aws --format list
```

---

## Weg A: Entra ID als IdP über AWS IAM Identity Center (interaktiv)

Ziel: `aws sso login --profile nis2scan` öffnet den Entra-ID-Login (mit euren
Conditional-Access-/MFA-Policies); der Scan läuft mit temporären Credentials.

1. **Identity Center aktivieren** (AWS-Konsole → IAM Identity Center, eine Region
   als Identity-Center-Region wählen).
2. **Entra ID als externen IdP verbinden**
   (Identity Center → Settings → Identity source → *Change* → *External identity
   provider*). In Entra ID eine „AWS IAM Identity Center"-Enterprise-App anlegen,
   SAML-Metadaten beидseitig austauschen, optional SCIM-Provisioning aktivieren.
3. **Permission Set „nis2scan-readonly"** anlegen (Identity Center → Permission
   sets → Create). Inline-Policy = Ausgabe des Permissions-Generators (s. o.);
   Session-Dauer z. B. 1 h.
4. **Zuweisen**: Permission Set dem/den AWS-Konten für die Scan-Nutzer:innen
   (bzw. der aus Entra provisionierten Gruppe) zuweisen.
5. **Lokales SSO-Profil** in `~/.aws/config`:

   ```ini
   [profile nis2scan]
   sso_session = nis2scan-sso
   sso_account_id = 111122223333
   sso_role_name  = nis2scan-readonly
   region         = eu-central-1

   [sso-session nis2scan-sso]
   sso_start_url = https://<euer-portal>.awsapps.com/start
   sso_region    = eu-central-1
   sso_registration_scopes = sso:account:access
   ```

6. **Scannen**:

   ```bash
   aws sso login --profile nis2scan
   nis2scan scan --provider aws --profile nis2scan --region eu-central-1
   ```

> Hinweis: SAML/SSO ist ein **interaktiver** Flow (Browser-Login). Für
> unbeaufsichtigte Scans siehe Weg B.

---

## Weg B: Cross-Account-Rolle mit ExternalId (unbeaufsichtigt / SaaS)

Der Scanner (oder der SaaS-Worker) nimmt in jedem Zielkonto eine Read-Only-Rolle
per `sts:AssumeRole` an. In der Vertrauensrichtlinie steht eine **ExternalId**
(gemeinsames Geheimnis) als Confused-Deputy-Schutz — es werden **keine
dauerhaften Zugangsschlüssel** hinterlegt.

Terraform für das Zielkonto: siehe [infra/aws/roles/nis2scan-cross-account.tf](../infra/aws/roles/nis2scan-cross-account.tf).

**CLI:**

```bash
nis2scan scan --provider aws \
  --assume-role-arn arn:aws:iam::<ZIELKONTO>:role/nis2scan-readonly \
  --external-id <EXTERNAL_ID> \
  --region eu-central-1
```

**SaaS:** Der Tenant hinterlegt Rollen-ARN + ExternalId einmalig
(`POST /api/v1/cloud-accounts`, Provider `aws`). Die ExternalId wird
serverseitig gespeichert und **nie über die API zurückgegeben**; der Worker
nimmt beim Scan die Rolle an. Beim Anlegen eines Scans wird die
`cloud_account_id` referenziert — die Ableitung erfolgt genau wie oben.

### Sicherheitsgrundsätze

- Immer eine **eigene ExternalId je Tenant/Kunde** (nicht wiederverwenden).
- Die Rolle ist strikt read-only (Policy aus dem Generator); kein `iam:*`,
  kein Schreibrecht.
- Rollen-ARN und ExternalId sind **keine** Credentials — ohne die
  vertrauenswürdige Principal-Identität des Scanners nutzlos.
