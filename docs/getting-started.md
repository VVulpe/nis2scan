# Getting Started with nis2scan

Comprehensive guide to install, configure, and run nis2scan against your AWS,
Azure, or GCP environment.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [AWS Setup](#aws-setup)
5. [Azure Setup](#azure-setup)
6. [GCP Setup](#gcp-setup)
7. [Running a Scan](#running-a-scan)
8. [Understanding Results](#understanding-results)
9. [CLI Reference](#cli-reference)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

- **Python 3.12 or later** (3.13 also supported)
- **Cloud credentials** for at least one provider (AWS, Azure, or GCP)
- **Read-only access** — nis2scan never modifies your cloud resources

### Verify Python version

```bash
python3 --version   # Must be 3.12+
```

---

## Installation

### From PyPI (recommended)

```bash
pip install nis2scan
```

> **Windows:** Installation requires long-path support (the Microsoft Graph SDK
> ships files whose paths exceed the classic 260-character limit). Enable it
> once as administrator, then reboot:
>
> ```powershell
> Set-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" -Name LongPathsEnabled -Value 1
> ```
>
> Without it, `pip install nis2scan` fails with `OSError: [Errno 2] No such
> file or directory: ...msgraph\generated\...`. Alternatively install inside
> WSL, where the limit does not exist.

### From source (development)

```bash
git clone https://github.com/VVulpe/nis2scan.git
cd nis2scan
pip install -e ".[dev]"
```

### Verify installation

```bash
nis2scan --version
# nis2scan v0.1.0
```

---

## Configuration

### Quick start (CLI only)

No config file needed — use CLI flags:

```bash
nis2scan scan --provider aws --region eu-central-1
```

### Config file (recommended for production)

Copy and customize the default config:

```bash
cp config/default.yaml config/my-company.yaml
```

Edit `config/my-company.yaml`:

```yaml
company:
  name: "Ihre GmbH"
  sector: "manufacturing"        # Your industry sector
  nis2_category: "important"     # "important" or "essential"

scan:
  providers:
    aws:
      enabled: true
      # profile: "nis2scan-readonly"  # AWS CLI profile (optional)
      regions:
        - "eu-central-1"
        - "eu-west-1"
    azure:
      enabled: false
      # subscription_ids: ["your-subscription-id"]
    gcp:
      enabled: false
      # accounts: ["your-project-id"]

  bsig_30_scope: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]

output:
  formats:
    - json
    - markdown
  output_dir: "./reports"
  include_evidence: true
```

Run with config file:

```bash
nis2scan scan --config config/my-company.yaml
```

---

## AWS Setup

### Step 1: Create a read-only IAM user or role

**Option A: IAM User (simplest for local scans)**

```bash
# Create user
aws iam create-user --user-name nis2scan-readonly

# Attach ViewOnlyAccess managed policy
aws iam attach-user-policy \
  --user-name nis2scan-readonly \
  --policy-arn arn:aws:iam::aws:policy/job-function/ViewOnlyAccess

# Create access key
aws iam create-access-key --user-name nis2scan-readonly
```

**Option B: IAM Role with minimal permissions (recommended)**

Generate the exact permissions nis2scan needs:

```bash
nis2scan permissions --provider aws --format terraform > nis2scan-policy.tf
```

Or see [docs/permissions.md](permissions.md) for the full list of 70+ read-only
IAM actions grouped by service.

### Step 2: Configure credentials

```bash
# Option 1: AWS CLI profile
aws configure --profile nis2scan-readonly
# Enter the access key ID and secret from Step 1

# Option 2: Environment variables
export AWS_ACCESS_KEY_ID=AKIA...
export AWS_SECRET_ACCESS_KEY=...
export AWS_DEFAULT_REGION=eu-central-1

# Option 3: IAM role (if running on EC2/ECS/Lambda)
# No setup needed — uses instance metadata automatically
```

### Step 3: Run the scan

```bash
# With profile
nis2scan scan --provider aws --profile nis2scan-readonly --region eu-central-1

# With default credentials
nis2scan scan --provider aws --region eu-central-1

# Multiple regions
nis2scan scan --provider aws --region eu-central-1 --region eu-west-1

# Specific §30 areas only
nis2scan scan --provider aws --scope 8 --scope 9 --scope 10
```

### AWS permissions summary

nis2scan needs **read-only** access to these services:

| Service | Purpose |
|---------|---------|
| STS | Account identity |
| S3, EC2, RDS, KMS | Encryption & backup checks (NR3, NR8) |
| IAM | Access control & MFA checks (NR9, NR10) |
| GuardDuty, Security Hub | Risk analysis & incident response (NR1, NR2) |
| CloudTrail, Config | Audit logging & compliance (NR1, NR6) |
| CloudWatch, Lambda, ECR | Monitoring & vulnerability checks (NR2, NR5) |
| Organizations, RAM | Supply chain checks (NR4) |

Full permission details: [docs/permissions.md](permissions.md)

---

## Azure Setup

### Step 1: Create a service principal

```bash
# Create SP with Reader role on your subscription
az ad sp create-for-rbac \
  --name "nis2scan-scanner" \
  --role "Reader" \
  --scopes "/subscriptions/YOUR_SUBSCRIPTION_ID"
```

Save the output — you'll need `appId`, `password`, and `tenant`.

### Step 2: Grant Graph API permissions (for identity checks)

Some checks (NR4, NR7, NR9, NR10) need Microsoft Graph API access for
Entra ID (Azure AD) data:

```bash
APP_ID="your-app-id-from-step-1"

# Add Graph API permissions
az ad app permission add --id $APP_ID \
  --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
    e1fe6dd8-ba31-4d61-89e7-88639da4683d=Role \
    246dd0d5-5bd0-4def-940b-0421030a5b68=Role \
    230c1aed-a721-4c5d-9cb4-a90514e508ef=Role \
    9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role

# Grant admin consent (requires Global Admin)
az ad app permission admin-consent --id $APP_ID
```

These permissions are:
- `User.Read.All` — Guest user and stale user checks
- `Policy.Read.All` — Conditional Access and MFA checks
- `RoleManagement.Read.Directory` — PIM checks
- `Application.Read.All` — Service principal audit

### Step 3: Configure credentials

```bash
# Option 1: Service principal (recommended for automation)
export AZURE_CLIENT_ID="your-app-id"
export AZURE_CLIENT_SECRET="your-password"
export AZURE_TENANT_ID="your-tenant-id"

# Option 2: Azure CLI (simplest for local scans)
az login
# nis2scan uses DefaultAzureCredential — picks up az login automatically

# Option 3: Managed Identity (on Azure VMs/App Service)
# No setup needed — uses managed identity automatically
```

### Step 4: Run the scan

```bash
# Auto-discovers subscriptions
nis2scan scan --provider azure

# Specific subscription (via config file)
# In config.yaml: azure.subscription_ids: ["your-sub-id"]
nis2scan scan --provider azure --config config/my-company.yaml
```

### Azure permissions summary

| Category | Permissions |
|----------|-------------|
| **ARM (38 permissions)** | Security, Storage, Compute, Network, SQL, KeyVault, Monitor, Web |
| **Graph API (4 permissions)** | User.Read.All, Policy.Read.All, RoleManagement.Read.Directory, Application.Read.All |

Full permission details: [docs/permissions.md](permissions.md)

---

## GCP Setup

### Step 1: Authenticate

```bash
# Option 1: User account (simplest for local scans)
gcloud auth application-default login

# Option 2: Service account (recommended for automation)
gcloud iam service-accounts create nis2scan-scanner \
  --display-name="nis2scan Scanner"

# Grant Viewer + security roles
PROJECT_ID="your-project-id"
SA_EMAIL="nis2scan-scanner@${PROJECT_ID}.iam.gserviceaccount.com"

for ROLE in roles/viewer roles/securitycenter.sourcesViewer \
  roles/iam.securityReviewer roles/monitoring.viewer \
  roles/logging.viewer roles/compute.viewer \
  roles/container.clusterViewer; do
  gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_EMAIL" \
    --role="$ROLE"
done

# Create and download key
gcloud iam service-accounts keys create nis2scan-key.json \
  --iam-account=$SA_EMAIL

export GOOGLE_APPLICATION_CREDENTIALS="$(pwd)/nis2scan-key.json"
```

### Step 2: Enable required APIs

```bash
gcloud services enable \
  securitycenter.googleapis.com \
  cloudresourcemanager.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  cloudkms.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  container.googleapis.com \
  cloudasset.googleapis.com \
  dns.googleapis.com \
  sqladmin.googleapis.com \
  iam.googleapis.com \
  orgpolicy.googleapis.com \
  essentialcontacts.googleapis.com \
  iap.googleapis.com \
  certificatemanager.googleapis.com
```

### Step 3: Run the scan

```bash
# Auto-discovers project from credentials
nis2scan scan --provider gcp

# Specific project (via config file)
# In config.yaml: gcp.accounts: ["your-project-id"]
nis2scan scan --provider gcp --config config/my-company.yaml
```

### GCP permissions summary

| Role | Purpose |
|------|---------|
| `roles/viewer` | General read access |
| `roles/securitycenter.sourcesViewer` | SCC checks (NR1, NR2, NR6) |
| `roles/iam.securityReviewer` | IAM audit (NR4, NR9) |
| `roles/monitoring.viewer` | Monitoring checks (NR2, NR6) |
| `roles/logging.viewer` | Logging checks (NR1, NR2, NR6) |
| `roles/compute.viewer` | Compute checks (NR3, NR8, NR9, NR10) |
| `roles/container.clusterViewer` | GKE checks (NR4, NR5) |

Full permission details: [docs/permissions.md](permissions.md)

---

## Running a Scan

### Basic usage

```bash
# AWS (default)
nis2scan scan --provider aws --region eu-central-1

# Azure
nis2scan scan --provider azure

# GCP
nis2scan scan --provider gcp
```

### Common options

```bash
# Multiple regions
nis2scan scan --provider aws --region eu-central-1 --region eu-west-1

# Specific §30 areas (e.g., only Cryptography + Access Control)
nis2scan scan --provider aws --scope 8 --scope 9

# JSON output only
nis2scan scan --provider aws --format json

# Custom output directory
nis2scan scan --provider aws --output /path/to/reports

# With config file
nis2scan scan --config config/my-company.yaml
```

### View required permissions

```bash
# List all permissions
nis2scan permissions --provider aws

# As Terraform IAM policy
nis2scan permissions --provider aws --format terraform

# As JSON
nis2scan permissions --provider azure --format json
```

---

## Understanding Results

### Exit codes

| Code | Meaning |
|------|---------|
| 0 | Compliant — no findings or only LOW/INFO |
| 1 | High severity findings found |
| 2 | Critical severity findings found |

### Output files

After a scan, reports are generated in the output directory (default: `./reports/`):

```
reports/
  nis2scan_report_20260322_143000.json     # Machine-readable
  nis2scan_report_20260322_143000.md       # Human-readable
```

### Compliance matrix

The console output shows a matrix of all 10 §30 BSIG areas:

```
                    §30 BSIG Compliance-Matrix
┌─────┬──────────────────────────────────┬───────┬──────────┬──────────┐
│ Nr. │ Bereich                          │ Score │ Findings │ Kritisch │
├─────┼──────────────────────────────────┼───────┼──────────┼──────────┤
│ 1   │ Risikoanalyse                    │  80%  │        1 │        - │
│ 2   │ Incident Response                │   0%  │        5 │        2 │
│ ...                                                                  │
```

### Finding severity levels

| Severity | Meaning | Action |
|----------|---------|--------|
| **CRITICAL** | Immediate legal compliance risk | Fix within 24-48h |
| **HIGH** | Significant gap in §30 requirements | Fix within 1-2 weeks |
| **MEDIUM** | Best-practice deviation | Plan for next quarter |
| **LOW** | Minor improvement opportunity | Backlog |
| **INFO** | Informational only | No action needed |

### Finding structure

Each finding includes:
- **Legal reference**: Exact §30 BSIG subsection
- **ISO 27001 control**: Mapped control from ISO 27001:2022
- **Current state**: What was found in your environment
- **Expected state**: What compliance requires
- **Remediation**: Specific CLI commands to fix the issue
- **Audit evidence**: API call details for auditor review

### GDPR compliance

Pseudonymization is an **export decision** (report profile), not a scan
setting. By default reports use the `intern` profile with full identifiers so
your team can locate and fix issues. When a report is shared externally
(auditors, authorities), export it with the `extern` profile — identifying
values (resource IDs, account IDs, usernames embedded in descriptions and
evidence) are replaced by keyed pseudonyms:

```bash
nis2scan scan --provider aws --report-profile extern
```

Set the `NIS2SCAN_SECRET` environment variable so pseudonyms are keyed
(HMAC-SHA256) and resistant to dictionary attacks; the same secret keeps
finding fingerprints stable across scans.

---

## CLI Reference

### `nis2scan scan`

Run a NIS2 compliance scan.

| Flag | Default | Description |
|------|---------|-------------|
| `--provider`, `-p` | `aws` | Cloud provider: `aws`, `azure`, or `gcp` |
| `--config`, `-c` | `config/default.yaml` | Config file path |
| `--region`, `-r` | `eu-central-1` | Cloud region(s) to scan (repeatable) |
| `--scope`, `-s` | `1-10` | §30 BSIG areas to check (repeatable) |
| `--profile` | None | AWS CLI profile name |
| `--format`, `-f` | `json,markdown` | Output formats: `json`, `markdown` (+ formats from installed plugins, e.g. `pdf`) |
| `--output`, `-o` | `./reports` | Output directory |
| `--report-profile` | `intern` | Export profile: `intern` (raw identifiers) or `extern` (pseudonymized) |

### `nis2scan permissions`

Show required cloud permissions.

| Flag | Default | Description |
|------|---------|-------------|
| `--provider`, `-p` | `aws` | Cloud provider |
| `--format`, `-f` | `list` | Output: `list`, `terraform`, `json` |

### Premium commands (plugin)

`nis2scan remediate`, `nis2scan monitor`, and the `nis2scan license` subcommands
are part of the proprietary `nis2scan-premium` plugin (Professional tier) and
appear automatically once the plugin is installed. This repository contains no
premium code — only the entry-point plugin loader (`nis2scan.plugins`).

---

## Troubleshooting

### `pip install` says "No matching distribution found for nis2scan"

Your default Python is older than 3.12 (check with `python --version`) — pip
then hides all nis2scan versions because of their `Requires-Python >=3.12`
marker. Install with a modern interpreter, e.g. on Windows:

```powershell
py -3.13 -m pip install nis2scan
```

### `pip install` fails on Windows with `OSError: [Errno 2] ...msgraph\generated\...`

Windows long-path support is disabled (the default). See
[Installation](#installation) for the one-time registry fix, or install
inside WSL.

### "No AWS/Azure/GCP credentials found"

Make sure you're authenticated:

```bash
# AWS
aws sts get-caller-identity

# Azure
az account show

# GCP
gcloud auth application-default print-access-token
```

### "Access Denied" or "Forbidden" errors

Some checks need specific permissions beyond basic `Viewer`/`ReadOnlyAccess`.
Generate the exact permission list:

```bash
nis2scan permissions --provider aws --format list
```

The scan continues even if individual checks fail due to missing permissions —
failed checks appear as errors in the report, not as findings.

### "Provider not enabled"

Make sure your config file enables the provider:

```yaml
scan:
  providers:
    aws:
      enabled: true
```

Or use the `--provider` CLI flag (which auto-enables the provider).

### High number of findings on first scan

This is normal. Most organizations have 50-100+ findings on their first scan.
Focus on:

1. **Critical** findings first (legal compliance risk)
2. **High** findings next (significant gaps)
3. Use `--scope` to focus on one §30 area at a time

### Scan takes too long

- Reduce scope: `--scope 1 --scope 2` (only scan specific areas)
- Reduce regions: `--region eu-central-1` (instead of all regions)
- Some APIs are slow (AWS Organizations, Azure Graph) — this is normal

### PDF export not working

PDF export is a PROFESSIONAL feature shipped in the `nis2scan-premium` plugin.
License customers install it from the private package index, then:

```bash
nis2scan license activate YOUR_KEY
nis2scan scan --provider aws --format pdf
```

---

## Next Steps

1. **Run your first scan** and review the report
2. **Fix critical findings** — these represent immediate legal compliance risk
3. **Create ISMS documentation** — nis2scan provides Level 4 evidence, but you
   need Level 1-3 policies (see [nis2scan.de/templates](https://nis2scan.de/templates))
4. **Set up CI/CD** — run scans automatically on every deployment
   (see [docs/permissions.md](permissions.md) for OIDC setup)
5. **Schedule regular scans** — NIS2 requires ongoing compliance, not one-time
