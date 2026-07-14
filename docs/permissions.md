# Required Permissions

nis2scan requires read-only permissions to scan your cloud environment.
Below are the minimum permissions needed for each provider.

---

## AWS

### Scan Permissions (Read-Only)

The scanner needs these IAM permissions. The full Terraform definition is in
[`infra/aws/oidc/main.tf`](../infra/aws/oidc/main.tf) (policy `ci_scan_read`).

| Service | Actions | Used by |
|---------|---------|---------|
| **STS** | `sts:GetCallerIdentity` | Session bootstrap |
| **S3** | `s3:ListAllMyBuckets`, `s3:GetBucketEncryption`, `s3:GetBucketLocation`, `s3:GetAccountPublicAccessBlock`, `s3:GetBucketPolicy`, `s3:GetBucketVersioning`, `s3:GetBucketObjectLockConfiguration` | NR3, NR8, NR9 |
| **EC2** | `ec2:DescribeInstances`, `ec2:DescribeVolumes`, `ec2:DescribeSecurityGroups`, `ec2:GetSecurityGroupsForVpc`, `ec2:DescribeRegions`, `ec2:DescribeSnapshots`, `ec2:DescribeVpnGateways`, `ec2:DescribeClientVpnEndpoints` | NR5, NR8, NR9, NR10 |
| **RDS** | `rds:DescribeDBInstances` | NR3, NR8 |
| **KMS** | `kms:ListKeys`, `kms:DescribeKey`, `kms:GetKeyRotationStatus` | NR8 |
| **IAM** | `iam:ListUsers`, `iam:ListMFADevices`, `iam:ListAccessKeys`, `iam:GetLoginProfile`, `iam:GetAccountSummary`, `iam:GetAccountPasswordPolicy`, `iam:ListPolicies`, `iam:GetPolicy`, `iam:GetPolicyVersion`, `iam:GetAccessKeyLastUsed`, `iam:ListUserTags`, `iam:ListRoles`, `iam:GetRole` | NR4, NR9, NR10 |
| **ELB** | `elasticloadbalancing:DescribeLoadBalancers`, `elasticloadbalancing:DescribeListeners`, `elasticloadbalancing:DescribeSSLPolicies` | NR8 |
| **GuardDuty** | `guardduty:ListDetectors`, `guardduty:GetDetector` | NR1, NR2 |
| **CloudWatch** | `cloudwatch:DescribeAlarms` | NR2 |
| **CloudTrail** | `cloudtrail:DescribeTrails`, `cloudtrail:GetTrailStatus` | NR1, NR6 |
| **Config** | `config:DescribeConfigurationRecorders`, `config:DescribeConfigurationRecorderStatus`, `config:DescribeConfigRules`, `config:DescribeComplianceByConfigRule` | NR1, NR6 |
| **Security Hub** | `securityhub:DescribeHub`, `securityhub:GetFindings` | NR1, NR2, NR6 |
| **Lambda** | `lambda:ListFunctions`, `lambda:GetFunction` | NR5 |
| **CloudWatch Logs** | `logs:DescribeLogGroups` | NR6 |
| **ECR** | `ecr:DescribeRepositories` | NR5 |
| **SSM** | `ssm:DescribeInstanceInformation`, `ssm:DescribePatchBaselines`, `ssm:DescribeInstancePatchStates` | NR5 |
| **ACM** | `acm:ListCertificates`, `acm:DescribeCertificate` | NR8 |
| **Organizations** | `organizations:DescribeOrganization`, `organizations:ListPolicies` | NR1, NR4 |
| **SSM Incidents** | `ssm-incidents:ListResponsePlans` | NR2 |
| **Backup** | `backup:ListBackupPlans` | NR3 |
| **Detective** | `detective:ListGraphs` | NR2 |
| **Route 53** | `route53:ListHealthChecks` | NR3 |
| **RAM** | `ram:GetResourceShares` | NR4 |
| **SES/SNS** | `ses:GetAccount`, `sns:ListTopics`, `sns:GetTopicAttributes` | NR10 |
| **Support** | `support:DescribeTrustedAdvisorChecks` | NR4 |

### GitHub Actions OIDC Setup

The CI role uses OIDC federation (no static credentials). See
[`infra/aws/oidc/main.tf`](../infra/aws/oidc/main.tf) for the full setup:

```bash
cd infra/aws/oidc
terraform init
terraform apply -var="github_repo=<owner>/<repo>" -var="aws_account_id=<account_id>"
```

Store the output `ci_role_arn` as GitHub secret `AWS_CI_ROLE_ARN`.

---

## Azure

### Service Principal Permissions

The scanner requires a service principal (or managed identity) with **Reader**
role on the target subscriptions, plus the specific resource provider read
permissions listed below.

#### Azure Resource Manager Permissions

| Permission | Used by |
|-----------|---------|
| `Microsoft.Security/pricings/read` | NR1 (Defender for Cloud) |
| `Microsoft.Security/securityContacts/read` | NR2 (Alert Notifications) |
| `Microsoft.Security/autoProvisioningSettings/read` | NR5 (Vulnerability Assessment) |
| `Microsoft.Security/secureScores/read` | NR6 (Effectiveness) |
| `Microsoft.Authorization/policyAssignments/read` | NR1 (Policy Assignments) |
| `Microsoft.Authorization/classicAdministrators/read` | NR9 (Access Control) |
| `Microsoft.Management/managementGroups/read` | NR1 (Management Groups) |
| `Microsoft.OperationalInsights/workspaces/read` | NR1, NR2 (Log Analytics) |
| `Microsoft.Insights/actionGroups/read` | NR2 (Action Groups) |
| `Microsoft.Insights/diagnosticSettings/read` | NR6 (Diagnostics) |
| `Microsoft.AlertsManagement/actionRules/read` | NR2 (Alert Processing Rules) |
| `Microsoft.RecoveryServices/vaults/read` | NR3 (Backup Vaults) |
| `Microsoft.RecoveryServices/vaults/backupPolicies/read` | NR3 (Backup Policies) |
| `Microsoft.Storage/storageAccounts/read` | NR3, NR8, NR9 (Storage) |
| `Microsoft.Storage/storageAccounts/blobServices/containers/read` | NR3 (Immutable Blobs) |
| `Microsoft.Sql/servers/read` | NR3, NR5, NR8 (SQL) |
| `Microsoft.Sql/servers/databases/read` | NR3, NR8 (SQL Databases) |
| `Microsoft.Sql/servers/databases/backupShortTermRetentionPolicies/read` | NR3 (SQL Backup) |
| `Microsoft.Sql/servers/databases/transparentDataEncryption/read` | NR8 (SQL TDE) |
| `Microsoft.Sql/servers/vulnerabilityAssessments/read` | NR5 (SQL VA) |
| `Microsoft.Compute/virtualMachines/read` | NR3 (Availability Zones) |
| `Microsoft.Compute/disks/read` | NR8 (Disk Encryption) |
| `Microsoft.Network/networkSecurityGroups/read` | NR9 (NSG Rules) |
| `Microsoft.Network/privateEndpoints/read` | NR4 (Private Endpoints) |
| `Microsoft.Network/virtualNetworkGateways/read` | NR10 (VPN) |
| `Microsoft.Network/bastionHosts/read` | NR10 (Bastion) |
| `Microsoft.Network/frontDoors/read` | NR3 (Front Door) |
| `Microsoft.Network/trafficManagerProfiles/read` | NR3 (Traffic Manager) |
| `Microsoft.Network/applicationGateways/read` | NR8 (App Gateway TLS) |
| `Microsoft.KeyVault/vaults/read` | NR8 (Key Vault) |
| `Microsoft.ContainerRegistry/registries/read` | NR5 (ACR) |
| `Microsoft.Web/sites/read` | NR5, NR8 (App Service) |
| `Microsoft.Web/sites/config/read` | NR8 (App Service TLS) |
| `Microsoft.ManagedServices/registrationAssignments/read` | NR4 (Lighthouse) |
| `Microsoft.Maintenance/maintenanceConfigurations/read` | NR5 (Update Management) |
| `Microsoft.PolicyInsights/policyStates/queryResults/action` | NR6 (Policy Compliance) |

#### Microsoft Graph API Permissions (Application)

These are **Application permissions** on the Microsoft Graph API, required for
Entra ID (Azure AD) checks:

| Permission | Used by |
|-----------|---------|
| `User.Read.All` | NR4 (Guest Users), NR7 (Training), NR9 (Stale Users) |
| `Policy.Read.All` | NR7 (Conditional Access), NR10 (MFA) |
| `RoleManagement.Read.Directory` | NR9 (PIM) |
| `Application.Read.All` | NR4 (SP Credentials), NR9 (Stale SPs) |

### Service Principal Setup (Azure CLI)

```bash
# Create service principal with Reader role
az ad sp create-for-rbac \
  --name "nis2scan-scanner" \
  --role "Reader" \
  --scopes "/subscriptions/<SUBSCRIPTION_ID>"

# Grant Graph API permissions (requires Global Admin consent)
APP_ID=$(az ad sp list --display-name nis2scan-scanner --query '[0].appId' -o tsv)
az ad app permission add --id $APP_ID --api 00000003-0000-0000-c000-000000000000 \
  --api-permissions \
    e1fe6dd8-ba31-4d61-89e7-88639da4683d=Role \
    246dd0d5-5bd0-4def-940b-0421030a5b68=Role \
    230c1aed-a721-4c5d-9cb4-a90514e508ef=Role \
    9a5d68dd-52b0-4cc2-bd40-abcf44ac3a30=Role

# Admin consent
az ad app permission admin-consent --id $APP_ID
```

### GitHub Actions OIDC Setup (Azure)

For CI, use federated credentials instead of client secrets:

```bash
# Create federated credential for GitHub Actions
az ad app federated-credential create --id $APP_ID --parameters '{
  "name": "github-nis2scan",
  "issuer": "https://token.actions.githubusercontent.com",
  "subject": "repo:<owner>/<repo>:ref:refs/heads/main",
  "audiences": ["api://AzureADTokenExchange"]
}'
```

Store these as GitHub secrets:
- `AZURE_CLIENT_ID` — Application (client) ID
- `AZURE_TENANT_ID` — Directory (tenant) ID
- `AZURE_SUBSCRIPTION_ID` — Target subscription ID

---

## GCP

### Scan Permissions (Read-Only)

The scanner needs a service account with **Viewer** role plus these specific
permissions. The full Terraform definition is in
[`infra/gcp/oidc/main.tf`](../infra/gcp/oidc/main.tf).

| IAM Role | Used by |
|----------|---------|
| `roles/viewer` | All checks (general read access) |
| `roles/securitycenter.sourcesViewer` | NR1, NR2, NR6 (SCC) |
| `roles/iam.securityReviewer` | NR4, NR9 (IAM audit) |
| `roles/monitoring.viewer` | NR2, NR6 (Monitoring) |
| `roles/logging.viewer` | NR1, NR2, NR6 (Logging) |
| `roles/storage.objectViewer` | NR3, NR9 (GCS) |
| `roles/compute.viewer` | NR3, NR8, NR9, NR10 (Compute) |
| `roles/container.clusterViewer` | NR4, NR5 (GKE) |

#### Specific Permissions by Check

| Permission | Used by |
|-----------|---------|
| `securitycenter.sources.list` | NR1 (SCC enabled) |
| `securitycenter.notificationconfig.list` | NR2 (SCC notifications) |
| `securitycenter.findings.list` | NR6 (SHA findings) |
| `orgpolicy.policy.get` | NR1, NR7, NR9 (Org Policies) |
| `resourcemanager.projects.getIamPolicy` | NR1, NR4, NR9 (IAM audit) |
| `cloudasset.feeds.list` | NR1 (Asset Inventory) |
| `accesscontextmanager.accessPolicies.list` | NR1, NR4 (VPC SC) |
| `monitoring.alertPolicies.list` | NR2 (Alert Policies) |
| `monitoring.notificationChannels.list` | NR2 (Notification Channels) |
| `monitoring.dashboards.list` | NR6 (Dashboards) |
| `logging.logMetrics.list` | NR2 (Log-based alerts) |
| `logging.sinks.list` | NR2, NR6 (Log sinks) |
| `cloudsql.instances.list` | NR3, NR8 (Cloud SQL) |
| `storage.buckets.list` | NR3, NR9 (GCS) |
| `storage.buckets.get` | NR3 (GCS config) |
| `storage.buckets.getIamPolicy` | NR9 (Bucket ACLs) |
| `compute.instances.list` | NR3 (Multi-zone) |
| `compute.resourcePolicies.list` | NR3 (Snapshot schedules) |
| `compute.disks.list` | NR8 (Disk encryption) |
| `compute.sslPolicies.list` | NR8 (TLS policies) |
| `compute.firewalls.list` | NR9 (Firewall rules) |
| `compute.vpnGateways.list` | NR10 (VPN) |
| `compute.projects.get` | NR10 (OS Login 2FA) |
| `iam.serviceAccounts.list` | NR4, NR9 (SA hygiene) |
| `iam.serviceAccountKeys.list` | NR4, NR9 (SA keys) |
| `container.clusters.list` | NR4, NR5 (GKE) |
| `binaryauthorization.policy.get` | NR4 (Binary Auth) |
| `cloudkms.keyRings.list` | NR8 (KMS) |
| `cloudkms.cryptoKeys.list` | NR8 (KMS rotation) |
| `certificatemanager.certs.list` | NR8 (Cert expiry) |
| `recommender.iamPolicyRecommendations.list` | NR6, NR9 (IAM Recommender) |
| `essentialcontacts.contacts.list` | NR7 (Security contacts) |
| `iap.tunnelInstances.getIamPolicy` | NR9, NR10 (IAP) |
| `dns.managedZones.list` | NR3 (DNS) |
| `containeranalysis.occurrences.list` | NR5 (Container scanning) |
| `osconfig.patchDeployments.list` | NR5 (Patch mgmt) |
| `websecurityscanner.scanconfigs.list` | NR5 (Web scanner) |
| `artifactregistry.repositories.list` | NR5 (Artifact Registry) |

### Service Account Setup (gcloud CLI)

```bash
# Create service account
gcloud iam service-accounts create nis2scan-scanner \
  --display-name="nis2scan Scanner"

# Grant Viewer + security roles
for ROLE in roles/viewer roles/securitycenter.sourcesViewer \
  roles/iam.securityReviewer roles/monitoring.viewer \
  roles/logging.viewer roles/compute.viewer \
  roles/container.clusterViewer; do
  gcloud projects add-iam-policy-binding PROJECT_ID \
    --member="serviceAccount:nis2scan-scanner@PROJECT_ID.iam.gserviceaccount.com" \
    --role="$ROLE"
done

# Authenticate locally
gcloud auth activate-service-account \
  --key-file=path/to/key.json
```

### GitHub Actions OIDC Setup (GCP)

For CI, use Workload Identity Federation (no service account keys):

```bash
cd infra/gcp/oidc
terraform init
terraform apply -var="project_id=PROJECT_ID"
```

Store these as GitHub secrets:
- `GCP_PROJECT_ID` — GCP project ID
- `GCP_WORKLOAD_IDENTITY_PROVIDER` — Full WIF provider name
- `GCP_SERVICE_ACCOUNT` — Service account email
