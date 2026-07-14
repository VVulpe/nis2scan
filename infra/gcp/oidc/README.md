# GCP OIDC Setup for GitHub Actions

## Prerequisites
- GCP project with billing enabled
- `gcloud` CLI authenticated with Owner role
- GitHub repository: VVulpe/nis2scan

## Setup

### 1. Create GCP project (if needed)
```bash
gcloud projects create nis2scan-test --name="nis2scan Integration Tests"
gcloud config set project nis2scan-test
gcloud billing projects link nis2scan-test --billing-account=BILLING_ACCOUNT_ID
```

### 2. Enable required APIs
```bash
gcloud services enable \
  iam.googleapis.com \
  iamcredentials.googleapis.com \
  cloudresourcemanager.googleapis.com \
  compute.googleapis.com \
  storage.googleapis.com \
  cloudkms.googleapis.com \
  logging.googleapis.com \
  monitoring.googleapis.com \
  securitycenter.googleapis.com \
  container.googleapis.com \
  cloudasset.googleapis.com \
  dns.googleapis.com \
  sqladmin.googleapis.com
```

### 3. Apply OIDC Terraform
```bash
cd infra/gcp/oidc
terraform init
terraform apply -var="project_id=nis2scan-test"
```

### 4. Set GitHub Secrets
```bash
gh secret set GCP_PROJECT_ID --body "$(terraform output -raw project_id)"
gh secret set GCP_WORKLOAD_IDENTITY_PROVIDER --body "$(terraform output -raw workload_identity_provider)"
gh secret set GCP_SERVICE_ACCOUNT --body "$(terraform output -raw service_account_email)"
```

### 5. Test
```bash
gh workflow run "Integration Tests (GCP)"
```
