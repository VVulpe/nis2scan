# Azure Integration Test Infrastructure

Terraform configuration that deploys compliant AND non-compliant Azure resources
for nis2scan integration testing.

## One-Time Setup

```bash
# 1. Create the OIDC service principal
cd infra/azure/oidc
terraform init
terraform apply -var="subscription_id=YOUR_SUBSCRIPTION_ID"

# 2. Grant admin consent for Graph API permissions (open the URL from output)
# 3. Set GitHub Secrets from the Terraform outputs:
#    - AZURE_CLIENT_ID
#    - AZURE_TENANT_ID
#    - AZURE_SUBSCRIPTION_ID
```

## Test Infrastructure

```bash
# Deploy (CI does this automatically)
cd infra/azure
terraform init
terraform apply -auto-approve

# Export outputs for tests
terraform output -json > ../../tests/integration/az_tf_outputs.json

# Run tests
pytest tests/integration/test_integration_az_*.py -v -m integration

# Destroy (always!)
terraform destroy -auto-approve
```

## Modules

| Module | Check IDs | Resources | Cost |
|--------|-----------|-----------|------|
| nr3_bcm | NR3-003, NR3-006 | Storage Accounts (GRS vs LRS) | ~$0.01 |
| nr5_schwachstellen | NR5-003 | Container Registries (Standard vs Basic) | ~$0.01 |
| nr6_wirksamkeit | NR6-003, NR6-004 | Log Analytics (365d vs 30d), Key Vault | ~$0.01 |
| nr8_kryptographie | NR8-001, NR8-004, NR8-005 | Storage (CMK vs PMK), Key Vaults, App Services | ~$0.02 |
| nr9_zugriffskontrolle | NR9-003, NR9-004 | NSGs (restricted vs open), Storage (private vs public) | ~$0.00 |

**Total per run: ~$0.05 | Lifetime: ~15 min**
