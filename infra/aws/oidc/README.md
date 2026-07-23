# OIDC Setup for GitHub Actions

This Terraform configuration creates the OIDC trust between GitHub Actions and your AWS account. **Apply this once manually** before using the integration test pipeline.

## Prerequisites

- AWS CLI configured with admin credentials for your test account
- Terraform >= 1.5 installed

## Setup

```bash
cd infra/aws/oidc
terraform init
terraform apply \
  -var="aws_account_id=YOUR_ACCOUNT_ID" \
  -var="github_repo=letaible/nis2scan"
```

## Output

After apply, note the `ci_role_arn` output. Update `.github/workflows/integration-tests-aws.yml` with this ARN:

```yaml
- uses: aws-actions/configure-aws-credentials@v4
  with:
    role-to-assume: <ci_role_arn from output>
    aws-region: eu-central-1
```

## Teardown

To remove the OIDC trust and CI role:

```bash
terraform destroy -var="aws_account_id=YOUR_ACCOUNT_ID"
```
