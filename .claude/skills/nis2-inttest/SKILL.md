---
name: nis2-inttest
description: Create and manage integration tests that deploy real AWS/Azure infrastructure with intentional compliance gaps via Terraform, run nis2scan against it, validate findings, then destroy everything. Use when working on integration tests, Terraform test fixtures, GitHub Actions CI/CD pipeline for cloud testing, or compliance gap validation. Triggers on integration test, terraform, real cloud, end-to-end, pipeline, github actions, deploy, destroy, fixture, gap, compliance test.
allowed-tools: Read, Write, Edit, Bash, Grep, Glob
---

# NIS2 Integration Testing with Real Cloud Infrastructure

## Architecture Overview

```
GitHub Actions Pipeline
│
├── 1. terraform init + apply     → Deploy INTENTIONALLY non-compliant infra
│      (AWS + Azure in parallel)
│
├── 2. nis2scan scan              → Run scanner against live infra
│      (outputs JSON)
│
├── 3. pytest validate            → Assert expected findings match actual
│      (compare JSON output vs expected_findings.json)
│
├── 4. terraform destroy          → Tear down EVERYTHING
│      (runs even if step 2 or 3 fail)
│
└── 5. Report results             → Post to PR / upload artifact
```

## Critical Constraints

1. **COST CONTROL**: Every resource must be in the cheapest tier possible. Use t3.micro, Standard_B1s, S3 buckets with no data, empty RDS instances. Target: <$5 per full test run.
2. **ALWAYS DESTROY**: `terraform destroy` runs in a `finally` block / GitHub Actions `always()`. Even if tests crash, infra gets cleaned up.
3. **DEDICATED ACCOUNTS**: Use isolated AWS accounts / Azure subscriptions for testing. NEVER run against production.
4. **TIME LIMIT**: GitHub Actions job timeout at 30 minutes. If Terraform hangs, the job dies and a scheduled cleanup Lambda/Function sweeps orphaned resources.
5. **STATE ISOLATION**: Each PR gets its own Terraform workspace. No state conflicts between parallel runs.
6. **NO SECRETS IN CODE**: AWS credentials and Azure service principal via GitHub Secrets + OIDC federation (preferred).

## Project Structure

```
tests/
├── unit/                           # Moto-based unit tests (existing)
│   ├── test_checks_aws/
│   └── test_checks_azure/
├── integration/                    # Real cloud integration tests
│   ├── conftest.py                 # Pytest fixtures: run scan, load results
│   ├── test_nr1_risikoanalyse.py   # Assert findings for §30 Nr.1
│   ├── test_nr2_incident.py
│   ├── test_nr3_bcm.py
│   ├── test_nr8_kryptographie.py   # Phase 1
│   ├── test_nr9_zugriffskontrolle.py  # Phase 1
│   ├── test_nr10_mfa.py           # Phase 1
│   ├── expected/                   # Expected findings per provider
│   │   ├── aws_expected.json
│   │   └── azure_expected.json
│   └── README.md
├── terraform/                      # Infrastructure-as-Code for test fixtures
│   ├── aws/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   ├── provider.tf
│   │   ├── modules/
│   │   │   ├── nr1_risikoanalyse/    # Gaps for §30 Nr.1
│   │   │   ├── nr2_incident/
│   │   │   ├── nr3_bcm/
│   │   │   ├── nr8_kryptographie/    # Phase 1
│   │   │   ├── nr9_zugriffskontrolle/ # Phase 1
│   │   │   └── nr10_mfa/            # Phase 1
│   │   └── backend.tf               # S3 backend for state
│   ├── azure/
│   │   ├── main.tf
│   │   ├── variables.tf
│   │   ├── outputs.tf
│   │   ├── provider.tf
│   │   ├── modules/
│   │   │   ├── nr1_risikoanalyse/
│   │   │   ├── nr8_kryptographie/
│   │   │   ├── nr9_zugriffskontrolle/
│   │   │   └── nr10_mfa/
│   │   └── backend.tf               # Azure Storage backend
│   └── shared/
│       ├── tags.tf                   # Common tags for cost tracking + cleanup
│       └── cleanup.tf               # Scheduled cleanup for orphaned resources
└── .github/
    └── workflows/
        ├── integration-test.yml      # Triggered on PR + weekly schedule
        └── cleanup-orphans.yml       # Daily cleanup of any leaked resources
```

## Terraform Fixture Design Principle

Each §30 module deploys TWO sets of resources:
- **NON-COMPLIANT** resources (intentional gaps → scanner MUST find these)
- **COMPLIANT** resources (correct config → scanner must NOT flag these)

This tests BOTH detection AND false-positive avoidance.

Every resource gets these tags for lifecycle management:
```hcl
locals {
  common_tags = {
    Project     = "nis2scan-integration-test"
    Environment = "test"
    ManagedBy   = "terraform"
    TTL         = "2h"                          # Max lifetime
    CreatedAt   = timestamp()
    PRNumber    = var.pr_number                  # For isolation
    GHRunID     = var.github_run_id              # For traceability
  }
}
```

## Terraform Modules: AWS

### Module: nr8_kryptographie (Phase 1)

```hcl
# tests/terraform/aws/modules/nr8_kryptographie/main.tf

# === NON-COMPLIANT RESOURCES (scanner MUST detect) ===

# GAP: S3 bucket WITHOUT default encryption
resource "aws_s3_bucket" "unencrypted" {
  bucket        = "nis2scan-test-unencrypted-${var.run_id}"
  force_destroy = true
  tags          = var.common_tags
}
# Intentionally NO aws_s3_bucket_server_side_encryption_configuration

# GAP: EBS volume WITHOUT encryption
resource "aws_ebs_volume" "unencrypted" {
  availability_zone = "${var.region}a"
  size              = 1         # Minimum size = minimum cost
  encrypted         = false     # INTENTIONAL GAP
  tags              = var.common_tags
}

# GAP: RDS instance WITHOUT storage encryption
resource "aws_db_instance" "unencrypted" {
  identifier           = "nis2scan-test-unenc-${var.run_id}"
  engine               = "mysql"
  engine_version       = "8.0"
  instance_class       = "db.t3.micro"     # Cheapest
  allocated_storage    = 20                 # Minimum
  storage_encrypted    = false              # INTENTIONAL GAP
  username             = "admin"
  password             = "testpassword123"  # Test only, destroyed after
  skip_final_snapshot  = true               # Fast cleanup
  apply_immediately    = true
  tags                 = var.common_tags
}

# GAP: KMS key WITHOUT rotation
resource "aws_kms_key" "no_rotation" {
  description         = "nis2scan-test-no-rotation"
  enable_key_rotation = false   # INTENTIONAL GAP
  deletion_window_in_days = 7   # Fastest possible deletion
  tags                = var.common_tags
}

# GAP: ALB with TLS 1.0 policy (outdated)
resource "aws_lb" "weak_tls" {
  name               = "nis2-test-weaktls-${var.run_id}"
  internal           = true              # No public exposure
  load_balancer_type = "application"
  subnets            = var.subnet_ids
  tags               = var.common_tags
}

resource "aws_lb_listener" "weak_tls" {
  load_balancer_arn = aws_lb.weak_tls.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS-1-0-2015-04"  # INTENTIONAL GAP
  certificate_arn   = var.test_cert_arn

  default_action {
    type = "fixed-response"
    fixed_response {
      content_type = "text/plain"
      message_body = "test"
      status_code  = "200"
    }
  }
}

# === COMPLIANT RESOURCES (scanner must NOT flag) ===

# COMPLIANT: S3 bucket WITH AES-256 encryption
resource "aws_s3_bucket" "encrypted" {
  bucket        = "nis2scan-test-encrypted-${var.run_id}"
  force_destroy = true
  tags          = var.common_tags
}

resource "aws_s3_bucket_server_side_encryption_configuration" "encrypted" {
  bucket = aws_s3_bucket.encrypted.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "aws:kms"
    }
  }
}

# COMPLIANT: EBS volume WITH encryption
resource "aws_ebs_volume" "encrypted" {
  availability_zone = "${var.region}a"
  size              = 1
  encrypted         = true
  tags              = var.common_tags
}

# COMPLIANT: KMS key WITH rotation
resource "aws_kms_key" "with_rotation" {
  description         = "nis2scan-test-with-rotation"
  enable_key_rotation = true
  deletion_window_in_days = 7
  tags                = var.common_tags
}
```

### Module: nr9_zugriffskontrolle (Phase 1)

```hcl
# tests/terraform/aws/modules/nr9_zugriffskontrolle/main.tf

# === NON-COMPLIANT ===

# GAP: IAM user WITHOUT MFA
resource "aws_iam_user" "no_mfa" {
  name = "nis2scan-test-no-mfa-${var.run_id}"
  tags = var.common_tags
}

resource "aws_iam_access_key" "old_key" {
  user = aws_iam_user.no_mfa.name
  # Key will be >0 days old. For testing "old key" detection,
  # the check threshold in tests is set to 0 days.
}

# GAP: IAM policy with wildcard admin
resource "aws_iam_policy" "admin_wildcard" {
  name        = "nis2scan-test-admin-${var.run_id}"
  description = "INTENTIONAL GAP: wildcard admin policy"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })

  tags = var.common_tags
}

# GAP: Security group with 0.0.0.0/0 inbound on SSH
resource "aws_security_group" "open_ssh" {
  name        = "nis2scan-test-open-ssh-${var.run_id}"
  description = "INTENTIONAL GAP: open SSH"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # INTENTIONAL GAP
  }

  tags = var.common_tags
}

# GAP: S3 bucket with public access NOT blocked
resource "aws_s3_bucket" "public_possible" {
  bucket        = "nis2scan-test-nopab-${var.run_id}"
  force_destroy = true
  tags          = var.common_tags
}
# Intentionally NO aws_s3_bucket_public_access_block

# === COMPLIANT ===

# COMPLIANT: Security group with restricted access
resource "aws_security_group" "restricted" {
  name        = "nis2scan-test-restricted-${var.run_id}"
  description = "Compliant: restricted access"
  vpc_id      = var.vpc_id

  ingress {
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"]
  }

  tags = var.common_tags
}

# COMPLIANT: S3 with public access blocked
resource "aws_s3_bucket" "public_blocked" {
  bucket        = "nis2scan-test-pab-${var.run_id}"
  force_destroy = true
  tags          = var.common_tags
}

resource "aws_s3_bucket_public_access_block" "blocked" {
  bucket                  = aws_s3_bucket.public_blocked.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}
```

### Module: nr10_mfa (Phase 1)

```hcl
# tests/terraform/aws/modules/nr10_mfa/main.tf

# === NON-COMPLIANT ===

# GAP: IAM user without MFA enforced
resource "aws_iam_user" "no_mfa_user" {
  name = "nis2scan-test-nomfa-${var.run_id}"
  tags = var.common_tags
}

# No MFA device attached — scanner must detect this

# GAP: No SSO / Identity Center configured
# (Absence check — scanner detects that SSO is not enabled)

# === COMPLIANT ===
# MFA on root account cannot be tested via Terraform
# (root MFA is manual). Document this as a known limitation.
```

## Azure Terraform Modules (same pattern)

### Module: nr8_kryptographie

```hcl
# tests/terraform/azure/modules/nr8_kryptographie/main.tf

# === NON-COMPLIANT ===

# GAP: Storage Account with Microsoft-managed keys only (no CMK)
resource "azurerm_storage_account" "no_cmk" {
  name                     = "nis2testnock${var.run_id}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"     # Cheapest
  # No customer_managed_key block — INTENTIONAL GAP
  tags = var.common_tags
}

# GAP: App Service without HTTPS enforcement
resource "azurerm_linux_web_app" "no_https" {
  name                = "nis2-test-nossl-${var.run_id}"
  resource_group_name = var.resource_group_name
  location            = var.location
  service_plan_id     = var.app_service_plan_id

  https_only = false   # INTENTIONAL GAP

  site_config {
    minimum_tls_version = "1.0"   # INTENTIONAL GAP
  }

  tags = var.common_tags
}

# === COMPLIANT ===

resource "azurerm_storage_account" "encrypted" {
  name                     = "nis2testenc${var.run_id}"
  resource_group_name      = var.resource_group_name
  location                 = var.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
  min_tls_version          = "TLS1_2"
  tags                     = var.common_tags
}
```

## Integration Test Implementation

### conftest.py

```python
# tests/integration/conftest.py

import json
import pytest
import subprocess
from pathlib import Path

SCAN_RESULT_PATH = Path("tests/integration/scan_result.json")


@pytest.fixture(scope="session")
def aws_scan_result():
    """Run nis2scan against the live AWS test environment."""
    result = subprocess.run(
        [
            "python", "-m", "nis2scan", "scan",
            "--provider", "aws",
            "--config", "tests/integration/test_config_aws.yaml",
            "--format", "json",
            "--output", str(SCAN_RESULT_PATH),
        ],
        capture_output=True,
        text=True,
        timeout=300,  # 5 min max
    )
    assert result.returncode == 0, f"Scan failed: {result.stderr}"
    with open(SCAN_RESULT_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="session")
def azure_scan_result():
    """Run nis2scan against the live Azure test environment."""
    result = subprocess.run(
        [
            "python", "-m", "nis2scan", "scan",
            "--provider", "azure",
            "--config", "tests/integration/test_config_azure.yaml",
            "--format", "json",
            "--output", "tests/integration/scan_result_azure.json",
        ],
        capture_output=True,
        text=True,
        timeout=300,
    )
    assert result.returncode == 0, f"Scan failed: {result.stderr}"
    with open("tests/integration/scan_result_azure.json") as f:
        return json.load(f)


def findings_for_check(scan_result: dict, check_id: str) -> list[dict]:
    """Extract findings for a specific check ID."""
    return [
        f for f in scan_result.get("findings", [])
        if f["check_id"] == check_id
    ]


def findings_for_bsig_nr(scan_result: dict, nr: int) -> list[dict]:
    """Extract all findings for a §30 area."""
    return [
        f for f in scan_result.get("findings", [])
        if f["bsig_30_nr"] == nr
    ]


def finding_for_resource(scan_result: dict, resource_id_contains: str) -> dict | None:
    """Find a specific finding by partial resource ID match."""
    for f in scan_result.get("findings", []):
        if resource_id_contains in f.get("resource_id", ""):
            return f
    return None
```

### Test: Nr. 8 Kryptographie

```python
# tests/integration/test_nr8_kryptographie.py

import pytest
from tests.integration.conftest import (
    findings_for_check,
    finding_for_resource,
    findings_for_bsig_nr,
)


class TestNr8KryptographieAWS:
    """Integration tests for §30 Nr.8 — Kryptographie (AWS)."""

    # --- NON-COMPLIANT: Must detect ---

    def test_detects_unencrypted_s3_bucket(self, aws_scan_result):
        """Unencrypted S3 bucket must produce a HIGH finding."""
        f = finding_for_resource(aws_scan_result, "nis2scan-test-unencrypted")
        assert f is not None, "Scanner missed unencrypted S3 bucket"
        assert f["check_id"] == "AWS-NR8-001"
        assert f["severity"] in ("HIGH", "CRITICAL")
        assert f["bsig_30_nr"] == 8

    def test_detects_unencrypted_ebs(self, aws_scan_result):
        """Unencrypted EBS volume must produce a HIGH finding."""
        f = finding_for_resource(aws_scan_result, "nis2scan-test-unencrypted")
        # Could match multiple — filter by check
        ebs_findings = [
            x for x in findings_for_check(aws_scan_result, "AWS-NR8-002")
            if "unencrypted" in x.get("resource_id", "").lower()
                or x.get("current_state", {}).get("encrypted") is False
        ]
        assert len(ebs_findings) >= 1, "Scanner missed unencrypted EBS volume"

    def test_detects_unencrypted_rds(self, aws_scan_result):
        """Unencrypted RDS instance must produce a HIGH finding."""
        f = finding_for_resource(aws_scan_result, "nis2scan-test-unenc")
        assert f is not None, "Scanner missed unencrypted RDS instance"
        assert f["severity"] in ("HIGH", "CRITICAL")

    def test_detects_kms_no_rotation(self, aws_scan_result):
        """KMS key without rotation must produce a MEDIUM finding."""
        findings = findings_for_check(aws_scan_result, "AWS-NR8-004")
        no_rotation = [
            f for f in findings
            if f.get("current_state", {}).get("key_rotation_enabled") is False
        ]
        assert len(no_rotation) >= 1, "Scanner missed KMS key without rotation"

    def test_detects_weak_tls_policy(self, aws_scan_result):
        """ALB with TLS 1.0 policy must produce a HIGH finding."""
        f = finding_for_resource(aws_scan_result, "nis2-test-weaktls")
        assert f is not None, "Scanner missed ALB with weak TLS"
        assert f["severity"] in ("HIGH", "CRITICAL")

    # --- COMPLIANT: Must NOT flag ---

    def test_no_false_positive_encrypted_s3(self, aws_scan_result):
        """Encrypted S3 bucket must NOT produce a finding for NR8-001."""
        f = finding_for_resource(aws_scan_result, "nis2scan-test-encrypted")
        # Should either be None or INFO severity
        if f is not None:
            assert f["severity"] == "INFO", (
                f"False positive: encrypted S3 flagged as {f['severity']}"
            )

    def test_no_false_positive_encrypted_ebs(self, aws_scan_result):
        """Encrypted EBS volume must NOT produce a finding."""
        findings = findings_for_check(aws_scan_result, "AWS-NR8-002")
        false_positives = [
            f for f in findings
            if f.get("current_state", {}).get("encrypted") is True
               and f["severity"] not in ("INFO",)
        ]
        assert len(false_positives) == 0, "False positive on encrypted EBS"

    def test_no_false_positive_kms_with_rotation(self, aws_scan_result):
        """KMS key WITH rotation must NOT produce a finding."""
        findings = findings_for_check(aws_scan_result, "AWS-NR8-004")
        false_positives = [
            f for f in findings
            if f.get("current_state", {}).get("key_rotation_enabled") is True
               and f["severity"] not in ("INFO",)
        ]
        assert len(false_positives) == 0, "False positive on KMS with rotation"

    # --- REPORT QUALITY ---

    def test_all_nr8_findings_have_remediation(self, aws_scan_result):
        """Every NR8 finding must include remediation text in German."""
        for f in findings_for_bsig_nr(aws_scan_result, 8):
            assert f.get("remediation"), f"Finding {f['check_id']} missing remediation"
            assert len(f["remediation"]) > 20, "Remediation too short"

    def test_all_nr8_findings_have_evidence(self, aws_scan_result):
        """Every NR8 finding must include audit evidence."""
        for f in findings_for_bsig_nr(aws_scan_result, 8):
            assert f.get("audit_evidence"), f"Finding {f['check_id']} missing evidence"

    def test_nr8_findings_count(self, aws_scan_result):
        """Sanity check: we expect at least 5 findings for the non-compliant resources."""
        findings = findings_for_bsig_nr(aws_scan_result, 8)
        non_info = [f for f in findings if f["severity"] != "INFO"]
        assert len(non_info) >= 5, (
            f"Expected ≥5 NR8 findings, got {len(non_info)}. "
            "Scanner may be missing checks."
        )
```

## GitHub Actions Workflow

```yaml
# .github/workflows/integration-test.yml

name: Integration Tests (Real Cloud)

on:
  pull_request:
    paths:
      - 'nis2scan/engine/**'
      - 'tests/terraform/**'
      - 'tests/integration/**'
  schedule:
    - cron: '0 6 * * 1'  # Weekly Monday 6am UTC
  workflow_dispatch:       # Manual trigger

permissions:
  id-token: write         # For OIDC federation
  contents: read
  pull-requests: write    # For posting results

env:
  TF_VAR_run_id: ${{ github.run_id }}
  TF_VAR_pr_number: ${{ github.event.pull_request.number || 'manual' }}
  TF_VAR_github_run_id: ${{ github.run_id }}
  AWS_REGION: eu-central-1
  AZURE_LOCATION: westeurope

jobs:
  integration-test-aws:
    name: AWS Integration Tests
    runs-on: ubuntu-latest
    timeout-minutes: 30
    environment: integration-test-aws

    steps:
      - uses: actions/checkout@v4

      - name: Configure AWS Credentials (OIDC)
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_INTTEST_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3
        with:
          terraform_version: 1.7.x

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install nis2scan
        run: pip install -e ".[dev]"

      - name: Terraform Init & Apply (AWS)
        id: tf-apply
        working-directory: tests/terraform/aws
        run: |
          terraform init
          terraform workspace select pr-${{ env.TF_VAR_pr_number }} || \
            terraform workspace new pr-${{ env.TF_VAR_pr_number }}
          terraform apply -auto-approve -input=false
        timeout-minutes: 10

      - name: Wait for Resources
        run: sleep 30  # Some resources need propagation time

      - name: Run nis2scan (AWS)
        run: |
          python -m nis2scan scan \
            --provider aws \
            --config tests/integration/test_config_aws.yaml \
            --format json \
            --output tests/integration/scan_result.json

      - name: Run Integration Tests
        run: |
          pytest tests/integration/test_nr8_kryptographie.py \
                 tests/integration/test_nr9_zugriffskontrolle.py \
                 tests/integration/test_nr10_mfa.py \
                 -v --tb=short --junitxml=test-results-aws.xml

      - name: Upload Scan Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: aws-scan-results
          path: tests/integration/scan_result.json

      - name: Upload Test Results
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: aws-test-results
          path: test-results-aws.xml

      # CRITICAL: Always destroy, even if tests fail
      - name: Terraform Destroy (AWS)
        if: always()
        working-directory: tests/terraform/aws
        run: |
          terraform destroy -auto-approve -input=false
          terraform workspace select default
          terraform workspace delete pr-${{ env.TF_VAR_pr_number }} || true
        timeout-minutes: 10

  integration-test-azure:
    name: Azure Integration Tests
    runs-on: ubuntu-latest
    timeout-minutes: 30
    environment: integration-test-azure

    steps:
      - uses: actions/checkout@v4

      - name: Azure Login (OIDC)
        uses: azure/login@v2
        with:
          client-id: ${{ secrets.AZURE_CLIENT_ID }}
          tenant-id: ${{ secrets.AZURE_TENANT_ID }}
          subscription-id: ${{ secrets.AZURE_SUBSCRIPTION_ID }}

      - name: Setup Terraform
        uses: hashicorp/setup-terraform@v3

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.12'

      - name: Install nis2scan
        run: pip install -e ".[dev]"

      - name: Terraform Init & Apply (Azure)
        working-directory: tests/terraform/azure
        run: |
          terraform init
          terraform workspace select pr-${{ env.TF_VAR_pr_number }} || \
            terraform workspace new pr-${{ env.TF_VAR_pr_number }}
          terraform apply -auto-approve -input=false
        timeout-minutes: 15

      - name: Run nis2scan (Azure)
        run: |
          python -m nis2scan scan \
            --provider azure \
            --config tests/integration/test_config_azure.yaml \
            --format json \
            --output tests/integration/scan_result_azure.json

      - name: Run Integration Tests
        run: |
          pytest tests/integration/ -k "Azure" \
                 -v --tb=short --junitxml=test-results-azure.xml

      - name: Terraform Destroy (Azure)
        if: always()
        working-directory: tests/terraform/azure
        run: |
          terraform destroy -auto-approve -input=false
          terraform workspace select default
          terraform workspace delete pr-${{ env.TF_VAR_pr_number }} || true
        timeout-minutes: 10

  # Safety net: clean up orphaned resources
  cleanup:
    name: Verify Cleanup
    needs: [integration-test-aws, integration-test-azure]
    if: always()
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - name: Configure AWS
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_INTTEST_ROLE_ARN }}
          aws-region: ${{ env.AWS_REGION }}
      - name: Check for Orphaned AWS Resources
        run: |
          # Find any resources with our test tag that shouldn't exist
          aws resourcegroupstaggingapi get-resources \
            --tag-filters Key=Project,Values=nis2scan-integration-test \
            --query 'ResourceTagMappingList[].ResourceARN' \
            --output text | head -20
          ORPHANS=$(aws resourcegroupstaggingapi get-resources \
            --tag-filters Key=Project,Values=nis2scan-integration-test \
            --query 'length(ResourceTagMappingList)' --output text)
          if [ "$ORPHANS" -gt "0" ]; then
            echo "::warning::Found $ORPHANS orphaned resources! Run cleanup."
          fi
```

## Orphan Cleanup (Safety Net)

```yaml
# .github/workflows/cleanup-orphans.yml

name: Cleanup Orphaned Test Resources

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2am UTC
  workflow_dispatch:

jobs:
  cleanup-aws:
    runs-on: ubuntu-latest
    steps:
      - name: Configure AWS
        uses: aws-actions/configure-aws-credentials@v4
        with:
          role-to-assume: ${{ secrets.AWS_INTTEST_ROLE_ARN }}
          aws-region: eu-central-1
      - name: Find and Delete Orphaned Resources
        run: |
          echo "Finding resources tagged with nis2scan-integration-test..."
          # Delete S3 buckets
          for bucket in $(aws s3api list-buckets --query \
            "Buckets[?contains(Name, 'nis2scan-test')].Name" --output text); do
            echo "Deleting orphaned bucket: $bucket"
            aws s3 rb "s3://$bucket" --force || true
          done
          # Delete test IAM users
          for user in $(aws iam list-users --query \
            "Users[?contains(UserName, 'nis2scan-test')].UserName" --output text); do
            echo "Deleting orphaned IAM user: $user"
            # Delete access keys first
            for key in $(aws iam list-access-keys --user-name "$user" \
              --query 'AccessKeyMetadata[].AccessKeyId' --output text); do
              aws iam delete-access-key --user-name "$user" --access-key-id "$key"
            done
            aws iam delete-user --user-name "$user" || true
          done
          echo "Cleanup complete."
```

## AWS Test Account IAM Role (Terraform)

```hcl
# Separate Terraform for the OIDC role (run once manually)
# tests/terraform/aws-bootstrap/main.tf

resource "aws_iam_openid_connect_provider" "github" {
  url             = "https://token.actions.githubusercontent.com"
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = ["6938fd4d98bab03faadb97b34396831e3780aea1"]
}

resource "aws_iam_role" "inttest" {
  name = "nis2scan-integration-test"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = aws_iam_openid_connect_provider.github.arn
      }
      Action = "sts:AssumeRoleWithWebIdentity"
      Condition = {
        StringLike = {
          "token.actions.githubusercontent.com:sub" = "repo:YOUR_ORG/nis2scan:*"
        }
      }
    }]
  })
}

# Broad permissions for test resource creation + nis2scan read
resource "aws_iam_role_policy_attachment" "inttest" {
  role       = aws_iam_role.inttest.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
  # In production: scope down to only needed services
}
```

## Cost Estimation Per Test Run

| Resource | AWS Cost | Azure Cost | Duration |
|----------|----------|------------|----------|
| S3 Buckets (empty, 3x) | ~$0.00 | ~$0.00 | 15 min |
| EBS Volumes (1GB, 2x) | ~$0.01 | ~$0.01 | 15 min |
| RDS t3.micro (1x) | ~$0.03 | N/A | 15 min |
| ALB (1x) | ~$0.01 | N/A | 15 min |
| KMS Keys (2x) | ~$0.00 | ~$0.00 | 15 min |
| Storage Accounts (2x) | N/A | ~$0.00 | 15 min |
| App Service (1x) | N/A | ~$0.02 | 15 min |
| **Total per run** | **~$0.05** | **~$0.03** | **~15 min** |
| **Monthly (weekly runs)** | **~$0.20** | **~$0.12** | 4 runs |

Target: < $1/month for weekly integration tests.
