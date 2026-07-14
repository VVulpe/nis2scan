---
name: nis2-check
description: Create or modify NIS2 compliance check modules. Use when building new checks for §30 BSIG areas, adding cloud provider checks, or implementing Finding generation logic. Triggers on keywords like check, finding, scan, §30, BSIG, compliance, provider.
allowed-tools: Read, Write, Edit, Bash, Grep, Glob
---

# NIS2 Check Module Development

## When to Use
- Creating a new check module (nr1 through nr10) for AWS or Azure
- Modifying existing check logic
- Adding new Findings to a check
- Implementing cloud API calls for compliance verification

## Check Module Structure

Every check module follows this exact pattern:

```python
"""§30 Abs. 2 Nr. {N} — {German title of the measure}."""

from nis2scan.engine.providers.base import BaseCheck, CheckResult
from nis2scan.engine.models.finding import Finding, Severity
from nis2scan.engine.models.check import CloudProvider

class {CheckName}(BaseCheck):
    check_id = "{PROVIDER}-NR{N}-{SEQ:03d}"
    bsig_30_nr = {N}
    provider = CloudProvider.{AWS|AZURE}
    required_permissions = [
        # List EVERY IAM permission / Azure RBAC action needed
    ]

    async def execute(self, session) -> CheckResult:
        findings = []
        errors = []

        try:
            # 1. Call cloud API (read-only!)
            # 2. Evaluate compliance condition
            # 3. Create Finding if non-compliant
            pass
        except ClientError as e:
            errors.append(CheckError(
                check_id=self.check_id,
                error_type="api_error",
                message=str(e)
            ))

        return CheckResult(
            check_id=self.check_id,
            findings=findings,
            errors=errors,
            skipped=False,
            duration_ms=elapsed
        )
```

## Finding Construction Rules

1. **title**: Short German description. Max 80 chars. Example: "S3-Bucket ohne Default-Verschlüsselung"
2. **description**: German. What was found, why it matters for NIS2.
3. **severity**: Use this logic:
   - CRITICAL: Direct exposure, exploitable now (public S3, no root MFA)
   - HIGH: Significant gap in required NIS2 measure (no encryption, no backups)
   - MEDIUM: Partial implementation, improvement needed (weak TLS, old keys)
   - LOW: Best practice not met, but basic compliance exists
   - INFO: Informational, no action required
4. **remediation**: German. Concrete steps to fix. Include AWS CLI / Azure CLI commands where possible.
5. **audit_evidence**: The raw API response (sanitized) that proves the finding. This is what the auditor sees.
6. **resource_id**: Full ARN (AWS) or full Resource ID (Azure). Never truncate.

## Critical Constraints
- NEVER call write/modify/delete APIs. Read-only operations only.
- ALWAYS handle API errors gracefully — a failed API call is a CheckError, not a crash.
- ALWAYS implement pagination for list operations (S3 buckets, EC2 instances, etc.).
- ALWAYS check ALL regions unless config limits to specific regions.
- Pseudonymize IAM usernames: hash with SHA-256, show first 8 chars.

## Testing Pattern

```python
@mock_aws
def test_{check_name}_non_compliant():
    """Test that check detects non-compliant resource."""
    # 1. Create mock resource in non-compliant state
    # 2. Run check
    # 3. Assert Finding with correct severity and bsig_30_nr
    
@mock_aws  
def test_{check_name}_compliant():
    """Test that check passes for compliant resource."""
    # 1. Create mock resource in compliant state
    # 2. Run check
    # 3. Assert no Findings

@mock_aws
def test_{check_name}_api_error():
    """Test graceful handling of API errors."""
    # 1. Mock API to raise ClientError
    # 2. Run check
    # 3. Assert CheckError, no crash
```
