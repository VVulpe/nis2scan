# --- NR9-001: IAM User MFA ---
output "iam_user_with_mfa" {
  description = "Username of the IAM user with MFA enabled"
  value       = aws_iam_user.with_mfa.name
}

output "iam_user_without_mfa" {
  description = "Username of the IAM user without MFA"
  value       = aws_iam_user.without_mfa.name
}

# --- NR9-004: Security Groups ---
output "compliant_sg_id" {
  description = "ID of the compliant security group (restricted ingress)"
  value       = aws_security_group.compliant.id
}

output "non_compliant_sg_id" {
  description = "ID of the non-compliant security group (SSH open to world)"
  value       = aws_security_group.non_compliant.id
}

# --- NR9-003: S3 Public Access Block ---
output "s3_public_access_block_set" {
  description = "Whether the S3 account public access block is configured (always true)"
  value       = true
}

# --- NR9-005: IAM Wildcard Policy ---
output "non_compliant_iam_policy_arn" {
  description = "ARN of the non-compliant IAM policy with wildcard permissions"
  value       = aws_iam_policy.wildcard.arn
}
