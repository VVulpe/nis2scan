###############################################################################
# NR8-001: S3 Default Encryption
###############################################################################

output "compliant_s3_bucket" {
  description = "Name of the compliant S3 bucket (explicit SSE-S3 encryption)"
  value       = aws_s3_bucket.compliant.bucket
}

output "non_compliant_s3_bucket" {
  description = "Name of the non-compliant S3 bucket (no explicit encryption config)"
  value       = aws_s3_bucket.non_compliant.bucket
}

###############################################################################
# NR8-002: EBS Volumes Encrypted
###############################################################################

output "compliant_ebs_volume_id" {
  description = "ID of the compliant EBS volume (encrypted)"
  value       = aws_ebs_volume.compliant.id
}

output "non_compliant_ebs_volume_id" {
  description = "ID of the non-compliant EBS volume (unencrypted)"
  value       = aws_ebs_volume.non_compliant.id
}

###############################################################################
# NR8-003: RDS Storage Encryption
###############################################################################

output "compliant_rds_id" {
  description = "Identifier of the compliant RDS instance (storage encrypted)"
  value       = aws_db_instance.compliant.identifier
}

output "non_compliant_rds_id" {
  description = "Identifier of the non-compliant RDS instance (storage not encrypted)"
  value       = aws_db_instance.non_compliant.identifier
}

###############################################################################
# NR8-004: KMS Key Rotation
###############################################################################

output "compliant_kms_key_id" {
  description = "ID of the compliant KMS key (rotation enabled)"
  value       = aws_kms_key.compliant.key_id
}

output "non_compliant_kms_key_id" {
  description = "ID of the non-compliant KMS key (rotation disabled)"
  value       = aws_kms_key.non_compliant.key_id
}

###############################################################################
# NR8-005: ALB TLS Policy
###############################################################################

output "compliant_alb_arn" {
  description = "ARN of the compliant ALB (TLS 1.3 policy)"
  value       = aws_lb.compliant.arn
}

output "non_compliant_alb_arn" {
  description = "ARN of the non-compliant ALB (weak TLS 1.0 policy)"
  value       = aws_lb.non_compliant.arn
}
