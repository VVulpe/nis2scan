# NR3-002: S3 Versioning
output "compliant_s3_versioning_bucket" {
  description = "Name of the S3 bucket with versioning enabled"
  value       = aws_s3_bucket.versioning_compliant.id
}

output "non_compliant_s3_versioning_bucket" {
  description = "Name of the S3 bucket without versioning"
  value       = aws_s3_bucket.versioning_non_compliant.id
}

# NR3-003: S3 Object Lock
output "compliant_object_lock_bucket" {
  description = "Name of the S3 bucket with Object Lock enabled"
  value       = aws_s3_bucket.object_lock_compliant.id
}

output "non_compliant_object_lock_bucket" {
  description = "Name of S3 bucket without Object Lock (same as versioning non-compliant)"
  value       = aws_s3_bucket.versioning_non_compliant.id
}

# NR3-006: EBS Snapshots
output "compliant_snapshot_volume_id" {
  description = "Volume ID with an encrypted snapshot"
  value       = aws_ebs_volume.snapshot_compliant.id
}

output "compliant_snapshot_id" {
  description = "Encrypted snapshot ID"
  value       = aws_ebs_snapshot.compliant.id
}

output "non_compliant_snapshot_volume_id" {
  description = "Volume ID with NO snapshot"
  value       = aws_ebs_volume.snapshot_non_compliant.id
}
