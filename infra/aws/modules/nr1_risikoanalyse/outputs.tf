# NR1-004: CloudTrail
output "compliant_trail_name" {
  description = "Name of the compliant CloudTrail (log validation enabled)"
  value       = aws_cloudtrail.compliant.name
}

output "compliant_trail_arn" {
  description = "ARN of the compliant CloudTrail"
  value       = aws_cloudtrail.compliant.arn
}

output "non_compliant_trail_name" {
  description = "Name of the non-compliant CloudTrail (log validation disabled)"
  value       = aws_cloudtrail.non_compliant.name
}

output "non_compliant_trail_arn" {
  description = "ARN of the non-compliant CloudTrail"
  value       = aws_cloudtrail.non_compliant.arn
}
