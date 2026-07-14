# NR6-004: CloudWatch Log Groups
output "compliant_log_group_name" {
  description = "Name of the compliant log group (retention >= 365)"
  value       = aws_cloudwatch_log_group.compliant.name
}

output "compliant_log_group_arn" {
  description = "ARN of the compliant log group"
  value       = aws_cloudwatch_log_group.compliant.arn
}

output "non_compliant_log_group_name" {
  description = "Name of the non-compliant log group (short retention)"
  value       = aws_cloudwatch_log_group.non_compliant.name
}

output "non_compliant_log_group_arn" {
  description = "ARN of the non-compliant log group"
  value       = aws_cloudwatch_log_group.non_compliant.arn
}
