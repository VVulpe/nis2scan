# NR5-001: ECR Repositories
output "compliant_ecr_repo_arn" {
  description = "ARN of the compliant ECR repository (scan on push enabled)"
  value       = aws_ecr_repository.compliant.arn
}

output "compliant_ecr_repo_name" {
  description = "Name of the compliant ECR repository"
  value       = aws_ecr_repository.compliant.name
}

output "non_compliant_ecr_repo_arn" {
  description = "ARN of the non-compliant ECR repository (scan on push disabled)"
  value       = aws_ecr_repository.non_compliant.arn
}

output "non_compliant_ecr_repo_name" {
  description = "Name of the non-compliant ECR repository"
  value       = aws_ecr_repository.non_compliant.name
}

# NR5-004: Lambda Runtime
output "compliant_lambda_arn" {
  description = "ARN of the compliant Lambda function (current runtime)"
  value       = aws_lambda_function.compliant.arn
}

output "compliant_lambda_name" {
  description = "Name of the compliant Lambda function"
  value       = aws_lambda_function.compliant.function_name
}

output "non_compliant_lambda_arn" {
  description = "ARN of the non-compliant Lambda function (deprecated runtime)"
  value       = aws_lambda_function.non_compliant_lambda.arn
}

output "non_compliant_lambda_name" {
  description = "Name of the non-compliant Lambda function"
  value       = aws_lambda_function.non_compliant_lambda.function_name
}
