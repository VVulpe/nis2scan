# --- NR10-002: IAM User Console MFA Enforcement ---
output "iam_console_user_no_mfa" {
  description = "Username of the console-enabled IAM user without MFA"
  value       = aws_iam_user.console_no_mfa.name
}
