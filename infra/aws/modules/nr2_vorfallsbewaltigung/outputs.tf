# NR2-004: CloudWatch Alarm
output "alarm_name" {
  description = "Name of the CloudWatch billing alarm"
  value       = aws_cloudwatch_metric_alarm.billing_alarm.alarm_name
}

output "alarm_arn" {
  description = "ARN of the CloudWatch billing alarm"
  value       = aws_cloudwatch_metric_alarm.billing_alarm.arn
}
