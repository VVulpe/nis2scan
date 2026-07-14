# ============================================================================
# Nr. 2 — Bewältigung von Sicherheitsvorfällen (Incident Response)
# ============================================================================
# NR2-004: CloudWatch Alarm for monitoring
# ============================================================================

# ---------------------------------------------------------------------------
# NR2-004: CloudWatch Metric Alarm — Compliant (alarm exists)
# ---------------------------------------------------------------------------
# A simple free-tier alarm on estimated charges to prove alarm presence.

resource "aws_cloudwatch_metric_alarm" "billing_alarm" {
  alarm_name          = "${var.name}-billing-alarm"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EstimatedCharges"
  namespace           = "AWS/Billing"
  period              = 86400
  statistic           = "Maximum"
  threshold           = 100
  alarm_description   = "NIS2 integration test — billing alarm for NR2-004"
  treat_missing_data  = "notBreaching"

  # No actions needed — this is just for the integration test
  alarm_actions = []

  tags = {
    Name  = "${var.name}-billing-alarm"
    Check = "NR2-004"
    Role  = "compliant"
  }
}
