# ============================================================================
# Nr. 10 — MFA & Kommunikation (MFA & Communication)
# ============================================================================
# NR10-002: IAM User Console MFA Enforcement
# ============================================================================

# --- Console user WITHOUT MFA (non-compliant) ---
resource "random_password" "console_user" {
  length  = 24
  special = true
}

resource "aws_iam_user" "console_no_mfa" {
  name          = "${var.name}-nr10-console-nomfa"
  force_destroy = true

  tags = { Name = "${var.name}-nr10-console-nomfa" }
}

resource "aws_iam_user_login_profile" "console_no_mfa" {
  user                    = aws_iam_user.console_no_mfa.name
  password_reset_required = false
}
