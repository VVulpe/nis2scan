# ============================================================================
# Nr. 7 — Grundlegende Verfahren der Cyberhygiene (Cyber Hygiene)
# ============================================================================
# NR7-001: IAM Password Policy
# NR7-002: Root Account Access Keys — no infra needed (reads account summary)
# ============================================================================

# ---------------------------------------------------------------------------
# NR7-001: IAM Password Policy — Non-compliant (weak settings)
# ---------------------------------------------------------------------------
# Set a deliberately weak password policy for integration testing.
# The check should detect that minimum_password_length < 14.

resource "aws_iam_account_password_policy" "weak" {
  minimum_password_length        = 8
  require_lowercase_characters   = true
  require_uppercase_characters   = false
  require_numbers                = true
  require_symbols                = false
  allow_users_to_change_password = true
  max_password_age               = 0
  password_reuse_prevention      = 0
}
