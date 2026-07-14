# ============================================================================
# Nr. 4 — Sicherheit der Lieferkette (Supply Chain Security)
# ============================================================================
# The NR4 checks (NR4-002 through NR4-005) are all positive-path tests:
# - NR4-002: CI account has no RAM shares → check runs clean
# - NR4-003: CI account has no Organizations → finding expected
# - NR4-004: CI account has OIDC role (GitHub trust) → detected as cross-account
# - NR4-005: CI account has no Organizations → finding expected
#
# No additional Terraform resources needed — the checks detect the absence
# of proper supply chain controls (Organizations, SCPs, RAM policies).
# ============================================================================

# Empty module — kept for structural consistency with other modules.
# The nis2scan-ci OIDC role already serves as the cross-account role
# test case for NR4-004.
