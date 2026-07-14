"""§30 Abs. 2 Nr. 7 — Cyberhygiene & Schulungen checks for Azure.

Checks Entra ID Password Protection and Security Defaults / Conditional Access Baseline.
(BSIG wording: basic training and security awareness)
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 7
BSIG_30_TEXT = (
    "§30 Abs. 2 Nr. 7 BSIG — grundlegende Schulungen und Sensibilisierungsmaßnahmen "
    "im Bereich der Sicherheit in der Informationstechnik"
)


class CheckPasswordProtection(BaseCheck):
    """Check that Entra ID Password Protection is configured."""

    check_id = "AZ-NR7-001"
    title = "Entra ID Password Protection konfiguriert"
    description = (
        "Prüft ob Entra ID Password Protection mit benutzerdefinierter Liste verbotener Passwörter konfiguriert ist."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Directory.Read.All"]
    pruefgrenzen = (
        'Prüft nur das Entra-ID-groupSettings-Objekt "Password Rule Settings" (Graph API) auf '
        "aktivierten Banned-Password-Check und nicht-leere benutzerdefinierte Sperrliste. "
        "On-Premises-Password-Protection sowie Wirksamkeit und Inhalte der Sperrliste "
        "werden nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        expected_state = (
            "Password Protection mit benutzerdefinierter Liste verbotener Passwörter "
            "(EnableBannedPasswordCheck aktiviert, BannedPasswordList nicht leer)"
        )

        try:
            from msgraph import GraphServiceClient  # type: ignore[attr-defined]

            graph_client = GraphServiceClient(session.credential)

            # Password Protection lives in the "Password Rule Settings" groupSettings object
            # (Graph v1.0 /groupSettings), NOT in the authentication methods policy.
            settings_response = await graph_client.group_settings.get()
            settings = settings_response.value if settings_response and settings_response.value else []

            password_settings = None
            for setting in settings:
                if str(getattr(setting, "display_name", "") or "") == "Password Rule Settings":
                    password_settings = setting
                    break

            if password_settings is None:
                # Defect case 1: no "Password Rule Settings" object exists for the tenant
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Password Protection nicht konfiguriert",
                        description=(
                            "Für den Tenant ist keine benutzerdefinierte Liste verbotener Passwörter "
                            "konfiguriert; es greift nur die globale Microsoft-Sperrliste."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.5.17 Authentifizierungsinformationen",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/groupSettings",
                        resource_type="Microsoft.Graph/groupSettings",
                        account_id=session.subscription_id,
                        current_state={"password_rule_settings_present": False},
                        expected_state=expected_state,
                        remediation=(
                            "Konfigurieren Sie Password Protection: "
                            "Entra Admin Center → Schutz → Authentifizierungsmethoden → "
                            "Kennwortschutz → Benutzerdefinierte Liste verbotener Kennwörter aktivieren"
                        ),
                        remediation_effort="LOW",
                        audit_evidence="Graph API groupSettings: no 'Password Rule Settings' object found",
                    )
                )
            else:
                setting_id = getattr(password_settings, "id", None)
                resource_id = f"/groupSettings/{setting_id}" if setting_id else "/groupSettings"

                setting_values: dict[str, str] = {}
                for value in getattr(password_settings, "values", None) or []:
                    name = getattr(value, "name", None)
                    if name is not None:
                        setting_values[str(name)] = str(getattr(value, "value", "") or "")

                check_enabled = setting_values.get("EnableBannedPasswordCheck", "").strip().lower() == "true"
                banned_list = setting_values.get("BannedPasswordList", "")
                banned_entries = [e for e in banned_list.split("\t") if e.strip()]

                if check_enabled and banned_entries:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Password Protection konfiguriert",
                            description=(
                                "Für den Tenant ist eine benutzerdefinierte Liste verbotener Passwörter "
                                "konfiguriert; der Banned-Password-Check (EnableBannedPasswordCheck) "
                                "ist aktiviert."
                            ),
                            region="global",
                            resource_id=resource_id,
                            resource_type="Microsoft.Graph/groupSettings",
                            account_id=session.subscription_id,
                            current_state={
                                "password_rule_settings_present": True,
                                "enable_banned_password_check": True,
                                "banned_password_list_entries": len(banned_entries),
                            },
                            expected_state=expected_state,
                            audit_evidence=(
                                f"Graph API groupSettings 'Password Rule Settings': "
                                f"EnableBannedPasswordCheck=True, "
                                f"BannedPasswordList entries={len(banned_entries)}"
                            ),
                            iso27001_control="A.5.17 Authentifizierungsinformationen",
                        )
                    )
                else:
                    # Defect case 2: settings object exists, but the check is disabled
                    # and/or the custom banned password list is empty
                    issues: list[str] = []
                    if not check_enabled:
                        issues.append("der Banned-Password-Check (EnableBannedPasswordCheck) ist deaktiviert")
                    if not banned_entries:
                        issues.append("die benutzerdefinierte Sperrliste (BannedPasswordList) ist leer")
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Benutzerdefinierte Passwort-Sperrliste deaktiviert oder leer",
                            description=(
                                f'Für den Tenant ist das groupSettings-Objekt "Password Rule Settings" '
                                f"vorhanden, aber {' und '.join(issues)}; es greift nur die globale "
                                f"Microsoft-Sperrliste."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.17 Authentifizierungsinformationen",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=resource_id,
                            resource_type="Microsoft.Graph/groupSettings",
                            account_id=session.subscription_id,
                            current_state={
                                "password_rule_settings_present": True,
                                "enable_banned_password_check": check_enabled,
                                "banned_password_list_entries": len(banned_entries),
                            },
                            expected_state=expected_state,
                            remediation=(
                                "Konfigurieren Sie Password Protection: "
                                "Entra Admin Center → Schutz → Authentifizierungsmethoden → "
                                "Kennwortschutz → Benutzerdefinierte Liste verbotener Kennwörter aktivieren"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(
                                f"Graph API groupSettings 'Password Rule Settings': "
                                f"EnableBannedPasswordCheck={check_enabled}, "
                                f"BannedPasswordList entries={len(banned_entries)}"
                            ),
                        )
                    )
        except Exception as exc:
            errors.append(
                CheckError(
                    check_id=self.check_id,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    region="global",
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckSecurityDefaults(BaseCheck):
    """Check that Security Defaults or Conditional Access baseline is active."""

    check_id = "AZ-NR7-002"
    title = "Security Defaults oder Conditional Access Baseline"
    description = (
        "Prüft ob Security Defaults aktiviert sind oder eine äquivalente "
        "Conditional Access Baseline-Konfiguration besteht."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Policy.Read.All"]
    pruefgrenzen = (
        "Prüft nur, ob Security Defaults oder Conditional-Access-Grundschutz aktiv "
        "ist. Die inhaltliche Güte der CA-Policies wird nicht bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        try:
            from msgraph import GraphServiceClient  # type: ignore[attr-defined]

            graph_client = GraphServiceClient(session.credential)

            # Check Security Defaults
            security_defaults = await graph_client.policies.identity_security_defaults_enforcement_policy.get()
            sd_enabled = security_defaults.is_enabled if security_defaults else False

            if sd_enabled:
                # Security Defaults are enabled — baseline is met (ADR-0006: positive evidence)
                findings.append(
                    compliant_finding(
                        self,
                        title="Security Defaults aktiviert",
                        description=(
                            "Security Defaults sind aktiviert — MFA-Enforcement, "
                            "Legacy-Auth-Blockierung und weitere Baselines greifen."
                        ),
                        region="global",
                        resource_id="/policies/identitySecurityDefaultsEnforcementPolicy",
                        resource_type="Microsoft.Graph/identitySecurityDefaultsEnforcementPolicy",
                        account_id=session.subscription_id,
                        current_state={"security_defaults_enabled": True},
                        expected_state="Security Defaults aktiviert ODER äquivalente CA-Policies",
                        audit_evidence="Graph API: Security Defaults enabled",
                        iso27001_control="A.8.5 Sichere Authentisierung",
                    )
                )
                return CheckResult(check_id=self.check_id, findings=findings, errors=errors)

            # Security Defaults disabled — check for CA policies that actually require MFA as replacement.
            # Only enabled policies with an "mfa" grant control count as an equivalent baseline.
            policies_response = await graph_client.identity.conditional_access.policies.get()
            policies = policies_response.value if policies_response and policies_response.value else []

            mfa_policies = []
            for policy in policies:
                if not policy.state or str(policy.state).lower() != "enabled":
                    continue
                grant = policy.grant_controls
                if not grant or not grant.built_in_controls:
                    continue
                if "mfa" in [str(c).lower() for c in grant.built_in_controls]:
                    mfa_policies.append(policy)

            if mfa_policies:
                findings.append(
                    compliant_finding(
                        self,
                        title="Conditional-Access-Richtlinien mit MFA-Anforderung aktiv",
                        description=(
                            f"Security Defaults sind deaktiviert; {len(mfa_policies)} aktive "
                            f"Conditional-Access-Richtlinien verlangen MFA. Geltungsbereich und "
                            f"Ausnahmen der Richtlinien werden nicht bewertet (siehe Prüfgrenzen)."
                        ),
                        region="global",
                        resource_id="/identity/conditionalAccess/policies",
                        resource_type="Microsoft.Graph/conditionalAccessPolicies",
                        account_id=session.subscription_id,
                        current_state={
                            "security_defaults_enabled": False,
                            "conditional_access_mfa_policies": len(mfa_policies),
                        },
                        expected_state="Security Defaults aktiviert ODER äquivalente CA-Policies",
                        audit_evidence=(
                            f"Graph API: Security Defaults disabled, {len(mfa_policies)} enabled "
                            f"CA policies with MFA grant control"
                        ),
                        iso27001_control="A.8.5 Sichere Authentisierung",
                    )
                )
            else:
                findings.append(
                    Finding(
                        check_id=self.check_id,
                        title="Weder Security Defaults noch Conditional Access mit MFA-Anforderung aktiv",
                        description=(
                            "Security Defaults sind deaktiviert und es gibt keine aktiven "
                            "Conditional Access Policies, die MFA verlangen. Ohne grundlegende "
                            "Sicherheitsstandards fehlen MFA-Enforcement, Legacy-Auth-Blockierung "
                            "und weitere Baselines."
                        ),
                        bsig_30_nr=BSIG_30_NR,
                        bsig_30_text=BSIG_30_TEXT,
                        iso27001_control="A.8.5 Sichere Authentisierung",
                        severity=Severity.HIGH,
                        provider=CloudProvider.AZURE,
                        region="global",
                        resource_id="/policies/identitySecurityDefaultsEnforcementPolicy",
                        resource_type="Microsoft.Graph/identitySecurityDefaultsEnforcementPolicy",
                        account_id=session.subscription_id,
                        current_state={
                            "security_defaults_enabled": False,
                            "conditional_access_mfa_policies": 0,
                        },
                        expected_state="Security Defaults aktiviert ODER äquivalente CA-Policies",
                        remediation=(
                            "Aktivieren Sie Security Defaults: "
                            "Entra Admin Center → Identität → Übersicht → Eigenschaften → "
                            "Sicherheitsstandards verwalten → Aktiviert. "
                            "Oder erstellen Sie Conditional Access Policies, die MFA verlangen."
                        ),
                        remediation_effort="LOW",
                        audit_evidence=(
                            "Graph API: Security Defaults disabled, 0 enabled CA policies with MFA grant control"
                        ),
                    )
                )
        except Exception as exc:
            errors.append(
                CheckError(
                    check_id=self.check_id,
                    error_type=type(exc).__name__,
                    message=str(exc),
                    region="global",
                )
            )

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
