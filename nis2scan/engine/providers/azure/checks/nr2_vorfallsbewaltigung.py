"""§30 Abs. 2 Nr. 2 — Bewältigung von Sicherheitsvorfällen checks for Azure.

Checks Defender alerting, Sentinel analytics, playbooks, action groups, and alert processing.
"""

from typing import Any

import structlog

from nis2scan.engine.evidence import compliant_finding
from nis2scan.engine.models.check import BaseCheck, CheckError, CheckResult
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity

logger = structlog.get_logger()

BSIG_30_NR = 2
BSIG_30_TEXT = "§30 Abs. 2 Nr. 2 BSIG — Bewältigung von Sicherheitsvorfällen"


class CheckDefenderAlertNotifications(BaseCheck):
    """Check that Defender alert notifications are configured."""

    check_id = "AZ-NR2-001"
    title = "Defender Alert-Benachrichtigungen konfiguriert"
    description = "Prüft ob Microsoft Defender for Cloud Alert-Benachrichtigungen konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Security/securityContacts/read"]
    pruefgrenzen = (
        "Prüft nur, ob Defender-Sicherheitskontakte mit Benachrichtigung konfiguriert "
        "sind. Ob Alarme gelesen und bearbeitet werden, ist nicht prüfbar."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.security import SecurityCenter

                client = session.get_client(SecurityCenter, sub_id)
                contacts = list(client.security_contacts.list())

                # Check if any contact has alert notifications enabled
                notif_enabled = any(
                    getattr(c, "alert_notifications", None) and getattr(c.alert_notifications, "state", "") == "On"
                    for c in contacts
                )

                if contacts and notif_enabled:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Defender Alert-Benachrichtigungen aktiv",
                            description=(
                                f"Subscription {sub_id} hat {len(contacts)} Security Contact(s) "
                                f"mit aktiven Alert-Benachrichtigungen."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Security/securityContacts",
                            account_id=sub_id,
                            current_state={"security_contacts": len(contacts), "notifications_enabled": True},
                            expected_state="Mindestens ein Security Contact mit Alert-Benachrichtigungen",
                            audit_evidence=(
                                f"security_contacts.list() returned {len(contacts)} contact(s), alert_notifications=On"
                            ),
                            iso27001_control="A.5.24 Incident Management",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Defender Alert-Benachrichtigungen nicht konfiguriert",
                            description=(
                                f"Subscription {sub_id} hat keine aktiven "
                                "Defender Alert-Benachrichtigungen. Ohne Benachrichtigungen "
                                "werden Sicherheitsvorfälle nicht zeitnah erkannt."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.24 Incident Management",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Security/securityContacts",
                            account_id=sub_id,
                            current_state={"security_contacts": len(contacts), "notifications_enabled": notif_enabled},
                            expected_state="Mindestens ein Security Contact mit Alert-Benachrichtigungen",
                            remediation=(
                                "Konfigurieren Sie Defender Alert-Benachrichtigungen: "
                                "az security contact create --name default --email security@company.com "
                                "--alert-notifications on --alerts-admins on"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=f"security_contacts.list() returned {len(contacts)} contacts",
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


class CheckSentinelAnalyticsRules(BaseCheck):
    """Check that a Log Analytics workspace exists as the foundation for Sentinel analytics rules."""

    check_id = "AZ-NR2-002"
    title = "Log Analytics Workspace als Sentinel-Grundlage vorhanden"
    description = (
        "Prüft ob mindestens ein Log Analytics Workspace existiert — technische "
        "Voraussetzung für Microsoft Sentinel Analytics Rules."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.OperationalInsights/workspaces/read",
    ]
    pruefgrenzen = (
        "Prüft nur die Existenz von Log-Analytics-Workspaces. Ob Sentinel aktiviert ist "
        "und aktive Analytics Rules existieren, wird nicht geprüft — Nachweis über die "
        "Attestierungs-Checkliste."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.loganalytics import LogAnalyticsManagementClient

                la_client = session.get_client(LogAnalyticsManagementClient, sub_id)
                workspaces = list(la_client.workspaces.list())

                if workspaces:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Log Analytics Workspace für Analytics Rules vorhanden",
                            description=(
                                f"Subscription {sub_id} hat {len(workspaces)} Log Analytics "
                                f"Workspace(s) als Grundlage für Sentinel Analytics Rules."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.OperationalInsights/workspaces",
                            account_id=sub_id,
                            current_state={"log_analytics_workspaces": len(workspaces)},
                            expected_state="Mindestens ein Log Analytics Workspace vorhanden",
                            audit_evidence=f"workspaces.list() returned {len(workspaces)} workspace(s)",
                            iso27001_control="A.5.24, A.8.16 Incident Detection",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Kein Log Analytics Workspace vorhanden",
                            description=(
                                f"Subscription {sub_id} hat keinen Log Analytics Workspace. Damit "
                                "fehlt die technische Voraussetzung für Microsoft Sentinel Analytics Rules."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.24, A.8.16 Incident Detection",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.OperationalInsights/workspaces",
                            account_id=sub_id,
                            current_state={"log_analytics_workspaces": 0},
                            expected_state="Mindestens ein Log Analytics Workspace vorhanden",
                            remediation=(
                                "Erstellen Sie einen Log Analytics Workspace: "
                                "az monitor log-analytics workspace create "
                                "--resource-group <rg> --workspace-name <ws>"
                            ),
                            remediation_effort="HIGH",
                            audit_evidence="No Log Analytics workspaces found",
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


class CheckSentinelPlaybooks(BaseCheck):
    """Check for Logic Apps whose name suggests security automation (keyword heuristic only)."""

    check_id = "AZ-NR2-003"
    title = "Logic Apps mit sicherheitsbezogenem Namensmuster vorhanden"
    description = (
        "Prüft ob Logic Apps existieren, deren Name auf Sicherheitsautomatisierung "
        "hindeutet (Schlüsselwortabgleich im Ressourcennamen)."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = [
        "Microsoft.Logic/workflows/read",
    ]
    pruefgrenzen = (
        "Die Identifikation erfolgt ausschließlich über Schlüsselwörter im "
        "Ressourcennamen; eine Verknüpfung mit Sentinel-Vorfällen wird nicht geprüft. "
        "Ob die gefundenen Logic Apps tatsächlich Sentinel-Playbooks sind und "
        "funktionieren, wird nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.resource import ResourceManagementClient

                rm_client = session.get_client(ResourceManagementClient, sub_id)
                # Look for Logic Apps in the subscription
                logic_apps = list(rm_client.resources.list(filter="resourceType eq 'Microsoft.Logic/workflows'"))

                # Check if any Logic App is related to security/Sentinel
                sentinel_playbooks = [
                    la
                    for la in logic_apps
                    if any(
                        kw in (la.name or "").lower()
                        for kw in ["sentinel", "security", "incident", "alert", "playbook"]
                    )
                ]

                if sentinel_playbooks:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Logic Apps mit sicherheitsbezogenem Namensmuster vorhanden",
                            description=(
                                f"Subscription {sub_id} hat {len(sentinel_playbooks)} Logic App(s), "
                                f"deren Name auf Sicherheitsautomatisierung hindeutet "
                                f"(Schlüsselwortabgleich); ob es sich um Sentinel-Playbooks handelt "
                                f"und ob sie an Vorfälle gekoppelt sind, wird nicht geprüft."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Logic/workflows",
                            account_id=sub_id,
                            current_state={
                                "total_logic_apps": len(logic_apps),
                                "security_playbooks": len(sentinel_playbooks),
                            },
                            expected_state="Mindestens eine Logic App mit sicherheitsbezogenem Namensmuster",
                            audit_evidence=(
                                f"resources.list() returned {len(logic_apps)} Logic Apps, "
                                f"{len(sentinel_playbooks)} security-related"
                            ),
                            iso27001_control="A.5.26 Response to Incidents",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Logic Apps mit sicherheitsbezogenem Namensmuster",
                            description=(
                                f"Subscription {sub_id} hat keine Logic Apps, deren Name auf "
                                f"Sicherheitsautomatisierung hindeutet (Schlüsselwortabgleich)."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.26 Response to Incidents",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Logic/workflows",
                            account_id=sub_id,
                            current_state={
                                "total_logic_apps": len(logic_apps),
                                "security_playbooks": 0,
                            },
                            expected_state="Mindestens eine Logic App mit sicherheitsbezogenem Namensmuster",
                            remediation=(
                                "Erstellen Sie Sentinel Playbooks für automatisierte Incident-Response: "
                                "Azure Portal → Sentinel → Automation → Create Playbook"
                            ),
                            remediation_effort="HIGH",
                            audit_evidence=(
                                f"resources.list() returned {len(logic_apps)} Logic Apps, 0 security-related"
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


class CheckActionGroups(BaseCheck):
    """Check that Azure Monitor Action Groups are configured for alerting."""

    check_id = "AZ-NR2-004"
    title = "Action Groups für Alerting"
    description = "Prüft ob Azure Monitor Action Groups für Alerting-Eskalation konfiguriert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.Insights/actionGroups/read"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Action Groups. Erreichbarkeit der hinterlegten "
        "Kontakte und tatsächliche Alarm-Zustellung werden nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.monitor import MonitorManagementClient

                client = session.get_client(MonitorManagementClient, sub_id)
                action_groups = list(client.action_groups.list_by_subscription_id())

                if action_groups:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Action Groups konfiguriert",
                            description=(
                                f"Subscription {sub_id} hat {len(action_groups)} Azure Monitor "
                                f"Action Group(s) für Alerting-Eskalation."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Insights/actionGroups",
                            account_id=sub_id,
                            current_state={"action_groups": len(action_groups)},
                            expected_state="Mindestens eine Azure Monitor Action Group konfiguriert",
                            audit_evidence=(
                                f"action_groups.list_by_subscription_id() returned {len(action_groups)} group(s)"
                            ),
                            iso27001_control="A.5.24 Incident Management",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Action Groups konfiguriert",
                            description=(
                                f"Subscription {sub_id} hat keine Azure Monitor "
                                "Action Groups. Ohne Action Groups können Alerts nicht an "
                                "Verantwortliche weitergeleitet werden."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.24 Incident Management",
                            severity=Severity.HIGH,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.Insights/actionGroups",
                            account_id=sub_id,
                            current_state={"action_groups": 0},
                            expected_state="Mindestens eine Azure Monitor Action Group konfiguriert",
                            remediation=(
                                "Erstellen Sie eine Action Group: "
                                "az monitor action-group create --name 'SecurityTeam' "
                                "--resource-group <rg> --short-name 'SecTeam' "
                                "--action email security security@company.com"
                            ),
                            remediation_effort="LOW",
                            audit_evidence="action_groups.list_by_subscription_id() returned 0 groups",
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


class CheckAlertProcessingRules(BaseCheck):
    """Check that Alert Processing Rules are defined for alert routing."""

    check_id = "AZ-NR2-005"
    title = "Alert Processing Rules definiert"
    description = "Prüft ob Alert Processing Rules für Priorisierung und Routing von Alerts definiert sind."
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.AZURE
    required_permissions = ["Microsoft.AlertsManagement/actionRules/read"]
    pruefgrenzen = (
        "Prüft nur die Existenz von Alert Processing Rules. Ob die Regeln Alarme "
        "sinnvoll routen (statt zu unterdrücken), wird nicht inhaltlich bewertet."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for sub_id in session.subscription_ids:
            try:
                from azure.mgmt.resource import ResourceManagementClient

                rm_client = session.get_client(ResourceManagementClient, sub_id)
                # Alert processing rules are under Microsoft.AlertsManagement/actionRules
                rules = list(
                    rm_client.resources.list(filter="resourceType eq 'Microsoft.AlertsManagement/actionRules'")
                )

                if rules:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Alert Processing Rules definiert",
                            description=(
                                f"Subscription {sub_id} hat {len(rules)} Alert Processing "
                                f"Rule(s) für die zentrale Alert-Verarbeitung."
                            ),
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.AlertsManagement/actionRules",
                            account_id=sub_id,
                            current_state={"alert_processing_rules": len(rules)},
                            expected_state="Mindestens eine Alert Processing Rule",
                            audit_evidence=f"resources.list() returned {len(rules)} alert processing rule(s)",
                            iso27001_control="A.5.25 Assessment and Decision on Events",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Alert Processing Rules",
                            description=(
                                f"Subscription {sub_id} hat keine Alert Processing Rules. Ohne "
                                "Alert Processing Rules fehlt eine zentrale Regelebene für "
                                "Priorisierung und Routing von Alerts."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.5.25 Assessment and Decision on Events",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.AZURE,
                            region="global",
                            resource_id=f"/subscriptions/{sub_id}",
                            resource_type="Microsoft.AlertsManagement/actionRules",
                            account_id=sub_id,
                            current_state={"alert_processing_rules": 0},
                            expected_state="Mindestens eine Alert Processing Rule",
                            remediation=(
                                "Erstellen Sie Alert Processing Rules: "
                                "Azure Portal → Monitor → Alerts → Alert processing rules → Create"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence="resources.list() returned 0 alert processing rules",
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
