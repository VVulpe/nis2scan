"""§30 Abs. 2 Nr. 7 — Cyberhygiene und Cybersicherheitsschulungen checks for GCP.

Checks Organization Security Policies and Essential Contacts.
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

SECURITY_CONSTRAINTS = [
    "iam.disableServiceAccountKeyCreation",
    "compute.requireOsLogin",
    "storage.uniformBucketLevelAccess",
    "iam.disableServiceAccountKeyUpload",
    "compute.disableSerialPortAccess",
    "compute.disableNestedVirtualization",
    "sql.restrictPublicIp",
]


class CheckOrgSecurityPolicies(BaseCheck):
    """Prüft ob sicherheitsrelevante Organisationsrichtlinien gesetzt sind."""

    check_id = "GCP-NR7-001"
    title = "Sicherheitsrelevante Organisationsrichtlinien"
    description = (
        "Prüft ob Org Policy sicherheitsrelevante Einschränkungen wie "
        "Deaktivierung von Service-Account-Schlüsseln, OS Login-Pflicht "
        "und einheitliche Bucket-Zugriffssteuerung erzwingt."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["orgpolicy.policies.list"]
    pruefgrenzen = (
        "Prüft die Projekt-Policies gegen eine feste Liste sicherheitsrelevanter "
        "Constraints. Auf Organisationsebene gesetzte Policies, die nicht auf "
        "Projektebene sichtbar sind, können unerkannt bleiben."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("orgpolicy", "v2")
                result = service.projects().policies().list(parent=f"projects/{project_id}").execute()
                policies = result.get("policies", [])

                # Extract constraint names from policies that are actually enforced.
                # All SECURITY_CONSTRAINTS entries are boolean constraints, so a policy
                # only counts as active if at least one of its spec.rules has enforce=true.
                active_constraints = set()
                for policy in policies:
                    constraint_name = policy.get("name", "").split("/")[-1]
                    rules = policy.get("spec", {}).get("rules", [])
                    if any(rule.get("enforce") is True for rule in rules):
                        active_constraints.add(constraint_name)

                # Check which security constraints are present (exact match, not substring)
                found_security = [c for c in SECURITY_CONSTRAINTS if c in active_constraints]

                if found_security:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Sicherheitsrelevante Organisationsrichtlinien aktiv",
                            description=(
                                f"Projekt {project_id} erzwingt {len(found_security)} "
                                f"sicherheitsrelevante Org Policy Constraint(s): "
                                f"{', '.join(found_security)}."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/orgpolicies",
                            resource_type="gcp.orgpolicy.Policy",
                            account_id=project_id,
                            current_state={
                                "total_policies": len(policies),
                                "security_constraints_found": len(found_security),
                            },
                            expected_state=(
                                "Sicherheitsrelevante Org Policy Constraints wie "
                                "iam.disableServiceAccountKeyCreation, "
                                "compute.requireOsLogin und "
                                "storage.uniformBucketLevelAccess aktiviert"
                            ),
                            audit_evidence=(
                                f"policies.list() returned {len(policies)} policies, "
                                f"{len(found_security)} matching security constraints"
                            ),
                            iso27001_control="A.8.9 Konfigurationsmanagement",
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine sicherheitsrelevanten Organisationsrichtlinien",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "sicherheitsrelevanten Organization Policy Constraints "
                                "konfiguriert. Sicherheitsrelevante Organisationsrichtlinien "
                                "sind ein technischer Grundbaustein der Cyberhygiene in der "
                                "Cloud-Umgebung."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.8.9 Konfigurationsmanagement",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/orgpolicies",
                            resource_type="gcp.orgpolicy.Policy",
                            account_id=project_id,
                            current_state={
                                "total_policies": len(policies),
                                "security_constraints_found": 0,
                                "expected_constraints": SECURITY_CONSTRAINTS,
                            },
                            expected_state=(
                                "Sicherheitsrelevante Org Policy Constraints wie "
                                "iam.disableServiceAccountKeyCreation, "
                                "compute.requireOsLogin und "
                                "storage.uniformBucketLevelAccess aktiviert"
                            ),
                            remediation=(
                                "Setzen Sie sicherheitsrelevante Org Policies:\n"
                                "gcloud org-policies set-policy policy.yaml "
                                "--project=<PROJECT_ID>\n"
                                "Empfohlene Constraints:\n"
                                "- constraints/iam.disableServiceAccountKeyCreation\n"
                                "- constraints/compute.requireOsLogin\n"
                                "- constraints/storage.uniformBucketLevelAccess"
                            ),
                            remediation_effort="MEDIUM",
                            audit_evidence=(
                                f"policies.list() returned {len(policies)} policies, none matching security constraints"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)


class CheckEssentialContacts(BaseCheck):
    """Prüft ob Essential Contacts für Sicherheitsbenachrichtigungen konfiguriert sind."""

    check_id = "GCP-NR7-002"
    title = "Essential Contacts für Sicherheitsbenachrichtigungen"
    description = (
        "Prüft ob Essential Contacts mit der Kategorie SECURITY "
        "konfiguriert sind, um sicherheitsrelevante Benachrichtigungen "
        "an die zuständigen Personen zu senden."
    )
    bsig_30_nr = BSIG_30_NR
    provider = CloudProvider.GCP
    required_permissions = ["essentialcontacts.contacts.list"]
    pruefgrenzen = (
        "Prüft nur Essential Contacts der Kategorie SECURITY auf Projektebene. "
        "Organisationsweite Kontakte werden nicht geprüft."
    )

    async def execute(self, session: Any) -> CheckResult:
        findings: list[Finding] = []
        errors: list[CheckError] = []

        for project_id in session.project_ids:
            try:
                service = session.service("essentialcontacts", "v1")
                result = service.projects().contacts().list(parent=f"projects/{project_id}").execute()
                contacts = result.get("contacts", [])

                # Filter for SECURITY category contacts, then for ones with a confirmed email address
                security_contacts = [
                    c for c in contacts if "SECURITY" in c.get("notificationCategorySubscriptions", [])
                ]
                valid_security_contacts = [c for c in security_contacts if c.get("validationState") == "VALID"]

                expected_state = (
                    "Mindestens ein validierter Essential Contact (validationState=VALID) "
                    "mit der Kategorie SECURITY konfiguriert"
                )

                if valid_security_contacts:
                    findings.append(
                        compliant_finding(
                            self,
                            title="Sicherheits-Ansprechpartner konfiguriert",
                            description=(
                                f"Projekt {project_id} hat {len(valid_security_contacts)} validierte(n) "
                                f"Essential Contact(s) für die Kategorie SECURITY."
                            ),
                            region="global",
                            resource_id=f"projects/{project_id}/essentialcontacts",
                            resource_type="gcp.essentialcontacts.Contact",
                            account_id=project_id,
                            current_state={
                                "total_contacts": len(contacts),
                                "security_contacts": len(security_contacts),
                                "security_contacts_valid": len(valid_security_contacts),
                                "security_contacts_invalid": len(security_contacts) - len(valid_security_contacts),
                            },
                            expected_state=expected_state,
                            audit_evidence=(
                                f"contacts.list() returned {len(contacts)} contacts, "
                                f"{len(security_contacts)} with SECURITY category, "
                                f"{len(valid_security_contacts)} with validationState=VALID"
                            ),
                            iso27001_control="A.6.8 Meldung von Informationssicherheitsereignissen",
                        )
                    )
                elif security_contacts:
                    # SECURITY contacts exist, but none of them has a confirmed email address
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Sicherheits-Ansprechpartner nicht validiert",
                            description=(
                                f"Projekt {project_id} hat SECURITY-Kontakte, deren E-Mail-Adresse nicht als "
                                f"gültig bestätigt ist (validationState != VALID); die Zustellung kritischer "
                                f"Sicherheitsbenachrichtigungen ist nicht sichergestellt."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.6.8 Meldung von Informationssicherheitsereignissen",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/essentialcontacts",
                            resource_type="gcp.essentialcontacts.Contact",
                            account_id=project_id,
                            current_state={
                                "total_contacts": len(contacts),
                                "security_contacts": len(security_contacts),
                                "security_contacts_valid": 0,
                                "security_contacts_invalid": len(security_contacts),
                            },
                            expected_state=expected_state,
                            remediation=(
                                "Bestätigen Sie die E-Mail-Adresse des Essential Contact über den "
                                "Validierungs-Link in der Bestätigungs-E-Mail, oder legen Sie einen neuen "
                                "Kontakt an:\n"
                                "gcloud essential-contacts create "
                                "--email=security@example.com "
                                "--notification-categories=SECURITY "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(
                                f"contacts.list() returned {len(contacts)} contacts, "
                                f"{len(security_contacts)} with SECURITY category, "
                                f"0 with validationState=VALID"
                            ),
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            check_id=self.check_id,
                            title="Keine Sicherheits-Ansprechpartner konfiguriert",
                            description=(
                                f"Projekt {project_id} hat keine "
                                "Essential Contacts für die Kategorie SECURITY. "
                                "Ohne Sicherheits-Ansprechpartner werden kritische "
                                "Sicherheitsbenachrichtigungen nicht zugestellt."
                            ),
                            bsig_30_nr=BSIG_30_NR,
                            bsig_30_text=BSIG_30_TEXT,
                            iso27001_control="A.6.8 Meldung von Informationssicherheitsereignissen",
                            severity=Severity.MEDIUM,
                            provider=CloudProvider.GCP,
                            region="global",
                            resource_id=f"projects/{project_id}/essentialcontacts",
                            resource_type="gcp.essentialcontacts.Contact",
                            account_id=project_id,
                            current_state={
                                "total_contacts": len(contacts),
                                "security_contacts": 0,
                                "security_contacts_valid": 0,
                                "security_contacts_invalid": 0,
                            },
                            expected_state=expected_state,
                            remediation=(
                                "Fügen Sie einen Sicherheits-Ansprechpartner hinzu:\n"
                                "gcloud essential-contacts create "
                                "--email=security@example.com "
                                "--notification-categories=SECURITY "
                                "--project=<PROJECT_ID>"
                            ),
                            remediation_effort="LOW",
                            audit_evidence=(
                                f"contacts.list() returned {len(contacts)} contacts, none with SECURITY category"
                            ),
                        )
                    )
            except Exception as exc:
                errors.append(CheckError(message=str(exc), error_type=type(exc).__name__))

        return CheckResult(check_id=self.check_id, findings=findings, errors=errors)
