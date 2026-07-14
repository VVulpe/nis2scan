"""Positive-evidence helper (ADR-0006).

A compliant Prüfobjekt is first-class evidence, not just the absence of a
defect. Checks call compliant_finding() for every object that passed, so the
report can list belastbare Positivnachweise per §30 area.
"""

from typing import Any

from nis2scan.engine.mapping.bsig_30 import BSIG_30_BY_NR
from nis2scan.engine.models.check import BaseCheck
from nis2scan.engine.models.finding import Finding, FindingStatus, Severity


def compliant_finding(
    check: BaseCheck,
    *,
    title: str,
    description: str,
    region: str,
    resource_id: str,
    resource_type: str,
    account_id: str,
    expected_state: str,
    audit_evidence: str,
    current_state: dict[str, Any] | None = None,
    iso27001_control: str | None = None,
) -> Finding:
    """Build a COMPLIANT finding as positive evidence for one Prüfobjekt.

    Severity is INFO by definition — compliant findings never count towards
    defect statistics (build_summary separates them per ADR-0006).
    """
    area = BSIG_30_BY_NR.get(check.bsig_30_nr)
    bsig_30_text = f"§30 Abs. 2 Nr. {check.bsig_30_nr} BSIG — {area.law_text_de}" if area else ""
    return Finding(
        check_id=check.check_id,
        status=FindingStatus.COMPLIANT,
        title=title,
        description=description,
        bsig_30_nr=check.bsig_30_nr,
        bsig_30_text=bsig_30_text,
        iso27001_control=iso27001_control,
        severity=Severity.INFO,
        provider=check.provider,
        region=region,
        resource_id=resource_id,
        resource_type=resource_type,
        account_id=account_id,
        current_state=current_state or {},
        expected_state=expected_state,
        remediation="Keine Maßnahme erforderlich — Anforderung erfüllt.",
        remediation_effort="LOW",
        audit_evidence=audit_evidence,
    )
