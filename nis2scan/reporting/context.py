"""Shared Jinja2 render context for the Markdown and HTML report templates."""

from typing import Any

from nis2scan.engine.mapping.bsig_30 import BSIG_30_BY_NR
from nis2scan.engine.models.finding import Finding, FindingStatus, Severity
from nis2scan.engine.models.result import ScanResult
from nis2scan.reporting.labels import (
    ERFUELLUNGSGRAD_LABELS,
    FINDING_STATUS_LABELS,
    NIS2_CATEGORY_LABELS,
    OUTCOME_LABELS,
)
from nis2scan.reporting.pseudonymize import REPORT_PROFILE_LABELS, ReportProfile

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}


def build_report_context(result: ScanResult, profile: ReportProfile = ReportProfile.INTERN) -> dict[str, Any]:
    """Build the template context from a ScanResult.

    Splits findings into Mängel (non-compliant) and Positivnachweise
    (compliant, ADR-0006) and groups both by §30 area.
    """
    maengel_by_area: dict[int, list[Finding]] = {}
    positive_by_area: dict[int, list[Finding]] = {}
    for finding in result.findings:
        target = maengel_by_area if finding.status == FindingStatus.NON_COMPLIANT else positive_by_area
        target.setdefault(finding.bsig_30_nr, []).append(finding)

    for area_findings in maengel_by_area.values():
        area_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 5))

    # Coverage model (ADR-0009): scanned areas with their automatable partial
    # aspect and the manual attestation checklist; plus per-check known
    # limitations (ADR-0016 rule 2) with an honest count of undocumented ones.
    scanned_nrs = sorted({score.bsig_30_nr for score in result.summary.scores_by_area})
    attestierung_areas = [BSIG_30_BY_NR[nr] for nr in scanned_nrs if nr in BSIG_30_BY_NR]
    pruefgrenzen_entries = [e for e in result.check_outcomes if e.pruefgrenzen]
    pruefgrenzen_missing = len(result.check_outcomes) - len(pruefgrenzen_entries)

    company = result.config.company
    return {
        "result": result,
        "summary": result.summary,
        "config": result.config,
        "company": company,
        "findings_by_area": maengel_by_area,  # legacy alias, kept for template compatibility
        "maengel_by_area": maengel_by_area,
        "positive_by_area": positive_by_area,
        "check_outcomes": result.check_outcomes,
        "attestierung_areas": attestierung_areas,
        "pruefgrenzen_entries": pruefgrenzen_entries,
        "pruefgrenzen_missing": pruefgrenzen_missing,
        "bsig_areas": BSIG_30_BY_NR,
        "Severity": Severity,
        "erfuellungsgrad_labels": ERFUELLUNGSGRAD_LABELS,
        "outcome_labels": OUTCOME_LABELS,
        "finding_status_labels": FINDING_STATUS_LABELS,
        "nis2_category_label": NIS2_CATEGORY_LABELS.get(company.nis2_category, company.nis2_category),
        "report_profile_label": REPORT_PROFILE_LABELS.get(profile, str(profile)),
    }
