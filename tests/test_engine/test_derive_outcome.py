"""Tests for derive_outcome (ADR-0007) incl. fail-safe empty-result semantics (ADR-0016)."""

from nis2scan.engine.models.check import CheckError, CheckOutcome, CheckResult, derive_outcome
from nis2scan.engine.models.finding import CloudProvider, Finding, FindingStatus, Severity


def _finding(status: FindingStatus) -> Finding:
    return Finding(
        check_id="TST-NR1-001",
        title="Testfeststellung",
        description="Testbeschreibung",
        bsig_30_nr=1,
        bsig_30_text="§30 Abs. 2 Nr. 1 BSIG",
        severity=Severity.INFO if status == FindingStatus.COMPLIANT else Severity.HIGH,
        status=status,
        provider=CloudProvider.AWS,
        region="eu-central-1",
        resource_id="resource-1",
        resource_type="test.Resource",
        account_id="000000000000",
        current_state={},
        expected_state="Erwarteter Zustand",
        remediation="Keine" if status == FindingStatus.COMPLIANT else "Beheben",
        remediation_effort="LOW",
        audit_evidence="evidence",
    )


def test_skipped_yields_not_in_scope():
    result = CheckResult(check_id="TST-NR1-001", skipped=True, skip_reason="excluded")

    assert derive_outcome(result) == CheckOutcome.NOT_IN_SCOPE


def test_non_compliant_finding_yields_failed():
    result = CheckResult(check_id="TST-NR1-001", findings=[_finding(FindingStatus.NON_COMPLIANT)])

    assert derive_outcome(result) == CheckOutcome.FAILED


def test_defect_wins_over_error():
    result = CheckResult(
        check_id="TST-NR1-001",
        findings=[_finding(FindingStatus.NON_COMPLIANT)],
        errors=[CheckError(message="boom")],
    )

    assert derive_outcome(result) == CheckOutcome.FAILED


def test_error_wins_over_positive_evidence():
    # ADR-0016: partial evidence plus an error is never PASSED
    result = CheckResult(
        check_id="TST-NR1-001",
        findings=[_finding(FindingStatus.COMPLIANT)],
        errors=[CheckError(message="boom")],
    )

    assert derive_outcome(result) == CheckOutcome.ERROR


def test_compliant_findings_yield_passed():
    result = CheckResult(check_id="TST-NR1-001", findings=[_finding(FindingStatus.COMPLIANT)])

    assert derive_outcome(result) == CheckOutcome.PASSED


def test_empty_result_yields_not_applicable():
    # Post positive-evidence migration (ADR-0006): empty means zero
    # Prüfobjekte evaluated — never PASSED (ADR-0016)
    result = CheckResult(check_id="TST-NR1-001")

    assert derive_outcome(result) == CheckOutcome.NOT_APPLICABLE
