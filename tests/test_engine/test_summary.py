"""Tests for build_summary — Erfüllungsgrad aggregation and check counts (ADR-0007/0008/0016)."""

from datetime import date

from nis2scan.engine.models.check import CheckOutcome
from nis2scan.engine.models.finding import CloudProvider, Finding, FindingExceptionInfo, FindingStatus, Severity
from nis2scan.engine.models.result import CheckOutcomeEntry, Erfuellungsgrad
from nis2scan.engine.scanner import build_summary


def _finding(
    nr: int, severity: Severity = Severity.HIGH, status: FindingStatus = FindingStatus.NON_COMPLIANT
) -> Finding:
    return Finding(
        check_id=f"AWS-NR{nr}-001",
        status=status,
        title="Testbefund",
        description="Testbeschreibung",
        bsig_30_nr=nr,
        bsig_30_text=f"§30 Abs. 2 Nr. {nr} BSIG",
        severity=severity,
        provider=CloudProvider.AWS,
        region="eu-central-1",
        resource_id="arn:aws:s3:::test-bucket",
        resource_type="AWS::S3::Bucket",
        account_id="123456789012",
        expected_state="Soll-Zustand",
        remediation="Empfehlung",
        remediation_effort="LOW",
    )


def _entry(nr: int, outcome: CheckOutcome, errors: int = 0) -> CheckOutcomeEntry:
    return CheckOutcomeEntry(
        check_id=f"AWS-NR{nr}-00{nr}",
        title="Testcheck",
        provider="AWS",
        bsig_30_nr=nr,
        outcome=outcome,
        error_count=errors,
    )


class TestErfuellungsgradGesamt:
    def test_all_areas_passed_is_erfuellt(self):
        entries = [_entry(1, CheckOutcome.PASSED), _entry(2, CheckOutcome.PASSED)]
        summary = build_summary([], [1, 2], entries)

        assert summary.erfuellungsgrad_gesamt == Erfuellungsgrad.ERFUELLT
        assert summary.overall_status == "COMPLIANT"

    def test_not_applicable_counted_separately(self):
        # NA checks (no Prüfobjekte) never inflate the denominator silently:
        # 1 passed + 6 NA is "1/1 applicable passed", not "1/7"
        entries = [_entry(8, CheckOutcome.PASSED)] + [_entry(8, CheckOutcome.NOT_APPLICABLE) for _ in range(6)]
        summary = build_summary([], [8], entries)

        assert summary.total_checks == 7
        assert summary.not_applicable_checks == 6
        area = summary.scores_by_area[0]
        assert area.not_applicable_checks == 6
        assert area.total_checks - area.not_applicable_checks == 1
        # the evaluable partial aspect passed — ERFUELLT stays correct
        assert area.erfuellungsgrad == Erfuellungsgrad.ERFUELLT

    def test_all_not_applicable_is_nicht_bewertbar(self):
        entries = [_entry(8, CheckOutcome.NOT_APPLICABLE) for _ in range(3)]
        summary = build_summary([], [8], entries)

        assert summary.scores_by_area[0].erfuellungsgrad == Erfuellungsgrad.NICHT_BEWERTBAR

    def test_errors_never_upgrade_to_erfuellt(self):
        # ADR-0016: an errored check must not count as fulfilled — Lacework problem.
        entries = [_entry(1, CheckOutcome.PASSED), _entry(2, CheckOutcome.ERROR, errors=1)]
        summary = build_summary([], [1, 2], entries)

        assert summary.erfuellungsgrad_gesamt == Erfuellungsgrad.TEILWEISE_ERFUELLT
        assert summary.error_checks == 1
        assert summary.overall_status != "COMPLIANT"

    def test_all_errors_is_nicht_bewertbar(self):
        entries = [_entry(1, CheckOutcome.ERROR, errors=1), _entry(2, CheckOutcome.ERROR, errors=2)]
        summary = build_summary([], [1, 2], entries)

        assert summary.erfuellungsgrad_gesamt == Erfuellungsgrad.NICHT_BEWERTBAR
        # Legacy field is fail-safe: unknown never reads as compliant.
        assert summary.overall_status == "NON_COMPLIANT"

    def test_all_areas_failed_is_nicht_erfuellt(self):
        entries = [_entry(1, CheckOutcome.FAILED), _entry(2, CheckOutcome.FAILED)]
        findings = [_finding(1), _finding(2)]
        summary = build_summary(findings, [1, 2], entries)

        assert summary.erfuellungsgrad_gesamt == Erfuellungsgrad.NICHT_ERFUELLT
        assert summary.overall_status == "NON_COMPLIANT"

    def test_mixed_areas_is_teilweise_erfuellt(self):
        entries = [_entry(1, CheckOutcome.PASSED), _entry(2, CheckOutcome.FAILED)]
        summary = build_summary([_finding(2)], [1, 2], entries)

        assert summary.erfuellungsgrad_gesamt == Erfuellungsgrad.TEILWEISE_ERFUELLT
        assert summary.overall_status == "PARTIALLY_COMPLIANT"

    def test_empty_scan_is_nicht_bewertbar(self):
        summary = build_summary([], [], [])

        assert summary.erfuellungsgrad_gesamt == Erfuellungsgrad.NICHT_BEWERTBAR
        assert summary.total_checks == 0


class TestCheckCounts:
    def test_counts_by_outcome(self):
        entries = [
            _entry(1, CheckOutcome.PASSED),
            _entry(1, CheckOutcome.PASSED),
            _entry(2, CheckOutcome.FAILED),
            _entry(3, CheckOutcome.ERROR, errors=1),
            _entry(4, CheckOutcome.NOT_IN_SCOPE),
        ]
        summary = build_summary([_finding(2)], [1, 2, 3, 4], entries)

        assert summary.total_checks == 5
        assert summary.passed_checks == 2
        assert summary.failed_checks == 1
        assert summary.error_checks == 1

    def test_per_area_error_visible(self):
        entries = [_entry(3, CheckOutcome.ERROR, errors=2)]
        summary = build_summary([], [3], entries)

        area = summary.scores_by_area[0]
        assert area.error_checks == 1
        assert area.erfuellungsgrad == Erfuellungsgrad.NICHT_BEWERTBAR


class TestFindingStatusSeparation:
    def test_compliant_findings_not_counted_as_maengel(self):
        # ADR-0006: positive evidence must not inflate defect statistics.
        findings = [
            _finding(1, Severity.HIGH, FindingStatus.NON_COMPLIANT),
            _finding(1, Severity.HIGH, FindingStatus.COMPLIANT),
            _finding(1, Severity.CRITICAL, FindingStatus.COMPLIANT),
        ]
        entries = [_entry(1, CheckOutcome.FAILED)]
        summary = build_summary(findings, [1], entries)

        assert summary.total_findings == 1
        assert summary.compliant_count == 2
        assert summary.high_count == 1
        assert summary.critical_count == 0  # the CRITICAL finding is compliant evidence
        area = summary.scores_by_area[0]
        assert area.critical_count == 0


class TestExceptionsAcceptedCount:
    """ADR-0026: additive second-track disclosure — existing counts unchanged."""

    def test_accepted_exception_counted_additively_not_subtracted(self):
        excepted = _finding(1)
        excepted.exception = FindingExceptionInfo(reason="Akzeptiertes Risiko", expires=date(2099, 1, 1))
        open_finding = _finding(1)
        entries = [_entry(1, CheckOutcome.FAILED)]

        summary = build_summary([excepted, open_finding], [1], entries)

        # Existing counts are NOT redefined by exceptions (ADR-0026 decision 4).
        assert summary.total_findings == 2
        assert summary.high_count == 2
        assert summary.scores_by_area[0].failed_checks == 1
        # Additive second-track count.
        assert summary.exceptions_accepted_count == 1
        assert summary.scores_by_area[0].exceptions_accepted_count == 1

    def test_no_exceptions_defaults_to_zero(self):
        summary = build_summary([_finding(1)], [1], [_entry(1, CheckOutcome.FAILED)])

        assert summary.exceptions_accepted_count == 0
        assert summary.scores_by_area[0].exceptions_accepted_count == 0

    def test_accepted_count_split_per_area(self):
        f1 = _finding(1)
        f1.exception = FindingExceptionInfo(reason="ok", expires=date(2099, 1, 1))
        f2 = _finding(2)  # not excepted
        entries = [_entry(1, CheckOutcome.FAILED), _entry(2, CheckOutcome.FAILED)]

        summary = build_summary([f1, f2], [1, 2], entries)

        by_nr = {s.bsig_30_nr: s.exceptions_accepted_count for s in summary.scores_by_area}
        assert by_nr[1] == 1
        assert by_nr[2] == 0
        assert summary.exceptions_accepted_count == 1
