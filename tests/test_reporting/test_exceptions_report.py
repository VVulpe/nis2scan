"""Report rendering tests for Findings-Exceptions (ADR-0026): the "Ausnahmen"
section, the "Abgelaufene Ausnahmen" hint, the dual-track Erfüllungsgrad
disclosure ("davon N per dokumentierter Ausnahme akzeptiert"), and the
report-layer derived effective view ("erfüllt (mit dokumentierten Ausnahmen)",
founder decision round 2)."""

from datetime import date

import pytest

from nis2scan.engine.models.check import CheckOutcome
from nis2scan.engine.models.config import CompanyInfo, ScanConfig
from nis2scan.engine.models.finding import CloudProvider, Finding, FindingExceptionInfo, FindingStatus, Severity
from nis2scan.engine.models.result import CheckOutcomeEntry, ScanResult
from nis2scan.engine.scanner import build_summary
from nis2scan.reporting.markdown import render_report
from nis2scan.reporting.pseudonymize import ReportProfile, apply_profile


def _finding(resource_id: str, status: FindingStatus = FindingStatus.NON_COMPLIANT) -> Finding:
    return Finding(
        check_id="AWS-NR9-001",
        status=status,
        title="IAM-Benutzer ohne MFA",
        description="Testbeschreibung",
        bsig_30_nr=9,
        bsig_30_text="§30 Abs. 2 Nr. 9 BSIG",
        severity=Severity.HIGH if status == FindingStatus.NON_COMPLIANT else Severity.INFO,
        provider=CloudProvider.AWS,
        region="eu-central-1",
        resource_id=resource_id,
        resource_type="AWS::IAM::User",
        account_id="123456789012",
        expected_state="MFA aktiviert",
        remediation="MFA aktivieren",
        remediation_effort="LOW",
    )


@pytest.fixture
def scan_result_with_exception() -> ScanResult:
    excepted = _finding("arn:aws:iam::123456789012:user/alice")
    excepted.exception = FindingExceptionInfo(
        reason="Break-Glass-Account, siehe SEC-42", expires=date(2099, 1, 1), author="vladi", ticket="SEC-42"
    )
    findings = [excepted]
    entries = [
        CheckOutcomeEntry(
            check_id="AWS-NR9-001", title="MFA-Check", provider="AWS", bsig_30_nr=9, outcome=CheckOutcome.FAILED
        )
    ]
    return ScanResult(
        scan_id="test-scan",
        config=ScanConfig(company=CompanyInfo(name="Testfirma GmbH")),
        summary=build_summary(findings, [9], entries),
        findings=findings,
        check_outcomes=entries,
    )


@pytest.fixture
def scan_result_with_expired_exception() -> ScanResult:
    expired = _finding("arn:aws:iam::123456789012:user/bob")
    expired.expired_exception = FindingExceptionInfo(reason="Alte Ausnahme", expires=date(2020, 1, 1))
    findings = [expired]
    entries = [
        CheckOutcomeEntry(
            check_id="AWS-NR9-001", title="MFA-Check", provider="AWS", bsig_30_nr=9, outcome=CheckOutcome.FAILED
        )
    ]
    return ScanResult(
        scan_id="test-scan",
        config=ScanConfig(company=CompanyInfo(name="Testfirma GmbH")),
        summary=build_summary(findings, [9], entries),
        findings=findings,
        check_outcomes=entries,
    )


@pytest.fixture
def scan_result_without_exceptions() -> ScanResult:
    findings = [_finding("arn:aws:iam::123456789012:user/carol")]
    entries = [
        CheckOutcomeEntry(
            check_id="AWS-NR9-001", title="MFA-Check", provider="AWS", bsig_30_nr=9, outcome=CheckOutcome.FAILED
        )
    ]
    return ScanResult(
        scan_id="test-scan",
        config=ScanConfig(company=CompanyInfo(name="Testfirma GmbH")),
        summary=build_summary(findings, [9], entries),
        findings=findings,
        check_outcomes=entries,
    )


class TestAusnahmenSection:
    def test_section_header_present(self, scan_result_with_exception):
        report = render_report(scan_result_with_exception)
        assert "### Ausnahmen" in report

    def test_excepted_finding_listed_with_details(self, scan_result_with_exception):
        report = render_report(scan_result_with_exception)

        assert "AWS-NR9-001" in report
        assert "arn:aws:iam::123456789012:user/alice" in report
        assert "Break-Glass-Account, siehe SEC-42" in report
        assert "01.01.2099" in report
        assert "vladi" in report
        assert "SEC-42" in report

    def test_no_exceptions_shows_placeholder_text(self, scan_result_without_exceptions):
        report = render_report(scan_result_without_exceptions)

        assert "Keine dokumentierten Ausnahmen angewendet." in report

    def test_excepted_finding_still_listed_as_open_defect(self, scan_result_with_exception):
        # ADR-0026 decision 4: transparency, not suppression — the Mangel
        # still appears under "Mängel nach §30-Bereich".
        report = render_report(scan_result_with_exception)

        assert "Mängel nach §30-Bereich" in report
        assert "IAM-Benutzer ohne MFA" in report


class TestAbgelaufeneAusnahmen:
    def test_expired_block_appears_when_present(self, scan_result_with_expired_exception):
        report = render_report(scan_result_with_expired_exception)

        assert "Abgelaufene Ausnahmen" in report
        assert "arn:aws:iam::123456789012:user/bob" in report
        assert "Alte Ausnahme" in report
        assert "01.01.2020" in report
        # F5 (legal review): same column label as the active table — on the
        # expires day itself the exception still applies.
        assert "Befristet bis" in report
        assert "Abgelaufen am" not in report

    def test_expired_block_absent_without_expired_exceptions(self, scan_result_with_exception):
        report = render_report(scan_result_with_exception)
        assert "Abgelaufene Ausnahmen" not in report


class TestDualTrackErfuellungsgrad:
    def test_executive_summary_shows_accepted_count(self, scan_result_with_exception):
        report = render_report(scan_result_with_exception)

        assert "davon per dokumentierter Ausnahme akzeptiert" in report
        # Mängel gesamt still counts the excepted finding in full.
        assert "| **Mängel gesamt** | 1 |" in report

    def test_no_accepted_line_without_exceptions(self, scan_result_without_exceptions):
        report = render_report(scan_result_without_exceptions)
        assert "davon per dokumentierter Ausnahme akzeptiert" not in report

    def test_compliance_matrix_shows_exception_column(self, scan_result_with_exception):
        report = render_report(scan_result_with_exception)
        assert "davon Ausnahme" in report


class TestExternProfilePseudonymizesResourceIdInExceptionSection:
    def test_resource_id_pseudonymized_reason_untouched(self, scan_result_with_exception):
        # Known limitation (ADR-0026, documented in pseudonymize.py): the
        # exception's free-text reason is NOT scrubbed, only the finding's own
        # resource_id/account_id (which the Ausnahmen table also displays).
        report = render_report(scan_result_with_exception, ReportProfile.EXTERN)

        assert "arn:aws:iam::123456789012:user/alice" not in report
        assert "Break-Glass-Account, siehe SEC-42" in report

    def test_extern_reduces_config_exceptions_path_to_filename(self, scan_result_with_exception):
        # F3b (legal review): a full local path often contains the operator's
        # OS user name — it must not leave the organization via EXTERN JSON.
        scan_result_with_exception.config.exceptions_path = "/home/vulpe/privat/exceptions.yaml"

        extern = apply_profile(scan_result_with_exception, ReportProfile.EXTERN)

        assert extern.config.exceptions_path == "exceptions.yaml"
        # The internal (raw) result keeps the full path for traceability.
        assert scan_result_with_exception.config.exceptions_path == "/home/vulpe/privat/exceptions.yaml"


def _result(findings: list[Finding], entries: list[CheckOutcomeEntry], scope: list[int]) -> ScanResult:
    return ScanResult(
        scan_id="test-scan",
        config=ScanConfig(company=CompanyInfo(name="Testfirma GmbH")),
        summary=build_summary(findings, scope, entries),
        findings=findings,
        check_outcomes=entries,
    )


def _entry(nr: int, outcome: CheckOutcome, error_count: int = 0, check_id: str = "") -> CheckOutcomeEntry:
    return CheckOutcomeEntry(
        check_id=check_id or f"AWS-NR{nr}-001",
        title="Testcheck",
        provider="AWS",
        bsig_30_nr=nr,
        outcome=outcome,
        error_count=error_count,
    )


class TestZusatzsicht:
    """Report-layer derived Zusatzsicht (ADR-0026 Nachtrag, legal review F1):
    strict counts stay untouched; the additional view is display-only,
    fail-safe, and never reuses the reserved ordinal label as a rating."""

    ZEILE = "Zusatzsicht: Bereiche strikt erfüllt oder alle Mängel per dokumentierter Ausnahme akzeptiert"
    FUSSNOTE_START = (
        "Zusatzsicht: Sämtliche Mängel dieses Bereichs sind durch aktive dokumentierte Ausnahmen akzeptiert"
    )
    FUSSNOTE_ENDE = "eine Ausnahme beseitigt den Mangel nicht, sie dokumentiert seine Akzeptanz."

    def test_zusatzsicht_line_when_all_maengel_excepted(self, scan_result_with_exception):
        report = render_report(scan_result_with_exception)

        assert self.ZEILE in report
        assert "1 von 1 (davon 0 strikt erfüllt)" in report
        # The strict rating stays visible and unchanged.
        assert "Nicht erfüllt" in report

    def test_matrix_footnote_for_zusatzsicht_area(self, scan_result_with_exception):
        report = render_report(scan_result_with_exception)

        assert self.FUSSNOTE_START in report
        assert "(Risikoentscheidung der Einrichtung)" in report
        assert self.FUSSNOTE_ENDE in report
        # Avoid the German typographic quotes in the assertion (encoding-safe):
        assert "Die strikte Bewertung in der Spalte" in report

    def test_zusatzsicht_absent_without_exceptions(self, scan_result_without_exceptions):
        report = render_report(scan_result_without_exceptions)

        assert "Zusatzsicht" not in report

    def test_zusatzsicht_absent_with_only_expired_exceptions(self, scan_result_with_expired_exception):
        # An expired exception is not an applied exception — no Zusatzsicht.
        report = render_report(scan_result_with_expired_exception)

        assert "Zusatzsicht" not in report

    def test_open_defect_without_exception_blocks_area(self):
        excepted = _finding("arn:aws:iam::123456789012:user/alice")
        excepted.exception = FindingExceptionInfo(reason="ok", expires=date(2099, 1, 1))
        open_defect = _finding("arn:aws:iam::123456789012:user/bob")
        result = _result([excepted, open_defect], [_entry(9, CheckOutcome.FAILED)], [9])

        report = render_report(result)

        # Line shows (an exception was applied) but the area is NOT counted.
        assert "0 von 1 (davon 0 strikt erfüllt)" in report
        assert self.FUSSNOTE_START not in report

    def test_check_error_in_area_blocks_area(self):
        # Fail-safe (ADR-0016): errors must never appear covered by exceptions.
        excepted = _finding("arn:aws:iam::123456789012:user/alice")
        excepted.exception = FindingExceptionInfo(reason="ok", expires=date(2099, 1, 1))
        entries = [
            _entry(9, CheckOutcome.FAILED),
            _entry(9, CheckOutcome.ERROR, error_count=1, check_id="AWS-NR9-002"),
        ]
        result = _result([excepted], entries, [9])

        report = render_report(result)

        assert "0 von 1 (davon 0 strikt erfüllt)" in report
        assert self.FUSSNOTE_START not in report

    def test_error_count_on_failed_check_blocks_area(self):
        # Even a FAILED check carrying errors (defect wins over error in
        # derive_outcome) keeps the strict view alone — partial evaluation
        # plus exceptions must never surface in the Zusatzsicht.
        excepted = _finding("arn:aws:iam::123456789012:user/alice")
        excepted.exception = FindingExceptionInfo(reason="ok", expires=date(2099, 1, 1))
        result = _result([excepted], [_entry(9, CheckOutcome.FAILED, error_count=1)], [9])

        report = render_report(result)

        assert "0 von 1 (davon 0 strikt erfüllt)" in report
        assert self.FUSSNOTE_START not in report

    def test_strictly_erfuellt_areas_counted_alongside(self):
        excepted = _finding("arn:aws:iam::123456789012:user/alice")
        excepted.exception = FindingExceptionInfo(reason="ok", expires=date(2099, 1, 1))
        entries = [_entry(1, CheckOutcome.PASSED), _entry(9, CheckOutcome.FAILED)]
        result = _result([excepted], entries, [1, 9])

        report = render_report(result)

        assert "2 von 2 (davon 1 strikt erfüllt)" in report


class TestExternHinweisFreitext:
    """EXTERN profile hint (legal review F3 on the pseudonymization boundary)."""

    HINT = (
        "Hinweis: Vermerk, Autor und Ticket stammen unverändert aus der Ausnahmen-Datei der Einrichtung "
        "und werden bei der Pseudonymisierung nicht verändert. Personenbezogene Angaben (z. B. Klarnamen "
        "im Autor-Feld) und Ressourcen-Bezeichner im Vermerk erscheinen daher auch in diesem externen "
        "Report im Klartext."
    )

    def test_hint_shown_in_extern_profile(self, scan_result_with_exception):
        report = render_report(scan_result_with_exception, ReportProfile.EXTERN)
        assert self.HINT in report

    def test_hint_absent_in_intern_profile(self, scan_result_with_exception):
        report = render_report(scan_result_with_exception, ReportProfile.INTERN)
        assert self.HINT not in report

    def test_hint_absent_in_extern_without_exceptions(self, scan_result_without_exceptions):
        report = render_report(scan_result_without_exceptions, ReportProfile.EXTERN)
        assert self.HINT not in report

    def test_hint_shown_in_extern_with_only_expired_exceptions(self, scan_result_with_expired_exception):
        # The expired table also prints free-text Vermerke — hint applies too.
        report = render_report(scan_result_with_expired_exception, ReportProfile.EXTERN)
        assert self.HINT in report
