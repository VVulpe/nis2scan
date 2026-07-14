"""Tests for export-time pseudonymization (ADR-0011)."""

import pytest

from nis2scan.engine.models.config import ScanConfig
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity
from nis2scan.engine.models.result import ScanResult
from nis2scan.reporting.markdown import render_report
from nis2scan.reporting.pseudonymize import (
    ReportProfile,
    apply_profile,
    pseudonymize_result,
)


def _finding() -> Finding:
    return Finding(
        check_id="AWS-NR9-001",
        title="IAM-Benutzer ohne MFA",
        description=("Der IAM-Benutzer 'alice-admin' hat keine MFA-Authentifizierung konfiguriert."),
        bsig_30_nr=9,
        bsig_30_text="§30 Abs. 2 Nr. 9 BSIG",
        severity=Severity.HIGH,
        provider=CloudProvider.AWS,
        region="global",
        resource_id="arn:aws:iam::123456789012:user/alice-admin",
        resource_type="AWS::IAM::User",
        account_id="123456789012",
        current_state={
            "mfa_enabled": False,
            "user_name": "alice-admin",
            "sse_algorithm": "aws:kms",
            "key_age_days": 93,
        },
        expected_state="MFA aktiviert",
        remediation="Aktivieren Sie MFA für den IAM-Benutzer alice-admin.",
        remediation_effort="LOW",
        audit_evidence="ListMFADevices returned 0 devices for user alice-admin",
    )


def _result() -> ScanResult:
    return ScanResult(scan_id="test", config=ScanConfig(), findings=[_finding()])


class TestPseudonymizeResult:
    def test_identifiers_replaced_everywhere(self):
        pseudonymized = pseudonymize_result(_result())
        f = pseudonymized.findings[0]

        assert "alice-admin" not in f.resource_id
        assert "123456789012" not in f.resource_id
        assert "123456789012" not in f.account_id
        assert "alice-admin" not in f.description
        assert "alice-admin" not in f.remediation
        assert "alice-admin" not in f.audit_evidence
        assert f.current_state["user_name"].startswith("pseu_")

    def test_non_identifying_evidence_untouched(self):
        pseudonymized = pseudonymize_result(_result())
        f = pseudonymized.findings[0]

        assert f.current_state["mfa_enabled"] is False
        assert f.current_state["key_age_days"] == 93
        # Technical constants under non-identifying keys stay readable.
        assert f.current_state["sse_algorithm"] == "aws:kms"

    def test_original_not_mutated(self):
        original = _result()
        pseudonymize_result(original)

        assert "alice-admin" in original.findings[0].description
        assert original.findings[0].current_state["user_name"] == "alice-admin"

    def test_deterministic_pseudonyms(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.setenv("NIS2SCAN_SECRET", "test-secret")
        first = pseudonymize_result(_result()).findings[0]
        second = pseudonymize_result(_result()).findings[0]

        assert first.resource_id == second.resource_id
        assert first.current_state["user_name"] == second.current_state["user_name"]

    def test_keyed_differs_from_unkeyed(self, monkeypatch: pytest.MonkeyPatch):
        monkeypatch.delenv("NIS2SCAN_SECRET", raising=False)
        unkeyed = pseudonymize_result(_result()).findings[0]
        monkeypatch.setenv("NIS2SCAN_SECRET", "test-secret")
        keyed = pseudonymize_result(_result()).findings[0]

        assert keyed.account_id != unkeyed.account_id

    def test_same_identifier_gets_same_pseudonym_within_finding(self):
        f = pseudonymize_result(_result()).findings[0]
        user_pseudonym = f.current_state["user_name"]

        assert user_pseudonym in f.description
        assert user_pseudonym in f.audit_evidence


class TestApplyProfile:
    def test_intern_passthrough(self):
        result = _result()
        assert apply_profile(result, ReportProfile.INTERN) is result

    def test_extern_pseudonymizes(self):
        result = apply_profile(_result(), ReportProfile.EXTERN)
        assert "alice-admin" not in result.findings[0].description

    def test_profile_marker_stamped(self):
        # Schema 1.0: stored/exported JSON is self-describing (ADR-0011).
        intern = apply_profile(_result(), ReportProfile.INTERN)
        extern = apply_profile(_result(), ReportProfile.EXTERN)
        assert intern.report_profile == "intern"
        assert extern.report_profile == "extern"


class TestReportIntegration:
    def test_extern_markdown_contains_no_raw_identifiers(self):
        report = render_report(_result(), ReportProfile.EXTERN)

        assert "alice-admin" not in report
        assert "pseu_" in report
        assert "Extern (pseudonymisiert)" in report

    def test_intern_markdown_contains_raw_identifiers(self):
        report = render_report(_result(), ReportProfile.INTERN)

        assert "alice-admin" in report
        assert "Intern (Klardaten)" in report
