"""Tests for Findings-Exceptions (ADR-0026): loader, matching, expiry, engine annotation."""

from datetime import date
from pathlib import Path

import pytest

from nis2scan.engine.finding_exceptions import (
    ExceptionsFile,
    ExceptionsFileError,
    FindingExceptionRule,
    apply_exceptions,
    find_long_running_rules,
    load_exceptions_file,
)
from nis2scan.engine.models.finding import CloudProvider, Finding, FindingStatus, Severity


def _finding(
    check_id: str = "AWS-NR9-001",
    resource_id: str = "arn:aws:iam::123456789012:user/alice",
    account_id: str = "123456789012",
    region: str = "eu-central-1",
    status: FindingStatus = FindingStatus.NON_COMPLIANT,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        check_id=check_id,
        status=status,
        title="Testbefund",
        description="Testbeschreibung",
        bsig_30_nr=9,
        bsig_30_text="§30 Abs. 2 Nr. 9 BSIG",
        severity=severity,
        provider=CloudProvider.AWS,
        region=region,
        resource_id=resource_id,
        resource_type="AWS::IAM::User",
        account_id=account_id,
        expected_state="Soll-Zustand",
        remediation="Empfehlung",
        remediation_effort="LOW",
    )


def _rule(**overrides: object) -> FindingExceptionRule:
    defaults: dict[str, object] = {
        "check_id": "AWS-NR9-001",
        "resource_id": "arn:aws:iam::123456789012:user/alice",
        "reason": "Akzeptiertes Risiko, siehe SEC-123",
        "expires": date(2099, 1, 1),
    }
    defaults.update(overrides)
    return FindingExceptionRule.model_validate(defaults)


class TestLoadExceptionsFile:
    def test_valid_file_loads(self, tmp_path: Path):
        path = tmp_path / "exceptions.yaml"
        path.write_text(
            "version: 1\n"
            "exceptions:\n"
            "  - check_id: AWS-NR9-001\n"
            "    resource_id: arn:aws:iam::123456789012:user/alice\n"
            "    reason: Akzeptiertes Risiko\n"
            "    expires: 2099-01-01\n",
            encoding="utf-8",
        )

        result = load_exceptions_file(path)

        assert result.version == 1
        assert len(result.exceptions) == 1
        assert result.exceptions[0].check_id == "AWS-NR9-001"
        assert result.exceptions[0].expires == date(2099, 1, 1)

    def test_missing_required_field_raises_german_message(self, tmp_path: Path):
        path = tmp_path / "exceptions.yaml"
        path.write_text(
            "exceptions:\n"
            "  - check_id: AWS-NR9-001\n"
            "    resource_id: arn:aws:iam::123456789012:user/alice\n"
            "    reason: ok\n"
            "    expires: 2099-01-01\n"
            "  - check_id: AWS-NR9-002\n"
            "    resource_id: arn:aws:iam::123456789012:user/bob\n"
            "    reason: ok\n"
            "    expires: 2099-01-01\n"
            "  - check_id: AWS-NR9-003\n"
            "    resource_id: arn:aws:iam::123456789012:user/carol\n"
            "    reason: ok\n",  # entry 3 (index 2) is missing 'expires'
            encoding="utf-8",
        )

        with pytest.raises(ExceptionsFileError) as exc_info:
            load_exceptions_file(path)

        message = str(exc_info.value)
        assert "Eintrag 3" in message
        assert "expires" in message
        assert "Ausnahmen-Datei ungültig" in message

    def test_broken_yaml_raises(self, tmp_path: Path):
        path = tmp_path / "exceptions.yaml"
        path.write_text("exceptions: [this is: not: valid: yaml", encoding="utf-8")

        with pytest.raises(ExceptionsFileError):
            load_exceptions_file(path)

    def test_missing_file_raises(self, tmp_path: Path):
        with pytest.raises(ExceptionsFileError):
            load_exceptions_file(tmp_path / "does-not-exist.yaml")

    def test_non_mapping_root_raises(self, tmp_path: Path):
        path = tmp_path / "exceptions.yaml"
        path.write_text("- just\n- a\n- list\n", encoding="utf-8")

        with pytest.raises(ExceptionsFileError):
            load_exceptions_file(path)

    def test_empty_file_yields_no_exceptions(self, tmp_path: Path):
        path = tmp_path / "exceptions.yaml"
        path.write_text("", encoding="utf-8")

        result = load_exceptions_file(path)
        assert result.exceptions == []


class TestLongRunningWarning:
    def test_rule_over_12_months_is_flagged(self):
        today = date(2026, 7, 23)
        long_rule = _rule(expires=date(2028, 1, 1))
        short_rule = _rule(check_id="AWS-NR9-002", expires=date(2026, 12, 1))
        exceptions_file = ExceptionsFile(exceptions=[long_rule, short_rule])

        flagged = find_long_running_rules(exceptions_file, today)

        assert long_rule in flagged
        assert short_rule not in flagged

    def test_load_logs_warning_but_never_rejects(self, tmp_path: Path):
        # ADR-0026 decision 3: long runtime warns (Wiedervorlage), never rejected.
        path = tmp_path / "exceptions.yaml"
        path.write_text(
            "exceptions:\n"
            "  - check_id: AWS-NR9-001\n"
            "    resource_id: arn:aws:iam::123456789012:user/alice\n"
            "    reason: Langfristig akzeptiertes Risiko\n"
            "    expires: 2099-01-01\n",
            encoding="utf-8",
        )

        result = load_exceptions_file(path)
        assert len(result.exceptions) == 1


class TestRuleMatching:
    def test_exact_match(self):
        assert _rule().matches(_finding()) is True

    def test_no_match_different_check_id(self):
        assert _rule(check_id="AWS-NR9-999").matches(_finding()) is False

    def test_no_match_different_resource(self):
        rule = _rule(resource_id="arn:aws:iam::123456789012:user/other")
        assert rule.matches(_finding()) is False

    def test_account_id_narrows_match_mismatch(self):
        rule = _rule(account_id="999999999999")
        assert rule.matches(_finding(account_id="123456789012")) is False

    def test_account_id_narrows_match_hit(self):
        rule = _rule(account_id="123456789012")
        assert rule.matches(_finding(account_id="123456789012")) is True

    def test_region_narrows_match_mismatch(self):
        rule = _rule(region="eu-west-1")
        assert rule.matches(_finding(region="eu-central-1")) is False

    def test_region_narrows_match_hit(self):
        rule = _rule(region="eu-central-1")
        assert rule.matches(_finding(region="eu-central-1")) is True

    def test_unset_account_and_region_match_any(self):
        rule = _rule()  # account_id/region left unset on the rule
        finding = _finding(account_id="999999999999", region="us-east-1")
        assert rule.matches(finding) is True


class TestExpiry:
    def test_expired_rule_is_expired(self):
        rule = _rule(expires=date(2020, 1, 1))
        assert rule.is_expired(as_of=date(2026, 7, 23)) is True

    def test_future_rule_is_not_expired(self):
        rule = _rule(expires=date(2099, 1, 1))
        assert rule.is_expired(as_of=date(2026, 7, 23)) is False

    def test_rule_expiring_today_is_not_expired(self):
        # expires < as_of, so the due date itself is still covered.
        rule = _rule(expires=date(2026, 7, 23))
        assert rule.is_expired(as_of=date(2026, 7, 23)) is False


class TestApplyExceptions:
    def test_active_rule_annotates_non_compliant_finding(self):
        rule = _rule()
        exceptions_file = ExceptionsFile(exceptions=[rule])
        finding = _finding()

        result = apply_exceptions([finding], exceptions_file, scan_date=date(2026, 7, 23))

        assert result.applied_count == 1
        assert finding.exception is not None
        assert finding.exception.reason == rule.reason
        assert finding.exception.expires == rule.expires
        assert finding.expired_exception is None

    def test_compliant_finding_never_annotated(self):
        # ADR-0016 fail-safe: an exception may accept a defect, it can never
        # manufacture compliance — even a matching rule must not touch it.
        rule = _rule()
        exceptions_file = ExceptionsFile(exceptions=[rule])
        finding = _finding(status=FindingStatus.COMPLIANT, severity=Severity.INFO)

        result = apply_exceptions([finding], exceptions_file, scan_date=date(2026, 7, 23))

        assert result.applied_count == 0
        assert finding.exception is None
        assert finding.expired_exception is None

    def test_expired_rule_does_not_apply_but_is_reported(self):
        rule = _rule(expires=date(2026, 1, 1))  # expired relative to scan_date below
        exceptions_file = ExceptionsFile(exceptions=[rule])
        finding = _finding()

        result = apply_exceptions([finding], exceptions_file, scan_date=date(2026, 7, 23))

        assert result.applied_count == 0
        assert finding.exception is None
        assert finding.expired_exception is not None
        assert finding.expired_exception.expires == rule.expires
        assert len(result.expired_matches) == 1
        assert result.expired_matches[0].check_id == rule.check_id

    def test_no_match_leaves_finding_untouched(self):
        rule = _rule(resource_id="arn:aws:iam::123456789012:user/someone-else")
        exceptions_file = ExceptionsFile(exceptions=[rule])
        finding = _finding()

        result = apply_exceptions([finding], exceptions_file, scan_date=date(2026, 7, 23))

        assert result.applied_count == 0
        assert finding.exception is None
        assert finding.expired_exception is None
        assert result.expired_matches == []

    def test_multiple_findings_mixed(self):
        active_rule = _rule()
        expired_rule = _rule(
            check_id="AWS-NR9-002",
            resource_id="arn:aws:iam::123456789012:user/bob",
            expires=date(2020, 1, 1),
        )
        exceptions_file = ExceptionsFile(exceptions=[active_rule, expired_rule])

        f1 = _finding()
        f2 = _finding(check_id="AWS-NR9-002", resource_id="arn:aws:iam::123456789012:user/bob")
        f3 = _finding(check_id="AWS-NR9-003", resource_id="arn:aws:iam::123456789012:user/carol")

        result = apply_exceptions([f1, f2, f3], exceptions_file, scan_date=date(2026, 7, 23))

        assert result.applied_count == 1
        assert f1.exception is not None
        assert f2.exception is None
        assert f2.expired_exception is not None
        assert f3.exception is None
        assert f3.expired_exception is None
