"""Tests for core Pydantic models."""

from datetime import UTC

import pytest

from nis2scan.engine.models.config import ScanConfig
from nis2scan.engine.models.finding import CloudProvider, Finding, Severity
from nis2scan.engine.models.result import ScanResult


class TestFinding:
    """Tests for the Finding model."""

    def test_finding_creation(self):
        finding = Finding(
            check_id="AWS-NR8-001",
            title="Test Finding",
            description="Test description",
            bsig_30_nr=8,
            bsig_30_text="§30 Abs. 2 Nr. 8 BSIG",
            severity=Severity.HIGH,
            provider=CloudProvider.AWS,
            region="eu-central-1",
            resource_id="arn:aws:s3:::test-bucket",
            resource_type="AWS::S3::Bucket",
            account_id="123456789012",
            expected_state="Encrypted",
            remediation="Enable encryption",
            remediation_effort="LOW",
        )

        assert finding.check_id == "AWS-NR8-001"
        assert finding.severity == Severity.HIGH
        assert finding.bsig_30_nr == 8

    def test_finding_bsig_range_validation(self):
        with pytest.raises(ValueError):
            Finding(
                check_id="TEST",
                title="Test",
                description="Test",
                bsig_30_nr=11,  # Invalid: must be 1-10
                bsig_30_text="Test",
                severity=Severity.LOW,
                provider=CloudProvider.AWS,
                region="us-east-1",
                resource_id="test",
                resource_type="test",
                account_id="123",
                expected_state="test",
                remediation="test",
                remediation_effort="LOW",
            )

    def test_finding_serialization(self):
        finding = Finding(
            check_id="AWS-NR8-001",
            title="Test",
            description="Test",
            bsig_30_nr=8,
            bsig_30_text="§30 Abs. 2 Nr. 8",
            severity=Severity.CRITICAL,
            provider=CloudProvider.AWS,
            region="eu-central-1",
            resource_id="test-arn",
            resource_type="AWS::S3::Bucket",
            account_id="123456789012",
            expected_state="Encrypted",
            remediation="Fix it",
            remediation_effort="LOW",
        )

        data = finding.model_dump()
        assert data["severity"] == "CRITICAL"
        assert data["provider"] == "AWS"

    def test_finding_timestamp_is_timezone_aware(self):
        """Fail-safe hotfix bonus fix: default_factory used to be datetime.utcnow
        (naive), the source of 441 DeprecationWarnings across the test suite."""
        finding = Finding(
            check_id="AWS-NR8-001",
            title="Test",
            description="Test",
            bsig_30_nr=8,
            bsig_30_text="§30 Abs. 2 Nr. 8",
            severity=Severity.LOW,
            provider=CloudProvider.AWS,
            region="eu-central-1",
            resource_id="test",
            resource_type="test",
            account_id="123",
            expected_state="test",
            remediation="test",
            remediation_effort="LOW",
        )

        assert finding.timestamp.tzinfo is not None
        assert finding.timestamp.tzinfo == UTC


class TestScanResult:
    """Tests for the ScanResult model."""

    def test_scan_result_json_roundtrip(self):
        result = ScanResult(
            scan_id="test-123",
            config=ScanConfig(),
        )

        json_str = result.to_json()
        parsed = ScanResult.from_json(json_str)

        assert parsed.scan_id == "test-123"

    def test_scan_result_with_findings(self):
        finding = Finding(
            check_id="AWS-NR8-001",
            title="Test",
            description="Test",
            bsig_30_nr=8,
            bsig_30_text="§30 Abs. 2 Nr. 8",
            severity=Severity.HIGH,
            provider=CloudProvider.AWS,
            region="eu-central-1",
            resource_id="test",
            resource_type="test",
            account_id="123",
            expected_state="test",
            remediation="test",
            remediation_effort="LOW",
        )

        result = ScanResult(
            scan_id="test-456",
            config=ScanConfig(),
            findings=[finding],
        )

        assert len(result.findings) == 1
        json_str = result.to_json()
        assert "AWS-NR8-001" in json_str
