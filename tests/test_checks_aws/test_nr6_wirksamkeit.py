"""Tests for §30 Nr. 6 — Wirksamkeit AWS checks incl. positive evidence (ADR-0006)."""

import asyncio
from datetime import UTC, datetime
from unittest.mock import MagicMock

import boto3
import pytest
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr6_wirksamkeit import (
    CheckCloudTrailLogIntegrity,
    CheckCloudWatchLogRetention,
    CheckConfigRulesCompliance,
    CheckSecurityHubComplianceScore,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session(regions: list[str] | None = None) -> AwsSession:
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=regions or ["eu-central-1"], accounts=["123456789012"])


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckCloudTrailLogIntegrity:
    @mock_aws
    def test_logging_without_delivery_timestamp_produces_finding(self, monkeypatch: pytest.MonkeyPatch):
        # B-Nr.6-1: IsLogging=True but GetTrailStatus omits LatestDeliveryTime
        # entirely used to produce zero findings (silent gap) — now a defect.
        session = _make_session()
        original_client = session.client

        ct_mock = MagicMock()
        ct_mock.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "no-delivery-trail",
                    "TrailARN": "arn:aws:cloudtrail:eu-central-1:123456789012:trail/no-delivery-trail",
                    "HomeRegion": "eu-central-1",
                    "LogFileValidationEnabled": False,
                }
            ]
        }
        ct_mock.get_trail_status.return_value = {"IsLogging": True}

        def fake_client(service, region=None):
            if service == "cloudtrail":
                return ct_mock
            return original_client(service, region=region)

        monkeypatch.setattr(session, "client", fake_client)

        result = asyncio.run(CheckCloudTrailLogIntegrity().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].title == "CloudTrail ohne registrierte Log-Zustellung"
        assert not _compliant(result)

    @mock_aws
    def test_logging_with_validation_without_digest_timestamp_produces_finding(self, monkeypatch: pytest.MonkeyPatch):
        # Analog case: log file validation enabled but LatestDigestDeliveryTime missing.
        session = _make_session()
        original_client = session.client

        ct_mock = MagicMock()
        ct_mock.describe_trails.return_value = {
            "trailList": [
                {
                    "Name": "no-digest-trail",
                    "TrailARN": "arn:aws:cloudtrail:eu-central-1:123456789012:trail/no-digest-trail",
                    "HomeRegion": "eu-central-1",
                    "LogFileValidationEnabled": True,
                }
            ]
        }
        ct_mock.get_trail_status.return_value = {
            "IsLogging": True,
            "LatestDeliveryTime": datetime.now(UTC),
        }

        def fake_client(service, region=None):
            if service == "cloudtrail":
                return ct_mock
            return original_client(service, region=region)

        monkeypatch.setattr(session, "client", fake_client)

        result = asyncio.run(CheckCloudTrailLogIntegrity().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].title == "CloudTrail ohne registrierte Digest-Zustellung"
        assert not _compliant(result)


class TestCheckConfigRulesCompliance:
    @mock_aws
    def test_config_rule_produces_positive_evidence(self):
        session = _make_session()
        config = session.client("config")
        config.put_configuration_recorder(
            ConfigurationRecorder={
                "name": "default",
                "roleARN": "arn:aws:iam::123456789012:role/config-role",
                "recordingGroup": {"allSupported": True},
            }
        )
        config.put_config_rule(
            ConfigRule={
                "ConfigRuleName": "s3-encryption-rule",
                "Source": {"Owner": "AWS", "SourceIdentifier": "S3_BUCKET_SERVER_SIDE_ENCRYPTION_ENABLED"},
            }
        )

        result = asyncio.run(CheckConfigRulesCompliance().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["config_rules_count"] == 1
        assert not _maengel(result)

    @mock_aws
    def test_no_rules_produces_finding(self):
        session = _make_session()
        result = asyncio.run(CheckConfigRulesCompliance().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_generic_exception_produces_check_error(self, monkeypatch: pytest.MonkeyPatch):
        # B-Nr.6-3: the old exception handler (`config_client.__class__.exceptions...`)
        # crashed on attribute access for ANY exception, letting it escape uncaught.
        # A generic (non-ClientError) exception must now become a CheckError.
        session = _make_session()
        original_client = session.client

        config_mock = MagicMock()
        config_mock.describe_config_rules.side_effect = RuntimeError("boom")

        def fake_client(service, region=None):
            if service == "config":
                return config_mock
            return original_client(service, region=region)

        monkeypatch.setattr(session, "client", fake_client)

        result = asyncio.run(CheckConfigRulesCompliance().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"

    @mock_aws
    def test_no_available_configuration_recorder_produces_finding(self, monkeypatch: pytest.MonkeyPatch):
        # The fixed handler now recognizes the ClientError code explicitly instead
        # of relying on a broken class-attribute lookup.
        from botocore.exceptions import ClientError

        session = _make_session()
        original_client = session.client

        config_mock = MagicMock()
        config_mock.describe_config_rules.side_effect = ClientError(
            {"Error": {"Code": "NoAvailableConfigurationRecorderException", "Message": "no recorder"}},
            "DescribeConfigRules",
        )

        def fake_client(service, region=None):
            if service == "config":
                return config_mock
            return original_client(service, region=region)

        monkeypatch.setattr(session, "client", fake_client)

        result = asyncio.run(CheckConfigRulesCompliance().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].title == "AWS Config nicht aktiviert"
        assert not result.errors


class TestCheckCloudWatchLogRetention:
    @mock_aws
    def test_long_retention_produces_positive_evidence(self):
        session = _make_session()
        logs = session.client("logs")
        logs.create_log_group(logGroupName="audit-logs")
        logs.put_retention_policy(logGroupName="audit-logs", retentionInDays=365)

        result = asyncio.run(CheckCloudWatchLogRetention().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["retention_days"] == 365
        assert not _maengel(result)

    @mock_aws
    def test_never_expire_produces_positive_evidence(self):
        session = _make_session()
        logs = session.client("logs")
        logs.create_log_group(logGroupName="forever-logs")

        result = asyncio.run(CheckCloudWatchLogRetention().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["retention_days"] is None
        assert not _maengel(result)

    @mock_aws
    def test_short_retention_produces_finding(self):
        session = _make_session()
        logs = session.client("logs")
        logs.create_log_group(logGroupName="short-logs")
        logs.put_retention_policy(logGroupName="short-logs", retentionInDays=30)

        result = asyncio.run(CheckCloudWatchLogRetention().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckSecurityHubComplianceScore:
    @mock_aws
    def test_enabled_hub_few_failures_produces_positive_evidence(self):
        session = _make_session()
        sh = session.client("securityhub")
        sh.enable_security_hub()

        result = asyncio.run(CheckSecurityHubComplianceScore().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["failed_findings_count"] == 0
        assert not _maengel(result)

    @mock_aws
    def test_25_failed_findings_over_two_pages_produces_finding(self, monkeypatch: pytest.MonkeyPatch):
        # B-Nr.6-5: a single MaxResults=100 page used to silently undercount —
        # verify pagination actually accumulates across NextToken pages.
        session = _make_session()
        real_sh = session.client("securityhub")
        real_sh.enable_security_hub()
        original_client = session.client

        sh_mock = MagicMock()
        sh_mock.exceptions = real_sh.exceptions
        sh_mock.describe_hub.return_value = {}
        page1 = {"Findings": [{"Id": f"f-{i}"} for i in range(20)], "NextToken": "token-1"}
        page2 = {"Findings": [{"Id": f"f-{i}"} for i in range(20, 25)]}
        sh_mock.get_findings.side_effect = [page1, page2]

        def fake_client(service, region=None):
            if service == "securityhub":
                return sh_mock
            return original_client(service, region=region)

        monkeypatch.setattr(session, "client", fake_client)

        result = asyncio.run(CheckSecurityHubComplianceScore().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].current_state["failed_findings_count"] == 25
        assert not _compliant(result)
        assert sh_mock.get_findings.call_count == 2
