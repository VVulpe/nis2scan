"""Tests for §30 Nr. 2 — Vorfallsbewältigung AWS checks incl. positive evidence (ADR-0006)."""

import asyncio

import boto3
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr2_vorfallsbewaltigung import (
    CheckCloudWatchAlarms,
    CheckGuardDutyEnabled,
    CheckSecurityHubFindings,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session(regions: list[str] | None = None) -> AwsSession:
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=regions or ["eu-central-1"], accounts=["123456789012"])


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckGuardDutyEnabled:
    @mock_aws
    def test_no_detector_produces_finding(self):
        session = _make_session()
        result = asyncio.run(CheckGuardDutyEnabled().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert not _compliant(result)

    @mock_aws
    def test_enabled_detector_produces_positive_evidence(self):
        session = _make_session()
        gd = session.client("guardduty")
        gd.create_detector(Enable=True)

        result = asyncio.run(CheckGuardDutyEnabled().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].severity.value == "INFO"
        assert not _maengel(result)


class TestCheckCloudWatchAlarms:
    @mock_aws
    def test_no_alarms_produces_finding(self):
        session = _make_session()
        result = asyncio.run(CheckCloudWatchAlarms().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "HIGH"
        assert not _compliant(result)

    @mock_aws
    def test_metric_alarm_produces_positive_evidence(self):
        session = _make_session()
        cw = session.client("cloudwatch")
        cw.put_metric_alarm(
            AlarmName="root-usage",
            MetricName="RootAccountUsage",
            Namespace="CloudTrailMetrics",
            Statistic="Sum",
            Period=300,
            EvaluationPeriods=1,
            Threshold=1.0,
            ComparisonOperator="GreaterThanOrEqualToThreshold",
        )

        result = asyncio.run(CheckCloudWatchAlarms().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert "root-usage" in compliant[0].resource_id
        assert not _maengel(result)


class TestCheckSecurityHubFindings:
    @mock_aws
    def test_enabled_hub_produces_positive_evidence(self):
        session = _make_session()
        sh = session.client("securityhub")
        sh.enable_security_hub()

        result = asyncio.run(CheckSecurityHubFindings().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)
