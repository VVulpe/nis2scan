"""Tests for §30 Nr. 2 — Vorfallsbewältigung AWS checks incl. positive evidence (ADR-0006)."""

import asyncio
from unittest.mock import MagicMock

import boto3
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr2_vorfallsbewaltigung import (
    CheckCloudWatchAlarms,
    CheckDetectiveEnabled,
    CheckGuardDutyEnabled,
    CheckIncidentManagerResponsePlans,
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

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        gd = session.client("guardduty")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(gd, "list_detectors", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: gd)

        result = asyncio.run(CheckGuardDutyEnabled().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"


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

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        cw = session.client("cloudwatch")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(cw, "describe_alarms", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: cw)

        result = asyncio.run(CheckCloudWatchAlarms().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"


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

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self, monkeypatch):
        session = _make_session()
        sh = session.client("securityhub")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(sh, "get_findings", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: sh)

        result = asyncio.run(CheckSecurityHubFindings().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"


def _session_with_fake_client(service_name: str, fake_client: MagicMock) -> AwsSession:
    """moto has no backend for 'detective' or 'ssm-incidents' — stub the client
    entirely so AWS-NR2-005/-003 tests can control responses deterministically
    (same pattern as test_nr8_kryptographie.py's _session_with_fake_elbv2).
    """
    session = _make_session()
    real_client = session.client

    def client(service: str, region: str | None = None):
        if service == service_name:
            return fake_client
        return real_client(service, region=region)

    session.client = client  # type: ignore[method-assign]
    return session


class TestCheckDetectiveEnabled:
    @mock_aws
    def test_no_graphs_produces_finding(self):
        detective = MagicMock()
        detective.list_graphs.return_value = {"GraphList": []}
        session = _session_with_fake_client("detective", detective)

        result = asyncio.run(CheckDetectiveEnabled().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "LOW"
        assert not _compliant(result)

    @mock_aws
    def test_graph_present_produces_positive_evidence(self):
        detective = MagicMock()
        detective.list_graphs.return_value = {
            "GraphList": [{"Arn": "arn:aws:detective:eu-central-1:123456789012:graph/abc123"}]
        }
        session = _session_with_fake_client("detective", detective)

        result = asyncio.run(CheckDetectiveEnabled().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["graphs"] == 1
        assert not _maengel(result)

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self):
        detective = MagicMock()
        detective.list_graphs.side_effect = RuntimeError("boom")
        session = _session_with_fake_client("detective", detective)

        result = asyncio.run(CheckDetectiveEnabled().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"


class TestCheckIncidentManagerResponsePlans:
    @mock_aws
    def test_no_plans_produces_finding(self):
        incidents = MagicMock()
        incidents.list_response_plans.return_value = {"responsePlanSummaries": []}
        session = _session_with_fake_client("ssm-incidents", incidents)

        result = asyncio.run(CheckIncidentManagerResponsePlans().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "MEDIUM"
        assert not _compliant(result)

    @mock_aws
    def test_plan_present_produces_positive_evidence(self):
        incidents = MagicMock()
        incidents.list_response_plans.return_value = {
            "responsePlanSummaries": [{"arn": "arn:aws:ssm-incidents:eu-central-1:123456789012:response-plan/main"}]
        }
        session = _session_with_fake_client("ssm-incidents", incidents)

        result = asyncio.run(CheckIncidentManagerResponsePlans().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["response_plans"] == 1
        assert not _maengel(result)

    @mock_aws
    def test_api_error_produces_check_error_no_finding(self):
        incidents = MagicMock()
        incidents.list_response_plans.side_effect = RuntimeError("boom")
        session = _session_with_fake_client("ssm-incidents", incidents)

        result = asyncio.run(CheckIncidentManagerResponsePlans().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"
