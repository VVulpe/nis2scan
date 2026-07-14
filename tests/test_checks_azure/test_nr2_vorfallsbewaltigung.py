"""Tests for §30 Nr. 2 — Vorfallsbewältigung Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr2_vorfallsbewaltigung import (
    CheckActionGroups,
    CheckAlertProcessingRules,
    CheckDefenderAlertNotifications,
    CheckSentinelAnalyticsRules,
    CheckSentinelPlaybooks,
)

from .conftest import FakeAzureSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckDefenderAlertNotifications:
    def test_enabled_notifications_produce_positive_evidence(self):
        client = MagicMock()
        client.security_contacts.list.return_value = [
            SimpleNamespace(alert_notifications=SimpleNamespace(state="On")),
        ]
        session = FakeAzureSession({"SecurityCenter": client})

        result = asyncio.run(CheckDefenderAlertNotifications().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_contacts_produces_finding(self):
        client = MagicMock()
        client.security_contacts.list.return_value = []
        session = FakeAzureSession({"SecurityCenter": client})

        result = asyncio.run(CheckDefenderAlertNotifications().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_disabled_notifications_produce_finding(self):
        client = MagicMock()
        client.security_contacts.list.return_value = [
            SimpleNamespace(alert_notifications=SimpleNamespace(state="Off")),
        ]
        session = FakeAzureSession({"SecurityCenter": client})

        result = asyncio.run(CheckDefenderAlertNotifications().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckSentinelAnalyticsRules:
    def test_workspace_produces_positive_evidence(self):
        client = MagicMock()
        client.workspaces.list.return_value = [SimpleNamespace(name="sec-ws")]
        session = FakeAzureSession({"LogAnalyticsManagementClient": client})

        result = asyncio.run(CheckSentinelAnalyticsRules().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_workspace_produces_finding(self):
        client = MagicMock()
        client.workspaces.list.return_value = []
        session = FakeAzureSession({"LogAnalyticsManagementClient": client})

        result = asyncio.run(CheckSentinelAnalyticsRules().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckSentinelPlaybooks:
    def test_security_playbook_produces_positive_evidence(self):
        client = MagicMock()
        client.resources.list.return_value = [
            SimpleNamespace(name="sentinel-block-ip-playbook"),
            SimpleNamespace(name="unrelated-workflow"),
        ]
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckSentinelPlaybooks().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["security_playbooks"] == 1
        assert not _maengel(result)

    def test_no_security_playbook_produces_finding(self):
        client = MagicMock()
        client.resources.list.return_value = [SimpleNamespace(name="billing-export")]
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckSentinelPlaybooks().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckActionGroups:
    def test_action_group_produces_positive_evidence(self):
        client = MagicMock()
        client.action_groups.list_by_subscription_id.return_value = [SimpleNamespace(name="sec-team")]
        session = FakeAzureSession({"MonitorManagementClient": client})

        result = asyncio.run(CheckActionGroups().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_action_groups_produces_finding(self):
        client = MagicMock()
        client.action_groups.list_by_subscription_id.return_value = []
        session = FakeAzureSession({"MonitorManagementClient": client})

        result = asyncio.run(CheckActionGroups().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckAlertProcessingRules:
    def test_rule_produces_positive_evidence(self):
        client = MagicMock()
        client.resources.list.return_value = [SimpleNamespace(name="route-to-sec")]
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckAlertProcessingRules().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_rules_produces_finding(self):
        client = MagicMock()
        client.resources.list.return_value = []
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckAlertProcessingRules().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
