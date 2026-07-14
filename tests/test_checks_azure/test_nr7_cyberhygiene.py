"""Tests for §30 Nr. 7 — Cyberhygiene Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr7_cyberhygiene import (
    CheckPasswordProtection,
    CheckSecurityDefaults,
)

from .conftest import FakeAzureSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


@pytest.fixture
def graph_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    import msgraph

    client = MagicMock()
    monkeypatch.setattr(msgraph, "GraphServiceClient", lambda credential: client)
    return client


def _password_rule_settings(check_enabled: str, banned_list: str) -> SimpleNamespace:
    return SimpleNamespace(
        id="setting-0001",
        display_name="Password Rule Settings",
        values=[
            SimpleNamespace(name="EnableBannedPasswordCheck", value=check_enabled),
            SimpleNamespace(name="BannedPasswordList", value=banned_list),
        ],
    )


class TestCheckPasswordProtection:
    def _setup(self, graph_client: MagicMock, settings: list[SimpleNamespace]) -> None:
        graph_client.group_settings.get = AsyncMock(return_value=SimpleNamespace(value=settings))

    def test_banned_password_check_enabled_with_list_produces_positive_evidence(self, graph_client: MagicMock):
        self._setup(graph_client, [_password_rule_settings("True", "firmenname\tprodukt2026")])
        session = FakeAzureSession()

        result = asyncio.run(CheckPasswordProtection().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["enable_banned_password_check"] is True
        assert compliant[0].current_state["banned_password_list_entries"] == 2
        assert not _maengel(result)
        assert not result.errors

    def test_no_password_rule_settings_produces_finding_case_1(self, graph_client: MagicMock):
        # A tenant with an unrelated groupSettings template only — no "Password Rule Settings"
        other = SimpleNamespace(id="setting-0002", display_name="Group.Unified", values=[])
        self._setup(graph_client, [other])
        session = FakeAzureSession()

        result = asyncio.run(CheckPasswordProtection().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].description == (
            "Für den Tenant ist keine benutzerdefinierte Liste verbotener Passwörter "
            "konfiguriert; es greift nur die globale Microsoft-Sperrliste."
        )
        assert maengel[0].current_state["password_rule_settings_present"] is False
        assert not _compliant(result)

    def test_banned_password_check_disabled_produces_finding_case_2(self, graph_client: MagicMock):
        self._setup(graph_client, [_password_rule_settings("False", "firmenname")])
        session = FakeAzureSession()

        result = asyncio.run(CheckPasswordProtection().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert "EnableBannedPasswordCheck" in maengel[0].description
        assert maengel[0].current_state["enable_banned_password_check"] is False
        assert not _compliant(result)

    def test_empty_banned_password_list_produces_finding_case_2(self, graph_client: MagicMock):
        self._setup(graph_client, [_password_rule_settings("True", "")])
        session = FakeAzureSession()

        result = asyncio.run(CheckPasswordProtection().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert "BannedPasswordList" in maengel[0].description
        assert maengel[0].current_state["banned_password_list_entries"] == 0
        assert not _compliant(result)

    def test_graph_exception_produces_check_error(self, graph_client: MagicMock):
        graph_client.group_settings.get = AsyncMock(side_effect=RuntimeError("Graph unavailable"))
        session = FakeAzureSession()

        result = asyncio.run(CheckPasswordProtection().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


def _ca_policy(state: str, mfa: bool) -> SimpleNamespace:
    built_in_controls = ["mfa"] if mfa else ["compliantDevice"]
    return SimpleNamespace(
        state=state,
        grant_controls=SimpleNamespace(built_in_controls=built_in_controls),
    )


class TestCheckSecurityDefaults:
    def _setup(self, graph_client: MagicMock, sd_enabled: bool, policies: list[SimpleNamespace]) -> None:
        graph_client.policies.identity_security_defaults_enforcement_policy.get = AsyncMock(
            return_value=SimpleNamespace(is_enabled=sd_enabled)
        )
        graph_client.identity.conditional_access.policies.get = AsyncMock(return_value=SimpleNamespace(value=policies))

    def test_security_defaults_produce_positive_evidence(self, graph_client: MagicMock):
        self._setup(graph_client, sd_enabled=True, policies=[])
        session = FakeAzureSession()

        result = asyncio.run(CheckSecurityDefaults().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["security_defaults_enabled"] is True
        assert not _maengel(result)

    def test_ca_baseline_with_mfa_produces_positive_evidence(self, graph_client: MagicMock):
        policies = [_ca_policy("enabled", mfa=True) for _ in range(3)]
        self._setup(graph_client, sd_enabled=False, policies=policies)
        session = FakeAzureSession()

        result = asyncio.run(CheckSecurityDefaults().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["conditional_access_mfa_policies"] == 3
        assert not _maengel(result)

    def test_ca_baseline_without_mfa_control_produces_finding(self, graph_client: MagicMock):
        policies = [_ca_policy("enabled", mfa=False)]
        self._setup(graph_client, sd_enabled=False, policies=policies)
        session = FakeAzureSession()

        result = asyncio.run(CheckSecurityDefaults().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_neither_produces_finding(self, graph_client: MagicMock):
        self._setup(graph_client, sd_enabled=False, policies=[])
        session = FakeAzureSession()

        result = asyncio.run(CheckSecurityDefaults().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
