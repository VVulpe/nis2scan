"""Tests for §30 Nr. 7 — Cyberhygiene Azure checks incl. positive evidence (ADR-0006)."""

import asyncio

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


def _password_rule_settings(check_enabled: str, banned_list: str) -> dict:
    return {
        "id": "setting-0001",
        "displayName": "Password Rule Settings",
        "values": [
            {"name": "EnableBannedPasswordCheck", "value": check_enabled},
            {"name": "BannedPasswordList", "value": banned_list},
        ],
    }


class TestCheckPasswordProtection:
    def _setup(self, monkeypatch: pytest.MonkeyPatch, settings: list[dict]) -> None:
        from nis2scan.engine.providers.azure import graph

        async def fake_get_all(credential, url, timeout=30.0):
            return settings

        monkeypatch.setattr(graph, "graph_get_all", fake_get_all)

    def test_banned_password_check_enabled_with_list_produces_positive_evidence(self, monkeypatch: pytest.MonkeyPatch):
        self._setup(monkeypatch, [_password_rule_settings("True", "firmenname\tprodukt2026")])
        session = FakeAzureSession()

        result = asyncio.run(CheckPasswordProtection().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["enable_banned_password_check"] is True
        assert compliant[0].current_state["banned_password_list_entries"] == 2
        assert not _maengel(result)
        assert not result.errors

    def test_no_password_rule_settings_produces_finding_case_1(self, monkeypatch: pytest.MonkeyPatch):
        # A tenant with an unrelated groupSettings template only — no "Password Rule Settings"
        other = {"id": "setting-0002", "displayName": "Group.Unified", "values": []}
        self._setup(monkeypatch, [other])
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

    def test_banned_password_check_disabled_produces_finding_case_2(self, monkeypatch: pytest.MonkeyPatch):
        self._setup(monkeypatch, [_password_rule_settings("False", "firmenname")])
        session = FakeAzureSession()

        result = asyncio.run(CheckPasswordProtection().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert "EnableBannedPasswordCheck" in maengel[0].description
        assert maengel[0].current_state["enable_banned_password_check"] is False
        assert not _compliant(result)

    def test_empty_banned_password_list_produces_finding_case_2(self, monkeypatch: pytest.MonkeyPatch):
        self._setup(monkeypatch, [_password_rule_settings("True", "")])
        session = FakeAzureSession()

        result = asyncio.run(CheckPasswordProtection().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert "BannedPasswordList" in maengel[0].description
        assert maengel[0].current_state["banned_password_list_entries"] == 0
        assert not _compliant(result)

    def test_graph_exception_produces_check_error(self, monkeypatch: pytest.MonkeyPatch):
        from nis2scan.engine.providers.azure import graph

        async def failing_get_all(credential, url, timeout=30.0):
            raise RuntimeError("Graph unavailable")

        monkeypatch.setattr(graph, "graph_get_all", failing_get_all)
        session = FakeAzureSession()

        result = asyncio.run(CheckPasswordProtection().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


def _ca_policy(state: str, mfa: bool) -> dict:
    built_in_controls = ["mfa"] if mfa else ["compliantDevice"]
    return {
        "state": state,
        "grantControls": {"builtInControls": built_in_controls},
    }


class TestCheckSecurityDefaults:
    def _setup(self, monkeypatch: pytest.MonkeyPatch, sd_enabled: bool, policies: list[dict]) -> None:
        from nis2scan.engine.providers.azure import graph

        async def fake_get(credential, url, timeout=30.0):
            if "identitySecurityDefaultsEnforcementPolicy" in url:
                return {"isEnabled": sd_enabled}
            raise AssertionError(f"unexpected graph_get url: {url}")

        async def fake_get_all(credential, url, timeout=30.0):
            if "conditionalAccess" in url:
                return policies
            raise AssertionError(f"unexpected graph_get_all url: {url}")

        monkeypatch.setattr(graph, "graph_get", fake_get)
        monkeypatch.setattr(graph, "graph_get_all", fake_get_all)

    def test_security_defaults_produce_positive_evidence(self, monkeypatch: pytest.MonkeyPatch):
        self._setup(monkeypatch, sd_enabled=True, policies=[])
        session = FakeAzureSession()

        result = asyncio.run(CheckSecurityDefaults().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["security_defaults_enabled"] is True
        assert not _maengel(result)

    def test_ca_baseline_with_mfa_produces_positive_evidence(self, monkeypatch: pytest.MonkeyPatch):
        policies = [_ca_policy("enabled", mfa=True) for _ in range(3)]
        self._setup(monkeypatch, sd_enabled=False, policies=policies)
        session = FakeAzureSession()

        result = asyncio.run(CheckSecurityDefaults().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["conditional_access_mfa_policies"] == 3
        assert not _maengel(result)

    def test_ca_baseline_without_mfa_control_produces_finding(self, monkeypatch: pytest.MonkeyPatch):
        policies = [_ca_policy("enabled", mfa=False)]
        self._setup(monkeypatch, sd_enabled=False, policies=policies)
        session = FakeAzureSession()

        result = asyncio.run(CheckSecurityDefaults().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_neither_produces_finding(self, monkeypatch: pytest.MonkeyPatch):
        self._setup(monkeypatch, sd_enabled=False, policies=[])
        session = FakeAzureSession()

        result = asyncio.run(CheckSecurityDefaults().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
