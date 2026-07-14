"""Tests for §30 Nr. 10 — MFA & Kommunikation Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr10_mfa_kommunikation import (
    GLOBAL_ADMIN_ROLE_ID,
    CheckBreakGlassAccounts,
    CheckMfaAllUsers,
    CheckO365TlsEnforcement,
    CheckPhishingResistantMfa,
    CheckVpnBastion,
)

from .conftest import FakeAzureSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


@pytest.fixture
def graph_router(monkeypatch: pytest.MonkeyPatch) -> SimpleNamespace:
    """URL-routing fake for the Graph REST helper (graph_get_all / graph_get).

    Tests register wire-format (camelCase) fixture data by URL substring in
    `.collections` (for graph_get_all) or `.objects` (for graph_get); the fakes
    below dispatch on the first substring found in the requested URL — same
    pattern as TestCheckStaleServicePrincipals's own `_setup` in
    test_nr9_zugriffskontrolle.py.
    """
    from nis2scan.engine.providers.azure import graph

    router = SimpleNamespace(collections={}, objects={})

    async def fake_get_all(credential, url, timeout=30.0):
        for substring, value in router.collections.items():
            if substring in url:
                return value
        raise AssertionError(f"No graph_get_all route registered for URL: {url}")

    async def fake_get(credential, url, timeout=30.0):
        for substring, value in router.objects.items():
            if substring in url:
                return value
        raise AssertionError(f"No graph_get route registered for URL: {url}")

    monkeypatch.setattr(graph, "graph_get_all", fake_get_all)
    monkeypatch.setattr(graph, "graph_get", fake_get)

    return router


def _mfa_policy(include_users: list[str], controls: list[str], exclude_users: list[str] | None = None) -> dict:
    return {
        "state": "enabled",
        "grantControls": {"builtInControls": controls},
        "conditions": {
            "users": {"includeUsers": include_users, "excludeUsers": exclude_users or []},
            "applications": {"includeApplications": ["All"]},
        },
    }


class TestCheckMfaAllUsers:
    def test_mfa_for_all_produces_positive_evidence(self, graph_router: SimpleNamespace):
        graph_router.collections["conditionalAccess"] = [_mfa_policy(["All"], ["mfa"])]
        result = asyncio.run(CheckMfaAllUsers().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_mfa_policy_produces_finding(self, graph_router: SimpleNamespace):
        graph_router.collections["conditionalAccess"] = []
        result = asyncio.run(CheckMfaAllUsers().execute(FakeAzureSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert not _compliant(result)

    def test_mfa_for_all_with_exceptions_produces_positive_evidence_with_caveat(self, graph_router: SimpleNamespace):
        """B-Nr.10-6: exclude_users must not silently flip to full compliance."""
        graph_router.collections["conditionalAccess"] = [_mfa_policy(["All"], ["mfa"], exclude_users=["bg-1", "bg-2"])]
        result = asyncio.run(CheckMfaAllUsers().execute(FakeAzureSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)
        assert "2 ausgenommenen Objekten" in compliant[0].description
        assert "organisatorisch zu begründen" in compliant[0].description
        assert compliant[0].expected_state == "Conditional Access Policy mit MFA für alle Benutzer"


class TestCheckPhishingResistantMfa:
    def _setup(self, graph_router: SimpleNamespace, fido2_state: str) -> None:
        graph_router.objects["authenticationMethodsPolicy"] = {
            "authenticationMethodConfigurations": [{"id": "Fido2", "state": fido2_state}]
        }

    def test_fido2_enabled_produces_positive_evidence(self, graph_router: SimpleNamespace):
        self._setup(graph_router, "enabled")

        result = asyncio.run(CheckPhishingResistantMfa().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_fido2_disabled_produces_finding(self, graph_router: SimpleNamespace):
        self._setup(graph_router, "disabled")

        result = asyncio.run(CheckPhishingResistantMfa().execute(FakeAzureSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckVpnBastion:
    def _session(self, has_bastion: bool) -> FakeAzureSession:
        network_client = MagicMock()
        network_client.virtual_network_gateways.list_all.return_value = []
        resource_client = MagicMock()
        resource_client.resources.list.return_value = [SimpleNamespace(name="bastion-1")] if has_bastion else []
        return FakeAzureSession(
            {"NetworkManagementClient": network_client, "ResourceManagementClient": resource_client}
        )

    def test_bastion_produces_positive_evidence(self):
        result = asyncio.run(CheckVpnBastion().execute(self._session(has_bastion=True)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_nothing_produces_finding(self):
        result = asyncio.run(CheckVpnBastion().execute(self._session(has_bastion=False)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckO365TlsEnforcement:
    def test_o365_policy_produces_positive_evidence(self, graph_router: SimpleNamespace):
        graph_router.collections["conditionalAccess"] = [_mfa_policy(["All"], ["mfa"])]
        result = asyncio.run(CheckO365TlsEnforcement().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_o365_policy_produces_finding(self, graph_router: SimpleNamespace):
        graph_router.collections["conditionalAccess"] = []
        result = asyncio.run(CheckO365TlsEnforcement().execute(FakeAzureSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckBreakGlassAccounts:
    def _setup(self, graph_router: SimpleNamespace, break_glass_count: int, total_admins: int | None = None) -> None:
        """Wire up `break_glass_count` permanent Global Admins excluded from CA policies.

        `total_admins` (default: max(break_glass_count, 1)) lets a test model extra
        Global Admins that are NOT CA-excluded, i.e. not break-glass accounts.
        """
        total = total_admins if total_admins is not None else max(break_glass_count, 1)
        principal_ids = [f"bg-user-{i}" for i in range(total)]
        graph_router.collections["roleAssignments"] = [
            {"roleDefinitionId": GLOBAL_ADMIN_ROLE_ID, "principalId": pid} for pid in principal_ids
        ]
        excluded = principal_ids[:break_glass_count]
        graph_router.collections["conditionalAccess"] = [{"conditions": {"users": {"excludeUsers": excluded}}}]

    def test_two_break_glass_accounts_produce_positive_evidence(self, graph_router: SimpleNamespace):
        """B-Nr.10-9: Option A counts CA-excluded permanent Global Admins; >=2 is compliant."""
        self._setup(graph_router, break_glass_count=2)

        result = asyncio.run(CheckBreakGlassAccounts().execute(FakeAzureSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)
        assert compliant[0].expected_state == (
            "Mindestens zwei Break-Glass-Konten (permanente Global-Admin-Rolle mit CA-Ausschluss)"
        )

    def test_one_break_glass_account_produces_medium_finding(self, graph_router: SimpleNamespace):
        """B-Nr.10-9: exactly one CA-excluded permanent Global Admin is a MEDIUM defect."""
        self._setup(graph_router, break_glass_count=1)

        result = asyncio.run(CheckBreakGlassAccounts().execute(FakeAzureSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "MEDIUM"
        assert not _compliant(result)

    def test_no_break_glass_produces_finding(self, graph_router: SimpleNamespace):
        self._setup(graph_router, break_glass_count=0)

        result = asyncio.run(CheckBreakGlassAccounts().execute(FakeAzureSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "HIGH"
        assert not _compliant(result)
