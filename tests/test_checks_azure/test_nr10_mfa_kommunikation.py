"""Tests for §30 Nr. 10 — MFA & Kommunikation Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

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
def graph_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    import msgraph

    client = MagicMock()
    monkeypatch.setattr(msgraph, "GraphServiceClient", lambda credential: client)
    return client


def _mfa_policy(
    include_users: list[str], controls: list[str], exclude_users: list[str] | None = None
) -> SimpleNamespace:
    return SimpleNamespace(
        state="enabled",
        grant_controls=SimpleNamespace(built_in_controls=controls),
        conditions=SimpleNamespace(
            users=SimpleNamespace(include_users=include_users, exclude_users=exclude_users or []),
            applications=SimpleNamespace(include_applications=["All"]),
        ),
    )


class TestCheckMfaAllUsers:
    def test_mfa_for_all_produces_positive_evidence(self, graph_client: MagicMock):
        graph_client.identity.conditional_access.policies.get = AsyncMock(
            return_value=SimpleNamespace(value=[_mfa_policy(["All"], ["mfa"])])
        )
        result = asyncio.run(CheckMfaAllUsers().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_mfa_policy_produces_finding(self, graph_client: MagicMock):
        graph_client.identity.conditional_access.policies.get = AsyncMock(return_value=SimpleNamespace(value=[]))
        result = asyncio.run(CheckMfaAllUsers().execute(FakeAzureSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert not _compliant(result)

    def test_mfa_for_all_with_exceptions_produces_positive_evidence_with_caveat(self, graph_client: MagicMock):
        """B-Nr.10-6: exclude_users must not silently flip to full compliance."""
        graph_client.identity.conditional_access.policies.get = AsyncMock(
            return_value=SimpleNamespace(value=[_mfa_policy(["All"], ["mfa"], exclude_users=["bg-1", "bg-2"])])
        )
        result = asyncio.run(CheckMfaAllUsers().execute(FakeAzureSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)
        assert "2 ausgenommenen Objekten" in compliant[0].description
        assert "organisatorisch zu begründen" in compliant[0].description
        assert compliant[0].expected_state == "Conditional Access Policy mit MFA für alle Benutzer"


class TestCheckPhishingResistantMfa:
    def _setup(self, graph_client: MagicMock, fido2_state: str) -> None:
        graph_client.policies.authentication_methods_policy.get = AsyncMock(
            return_value=SimpleNamespace(
                authentication_method_configurations=[SimpleNamespace(id="Fido2", state=fido2_state)]
            )
        )

    def test_fido2_enabled_produces_positive_evidence(self, graph_client: MagicMock):
        self._setup(graph_client, "enabled")

        result = asyncio.run(CheckPhishingResistantMfa().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_fido2_disabled_produces_finding(self, graph_client: MagicMock):
        self._setup(graph_client, "disabled")

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
    def test_o365_policy_produces_positive_evidence(self, graph_client: MagicMock):
        graph_client.identity.conditional_access.policies.get = AsyncMock(
            return_value=SimpleNamespace(value=[_mfa_policy(["All"], ["mfa"])])
        )
        result = asyncio.run(CheckO365TlsEnforcement().execute(FakeAzureSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_o365_policy_produces_finding(self, graph_client: MagicMock):
        graph_client.identity.conditional_access.policies.get = AsyncMock(return_value=SimpleNamespace(value=[]))
        result = asyncio.run(CheckO365TlsEnforcement().execute(FakeAzureSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckBreakGlassAccounts:
    def _setup(self, graph_client: MagicMock, break_glass_count: int, total_admins: int | None = None) -> None:
        """Wire up `break_glass_count` permanent Global Admins excluded from CA policies.

        `total_admins` (default: max(break_glass_count, 1)) lets a test model extra
        Global Admins that are NOT CA-excluded, i.e. not break-glass accounts.
        """
        total = total_admins if total_admins is not None else max(break_glass_count, 1)
        principal_ids = [f"bg-user-{i}" for i in range(total)]
        graph_client.role_management.directory.role_assignments.get = AsyncMock(
            return_value=SimpleNamespace(
                value=[
                    SimpleNamespace(role_definition_id=GLOBAL_ADMIN_ROLE_ID, principal_id=pid) for pid in principal_ids
                ]
            )
        )
        excluded = principal_ids[:break_glass_count]
        policies = [
            SimpleNamespace(
                conditions=SimpleNamespace(users=SimpleNamespace(exclude_users=excluded)),
            )
        ]
        graph_client.identity.conditional_access.policies.get = AsyncMock(return_value=SimpleNamespace(value=policies))

    def test_two_break_glass_accounts_produce_positive_evidence(self, graph_client: MagicMock):
        """B-Nr.10-9: Option A counts CA-excluded permanent Global Admins; >=2 is compliant."""
        self._setup(graph_client, break_glass_count=2)

        result = asyncio.run(CheckBreakGlassAccounts().execute(FakeAzureSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)
        assert compliant[0].expected_state == (
            "Mindestens zwei Break-Glass-Konten (permanente Global-Admin-Rolle mit CA-Ausschluss)"
        )

    def test_one_break_glass_account_produces_medium_finding(self, graph_client: MagicMock):
        """B-Nr.10-9: exactly one CA-excluded permanent Global Admin is a MEDIUM defect."""
        self._setup(graph_client, break_glass_count=1)

        result = asyncio.run(CheckBreakGlassAccounts().execute(FakeAzureSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "MEDIUM"
        assert not _compliant(result)

    def test_no_break_glass_produces_finding(self, graph_client: MagicMock):
        self._setup(graph_client, break_glass_count=0)

        result = asyncio.run(CheckBreakGlassAccounts().execute(FakeAzureSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "HIGH"
        assert not _compliant(result)
