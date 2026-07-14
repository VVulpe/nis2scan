"""Tests for §30 Nr. 4 — Lieferkette Azure checks incl. positive evidence (ADR-0006)."""

import asyncio
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.azure.checks.nr4_lieferkette import (
    CheckGuestUsersConditionalAccess,
    CheckLighthouseDelegations,
    CheckMarketplaceImageTrust,
    CheckPrivateEndpoints,
    CheckServicePrincipalCredentials,
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


class TestCheckLighthouseDelegations:
    def test_no_delegations_produces_positive_evidence(self):
        client = MagicMock()
        client.resources.list.return_value = []
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckLighthouseDelegations().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_delegations_produce_finding(self):
        client = MagicMock()
        client.resources.list.return_value = [SimpleNamespace(name="msp-delegation")]
        session = FakeAzureSession({"ResourceManagementClient": client})

        result = asyncio.run(CheckLighthouseDelegations().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckGuestUsersConditionalAccess:
    def _setup_graph(self, graph_client: MagicMock, guests: bool, ca_for_guests: bool) -> None:
        users = [SimpleNamespace(user_type="Guest")] if guests else [SimpleNamespace(user_type="Member")]
        graph_client.users.get = AsyncMock(return_value=SimpleNamespace(value=users))
        policies = []
        if ca_for_guests:
            policies = [
                SimpleNamespace(
                    state="enabled",
                    conditions=SimpleNamespace(
                        users=SimpleNamespace(
                            include_users=["All"],
                            include_groups=[],
                            include_guests_or_external_users=None,
                        )
                    ),
                )
            ]
        graph_client.identity.conditional_access.policies.get = AsyncMock(return_value=SimpleNamespace(value=policies))

    def test_guests_with_ca_produce_positive_evidence(self, graph_client: MagicMock):
        self._setup_graph(graph_client, guests=True, ca_for_guests=True)
        session = FakeAzureSession()

        result = asyncio.run(CheckGuestUsersConditionalAccess().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_guests_without_ca_produce_finding(self, graph_client: MagicMock):
        self._setup_graph(graph_client, guests=True, ca_for_guests=False)
        session = FakeAzureSession()

        result = asyncio.run(CheckGuestUsersConditionalAccess().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_no_guests_yields_no_findings(self, graph_client: MagicMock):
        self._setup_graph(graph_client, guests=False, ca_for_guests=False)
        session = FakeAzureSession()

        result = asyncio.run(CheckGuestUsersConditionalAccess().execute(session))

        assert not result.findings
        assert not result.errors

    def test_ca_policy_with_only_include_groups_produces_no_positive_evidence(self, graph_client: MagicMock):
        # A CA policy that targets guests only via group membership must not count as
        # covering guests (B-Nr.4-8) — group membership is not evaluated by this check.
        users = [SimpleNamespace(user_type="Guest")]
        graph_client.users.get = AsyncMock(return_value=SimpleNamespace(value=users))
        policies = [
            SimpleNamespace(
                state="enabled",
                conditions=SimpleNamespace(
                    users=SimpleNamespace(
                        include_users=[],
                        include_groups=["some-group-id"],
                        include_guests_or_external_users=None,
                    )
                ),
            )
        ]
        graph_client.identity.conditional_access.policies.get = AsyncMock(return_value=SimpleNamespace(value=policies))
        session = FakeAzureSession()

        result = asyncio.run(CheckGuestUsersConditionalAccess().execute(session))

        assert not _compliant(result)
        assert len(_maengel(result)) == 1


class TestCheckPrivateEndpoints:
    def test_endpoints_produce_positive_evidence(self):
        client = MagicMock()
        client.private_endpoints.list_by_subscription.return_value = [SimpleNamespace(name="pe-sql")]
        session = FakeAzureSession({"NetworkManagementClient": client})

        result = asyncio.run(CheckPrivateEndpoints().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_endpoints_produces_finding(self):
        client = MagicMock()
        client.private_endpoints.list_by_subscription.return_value = []
        session = FakeAzureSession({"NetworkManagementClient": client})

        result = asyncio.run(CheckPrivateEndpoints().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckServicePrincipalCredentials:
    def _setup_apps(self, graph_client: MagicMock, cred_age_days: int) -> None:
        start = datetime.now(UTC) - timedelta(days=cred_age_days)
        apps = [
            SimpleNamespace(password_credentials=[SimpleNamespace(start_date_time=start)]),
        ]
        graph_client.applications.get = AsyncMock(return_value=SimpleNamespace(value=apps))

    def test_fresh_credentials_produce_positive_evidence(self, graph_client: MagicMock):
        self._setup_apps(graph_client, cred_age_days=10)
        session = FakeAzureSession()

        result = asyncio.run(CheckServicePrincipalCredentials().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_old_credentials_produce_finding(self, graph_client: MagicMock):
        self._setup_apps(graph_client, cred_age_days=200)
        session = FakeAzureSession()

        result = asyncio.run(CheckServicePrincipalCredentials().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckMarketplaceImageTrust:
    def _compute_client(self, publisher: str) -> MagicMock:
        client = MagicMock()
        client.virtual_machines.list_all.return_value = [
            SimpleNamespace(
                name="vm-1",
                storage_profile=SimpleNamespace(image_reference=SimpleNamespace(publisher=publisher)),
            ),
        ]
        return client

    def test_trusted_publisher_produces_positive_evidence(self):
        session = FakeAzureSession({"ComputeManagementClient": self._compute_client("Canonical")})

        result = asyncio.run(CheckMarketplaceImageTrust().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_untrusted_publisher_produces_finding(self):
        session = FakeAzureSession({"ComputeManagementClient": self._compute_client("shady-images-inc")})

        result = asyncio.run(CheckMarketplaceImageTrust().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
