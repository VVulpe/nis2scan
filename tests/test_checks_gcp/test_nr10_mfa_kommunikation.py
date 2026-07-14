"""Tests for §30 Nr. 10 — MFA & Kommunikation GCP checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.gcp.checks.nr10_mfa_kommunikation import (
    CheckIapAdminAccess,
    CheckOsLoginWith2fa,
    CheckSecureLdap,
    CheckTwoStepVerification,
    CheckVpnGateways,
)

from .conftest import FakeGcpSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckTwoStepVerification:
    def _session(self, users: list[dict]) -> FakeGcpSession:
        svc = MagicMock()
        svc.users.return_value.list.return_value.execute.return_value = {"users": users}
        return FakeGcpSession(services={"admin": svc})

    def _paged_session(self, pages: list[dict]) -> FakeGcpSession:
        svc = MagicMock()
        svc.users.return_value.list.return_value.execute.side_effect = pages
        return FakeGcpSession(services={"admin": svc})

    def test_all_users_with_2sv_produce_positive_evidence(self):
        users = [{"primaryEmail": "a@example.com", "isEnforcedIn2Sv": True}]

        result = asyncio.run(CheckTwoStepVerification().execute(self._session(users)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_user_without_2sv_produces_finding(self):
        users = [{"primaryEmail": "a@example.com", "isEnforcedIn2Sv": False}]

        result = asyncio.run(CheckTwoStepVerification().execute(self._session(users)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_empty_user_list_produces_check_error(self):
        """B-Nr.10-10: an empty user list is not evaluable and must not fail silently."""
        result = asyncio.run(CheckTwoStepVerification().execute(self._session([])))

        assert not result.findings
        assert len(result.errors) == 1
        assert "nicht bewertbar" in result.errors[0].message

    def test_two_pages_violation_on_second_page_produces_finding(self):
        """B-Nr.10-10: pagination must follow nextPageToken across all pages."""
        page1 = {
            "users": [{"primaryEmail": "a@example.com", "isEnforcedIn2Sv": True}],
            "nextPageToken": "TOKEN2",
        }
        page2 = {"users": [{"primaryEmail": "b@example.com", "isEnforcedIn2Sv": False}]}
        session = self._paged_session([page1, page2])

        result = asyncio.run(CheckTwoStepVerification().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert not _compliant(result)
        assert not result.errors
        assert maengel[0].current_state["total_users"] == 2


class TestCheckIapAdminAccess:
    def _session(self, bindings: list[dict]) -> FakeGcpSession:
        svc = MagicMock()
        chain = svc.projects.return_value.iap_tunnel.return_value
        chain.getIamPolicy.return_value.execute.return_value = {"bindings": bindings}
        return FakeGcpSession(services={"iap": svc})

    def test_iap_bindings_produce_positive_evidence(self):
        session = self._session([{"role": "roles/iap.tunnelResourceAccessor", "members": ["user:a@example.com"]}])

        result = asyncio.run(CheckIapAdminAccess().execute(session))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_iap_bindings_produces_finding(self):
        result = asyncio.run(CheckIapAdminAccess().execute(self._session([])))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert not _compliant(result)
        # B-Nr.10-11: downgraded HIGH -> MEDIUM, IAP is one of several access paths (GCP-NR10-003)
        assert maengel[0].severity.value == "MEDIUM"
        assert "GCP-NR10-003" in maengel[0].description


class TestCheckVpnGateways:
    @pytest.fixture
    def vpn_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import compute_v1

        client = MagicMock()
        monkeypatch.setattr(compute_v1, "VpnGatewaysClient", lambda credentials: client)
        return client

    def _iap_session(self, bindings: list[dict]) -> FakeGcpSession:
        svc = MagicMock()
        chain = svc.projects.return_value.iap_tunnel.return_value
        chain.getIamPolicy.return_value.execute.return_value = {"bindings": bindings}
        return FakeGcpSession(services={"iap": svc})

    def test_vpn_gateway_produces_positive_evidence(self, vpn_client: MagicMock):
        scoped = SimpleNamespace(vpn_gateways=[SimpleNamespace(name="vpn-1")])
        vpn_client.aggregated_list.return_value = [("regions/europe-west3", scoped)]

        result = asyncio.run(CheckVpnGateways().execute(self._iap_session([])))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["vpn_gateways"] == 1
        assert not _maengel(result)

    def test_iap_alternative_produces_positive_evidence(self, vpn_client: MagicMock):
        vpn_client.aggregated_list.return_value = [("regions/europe-west3", SimpleNamespace(vpn_gateways=[]))]
        session = self._iap_session([{"role": "roles/iap.tunnelResourceAccessor", "members": ["user:a@example.com"]}])

        result = asyncio.run(CheckVpnGateways().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["iap_configured"] is True
        assert not _maengel(result)

    def test_neither_vpn_nor_iap_produces_finding(self, vpn_client: MagicMock):
        vpn_client.aggregated_list.return_value = [("regions/europe-west3", SimpleNamespace(vpn_gateways=[]))]

        result = asyncio.run(CheckVpnGateways().execute(self._iap_session([])))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert not _compliant(result)
        assert maengel[0].title == "Keine VPN-Gateways oder IAP konfiguriert"

    def test_iap_fallback_error_produces_check_error_and_no_iap_claim(self, vpn_client: MagicMock):
        """B-Nr.10-12: a failed IAP fallback check must surface as CheckError, and the
        Mangel text must not claim IAP was confirmed absent — only VPN absence."""
        vpn_client.aggregated_list.return_value = [("regions/europe-west3", SimpleNamespace(vpn_gateways=[]))]
        svc = MagicMock()
        svc.projects.return_value.iap_tunnel.return_value.getIamPolicy.return_value.execute.side_effect = RuntimeError(
            "boom"
        )
        session = FakeGcpSession(services={"iap": svc})

        result = asyncio.run(CheckVpnGateways().execute(session))

        assert len(result.errors) == 1
        assert "IAP-Status nicht prüfbar" in result.errors[0].message

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert not _compliant(result)
        assert maengel[0].title == "Keine VPN-Gateways konfiguriert"
        assert "noch IAP-Tunnel konfiguriert" not in maengel[0].description
        assert "nicht geprüft werden" in maengel[0].description


class TestCheckOsLoginWith2fa:
    @pytest.fixture
    def projects_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import compute_v1

        client = MagicMock()
        monkeypatch.setattr(compute_v1, "ProjectsClient", lambda credentials: client)
        return client

    def _wire(self, projects_client: MagicMock, metadata: dict[str, str]) -> None:
        items = [SimpleNamespace(key=k, value=v) for k, v in metadata.items()]
        projects_client.get.return_value = SimpleNamespace(
            common_instance_metadata=SimpleNamespace(items_=items),
        )

    def test_oslogin_2fa_produces_positive_evidence(self, projects_client: MagicMock):
        self._wire(projects_client, {"enable-oslogin": "TRUE", "enable-oslogin-2fa": "TRUE"})

        result = asyncio.run(CheckOsLoginWith2fa().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_missing_oslogin_2fa_produces_finding(self, projects_client: MagicMock):
        self._wire(projects_client, {"enable-oslogin": "TRUE"})

        result = asyncio.run(CheckOsLoginWith2fa().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckSecureLdap:
    def _session(self, group_names: list[str]) -> FakeGcpSession:
        svc = MagicMock()
        svc.groups.return_value.list.return_value.execute.return_value = {
            "groups": [{"displayName": n} for n in group_names]
        }
        return FakeGcpSession(services={"cloudidentity": svc})

    def test_security_groups_produce_positive_evidence(self):
        result = asyncio.run(CheckSecureLdap().execute(self._session(["Security Team", "Dev Team"])))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["security_groups"] == 1
        assert not _maengel(result)

    def test_no_security_groups_produce_low_finding(self):
        """B-Nr.10-13 (Rewidmung): an empty hit list is now a LOW Mangel, not silence."""
        result = asyncio.run(CheckSecureLdap().execute(self._session(["Dev Team"])))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "LOW"
        assert not _compliant(result)

    def test_403_produces_check_error_not_finding(self):
        """B-Nr.10-13: Cloud Identity inaccessible (403/not-enabled) is CheckError, not a Mangel."""
        svc = MagicMock()
        svc.groups.return_value.list.return_value.execute.side_effect = RuntimeError("403 Forbidden")
        session = FakeGcpSession(services={"cloudidentity": svc})

        result = asyncio.run(CheckSecureLdap().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
