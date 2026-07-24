"""Tests for §30 Nr. 3 — BCM GCP checks incl. positive evidence (ADR-0006)."""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.gcp.checks.nr3_bcm import (
    CheckCloudSqlBackups,
    CheckCloudSqlHighAvailability,
    CheckDiskSnapshotSchedules,
    CheckDnsHealthChecks,
    CheckGcsRetentionPolicy,
    CheckGcsVersioning,
    CheckMultiZoneDeployments,
)

from .conftest import FakeGcpSession


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


def _sql_session(backup_enabled: bool, availability_type: str = "ZONAL") -> FakeGcpSession:
    svc = MagicMock()
    svc.instances.return_value.list.return_value.execute.return_value = {
        "items": [
            {
                "name": "db-1",
                "region": "europe-west3",
                "settings": {
                    "backupConfiguration": {"enabled": backup_enabled},
                    "availabilityType": availability_type,
                },
            }
        ]
    }
    return FakeGcpSession(services={"sqladmin": svc})


class TestCheckCloudSqlBackups:
    def test_backup_enabled_produces_positive_evidence(self):
        result = asyncio.run(CheckCloudSqlBackups().execute(_sql_session(backup_enabled=True)))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_backup_disabled_produces_finding(self):
        result = asyncio.run(CheckCloudSqlBackups().execute(_sql_session(backup_enabled=False)))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = _sql_session(backup_enabled=True)
        service = session.service("sqladmin", "v1beta4")
        service.instances.return_value.list.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckCloudSqlBackups().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckCloudSqlHighAvailability:
    def test_regional_produces_positive_evidence(self):
        result = asyncio.run(CheckCloudSqlHighAvailability().execute(_sql_session(True, availability_type="REGIONAL")))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_zonal_produces_finding(self):
        result = asyncio.run(CheckCloudSqlHighAvailability().execute(_sql_session(True, availability_type="ZONAL")))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self):
        session = _sql_session(True, availability_type="REGIONAL")
        service = session.service("sqladmin", "v1beta4")
        service.instances.return_value.list.return_value.execute.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckCloudSqlHighAvailability().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckGcsVersioning:
    @pytest.fixture
    def storage_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import storage

        client = MagicMock()
        monkeypatch.setattr(storage, "Client", lambda credentials, project: client)
        return client

    def _bucket(self, versioned: bool) -> SimpleNamespace:
        return SimpleNamespace(
            name="bucket-1",
            location="EU",
            versioning_enabled=versioned,
            retention_policy=None,
        )

    def test_versioned_bucket_produces_positive_evidence(self, storage_client: MagicMock):
        storage_client.list_buckets.return_value = [self._bucket(versioned=True)]

        result = asyncio.run(CheckGcsVersioning().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_unversioned_bucket_produces_finding(self, storage_client: MagicMock):
        storage_client.list_buckets.return_value = [self._bucket(versioned=False)]

        result = asyncio.run(CheckGcsVersioning().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, storage_client: MagicMock):
        storage_client.list_buckets.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckGcsVersioning().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckGcsRetentionPolicy:
    @pytest.fixture
    def storage_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import storage

        client = MagicMock()
        monkeypatch.setattr(storage, "Client", lambda credentials, project: client)
        return client

    def _bucket(self, retention_policy: object | None) -> SimpleNamespace:
        return SimpleNamespace(
            name="bucket-1",
            location="EU",
            versioning_enabled=False,
            retention_policy=retention_policy,
        )

    def test_retention_policy_produces_positive_evidence(self, storage_client: MagicMock):
        storage_client.list_buckets.return_value = [self._bucket(retention_policy={"retentionPeriod": "31536000"})]

        result = asyncio.run(CheckGcsRetentionPolicy().execute(FakeGcpSession()))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["retention_policy"] == "configured"
        assert not _maengel(result)

    def test_no_retention_policy_produces_finding(self, storage_client: MagicMock):
        storage_client.list_buckets.return_value = [self._bucket(retention_policy=None)]

        result = asyncio.run(CheckGcsRetentionPolicy().execute(FakeGcpSession()))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "MEDIUM"
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, storage_client: MagicMock):
        storage_client.list_buckets.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckGcsRetentionPolicy().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckMultiZoneDeployments:
    @pytest.fixture
    def instances_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        import google.cloud.compute_v1 as compute_v1

        client = MagicMock()
        monkeypatch.setattr(compute_v1, "InstancesClient", lambda credentials: client)
        return client

    def _zone_entry(self, zone: str) -> tuple:
        return (zone, SimpleNamespace(instances=[SimpleNamespace(status="RUNNING")]))

    def test_multi_zone_produces_positive_evidence(self, instances_client: MagicMock):
        instances_client.aggregated_list.return_value = [
            self._zone_entry("zones/europe-west3-a"),
            self._zone_entry("zones/europe-west3-b"),
        ]

        result = asyncio.run(CheckMultiZoneDeployments().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_single_zone_produces_finding(self, instances_client: MagicMock):
        instances_client.aggregated_list.return_value = [self._zone_entry("zones/europe-west3-a")]

        result = asyncio.run(CheckMultiZoneDeployments().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, instances_client: MagicMock):
        instances_client.aggregated_list.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckMultiZoneDeployments().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckDiskSnapshotSchedules:
    @pytest.fixture
    def policies_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        import google.cloud.compute_v1 as compute_v1

        client = MagicMock()
        monkeypatch.setattr(compute_v1, "ResourcePoliciesClient", lambda credentials: client)
        return client

    def test_snapshot_policy_produces_positive_evidence(self, policies_client: MagicMock):
        policies_client.aggregated_list.return_value = [
            (
                "regions/europe-west3",
                SimpleNamespace(resource_policies=[SimpleNamespace(snapshot_schedule_policy=SimpleNamespace())]),
            ),
        ]

        result = asyncio.run(CheckDiskSnapshotSchedules().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_policy_produces_finding(self, policies_client: MagicMock):
        policies_client.aggregated_list.return_value = [
            ("regions/europe-west3", SimpleNamespace(resource_policies=[])),
        ]

        result = asyncio.run(CheckDiskSnapshotSchedules().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, policies_client: MagicMock):
        policies_client.aggregated_list.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckDiskSnapshotSchedules().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"


class TestCheckDnsHealthChecks:
    @pytest.fixture
    def dns_client(self, monkeypatch: pytest.MonkeyPatch) -> MagicMock:
        from google.cloud import dns

        client = MagicMock()
        monkeypatch.setattr(dns, "Client", lambda credentials, project: client)
        return client

    def test_zones_produce_positive_evidence(self, dns_client: MagicMock):
        dns_client.list_zones.return_value = [SimpleNamespace(name="prod-zone")]

        result = asyncio.run(CheckDnsHealthChecks().execute(FakeGcpSession()))

        assert len(_compliant(result)) == 1
        assert not _maengel(result)

    def test_no_zones_produces_finding(self, dns_client: MagicMock):
        dns_client.list_zones.return_value = []

        result = asyncio.run(CheckDnsHealthChecks().execute(FakeGcpSession()))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    def test_api_error_produces_check_error_no_finding(self, dns_client: MagicMock):
        dns_client.list_zones.side_effect = RuntimeError("boom")

        result = asyncio.run(CheckDnsHealthChecks().execute(FakeGcpSession()))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "RuntimeError"
