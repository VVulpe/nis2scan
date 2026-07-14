"""Full Azure scan path: cross-tenant config -> run_scan -> contract output.

Verifies the complete unattended flow before it ever reaches a customer:
ProviderConfig(azure_tenant_id=...) -> create_azure_session builds the
cross-tenant credential -> a real registered Azure check executes against a
mocked SDK client -> findings, outcomes, and summary land in the ScanResult.
"""

import asyncio
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

from nis2scan.engine.models.check import CheckOutcome
from nis2scan.engine.models.config import ProviderConfig, ScanConfig
from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.registry import CheckRegistry
from nis2scan.engine.scanner import run_scan

CUSTOMER_TENANT = "11111111-2222-3333-4444-555555555555"


@pytest.fixture(autouse=True)
def _clean_registry():
    CheckRegistry.reset()
    yield
    CheckRegistry.reset()


@pytest.fixture
def azure_env(monkeypatch: pytest.MonkeyPatch) -> dict:
    """Scanner app credentials + captured ClientSecretCredential args."""
    monkeypatch.setenv("NIS2SCAN_AZURE_CLIENT_ID", "scanner-app-id")
    monkeypatch.setenv("NIS2SCAN_AZURE_CLIENT_SECRET", "scanner-app-secret")

    captured: dict = {}

    class FakeCred:
        def __init__(self, tenant_id: str, client_id: str, client_secret: str) -> None:
            captured["tenant_id"] = tenant_id
            captured["client_id"] = client_id

    import azure.identity

    monkeypatch.setattr(azure.identity, "ClientSecretCredential", FakeCred)
    return captured


def _scan_config() -> ScanConfig:
    return ScanConfig(
        providers={
            "azure": ProviderConfig(
                enabled=True,
                azure_tenant_id=CUSTOMER_TENANT,
                subscription_ids=["00000000-0000-0000-0000-000000000001"],
            )
        },
        bsig_30_scope=[1],
    )


def test_full_azure_scan_path_cross_tenant(azure_env: dict, monkeypatch: pytest.MonkeyPatch):
    # Register ONE real Azure check (AZ-NR1-001 Defender for Cloud) and mock
    # its SDK client so the whole engine path runs without cloud access.
    from azure.mgmt.security import SecurityCenter

    from nis2scan.engine.providers.azure.checks.nr1_risikoanalyse import CheckDefenderForCloud

    CheckRegistry.get_instance().register(CheckDefenderForCloud())

    security_client = MagicMock()
    security_client.pricings.list.return_value = [SimpleNamespace(name="VirtualMachines", pricing_tier="Standard")]

    from nis2scan.engine.providers.azure.session import AzureSession

    original_get_client = AzureSession.get_client

    def fake_get_client(self, client_class, subscription_id=None):
        if client_class is SecurityCenter:
            return security_client
        return original_get_client(self, client_class, subscription_id)

    monkeypatch.setattr(AzureSession, "get_client", fake_get_client)

    result = asyncio.run(run_scan(_scan_config()))

    # Cross-tenant credential was built against the CUSTOMER tenant
    assert azure_env["tenant_id"] == CUSTOMER_TENANT
    assert azure_env["client_id"] == "scanner-app-id"

    # The check executed and produced contract output
    assert result.summary.total_checks == 1
    entry = result.check_outcomes[0]
    assert entry.check_id == "AZ-NR1-001"
    assert entry.outcome in (CheckOutcome.PASSED, CheckOutcome.FAILED)
    assert result.findings, "check must emit positive evidence or a defect (ADR-0006)"
    assert all(f.status in (FindingStatus.COMPLIANT, FindingStatus.NON_COMPLIANT) for f in result.findings)


def test_full_azure_scan_path_fails_safe_without_app_credentials(monkeypatch: pytest.MonkeyPatch):
    # No scanner app credentials -> session creation fails -> every check is
    # ERROR, the area is NICHT_BEWERTBAR — never silently green (ADR-0016).
    for var in ("NIS2SCAN_AZURE_CLIENT_ID", "AZURE_CLIENT_ID", "NIS2SCAN_AZURE_CLIENT_SECRET", "AZURE_CLIENT_SECRET"):
        monkeypatch.delenv(var, raising=False)

    from nis2scan.engine.providers.azure.checks.nr1_risikoanalyse import CheckDefenderForCloud

    CheckRegistry.get_instance().register(CheckDefenderForCloud())

    result = asyncio.run(run_scan(_scan_config()))

    assert result.summary.error_checks == 1
    assert result.summary.passed_checks == 0
    assert result.check_outcomes[0].outcome == CheckOutcome.ERROR
