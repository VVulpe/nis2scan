"""Tests for AWS session creation incl. cross-account AssumeRole."""

import boto3
from moto import mock_aws

from nis2scan.engine.models.config import ProviderConfig
from nis2scan.engine.providers.aws.session import create_aws_session


@mock_aws
def test_session_without_role_uses_ambient_credentials():
    session = create_aws_session(ProviderConfig(enabled=True, regions=["eu-central-1"]))

    # moto's default account
    assert session.account_id == "123456789012"


@mock_aws
def test_assume_role_switches_to_the_target_account_credentials():
    # A role in another account; moto lets us assume it and returns that
    # account's identity for the assumed session.
    role_arn = "arn:aws:iam::210987654321:role/nis2scan-readonly"
    config = ProviderConfig(
        enabled=True,
        regions=["eu-central-1"],
        assume_role_arn=role_arn,
        external_id="shared-secret-123",
    )

    session = create_aws_session(config)
    ident = session.session.client("sts").get_caller_identity()

    assert ident["Account"] == "210987654321"
    assert ":assumed-role/nis2scan-readonly/nis2scan" in ident["Arn"]


@mock_aws
def test_assume_role_passes_external_id():
    # The assumed session must carry temporary (token-bearing) credentials,
    # not the ambient ones.
    config = ProviderConfig(
        enabled=True,
        assume_role_arn="arn:aws:iam::210987654321:role/nis2scan-readonly",
        external_id="ext-1",
    )

    session = create_aws_session(config)
    creds = session.session.get_credentials()

    assert creds.token is not None
    # ambient moto creds have no session token
    assert boto3.Session().get_credentials().token != creds.token


# --- Azure cross-tenant session ---


def test_azure_session_cross_tenant_requires_app_credentials(monkeypatch):
    import pytest

    from nis2scan.engine.providers.azure.session import create_azure_session

    monkeypatch.delenv("NIS2SCAN_AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_ID", raising=False)
    monkeypatch.delenv("NIS2SCAN_AZURE_CLIENT_SECRET", raising=False)
    monkeypatch.delenv("AZURE_CLIENT_SECRET", raising=False)

    config = ProviderConfig(
        enabled=True,
        azure_tenant_id="11111111-2222-3333-4444-555555555555",
        subscription_ids=["sub-1"],
    )
    with pytest.raises(ValueError, match="Scanner-App-Credentials"):
        create_azure_session(config)


def test_azure_session_uses_client_secret_credential_against_customer_tenant(monkeypatch):
    from nis2scan.engine.providers.azure import session as az_session

    monkeypatch.setenv("NIS2SCAN_AZURE_CLIENT_ID", "app-client-id")
    monkeypatch.setenv("NIS2SCAN_AZURE_CLIENT_SECRET", "app-secret")

    captured = {}

    class FakeCred:
        def __init__(self, tenant_id, client_id, client_secret):
            captured["tenant_id"] = tenant_id
            captured["client_id"] = client_id

    import azure.identity

    monkeypatch.setattr(azure.identity, "ClientSecretCredential", FakeCred)

    config = ProviderConfig(
        enabled=True,
        azure_tenant_id="11111111-2222-3333-4444-555555555555",
        subscription_ids=["sub-1", "sub-2"],
    )
    result = az_session.create_azure_session(config)

    assert captured["tenant_id"] == "11111111-2222-3333-4444-555555555555"
    assert captured["client_id"] == "app-client-id"
    assert result.subscription_ids == ["sub-1", "sub-2"]
