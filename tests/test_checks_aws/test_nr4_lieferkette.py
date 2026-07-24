"""Tests for §30 Nr. 4 — Lieferkette AWS checks incl. positive evidence (ADR-0006)."""

import asyncio

import boto3
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr4_lieferkette import (
    CheckCrossAccountRoles,
    CheckOrganizationsExternalAccounts,
    CheckRamSharingPolicies,
    CheckScpForThirdPartyOus,
    CheckTrustedAdvisorAccess,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session(regions: list[str] | None = None) -> AwsSession:
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=regions or ["eu-central-1"], accounts=["123456789012"])


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


class TestCheckTrustedAdvisorAccess:
    @mock_aws
    def test_full_access_produces_positive_evidence(self):
        # moto's default DescribeTrustedAdvisorChecks returns >=20 checks (Business/Enterprise-like access).
        session = _make_session()

        result = asyncio.run(CheckTrustedAdvisorAccess().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["available_checks"] >= 20
        assert not _maengel(result)

    @mock_aws
    def test_limited_access_produces_info_finding(self, monkeypatch):
        session = _make_session()
        support = session.client("support", region="us-east-1")
        real_describe = support.describe_trusted_advisor_checks

        def _limited(**kwargs):
            resp = real_describe(**kwargs)
            resp["checks"] = resp["checks"][:5]
            return resp

        monkeypatch.setattr(support, "describe_trusted_advisor_checks", _limited)
        monkeypatch.setattr(session, "client", lambda service, region=None: support)

        result = asyncio.run(CheckTrustedAdvisorAccess().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity.value == "INFO"
        assert maengel[0].current_state["available_checks"] == 5
        assert not _compliant(result)

    @mock_aws
    def test_api_error_produces_check_error_not_silent_pass(self, monkeypatch):
        session = _make_session()
        support = session.client("support", region="us-east-1")

        def _raise(**kwargs):
            raise RuntimeError("boom")

        monkeypatch.setattr(support, "describe_trusted_advisor_checks", _raise)
        monkeypatch.setattr(session, "client", lambda service, region=None: support)

        result = asyncio.run(CheckTrustedAdvisorAccess().execute(session))

        assert not result.findings
        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"


class TestCheckRamSharingPolicies:
    @mock_aws
    def test_no_external_shares_produces_positive_evidence(self):
        session = _make_session()
        result = asyncio.run(CheckRamSharingPolicies().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["external_shares_active"] == 0
        assert not _maengel(result)

    @mock_aws
    def test_external_share_produces_finding(self):
        session = _make_session()
        # RAM is region-scoped; use the check's own region (session.regions[0])
        ram = session.client("ram", region="eu-central-1")
        ram.create_resource_share(name="external-share", allowExternalPrincipals=True)

        result = asyncio.run(CheckRamSharingPolicies().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)

    @mock_aws
    def test_ram_api_error_produces_check_error_not_silent_pass(self, monkeypatch):
        session = _make_session()

        class BoomRamClient:
            def get_resource_shares(self, **kwargs):
                raise Exception("Could not connect to the endpoint URL")

        monkeypatch.setattr(session, "client", lambda service, region=None: BoomRamClient())

        result = asyncio.run(CheckRamSharingPolicies().execute(session))

        assert len(result.errors) == 1
        assert result.errors[0].error_type == "AWSClientError"
        assert not result.findings


class TestCheckOrganizationsExternalAccounts:
    @mock_aws
    def test_all_features_produces_positive_evidence(self):
        session = _make_session()
        orgs = session.client("organizations", region="us-east-1")
        orgs.create_organization(FeatureSet="ALL")

        result = asyncio.run(CheckOrganizationsExternalAccounts().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["feature_set"] == "ALL"
        assert not _maengel(result)

    @mock_aws
    def test_no_organization_produces_finding(self):
        session = _make_session()
        result = asyncio.run(CheckOrganizationsExternalAccounts().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckCrossAccountRoles:
    @mock_aws
    def test_no_cross_account_roles_produces_positive_evidence(self):
        session = _make_session()
        result = asyncio.run(CheckCrossAccountRoles().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert not _maengel(result)

    @mock_aws
    def test_cross_account_role_produces_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_role(
            RoleName="vendor-access",
            AssumeRolePolicyDocument=(
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                '"Principal":{"AWS":"arn:aws:iam::999999999999:root"},"Action":"sts:AssumeRole"}]}'
            ),
        )

        result = asyncio.run(CheckCrossAccountRoles().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert "vendor-access" in maengel[0].resource_id
        assert not _compliant(result)

    @mock_aws
    def test_wildcard_principal_produces_unrestricted_trust_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_role(
            RoleName="wide-open",
            AssumeRolePolicyDocument=(
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                '"Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}'
            ),
        )

        result = asyncio.run(CheckCrossAccountRoles().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].title == "IAM-Rolle mit uneingeschränktem Trust (Principal *)"
        assert "wide-open" in maengel[0].resource_id
        assert not _compliant(result)

    @mock_aws
    def test_wildcard_with_condition_produces_cross_account_not_critical(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_role(
            RoleName="org-wide-role",
            AssumeRolePolicyDocument=(
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                '"Principal":{"AWS":"*"},"Action":"sts:AssumeRole",'
                '"Condition":{"StringEquals":{"aws:PrincipalOrgID":"o-example123"}}}]}'
            ),
        )

        result = asyncio.run(CheckCrossAccountRoles().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].title == "IAM-Rolle mit Cross-Account Trust"
        assert maengel[0].severity.value != "CRITICAL"
        assert "org-wide-role" in maengel[0].resource_id

    @mock_aws
    def test_bare_foreign_account_id_produces_cross_account_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_role(
            RoleName="bare-account-id-trust",
            AssumeRolePolicyDocument=(
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                '"Principal":{"AWS":"999988887777"},"Action":"sts:AssumeRole"}]}'
            ),
        )

        result = asyncio.run(CheckCrossAccountRoles().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].title == "IAM-Rolle mit Cross-Account Trust"
        assert "bare-account-id-trust" in maengel[0].resource_id
        assert not _compliant(result)


class TestCheckScpForThirdPartyOus:
    @mock_aws
    def test_custom_scp_produces_positive_evidence(self):
        session = _make_session()
        orgs = session.client("organizations", region="us-east-1")
        orgs.create_organization(FeatureSet="ALL")
        orgs.create_policy(
            Name="third-party-restrictions",
            Description="Restrict third-party permissions",
            Type="SERVICE_CONTROL_POLICY",
            Content='{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}',
        )

        result = asyncio.run(CheckScpForThirdPartyOus().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["custom_scps"] == 1
        assert not _maengel(result)

    @mock_aws
    def test_no_custom_scp_produces_finding(self):
        session = _make_session()
        orgs = session.client("organizations", region="us-east-1")
        orgs.create_organization(FeatureSet="ALL")

        result = asyncio.run(CheckScpForThirdPartyOus().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)
