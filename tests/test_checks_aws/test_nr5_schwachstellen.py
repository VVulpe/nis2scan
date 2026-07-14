"""Tests for §30 Nr. 5 — Schwachstellenmanagement AWS checks incl. positive evidence (ADR-0006)."""

import asyncio
import io
import zipfile
from unittest.mock import MagicMock

import boto3
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus, Severity
from nis2scan.engine.providers.aws.checks.nr5_schwachstellen import (
    CheckAmiAge,
    CheckEcrImageScanning,
    CheckLambdaRuntimeDeprecation,
    CheckSsmPatchCompliance,
    CheckSsmPatchManagerCompliance,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session(regions: list[str] | None = None) -> AwsSession:
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=regions or ["eu-central-1"], accounts=["123456789012"])


def _session_with_stubbed_ssm(
    managed_instance_ids: list[str] | None = None, regions: list[str] | None = None
) -> AwsSession:
    """moto does not implement SSM's DescribeInstanceInformation (raises
    NotImplementedError, see TestCheckSsmPatchCompliance below) — stub the
    managed-instance lookup so nr5-003 tests can control it deterministically.
    All other SSM calls (create_patch_baseline, describe_patch_baselines, ...)
    still go through the real moto-backed client.
    """
    session = _make_session(regions)
    region = (regions or ["eu-central-1"])[0]
    ssm_client = session.session.client("ssm", region_name=region)

    fake_paginator = MagicMock()
    fake_paginator.paginate.return_value = [
        {"InstanceInformationList": [{"InstanceId": iid} for iid in (managed_instance_ids or [])]}
    ]
    real_get_paginator = ssm_client.get_paginator

    def get_paginator(name: str):
        if name == "describe_instance_information":
            return fake_paginator
        return real_get_paginator(name)

    ssm_client.get_paginator = get_paginator  # type: ignore[method-assign]

    real_client = session.client

    def client(service: str, region: str | None = None):
        if service == "ssm":
            return ssm_client
        return real_client(service, region=region)

    session.client = client  # type: ignore[method-assign]
    return session


def _compliant(result):
    return [f for f in result.findings if f.status == FindingStatus.COMPLIANT]


def _maengel(result):
    return [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]


def _lambda_zip() -> bytes:
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("handler.py", "def handler(event, context):\n    return 'ok'\n")
    return buf.getvalue()


class TestCheckEcrImageScanning:
    @mock_aws
    def test_scan_on_push_produces_positive_evidence(self):
        session = _make_session()
        ecr = session.client("ecr")
        ecr.create_repository(
            repositoryName="scanned-repo",
            imageScanningConfiguration={"scanOnPush": True},
        )

        result = asyncio.run(CheckEcrImageScanning().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["scan_on_push"] is True
        assert not _maengel(result)

    @mock_aws
    def test_no_scan_on_push_produces_finding(self):
        session = _make_session()
        ecr = session.client("ecr")
        ecr.create_repository(repositoryName="unscanned-repo")

        result = asyncio.run(CheckEcrImageScanning().execute(session))

        assert len(_maengel(result)) == 1
        assert not _compliant(result)


class TestCheckLambdaRuntimeDeprecation:
    @mock_aws
    def test_current_runtime_produces_positive_evidence(self):
        session = _make_session()
        iam = session.client("iam")
        role = iam.create_role(
            RoleName="lambda-role",
            AssumeRolePolicyDocument=(
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                '"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
            ),
        )["Role"]
        lam = session.client("lambda")
        lam.create_function(
            FunctionName="modern-fn",
            Runtime="python3.12",
            Role=role["Arn"],
            Handler="handler.handler",
            Code={"ZipFile": _lambda_zip()},
        )

        result = asyncio.run(CheckLambdaRuntimeDeprecation().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["runtime"] == "python3.12"
        assert not _maengel(result)

    @mock_aws
    def test_nodejs18x_produces_finding(self):
        # B-Nr.5-5: nodejs18.x was added to DEPRECATED_RUNTIMES (Mapping-Stand
        # 2026.07) — previously judged compliant, now a Mangel.
        session = _make_session()
        iam = session.client("iam")
        role = iam.create_role(
            RoleName="lambda-role",
            AssumeRolePolicyDocument=(
                '{"Version":"2012-10-17","Statement":[{"Effect":"Allow",'
                '"Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}'
            ),
        )["Role"]
        lam = session.client("lambda")
        lam.create_function(
            FunctionName="legacy-fn",
            Runtime="nodejs18.x",
            Role=role["Arn"],
            Handler="handler.handler",
            Code={"ZipFile": _lambda_zip()},
        )

        result = asyncio.run(CheckLambdaRuntimeDeprecation().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].current_state["runtime"] == "nodejs18.x"
        assert not _compliant(result)


class TestCheckAmiAge:
    @mock_aws
    def test_fresh_ami_produces_positive_evidence(self):
        session = _make_session()
        ec2 = session.client("ec2")
        images = ec2.describe_images(Owners=["amazon"]).get("Images", [])
        ami_id = images[0]["ImageId"]
        ec2.run_instances(ImageId=ami_id, MinCount=1, MaxCount=1)

        result = asyncio.run(CheckAmiAge().execute(session))

        # moto AMIs are freshly created — age is 0 days
        compliant = _compliant(result)
        assert len(compliant) >= 1
        assert compliant[0].current_state["ami_age_days"] <= 90
        assert not _maengel(result)


class TestCheckSsmPatchCompliance:
    @mock_aws
    def test_api_error_recorded_no_silent_evidence(self):
        # moto does not implement describe_instance_information — the check
        # must record an error and emit NO evidence (fail-safe, ADR-0016).
        session = _make_session()
        ec2 = session.client("ec2")
        images = ec2.describe_images(Owners=["amazon"]).get("Images", [])
        ec2.run_instances(ImageId=images[0]["ImageId"], MinCount=1, MaxCount=1)

        result = asyncio.run(CheckSsmPatchCompliance().execute(session))

        assert len(result.errors) == 1
        assert not result.findings


class TestCheckSsmPatchManagerCompliance:
    @mock_aws
    def test_custom_baseline_produces_positive_evidence(self):
        session = _session_with_stubbed_ssm()
        session.client("ssm").create_patch_baseline(Name="custom-baseline", OperatingSystem="AMAZON_LINUX_2")

        result = asyncio.run(CheckSsmPatchManagerCompliance().execute(session))

        compliant = _compliant(result)
        assert len(compliant) == 1
        assert compliant[0].current_state["custom_baselines"] >= 1
        assert not _maengel(result)

    @mock_aws
    def test_no_custom_baseline_with_managed_instance_produces_finding(self):
        session = _session_with_stubbed_ssm(managed_instance_ids=["i-1234567890abcdef0"])

        result = asyncio.run(CheckSsmPatchManagerCompliance().execute(session))

        maengel = _maengel(result)
        assert len(maengel) == 1
        assert maengel[0].severity == Severity.MEDIUM
        assert not _compliant(result)

    @mock_aws
    def test_no_custom_baseline_without_managed_instances_produces_no_finding(self):
        # B-Nr.5-4: a region without managed instances has no Prüfobjekt for
        # patch baselines — the Mangel-Finding must not fire.
        session = _session_with_stubbed_ssm(managed_instance_ids=[])

        result = asyncio.run(CheckSsmPatchManagerCompliance().execute(session))

        assert not _maengel(result)
        assert not _compliant(result)
