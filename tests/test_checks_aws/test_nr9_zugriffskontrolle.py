"""Tests for §30 Nr. 9 — Zugriffskontrolle AWS checks using moto."""

import asyncio
import json

import boto3
from moto import mock_aws

from nis2scan.engine.models.finding import FindingStatus
from nis2scan.engine.providers.aws.checks.nr9_zugriffskontrolle import (
    CheckIamAccessKeyAge,
    CheckIamMfa,
    CheckIamWildcardPolicy,
    CheckS3BucketPolicy,
    CheckSecurityGroupOpenAccess,
)
from nis2scan.engine.providers.aws.session import AwsSession


def _make_session(regions: list[str] | None = None) -> AwsSession:
    session = boto3.Session(region_name="eu-central-1")
    return AwsSession(session=session, regions=regions or ["eu-central-1"], accounts=["123456789012"])


class TestCheckIamMfa:
    """Tests for IAM user MFA check."""

    @mock_aws
    def test_user_without_mfa_produces_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="testuser")
        iam.create_login_profile(UserName="testuser", Password="TestPass123!")

        check = CheckIamMfa()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) >= 1
        finding = result.findings[0]
        assert finding.check_id == "AWS-NR9-001"
        assert finding.severity.value == "HIGH"
        assert finding.bsig_30_nr == 9

    @mock_aws
    def test_user_with_mfa_no_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="testuser")
        iam.create_login_profile(UserName="testuser", Password="TestPass123!")
        iam.create_virtual_mfa_device(VirtualMFADeviceName="testuser-mfa")

        # Enable MFA on the user
        iam.enable_mfa_device(
            UserName="testuser",
            SerialNumber="arn:aws:iam::mfa/testuser-mfa",
            AuthenticationCode1="123456",
            AuthenticationCode2="654321",
        )

        check = CheckIamMfa()
        result = asyncio.run(check.execute(session))

        # The user with MFA yields positive evidence (ADR-0006), no defect
        user_findings = [f for f in result.findings if "testuser" in str(f.current_state)]
        assert len(user_findings) == 1
        assert user_findings[0].status == FindingStatus.COMPLIANT

    @mock_aws
    def test_user_without_login_profile_no_finding(self):
        # B-9-1: users without console login are out of scope for this check.
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="api-only-user")
        # No create_login_profile() call -> no console access

        check = CheckIamMfa()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 0
        assert len(result.errors) == 0

    @mock_aws
    def test_no_users_no_findings(self):
        session = _make_session()
        check = CheckIamMfa()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 0


class TestCheckIamAccessKeyAge:
    """Tests for IAM access key age check."""

    @mock_aws
    def test_old_access_key_produces_finding(self):
        session = _make_session()
        iam = session.client("iam")
        iam.create_user(UserName="testuser")
        iam.create_access_key(UserName="testuser")

        # Note: moto creates keys with current timestamp.
        # The check compares against 90 days, so a fresh key won't trigger a
        # defect — it yields positive evidence instead (ADR-0006).
        check = CheckIamAccessKeyAge()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 1
        assert result.findings[0].status == FindingStatus.COMPLIANT

    @mock_aws
    def test_no_access_keys_no_findings(self):
        session = _make_session()
        check = CheckIamAccessKeyAge()
        result = asyncio.run(check.execute(session))

        assert len(result.findings) == 0


class TestCheckSecurityGroupOpenAccess:
    """Tests for security group open access check."""

    @mock_aws
    def test_open_ssh_produces_finding(self):
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")

        # Create VPC and security group
        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="test-open-ssh",
            Description="Test SG with open SSH",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        check = CheckSecurityGroupOpenAccess()
        result = asyncio.run(check.execute(session))

        open_ssh_findings = [f for f in result.findings if sg_id in f.resource_id]
        assert len(open_ssh_findings) >= 1
        assert open_ssh_findings[0].severity.value == "CRITICAL"
        assert open_ssh_findings[0].status == FindingStatus.NON_COMPLIANT

    @mock_aws
    def test_open_ssh_ipv6_produces_finding(self):
        # B-9-2 (ii): ::/0 must be treated the same as 0.0.0.0/0.
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="test-open-ssh-ipv6",
            Description="Test SG with open SSH via IPv6",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 22,
                    "ToPort": 22,
                    "Ipv6Ranges": [{"CidrIpv6": "::/0"}],
                }
            ],
        )

        check = CheckSecurityGroupOpenAccess()
        result = asyncio.run(check.execute(session))

        sg_findings = [f for f in result.findings if sg_id in f.resource_id]
        maengel = [f for f in sg_findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 1
        assert maengel[0].severity.value == "CRITICAL"
        assert maengel[0].current_state["cidr"] == "::/0"

    @mock_aws
    def test_open_non_critical_port_produces_no_defect(self):
        # B-9-2 (i): 0.0.0.0/0 on a non-critical, non-full-range port is out of
        # scope — no Mangel-Finding (the SG still gets positive evidence).
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="test-open-https",
            Description="Test SG with open HTTPS",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "0.0.0.0/0"}],
                }
            ],
        )

        check = CheckSecurityGroupOpenAccess()
        result = asyncio.run(check.execute(session))

        sg_findings = [f for f in result.findings if sg_id in f.resource_id]
        maengel = [f for f in sg_findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 0
        assert len(sg_findings) == 1
        assert sg_findings[0].status == FindingStatus.COMPLIANT

    @mock_aws
    def test_restricted_sg_no_finding(self):
        session = _make_session()
        ec2 = session.client("ec2", region="eu-central-1")

        vpc = ec2.create_vpc(CidrBlock="10.0.0.0/16")
        vpc_id = vpc["Vpc"]["VpcId"]

        sg = ec2.create_security_group(
            GroupName="test-restricted",
            Description="Test SG with restricted access",
            VpcId=vpc_id,
        )
        sg_id = sg["GroupId"]

        ec2.authorize_security_group_ingress(
            GroupId=sg_id,
            IpPermissions=[
                {
                    "IpProtocol": "tcp",
                    "FromPort": 443,
                    "ToPort": 443,
                    "IpRanges": [{"CidrIp": "10.0.0.0/8"}],
                }
            ],
        )

        check = CheckSecurityGroupOpenAccess()
        result = asyncio.run(check.execute(session))

        # Restricted SG yields positive evidence (ADR-0006), no defect
        sg_findings = [f for f in result.findings if sg_id in f.resource_id]
        assert len(sg_findings) == 1
        assert sg_findings[0].status == FindingStatus.COMPLIANT


class TestCheckIamWildcardPolicy:
    """Tests for IAM wildcard policy check (B-9-3)."""

    @mock_aws
    def test_service_wide_wildcard_with_unrestricted_resource_produces_finding(self):
        session = _make_session()
        iam = session.client("iam")
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}],
        }
        iam.create_policy(PolicyName="wildcard-policy", PolicyDocument=json.dumps(policy_doc))

        check = CheckIamWildcardPolicy()
        result = asyncio.run(check.execute(session))

        maengel = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 1
        assert maengel[0].check_id == "AWS-NR9-005"
        assert maengel[0].severity.value == "HIGH"

    @mock_aws
    def test_resource_scoped_wildcard_action_no_finding(self):
        # Resource-scoped ARNs (bucket/*) remain allowed even with a
        # concrete (non-wildcard) action.
        session = _make_session()
        iam = session.client("iam")
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "arn:aws:s3:::bucket/*",
                }
            ],
        }
        iam.create_policy(PolicyName="scoped-policy", PolicyDocument=json.dumps(policy_doc))

        check = CheckIamWildcardPolicy()
        result = asyncio.run(check.execute(session))

        maengel = [f for f in result.findings if f.status == FindingStatus.NON_COMPLIANT]
        assert len(maengel) == 0
        compliant = [f for f in result.findings if f.status == FindingStatus.COMPLIANT]
        assert len(compliant) == 1


class TestCheckS3BucketPolicy:
    """Tests for S3 bucket policy public access check (B-9-4/B-9-5)."""

    @mock_aws
    def test_unconditional_principal_wildcard_produces_critical_finding(self):
        session = _make_session()
        s3 = session.client("s3")
        bucket_name = "test-bucket-public"
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                }
            ],
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy_doc))

        check = CheckS3BucketPolicy()
        result = asyncio.run(check.execute(session))

        bucket_findings = [f for f in result.findings if bucket_name in f.resource_id]
        assert len(bucket_findings) == 1
        assert bucket_findings[0].status == FindingStatus.NON_COMPLIANT
        assert bucket_findings[0].severity.value == "CRITICAL"

    @mock_aws
    def test_principal_wildcard_with_condition_produces_manual_review_finding(self):
        # B-9-5: Principal: * WITH a Condition is no longer silently skipped —
        # it now gets its own MEDIUM "manual review" finding, not a clean
        # positive.
        session = _make_session()
        s3 = session.client("s3")
        bucket_name = "test-bucket-condition"
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        policy_doc = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": f"arn:aws:s3:::{bucket_name}/*",
                    "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-12345"}},
                }
            ],
        }
        s3.put_bucket_policy(Bucket=bucket_name, Policy=json.dumps(policy_doc))

        check = CheckS3BucketPolicy()
        result = asyncio.run(check.execute(session))

        bucket_findings = [f for f in result.findings if bucket_name in f.resource_id]
        assert len(bucket_findings) == 1
        assert bucket_findings[0].status == FindingStatus.NON_COMPLIANT
        assert bucket_findings[0].severity.value == "MEDIUM"
        assert "manuell prüfen" in bucket_findings[0].title
        # No clean positive evidence when a conditional Principal: * exists.
        assert not any(f.status == FindingStatus.COMPLIANT for f in bucket_findings)

    @mock_aws
    def test_no_public_policy_produces_positive_evidence(self):
        session = _make_session()
        s3 = session.client("s3")
        bucket_name = "test-bucket-private"
        s3.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration={"LocationConstraint": "eu-central-1"},
        )
        # No bucket policy set at all -> NoSuchBucketPolicy -> compliant

        check = CheckS3BucketPolicy()
        result = asyncio.run(check.execute(session))

        bucket_findings = [f for f in result.findings if bucket_name in f.resource_id]
        assert len(bucket_findings) == 1
        assert bucket_findings[0].status == FindingStatus.COMPLIANT
