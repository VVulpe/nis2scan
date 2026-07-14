#!/usr/bin/env python3
"""Nuke all nis2scan integration-test resources from the AWS account.

Safety net for when terraform destroy fails or state is lost. Deletes all
resources tagged Project=nis2scan or named with 'nis2scan-' prefix, EXCEPT
for OIDC/CI infrastructure (nis2scan-ci-* roles and policies).

Designed to be safe for accounts with non-nis2scan resources.

Usage:
    python3 nuke_test_resources.py [--dry-run] [--region REGION]
"""

from __future__ import annotations

import argparse
import contextlib
import time

import boto3

TAG_PROJECT = "nis2scan"
NAME_PREFIX = "nis2scan-"

# CI/OIDC infrastructure — NEVER delete these
CI_PREFIXES = ("nis2scan-ci",)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Nuke all nis2scan test resources (safety net)")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without making changes",
    )
    parser.add_argument(
        "--region",
        default="eu-central-1",
        help="AWS region (default: eu-central-1)",
    )
    return parser.parse_args()


def is_ci_resource(name: str) -> bool:
    """Return True if this is a CI/OIDC resource that must be preserved."""
    return any(name.startswith(prefix) for prefix in CI_PREFIXES)


def is_nis2scan_test(name: str) -> bool:
    """Return True if this is a nis2scan test resource (not CI)."""
    return NAME_PREFIX in name and not is_ci_resource(name)


def nuke_albs(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan ALBs and their listeners."""
    elbv2 = session.client("elbv2")
    count = 0
    try:
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                name = lb["LoadBalancerName"]
                arn = lb["LoadBalancerArn"]
                # Check by name prefix or tag
                is_nis2 = is_nis2scan_test(name) or name.startswith("n2s-")
                if is_nis2 and name.startswith("n2s-"):
                    # Verify via tags for n2s- prefixed ALBs
                    try:
                        tags_resp = elbv2.describe_tags(ResourceArns=[arn])
                        is_nis2 = False
                        for td in tags_resp.get("TagDescriptions", []):
                            for tag in td.get("Tags", []):
                                if tag["Key"] == "Project" and tag["Value"] == TAG_PROJECT:
                                    is_nis2 = True
                    except Exception:
                        is_nis2 = False
                if not is_nis2:
                    continue

                # Delete listeners first
                try:
                    listeners = elbv2.describe_listeners(LoadBalancerArn=arn)
                    for listener in listeners.get("Listeners", []):
                        if dry_run:
                            print(f"  [DRY-RUN] Would delete listener {listener['ListenerArn']}")
                        else:
                            elbv2.delete_listener(ListenerArn=listener["ListenerArn"])
                            print(f"  Deleted listener {listener['ListenerArn']}")
                except Exception:
                    pass

                if dry_run:
                    print(f"  [DRY-RUN] Would delete ALB {name}")
                else:
                    print(f"  Deleting ALB {name}")
                    elbv2.delete_load_balancer(LoadBalancerArn=arn)
                count += 1
    except Exception as exc:
        print(f"  WARN: ALB cleanup error: {exc}")
    return count


def nuke_rds(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan RDS instances (skip final snapshot)."""
    rds = session.client("rds")
    count = 0
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                identifier = db["DBInstanceIdentifier"]
                if not is_nis2scan_test(identifier):
                    continue
                if dry_run:
                    print(f"  [DRY-RUN] Would delete RDS {identifier}")
                else:
                    print(f"  Deleting RDS {identifier} (status={db['DBInstanceStatus']})")
                    try:
                        rds.delete_db_instance(
                            DBInstanceIdentifier=identifier,
                            SkipFinalSnapshot=True,
                            DeleteAutomatedBackups=True,
                        )
                    except Exception as exc:
                        print(f"    WARN: {exc}")
                count += 1
    except Exception as exc:
        print(f"  WARN: RDS cleanup error: {exc}")

    # Wait for RDS instances to start deleting before moving on
    if count > 0 and not dry_run:
        print("  Waiting 30s for RDS deletion to begin...")
        time.sleep(30)

    # Delete DB subnet groups
    try:
        resp = rds.describe_db_subnet_groups()
        for sg in resp.get("DBSubnetGroups", []):
            name = sg["DBSubnetGroupName"]
            if is_nis2scan_test(name):
                if dry_run:
                    print(f"  [DRY-RUN] Would delete DB subnet group {name}")
                else:
                    print(f"  Deleting DB subnet group {name}")
                    try:
                        rds.delete_db_subnet_group(DBSubnetGroupName=name)
                    except Exception as exc:
                        print(f"    WARN: {exc}")
    except Exception:
        pass

    return count


def nuke_cloudtrail(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan CloudTrail trails."""
    ct = session.client("cloudtrail")
    count = 0
    try:
        trails = ct.describe_trails()
        for trail in trails.get("trailList", []):
            name = trail.get("Name", "")
            if not is_nis2scan_test(name):
                continue
            if dry_run:
                print(f"  [DRY-RUN] Would delete trail {name}")
            else:
                print(f"  Deleting trail {name}")
                ct.delete_trail(Name=name)
            count += 1
    except Exception as exc:
        print(f"  WARN: CloudTrail cleanup error: {exc}")
    return count


def nuke_lambda(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan Lambda functions."""
    lam = session.client("lambda")
    count = 0
    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name = fn["FunctionName"]
                if not is_nis2scan_test(name):
                    continue
                if dry_run:
                    print(f"  [DRY-RUN] Would delete Lambda {name}")
                else:
                    print(f"  Deleting Lambda {name}")
                    lam.delete_function(FunctionName=name)
                count += 1
    except Exception as exc:
        print(f"  WARN: Lambda cleanup error: {exc}")
    return count


def nuke_ecr(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan ECR repositories."""
    ecr = session.client("ecr")
    count = 0
    try:
        paginator = ecr.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                name = repo["repositoryName"]
                if not is_nis2scan_test(name):
                    continue
                if dry_run:
                    print(f"  [DRY-RUN] Would delete ECR repo {name}")
                else:
                    print(f"  Deleting ECR repo {name}")
                    ecr.delete_repository(repositoryName=name, force=True)
                count += 1
    except Exception as exc:
        print(f"  WARN: ECR cleanup error: {exc}")
    return count


def nuke_cloudwatch_alarms(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan CloudWatch alarms."""
    cw = session.client("cloudwatch")
    count = 0
    try:
        paginator = cw.get_paginator("describe_alarms")
        for page in paginator.paginate(AlarmNamePrefix=NAME_PREFIX):
            names = [a["AlarmName"] for a in page.get("MetricAlarms", [])]
            if not names:
                continue
            if dry_run:
                for n in names:
                    print(f"  [DRY-RUN] Would delete alarm {n}")
            else:
                for n in names:
                    print(f"  Deleting alarm {n}")
                cw.delete_alarms(AlarmNames=names)
            count += len(names)
    except Exception as exc:
        print(f"  WARN: CloudWatch alarm cleanup error: {exc}")
    return count


def nuke_log_groups(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan CloudWatch log groups."""
    logs = session.client("logs")
    count = 0
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate(logGroupNamePrefix="/nis2scan/"):
            for lg in page.get("logGroups", []):
                name = lg["logGroupName"]
                if dry_run:
                    print(f"  [DRY-RUN] Would delete log group {name}")
                else:
                    print(f"  Deleting log group {name}")
                    logs.delete_log_group(logGroupName=name)
                count += 1
    except Exception as exc:
        print(f"  WARN: Log group cleanup error: {exc}")
    return count


def nuke_s3_buckets(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan S3 buckets (empty them first)."""
    s3 = session.client("s3")
    s3r = session.resource("s3")
    count = 0
    try:
        resp = s3.list_buckets()
        for bucket in resp.get("Buckets", []):
            name = bucket["Name"]
            if not is_nis2scan_test(name):
                continue
            if dry_run:
                print(f"  [DRY-RUN] Would delete S3 bucket {name}")
                count += 1
                continue

            print(f"  Emptying and deleting S3 bucket {name}")
            try:
                # First, remove any object lock configuration
                with contextlib.suppress(Exception):
                    s3.put_object_lock_configuration(
                        Bucket=name,
                        ObjectLockConfiguration={"ObjectLockEnabled": "Enabled"},
                    )

                # Delete all object versions (handles versioning + object lock)
                b = s3r.Bucket(name)
                try:
                    # Try with governance bypass for object-locked objects
                    for version in b.object_versions.all():
                        try:
                            version.delete()
                        except Exception:
                            # Try with governance bypass
                            with contextlib.suppress(Exception):
                                s3.delete_object(
                                    Bucket=name,
                                    Key=version.key,
                                    VersionId=version.version_id,
                                    BypassGovernanceRetention=True,
                                )
                except Exception:
                    # Fall back to deleting objects without versions
                    try:
                        b.objects.all().delete()
                    except Exception as exc:
                        print(f"    WARN: Cannot empty bucket: {exc}")

                s3.delete_bucket(Bucket=name)
                print(f"    Deleted bucket {name}")
            except Exception as exc:
                print(f"    WARN: Cannot delete bucket {name}: {exc}")
            count += 1
    except Exception as exc:
        print(f"  WARN: S3 cleanup error: {exc}")
    return count


def nuke_ebs_snapshots(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan EBS snapshots."""
    ec2 = session.client("ec2")
    count = 0
    try:
        snaps = ec2.describe_snapshots(
            OwnerIds=["self"],
            Filters=[{"Name": "tag:Project", "Values": [TAG_PROJECT]}],
        )
        for snap in snaps.get("Snapshots", []):
            sid = snap["SnapshotId"]
            if dry_run:
                print(f"  [DRY-RUN] Would delete snapshot {sid}")
            else:
                print(f"  Deleting snapshot {sid}")
                ec2.delete_snapshot(SnapshotId=sid)
            count += 1
    except Exception as exc:
        print(f"  WARN: Snapshot cleanup error: {exc}")
    return count


def nuke_ebs_volumes(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan EBS volumes."""
    ec2 = session.client("ec2")
    count = 0
    try:
        vols = ec2.describe_volumes(Filters=[{"Name": "tag:Project", "Values": [TAG_PROJECT]}])
        for vol in vols.get("Volumes", []):
            vid = vol["VolumeId"]
            if dry_run:
                print(f"  [DRY-RUN] Would delete volume {vid}")
            else:
                print(f"  Deleting volume {vid}")
                try:
                    ec2.delete_volume(VolumeId=vid)
                except Exception as exc:
                    print(f"    WARN: {exc}")
            count += 1
    except Exception as exc:
        print(f"  WARN: Volume cleanup error: {exc}")
    return count


def nuke_kms_keys(session: boto3.Session, dry_run: bool) -> int:
    """Schedule deletion for nis2scan KMS keys."""
    kms = session.client("kms")
    count = 0
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page["Keys"]:
                key_id = key["KeyId"]
                try:
                    desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    if desc.get("KeyManager") == "AWS":
                        continue
                    if desc.get("KeyState") in ("PendingDeletion", "PendingImport"):
                        continue
                    description = desc.get("Description", "")
                    if NAME_PREFIX not in description:
                        continue
                    if dry_run:
                        print(f"  [DRY-RUN] Would schedule deletion for KMS key {key_id}")
                    else:
                        print(f"  Scheduling deletion for KMS key {key_id} ({description[:50]})")
                        kms.schedule_key_deletion(KeyId=key_id, PendingWindowInDays=7)
                    count += 1
                except Exception:
                    continue
    except Exception as exc:
        print(f"  WARN: KMS cleanup error: {exc}")
    return count


def nuke_iam_users(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan IAM users (clean up all dependencies first)."""
    iam = session.client("iam")
    count = 0
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            name = user["UserName"]
            if not is_nis2scan_test(name):
                continue
            if dry_run:
                print(f"  [DRY-RUN] Would delete IAM user {name}")
                count += 1
                continue

            print(f"  Cleaning up and deleting IAM user {name}")

            # Deactivate and delete MFA devices
            try:
                mfa_resp = iam.list_mfa_devices(UserName=name)
                for device in mfa_resp.get("MFADevices", []):
                    serial = device["SerialNumber"]
                    with contextlib.suppress(Exception):
                        iam.deactivate_mfa_device(UserName=name, SerialNumber=serial)
                    if ":mfa/" in serial:
                        with contextlib.suppress(Exception):
                            iam.delete_virtual_mfa_device(SerialNumber=serial)
            except Exception:
                pass

            # Delete login profile
            with contextlib.suppress(Exception):
                iam.delete_login_profile(UserName=name)

            # Delete access keys
            try:
                keys = iam.list_access_keys(UserName=name)
                for key in keys.get("AccessKeyMetadata", []):
                    iam.delete_access_key(UserName=name, AccessKeyId=key["AccessKeyId"])
            except Exception:
                pass

            # Detach managed policies
            try:
                policies = iam.list_attached_user_policies(UserName=name)
                for pol in policies.get("AttachedPolicies", []):
                    iam.detach_user_policy(UserName=name, PolicyArn=pol["PolicyArn"])
            except Exception:
                pass

            # Delete inline policies
            try:
                inline = iam.list_user_policies(UserName=name)
                for pol_name in inline.get("PolicyNames", []):
                    iam.delete_user_policy(UserName=name, PolicyName=pol_name)
            except Exception:
                pass

            # Delete signing certificates
            try:
                certs = iam.list_signing_certificates(UserName=name)
                for cert in certs.get("Certificates", []):
                    iam.delete_signing_certificate(UserName=name, CertificateId=cert["CertificateId"])
            except Exception:
                pass

            # Delete the user
            try:
                iam.delete_user(UserName=name)
                print(f"    Deleted user {name}")
            except Exception as exc:
                print(f"    WARN: Cannot delete user {name}: {exc}")
            count += 1
    return count


def nuke_iam_roles(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan IAM roles (not CI roles)."""
    iam = session.client("iam")
    count = 0
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            name = role["RoleName"]
            if "/aws-service-role/" in role.get("Path", ""):
                continue
            if not is_nis2scan_test(name):
                continue
            if dry_run:
                print(f"  [DRY-RUN] Would delete IAM role {name}")
                count += 1
                continue

            print(f"  Deleting IAM role {name}")

            # Detach managed policies
            try:
                policies = iam.list_attached_role_policies(RoleName=name)
                for pol in policies.get("AttachedPolicies", []):
                    iam.detach_role_policy(RoleName=name, PolicyArn=pol["PolicyArn"])
            except Exception:
                pass

            # Delete inline policies
            try:
                inline = iam.list_role_policies(RoleName=name)
                for pol_name in inline.get("PolicyNames", []):
                    iam.delete_role_policy(RoleName=name, PolicyName=pol_name)
            except Exception:
                pass

            # Delete instance profiles
            try:
                profiles = iam.list_instance_profiles_for_role(RoleName=name)
                for profile in profiles.get("InstanceProfiles", []):
                    iam.remove_role_from_instance_profile(
                        RoleName=name, InstanceProfileName=profile["InstanceProfileName"]
                    )
            except Exception:
                pass

            try:
                iam.delete_role(RoleName=name)
                print(f"    Deleted role {name}")
            except Exception as exc:
                print(f"    WARN: Cannot delete role {name}: {exc}")
            count += 1
    return count


def nuke_iam_policies(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan IAM policies (not CI policies)."""
    iam = session.client("iam")
    count = 0
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            name = policy["PolicyName"]
            arn = policy["Arn"]
            if not is_nis2scan_test(name):
                continue
            if dry_run:
                print(f"  [DRY-RUN] Would delete IAM policy {name}")
                count += 1
                continue

            print(f"  Deleting IAM policy {name}")

            # Delete non-default policy versions
            try:
                versions = iam.list_policy_versions(PolicyArn=arn)
                for v in versions.get("Versions", []):
                    if not v["IsDefaultVersion"]:
                        iam.delete_policy_version(PolicyArn=arn, VersionId=v["VersionId"])
            except Exception:
                pass

            try:
                iam.delete_policy(PolicyArn=arn)
                print(f"    Deleted policy {name}")
            except Exception as exc:
                print(f"    WARN: Cannot delete policy {name}: {exc}")
            count += 1
    return count


def nuke_virtual_mfa_devices(session: boto3.Session, dry_run: bool) -> int:
    """Delete orphaned nis2scan virtual MFA devices."""
    iam = session.client("iam")
    count = 0
    try:
        paginator = iam.get_paginator("list_virtual_mfa_devices")
        for page in paginator.paginate():
            for device in page["VirtualMFADevices"]:
                serial = device["SerialNumber"]
                if NAME_PREFIX not in serial or is_ci_resource(serial.split("/")[-1]):
                    continue
                if dry_run:
                    print(f"  [DRY-RUN] Would delete virtual MFA device {serial}")
                else:
                    print(f"  Deleting virtual MFA device {serial}")
                    try:
                        iam.delete_virtual_mfa_device(SerialNumber=serial)
                    except Exception as exc:
                        print(f"    WARN: {exc}")
                count += 1
    except Exception as exc:
        print(f"  WARN: MFA cleanup error: {exc}")
    return count


def nuke_security_groups(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan security groups."""
    ec2 = session.client("ec2")
    count = 0
    try:
        sgs = ec2.describe_security_groups(Filters=[{"Name": "tag:Project", "Values": [TAG_PROJECT]}])
        for sg in sgs.get("SecurityGroups", []):
            if sg["GroupName"] == "default":
                continue
            if dry_run:
                print(f"  [DRY-RUN] Would delete SG {sg['GroupId']} ({sg['GroupName']})")
            else:
                print(f"  Deleting SG {sg['GroupId']} ({sg['GroupName']})")
                try:
                    ec2.delete_security_group(GroupId=sg["GroupId"])
                except Exception as exc:
                    print(f"    WARN: {exc}")
            count += 1
    except Exception as exc:
        print(f"  WARN: SG cleanup error: {exc}")
    return count


def nuke_vpc(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan VPCs and all dependencies."""
    ec2 = session.client("ec2")
    count = 0
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Project", "Values": [TAG_PROJECT]}])
        for vpc in vpcs.get("Vpcs", []):
            vpc_id = vpc["VpcId"]
            if dry_run:
                print(f"  [DRY-RUN] Would delete VPC {vpc_id}")
                count += 1
                continue

            print(f"  Cleaning up and deleting VPC {vpc_id}")

            # Delete route table associations and route tables (non-main)
            try:
                rts = ec2.describe_route_tables(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
                for rt in rts.get("RouteTables", []):
                    is_main = any(a.get("Main", False) for a in rt.get("Associations", []))
                    if is_main:
                        continue
                    for assoc in rt.get("Associations", []):
                        if not assoc.get("Main", False):
                            ec2.disassociate_route_table(AssociationId=assoc["RouteTableAssociationId"])
                    ec2.delete_route_table(RouteTableId=rt["RouteTableId"])
            except Exception as exc:
                print(f"    WARN: Route table cleanup: {exc}")

            # Detach and delete internet gateways
            try:
                igws = ec2.describe_internet_gateways(Filters=[{"Name": "attachment.vpc-id", "Values": [vpc_id]}])
                for igw in igws.get("InternetGateways", []):
                    igw_id = igw["InternetGatewayId"]
                    ec2.detach_internet_gateway(InternetGatewayId=igw_id, VpcId=vpc_id)
                    ec2.delete_internet_gateway(InternetGatewayId=igw_id)
            except Exception as exc:
                print(f"    WARN: IGW cleanup: {exc}")

            # Delete subnets
            try:
                subnets = ec2.describe_subnets(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
                for subnet in subnets.get("Subnets", []):
                    ec2.delete_subnet(SubnetId=subnet["SubnetId"])
            except Exception as exc:
                print(f"    WARN: Subnet cleanup: {exc}")

            # Delete security groups (non-default)
            try:
                sgs = ec2.describe_security_groups(Filters=[{"Name": "vpc-id", "Values": [vpc_id]}])
                for sg in sgs.get("SecurityGroups", []):
                    if sg["GroupName"] != "default":
                        ec2.delete_security_group(GroupId=sg["GroupId"])
            except Exception as exc:
                print(f"    WARN: SG cleanup: {exc}")

            # Delete VPC
            try:
                ec2.delete_vpc(VpcId=vpc_id)
                print(f"    Deleted VPC {vpc_id}")
            except Exception as exc:
                print(f"    WARN: Cannot delete VPC: {exc}")
            count += 1
    except Exception as exc:
        print(f"  WARN: VPC cleanup error: {exc}")
    return count


def nuke_acm_certs(session: boto3.Session, dry_run: bool) -> int:
    """Delete nis2scan ACM certificates."""
    acm = session.client("acm")
    count = 0
    try:
        paginator = acm.get_paginator("list_certificates")
        for page in paginator.paginate():
            for cert in page.get("CertificateSummaryList", []):
                arn = cert["CertificateArn"]
                try:
                    tags_resp = acm.list_tags_for_certificate(CertificateArn=arn)
                    is_nis2 = any(
                        t["Key"] == "Project" and t["Value"] == TAG_PROJECT for t in tags_resp.get("Tags", [])
                    )
                    if not is_nis2:
                        continue
                except Exception:
                    continue

                if dry_run:
                    print(f"  [DRY-RUN] Would delete ACM cert {arn}")
                else:
                    print(f"  Deleting ACM cert {arn}")
                    acm.delete_certificate(CertificateArn=arn)
                count += 1
    except Exception as exc:
        print(f"  WARN: ACM cleanup error: {exc}")
    return count


def nuke_password_policy(session: boto3.Session, dry_run: bool) -> int:
    """Reset IAM password policy to AWS defaults (if nis2scan set it)."""
    iam = session.client("iam")
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        # Only reset if it looks like our weak test policy
        if policy.get("MinimumPasswordLength", 0) == 8 and not policy.get("RequireSymbols", True):
            if dry_run:
                print("  [DRY-RUN] Would delete weak password policy")
            else:
                print("  Deleting weak password policy (resetting to AWS defaults)")
                iam.delete_account_password_policy()
            return 1
    except Exception:
        pass
    return 0


def nuke_ebs_encryption_default(session: boto3.Session, dry_run: bool) -> int:
    """Re-enable EBS default encryption if disabled by nis2scan."""
    ec2 = session.client("ec2")
    try:
        resp = ec2.get_ebs_encryption_by_default()
        if not resp.get("EbsEncryptionByDefault", True):
            if dry_run:
                print("  [DRY-RUN] Would re-enable EBS default encryption")
            else:
                print("  Re-enabling EBS default encryption")
                ec2.enable_ebs_encryption_by_default()
            return 1
    except Exception:
        pass
    return 0


def nuke_s3_public_access_block(session: boto3.Session, dry_run: bool) -> int:
    """Restore S3 account public access block to fully restricted (all true).

    NR9 test infra sets ignore_public_acls=false. After terraform destroy,
    all four settings go to false (unrestricted). Restore them.
    """
    s3control = session.client("s3control")
    sts = session.client("sts")
    try:
        account_id = sts.get_caller_identity()["Account"]
        try:
            resp = s3control.get_public_access_block(AccountId=account_id)
            config = resp.get("PublicAccessBlockConfiguration", {})
        except s3control.exceptions.NoSuchPublicAccessBlockConfiguration:
            # No block at all — needs to be set
            config = {}

        all_true = all(
            config.get(k, False)
            for k in [
                "BlockPublicAcls",
                "IgnorePublicAcls",
                "BlockPublicPolicy",
                "RestrictPublicBuckets",
            ]
        )
        if all_true:
            return 0

        if dry_run:
            print("  [DRY-RUN] Would restore S3 public access block (all true)")
        else:
            print("  Restoring S3 account public access block (all settings → true)")
            s3control.put_public_access_block(
                AccountId=account_id,
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )
        return 1
    except Exception as exc:
        print(f"  WARN: S3 public access block restore error: {exc}")
    return 0


def nuke_db_subnet_groups(session: boto3.Session, dry_run: bool) -> int:
    """Delete orphaned nis2scan DB subnet groups (standalone, not just inside RDS)."""
    rds = session.client("rds")
    count = 0
    try:
        resp = rds.describe_db_subnet_groups()
        for sg in resp.get("DBSubnetGroups", []):
            name = sg["DBSubnetGroupName"]
            if not is_nis2scan_test(name):
                continue
            if dry_run:
                print(f"  [DRY-RUN] Would delete DB subnet group {name}")
            else:
                print(f"  Deleting DB subnet group {name}")
                try:
                    rds.delete_db_subnet_group(DBSubnetGroupName=name)
                except Exception as exc:
                    print(f"    WARN: {exc}")
            count += 1
    except Exception as exc:
        print(f"  WARN: DB subnet group cleanup error: {exc}")
    return count


def nuke_instance_profiles(session: boto3.Session, dry_run: bool) -> int:
    """Delete orphaned nis2scan instance profiles."""
    iam = session.client("iam")
    count = 0
    try:
        paginator = iam.get_paginator("list_instance_profiles")
        for page in paginator.paginate():
            for profile in page["InstanceProfiles"]:
                name = profile["InstanceProfileName"]
                if not is_nis2scan_test(name):
                    continue
                if dry_run:
                    print(f"  [DRY-RUN] Would delete instance profile {name}")
                    count += 1
                    continue

                print(f"  Deleting instance profile {name}")
                # Remove all roles first
                for role in profile.get("Roles", []):
                    with contextlib.suppress(Exception):
                        iam.remove_role_from_instance_profile(InstanceProfileName=name, RoleName=role["RoleName"])
                try:
                    iam.delete_instance_profile(InstanceProfileName=name)
                    print(f"    Deleted instance profile {name}")
                except Exception as exc:
                    print(f"    WARN: {exc}")
                count += 1
    except Exception as exc:
        print(f"  WARN: Instance profile cleanup error: {exc}")
    return count


def nuke_target_groups(session: boto3.Session, dry_run: bool) -> int:
    """Delete orphaned nis2scan target groups."""
    elbv2 = session.client("elbv2")
    count = 0
    try:
        paginator = elbv2.get_paginator("describe_target_groups")
        for page in paginator.paginate():
            for tg in page.get("TargetGroups", []):
                arn = tg["TargetGroupArn"]
                name = tg["TargetGroupName"]
                if not is_nis2scan_test(name):
                    continue
                if dry_run:
                    print(f"  [DRY-RUN] Would delete target group {name}")
                else:
                    print(f"  Deleting target group {name}")
                    try:
                        elbv2.delete_target_group(TargetGroupArn=arn)
                    except Exception as exc:
                        print(f"    WARN: {exc}")
                count += 1
    except Exception as exc:
        print(f"  WARN: Target group cleanup error: {exc}")
    return count


def main() -> None:
    args = parse_args()
    mode = "[DRY-RUN] " if args.dry_run else ""

    print(f"{mode}nis2scan test resource nuke (region={args.region})")
    print("=" * 60)
    print("NOTE: CI/OIDC resources (nis2scan-ci-*) are preserved.")
    print()

    session = boto3.Session(region_name=args.region)
    total = 0

    # Order matters! Delete dependent resources first.
    steps = [
        ("1. ALBs (must delete before SGs/subnets)", lambda: nuke_albs(session, args.dry_run)),
        ("2. Target groups (orphaned after ALB deletion)", lambda: nuke_target_groups(session, args.dry_run)),
        ("3. RDS instances (slow, started early)", lambda: nuke_rds(session, args.dry_run)),
        ("4. CloudTrail trails (must delete before S3)", lambda: nuke_cloudtrail(session, args.dry_run)),
        ("5. Lambda functions (must delete before roles)", lambda: nuke_lambda(session, args.dry_run)),
        ("6. ECR repositories", lambda: nuke_ecr(session, args.dry_run)),
        ("7. CloudWatch alarms", lambda: nuke_cloudwatch_alarms(session, args.dry_run)),
        ("8. CloudWatch log groups", lambda: nuke_log_groups(session, args.dry_run)),
        ("9. S3 buckets (empty + delete, incl. object lock)", lambda: nuke_s3_buckets(session, args.dry_run)),
        ("10. EBS snapshots", lambda: nuke_ebs_snapshots(session, args.dry_run)),
        ("11. EBS volumes", lambda: nuke_ebs_volumes(session, args.dry_run)),
        ("12. KMS keys (schedule deletion)", lambda: nuke_kms_keys(session, args.dry_run)),
        ("13. ACM certificates", lambda: nuke_acm_certs(session, args.dry_run)),
        ("14. IAM users (+ MFA, keys, profiles)", lambda: nuke_iam_users(session, args.dry_run)),
        ("15. Orphaned virtual MFA devices", lambda: nuke_virtual_mfa_devices(session, args.dry_run)),
        ("16. IAM roles (+ policies)", lambda: nuke_iam_roles(session, args.dry_run)),
        ("17. IAM policies", lambda: nuke_iam_policies(session, args.dry_run)),
        ("18. Instance profiles (orphaned)", lambda: nuke_instance_profiles(session, args.dry_run)),
        ("19. Security groups", lambda: nuke_security_groups(session, args.dry_run)),
        ("20. DB subnet groups (orphaned)", lambda: nuke_db_subnet_groups(session, args.dry_run)),
        ("21. VPCs (+ subnets, IGWs, route tables)", lambda: nuke_vpc(session, args.dry_run)),
        ("22. S3 public access block (restore all true)", lambda: nuke_s3_public_access_block(session, args.dry_run)),
        ("23. Password policy (reset to defaults)", lambda: nuke_password_policy(session, args.dry_run)),
        ("24. EBS default encryption (re-enable)", lambda: nuke_ebs_encryption_default(session, args.dry_run)),
    ]

    for label, fn in steps:
        print(f"\n{mode}{label}")
        count = fn()
        if count:
            print(f"  → {count} resource(s)")
        total += count

    print(f"\n{'=' * 60}")
    print(f"{mode}Done: {total} resource(s) processed")

    if total == 0:
        print("Nothing to nuke — account is clean.")
    elif not args.dry_run:
        print("\nNote: KMS keys have a 7-day deletion window (AWS requirement).")
        print("Note: RDS instances may take several minutes to fully delete.")


if __name__ == "__main__":
    main()
