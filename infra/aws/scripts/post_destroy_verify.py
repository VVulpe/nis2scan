#!/usr/bin/env python3
"""Post-destroy verification for nis2scan integration-test resources.

Scans the AWS account for any remaining nis2scan resources that should have
been removed by terraform destroy. Only checks resources tagged with
Project=nis2scan or named with 'nis2scan-' prefix.

Exits with code 1 if leftover resources are found, 0 if clean.

Usage:
    python3 post_destroy_verify.py [--region REGION]
"""

from __future__ import annotations

import argparse
import sys

import boto3

TAG_PROJECT = "nis2scan"
NAME_PREFIX = "nis2scan-"

# CI/OIDC infrastructure — these are permanent and expected
CI_PREFIXES = ("nis2scan-ci",)


def is_ci_resource(name: str) -> bool:
    """Return True if this is a CI/OIDC resource that should be preserved."""
    return any(name.startswith(prefix) for prefix in CI_PREFIXES)


def is_nis2scan_test(name: str) -> bool:
    """Return True if this is a nis2scan test resource (not CI)."""
    return NAME_PREFIX in name and not is_ci_resource(name)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Post-destroy verification for nis2scan resources")
    parser.add_argument(
        "--region",
        default="eu-central-1",
        help="AWS region to check (default: eu-central-1)",
    )
    return parser.parse_args()


def check_iam_users(iam: object) -> list[str]:
    """Check for leftover nis2scan IAM users."""
    leftovers = []
    paginator = iam.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            name = user["UserName"]
            if is_nis2scan_test(name):
                leftovers.append(f"IAM User: {name}")
    return leftovers


def check_iam_policies(iam: object) -> list[str]:
    """Check for leftover nis2scan IAM policies (excludes CI policies)."""
    leftovers = []
    paginator = iam.get_paginator("list_policies")
    for page in paginator.paginate(Scope="Local"):
        for policy in page["Policies"]:
            name = policy["PolicyName"]
            if is_nis2scan_test(name):
                leftovers.append(f"IAM Policy: {name} ({policy['Arn']})")
    return leftovers


def check_iam_roles(iam: object) -> list[str]:
    """Check for leftover nis2scan IAM roles (excluding OIDC/CI roles)."""
    leftovers = []
    paginator = iam.get_paginator("list_roles")
    for page in paginator.paginate():
        for role in page["Roles"]:
            name = role["RoleName"]
            # Skip AWS service roles
            if "/aws-service-role/" in role.get("Path", ""):
                continue
            if is_nis2scan_test(name):
                leftovers.append(f"IAM Role: {name}")
    return leftovers


def check_mfa_devices(iam: object) -> list[str]:
    """Check for leftover nis2scan virtual MFA devices."""
    leftovers = []
    paginator = iam.get_paginator("list_virtual_mfa_devices")
    for page in paginator.paginate():
        for device in page["VirtualMFADevices"]:
            serial = device["SerialNumber"]
            if NAME_PREFIX in serial and not is_ci_resource(serial.split("/")[-1]):
                leftovers.append(f"Virtual MFA Device: {serial}")
    return leftovers


def check_s3_buckets(s3: object) -> list[str]:
    """Check for leftover nis2scan S3 buckets."""
    leftovers = []
    try:
        resp = s3.list_buckets()
        for bucket in resp.get("Buckets", []):
            name = bucket["Name"]
            if is_nis2scan_test(name):
                leftovers.append(f"S3 Bucket: {name}")
    except Exception as exc:
        print(f"  WARN: Cannot list S3 buckets: {exc}")
    return leftovers


def check_kms_keys(kms: object) -> list[str]:
    """Check for leftover nis2scan KMS keys (not pending deletion)."""
    leftovers = []
    try:
        paginator = kms.get_paginator("list_keys")
        for page in paginator.paginate():
            for key in page["Keys"]:
                key_id = key["KeyId"]
                try:
                    desc = kms.describe_key(KeyId=key_id)["KeyMetadata"]
                    # Skip AWS-managed keys
                    if desc.get("KeyManager") == "AWS":
                        continue
                    # Skip keys already pending deletion
                    if desc.get("KeyState") == "PendingDeletion":
                        continue
                    # Check description for nis2scan
                    description = desc.get("Description", "")
                    if NAME_PREFIX in description:
                        leftovers.append(f"KMS Key: {key_id} (state={desc.get('KeyState')}, desc={description[:60]})")
                except Exception:
                    continue
    except Exception as exc:
        print(f"  WARN: Cannot list KMS keys: {exc}")
    return leftovers


def check_ec2_resources(ec2: object) -> list[str]:
    """Check for leftover nis2scan EC2 resources (VPCs, SGs, EBS, snapshots)."""
    leftovers = []

    # VPCs
    try:
        vpcs = ec2.describe_vpcs(Filters=[{"Name": "tag:Project", "Values": [TAG_PROJECT]}])
        for vpc in vpcs.get("Vpcs", []):
            leftovers.append(f"VPC: {vpc['VpcId']}")
    except Exception as exc:
        print(f"  WARN: Cannot check VPCs: {exc}")

    # Security Groups
    try:
        sgs = ec2.describe_security_groups(Filters=[{"Name": "tag:Project", "Values": [TAG_PROJECT]}])
        for sg in sgs.get("SecurityGroups", []):
            leftovers.append(f"Security Group: {sg['GroupId']} ({sg['GroupName']})")
    except Exception as exc:
        print(f"  WARN: Cannot check Security Groups: {exc}")

    # EBS Volumes
    try:
        vols = ec2.describe_volumes(Filters=[{"Name": "tag:Project", "Values": [TAG_PROJECT]}])
        for vol in vols.get("Volumes", []):
            leftovers.append(f"EBS Volume: {vol['VolumeId']}")
    except Exception as exc:
        print(f"  WARN: Cannot check EBS volumes: {exc}")

    # EBS Snapshots (owned by this account)
    try:
        snaps = ec2.describe_snapshots(
            OwnerIds=["self"],
            Filters=[{"Name": "tag:Project", "Values": [TAG_PROJECT]}],
        )
        for snap in snaps.get("Snapshots", []):
            leftovers.append(f"EBS Snapshot: {snap['SnapshotId']}")
    except Exception as exc:
        print(f"  WARN: Cannot check EBS snapshots: {exc}")

    return leftovers


def check_rds_instances(rds: object) -> list[str]:
    """Check for leftover nis2scan RDS instances."""
    leftovers = []
    try:
        paginator = rds.get_paginator("describe_db_instances")
        for page in paginator.paginate():
            for db in page["DBInstances"]:
                identifier = db["DBInstanceIdentifier"]
                if is_nis2scan_test(identifier):
                    leftovers.append(f"RDS Instance: {identifier} (status={db['DBInstanceStatus']})")
    except Exception as exc:
        print(f"  WARN: Cannot check RDS instances: {exc}")
    return leftovers


def check_cloudtrail(ct: object) -> list[str]:
    """Check for leftover nis2scan CloudTrail trails."""
    leftovers = []
    try:
        trails = ct.describe_trails()
        for trail in trails.get("trailList", []):
            name = trail.get("Name", "")
            if is_nis2scan_test(name):
                leftovers.append(f"CloudTrail: {name}")
    except Exception as exc:
        print(f"  WARN: Cannot check CloudTrail: {exc}")
    return leftovers


def check_cloudwatch_log_groups(logs: object) -> list[str]:
    """Check for leftover nis2scan CloudWatch log groups."""
    leftovers = []
    try:
        paginator = logs.get_paginator("describe_log_groups")
        for page in paginator.paginate(logGroupNamePrefix="/nis2scan/"):
            for lg in page.get("logGroups", []):
                leftovers.append(f"CloudWatch Log Group: {lg['logGroupName']}")
    except Exception as exc:
        print(f"  WARN: Cannot check CloudWatch log groups: {exc}")
    return leftovers


def check_ecr_repos(ecr: object) -> list[str]:
    """Check for leftover nis2scan ECR repositories."""
    leftovers = []
    try:
        paginator = ecr.get_paginator("describe_repositories")
        for page in paginator.paginate():
            for repo in page.get("repositories", []):
                name = repo["repositoryName"]
                if is_nis2scan_test(name):
                    leftovers.append(f"ECR Repository: {name}")
    except Exception as exc:
        print(f"  WARN: Cannot check ECR repos: {exc}")
    return leftovers


def check_lambda_functions(lam: object) -> list[str]:
    """Check for leftover nis2scan Lambda functions."""
    leftovers = []
    try:
        paginator = lam.get_paginator("list_functions")
        for page in paginator.paginate():
            for fn in page.get("Functions", []):
                name = fn["FunctionName"]
                if is_nis2scan_test(name):
                    leftovers.append(f"Lambda Function: {name}")
    except Exception as exc:
        print(f"  WARN: Cannot check Lambda functions: {exc}")
    return leftovers


def check_cloudwatch_alarms(cw: object) -> list[str]:
    """Check for leftover nis2scan CloudWatch alarms."""
    leftovers = []
    try:
        paginator = cw.get_paginator("describe_alarms")
        for page in paginator.paginate(AlarmNamePrefix=NAME_PREFIX):
            for alarm in page.get("MetricAlarms", []):
                leftovers.append(f"CloudWatch Alarm: {alarm['AlarmName']}")
    except Exception as exc:
        print(f"  WARN: Cannot check CloudWatch alarms: {exc}")
    return leftovers


def check_alb(elbv2: object) -> list[str]:
    """Check for leftover nis2scan ALBs."""
    leftovers = []
    try:
        paginator = elbv2.get_paginator("describe_load_balancers")
        for page in paginator.paginate():
            for lb in page.get("LoadBalancers", []):
                name = lb["LoadBalancerName"]
                # ALBs use n2s- prefix (shortened)
                if NAME_PREFIX in name or name.startswith("n2s-"):
                    # Verify via tags
                    try:
                        tags_resp = elbv2.describe_tags(ResourceArns=[lb["LoadBalancerArn"]])
                        for td in tags_resp.get("TagDescriptions", []):
                            for tag in td.get("Tags", []):
                                if tag["Key"] == "Project" and tag["Value"] == TAG_PROJECT:
                                    leftovers.append(f"ALB: {name} ({lb['LoadBalancerArn']})")
                    except Exception:
                        pass
    except Exception as exc:
        print(f"  WARN: Cannot check ALBs: {exc}")
    return leftovers


def check_db_subnet_groups(rds: object) -> list[str]:
    """Check for leftover nis2scan DB subnet groups."""
    leftovers = []
    try:
        resp = rds.describe_db_subnet_groups()
        for sg in resp.get("DBSubnetGroups", []):
            name = sg["DBSubnetGroupName"]
            if is_nis2scan_test(name):
                leftovers.append(f"DB Subnet Group: {name}")
    except Exception as exc:
        print(f"  WARN: Cannot check DB subnet groups: {exc}")
    return leftovers


def check_instance_profiles(iam: object) -> list[str]:
    """Check for leftover nis2scan instance profiles."""
    leftovers = []
    try:
        paginator = iam.get_paginator("list_instance_profiles")
        for page in paginator.paginate():
            for profile in page["InstanceProfiles"]:
                name = profile["InstanceProfileName"]
                if is_nis2scan_test(name):
                    leftovers.append(f"Instance Profile: {name}")
    except Exception as exc:
        print(f"  WARN: Cannot check instance profiles: {exc}")
    return leftovers


def check_target_groups(elbv2: object) -> list[str]:
    """Check for leftover nis2scan target groups."""
    leftovers = []
    try:
        paginator = elbv2.get_paginator("describe_target_groups")
        for page in paginator.paginate():
            for tg in page.get("TargetGroups", []):
                name = tg["TargetGroupName"]
                if is_nis2scan_test(name):
                    leftovers.append(f"Target Group: {name}")
    except Exception as exc:
        print(f"  WARN: Cannot check target groups: {exc}")
    return leftovers


def check_account_settings(session: object) -> list[str]:
    """Check account-level settings are restored to safe defaults."""
    leftovers = []

    # S3 public access block — all 4 should be true
    try:
        s3control = session.client("s3control")
        sts = session.client("sts")
        account_id = sts.get_caller_identity()["Account"]
        try:
            resp = s3control.get_public_access_block(AccountId=account_id)
            config = resp.get("PublicAccessBlockConfiguration", {})
            for setting in ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]:
                if not config.get(setting, False):
                    leftovers.append(f"Account Setting: S3 {setting} is false (should be true)")
        except Exception:
            leftovers.append("Account Setting: S3 public access block not configured")
    except Exception as exc:
        print(f"  WARN: Cannot check S3 public access block: {exc}")

    # EBS default encryption — should be true
    try:
        ec2 = session.client("ec2")
        resp = ec2.get_ebs_encryption_by_default()
        if not resp.get("EbsEncryptionByDefault", True):
            leftovers.append("Account Setting: EBS default encryption is disabled")
    except Exception as exc:
        print(f"  WARN: Cannot check EBS encryption default: {exc}")

    # Password policy — should be deleted (AWS defaults) or strong
    try:
        iam = session.client("iam")
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        if policy.get("MinimumPasswordLength", 0) == 8 and not policy.get("RequireSymbols", True):
            leftovers.append("Account Setting: Weak password policy still active (MinLength=8, no symbols)")
    except Exception:
        pass  # NoSuchEntity = no policy = OK (AWS defaults)

    return leftovers


def main() -> None:
    args = parse_args()
    region = args.region

    print(f"nis2scan post-destroy verification (region={region})")
    print("=" * 60)

    session = boto3.Session(region_name=region)
    iam = session.client("iam")
    s3 = session.client("s3")
    ec2 = session.client("ec2")
    rds = session.client("rds")
    kms = session.client("kms")
    ct = session.client("cloudtrail")
    logs = session.client("logs")
    ecr = session.client("ecr")
    lam = session.client("lambda")
    cw = session.client("cloudwatch")
    elbv2 = session.client("elbv2")

    all_leftovers: list[str] = []

    checks = [
        ("IAM Users", lambda: check_iam_users(iam)),
        ("IAM Policies", lambda: check_iam_policies(iam)),
        ("IAM Roles", lambda: check_iam_roles(iam)),
        ("Virtual MFA Devices", lambda: check_mfa_devices(iam)),
        ("Instance Profiles", lambda: check_instance_profiles(iam)),
        ("S3 Buckets", lambda: check_s3_buckets(s3)),
        ("KMS Keys", lambda: check_kms_keys(kms)),
        ("EC2 Resources", lambda: check_ec2_resources(ec2)),
        ("RDS Instances", lambda: check_rds_instances(rds)),
        ("DB Subnet Groups", lambda: check_db_subnet_groups(rds)),
        ("CloudTrail Trails", lambda: check_cloudtrail(ct)),
        ("CloudWatch Log Groups", lambda: check_cloudwatch_log_groups(logs)),
        ("ECR Repositories", lambda: check_ecr_repos(ecr)),
        ("Lambda Functions", lambda: check_lambda_functions(lam)),
        ("CloudWatch Alarms", lambda: check_cloudwatch_alarms(cw)),
        ("Application Load Balancers", lambda: check_alb(elbv2)),
        ("Target Groups", lambda: check_target_groups(elbv2)),
        ("Account Settings", lambda: check_account_settings(session)),
    ]

    for label, check_fn in checks:
        print(f"\nChecking {label}...")
        found = check_fn()
        if found:
            for item in found:
                print(f"  LEFTOVER: {item}")
            all_leftovers.extend(found)
        else:
            print("  OK — none found")

    print("\n" + "=" * 60)
    if all_leftovers:
        print(f"FAIL: {len(all_leftovers)} leftover nis2scan resource(s) found!")
        print("\nLeftover resources:")
        for item in all_leftovers:
            print(f"  - {item}")
        sys.exit(1)
    else:
        print("PASS: No nis2scan resources found — account is clean.")
        sys.exit(0)


if __name__ == "__main__":
    main()
