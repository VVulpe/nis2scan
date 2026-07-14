#!/usr/bin/env python3
"""Pre-destroy cleanup for nis2scan integration-test resources.

Handles out-of-band resources that Terraform cannot cleanly destroy on its own:
- Deactivates MFA devices on nis2scan IAM users (created by enable_mfa.py)
- Deletes login profiles that may block IAM user force_destroy

Only touches resources tagged Project=nis2scan or named with 'nis2scan-' prefix.

Usage:
    python3 pre_destroy_cleanup.py [--dry-run]
"""

from __future__ import annotations

import argparse

import boto3

TAG_PROJECT = "nis2scan"
NAME_PREFIX = "nis2scan-"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Pre-destroy cleanup for nis2scan resources")
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print what would be done without making changes",
    )
    return parser.parse_args()


def is_nis2scan_user(iam_client: object, username: str) -> bool:
    """Check if an IAM user belongs to nis2scan by name prefix or tags."""
    if username.startswith(NAME_PREFIX) or "-nr9-" in username or "-nr10-" in username:
        return True
    try:
        resp = iam_client.list_user_tags(UserName=username)
        for tag in resp.get("Tags", []):
            if tag["Key"] == "Project" and tag["Value"] == TAG_PROJECT:
                return True
    except Exception:
        pass
    return False


def deactivate_mfa_devices(iam_client: object, dry_run: bool) -> int:
    """Deactivate and delete MFA devices on nis2scan IAM users."""
    count = 0
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            if not is_nis2scan_user(iam_client, username):
                continue

            # List MFA devices for this user
            try:
                mfa_resp = iam_client.list_mfa_devices(UserName=username)
            except Exception as exc:
                print(f"  WARN: Cannot list MFA for {username}: {exc}")
                continue

            for device in mfa_resp.get("MFADevices", []):
                serial = device["SerialNumber"]
                if dry_run:
                    print(f"  [DRY-RUN] Would deactivate MFA {serial} on {username}")
                else:
                    print(f"  Deactivating MFA {serial} on {username}")
                    try:
                        iam_client.deactivate_mfa_device(UserName=username, SerialNumber=serial)
                    except Exception as exc:
                        print(f"    WARN: deactivate failed: {exc}")

                    # Delete the virtual MFA device
                    if ":mfa/" in serial:
                        try:
                            iam_client.delete_virtual_mfa_device(SerialNumber=serial)
                            print(f"    Deleted virtual MFA device {serial}")
                        except Exception as exc:
                            print(f"    WARN: delete virtual MFA failed: {exc}")
                count += 1
    return count


def delete_login_profiles(iam_client: object, dry_run: bool) -> int:
    """Delete login profiles on nis2scan IAM users."""
    count = 0
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            if not is_nis2scan_user(iam_client, username):
                continue

            try:
                iam_client.get_login_profile(UserName=username)
            except iam_client.exceptions.NoSuchEntityException:
                continue
            except Exception:
                continue

            if dry_run:
                print(f"  [DRY-RUN] Would delete login profile for {username}")
            else:
                print(f"  Deleting login profile for {username}")
                try:
                    iam_client.delete_login_profile(UserName=username)
                except Exception as exc:
                    print(f"    WARN: delete login profile failed: {exc}")
            count += 1
    return count


def delete_access_keys(iam_client: object, dry_run: bool) -> int:
    """Delete access keys on nis2scan IAM users."""
    count = 0
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            if not is_nis2scan_user(iam_client, username):
                continue

            try:
                keys_resp = iam_client.list_access_keys(UserName=username)
            except Exception:
                continue

            for key in keys_resp.get("AccessKeyMetadata", []):
                key_id = key["AccessKeyId"]
                if dry_run:
                    print(f"  [DRY-RUN] Would delete access key {key_id} for {username}")
                else:
                    print(f"  Deleting access key {key_id} for {username}")
                    try:
                        iam_client.delete_access_key(UserName=username, AccessKeyId=key_id)
                    except Exception as exc:
                        print(f"    WARN: delete access key failed: {exc}")
                count += 1
    return count


def detach_user_policies(iam_client: object, dry_run: bool) -> int:
    """Detach managed policies from nis2scan IAM users."""
    count = 0
    paginator = iam_client.get_paginator("list_users")
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            if not is_nis2scan_user(iam_client, username):
                continue

            try:
                policies = iam_client.list_attached_user_policies(UserName=username).get("AttachedPolicies", [])
            except Exception:
                continue

            for pol in policies:
                if dry_run:
                    print(f"  [DRY-RUN] Would detach {pol['PolicyArn']} from {username}")
                else:
                    print(f"  Detaching {pol['PolicyArn']} from {username}")
                    try:
                        iam_client.detach_user_policy(UserName=username, PolicyArn=pol["PolicyArn"])
                    except Exception as exc:
                        print(f"    WARN: detach failed: {exc}")
                count += 1
    return count


def main() -> None:
    args = parse_args()
    mode = "[DRY-RUN] " if args.dry_run else ""

    print(f"{mode}nis2scan pre-destroy cleanup")
    print("=" * 60)

    iam = boto3.client("iam")

    print(f"\n{mode}1. Deactivating MFA devices on nis2scan users...")
    mfa_count = deactivate_mfa_devices(iam, args.dry_run)
    print(f"   {mfa_count} MFA device(s) processed")

    print(f"\n{mode}2. Deleting login profiles on nis2scan users...")
    login_count = delete_login_profiles(iam, args.dry_run)
    print(f"   {login_count} login profile(s) processed")

    print(f"\n{mode}3. Deleting access keys on nis2scan users...")
    key_count = delete_access_keys(iam, args.dry_run)
    print(f"   {key_count} access key(s) processed")

    print(f"\n{mode}4. Detaching policies from nis2scan users...")
    pol_count = detach_user_policies(iam, args.dry_run)
    print(f"   {pol_count} policy attachment(s) processed")

    total = mfa_count + login_count + key_count + pol_count
    print(f"\n{mode}Cleanup complete: {total} resource(s) processed")

    if total == 0:
        print("Nothing to clean up — all clear.")


if __name__ == "__main__":
    main()
