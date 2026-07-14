#!/usr/bin/env python3
"""Enable a virtual MFA device for an IAM user.

Called by Terraform's null_resource local-exec provisioner during
integration-test infrastructure setup.

Usage:
    python3 enable_mfa.py --username USER --serial MFA_ARN --seed BASE32_SEED
"""

from __future__ import annotations

import argparse
import time

import boto3
import pyotp


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Enable a virtual MFA device for an IAM user")
    parser.add_argument(
        "--username",
        required=True,
        help="IAM username to attach the MFA device to",
    )
    parser.add_argument(
        "--serial",
        required=True,
        help="ARN / serial number of the virtual MFA device",
    )
    parser.add_argument(
        "--seed",
        required=True,
        help="Base-32 encoded seed of the virtual MFA device",
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()

    totp = pyotp.TOTP(args.seed)

    # Generate two consecutive TOTP codes.  AWS requires two codes from
    # successive 30-second windows.
    code1 = totp.now()
    # Wait for the next time window to get a different code.
    time.sleep(30)
    code2 = totp.now()

    iam = boto3.client("iam")
    iam.enable_mfa_device(
        UserName=args.username,
        SerialNumber=args.serial,
        AuthenticationCode1=code1,
        AuthenticationCode2=code2,
    )

    print(f"MFA device {args.serial} enabled for user {args.username}")


if __name__ == "__main__":
    main()
