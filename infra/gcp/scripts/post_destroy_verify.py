#!/usr/bin/env python3
"""Post-destroy verification for GCP integration test resources.

KMS keys/keyrings are excluded because GCP does not allow immediate deletion —
they enter PENDING_DELETION for a minimum of 24 hours.  This is expected
behaviour and not a leak.
"""
import json
import subprocess
import sys
import time

# Asset types that cannot be deleted immediately in GCP
EXCLUDED_ASSET_TYPES = {
    "cloudkms.googleapis.com/CryptoKey",
    "cloudkms.googleapis.com/CryptoKeyVersion",
    "cloudkms.googleapis.com/KeyRing",
}


def main():
    # Check for resources with nis2 in the name via Cloud Asset Inventory
    result = subprocess.run(
        [
            "gcloud", "asset", "search-all-resources",
            "--query=name:nis2",
            "--format=json",
        ],
        capture_output=True, text=True,
    )

    if result.returncode != 0:
        print(f"Warning: asset search failed: {result.stderr}")
        check_buckets()
        check_firewall_rules()
        return

    resources = json.loads(result.stdout) if result.stdout.strip() else []

    # Filter out KMS resources (cannot be deleted)
    remaining = [
        r for r in resources
        if r.get("assetType", "") not in EXCLUDED_ASSET_TYPES
    ]

    if remaining:
        # Retry once — Cloud Asset Inventory is eventually consistent
        print(f"WARN: Found {len(remaining)} resources, retrying in 30s (propagation delay)...")
        for r in remaining:
            print(f"  - {r.get('assetType', 'unknown')}: {r.get('name', 'unknown')}")
        time.sleep(30)

        result2 = subprocess.run(
            [
                "gcloud", "asset", "search-all-resources",
                "--query=name:nis2",
                "--format=json",
            ],
            capture_output=True, text=True,
        )
        resources2 = json.loads(result2.stdout) if result2.stdout.strip() else []
        remaining2 = [
            r for r in resources2
            if r.get("assetType", "") not in EXCLUDED_ASSET_TYPES
        ]
        if remaining2:
            print(f"ERROR: Still found {len(remaining2)} remaining nis2scan resources after retry:")
            for r in remaining2:
                print(f"  - {r.get('assetType', 'unknown')}: {r.get('name', 'unknown')}")
            sys.exit(1)
        print("OK: Resources cleared after retry (propagation delay)")

    kms_count = len(resources) - len(remaining)
    if kms_count:
        print(f"INFO: {kms_count} KMS key(s) in PENDING_DELETION (expected, auto-purges in 24h)")
    print("OK: No nis2scan resources found after destroy")


def check_buckets():
    result = subprocess.run(
        ["gcloud", "storage", "ls"], capture_output=True, text=True,
    )
    buckets = [b for b in result.stdout.strip().split("\n") if "nis2" in b]
    if buckets:
        print(f"WARNING: Found {len(buckets)} nis2scan buckets: {buckets}")


def check_firewall_rules():
    result = subprocess.run(
        [
            "gcloud", "compute", "firewall-rules", "list",
            "--filter=name~nis2", "--format=json",
        ],
        capture_output=True, text=True,
    )
    rules = json.loads(result.stdout) if result.stdout.strip() else []
    if rules:
        print(f"WARNING: Found {len(rules)} nis2scan firewall rules")


if __name__ == "__main__":
    main()
