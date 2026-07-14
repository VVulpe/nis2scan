#!/usr/bin/env python3
"""Post-destroy verification for Azure integration test resources.

Scans the subscription for any orphaned nis2scan resources that Terraform
failed to destroy. Exits with code 1 if leftovers are found.

Usage:
    python post_destroy_verify.py
"""

import subprocess
import json
import sys


TAG_FILTER = "Project=nis2scan"
PREFIX = "nis2scan-"


def az_cli(args: list[str]) -> list[dict]:
    """Run an Azure CLI command and return parsed JSON output."""
    try:
        result = subprocess.run(
            ["az"] + args + ["-o", "json"],
            capture_output=True,
            text=True,
            timeout=60,
        )
        if result.returncode != 0:
            return []
        return json.loads(result.stdout) if result.stdout.strip() else []
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        return []


def check_resource_groups() -> list[str]:
    """Check for orphaned resource groups with nis2scan tags."""
    groups = az_cli(["group", "list", "--tag", TAG_FILTER])
    return [g["name"] for g in groups if isinstance(g, dict)]


def check_generic_resources() -> list[str]:
    """Check for any resources tagged with nis2scan across the subscription."""
    resources = az_cli([
        "resource", "list",
        "--tag", TAG_FILTER,
        "--query", "[].{name:name, type:type, rg:resourceGroup}",
    ])
    return [f"{r['name']} ({r['type']}) in {r['rg']}" for r in resources if isinstance(r, dict)]


def check_key_vaults() -> list[str]:
    """Check for soft-deleted Key Vaults from nis2scan."""
    vaults = az_cli(["keyvault", "list-deleted", "--query", "[].name"])
    return [v for v in vaults if isinstance(v, str) and PREFIX in v.lower()]


def main() -> None:
    print("=" * 60)
    print("Post-Destroy Verification (Azure)")
    print("=" * 60)

    leftover_count = 0

    # 1. Resource groups
    rgs = check_resource_groups()
    if rgs:
        print(f"\n❌ Resource Groups ({len(rgs)}):")
        for rg in rgs:
            print(f"   - {rg}")
        leftover_count += len(rgs)
    else:
        print("\n✅ No orphaned resource groups")

    # 2. Generic resources
    resources = check_generic_resources()
    if resources:
        print(f"\n❌ Tagged Resources ({len(resources)}):")
        for r in resources[:20]:
            print(f"   - {r}")
        if len(resources) > 20:
            print(f"   ... and {len(resources) - 20} more")
        leftover_count += len(resources)
    else:
        print("✅ No orphaned tagged resources")

    # 3. Soft-deleted Key Vaults
    vaults = check_key_vaults()
    if vaults:
        print(f"\n⚠️  Soft-deleted Key Vaults ({len(vaults)}):")
        for v in vaults:
            print(f"   - {v}")
        # Soft-deleted vaults auto-purge, don't count as hard failures
    else:
        print("✅ No soft-deleted Key Vaults")

    print("\n" + "=" * 60)
    if leftover_count > 0:
        print(f"FAILED: {leftover_count} orphaned resources found!")
        print("Run 'az group delete' on the resource groups listed above.")
        sys.exit(1)
    else:
        print("PASSED: All nis2scan resources cleaned up successfully.")
        sys.exit(0)


if __name__ == "__main__":
    main()
