"""AWS provider — boto3-based checks for §30 BSIG compliance."""

from nis2scan.engine.providers.aws.checks import register_all_aws_checks

__all__ = ["register_all_aws_checks"]
