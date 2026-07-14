"""Tests for the check registry — idempotent registration (SaaS long-process bug)."""

from nis2scan.engine.registry import CheckRegistry


def test_reregistration_never_duplicates():
    # Founder-reported: an 'AWS' scan showed 0/156 checks — 52 x 3, because
    # every eager scan re-registered all checks and the registry appended.
    CheckRegistry.reset()
    try:
        from nis2scan.engine.providers.aws.checks import register_all_aws_checks

        register_all_aws_checks()
        first = len(CheckRegistry.get_instance().get_checks_for_provider("aws"))

        register_all_aws_checks()
        register_all_aws_checks()
        third = len(CheckRegistry.get_instance().get_checks_for_provider("aws"))

        assert first == 52
        assert third == 52
    finally:
        CheckRegistry.reset()


def test_providers_stay_separated():
    CheckRegistry.reset()
    try:
        from nis2scan.engine.providers.aws.checks import register_all_aws_checks
        from nis2scan.engine.providers.azure.checks import register_all_azure_checks

        register_all_aws_checks()
        register_all_azure_checks()

        registry = CheckRegistry.get_instance()
        aws = registry.get_checks_for_provider("aws")
        azure = registry.get_checks_for_provider("azure")

        assert all(c.check_id.startswith("AWS-") for c in aws)
        assert all(c.check_id.startswith("AZ-") for c in azure)
    finally:
        CheckRegistry.reset()
