"""Azure provider — NIS2 compliance checks for Microsoft Azure."""

from nis2scan.engine.providers.azure.checks import register_all_azure_checks

__all__ = ["register_all_azure_checks"]
