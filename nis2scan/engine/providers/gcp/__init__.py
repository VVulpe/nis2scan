"""GCP provider — NIS2 compliance checks for Google Cloud Platform."""

from nis2scan.engine.providers.gcp.checks import register_all_gcp_checks

__all__ = ["register_all_gcp_checks"]
