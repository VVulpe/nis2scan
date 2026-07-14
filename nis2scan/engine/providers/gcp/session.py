"""GCP session management — multi-project support."""

from typing import Any

import structlog

from nis2scan.engine.models.config import ProviderConfig

logger = structlog.get_logger()


class GcpSession:
    """Wrapper around Google Cloud credentials with multi-project support."""

    def __init__(self, credentials: Any, project_ids: list[str]) -> None:
        self.credentials = credentials
        self.project_ids = project_ids

    @property
    def project_id(self) -> str:
        """Get the primary project ID."""
        return self.project_ids[0]

    def client(self, client_class: type, project_id: str | None = None) -> Any:
        """Create a Google Cloud SDK client.

        Args:
            client_class: The Google Cloud client class (e.g., storage.Client).
            project_id: Optional project override. Defaults to primary.
        """
        proj = project_id or self.project_id
        return client_class(credentials=self.credentials, project=proj)

    def service(self, service_name: str, version: str = "v1") -> Any:
        """Create a Google API discovery service client.

        Args:
            service_name: API service name (e.g., 'sqladmin', 'iam').
            version: API version (default: 'v1').
        """
        from googleapiclient.discovery import build

        return build(service_name, version, credentials=self.credentials, cache_discovery=False)


def create_gcp_session(config: ProviderConfig) -> GcpSession:
    """Create a GCP session from provider config."""
    import google.auth

    credentials, default_project = google.auth.default()

    # Get project IDs from config or use default
    project_ids = config.accounts or []
    if not project_ids:
        if default_project:
            project_ids = [default_project]
        else:
            from google.cloud.resourcemanager_v3 import ProjectsClient

            client = ProjectsClient(credentials=credentials)
            project_ids = [p.project_id for p in client.search_projects() if p.state.name == "ACTIVE"]

    if not project_ids:
        msg = "No GCP projects found. Set accounts in config or ensure credentials have access."
        raise ValueError(msg)

    logger.info("gcp.session.created", project_count=len(project_ids))
    return GcpSession(credentials=credentials, project_ids=project_ids)
