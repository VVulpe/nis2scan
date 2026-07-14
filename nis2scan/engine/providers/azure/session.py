"""Azure session management — multi-subscription support."""

from typing import Any

import structlog

from nis2scan.engine.models.config import ProviderConfig

logger = structlog.get_logger()


class AzureSession:
    """Wrapper around Azure credentials with multi-subscription support."""

    def __init__(self, credential: Any, subscription_ids: list[str]) -> None:
        self.credential = credential
        self.subscription_ids = subscription_ids

    @property
    def subscription_id(self) -> str:
        """Get the primary subscription ID."""
        return self.subscription_ids[0]

    def get_client(self, client_class: type, subscription_id: str | None = None) -> Any:
        """Create an Azure SDK management client.

        Args:
            client_class: The Azure management client class (e.g., SecurityCenter).
            subscription_id: Optional subscription override. Defaults to primary.
        """
        sub_id = subscription_id or self.subscription_id
        return client_class(self.credential, sub_id)


def create_azure_session(config: ProviderConfig) -> AzureSession:
    """Create an Azure session from provider config.

    Unattended cross-tenant mode (multi-tenant app + admin consent): when
    ``azure_tenant_id`` is set, the scanner's own app registration
    (AZURE_CLIENT_ID / AZURE_CLIENT_SECRET from the environment) authenticates
    against the CUSTOMER tenant. The customer grants Reader RBAC to the app's
    service principal once — no customer secrets are ever stored.
    """
    import os

    credential: Any
    if config.azure_tenant_id:
        from azure.identity import ClientSecretCredential

        client_id = os.environ.get("NIS2SCAN_AZURE_CLIENT_ID") or os.environ.get("AZURE_CLIENT_ID")
        client_secret = os.environ.get("NIS2SCAN_AZURE_CLIENT_SECRET") or os.environ.get("AZURE_CLIENT_SECRET")
        if not client_id or not client_secret:
            msg = (
                "azure_tenant_id ist gesetzt, aber die Scanner-App-Credentials fehlen "
                "(NIS2SCAN_AZURE_CLIENT_ID/NIS2SCAN_AZURE_CLIENT_SECRET bzw. AZURE_CLIENT_ID/AZURE_CLIENT_SECRET)."
            )
            raise ValueError(msg)
        credential = ClientSecretCredential(
            tenant_id=config.azure_tenant_id,
            client_id=client_id,
            client_secret=client_secret,
        )
    else:
        from azure.identity import DefaultAzureCredential

        credential = DefaultAzureCredential()

    # Get subscription IDs from config or discover them
    subscription_ids = config.subscription_ids or config.accounts or []
    if not subscription_ids:
        from azure.mgmt.resource.subscriptions import SubscriptionClient

        sub_client = SubscriptionClient(credential)
        subscription_ids = [sub.subscription_id for sub in sub_client.subscriptions.list() if sub.subscription_id]

    if not subscription_ids:
        msg = "No Azure subscriptions found. Set accounts in config or ensure credentials have access."
        raise ValueError(msg)

    logger.info("azure.session.created", subscription_count=len(subscription_ids))
    return AzureSession(credential=credential, subscription_ids=subscription_ids)
