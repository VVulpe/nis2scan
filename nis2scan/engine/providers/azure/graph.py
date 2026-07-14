"""Minimal Microsoft Graph REST helper — direct HTTPS, no msgraph-sdk.

Some checks need Graph endpoints that the v1.0 SDK does not generate
(e.g. the beta report servicePrincipalSignInActivities). This helper calls
Graph directly with the session credential; it is also the migration path
away from the heavyweight kiota-generated SDK (see MEMORY.md: msgraph-sdk
is not installable on default Windows due to MAX_PATH).
"""

from typing import Any

GRAPH_SCOPE = "https://graph.microsoft.com/.default"


async def graph_get_all(
    credential: Any,
    url: str,
    timeout: float = 30.0,
    transport: Any = None,
) -> list[dict[str, Any]]:
    """GET a Graph collection and follow @odata.nextLink pagination.

    Args:
        credential: azure.identity sync TokenCredential (as held by AzureSession).
        url: Absolute Graph collection URL (v1.0 or beta).
        timeout: Per-request timeout in seconds.
        transport: Optional httpx transport override (tests use MockTransport).

    Returns:
        All items from the collection's ``value`` arrays.

    Raises:
        httpx.HTTPStatusError: On non-2xx responses (checks convert this to
        CheckError — fail-safe per ADR-0016).
    """
    import asyncio

    import httpx

    # azure.identity sync credentials block; keep the event loop responsive.
    token = await asyncio.to_thread(credential.get_token, GRAPH_SCOPE)
    headers = {"Authorization": f"Bearer {token.token}"}

    items: list[dict[str, Any]] = []
    async with httpx.AsyncClient(timeout=timeout, transport=transport) as client:
        next_url: str | None = url
        while next_url:
            response = await client.get(next_url, headers=headers)
            response.raise_for_status()
            payload = response.json()
            items.extend(payload.get("value", []))
            next_url = payload.get("@odata.nextLink")
    return items
