"""Tests for the minimal Graph REST helper (pagination, auth, error surface)."""

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest

from nis2scan.engine.providers.azure.graph import graph_get_all


def _credential() -> MagicMock:
    credential = MagicMock(name="credential")
    credential.get_token.return_value = SimpleNamespace(token="test-token")
    return credential


def test_follows_odata_next_link_pagination():
    pages = {
        "https://graph.microsoft.com/v1.0/things": {
            "value": [{"id": "1"}],
            "@odata.nextLink": "https://graph.microsoft.com/v1.0/things?$skiptoken=x",
        },
        "https://graph.microsoft.com/v1.0/things?$skiptoken=x": {"value": [{"id": "2"}]},
    }
    seen_auth: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen_auth.append(request.headers["Authorization"])
        return httpx.Response(200, content=json.dumps(pages[str(request.url)]))

    items = asyncio.run(
        graph_get_all(
            _credential(),
            "https://graph.microsoft.com/v1.0/things",
            transport=httpx.MockTransport(handler),
        )
    )

    assert [item["id"] for item in items] == ["1", "2"]
    assert seen_auth == ["Bearer test-token"] * 2


def test_http_error_raises():
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(403, content=json.dumps({"error": {"code": "Authorization_RequestDenied"}}))

    with pytest.raises(httpx.HTTPStatusError):
        asyncio.run(
            graph_get_all(
                _credential(),
                "https://graph.microsoft.com/v1.0/things",
                transport=httpx.MockTransport(handler),
            )
        )
