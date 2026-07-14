"""Test harness for Azure checks — MagicMock-based session double.

Azure checks consume AzureSession via `session.get_client(ClientClass, sub_id)`
and iterate `session.subscription_ids`. FakeAzureSession returns pre-registered
mock clients keyed by the client CLASS NAME, so tests never import the heavy
azure-mgmt classes themselves:

    session = FakeAzureSession({"SecurityCenter": sc_mock})

Checks that construct SDK clients directly (e.g. ManagementGroupsMgmtClient)
are patched per test via monkeypatch on the azure module.

SDK response objects are built with types.SimpleNamespace — the checks only
read attributes.
"""

from typing import Any
from unittest.mock import MagicMock

SUB_ID = "00000000-0000-0000-0000-000000000001"


class FakeAzureSession:
    """Test double for AzureSession (see nis2scan/engine/providers/azure/session.py)."""

    def __init__(
        self,
        clients: dict[str, Any] | None = None,
        subscription_ids: list[str] | None = None,
    ) -> None:
        self.credential = MagicMock(name="credential")
        self.subscription_ids = subscription_ids or [SUB_ID]
        self._clients = clients or {}

    @property
    def subscription_id(self) -> str:
        return self.subscription_ids[0]

    def get_client(self, client_class: type, subscription_id: str | None = None) -> Any:
        name = client_class.__name__
        if name not in self._clients:
            raise AssertionError(f"No mock client registered for {name}")
        return self._clients[name]
