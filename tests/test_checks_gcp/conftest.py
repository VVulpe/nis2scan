"""Test harness for GCP checks — MagicMock-based session double.

GCP checks consume GcpSession three ways:
1. `session.client(ClientClass)` — mocked by class name via FakeGcpSession
2. `session.service(name, version)` — googleapiclient discovery; mocked by
   service name via FakeGcpSession (MagicMock chains projects().x().execute())
3. Direct construction (e.g. securitycenter_v1.SecurityCenterClient(...)) —
   monkeypatched on the google.cloud module per test
"""

from typing import Any
from unittest.mock import MagicMock

PROJECT_ID = "test-project-123"


class FakeGcpSession:
    """Test double for GcpSession (see nis2scan/engine/providers/gcp/session.py)."""

    def __init__(
        self,
        clients: dict[str, Any] | None = None,
        services: dict[str, Any] | None = None,
        project_ids: list[str] | None = None,
    ) -> None:
        self.credentials = MagicMock(name="credentials")
        self.project_ids = project_ids or [PROJECT_ID]
        self._clients = clients or {}
        self._services = services or {}

    @property
    def project_id(self) -> str:
        return self.project_ids[0]

    def client(self, client_class: type, project_id: str | None = None) -> Any:
        name = client_class.__name__
        if name not in self._clients:
            raise AssertionError(f"No mock client registered for {name}")
        return self._clients[name]

    def service(self, service_name: str, version: str = "v1") -> Any:
        if service_name not in self._services:
            raise AssertionError(f"No mock service registered for {service_name}")
        return self._services[service_name]
