"""Simple synchronous event bus for scan lifecycle events.

Phase 1: Single subscriber (CLI progress printer).
Phase 2: Replace with Redis/Celery for DB persistence, alerting, webhooks.
"""

from collections.abc import Callable
from enum import StrEnum
from typing import Any

EventHandler = Callable[[dict[str, Any]], None]


class ScanEvent(StrEnum):
    """Scan lifecycle events."""

    SCAN_STARTED = "scan_started"
    CHECK_STARTED = "check_started"
    CHECK_COMPLETED = "check_completed"
    FINDING_CRITICAL = "finding_critical"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"


class EventBus:
    """Simple synchronous event bus.

    In Phase 1, the only subscriber is the CLI progress printer.
    In Phase 2, add: DB persister, alerting service, webhook dispatcher.
    """

    def __init__(self) -> None:
        self._handlers: dict[ScanEvent, list[EventHandler]] = {}

    def subscribe(self, event: ScanEvent, handler: EventHandler) -> None:
        """Register a handler for an event type."""
        self._handlers.setdefault(event, []).append(handler)

    def emit(self, event: ScanEvent, data: dict[str, Any]) -> None:
        """Emit an event to all registered handlers."""
        for handler in self._handlers.get(event, []):
            handler(data)
