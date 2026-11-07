"""Asynchronous Event Bus for real-time scan event streaming and UI updates."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Any, Callable, Coroutine, Dict, List, Optional


class EventType(str, Enum):
    SCAN_STARTED = "scan_started"
    SCAN_COMPLETED = "scan_completed"
    SCAN_FAILED = "scan_failed"
    SCAN_INTERRUPTED = "scan_interrupted"

    STAGE_STARTED = "stage_started"
    STAGE_COMPLETED = "stage_completed"
    STAGE_FAILED = "stage_failed"

    TOOL_STARTED = "tool_started"
    TOOL_OUTPUT = "tool_output"
    TOOL_COMPLETED = "tool_completed"
    TOOL_FAILED = "tool_failed"

    PORT_DISCOVERED = "port_discovered"
    SERVICE_DISCOVERED = "service_discovered"
    FINDING_DISCOVERED = "finding_discovered"

    LOG_MESSAGE = "log_message"
    PROGRESS_UPDATE = "progress_update"


@dataclass
class ScanEvent:
    event_type: EventType
    scan_id: str
    stage_name: Optional[str] = None
    tool_name: Optional[str] = None
    data: Dict[str, Any] = field(default_factory=dict)
    message: Optional[str] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


EventHandler = Callable[[ScanEvent], Coroutine[Any, Any, None]]


class EventBus:
    """Async Pub/Sub Event Bus for RootScan."""

    def __init__(self):
        self._subscribers: Dict[EventType, List[EventHandler]] = {
            evt: [] for evt in EventType
        }
        self._global_subscribers: List[EventHandler] = []
        self._event_history: List[ScanEvent] = []
        self._max_history = 1000

    def subscribe(self, event_type: EventType, handler: EventHandler) -> None:
        """Subscribe a callback to a specific event type."""
        if event_type in self._subscribers:
            self._subscribers[event_type].append(handler)

    def subscribe_all(self, handler: EventHandler) -> None:
        """Subscribe a callback to all published events."""
        self._global_subscribers.append(handler)

    def unsubscribe(self, handler: EventHandler) -> None:
        """Unsubscribe a callback from all lists."""
        for handlers in self._subscribers.values():
            if handler in handlers:
                handlers.remove(handler)
        if handler in self._global_subscribers:
            self._global_subscribers.remove(handler)

    async def publish(self, event: ScanEvent) -> None:
        """Publish an event to all registered listeners asynchronously."""
        # Record history
        self._event_history.append(event)
        if len(self._event_history) > self._max_history:
            self._event_history.pop(0)

        # Notify specific subscribers
        handlers = list(self._subscribers.get(event.event_type, [])) + list(self._global_subscribers)
        if not handlers:
            return

        tasks = [asyncio.create_task(self._safe_call(handler, event)) for handler in handlers]
        await asyncio.gather(*tasks, return_exceptions=True)

    async def _safe_call(self, handler: EventHandler, event: ScanEvent) -> None:
        """Execute handler with exception trapping to avoid breaking publisher."""
        try:
            await handler(event)
        except Exception as e:
            # Avoid crashing event pipeline on subscriber error
            pass

    def get_history(self, scan_id: Optional[str] = None) -> List[ScanEvent]:
        """Retrieve recent events, optionally filtered by scan_id."""
        if scan_id is None:
            return list(self._event_history)
        return [evt for evt in self._event_history if evt.scan_id == scan_id]


# Global EventBus singleton
_event_bus: Optional[EventBus] = None


def get_event_bus() -> EventBus:
    global _event_bus
    if _event_bus is None:
        _event_bus = EventBus()
    return _event_bus

