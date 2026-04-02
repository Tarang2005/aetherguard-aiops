"""
core/events.py

Typed internal event bus for AetherGuard.
Decouples simulators, agents, and API layer via publish/subscribe.
The WebSocket route subscribes to events and streams them to the dashboard.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable, Coroutine


# ── Event types ───────────────────────────────────────────────────────────────

class EventType(str, Enum):
    ANOMALY_DETECTED    = "anomaly_detected"
    RCA_COMPLETE        = "rca_complete"
    REMEDIATION_PLANNED = "remediation_planned"
    APPROVAL_NEEDED     = "approval_needed"
    APPROVAL_RECEIVED   = "approval_received"
    CHAOS_STARTED       = "chaos_started"
    CHAOS_COMPLETE      = "chaos_complete"
    INCIDENT_RESOLVED   = "incident_resolved"
    INCIDENT_DISMISSED  = "incident_dismissed"
    METRICS_UPDATED     = "metrics_updated"
    AGENT_MESSAGE       = "agent_message"
    ERROR               = "error"


# ── Event model ───────────────────────────────────────────────────────────────

@dataclass
class AetherEvent:
    event_type:  EventType
    incident_id: str
    payload:     dict[str, Any] = field(default_factory=dict)
    timestamp:   str = field(
        default_factory=lambda: datetime.now(timezone.utc).isoformat()
    )

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_type":  self.event_type.value,
            "incident_id": self.incident_id,
            "payload":     self.payload,
            "timestamp":   self.timestamp,
        }


# ── Event bus ─────────────────────────────────────────────────────────────────

AsyncHandler = Callable[[AetherEvent], Coroutine]


class EventBus:
    """
    Simple async pub/sub event bus.
    Agents publish events; WebSocket route and dashboard subscribe.

    Usage:
        bus = EventBus()

        # Subscribe
        async def on_anomaly(event: AetherEvent):
            print(event.payload)
        bus.subscribe(EventType.ANOMALY_DETECTED, on_anomaly)

        # Publish
        await bus.publish(AetherEvent(
            event_type=EventType.ANOMALY_DETECTED,
            incident_id="INC-001",
            payload={"anomaly_count": 3},
        ))
    """

    def __init__(self) -> None:
        self._subscribers: dict[EventType, list[AsyncHandler]] = {
            e: [] for e in EventType
        }
        # Broadcast queue for WebSocket streaming (all events)
        self._broadcast_queue: asyncio.Queue[AetherEvent] = asyncio.Queue(maxsize=500)

    def subscribe(self, event_type: EventType, handler: AsyncHandler) -> None:
        """Register an async handler for a specific event type."""
        self._subscribers[event_type].append(handler)

    def unsubscribe(self, event_type: EventType, handler: AsyncHandler) -> None:
        """Remove a handler."""
        self._subscribers[event_type] = [
            h for h in self._subscribers[event_type] if h != handler
        ]

    async def publish(self, event: AetherEvent) -> None:
        """Publish an event to all subscribers and the broadcast queue."""
        # Put in broadcast queue for WebSocket
        try:
            self._broadcast_queue.put_nowait(event)
        except asyncio.QueueFull:
            pass  # Drop oldest — non-critical

        # Fire all registered handlers
        handlers = self._subscribers.get(event.event_type, [])
        if handlers:
            await asyncio.gather(*[h(event) for h in handlers], return_exceptions=True)

    async def get_next(self) -> AetherEvent:
        """Wait for and return the next event (for WebSocket streaming)."""
        return await self._broadcast_queue.get()

    def publish_sync(self, event: AetherEvent) -> None:
        """
        Synchronous publish for use in non-async agent code.
        Drops into the broadcast queue only (no handler dispatch).
        """
        try:
            self._broadcast_queue.put_nowait(event)
        except asyncio.QueueFull:
            pass


# ── Singleton ─────────────────────────────────────────────────────────────────

# Global event bus — import this everywhere
event_bus = EventBus()


# ── Convenience publishers ────────────────────────────────────────────────────

def emit_anomaly_detected(incident_id: str, anomaly_count: int, severity: str) -> None:
    event_bus.publish_sync(AetherEvent(
        event_type=EventType.ANOMALY_DETECTED,
        incident_id=incident_id,
        payload={"anomaly_count": anomaly_count, "severity": severity},
    ))


def emit_approval_needed(incident_id: str, action: str, cost_delta: float) -> None:
    event_bus.publish_sync(AetherEvent(
        event_type=EventType.APPROVAL_NEEDED,
        incident_id=incident_id,
        payload={"action": action, "cost_delta_usd": cost_delta},
    ))


def emit_agent_message(incident_id: str, agent: str, content: str) -> None:
    event_bus.publish_sync(AetherEvent(
        event_type=EventType.AGENT_MESSAGE,
        incident_id=incident_id,
        payload={"agent": agent, "content": content},
    ))


def emit_metrics_updated(incident_id: str, aws_count: int, network_count: int) -> None:
    event_bus.publish_sync(AetherEvent(
        event_type=EventType.METRICS_UPDATED,
        incident_id=incident_id,
        payload={"aws_records": aws_count, "network_records": network_count},
    ))