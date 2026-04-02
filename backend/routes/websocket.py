"""
backend/routes/websocket.py

WebSocket endpoint for real-time agent log streaming.
The Streamlit dashboard connects here to receive live
agent messages, metric updates, and incident events.
"""

from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from core.events import event_bus

router = APIRouter()


class ConnectionManager:
    """Manages active WebSocket connections."""

    def __init__(self):
        self.active: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.active.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        self.active = [c for c in self.active if c != ws]

    async def broadcast(self, message: dict) -> None:
        dead = []
        for ws in self.active:
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


manager = ConnectionManager()


@router.websocket("/events")
async def websocket_events(websocket: WebSocket):
    """
    Stream all AetherGuard events to connected dashboard clients.

    Each message is a JSON dict:
        {
            "event_type":  "anomaly_detected",
            "incident_id": "INC-XXXXXXXX",
            "payload":     {...},
            "timestamp":   "2026-04-02T10:00:00Z"
        }
    """
    await manager.connect(websocket)
    try:
        while True:
            try:
                # Wait for next event with heartbeat timeout
                event = await asyncio.wait_for(
                    event_bus.get_next(),
                    timeout=5.0,
                )
                await websocket.send_json(event.to_dict())
            except asyncio.TimeoutError:
                # Send heartbeat to keep connection alive
                await websocket.send_json({"event_type": "heartbeat", "timestamp": ""})
            except Exception:
                break
    except WebSocketDisconnect:
        manager.disconnect(websocket)


@router.websocket("/metrics")
async def websocket_metrics(websocket: WebSocket):
    """
    Stream live metric snapshots every 5 seconds.
    Used by the real-time graphs on the dashboard.
    """
    from backend.dependencies import get_aws_simulator, get_network_simulator

    await websocket.accept()
    try:
        while True:
            try:
                aws_sim = get_aws_simulator()
                net_sim = get_network_simulator()
                payload = {
                    "aws_summary":     aws_sim.get_summary(),
                    "network_summary": net_sim.get_health_summary(),
                }
                await websocket.send_json(payload)
                await asyncio.sleep(5.0)
            except Exception:
                break
    except WebSocketDisconnect:
        pass