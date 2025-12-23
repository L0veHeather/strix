"""WebSocket API.

Real-time communication with the frontend via WebSocket.
"""

from __future__ import annotations

import asyncio
import json
import logging
from typing import Any, Callable

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from strix.server.app import get_event_bus
from strix.engine import EventType

logger = logging.getLogger(__name__)
router = APIRouter()


class ConnectionManager:
    """Manages WebSocket connections."""
    
    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}
        self.scan_subscriptions: dict[str, set[str]] = {}  # scan_id -> connection_ids
        self._event_handlers: dict[str, Callable] = {}
    
    async def connect(self, websocket: WebSocket, client_id: str):
        """Accept a new WebSocket connection."""
        await websocket.accept()
        self.active_connections[client_id] = websocket
        logger.info(f"Client {client_id} connected. Total: {len(self.active_connections)}")
    
    def disconnect(self, client_id: str):
        """Handle client disconnection."""
        if client_id in self.active_connections:
            del self.active_connections[client_id]
        
        # Remove from all subscriptions
        for scan_id, subscribers in list(self.scan_subscriptions.items()):
            subscribers.discard(client_id)
            if not subscribers:
                del self.scan_subscriptions[scan_id]
        
        logger.info(f"Client {client_id} disconnected. Total: {len(self.active_connections)}")
    
    def subscribe_to_scan(self, client_id: str, scan_id: str):
        """Subscribe client to scan updates."""
        if scan_id not in self.scan_subscriptions:
            self.scan_subscriptions[scan_id] = set()
        self.scan_subscriptions[scan_id].add(client_id)
        logger.debug(f"Client {client_id} subscribed to scan {scan_id}")
    
    def unsubscribe_from_scan(self, client_id: str, scan_id: str):
        """Unsubscribe client from scan updates."""
        if scan_id in self.scan_subscriptions:
            self.scan_subscriptions[scan_id].discard(client_id)
    
    async def send_personal(self, client_id: str, message: dict[str, Any]):
        """Send message to specific client."""
        if client_id in self.active_connections:
            try:
                await self.active_connections[client_id].send_json(message)
            except Exception as e:
                logger.error(f"Failed to send to {client_id}: {e}")
    
    async def broadcast(self, message: dict[str, Any]):
        """Broadcast message to all connected clients."""
        for client_id, websocket in list(self.active_connections.items()):
            try:
                await websocket.send_json(message)
            except Exception as e:
                logger.error(f"Failed to broadcast to {client_id}: {e}")
    
    async def broadcast_to_scan(self, scan_id: str, message: dict[str, Any]):
        """Broadcast message to all clients subscribed to a scan."""
        subscribers = self.scan_subscriptions.get(scan_id, set())
        for client_id in subscribers:
            await self.send_personal(client_id, message)


# Global connection manager
manager = ConnectionManager()


def setup_event_bus_handlers():
    """Set up handlers to forward event bus events to WebSocket clients."""
    event_bus = get_event_bus()
    
    async def handle_scan_started(data: dict[str, Any]):
        await manager.broadcast({
            "type": "scan.started",
            "data": data,
        })
    
    async def handle_scan_progress(data: dict[str, Any]):
        scan_id = data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "scan.progress",
                "data": data,
            })
    
    async def handle_phase_started(data: dict[str, Any]):
        scan_id = data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "phase.started",
                "data": data,
            })
    
    async def handle_phase_completed(data: dict[str, Any]):
        scan_id = data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "phase.completed",
                "data": data,
            })
    
    async def handle_vulnerability_found(data: dict[str, Any]):
        scan_id = data.get("scan_id")
        # Broadcast to scan subscribers
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "vulnerability.found",
                "data": data,
            })
        # Also broadcast globally for dashboard updates
        await manager.broadcast({
            "type": "vulnerability.new",
            "data": {
                "scan_id": scan_id,
                "severity": data.get("severity"),
                "title": data.get("title"),
            },
        })
    
    async def handle_scan_completed(data: dict[str, Any]):
        scan_id = data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "scan.completed",
                "data": data,
            })
        await manager.broadcast({
            "type": "scan.finished",
            "data": {"scan_id": scan_id},
        })
    
    async def handle_scan_error(data: dict[str, Any]):
        scan_id = data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "scan.error",
                "data": data,
            })
    
    async def handle_plugin_started(data: dict[str, Any]):
        scan_id = data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "plugin.started",
                "data": data,
            })
    
    async def handle_plugin_completed(data: dict[str, Any]):
        scan_id = data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "plugin.completed",
                "data": data,
            })

    async def handle_plugin_error(data: dict[str, Any]):
        scan_id = data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "scan.error",
                "data": data,
            })

    async def handle_plugin_output(data: dict[str, Any]):
        scan_id = data.get("scan_id")
        if scan_id:
            await manager.broadcast_to_scan(scan_id, {
                "type": "plugin.output",
                "data": data,
            })
    
    # Subscribe to events
    event_bus.subscribe(EventType.SCAN_STARTED, handle_scan_started)
    event_bus.subscribe(EventType.SCAN_PROGRESS, handle_scan_progress)
    event_bus.subscribe(EventType.PHASE_STARTED, handle_phase_started)
    event_bus.subscribe(EventType.PHASE_COMPLETED, handle_phase_completed)
    event_bus.subscribe(EventType.VULNERABILITY_FOUND, handle_vulnerability_found)
    event_bus.subscribe(EventType.SCAN_COMPLETED, handle_scan_completed)
    event_bus.subscribe(EventType.SCAN_ERROR, handle_scan_error)
    event_bus.subscribe(EventType.PLUGIN_STARTED, handle_plugin_started)
    event_bus.subscribe(EventType.PLUGIN_COMPLETED, handle_plugin_completed)
    event_bus.subscribe(EventType.PLUGIN_ERROR, handle_plugin_error)
    event_bus.subscribe(EventType.PLUGIN_OUTPUT, handle_plugin_output)


# Initialize event handlers
setup_event_bus_handlers()


@router.websocket("/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    """WebSocket endpoint for real-time updates."""
    await manager.connect(websocket, client_id)
    
    try:
        while True:
            # Receive messages from client
            data = await websocket.receive_json()
            
            action = data.get("action")
            
            if action == "subscribe":
                scan_id = data.get("scan_id")
                if scan_id:
                    manager.subscribe_to_scan(client_id, scan_id)
                    await manager.send_personal(client_id, {
                        "type": "subscribed",
                        "scan_id": scan_id,
                    })
            
            elif action == "unsubscribe":
                scan_id = data.get("scan_id")
                if scan_id:
                    manager.unsubscribe_from_scan(client_id, scan_id)
                    await manager.send_personal(client_id, {
                        "type": "unsubscribed",
                        "scan_id": scan_id,
                    })
            
            elif action == "ping":
                await manager.send_personal(client_id, {"type": "pong"})
            
            else:
                await manager.send_personal(client_id, {
                    "type": "error",
                    "message": f"Unknown action: {action}",
                })
    
    except WebSocketDisconnect:
        manager.disconnect(client_id)
    except Exception as e:
        logger.exception(f"WebSocket error for {client_id}")
        manager.disconnect(client_id)
