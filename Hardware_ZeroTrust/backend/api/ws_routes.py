"""
WebSocket connection manager and telemetry streaming endpoint.
Provides real-time pushes of authentication attempts, security alerts, and relay state changes.
"""

import json
from typing import List
from fastapi import APIRouter, WebSocket, WebSocketDisconnect

router = APIRouter()


class ConnectionManager:
    """Maintains active WebSocket connections to dashboard clients."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    async def broadcast(self, message: dict):
        """Dispatches JSON payload to all connected clients."""
        payload_str = json.dumps(message)
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_text(payload_str)
            except Exception:
                disconnected.append(connection)

        for dead_conn in disconnected:
            self.disconnect(dead_conn)


ws_manager = ConnectionManager()


@router.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    """Real-time duplex stream for security dashboard."""
    await ws_manager.connect(websocket)
    # Send immediate connection acknowledgment
    await websocket.send_text(json.dumps({
        "event": "CONNECTED",
        "message": "Zero-Trust Gateway real-time telemetry stream established."
    }))
    try:
        while True:
            # Keep connection alive; accept client pings or commands
            data = await websocket.receive_text()
            try:
                msg = json.loads(data)
                if msg.get("action") == "PING":
                    await websocket.send_text(json.dumps({"event": "PONG"}))
            except Exception:
                pass
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
    except Exception:
        ws_manager.disconnect(websocket)
