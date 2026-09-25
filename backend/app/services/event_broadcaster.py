"""
Real-Time Event Broadcaster & WebSocket Manager
Broadcasts live SOC events (Agent activity, Task lifecycle, Evidence collection & verification).
Provides thread-safe history buffer for REST polling fallback.
"""
import asyncio
import collections
from datetime import datetime, timezone
from typing import List, Dict, Any
from fastapi import WebSocket

class EventBroadcaster:
    def __init__(self, max_history: int = 100):
        self.active_connections: List[WebSocket] = []
        self.event_history: collections.deque = collections.deque(maxlen=max_history)

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        if websocket in self.active_connections:
            self.active_connections.remove(websocket)

    def broadcast(self, event_type: str, message: str, data: Dict[str, Any] = None):
        event = {
            "type": event_type,
            "message": message,
            "data": data or {},
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        self.event_history.append(event)

        # Broadcast asynchronously to connected WebSockets
        if self.active_connections:
            asyncio.create_task(self._send_to_all(event))

    async def _send_to_all(self, event: Dict[str, Any]):
        disconnected = []
        for connection in self.active_connections:
            try:
                await connection.send_json(event)
            except Exception:
                disconnected.append(connection)
        for dc in disconnected:
            self.disconnect(dc)

    def get_recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        events = list(self.event_history)
        return events[-limit:]

broadcaster = EventBroadcaster()
