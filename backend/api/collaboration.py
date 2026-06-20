import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, List, Any
import json

logger = logging.getLogger(__name__)

router = APIRouter()

class ConnectionManager:
    """Manages active WebSocket connections for the Real-Time Collaborative Workbench."""
    def __init__(self):
        # Maps incident_id -> List of active WebSockets
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, incident_id: str):
        await websocket.accept()
        if incident_id not in self.active_connections:
            self.active_connections[incident_id] = []
        self.active_connections[incident_id].append(websocket)
        logger.info(f"[WEBSOCKET] Client connected to incident {incident_id}")

    def disconnect(self, websocket: WebSocket, incident_id: str):
        if incident_id in self.active_connections:
            self.active_connections[incident_id].remove(websocket)
            if not self.active_connections[incident_id]:
                del self.active_connections[incident_id]
        logger.info(f"[WEBSOCKET] Client disconnected from incident {incident_id}")

    async def broadcast(self, incident_id: str, message: Dict[str, Any], exclude: WebSocket = None):
        """Broadcasts a JSON message to all clients on the given incident."""
        if incident_id in self.active_connections:
            for connection in self.active_connections[incident_id]:
                if connection != exclude:
                    await connection.send_text(json.dumps(message))

manager = ConnectionManager()

@router.websocket("/{incident_id}")
async def websocket_endpoint(websocket: WebSocket, incident_id: str):
    await manager.connect(websocket, incident_id)
    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)
            
            # Rebroadcast cursor positions or live notes
            await manager.broadcast(incident_id, payload, exclude=websocket)
            
    except WebSocketDisconnect:
        manager.disconnect(websocket, incident_id)
        # Notify others that user left
        await manager.broadcast(incident_id, {
            "type": "USER_LEFT",
            "message": "A user disconnected."
        })
