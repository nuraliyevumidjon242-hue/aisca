import asyncio
import json


class AlertManager:
    def __init__(self):
        self.connections = set()

    async def connect(self, websocket):
        await websocket.accept()
        self.connections.add(websocket)

    def disconnect(self, websocket):
        self.connections.discard(websocket)

    async def broadcast(self, payload):
        if not self.connections:
            return
        message = json.dumps(payload)
        for websocket in list(self.connections):
            try:
                await websocket.send_text(message)
            except Exception:
                self.connections.discard(websocket)


alert_manager = AlertManager()
