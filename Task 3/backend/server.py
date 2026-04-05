import asyncio
import queue
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import json

from sniffer import NexusSniffer
from mitigation import MitigationEngine

app = FastAPI(title="Nexus IDS API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

alert_queue = queue.Queue()
sniffer = NexusSniffer(alert_queue)
mitigation = MitigationEngine()

active_connections = []

@app.on_event("startup")
async def startup_event():
    sniffer.start()
    asyncio.create_task(broadcast_queue_events())

@app.on_event("shutdown")
def shutdown_event():
    sniffer.stop()

async def broadcast_queue_events():
    """Continuously reads from the alert queue and broadcasts to all connected websockets."""
    while True:
        try:
            # Non-blocking get
            event = alert_queue.get_nowait()
            
            # Check if auto-mitigate is on and it's a critical alert
            if event["type"] == "alert" and mitigation.auto_mitigate:
                alert_data = event["data"]
                if alert_data["severity"] in ["High", "Critical"]:
                    mitigation.block_ip(alert_data["src_ip"])
                    # Send a mitigation event alongside the alert
                    mitigation_event = {
                        "type": "mitigation",
                        "data": {"action": "auto-blocked", "ip": alert_data["src_ip"]}
                    }
                    await broadcast_message(json.dumps(mitigation_event))
            
            await broadcast_message(json.dumps(event))
            alert_queue.task_done()
        except queue.Empty:
            await asyncio.sleep(0.05) # Yield control to the event loop

async def broadcast_message(message: str):
    for connection in active_connections:
        try:
            await connection.send_text(message)
        except Exception:
            pass

@app.websocket("/ws")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.append(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)
            
            # Handle commands from the dashboard
            if message.get("command") == "block_ip":
                result = mitigation.block_ip(message["ip"])
                await websocket.send_text(json.dumps({"type": "response", "data": result}))
            
            elif message.get("command") == "unblock_ip":
                result = mitigation.unblock_ip(message["ip"])
                await websocket.send_text(json.dumps({"type": "response", "data": result}))
                
            elif message.get("command") == "toggle_automitigate":
                result = mitigation.toggle_auto_mitigate(message["state"])
                await websocket.send_text(json.dumps({"type": "response", "data": result}))
                
    except WebSocketDisconnect:
        active_connections.remove(websocket)

@app.get("/")
def read_root():
    return {"status": "Nexus IDS is active"}

if __name__ == "__main__":
    uvicorn.run("server:app", host="0.0.0.0", port=8000, reload=True)
