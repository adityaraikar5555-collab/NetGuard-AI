"""
FastAPI Real-Time Detection & WebSocket Streaming Router for NetGuard AI.
Part of Phase 3: Real-Time Detection, Risk Scoring & WebSocket Streaming.

Endpoints:
- WebSocket /ws/live-stream               Live bidirectional WebSocket detection feed
- GET       /detection/latest             Fetch recent real-time flow detections
- GET       /detection/stats              Real-time engine throughput & attack statistics
- POST      /detection/start              Start continuous detection on authorized interface
- POST      /detection/stop               Stop continuous detection
- POST      /detection/simulate-event     Synthesizes flow and tests end-to-end WebSocket push
"""

import asyncio
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

import auth
import database
from realtime_detector import realtime_detector
from live_monitor import live_monitor

router = APIRouter(tags=["Real-Time Detection & WebSocket Stream"])


# ==============================================================================
# WEBSOCKET CONNECTION MANAGER
# ==============================================================================

class WebSocketConnectionManager:
    """Manages active WebSocket client connections and broadcasts live detection payloads."""

    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

        # Connect to realtime_detector events
        realtime_detector.register_listener(self._on_detector_event)

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)

    async def broadcast_json(self, message: Dict[str, Any]):
        async with self._lock:
            stale = []
            for connection in self.active_connections:
                try:
                    await connection.send_text(json.dumps(message))
                except Exception:
                    stale.append(connection)
            for s in stale:
                if s in self.active_connections:
                    self.active_connections.remove(s)

    def _on_detector_event(self, event: Dict[str, Any]):
        """Callback from realtime_detector synchronous thread; schedules async broadcast."""
        try:
            loop = asyncio.get_running_loop()
            if loop.is_running():
                asyncio.run_coroutine_threadsafe(self.broadcast_json(event), loop)
        except RuntimeError:
            # No running event loop in current thread
            pass
        except Exception:
            pass



ws_manager = WebSocketConnectionManager()


# ==============================================================================
# WEBSOCKET ENDPOINT
# ==============================================================================

@router.websocket("/ws/live-stream")
async def websocket_live_stream(
    websocket: WebSocket,
    token: Optional[str] = Query(None),
    api_key: Optional[str] = Query(None),
):
    """
    Real-time WebSocket feed emitting live network flow detections and alerts.
    Clients receive sub-second JSON notifications for every evaluated flow.
    """
    # Authenticate client if credentials provided
    client_user = "guest_observer"
    if token:
        try:
            payload = auth.decode_access_token(token)
            client_user = payload.get("username", "analyst")
        except Exception:
            pass
    elif api_key:
        u = database.get_user_by_api_key(api_key)
        if u:
            client_user = u["username"]

    await ws_manager.connect(websocket)

    # Send initial welcome and state snapshot
    await websocket.send_text(json.dumps({
        "type": "connection_established",
        "client": client_user,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "stats": realtime_detector.get_statistics(),
        "message": "Connected to NetGuard AI Real-Time Detection WebSocket Stream.",
    }))

    try:
        while True:
            # Handle incoming client messages (e.g. heartbeat or test simulation)
            raw_data = await websocket.receive_text()
            try:
                msg = json.loads(raw_data)
                action = msg.get("action", "").lower()
                if action == "ping":
                    await websocket.send_text(json.dumps({
                        "type": "pong",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "subscribers": len(ws_manager.active_connections),
                    }))
                elif action in ("simulate", "test"):
                    # Synthesize a flow and evaluate it through the pipeline
                    sim_flow = live_monitor.inject_synthetic_flow(
                        src_ip=msg.get("src_ip", "192.168.1.100"),
                        dst_ip=msg.get("dst_ip", "10.0.0.1"),
                        dst_port=int(msg.get("dst_port", 80)),
                    )
                    det_event = realtime_detector.evaluate_flow(sim_flow)
                    # Sent via broadcast automatically
            except Exception:
                pass
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception:
        await ws_manager.disconnect(websocket)


# ==============================================================================
# REST ENDPOINTS FOR REAL-TIME DETECTION
# ==============================================================================

class SimulateEventRequest(BaseModel):
    source_ip: str = "192.168.1.105"
    destination_ip: str = "10.0.0.1"
    destination_port: int = 80
    packet_count: int = 8


@router.get("/detection/latest")
def get_latest_detections(limit: int = Query(25, ge=1, le=100)):
    """
    Fetches recent real-time flow detection events.
    """
    events = realtime_detector.get_latest_detections(limit=limit)
    return {
        "status": "success",
        "count": len(events),
        "detections": events,
    }


@router.get("/detection/stats")
def get_detector_statistics():
    """
    Returns real-time detection pipeline telemetry and attack statistics.
    """
    stats = realtime_detector.get_statistics()
    stats["active_websocket_clients"] = len(ws_manager.active_connections)
    return {
        "status": "success",
        "statistics": stats,
    }


@router.post("/detection/start")
def start_realtime_detector(interface: Optional[str] = None):
    """
    Starts the real-time detection pipeline on the authorized interface.
    """
    try:
        res = realtime_detector.start_pipeline(interface=interface)
        return {"success": True, "result": res}
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/detection/stop")
def stop_realtime_detector():
    """
    Stops the real-time detection pipeline.
    """
    res = realtime_detector.stop_pipeline()
    return {"success": True, "result": res}


@router.post("/detection/simulate-event")
def simulate_detection_event(req: SimulateEventRequest):
    """
    Synthesizes a flow, executes ML inference, computes risk/severity,
    and broadcasts the result to all active WebSocket clients.
    """
    sim_flow = live_monitor.inject_synthetic_flow(
        src_ip=req.source_ip,
        dst_ip=req.destination_ip,
        dst_port=req.destination_port,
        packet_count=req.packet_count,
    )
    event = realtime_detector.evaluate_flow(sim_flow)
    return {"success": True, "event": event}
