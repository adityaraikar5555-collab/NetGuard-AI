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
from dataclasses import asdict
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, WebSocket, WebSocketDisconnect, status
from pydantic import BaseModel, Field

import auth
import database
from realtime_detector import realtime_detector
from live_monitor import live_monitor

try:
    from attack_simulator import attack_simulator
except Exception:
    try:
        from src.attack_simulator import attack_simulator
    except Exception:
        attack_simulator = None

try:
    from threat_map_engine import global_threat_map_engine
except Exception:
    try:
        from src.threat_map_engine import global_threat_map_engine
    except Exception:
        global_threat_map_engine = None

try:
    from zero_day_engine import zero_day_engine
except Exception:
    try:
        from src.zero_day_engine import zero_day_engine
    except Exception:
        zero_day_engine = None

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


# ==============================================================================
# RED VS BLUE CYBER ATTACK SIMULATOR & WAR-ROOM ENDPOINTS
# ==============================================================================

class LaunchAttackRequest(BaseModel):
    attack_type: str = Field("SYN_FLOOD", description="Attack profile key from arsenal")
    intensity: float = Field(1.0, ge=0.1, le=5.0, description="Offensive packet cadence multiplier")
    duration_sec: int = Field(3, ge=1, le=30, description="Duration of simulated attack campaign")
    attacker_ip: Optional[str] = Field(None, description="Spoofed or dedicated attacker source IP")
    target_ip: str = Field("192.168.1.100", description="Victim / SOC perimeter destination IP")
    target_port: Optional[int] = Field(None, description="Target destination network port")
    emit_live_probe: bool = Field(True, description="Whether to emit local loopback test socket frames")


class ReleaseQuarantineRequest(BaseModel):
    ip: str = Field(..., description="IP address to release from active quarantine")


@router.get("/simulator/arsenal")
def get_attack_arsenal():
    """
    Returns registered offensive attack profiles and MITRE ATT&CK techniques.
    """
    if attack_simulator is None:
        raise HTTPException(status_code=503, detail="Attack simulator engine not loaded.")
    return {
        "status": "success",
        "arsenal": attack_simulator.get_arsenal_list(),
    }


@router.post("/simulator/launch")
def launch_attack_campaign(req: LaunchAttackRequest):
    """
    Executes a Red vs Blue attack campaign:
    Synthesizes attack vector, runs ML inference & XAI attribution,
    generates automated SOAR containment, and isolates the host.
    """
    if attack_simulator is None:
        raise HTTPException(status_code=503, detail="Attack simulator engine not loaded.")

    battle_report = attack_simulator.run_war_game(
        attack_type=req.attack_type,
        intensity=req.intensity,
        duration_sec=req.duration_sec,
        attacker_ip=req.attacker_ip,
        target_ip=req.target_ip,
        target_port=req.target_port,
        emit_live_probe=req.emit_live_probe,
    )
    return {
        "status": "success",
        "battle_report": battle_report,
    }


@router.get("/simulator/quarantine")
def list_quarantined_hosts():
    """
    Returns all actively isolated/quarantined host IP addresses.
    """
    if attack_simulator is None:
        raise HTTPException(status_code=503, detail="Attack simulator engine not loaded.")
    return {
        "status": "success",
        "quarantined_hosts": attack_simulator.get_quarantined_hosts(),
    }


@router.post("/simulator/quarantine/release")
def release_quarantined_host(req: ReleaseQuarantineRequest):
    """
    Un-quarantines an IP address and restores authorized traffic flow.
    """
    if attack_simulator is None:
        raise HTTPException(status_code=503, detail="Attack simulator engine not loaded.")
    released = attack_simulator.unquarantine_host(req.ip)
    return {
        "status": "success" if released else "not_found",
        "released": released,
        "ip": req.ip,
    }


# ==============================================================================
# GLOBAL 3D THREAT INTELLIGENCE MAP TELEMETRY
# ==============================================================================

class ThreatPulseRequest(BaseModel):
    count: int = Field(default=3, ge=1, le=25)


@router.get("/threat-map/telemetry")
def get_threat_map_telemetry(
    limit_arcs: int = Query(default=30, ge=5, le=100),
    limit_events: int = Query(default=50, ge=5, le=200),
    severity: Optional[str] = Query(default=None),
):
    """
    Returns spatial threat coordinates, active cyber attack arcs, top threat origins,
    and rolling telemetry feed for the 3D Global Threat Intelligence visualization.
    """
    if global_threat_map_engine is None:
        raise HTTPException(status_code=503, detail="Global Threat Map engine not loaded.")

    return {
        "status": "success",
        "summary": global_threat_map_engine.get_summary_metrics(),
        "top_countries": global_threat_map_engine.get_top_origin_countries(limit=6),
        "arcs": global_threat_map_engine.get_threat_arc_data(limit=limit_arcs),
        "recent_events": global_threat_map_engine.get_recent_events(limit=limit_events, severity_filter=severity),
        "soc_hq": global_threat_map_engine.soc_location,
    }


@router.post("/threat-map/pulse")
def pulse_global_threats(req: ThreatPulseRequest):
    """
    Simulates a burst of real-time incoming cyber attack vectors from global endpoints.
    """
    if global_threat_map_engine is None:
        raise HTTPException(status_code=503, detail="Global Threat Map engine not loaded.")

    pulsed = global_threat_map_engine.pulse_attack(count=req.count)
    return {
        "status": "success",
        "pulsed_count": len(pulsed),
        "events": [asdict(e) if hasattr(e, "__dataclass_fields__") else e for e in pulsed],
        "summary": global_threat_map_engine.get_summary_metrics(),
    }


# ==============================================================================
# UNSUPERVISED AUTOENCODER (ZERO-DAY ENGINE) ENDPOINTS
# ==============================================================================

class ZeroDayScoreRequest(BaseModel):
    features: Dict[str, Any]


class ZeroDayFusionRequest(BaseModel):
    rf_prediction: str = Field(default="BENIGN")
    rf_probability: float = Field(default=0.0)
    features: Dict[str, Any]


@router.get("/detection/zero-day/status")
def get_zero_day_engine_status():
    """
    Returns the operational parameters, reconstruction threshold tau,
    and latent compression dimensions of the Unsupervised Autoencoder.
    """
    if zero_day_engine is None or not zero_day_engine.is_loaded:
        raise HTTPException(status_code=503, detail="Zero-Day Autoencoder engine not loaded.")

    return {
        "status": "ready",
        "input_dimensions": len(zero_day_engine.feature_names),
        "latent_bottleneck": zero_day_engine.latent_dim,
        "compression_ratio": f"{round((1 - zero_day_engine.latent_dim / len(zero_day_engine.feature_names)) * 100, 1)}%",
        "threshold_90": zero_day_engine.threshold_90,
        "threshold_95_tau": zero_day_engine.threshold_95,
        "threshold_99": zero_day_engine.threshold_99,
        "benign_mean_mse": zero_day_engine.benign_mean_mse,
    }


@router.post("/detection/zero-day/score")
def score_zero_day_flow(req: ZeroDayScoreRequest):
    """
    Passes a network flow through the deep Autoencoder, calculating reconstruction error,
    novelty anomaly score, and top 5 feature attribution residuals.
    """
    if zero_day_engine is None or not zero_day_engine.is_loaded:
        raise HTTPException(status_code=503, detail="Zero-Day Autoencoder engine not loaded.")

    result = zero_day_engine.score_flow(req.features)
    return {
        "status": "success",
        "analysis": result,
    }


@router.post("/detection/zero-day/fuse")
def fuse_dual_engine(req: ZeroDayFusionRequest):
    """
    Synthesizes Supervised Random Forest predictions with Unsupervised Autoencoder residuals
    to detect zero-day exploits that bypassed supervised classification.
    """
    if zero_day_engine is None or not zero_day_engine.is_loaded:
        raise HTTPException(status_code=503, detail="Zero-Day Autoencoder engine not loaded.")

    verdict = zero_day_engine.dual_engine_fusion(
        rf_prediction=req.rf_prediction,
        rf_probability=req.rf_probability,
        flow_features=req.features,
    )
    return {
        "status": "success",
        "verdict": verdict,
    }


