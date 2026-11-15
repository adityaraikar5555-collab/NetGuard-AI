"""
FastAPI Routes for Live Network Monitoring & Flow Reconstruction.
Part of Phase 2: Live Monitoring & Flow Feature Extraction.

Endpoints:
- GET  /monitor/interfaces             List all detected network interfaces
- POST /monitor/authorize              Strictly authorize a network interface
- POST /monitor/start                  Start live packet sniffing on authorized interface
- POST /monitor/stop                   Stop active packet sniffing
- GET  /monitor/status                 Real-time operational status and metrics
- GET  /monitor/flows/recent           Retrieve recent reconstructed 78-feature flows
- POST /monitor/simulate-packet-stream Inject simulated packet flows for testing
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field

from live_monitor import live_monitor
from backend.auth_routes import get_current_user

router = APIRouter(prefix="/monitor", tags=["Live Network Monitoring"])


# ==============================================================================
# PYDANTIC REQUEST SCHEMAS
# ==============================================================================

class AuthorizeInterfaceRequest(BaseModel):
    interface: str = Field(..., description="Friendly name or GUID of the network interface to authorize")


class StartMonitoringRequest(BaseModel):
    interface: str = Field(..., description="Interface to start sniffing on (must be authorized)")


class SimulatePacketStreamRequest(BaseModel):
    source_ip: str = Field("192.168.1.100", description="Simulated client IP")
    destination_ip: str = Field("10.0.0.1", description="Simulated target IP")
    source_port: int = Field(54321, ge=1, le=65535)
    destination_port: int = Field(80, ge=1, le=65535)
    protocol: str = Field("TCP", description="'TCP' or 'UDP'")
    packet_count: int = Field(8, ge=2, le=500)
    attack_type: Optional[str] = Field(None, description="Optional attack label to simulate")


# ==============================================================================
# ENDPOINTS
# ==============================================================================

@router.get("/interfaces")
def list_interfaces(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns all detected network interfaces with friendly names and authorization status.
    """
    interfaces = live_monitor.get_available_interfaces()
    return {
        "status": "success",
        "count": len(interfaces),
        "authorized_interface": live_monitor.get_status().get("authorized_interface"),
        "interfaces": interfaces,
    }


@router.post("/authorize")
def authorize_network_interface(
    req: AuthorizeInterfaceRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Authorizes a specific network interface. Only authorized interfaces can be monitored.
    """
    try:
        result = live_monitor.authorize_interface(req.interface)
        return {"success": True, "result": result}
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))


@router.post("/start")
def start_live_capture(
    req: StartMonitoringRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Begins live packet capture. Strictly verifies that the interface is authorized.
    """
    try:
        res = live_monitor.start_monitoring(req.interface)
        return {"success": True, "monitor": res}
    except PermissionError as pe:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(pe))
    except Exception as e:
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=str(e))


@router.post("/stop")
def stop_live_capture(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Halts live packet capture and flushes pending flows.
    """
    res = live_monitor.stop_monitoring()
    return {"success": True, "result": res}


@router.get("/status")
def get_monitoring_status(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns live statistics on packets captured, active flows, and buffer count.
    """
    return {"status": "success", "monitor": live_monitor.get_status()}


@router.get("/flows/recent")
def get_recent_reconstructed_flows(
    limit: int = Query(25, ge=1, le=100),
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Retrieves recently reconstructed network flows with all 78 CICIDS statistical features.
    """
    df = live_monitor.get_recent_flows_df(limit=limit)
    records = df.to_dict(orient="records") if not df.empty else []
    return {
        "status": "success",
        "flow_count": len(records),
        "flows": records,
    }


@router.post("/simulate-packet-stream")
def simulate_packet_stream(
    req: SimulatePacketStreamRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Injects a synthetic packet stream to reconstruct a flow and extract 78 CICIDS features.
    """
    flow = live_monitor.inject_synthetic_flow(
        src_ip=req.source_ip,
        dst_ip=req.destination_ip,
        src_port=req.source_port,
        dst_port=req.destination_port,
        protocol=req.protocol,
        packet_count=req.packet_count,
        attack_type=req.attack_type,
    )
    return {
        "status": "success",
        "flow": {
            "source_ip": flow.get("source_ip"),
            "destination_ip": flow.get("destination_ip"),
            "source_port": flow.get("source_port"),
            "destination_port": flow.get("destination_port"),
            "protocol": flow.get("protocol"),
            "packets": flow.get("packets"),
            "feature_count": len(flow.get("features", {})),
        },
    }
