"""
FastAPI Notification & Deduplication Routes for NetGuard AI.
Part of Phase 4: Notifications, Deduplication & Delivery.

Endpoints:
- POST /notifications/dispatch           Ingests alert, runs sliding-window deduplication, dispatches notifications
- GET  /notifications/suppression-stats  Retrieves rate-limiting and duplicate suppression telemetry
- POST /notifications/test-email         Tests HTML email alert formatting and delivery
"""

from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, EmailStr, Field

import auth
import database
from notification_engine import notification_engine
from backend.auth_routes import get_current_user

router = APIRouter(prefix="/notifications", tags=["Alert Notifications & Deduplication"])


# ==============================================================================
# PYDANTIC SCHEMAS
# ==============================================================================

class DispatchAlertRequest(BaseModel):
    attack_family: str = Field(..., description="Classification of threat (e.g. DDoS, PortScan, Infiltration)")
    severity: str = Field("High", description="Critical, High, Medium, Low")
    confidence: float = Field(0.95, ge=0.0, le=1.0)
    source_ip: str = Field("192.168.1.100")
    destination_ip: str = Field("10.0.0.1")
    destination_port: int = Field(80, ge=1, le=65535)
    protocol: str = Field("TCP")
    send_email: bool = Field(False)
    email_recipient: Optional[str] = Field(None)
    webhook_url: Optional[str] = Field(None)
    webhook_channel: str = Field("slack")


class TestEmailRequest(BaseModel):
    recipient: str = Field(..., description="Target email address")
    attack_family: str = Field("DDoS-LOIC-HTTP")
    severity: str = Field("Critical")


# ==============================================================================
# ENDPOINTS
# ==============================================================================

@router.post("/dispatch")
def dispatch_alert_notification(
    req: DispatchAlertRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Evaluates incoming alert against sliding-window deduplication.
    Suppresses storms from repeated events, and delivers unique alerts.
    """
    payload = {
        "attack_family": req.attack_family,
        "severity": req.severity,
        "confidence": req.confidence,
        "source_ip": req.source_ip,
        "destination_ip": req.destination_ip,
        "destination_port": req.destination_port,
        "protocol": req.protocol,
    }

    result = notification_engine.process_incoming_alert(
        alert_payload=payload,
        user_id=user["id"],
        send_email=req.send_email,
        email_recipient=req.email_recipient,
        webhook_url=req.webhook_url,
        webhook_channel=req.webhook_channel,
    )
    return {"status": "success", "result": result}


@router.get("/suppression-stats")
def get_suppression_stats(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns telemetry on alert deduplication, active rate-limit windows, and suppressed bursts.
    """
    stats = notification_engine.get_suppression_statistics()
    return {"status": "success", "statistics": stats}


@router.post("/test-email")
def test_email_dispatch(
    req: TestEmailRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Sends a test security alert email to verify SMTP configuration and HTML formatting.
    """
    dummy_payload = {
        "attack_family": req.attack_family,
        "severity": req.severity,
        "source_ip": "203.0.113.195",
        "destination_ip": "10.0.0.1",
        "destination_port": 443,
        "confidence": 0.98,
    }
    res = notification_engine.send_email_alert(recipient=req.recipient, alert_payload=dummy_payload)
    return {"status": "success", "result": res}
