"""
FastAPI Authentication & Multi-Tenant Alert Routes for NetGuard AI.
Part of Phase 1: Authentication & User-Specific Alert History.

Endpoints:
- POST   /auth/register               Register new account
- POST   /auth/login                  Sign in and receive JWT
- GET    /auth/me                     Get current authenticated user profile
- POST   /auth/api-key/regenerate     Regenerate agent API key
- GET    /alerts                      Retrieve authenticated user's alert history
- POST   /alerts                      Record an alert under user tenancy
- POST   /alerts/{id}/acknowledge    Acknowledge user alert
- DELETE /alerts/{id}                 Delete user alert
- GET    /alerts/stats                Get user alert statistics
"""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException, Query, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field

import auth
import database

router = APIRouter(tags=["Authentication & Multi-Tenant Alerts"])
security = HTTPBearer(auto_error=False)


# ==============================================================================
# PYDANTIC SCHEMAS
# ==============================================================================

class RegisterRequest(BaseModel):
    username: str = Field(..., min_length=3, max_length=50, description="Unique username")
    email: str = Field(..., min_length=5, max_length=120, description="Unique user email address")
    password: str = Field(..., min_length=6, description="Plaintext password")
    full_name: Optional[str] = Field(None, max_length=100)
    role: Optional[str] = Field("analyst", description="'analyst' or 'admin'")


class LoginRequest(BaseModel):
    username: str = Field(..., description="Username or registered email")
    password: str = Field(..., description="Account password")


class AuthResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: Dict[str, Any]


class CreateAlertRequest(BaseModel):
    attack_type: str = Field(..., description="Type of threat (e.g. DDoS, PortScan, Infiltration)")
    severity: str = Field("High", description="Critical, High, Medium, Low")
    confidence: float = Field(0.95, ge=0.0, le=1.0)
    source_ip: Optional[str] = "192.168.1.100"
    destination_ip: Optional[str] = "10.0.0.1"
    protocol: Optional[str] = "TCP"
    details: Optional[Dict[str, Any]] = None


# ==============================================================================
# DEPENDENCY: GET CURRENT AUTHENTICATED USER
# ==============================================================================

def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> Dict[str, Any]:
    """
    Authenticates a request via either:
    1. Authorization: Bearer <JWT_TOKEN>
    2. Header: X-API-Key: ng_live_<KEY>
    """
    # 1. Check API Key
    if x_api_key:
        user = database.get_user_by_api_key(x_api_key)
        if user and user.get("is_active"):
            return user
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or deactivated API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    # 2. Check Bearer JWT Token
    if credentials and credentials.scheme.lower() == "bearer":
        token = credentials.credentials
        try:
            payload = auth.decode_access_token(token)
            user_id = int(payload.get("sub"))
            user = database.get_user_by_id(user_id)
            if not user or not user.get("is_active"):
                raise HTTPException(
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    detail="User account does not exist or is inactive.",
                )
            return user
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid authentication token: {str(e)}",
                headers={"WWW-Authenticate": "Bearer"},
            )

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required. Please provide a Bearer token or X-API-Key header.",
        headers={"WWW-Authenticate": "Bearer"},
    )


# ==============================================================================
# AUTHENTICATION ENDPOINTS
# ==============================================================================

@router.post("/auth/register", response_model=AuthResponse, status_code=status.HTTP_201_CREATED)
def register(req: RegisterRequest):
    """
    Register a new user account with secure password hashing.
    """
    try:
        user = database.create_user(
            username=req.username,
            email=req.email,
            password=req.password,
            full_name=req.full_name,
            role=req.role or "analyst",
        )
    except ValueError as ve:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(ve))

    token = auth.create_access_token({
        "sub": str(user["id"]),
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    })
    return {"access_token": token, "token_type": "bearer", "user": user}


@router.post("/auth/login", response_model=AuthResponse)
def login(req: LoginRequest):
    """
    Sign in using username/email and password. Returns signed JWT token.
    """
    user = database.get_user_by_username(req.username)
    if not user:
        # Check if login passed email instead of username
        with database.get_db_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE email = ?", (req.username.strip().lower(),))
            row = cursor.fetchone()
            if row:
                user = dict(row)

    if not user or not auth.verify_password(req.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    if not user.get("is_active"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is inactive. Contact SOC administrator.",
        )

    token = auth.create_access_token({
        "sub": str(user["id"]),
        "username": user["username"],
        "email": user["email"],
        "role": user["role"],
    })

    safe_user = database.get_user_by_id(user["id"])
    return {"access_token": token, "token_type": "bearer", "user": safe_user}


@router.get("/auth/me")
def get_current_user_profile(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Retrieves the currently authenticated user's profile and permissions.
    """
    return {"status": "authenticated", "user": user}


@router.post("/auth/api-key/regenerate")
def regenerate_api_key(user: Dict[str, Any] = Depends(get_current_user)):
    """
    Regenerates the user's API key for background network monitoring agents.
    """
    new_key = database.regenerate_user_api_key(user["id"])
    return {"status": "success", "new_api_key": new_key}


# ==============================================================================
# MULTI-TENANT ALERT HISTORY ENDPOINTS
# ==============================================================================

@router.get("/alerts")
def list_user_alerts(
    severity: Optional[str] = Query(None, description="Critical, High, Medium, Low, or all"),
    unacknowledged_only: bool = Query(False, description="Filter to pending alerts only"),
    limit: int = Query(50, ge=1, le=500),
    offset: int = Query(0, ge=0),
    all_tenants: bool = Query(False, description="Admins can view all tenant alerts"),
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Fetches alert history strictly scoped to the current authenticated user.
    Admins may pass all_tenants=true to inspect all organization alerts.
    """
    is_admin = (user.get("role") == "admin") and all_tenants
    alerts = database.get_user_alerts(
        user_id=user["id"],
        severity=severity,
        unacknowledged_only=unacknowledged_only,
        limit=limit,
        offset=offset,
        is_admin_all=is_admin,
    )
    return {
        "status": "success",
        "user_id": user["id"],
        "username": user["username"],
        "count": len(alerts),
        "alerts": alerts,
    }


@router.post("/alerts", status_code=status.HTTP_201_CREATED)
def record_user_alert(
    req: CreateAlertRequest,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Records an alert tied strictly to the authenticated user's tenancy.
    """
    alert = database.insert_user_alert(
        user_id=user["id"],
        attack_type=req.attack_type,
        severity=req.severity,
        confidence=req.confidence,
        source_ip=req.source_ip,
        destination_ip=req.destination_ip,
        protocol=req.protocol,
        details=req.details,
    )
    return {"status": "created", "alert": alert}


@router.post("/alerts/{alert_id}/acknowledge")
def acknowledge_alert(
    alert_id: int,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Marks an alert as acknowledged. Enforces tenancy boundary.
    """
    is_admin = user.get("role") == "admin"
    success = database.acknowledge_user_alert(user["id"], alert_id, is_admin=is_admin)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found or access denied.",
        )
    return {"status": "success", "alert_id": alert_id, "acknowledged": True}


@router.delete("/alerts/{alert_id}")
def delete_alert(
    alert_id: int,
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Deletes an alert. Enforces tenancy boundary.
    """
    is_admin = user.get("role") == "admin"
    success = database.delete_user_alert(user["id"], alert_id, is_admin=is_admin)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Alert not found or access denied.",
        )
    return {"status": "success", "alert_id": alert_id, "deleted": True}


@router.get("/alerts/stats")
def get_alert_stats(
    all_tenants: bool = Query(False),
    user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Returns user-specific alert metrics (counts by severity, unacknowledged, total).
    """
    is_admin = (user.get("role") == "admin") and all_tenants
    stats = database.get_user_alert_statistics(user["id"], is_admin_all=is_admin)
    return {"status": "success", "user_id": user["id"], "statistics": stats}
