"""
Authentication & Multi-Tenant Alerts Client for Streamlit Dashboard.
Part of Phase 1: Authentication & User-Specific Alert History.

Supports:
1. HTTP requests to FastAPI backend when online.
2. Graceful direct fallback to src.auth and src.database when running locally or during tests.
"""

import os
from pathlib import Path
import sys
from typing import Any, Dict, List, Optional
import requests

# Ensure src is in sys.path for direct fallback if API is offline
PROJECT_ROOT = Path(__file__).resolve().parent.parent
SRC_DIR = PROJECT_ROOT / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

try:
    import auth
    import database
    _DIRECT_DB_AVAILABLE = True
except Exception:
    _DIRECT_DB_AVAILABLE = False


CLOUD_RENDER_API_URL = "https://netguard-ai-nd5e.onrender.com"
LOCAL_API_URL = "http://127.0.0.1:8000"


def _detect_default_api_url() -> str:
    env_val = os.getenv("NETGUARD_API_URL")
    if env_val:
        return env_val.rstrip("/")
    try:
        import socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.3)
        res = sock.connect_ex(("127.0.0.1", 8000))
        sock.close()
        if res == 0:
            return LOCAL_API_URL
    except Exception:
        pass
    return CLOUD_RENDER_API_URL


DEFAULT_API_URL = _detect_default_api_url()


def set_api_base_url(url: str):
    global DEFAULT_API_URL
    DEFAULT_API_URL = url.rstrip("/")


def login_user(username: str, password: str, api_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Authenticates a user via FastAPI /auth/login or direct database fallback.
    """
    url = (api_url or DEFAULT_API_URL).rstrip("/") + "/auth/login"
    timeout = 15 if "onrender.com" in url else 5
    try:
        resp = requests.post(
            url,
            json={"username": username, "password": password},
            timeout=timeout,
        )
        if resp.status_code == 200:
            return {"success": True, "data": resp.json()}
        else:
            detail = resp.json().get("detail", "Authentication failed.")
            return {"success": False, "error": detail}
    except Exception:
        # Fallback to direct DB check if API server is not running
        if _DIRECT_DB_AVAILABLE:
            user = database.get_user_by_username(username)
            if not user:
                with database.get_db_connection() as conn:
                    c = conn.cursor()
                    c.execute("SELECT * FROM users WHERE email = ?", (username.strip().lower(),))
                    row = c.fetchone()
                    if row:
                        user = dict(row)
            if user and auth.verify_password(password, user["password_hash"]):
                token = auth.create_access_token({
                    "sub": str(user["id"]),
                    "username": user["username"],
                    "email": user["email"],
                    "role": user["role"],
                })
                safe_user = database.get_user_by_id(user["id"])
                return {
                    "success": True,
                    "data": {
                        "access_token": token,
                        "token_type": "bearer",
                        "user": safe_user,
                    },
                }
        return {"success": False, "error": "Invalid username or password (API offline)."}


def register_user(
    username: str,
    email: str,
    password: str,
    full_name: Optional[str] = None,
    role: str = "analyst",
    api_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Registers a new user account.
    """
    url = (api_url or DEFAULT_API_URL).rstrip("/") + "/auth/register"
    try:
        resp = requests.post(
            url,
            json={
                "username": username,
                "email": email,
                "password": password,
                "full_name": full_name or username,
                "role": role,
            },
            timeout=5,
        )
        if resp.status_code == 201:
            return {"success": True, "data": resp.json()}
        else:
            detail = resp.json().get("detail", "Registration failed.")
            return {"success": False, "error": detail}
    except Exception:
        if _DIRECT_DB_AVAILABLE:
            try:
                user = database.create_user(username, email, password, full_name, role)
                token = auth.create_access_token({
                    "sub": str(user["id"]),
                    "username": user["username"],
                    "email": user["email"],
                    "role": user["role"],
                })
                return {
                    "success": True,
                    "data": {
                        "access_token": token,
                        "token_type": "bearer",
                        "user": user,
                    },
                }
            except Exception as e:
                return {"success": False, "error": str(e)}
        return {"success": False, "error": "Unable to connect to backend registration service."}


def fetch_my_profile(token: str, api_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Fetches the profile for the current session token.
    """
    url = (api_url or DEFAULT_API_URL).rstrip("/") + "/auth/me"
    try:
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if resp.status_code == 200:
            return {"success": True, "user": resp.json().get("user")}
    except Exception:
        pass

    if _DIRECT_DB_AVAILABLE and token:
        try:
            payload = auth.decode_access_token(token)
            user = database.get_user_by_id(int(payload["sub"]))
            if user:
                return {"success": True, "user": user}
        except Exception as e:
            return {"success": False, "error": str(e)}

    return {"success": False, "error": "Invalid session token."}


def fetch_user_alerts(
    token: str,
    severity: Optional[str] = None,
    unacknowledged_only: bool = False,
    limit: int = 100,
    api_url: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """
    Fetches user-specific alert history.
    """
    url = (api_url or DEFAULT_API_URL).rstrip("/") + "/alerts"
    params = {"limit": limit, "unacknowledged_only": str(unacknowledged_only).lower()}
    if severity and severity.lower() != "all":
        params["severity"] = severity

    try:
        resp = requests.get(
            url,
            headers={"Authorization": f"Bearer {token}"},
            params=params,
            timeout=5,
        )
        if resp.status_code == 200:
            return resp.json().get("alerts", [])
    except Exception:
        pass

    if _DIRECT_DB_AVAILABLE and token:
        try:
            payload = auth.decode_access_token(token)
            user_id = int(payload["sub"])
            is_admin = payload.get("role") == "admin"
            return database.get_user_alerts(
                user_id=user_id,
                severity=severity,
                unacknowledged_only=unacknowledged_only,
                limit=limit,
                is_admin_all=False,
            )
        except Exception:
            return []

    return []


def record_alert(
    token: str,
    attack_type: str,
    severity: str = "High",
    confidence: float = 0.95,
    source_ip: str = "192.168.1.100",
    destination_ip: str = "10.0.0.1",
    protocol: str = "TCP",
    details: Optional[Dict[str, Any]] = None,
    api_url: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Records an alert into the authenticated user's tenancy.
    """
    url = (api_url or DEFAULT_API_URL).rstrip("/") + "/alerts"
    payload = {
        "attack_type": attack_type,
        "severity": severity,
        "confidence": float(confidence),
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "details": details or {},
    }
    try:
        resp = requests.post(
            url,
            headers={"Authorization": f"Bearer {token}"},
            json=payload,
            timeout=5,
        )
        if resp.status_code == 201:
            return {"success": True, "alert": resp.json().get("alert")}
    except Exception:
        pass

    if _DIRECT_DB_AVAILABLE and token:
        try:
            user_payload = auth.decode_access_token(token)
            user_id = int(user_payload["sub"])
            alert = database.insert_user_alert(
                user_id=user_id,
                attack_type=attack_type,
                severity=severity,
                confidence=confidence,
                source_ip=source_ip,
                destination_ip=destination_ip,
                protocol=protocol,
                details=details,
            )
            return {"success": True, "alert": alert}
        except Exception as e:
            return {"success": False, "error": str(e)}

    return {"success": False, "error": "Unable to save alert."}


def acknowledge_alert(token: str, alert_id: int, api_url: Optional[str] = None) -> bool:
    """
    Marks an alert as acknowledged for the user.
    """
    url = (api_url or DEFAULT_API_URL).rstrip("/") + f"/alerts/{alert_id}/acknowledge"
    try:
        resp = requests.post(url, headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if resp.status_code == 200:
            return True
    except Exception:
        pass

    if _DIRECT_DB_AVAILABLE and token:
        try:
            payload = auth.decode_access_token(token)
            user_id = int(payload["sub"])
            is_admin = payload.get("role") == "admin"
            return database.acknowledge_user_alert(user_id, alert_id, is_admin=is_admin)
        except Exception:
            return False

    return False


def fetch_alert_stats(token: str, api_url: Optional[str] = None) -> Dict[str, Any]:
    """
    Fetches alert statistics for the current user.
    """
    url = (api_url or DEFAULT_API_URL).rstrip("/") + "/alerts/stats"
    try:
        resp = requests.get(url, headers={"Authorization": f"Bearer {token}"}, timeout=5)
        if resp.status_code == 200:
            return resp.json().get("statistics", {})
    except Exception:
        pass

    if _DIRECT_DB_AVAILABLE and token:
        try:
            payload = auth.decode_access_token(token)
            user_id = int(payload["sub"])
            return database.get_user_alert_statistics(user_id)
        except Exception:
            return {}

    return {}
