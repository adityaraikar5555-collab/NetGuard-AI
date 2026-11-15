"""
Database & Multi-Tenant Persistence Layer for NetGuard AI.
Part of Phase 1: Authentication & User-Specific Alert History.

Uses SQLite with Write-Ahead Logging (WAL) mode for concurrency and thread safety.
Enforces strict tenancy isolation: users can only query, create, or acknowledge
their own alert records unless specifically granted the 'admin' role.
"""

from contextlib import contextmanager
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import sqlite3
from typing import Any, Dict, List, Optional, Tuple, Union

from auth import generate_api_key, hash_password

# ==============================================================================
# DATABASE CONFIGURATION
# ==============================================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR = PROJECT_ROOT / "data"
DB_PATH = DATA_DIR / "netguard_users.db"


@contextmanager
def get_db_connection():
    """
    Context manager yielding a thread-safe SQLite connection configured with WAL mode.
    """
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(DB_PATH), timeout=20.0)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL;")
        conn.execute("PRAGMA foreign_keys=ON;")
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# ==============================================================================
# SCHEMA INITIALIZATION & SEEDING
# ==============================================================================

def init_db():
    """
    Initializes database tables, creates indices, and seeds default accounts if needed.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()

        # 1. Users Table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL COLLATE NOCASE,
                email TEXT UNIQUE NOT NULL COLLATE NOCASE,
                password_hash TEXT NOT NULL,
                full_name TEXT,
                role TEXT NOT NULL DEFAULT 'analyst',
                api_key TEXT UNIQUE NOT NULL,
                is_active INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );
        """)

        # 2. User Alerts Table (Multi-Tenant)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS user_alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                attack_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                confidence REAL NOT NULL DEFAULT 0.0,
                details_json TEXT,
                is_acknowledged INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
            );
        """)

        # Indices for efficient multi-tenant query isolation
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_user_time 
            ON user_alerts(user_id, timestamp DESC);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_alerts_user_sev 
            ON user_alerts(user_id, severity);
        """)
        cursor.execute("""
            CREATE INDEX IF NOT EXISTS idx_users_api_key 
            ON users(api_key);
        """)

        # Seed initial default admin and analyst if database is empty
        cursor.execute("SELECT COUNT(*) as cnt FROM users;")
        if cursor.fetchone()["cnt"] == 0:
            now_iso = datetime.now(timezone.utc).isoformat()
            
            # Default Admin
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, full_name, role, api_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "admin",
                "admin@netguard.ai",
                hash_password("NetGuard@Admin2026!"),
                "SOC Administrator",
                "admin",
                generate_api_key(),
                now_iso,
            ))

            # Default Analyst
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, full_name, role, api_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                "analyst",
                "analyst@netguard.ai",
                hash_password("Analyst@NetGuard2026!"),
                "Tier-1 Security Analyst",
                "analyst",
                generate_api_key(),
                now_iso,
            ))


# ==============================================================================
# USER OPERATIONS
# ==============================================================================

def create_user(
    username: str,
    email: str,
    password: str,
    full_name: Optional[str] = None,
    role: str = "analyst",
) -> Dict[str, Any]:
    """
    Registers a new user with bcrypt-hashed password and unique API key.
    """
    username = username.strip()
    email = email.strip().lower()
    if not username or not email or not password:
        raise ValueError("Username, email, and password are required.")

    if role not in ("admin", "analyst"):
        role = "analyst"

    pwd_hash = hash_password(password)
    api_key = generate_api_key()
    now_iso = datetime.now(timezone.utc).isoformat()

    with get_db_connection() as conn:
        cursor = conn.cursor()
        try:
            cursor.execute("""
                INSERT INTO users (username, email, password_hash, full_name, role, api_key, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (username, email, pwd_hash, full_name or username, role, api_key, now_iso))
            user_id = cursor.lastrowid
        except sqlite3.IntegrityError as e:
            err = str(e).lower()
            if "username" in err:
                raise ValueError(f"Username '{username}' is already taken.")
            elif "email" in err:
                raise ValueError(f"Email '{email}' is already registered.")
            raise ValueError("Registration failed: username or email already exists.")

    return get_user_by_id(user_id)


def get_user_by_id(user_id: int) -> Optional[Dict[str, Any]]:
    """Fetches user details by user ID (omitting password hash)."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, email, full_name, role, api_key, is_active, created_at
            FROM users WHERE id = ?
        """, (user_id,))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_username(username: str) -> Optional[Dict[str, Any]]:
    """Fetches full user record including password hash for authentication."""
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, email, password_hash, full_name, role, api_key, is_active, created_at
            FROM users WHERE username = ?
        """, (username.strip(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def get_user_by_api_key(api_key: str) -> Optional[Dict[str, Any]]:
    """Fetches user record matching an API key for live agents."""
    if not api_key:
        return None
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            SELECT id, username, email, full_name, role, api_key, is_active, created_at
            FROM users WHERE api_key = ?
        """, (api_key.strip(),))
        row = cursor.fetchone()
        return dict(row) if row else None


def regenerate_user_api_key(user_id: int) -> str:
    """Regenerates and updates the API key for a given user."""
    new_key = generate_api_key()
    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("UPDATE users SET api_key = ? WHERE id = ?", (new_key, user_id))
    return new_key


# ==============================================================================
# MULTI-TENANT ALERT OPERATIONS
# ==============================================================================

def insert_user_alert(
    user_id: int,
    attack_type: str,
    severity: str,
    confidence: float,
    source_ip: Optional[str] = None,
    destination_ip: Optional[str] = None,
    protocol: Optional[str] = None,
    details: Optional[Dict[str, Any]] = None,
    timestamp: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Inserts a newly detected alert strictly bound to the authenticated user ID.
    """
    now_iso = timestamp or datetime.now(timezone.utc).isoformat()
    sev_clean = severity.capitalize() if severity else "High"
    if sev_clean not in ("Critical", "High", "Medium", "Low", "None"):
        sev_clean = "High"

    details_str = json.dumps(details or {})

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO user_alerts (
                user_id, timestamp, source_ip, destination_ip,
                protocol, attack_type, severity, confidence, details_json, is_acknowledged
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 0)
        """, (
            user_id,
            now_iso,
            source_ip or "Unknown",
            destination_ip or "Unknown",
            protocol or "TCP",
            attack_type,
            sev_clean,
            float(confidence),
            details_str,
        ))
        alert_id = cursor.lastrowid

    return {
        "id": alert_id,
        "user_id": user_id,
        "timestamp": now_iso,
        "source_ip": source_ip,
        "destination_ip": destination_ip,
        "protocol": protocol,
        "attack_type": attack_type,
        "severity": sev_clean,
        "confidence": confidence,
        "is_acknowledged": 0,
    }


def get_user_alerts(
    user_id: int,
    severity: Optional[str] = None,
    unacknowledged_only: bool = False,
    limit: int = 100,
    offset: int = 0,
    is_admin_all: bool = False,
) -> List[Dict[str, Any]]:
    """
    Fetches alerts filtered strictly by the user's ID.
    If is_admin_all is True, an admin can view alerts across all tenants.
    """
    query = """
        SELECT a.id, a.user_id, u.username, a.timestamp, a.source_ip, a.destination_ip,
               a.protocol, a.attack_type, a.severity, a.confidence, a.details_json, a.is_acknowledged
        FROM user_alerts a
        JOIN users u ON a.user_id = u.id
        WHERE 1=1
    """
    params: List[Any] = []

    if not is_admin_all:
        query += " AND a.user_id = ?"
        params.append(user_id)

    if severity and severity.lower() != "all":
        query += " AND a.severity = ?"
        params.append(severity.capitalize())

    if unacknowledged_only:
        query += " AND a.is_acknowledged = 0"

    query += " ORDER BY a.id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    with get_db_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(query, params)
        rows = cursor.fetchall()
        
        alerts = []
        for r in rows:
            item = dict(r)
            if item.get("details_json"):
                try:
                    item["details"] = json.loads(item["details_json"])
                except Exception:
                    item["details"] = {}
            alerts.append(item)
        return alerts


def acknowledge_user_alert(user_id: int, alert_id: int, is_admin: bool = False) -> bool:
    """
    Marks an alert as acknowledged, strictly verifying user ownership.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if is_admin:
            cursor.execute("UPDATE user_alerts SET is_acknowledged = 1 WHERE id = ?", (alert_id,))
        else:
            cursor.execute(
                "UPDATE user_alerts SET is_acknowledged = 1 WHERE id = ? AND user_id = ?",
                (alert_id, user_id),
            )
        return cursor.rowcount > 0


def delete_user_alert(user_id: int, alert_id: int, is_admin: bool = False) -> bool:
    """
    Deletes an alert record, strictly verifying user ownership.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        if is_admin:
            cursor.execute("DELETE FROM user_alerts WHERE id = ?", (alert_id,))
        else:
            cursor.execute(
                "DELETE FROM user_alerts WHERE id = ? AND user_id = ?",
                (alert_id, user_id),
            )
        return cursor.rowcount > 0


def get_user_alert_statistics(user_id: int, is_admin_all: bool = False) -> Dict[str, Any]:
    """
    Computes alert statistics (total, unacknowledged, severity counts) strictly for the user.
    """
    with get_db_connection() as conn:
        cursor = conn.cursor()
        where_clause = "" if is_admin_all else "WHERE user_id = ?"
        params = [] if is_admin_all else [user_id]

        cursor.execute(f"SELECT COUNT(*) as total FROM user_alerts {where_clause}", params)
        total = cursor.fetchone()["total"]

        unack_where = "WHERE is_acknowledged = 0" if is_admin_all else "WHERE user_id = ? AND is_acknowledged = 0"
        cursor.execute(f"SELECT COUNT(*) as unack FROM user_alerts {unack_where}", params)
        unack = cursor.fetchone()["unack"]

        cursor.execute(f"""
            SELECT severity, COUNT(*) as count 
            FROM user_alerts 
            {where_clause} 
            GROUP BY severity
        """, params)
        sev_rows = cursor.fetchall()
        sev_counts = {r["severity"]: r["count"] for r in sev_rows}

    return {
        "total_alerts": total,
        "unacknowledged_alerts": unack,
        "severity_breakdown": {
            "Critical": sev_counts.get("Critical", 0),
            "High": sev_counts.get("High", 0),
            "Medium": sev_counts.get("Medium", 0),
            "Low": sev_counts.get("Low", 0),
        },
    }


# Auto-initialize database schema on module load
try:
    init_db()
except Exception as _e:
    print(f"[DATABASE INIT ERROR] {_e}")
