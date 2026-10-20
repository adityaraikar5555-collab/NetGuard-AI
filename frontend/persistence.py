"""
===============================================================================
NetGuard AI — Local JSON session persistence (frontend-only)
===============================================================================
Persists operator preferences and lightweight session artifacts under
frontend/.session_store/ so a browser refresh does not wipe triage, history,
notifications, or analysis snapshots.

Never stores full predictions DataFrames — snapshots are summary dicts only.
Never fabricates ML metrics.
===============================================================================
"""

from __future__ import annotations

import json
from copy import deepcopy
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

STORE_DIR = Path(__file__).resolve().parent / ".session_store"
STORE_FILE = STORE_DIR / "netguard_store.json"

MAX_TIMELINE = 100
MAX_HISTORY = 50
MAX_NOTIFICATIONS = 40
MAX_SNAPSHOTS = 10

_DEFAULT_STORE: Dict[str, Any] = {
    "app_settings": {
        "theme_mode": "Dark",
        "high_contrast": False,
        "reduced_motion": False,
        "refresh_preference": "manual",
        "show_notifications": True,
    },
    "session_timeline": [],
    "history": [],
    "alert_triage": {},
    "notifications": [],
    "analysis_snapshots": [],
    "onboarding_complete": False,
    "console_unlocked": False,
    "demo_mode": False,
}

# Session keys that map 1:1 onto the store.
_SESSION_KEYS = (
    "app_settings",
    "session_timeline",
    "history",
    "alert_triage",
    "notifications",
    "analysis_snapshots",
    "onboarding_complete",
    "console_unlocked",
    "demo_mode",
)


def _empty_store() -> Dict[str, Any]:
    return deepcopy(_DEFAULT_STORE)


def _trim_lists(data: Dict[str, Any]) -> Dict[str, Any]:
    """Enforce max sizes in-place and return the dict."""
    if isinstance(data.get("session_timeline"), list):
        data["session_timeline"] = data["session_timeline"][:MAX_TIMELINE]
    if isinstance(data.get("history"), list):
        data["history"] = data["history"][:MAX_HISTORY]
    if isinstance(data.get("notifications"), list):
        data["notifications"] = data["notifications"][:MAX_NOTIFICATIONS]
    if isinstance(data.get("analysis_snapshots"), list):
        data["analysis_snapshots"] = data["analysis_snapshots"][:MAX_SNAPSHOTS]
    return data


def load_store() -> Dict[str, Any]:
    """Load the on-disk store, merging with defaults for missing keys."""
    base = _empty_store()
    if not STORE_FILE.exists():
        return base
    try:
        raw = json.loads(STORE_FILE.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            return base
        for key in _DEFAULT_STORE:
            if key in raw:
                base[key] = raw[key]
        return _trim_lists(base)
    except (OSError, json.JSONDecodeError, TypeError, ValueError):
        return _empty_store()


def save_store(data: Dict[str, Any]) -> None:
    """Write the store to disk (creates STORE_DIR on write)."""
    if not isinstance(data, dict):
        return
    payload = _empty_store()
    for key in _DEFAULT_STORE:
        if key in data:
            payload[key] = data[key]
    _trim_lists(payload)
    try:
        STORE_DIR.mkdir(parents=True, exist_ok=True)
        STORE_FILE.write_text(
            json.dumps(payload, indent=2, default=str),
            encoding="utf-8",
        )
    except OSError:
        pass


def _is_empty_session_value(key: str, value: Any) -> bool:
    """Whether a session value should be overwritten from disk on merge."""
    if value is None:
        return True
    if key in ("session_timeline", "history", "notifications", "analysis_snapshots"):
        return isinstance(value, list) and len(value) == 0
    if key == "alert_triage":
        return isinstance(value, dict) and len(value) == 0
    if key == "app_settings":
        return not isinstance(value, dict) or len(value) == 0
    # Booleans / flags: only fill if missing (caller checks key existence)
    return False


def merge_into_session() -> None:
    """Copy persisted values into st.session_state when session is empty/missing."""
    try:
        import streamlit as st
    except ImportError:
        return

    store = load_store()
    for key in _SESSION_KEYS:
        if key not in st.session_state:
            st.session_state[key] = deepcopy(store.get(key, _DEFAULT_STORE.get(key)))
            continue
        current = st.session_state.get(key)
        if _is_empty_session_value(key, current):
            persisted = store.get(key)
            if persisted is not None:
                st.session_state[key] = deepcopy(persisted)


def persist_from_session() -> None:
    """Write current session fields back to disk."""
    try:
        import streamlit as st
    except ImportError:
        return

    data = load_store()
    for key in _SESSION_KEYS:
        if key in st.session_state:
            data[key] = deepcopy(st.session_state[key])
    save_store(data)


def add_notification(title: str, detail: str = "", kind: str = "info") -> Dict[str, Any]:
    """Append a notification to the store (and session if available)."""
    entry = {
        "title": str(title or "Notification"),
        "detail": str(detail or ""),
        "kind": str(kind or "info"),
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "read": False,
    }

    store = load_store()
    notes: List[Dict[str, Any]] = list(store.get("notifications") or [])
    notes.insert(0, entry)
    store["notifications"] = notes[:MAX_NOTIFICATIONS]
    save_store(store)

    try:
        import streamlit as st
        if "notifications" not in st.session_state:
            st.session_state.notifications = []
        st.session_state.notifications.insert(0, entry)
        st.session_state.notifications = st.session_state.notifications[:MAX_NOTIFICATIONS]
    except Exception:
        pass

    return entry


def get_notifications() -> List[Dict[str, Any]]:
    """Return notifications from session if present, else from disk."""
    try:
        import streamlit as st
        if "notifications" in st.session_state and isinstance(st.session_state.notifications, list):
            return list(st.session_state.notifications)
    except Exception:
        pass
    return list(load_store().get("notifications") or [])


def clear_notifications() -> None:
    """Clear all notifications in session and on disk."""
    store = load_store()
    store["notifications"] = []
    save_store(store)
    try:
        import streamlit as st
        st.session_state.notifications = []
    except Exception:
        pass


def mark_notification_read(idx: int) -> None:
    """Mark a notification as read by list index."""
    try:
        idx = int(idx)
    except (TypeError, ValueError):
        return

    try:
        import streamlit as st
        notes = st.session_state.get("notifications")
        if isinstance(notes, list) and 0 <= idx < len(notes):
            if isinstance(notes[idx], dict):
                notes[idx]["read"] = True
            st.session_state.notifications = notes
    except Exception:
        pass

    store = load_store()
    notes = list(store.get("notifications") or [])
    if 0 <= idx < len(notes) and isinstance(notes[idx], dict):
        notes[idx]["read"] = True
        store["notifications"] = notes
        save_store(store)
