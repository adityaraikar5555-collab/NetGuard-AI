"""
===============================================================================
NetGuard AI — Product features (frontend-only Streamlit helpers)
===============================================================================
Landing, auth gate, onboarding, triage, reports, compare-runs, docs hub, and
notification helpers. Imports local JSON persistence. No RAG/LLM imports.
Never fabricates ML metrics — only surfaces real session / history / snapshot data.
===============================================================================
"""

from __future__ import annotations

import hashlib
import html
import os
from datetime import datetime
from io import BytesIO
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

import streamlit as st

from persistence import (
    add_notification,
    clear_notifications,
    get_notifications,
    mark_notification_read,
    merge_into_session,
    persist_from_session,
)

try:
    from ui_components import esc
except ImportError:
    def esc(value) -> str:
        return html.escape(str(value), quote=True)

# ---------------------------------------------------------------------------
# Paths & constants
# ---------------------------------------------------------------------------

_REPO_ROOT = Path(__file__).resolve().parent.parent

DEMO_PASSWORD = os.environ.get("NETGUARD_DEMO_PASSWORD", "netguard")

DEMO_FILES: Dict[str, Dict[str, Path]] = {
    "CICIDS-2017": {
        "normal": _REPO_ROOT / "data" / "CICIDS-2017" / "test_10_rows.csv",
        "attack": _REPO_ROOT / "data" / "CICIDS-2017" / "test_attack_10_rows.csv",
    },
    "NSL-KDD": {
        "normal": _REPO_ROOT / "data" / "test" / "NSL-KDD" / "test_10_rows.csv",
        "attack": _REPO_ROOT / "data" / "test" / "NSL-KDD" / "test_10_rows.csv",
    },
}

TRIAGE_STATUSES = ["New", "Investigating", "Confirmed", "False Positive", "Resolved"]

ONBOARDING_STEPS = [
    {"id": 1, "title": "Welcome", "blurb": "Meet the NetGuard AI SOC console."},
    {"id": 2, "title": "Try Demo Traffic", "blurb": "Run a bundled sample through Live Traffic analysis."},
    {"id": 3, "title": "Review Threats", "blurb": "Inspect severity-ranked alerts after analysis."},
    {"id": 4, "title": "You're Ready", "blurb": "Enter the console and start investigating."},
]

_API_ENDPOINTS_FROM_README = [
    ("GET", "/", "App metadata & status"),
    ("GET", "/health", "Health check + ML engine readiness"),
    ("GET", "/model-info", "Loaded models, feature counts, classes"),
    ("GET", "/api/status", "Full service/model/endpoint status"),
    ("POST", "/predict/cicids", "Predict single CICIDS-2017 flow"),
    ("POST", "/predict/nsl-kdd", "Predict single NSL-KDD flow"),
    ("POST", "/analyze/cicids", "Analyze uploaded CICIDS CSV file"),
    ("POST", "/analyze/nsl-kdd", "Analyze uploaded NSL-KDD file"),
    ("POST", "/analyze/dataset", "Inspect/detect an uploaded dataset"),
    ("POST", "/chat", "Ask the RAG-powered SOC assistant"),
]


# ---------------------------------------------------------------------------
# Demo upload shim (analyze_file-compatible)
# ---------------------------------------------------------------------------

class DemoUploadFile:
    """BytesIO wrapper mimicking Streamlit UploadedFile for analyze_file()."""

    def __init__(self, path: Path):
        self._path = Path(path)
        self.name = self._path.name
        data = self._path.read_bytes()
        self.size = len(data)
        self._buf = BytesIO(data)

    def seek(self, offset: int, whence: int = 0):
        return self._buf.seek(offset, whence)

    def read(self, size: int = -1) -> bytes:
        return self._buf.read(size)

    def getvalue(self) -> bytes:
        return self._buf.getvalue()


def get_demo_file(dataset: str, prefer_attack: bool = False) -> Optional[DemoUploadFile]:
    """Return a DemoUploadFile for a bundled CSV, or None if missing."""
    mapping = DEMO_FILES.get(dataset)
    if not mapping:
        return None
    key = "attack" if prefer_attack else "normal"
    path = mapping.get(key) or mapping.get("normal")
    if path is None or not Path(path).exists():
        # Fall back to the other variant if preferred is missing
        alt = mapping.get("normal") if prefer_attack else mapping.get("attack")
        path = alt
    if path is None or not Path(path).exists():
        return None
    try:
        return DemoUploadFile(Path(path))
    except OSError:
        return None


# ---------------------------------------------------------------------------
# Session / product state
# ---------------------------------------------------------------------------

def ensure_product_state() -> None:
    """Initialize product-related session keys and merge from disk."""
    defaults = {
        "onboarding_complete": False,
        "console_unlocked": False,
        "demo_mode": False,
        "notifications": [],
        "alert_triage": {},
        "analysis_snapshots": [],
        "last_api_latency_ms": None,
        "show_landing_hero": True,
        "onboarding_step": 1,
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value
    try:
        merge_into_session()
    except Exception:
        pass


def push_product_notification(title: str, detail: str = "", kind: str = "info") -> None:
    """Persist + session notification; optional toast when settings allow."""
    add_notification(title, detail, kind=kind)
    settings = st.session_state.get("app_settings") or {}
    show = settings.get("show_notifications", True)
    if show:
        try:
            st.toast(f"{title}" + (f" — {detail}" if detail else ""), icon="🔔")
        except Exception:
            pass
    try:
        persist_from_session()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Auth gate
# ---------------------------------------------------------------------------

def render_auth_gate() -> bool:
    """Simple demo / password gate. Returns True if console is unlocked."""
    ensure_product_state()
    if st.session_state.get("console_unlocked"):
        return True

    st.markdown(
        """
        <div class="glass-panel" style="max-width:520px; margin:48px auto; padding:32px 28px; text-align:center;">
            <div class="hero-eyebrow">NETGUARD AI · ACCESS</div>
            <div style="font-family:var(--font-display); font-size:22px; font-weight:700; color:var(--heading); margin:8px 0 6px;">
                Unlock SOC Console
            </div>
            <div style="font-size:13px; color:var(--muted); max-width:400px; margin:0 auto 8px;">
                Enter demo mode for a guided walkthrough, or unlock with the analyst password.
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    col_a, col_b = st.columns(2)
    with col_a:
        st.markdown(
            '<div class="glass-panel" style="padding:18px; text-align:center;">'
            '<div style="font-family:var(--font-mono); font-size:11px; color:var(--signal); letter-spacing:1px;">DEMO MODE</div>'
            '<div style="font-size:13px; color:var(--muted); margin:8px 0 12px;">Open the console with sample traffic — no password.</div>'
            "</div>",
            unsafe_allow_html=True,
        )
        if st.button("Enter Demo Mode", use_container_width=True, type="primary", key="auth_demo_btn"):
            st.session_state.console_unlocked = True
            st.session_state.demo_mode = True
            st.session_state.show_landing_hero = False
            push_product_notification("Demo mode enabled", "SOC console unlocked for demo traffic.", "success")
            persist_from_session()
            st.rerun()

    with col_b:
        st.markdown(
            '<div class="glass-panel" style="padding:18px; text-align:center;">'
            '<div style="font-family:var(--font-mono); font-size:11px; color:var(--signal); letter-spacing:1px;">ANALYST</div>'
            '<div style="font-size:13px; color:var(--muted); margin:8px 0 4px;">Password unlock (default: netguard).</div>'
            "</div>",
            unsafe_allow_html=True,
        )
        pwd = st.text_input("Analyst password", type="password", key="auth_pwd_input", label_visibility="collapsed",
                            placeholder="Analyst password")
        if st.button("Unlock Console", use_container_width=True, key="auth_pwd_btn"):
            if (pwd or "") == DEMO_PASSWORD:
                st.session_state.console_unlocked = True
                st.session_state.demo_mode = False
                st.session_state.show_landing_hero = False
                push_product_notification("Console unlocked", "Analyst access granted.", "success")
                persist_from_session()
                st.rerun()
            else:
                st.error("Incorrect password.")

    return bool(st.session_state.get("console_unlocked"))


# ---------------------------------------------------------------------------
# Notifications
# ---------------------------------------------------------------------------

def render_notification_center() -> None:
    """Compact sidebar-friendly notification panel."""
    ensure_product_state()
    notes = get_notifications()
    unread = sum(1 for n in notes if isinstance(n, dict) and not n.get("read"))

    with st.expander(f"🔔 Notifications ({unread} unread)" if unread else "🔔 Notifications", expanded=False):
        if not notes:
            st.caption("No notifications yet.")
            return
        if st.button("Clear all", key="notif_clear_all", use_container_width=True):
            clear_notifications()
            persist_from_session()
            st.rerun()
        for i, n in enumerate(notes[:20]):
            if not isinstance(n, dict):
                continue
            kind = esc(n.get("kind", "info"))
            title = esc(n.get("title", "Notice"))
            detail = esc(n.get("detail", ""))
            time_s = esc(n.get("time", ""))
            read_mark = "" if n.get("read") else "● "
            st.markdown(
                f'<div class="glass-panel" style="padding:10px 12px; margin-bottom:6px;">'
                f'<div style="font-size:12px; color:var(--heading);">{read_mark}{title}'
                f' <span style="color:var(--muted); font-family:var(--font-mono); font-size:10px;">[{kind}]</span></div>'
                f'<div style="font-size:11px; color:var(--muted); margin-top:2px;">{detail}</div>'
                f'<div style="font-size:10px; color:var(--muted); font-family:var(--font-mono); margin-top:4px;">{time_s}</div>'
                f"</div>",
                unsafe_allow_html=True,
            )
            if not n.get("read"):
                if st.button("Mark read", key=f"notif_read_{i}", use_container_width=True):
                    mark_notification_read(i)
                    persist_from_session()
                    st.rerun()


# ---------------------------------------------------------------------------
# Health / latency strip & shortcuts
# ---------------------------------------------------------------------------

def render_health_latency_strip(
    api_online: bool,
    latency_ms: Optional[float] = None,
    ml_ready: Optional[bool] = None,
    rag_ready: Optional[bool] = None,
) -> None:
    """Compact status strip for API / ML / RAG / latency (real values only)."""
    api_label = "ONLINE" if api_online else "OFFLINE"
    api_col = "var(--signal)" if api_online else "#ef4444"
    lat = latency_ms if latency_ms is not None else st.session_state.get("last_api_latency_ms")
    lat_txt = f"{float(lat):.0f} ms" if isinstance(lat, (int, float)) else "N/A"

    def _pill(label: str, ready: Optional[bool]) -> str:
        if ready is True:
            return f'<span class="pill pill-neutral">{esc(label)}: READY</span>'
        if ready is False:
            return f'<span class="pill" style="border:1px solid #ef444455; color:#ef4444;">{esc(label)}: DOWN</span>'
        return f'<span class="pill pill-neutral">{esc(label)}: N/A</span>'

    st.markdown(
        f"""
        <div class="glass-panel" style="display:flex; align-items:center; gap:14px; flex-wrap:wrap; padding:10px 14px; margin-bottom:8px;">
            <span style="font-family:var(--font-mono); font-size:11px; color:{api_col};">API {api_label}</span>
            <span style="font-family:var(--font-mono); font-size:11px; color:var(--muted);">LATENCY {esc(lat_txt)}</span>
            {_pill("ML", ml_ready)}
            {_pill("RAG", rag_ready)}
        </div>
        """,
        unsafe_allow_html=True,
    )


def render_keyboard_shortcuts_help() -> None:
    st.caption(
        "Shortcuts: **Ctrl+K** / **⌘K** quick nav · **G then O** Overview · "
        "**G then L** Live Traffic · **G then T** Threat Detection · **G then H** History"
    )


def inject_keyboard_nav_script(page_names: Optional[Dict[str, str]] = None) -> None:
    """Lightweight JS: Ctrl+K focuses quick nav; documents G+letter shortcuts via data attrs."""
    mapping = page_names or {
        "o": "Overview",
        "l": "Live Traffic",
        "t": "Threat Detection",
        "h": "Prediction History",
        "s": "Settings",
    }
    data_attrs = " ".join(
        f'data-nav-{esc(k)}="{esc(v)}"' for k, v in mapping.items()
    )
    st.markdown(
        f"""
        <div id="netguard-kbd-nav" {data_attrs} style="display:none;" aria-hidden="true"></div>
        <script>
        (function () {{
            if (window.__netguardKbdBound) return;
            window.__netguardKbdBound = true;
            var pendingG = false;
            window.addEventListener('keydown', function (e) {{
                var tag = (e.target && e.target.tagName) || '';
                if (tag === 'INPUT' || tag === 'TEXTAREA' || (e.target && e.target.isContentEditable)) {{
                    if (!((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k')) return;
                }}
                if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {{
                    e.preventDefault();
                    var el = document.querySelector('input[aria-label*="Quick navigation"]');
                    if (el) {{ el.focus(); el.select(); }}
                    return;
                }}
                if (e.key.toLowerCase() === 'g' && !e.ctrlKey && !e.metaKey && !e.altKey) {{
                    pendingG = true;
                    setTimeout(function () {{ pendingG = false; }}, 800);
                    return;
                }}
                if (pendingG && !e.ctrlKey && !e.metaKey) {{
                    pendingG = false;
                    /* Navigation is applied by Streamlit session via UI; shortcut is documented only. */
                }}
            }});
        }})();
        </script>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Snapshots
# ---------------------------------------------------------------------------

def snapshot_from_normalized(
    normalized: Optional[Dict[str, Any]],
    filename: Optional[str] = None,
    severity_counts: Optional[Dict[str, Any]] = None,
) -> Optional[Dict[str, Any]]:
    """Append a summary-only snapshot (no predictions_df) and persist."""
    if not normalized or not isinstance(normalized, dict):
        return None
    snap = {
        "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "dataset": normalized.get("dataset"),
        "file": filename or normalized.get("filename") or st.session_state.get("uploaded_filename"),
        "total": normalized.get("total"),
        "normal": normalized.get("normal"),
        "attack": normalized.get("attack"),
        "attack_rate": normalized.get("attack_rate"),
    }
    if severity_counts and isinstance(severity_counts, dict):
        clean: Dict[str, int] = {}
        for k, v in severity_counts.items():
            try:
                clean[str(k)] = int(v)
            except (TypeError, ValueError):
                continue
        if clean:
            snap["severity_counts"] = clean

    if "analysis_snapshots" not in st.session_state:
        st.session_state.analysis_snapshots = []
    st.session_state.analysis_snapshots.insert(0, snap)
    st.session_state.analysis_snapshots = st.session_state.analysis_snapshots[:10]
    try:
        persist_from_session()
    except Exception:
        pass
    return snap


def _history_as_snapshot(entry: Dict[str, Any]) -> Dict[str, Any]:
    """Map a history row into snapshot-shaped metrics (real fields only)."""
    return {
        "timestamp": entry.get("Timestamp"),
        "dataset": entry.get("Dataset"),
        "file": entry.get("File"),
        "total": entry.get("Rows Analyzed"),
        "normal": entry.get("Normal"),
        "attack": entry.get("Anomaly"),
        "attack_rate": entry.get("Threat Rate (%)"),
    }


def _fmt_metric(val: Any) -> str:
    if val is None:
        return "N/A"
    if isinstance(val, float):
        return f"{val:.2f}"
    try:
        if isinstance(val, (int,)) or (isinstance(val, str) and val.isdigit()):
            return f"{int(val):,}"
    except (TypeError, ValueError):
        pass
    return esc(val)


# ---------------------------------------------------------------------------
# HTML incident report
# ---------------------------------------------------------------------------

def build_html_incident_report(
    analysis_result: Optional[Dict[str, Any]],
    triage_summary: Optional[Dict[str, Any]] = None,
    timeline_slice: Optional[List[Dict[str, Any]]] = None,
    filename: Optional[str] = None,
) -> str:
    """Self-contained dark HTML report from real session data only."""
    ar = analysis_result or {}
    # Prefer summary fields — never invent
    dataset = ar.get("dataset", "N/A")
    file_name = filename or ar.get("filename") or st.session_state.get("uploaded_filename") or "N/A"
    total = ar.get("total")
    normal = ar.get("normal")
    attack = ar.get("attack")
    rate = ar.get("attack_rate")
    generated = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    def cell(v):
        return "N/A" if v is None else html.escape(str(v))

    triage_rows = ""
    if triage_summary and isinstance(triage_summary, dict):
        for status, count in triage_summary.items():
            triage_rows += f"<tr><td>{html.escape(str(status))}</td><td>{html.escape(str(count))}</td></tr>"
    if not triage_rows:
        triage_rows = "<tr><td colspan='2'>No triage data recorded in this session.</td></tr>"

    timeline_html = ""
    for ev in (timeline_slice or [])[:25]:
        if not isinstance(ev, dict):
            continue
        timeline_html += (
            f"<tr><td>{html.escape(str(ev.get('time', '')))}</td>"
            f"<td>{html.escape(str(ev.get('event', '')))}</td>"
            f"<td>{html.escape(str(ev.get('detail', '')))}</td>"
            f"<td>{html.escape(str(ev.get('kind', '')))}</td></tr>"
        )
    if not timeline_html:
        timeline_html = "<tr><td colspan='4'>No timeline events in this session.</td></tr>"

    rate_txt = "N/A" if rate is None else f"{rate}%"

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<title>NetGuard AI — Incident Report</title>
<style>
  :root {{ --bg:#070b14; --panel:#0e1524; --text:#e6ebf5; --muted:#8b9bb4; --signal:#38bdf8; --border:rgba(56,189,248,0.25); }}
  * {{ box-sizing:border-box; }}
  body {{ margin:0; font-family:Segoe UI, system-ui, sans-serif; background:var(--bg); color:var(--text); padding:32px; }}
  h1 {{ font-size:22px; letter-spacing:1px; color:var(--signal); margin:0 0 4px; }}
  .sub {{ color:var(--muted); font-size:13px; margin-bottom:24px; }}
  .grid {{ display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr)); gap:12px; margin-bottom:24px; }}
  .kpi {{ background:var(--panel); border:1px solid var(--border); border-radius:10px; padding:14px 16px; }}
  .kpi .l {{ font-size:10px; text-transform:uppercase; letter-spacing:1px; color:var(--muted); }}
  .kpi .v {{ font-size:20px; font-weight:700; margin-top:6px; font-family:ui-monospace,monospace; }}
  table {{ width:100%; border-collapse:collapse; background:var(--panel); border:1px solid var(--border); border-radius:10px; overflow:hidden; margin-bottom:20px; }}
  th, td {{ text-align:left; padding:10px 12px; border-bottom:1px solid rgba(255,255,255,0.06); font-size:13px; }}
  th {{ color:var(--signal); font-size:11px; letter-spacing:1px; text-transform:uppercase; }}
  h2 {{ font-size:14px; color:var(--signal); letter-spacing:1px; text-transform:uppercase; margin:28px 0 10px; }}
  .foot {{ color:var(--muted); font-size:11px; margin-top:32px; }}
  @media print {{ body {{ background:#fff; color:#111; }} .kpi, table {{ border-color:#ccc; background:#fff; }} th {{ color:#0369a1; }} }}
</style>
</head>
<body>
  <h1>NETGUARD AI — INCIDENT REPORT</h1>
  <div class="sub">Generated {html.escape(generated)} · Print this page to save as PDF</div>
  <div class="grid">
    <div class="kpi"><div class="l">Dataset</div><div class="v" style="font-size:14px;">{cell(dataset)}</div></div>
    <div class="kpi"><div class="l">File</div><div class="v" style="font-size:14px;">{cell(file_name)}</div></div>
    <div class="kpi"><div class="l">Total Flows</div><div class="v">{cell(total)}</div></div>
    <div class="kpi"><div class="l">Normal</div><div class="v">{cell(normal)}</div></div>
    <div class="kpi"><div class="l">Attack / Anomaly</div><div class="v">{cell(attack)}</div></div>
    <div class="kpi"><div class="l">Threat Rate</div><div class="v">{html.escape(rate_txt)}</div></div>
  </div>
  <h2>Alert Triage Summary</h2>
  <table><thead><tr><th>Status</th><th>Count</th></tr></thead><tbody>{triage_rows}</tbody></table>
  <h2>Session Timeline</h2>
  <table><thead><tr><th>Time</th><th>Event</th><th>Detail</th><th>Kind</th></tr></thead><tbody>{timeline_html}</tbody></table>
  <div class="foot">Values reflect the active Streamlit session only. NetGuard AI does not fabricate metrics.</div>
</body>
</html>"""


def render_report_export_page() -> None:
    """Export HTML incident report from real analysis_result only."""
    ensure_product_state()
    st.markdown(
        '<div class="section-header"><div class="section-title">📄 Incident Report Export</div>'
        '<div class="section-description">Download a print-ready HTML report from the active analysis — no fabricated metrics.</div></div>',
        unsafe_allow_html=True,
    )

    result = st.session_state.get("analysis_result")
    if not result:
        st.markdown(
            """
            <div class="glass-panel" style="text-align:center; padding:48px 20px; border-style:dashed;">
                <div style="font-size:40px; margin-bottom:12px; opacity:0.85;">📄</div>
                <div style="font-family:var(--font-display); font-size:17px; font-weight:700; color:var(--heading);">No analysis to export</div>
                <div style="font-size:13px; color:var(--muted); margin-top:6px;">Run Live Traffic analysis first. Reports only use real session results.</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        st.markdown(
            f'<div class="glass-panel" style="padding:14px;"><div style="color:var(--muted); font-size:10px;">TOTAL</div>'
            f'<div style="font-size:20px; font-weight:700; font-family:var(--font-mono);">{_fmt_metric(result.get("total"))}</div></div>',
            unsafe_allow_html=True,
        )
    with c2:
        st.markdown(
            f'<div class="glass-panel" style="padding:14px;"><div style="color:var(--muted); font-size:10px;">NORMAL</div>'
            f'<div style="font-size:20px; font-weight:700; font-family:var(--font-mono);">{_fmt_metric(result.get("normal"))}</div></div>',
            unsafe_allow_html=True,
        )
    with c3:
        st.markdown(
            f'<div class="glass-panel" style="padding:14px;"><div style="color:var(--muted); font-size:10px;">ATTACK</div>'
            f'<div style="font-size:20px; font-weight:700; font-family:var(--font-mono);">{_fmt_metric(result.get("attack"))}</div></div>',
            unsafe_allow_html=True,
        )
    with c4:
        rate = result.get("attack_rate")
        rate_disp = "N/A" if rate is None else f"{rate}%"
        st.markdown(
            f'<div class="glass-panel" style="padding:14px;"><div style="color:var(--muted); font-size:10px;">THREAT RATE</div>'
            f'<div style="font-size:20px; font-weight:700; font-family:var(--font-mono);">{esc(rate_disp)}</div></div>',
            unsafe_allow_html=True,
        )

    triage = st.session_state.get("alert_triage") or {}
    triage_summary: Dict[str, int] = {}
    for meta in triage.values():
        if isinstance(meta, dict):
            status = meta.get("status", "New")
            triage_summary[status] = triage_summary.get(status, 0) + 1

    if triage_summary:
        st.markdown("**Triage summary (this session)**")
        st.write(triage_summary)
    else:
        st.caption("No alert triage recorded yet — export will note that in the report.")

    timeline = list(st.session_state.get("session_timeline") or [])[:40]
    html_doc = build_html_incident_report(
        result,
        triage_summary=triage_summary or None,
        timeline_slice=timeline,
        filename=st.session_state.get("uploaded_filename"),
    )
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    st.download_button(
        "⬇️ Download HTML Report (print to PDF)",
        data=html_doc.encode("utf-8"),
        file_name=f"netguard_incident_report_{stamp}.html",
        mime="text/html",
        use_container_width=True,
        type="primary",
    )


# ---------------------------------------------------------------------------
# Compare runs
# ---------------------------------------------------------------------------

def render_compare_runs_page() -> None:
    """Side-by-side compare of two real snapshots / history entries."""
    ensure_product_state()
    st.markdown(
        '<div class="section-header"><div class="section-title">⚖️ Compare Analysis Runs</div>'
        '<div class="section-description">Pick two saved snapshots or history rows — metrics come from prior real analyses only.</div></div>',
        unsafe_allow_html=True,
    )

    snaps = list(st.session_state.get("analysis_snapshots") or [])
    history = list(st.session_state.get("history") or [])
    options: List[Dict[str, Any]] = []
    labels: List[str] = []

    for i, s in enumerate(snaps):
        if not isinstance(s, dict):
            continue
        label = f"Snapshot · {s.get('timestamp', '?')} · {s.get('dataset', '?')} · {s.get('file', '?')}"
        labels.append(label)
        options.append(s)
    for i, h in enumerate(history):
        if not isinstance(h, dict):
            continue
        snap = _history_as_snapshot(h)
        label = f"History · {snap.get('timestamp', '?')} · {snap.get('dataset', '?')} · {snap.get('file', '?')}"
        labels.append(label)
        options.append(snap)

    if len(options) < 2:
        st.markdown(
            """
            <div class="glass-panel" style="text-align:center; padding:48px 20px; border-style:dashed;">
                <div style="font-size:40px; margin-bottom:12px; opacity:0.85;">⚖️</div>
                <div style="font-family:var(--font-display); font-size:17px; font-weight:700; color:var(--heading);">Need at least two runs</div>
                <div style="font-size:13px; color:var(--muted); margin-top:6px; max-width:440px; margin-left:auto; margin-right:auto;">
                    Complete two Live Traffic analyses (or retain prediction history) to compare attack rates and flow counts side by side.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    a_lab = st.selectbox("Run A", labels, index=0, key="compare_run_a")
    b_default = 1 if len(labels) > 1 else 0
    b_lab = st.selectbox("Run B", labels, index=b_default, key="compare_run_b")
    run_a = options[labels.index(a_lab)]
    run_b = options[labels.index(b_lab)]

    left, right = st.columns(2)
    for col, run, title in ((left, run_a, "Run A"), (right, run_b, "Run B")):
        with col:
            st.markdown(
                f'<div class="glass-panel" style="padding:16px;">'
                f'<div style="font-family:var(--font-mono); font-size:11px; color:var(--signal);">{esc(title)}</div>'
                f'<div style="margin-top:10px; font-size:13px; color:var(--muted);">Dataset</div>'
                f'<div style="font-weight:600;">{esc(run.get("dataset") or "N/A")}</div>'
                f'<div style="margin-top:8px; font-size:13px; color:var(--muted);">File</div>'
                f'<div style="font-weight:600; font-family:var(--font-mono); font-size:12px;">{esc(run.get("file") or "N/A")}</div>'
                f'<div style="margin-top:8px; font-size:13px; color:var(--muted);">Timestamp</div>'
                f'<div style="font-family:var(--font-mono); font-size:12px;">{esc(run.get("timestamp") or "N/A")}</div>'
                f'<hr style="border-color:rgba(56,189,248,0.15); margin:14px 0;"/>'
                f'<div>Total: <b>{_fmt_metric(run.get("total"))}</b></div>'
                f'<div>Normal: <b>{_fmt_metric(run.get("normal"))}</b></div>'
                f'<div>Attack: <b>{_fmt_metric(run.get("attack"))}</b></div>'
                f'<div>Threat rate: <b>{_fmt_metric(run.get("attack_rate"))}'
                f'{"%" if run.get("attack_rate") is not None else ""}</b></div>'
                f"</div>",
                unsafe_allow_html=True,
            )


# ---------------------------------------------------------------------------
# Docs hub
# ---------------------------------------------------------------------------

def render_docs_hub() -> None:
    """Static product documentation tabs (no backend changes)."""
    st.markdown(
        '<div class="section-header"><div class="section-title">📚 Documentation Hub</div>'
        '<div class="section-description">Operator guides for NetGuard AI — formats, severity rules, and API surface from the project README.</div></div>',
        unsafe_allow_html=True,
    )
    t1, t2, t3, t4, t5 = st.tabs([
        "Getting Started", "CSV Formats", "Severity Scoring", "Architecture", "API Quickstart",
    ])

    with t1:
        st.markdown(
            """
            ### Getting Started
            1. Ensure the FastAPI backend is reachable (local `http://127.0.0.1:8000` or the deployed Render URL).
            2. Open the Streamlit SOC console and unlock via **Demo Mode** or the analyst password.
            3. Choose **CICIDS-2017** or **NSL-KDD** in the sidebar dataset selector.
            4. Go to **Live Traffic**, upload a CSV (or use a bundled demo sample), and run analysis.
            5. Review **Threat Detection** for severity-ranked alerts, then triage statuses as needed.
            6. Export an HTML incident report or compare prior runs from product pages when wired in navigation.
            """
        )

    with t2:
        st.markdown(
            """
            ### CSV Formats (high-level)

            **CICIDS-2017**
            - Flow-based CSV with on the order of **78 numerical features** (plus labels in training sets).
            - Typical columns include duration, packet/byte counts, IAT statistics, flag counts, and flow rates.
            - Upload path: `POST /analyze/cicids` via Live Traffic when CICIDS is selected.

            **NSL-KDD**
            - Classic KDD-style records with **41 features** (+ label / difficulty in labeled files).
            - Mix of categorical (protocol, service, flag) and numeric connection attributes.
            - Upload path: `POST /analyze/nsl-kdd` when NSL-KDD is selected.

            The UI never invents columns — mismatched schemas surface as backend validation errors.
            """
        )

    with t3:
        st.markdown(
            """
            ### Severity Scoring (UI rule-based)

            Dashboard severity is a **frontend presentation layer** over model outputs — not a separate ML model.

            For each predicted flow:
            - Non-attack / benign flows → **None**
            - Attack with no score → **Medium** (default when probability unavailable)
            - Attack probability ≥ **0.90** → **Critical**
            - ≥ **0.75** → **High**
            - ≥ **0.50** → **Medium**
            - Below **0.50** → **Low**

            Scores above ~1.5 are treated as percentages and scaled by 100 before banding.
            Threat-level banners (MINIMAL → CRITICAL) additionally band the session **attack_rate**.
            """
        )

    with t4:
        st.markdown(
            """
            ### Architecture

            ```
            Streamlit SOC UI  →  FastAPI (health / predict / analyze / chat)
                                      ├─ ML engines (CICIDS + NSL-KDD .pkl)
                                      └─ RAG SOC assistant (knowledge base)
            ```

            - **Frontend:** Streamlit dashboard (`frontend/dashboard.py`) — visualization & operator UX only.
            - **Backend:** FastAPI serving inference and chat endpoints.
            - **Models:** Pre-trained artifacts under `models/` (not modified by this UI).
            - **Data:** Benchmark CSVs under `data/` for demos and evaluation.
            """
        )

    with t5:
        st.markdown("### API Quickstart (from project README)")
        st.caption("Base URL examples: local `http://127.0.0.1:8000` · deployed Render service.")
        rows = "| Method | Endpoint | Description |\n|--------|----------|-------------|\n"
        for method, path, desc in _API_ENDPOINTS_FROM_README:
            rows += f"| `{method}` | `{path}` | {desc} |\n"
        st.markdown(rows)


# ---------------------------------------------------------------------------
# Landing
# ---------------------------------------------------------------------------

def render_landing_page(api_online: bool = False) -> None:
    """Polished dark-SOC product landing inside Streamlit."""
    ensure_product_state()
    api_txt = "API ONLINE" if api_online else "API OFFLINE"
    api_col = "var(--signal)" if api_online else "#ef4444"

    st.markdown(
        f"""
        <div style="min-height:70vh; display:flex; flex-direction:column; justify-content:center; padding:24px 8px 8px;">
          <div style="font-family:var(--font-display); font-size:clamp(36px,6vw,56px); font-weight:800; letter-spacing:2px;
                      color:var(--heading); line-height:1.05;">
            NETGUARD <span style="color:var(--signal);">AI</span>
          </div>
          <div style="font-family:var(--font-display); font-size:clamp(18px,2.5vw,26px); color:var(--heading); margin-top:14px; max-width:640px;">
            Detect network anomalies before they become incidents.
          </div>
          <div style="font-size:14px; color:var(--muted); margin-top:10px; max-width:520px; line-height:1.55;">
            Enterprise SOC console for CICIDS-2017 and NSL-KDD traffic — live ML scoring,
            severity triage, and operator-ready investigation workflows.
          </div>
          <div style="margin-top:18px; font-family:var(--font-mono); font-size:11px; color:{api_col}; letter-spacing:1px;">
            ● {api_txt}
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    c1, c2, c3 = st.columns(3)
    with c1:
        if st.button("Enter SOC Console", use_container_width=True, type="primary", key="landing_enter"):
            st.session_state.console_unlocked = True
            st.session_state.show_landing_hero = False
            st.session_state.nav_page = "Overview"
            persist_from_session()
            st.rerun()
    with c2:
        if st.button("Try Demo", use_container_width=True, key="landing_demo"):
            st.session_state.console_unlocked = True
            st.session_state.demo_mode = True
            st.session_state.show_landing_hero = False
            st.session_state.nav_page = "Live Traffic"
            push_product_notification("Demo ready", "Open Live Traffic or Onboarding to run sample CSVs.", "info")
            persist_from_session()
            st.rerun()
    with c3:
        if st.button("Guided Tour", use_container_width=True, key="landing_tour"):
            st.session_state.console_unlocked = True
            st.session_state.show_landing_hero = False
            st.session_state.onboarding_step = 1
            st.session_state.nav_page = "Onboarding"
            persist_from_session()
            st.rerun()

    st.write("")
    st.markdown(
        """
        <div class="glass-panel" style="padding:22px 20px; margin-top:12px;">
          <div style="font-family:var(--font-mono); font-size:11px; color:var(--signal); letter-spacing:2px; margin-bottom:12px;">CAPABILITIES</div>
          <div style="display:grid; grid-template-columns:repeat(auto-fit,minmax(180px,1fr)); gap:14px;">
            <div><div style="font-weight:700; color:var(--heading);">Live ML Analysis</div>
                 <div style="font-size:12px; color:var(--muted); margin-top:4px;">Score uploaded flows against trained CICIDS & NSL-KDD models.</div></div>
            <div><div style="font-weight:700; color:var(--heading);">Threat Triage</div>
                 <div style="font-size:12px; color:var(--muted); margin-top:4px;">Severity bands, alert status, and investigation notes.</div></div>
            <div><div style="font-weight:700; color:var(--heading);">SOC Assistant</div>
                 <div style="font-size:12px; color:var(--muted); margin-top:4px;">RAG-backed answers over the project knowledge base.</div></div>
            <div><div style="font-weight:700; color:var(--heading);">Incident Reports</div>
                 <div style="font-size:12px; color:var(--muted); margin-top:4px;">Print-ready HTML exports from real session metrics.</div></div>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown(
        """
        <div class="glass-panel" style="padding:20px; margin-top:14px;">
          <div style="font-family:var(--font-mono); font-size:11px; color:var(--signal); letter-spacing:2px;">ARCHITECTURE</div>
          <div style="font-size:13px; color:var(--muted); margin-top:8px; line-height:1.6;">
            Streamlit operator UI talks to a FastAPI inference service. Models stay on the backend;
            the dashboard visualizes predictions, severity, topology, and session history without altering weights.
          </div>
        </div>
        <div style="text-align:center; margin:28px 0 8px; font-size:12px; color:var(--muted); font-family:var(--font-mono);">
          Built by Aditya Raikar · NetGuard AI
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Onboarding wizard
# ---------------------------------------------------------------------------

def render_onboarding_page(analyze_callback: Optional[Callable] = None) -> None:
    """4-step guided onboarding wizard."""
    ensure_product_state()
    step = int(st.session_state.get("onboarding_step") or 1)
    step = max(1, min(4, step))

    st.markdown(
        '<div class="section-header"><div class="section-title">🧭 Guided Onboarding</div>'
        '<div class="section-description">Four steps to your first NetGuard analysis.</div></div>',
        unsafe_allow_html=True,
    )

    # Progress strip
    pills = []
    for s in ONBOARDING_STEPS:
        active = s["id"] == step
        color = "var(--signal)" if active else "var(--muted)"
        weight = "700" if active else "500"
        pills.append(
            f'<span style="color:{color}; font-weight:{weight}; font-family:var(--font-mono); font-size:11px; margin-right:12px;">'
            f'{s["id"]}. {esc(s["title"])}</span>'
        )
    st.markdown(
        f'<div class="glass-panel" style="padding:12px 16px; margin-bottom:12px;">{"".join(pills)}</div>',
        unsafe_allow_html=True,
    )

    if step == 1:
        st.markdown(
            """
            <div class="glass-panel" style="padding:24px;">
              <div style="font-family:var(--font-display); font-size:18px; font-weight:700; color:var(--heading);">Welcome to NetGuard AI</div>
              <div style="font-size:13px; color:var(--muted); margin-top:8px; line-height:1.55;">
                This SOC console helps you analyze network flows, triage anomalies, and export session reports.
                Nothing on screen invents attack rates — every KPI comes from a real API response or file statistic.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Continue →", type="primary", key="onb_s1_next"):
            st.session_state.onboarding_step = 2
            st.rerun()

    elif step == 2:
        st.markdown("**Pick a demo dataset** and run a bundled sample.")
        ds = st.radio("Dataset", ["CICIDS-2017", "NSL-KDD"], horizontal=True, key="onb_dataset")
        prefer_attack = st.checkbox("Prefer attack sample (when available)", value=True, key="onb_prefer_attack")
        demo = get_demo_file(ds, prefer_attack=prefer_attack)
        if demo:
            st.caption(f"Sample ready: `{demo.name}` ({demo.size:,} bytes)")
        else:
            st.warning("Bundled demo CSV not found on disk for this dataset.")

        if st.button("Try Demo Analysis", type="primary", key="onb_try_demo", disabled=demo is None):
            st.session_state.active_dataset = ds
            if analyze_callback and demo is not None:
                try:
                    analyze_callback(demo)
                    push_product_notification("Demo analysis started", demo.name, "success")
                except Exception as exc:
                    st.error(f"Demo analysis failed: {exc}")
            else:
                st.info("Go to **Live Traffic** and upload the sample, or wire `analyze_callback` when embedding this page.")
                st.session_state.nav_page = "Live Traffic"
                persist_from_session()
        cols = st.columns(2)
        with cols[0]:
            if st.button("← Back", key="onb_s2_back"):
                st.session_state.onboarding_step = 1
                st.rerun()
        with cols[1]:
            if st.button("Continue →", key="onb_s2_next"):
                st.session_state.onboarding_step = 3
                st.rerun()

    elif step == 3:
        st.markdown(
            """
            <div class="glass-panel" style="padding:24px;">
              <div style="font-family:var(--font-display); font-size:18px; font-weight:700; color:var(--heading);">Review Threat Detection</div>
              <div style="font-size:13px; color:var(--muted); margin-top:8px; line-height:1.55;">
                After analysis, open <b>Threat Detection</b> to filter by severity, open an investigation panel,
                and set triage status (New → Investigating → Confirmed / False Positive / Resolved).
                Severity bands are rule-based over model scores — see Documentation Hub for thresholds.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Open Threat Detection", key="onb_goto_threats"):
            st.session_state.nav_page = "Threat Detection"
            persist_from_session()
            st.rerun()
        cols = st.columns(2)
        with cols[0]:
            if st.button("← Back", key="onb_s3_back"):
                st.session_state.onboarding_step = 2
                st.rerun()
        with cols[1]:
            if st.button("Continue →", key="onb_s3_next"):
                st.session_state.onboarding_step = 4
                st.rerun()

    else:
        st.markdown(
            """
            <div class="glass-panel" style="padding:24px; text-align:center;">
              <div style="font-family:var(--font-display); font-size:18px; font-weight:700; color:var(--heading);">You're ready</div>
              <div style="font-size:13px; color:var(--muted); margin-top:8px;">
                Onboarding complete. Jump to Overview to monitor session threat posture.
              </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        if st.button("Finish & Go to Overview", type="primary", key="onb_finish"):
            st.session_state.onboarding_complete = True
            st.session_state.nav_page = "Overview"
            push_product_notification("Onboarding complete", "Welcome to the SOC console.", "success")
            persist_from_session()
            st.rerun()
        if st.button("← Back", key="onb_s4_back"):
            st.session_state.onboarding_step = 3
            st.rerun()


# ---------------------------------------------------------------------------
# Alert triage panel
# ---------------------------------------------------------------------------

def _alert_stable_id(row, idx: int) -> str:
    """Stable triage key from prediction + severity + row identity."""
    parts = [
        str(idx),
        str(row.get("prediction", "")),
        str(row.get("Severity", "")),
        str(row.get("row", row.name if hasattr(row, "name") else "")),
        str(row.get("attack_probability", row.get("confidence", ""))),
    ]
    raw = "|".join(parts)
    return hashlib.sha1(raw.encode("utf-8")).hexdigest()[:16]


def render_alert_triage_panel(work_df) -> None:
    """Per-alert status + notes for visible threats (limit 25)."""
    ensure_product_state()
    if work_df is None or getattr(work_df, "empty", True):
        st.caption("No alerts available for triage.")
        return

    if "alert_triage" not in st.session_state or not isinstance(st.session_state.alert_triage, dict):
        st.session_state.alert_triage = {}

    st.markdown(
        '<div class="section-header"><div class="section-title">🗂️ Alert Triage</div>'
        '<div class="section-description">Assign status and notes to visible alerts (session-persisted).</div></div>',
        unsafe_allow_html=True,
    )

    status_filter = st.selectbox(
        "Filter by triage status",
        ["All"] + TRIAGE_STATUSES,
        key="triage_status_filter",
    )

    rows = list(work_df.head(25).iterrows())
    shown = 0
    for i, (orig_idx, row) in enumerate(rows):
        aid = _alert_stable_id(row, int(orig_idx) if str(orig_idx).isdigit() else i)
        meta = st.session_state.alert_triage.get(aid) or {"status": "New", "notes": ""}
        cur_status = meta.get("status", "New")
        if status_filter != "All" and cur_status != status_filter:
            continue
        shown += 1
        pred = esc(row.get("prediction", "Alert"))
        sev = esc(row.get("Severity", "Unknown"))
        with st.expander(f"#{i + 1} · {pred} · {sev} · {cur_status}", expanded=False):
            new_status = st.selectbox(
                "Status",
                TRIAGE_STATUSES,
                index=TRIAGE_STATUSES.index(cur_status) if cur_status in TRIAGE_STATUSES else 0,
                key=f"triage_status_{aid}",
            )
            notes = st.text_area(
                "Notes",
                value=str(meta.get("notes") or ""),
                key=f"triage_notes_{aid}",
                height=80,
            )
            st.session_state.alert_triage[aid] = {
                "status": new_status,
                "notes": notes,
                "updated": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            }

    if shown == 0:
        st.caption("No alerts match this triage filter.")
    else:
        try:
            persist_from_session()
        except Exception:
            pass


# ---------------------------------------------------------------------------
# About (upgraded)
# ---------------------------------------------------------------------------

def render_upgraded_about() -> None:
    """Portfolio-quality About section."""
    st.markdown(
        """
        <div class="section-header">
          <div class="section-title">ℹ️ About NetGuard AI</div>
          <div class="section-description">AI-assisted network anomaly detection for SOC-style investigation.</div>
        </div>
        <div class="glass-panel" style="padding:22px;">
          <div style="font-family:var(--font-display); font-size:20px; font-weight:700; color:var(--heading);">
            NETGUARD <span style="color:var(--signal);">AI</span>
          </div>
          <div style="font-size:13px; color:var(--muted); margin-top:10px; line-height:1.6; max-width:640px;">
            Built by <b style="color:var(--heading);">Aditya Raikar</b> — a Streamlit + FastAPI product that scores
            CICIDS-2017 and NSL-KDD traffic with trained ML models, then surfaces severity, topology, and
            operator triage without fabricating metrics.
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.write("")
    a, b = st.columns(2)
    with a:
        st.markdown(
            """
            <div class="glass-panel" style="padding:18px; height:100%;">
              <div style="font-family:var(--font-mono); font-size:11px; color:var(--signal); letter-spacing:1px;">STACK</div>
              <ul style="font-size:13px; color:var(--muted); margin:10px 0 0; padding-left:18px; line-height:1.7;">
                <li>Streamlit SOC dashboard</li>
                <li>FastAPI inference &amp; chat API</li>
                <li>scikit-learn model artifacts</li>
                <li>Plotly / Canvas visualizations</li>
                <li>RAG knowledge base (SOC assistant)</li>
              </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )
    with b:
        st.markdown(
            """
            <div class="glass-panel" style="padding:18px; height:100%;">
              <div style="font-family:var(--font-mono); font-size:11px; color:var(--signal); letter-spacing:1px;">PRINCIPLES</div>
              <ul style="font-size:13px; color:var(--muted); margin:10px 0 0; padding-left:18px; line-height:1.7;">
                <li><b style="color:var(--heading);">Data integrity</b> — N/A when unavailable; never invent attack rates</li>
                <li><b style="color:var(--heading);">UI-only safety</b> — frontend does not alter model weights</li>
                <li><b style="color:var(--heading);">Operator first</b> — triage, reports, and clear severity rules</li>
                <li><b style="color:var(--heading);">Accessible SOC</b> — dark theme, reduced motion, semantic status</li>
              </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")
    st.markdown(
        """
        <div class="glass-panel" style="padding:18px;">
          <div style="font-family:var(--font-mono); font-size:11px; color:var(--signal); letter-spacing:1px;">DEPLOYMENT LINKS</div>
          <div style="font-size:13px; color:var(--muted); margin-top:10px; line-height:1.8;">
            Streamlit Cloud: <span style="color:var(--heading);">[add your Cloud URL]</span><br/>
            API (Render): <span style="color:var(--heading);">https://netguard-ai-nd5e.onrender.com</span><br/>
            Local UI: <code>http://localhost:8501</code> · Local API: <code>http://127.0.0.1:8000</code>
          </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.caption("NetGuard AI dashboard is UI-only relative to prediction logic and model artifacts.")
