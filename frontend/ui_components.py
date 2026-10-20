"""
===============================================================================
NetGuard AI — Frontend Design-System & Reusable UI Components
===============================================================================
UI-layer ONLY. This module contains no ML logic, no RAG logic, and no backend
calls of its own. It provides reusable renderers (status bars, banners, threat
level indicators, CTAs) that the Streamlit dashboard layers over the existing
FastAPI responses.

Design language:
    * Enterprise SOC command-center aesthetic
    * Dark cyber theme with restrained glassmorphism
    * Semantic, colorblind-safe status rendering (icon + label, never color-only)
    * Accessible focus/hover states and reduced-motion support

Nothing in this file fabricates data. Every value passed in comes from the
caller, which sources it exclusively from the FastAPI backend or from pandas
statistics computed directly on a user-uploaded file.
===============================================================================
"""

from __future__ import annotations

from html import escape
from typing import List, Optional, Tuple

import streamlit as st

# ---------------------------------------------------------------------------
# Severity / threat-level constants shared across the dashboard UI
# ---------------------------------------------------------------------------

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low", "None"]

SEVERITY_ICON = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "None": "⚪",
    "Unknown": "⚪",
}

# Threat-level bands derived from real attack_rate values. Labels match the
# SOC convention used across the UI: MINIMAL / LOW / MEDIUM / HIGH / CRITICAL.
THREAT_LEVEL_ICON = {
    "MINIMAL": "🟢",
    "LOW": "🟡",
    "MEDIUM": "🟠",
    "HIGH": "🟠",
    "CRITICAL": "🔴",
    "UNKNOWN": "⚪",
}


def classify_threat_level(attack_rate, attack_count=None) -> Tuple[str, str]:
    """Map real attack-rate/attack-count values to a SOC threat level.

    Returns (level, description). When no data is available the level is
    UNKNOWN and the description explains availability — never fabricates values.
    """
    if attack_rate is None and attack_count is None:
        return "UNKNOWN", "Threat level could not be determined from available data."

    if attack_count == 0 or (attack_rate is not None and attack_rate == 0):
        return "MINIMAL", "No malicious traffic detected in the analyzed session."

    if attack_rate is None:
        return "LOW", f"{attack_count} anomalous flow(s) flagged (rate unavailable)."

    if attack_rate < 5:
        return "MINIMAL", f"{attack_count} anomalous flow(s) detected ({attack_rate:.1f}% of traffic)."
    if attack_rate < 15:
        return "LOW", f"{attack_count} anomalous flow(s) detected ({attack_rate:.1f}% of traffic)."
    if attack_rate < 35:
        return "MEDIUM", f"{attack_count} anomalous flow(s) detected ({attack_rate:.1f}% of traffic)."
    if attack_rate < 60:
        return "HIGH", f"{attack_count} anomalous flow(s) detected ({attack_rate:.1f}% of traffic)."
    return "CRITICAL", f"{attack_count} anomalous flow(s) detected ({attack_rate:.1f}% of traffic)."


def esc(value) -> str:
    """Safe HTML-escape for embedding user/backend values into UI markup."""
    return escape(str(value), quote=True)


# ---------------------------------------------------------------------------
# Command-center global status header
# ---------------------------------------------------------------------------

def render_global_status_header(
    api_online: bool,
    ml_ready: Optional[bool] = None,
    rag_ready: Optional[bool] = None,
    last_sync: Optional[str] = None,
    active_dataset: str = "CICIDS-2017",
    threat_level: str = "UNKNOWN",
) -> None:
    """Render the persistent SOC command-center header bar.

    All indicator values must be real; None flips the corresponding chip to a
    neutral "unavailable" state.
    """
    api_status, api_cls = ("ONLINE", "online") if api_online else ("OFFLINE", "offline")
    api_symbol = "●" if api_online else "○"

    def _ready_chip(label: str, flag: Optional[bool]) -> str:
        if flag is None:
            kind, text = "neutral", f"{label} — UNAVAILABLE"
        elif flag:
            kind, text = "online", f"{label} READY"
        else:
            kind, text = "offline", f"{label} OFFLINE"
        return f'<span class="hc-pill hc-pill-{kind}">{text}</span>'

    threat_cls = {
        "MINIMAL": "thr-minimal",
        "LOW": "thr-low",
        "MEDIUM": "thr-medium",
        "HIGH": "thr-high",
        "CRITICAL": "thr-critical",
        "UNKNOWN": "thr-unknown",
    }.get(threat_level, "thr-unknown")

    st.markdown(
        f"""
        <div class="cmd-header" role="banner" aria-label="NetGuard AI command center status">
            <div class="cmd-brand">
                <span class="cmd-logo" aria-hidden="true">🛡️</span>
                <span class="cmd-brand-text">
                    <span class="cmd-title">NETGUARD AI</span>
                    <span class="cmd-sub">SOC COMMAND CENTER</span>
                </span>
            </div>
            <div class="cmd-chips" role="status" aria-live="polite">
                <span class="hc-pill hc-pill-{api_cls}">{api_symbol} API {api_status}</span>
                {_ready_chip("ML", ml_ready)}
                {_ready_chip("RAG", rag_ready)}
                <span class="hc-pill hc-pill-neutral">DATASET · {esc(active_dataset)}</span>
            </div>
            <div class="cmd-meta">
                <span class="thr-chip {threat_cls}">
                    {THREAT_LEVEL_ICON.get(threat_level, THREAT_LEVEL_ICON["UNKNOWN"])} THREAT LEVEL {threat_level}
                </span>
                <span class="hc-pill hc-pill-neutral">
                    📡 LAST SYNC {esc(last_sync or "N/A")}
                </span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Action CTA row
# ---------------------------------------------------------------------------

def render_cta_row(
    cta_targets: List[Tuple[str, str, str, Optional[str]]],
) -> None:
    """Render a row of CTAs.

    Each item is (label, emoji, page_name, key). The first CTA renders as the
    primary action; the rest are secondary. Clicking navigates via session
    state only — no backend involvement.
    """
    if not cta_targets:
        return
    cols = st.columns(len(cta_targets))
    for idx, (col, (label, emoji, page_name, key)) in enumerate(zip(cols, cta_targets)):
        with col:
            btn_type = "primary" if idx == 0 else "secondary"
            if st.button(
                f"{emoji} {label}",
                use_container_width=True,
                type=btn_type,
                key=key or _auto_key(label),
            ):
                st.session_state.nav_page = page_name
                st.rerun()


def _auto_key(label: str) -> str:
    return "cta_" + "".join(c for c in label.lower() if c.isalnum() or c == "_")


# ---------------------------------------------------------------------------
# State banners (loading / success / error / empty / unavailable)
# ---------------------------------------------------------------------------

def state_banner(kind: str, message: str, detail: str = "") -> None:
    """Render a polished status banner.

    kind: "loading" | "success" | "error" | "warning" | "empty" | "unavailable"
    """
    mapping = {
        "loading": ("⏳", "hstate hstate-loading"),
        "success": ("✅", "hstate hstate-success"),
        "error": ("⚠️", "hstate hstate-error"),
        "warning": ("⚠️", "hstate hstate-warning"),
        "empty": ("📭", "hstate hstate-empty"),
        "unavailable": ("○", "hstate hstate-unavailable"),
    }
    icon, cls = mapping.get(kind, mapping["empty"])
    detail_html = f'<div class="hstate-detail">{esc(detail)}</div>' if detail else ""
    st.markdown(
        f"""
        <div class="{cls}" role="status" aria-label="{esc(kind)}">
            <span class="hstate-icon" aria-hidden="true">{icon}</span>
            <div>
                <div class="hstate-title">{esc(message)}</div>
                {detail_html}
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


# ---------------------------------------------------------------------------
# Severity distribution strip
# ---------------------------------------------------------------------------

def render_severity_strip(distribution: dict, total: int = 0) -> None:
    """Render a severity-distribution KPI strip.

    distribution maps severity -> count. Only real counts are shown; any
    severity with no data is rendered as an empty cell with a dash.
    """
    if not distribution:
        st.markdown(
            '<div class="glass-panel" style="font-family:var(--font-mono); '
            'font-size:12px; color:var(--muted); text-align:center; padding:14px;">'
            "No severity distribution available for this session.</div>",
            unsafe_allow_html=True,
        )
        return

    n = len(distribution) + 1
    cols = st.columns(n)
    with cols[0]:
        st.markdown(
            f"""
            <div class="metric-card">
                <div class="metric-icon-badge">🚨</div>
                <div class="metric-label">Total Threats</div>
                <div class="metric-value metric-danger">{total:,}</div>
            </div>
            """,
            unsafe_allow_html=True,
        )
    for i, (sev, count) in enumerate(distribution.items(), start=1):
        icon = SEVERITY_ICON.get(sev, SEVERITY_ICON["None"])
        with cols[i]:
            st.markdown(
                f"""
                <div class="metric-card">
                    <div class="metric-icon-badge">{icon}</div>
                    <div class="metric-label">{esc(sev)} Threats</div>
                    <div class="metric-value">{count:,}</div>
                </div>
                """,
                unsafe_allow_html=True,
            )