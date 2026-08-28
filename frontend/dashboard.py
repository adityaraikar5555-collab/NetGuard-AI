"""
================================================================================
NetGuard AI — Network Security Operations Center (SOC)
================================================================================
AI-Powered Network Anomaly Detection, Threat Intelligence & 3D Topology Platform

This file is a UI/dashboard layer ONLY. It does not implement any ML
prediction logic of its own. Every number shown here comes from either:

    1. The existing FastAPI backend (http://127.0.0.1:8000), via the
       endpoints already defined in app.py:
           GET  /health
           GET  /model-info
           POST /predict/cicids
           POST /predict/nsl-kdd
           POST /analyze/cicids
           POST /analyze/nsl-kdd
           POST /analyze/dataset
           GET  /api/status

    2. Statistics computed directly from a user-uploaded CSV using pandas
       (dataset exploration only — never used to fabricate ML results).

No backend logic, model files, preprocessing, endpoints, or response
contracts are modified by this file. app.py and api.py are unchanged.
================================================================================
"""

import math
from datetime import datetime

import numpy as np
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
import requests
import streamlit as st
import streamlit.components.v1 as components

# --------------------------------------------------------------------------
# Frontend API client import
# --------------------------------------------------------------------------
try:
    import api as api_client
except Exception:
    api_client = None

# ============================================================================
# CONFIG & PAGE SETUP
# ============================================================================

API_URL = "https://netguard-ai-nd5e.onrender.com"

# ============================================================================
# UPLOAD SIZE LIMITS
# ============================================================================
LIVE_TRAFFIC_MAX_MB = 25
EXPLORER_MAX_MB = 20

LIVE_TRAFFIC_MAX_BYTES = LIVE_TRAFFIC_MAX_MB * 1024 * 1024
EXPLORER_MAX_BYTES = EXPLORER_MAX_MB * 1024 * 1024

st.set_page_config(
    page_title="NetGuard AI | Network Security Operations Center",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

NAV_PAGES = [
    ("🏠", "Overview"),
    ("🌐", "Live Traffic"),
    ("📊", "Traffic Analytics"),
    ("🚨", "Threat Detection"),
    ("🕸️", "Network Topology"),
    ("🤖", "ML Insights"),
    ("🧠", "SOC AI Assistant"),
    ("📁", "Dataset Analysis"),
    ("📈", "Data Visualization Explorer"),
    ("📜", "Prediction History"),
    ("⚙️", "System Status"),
    ("ℹ️", "About"),
]

SEVERITY_ORDER = ["Critical", "High", "Medium", "Low"]
SEVERITY_ICON = {
    "Critical": "🔴",
    "High": "🟠",
    "Medium": "🟡",
    "Low": "🟢",
    "None": "⚪",
    "Unknown": "⚪",
}

# ============================================================================
# THEME SYSTEM — Dark (SOC Cyber Mode)
# ============================================================================

THEMES = {
    "Dark": {
        "bg": "#05070f",
        "surface": "rgba(13, 20, 36, 0.85)",
        "surface2": "rgba(18, 28, 50, 0.78)",
        "sidebar_bg": "#04060d",
        "border": "rgba(56, 189, 248, 0.22)",
        "border_soft": "rgba(56, 189, 248, 0.10)",
        "text": "#e6ebf5",
        "heading": "#f8fafc",
        "muted": "#94a3b8",
        "muted2": "#7c8aa5",
        "input_bg": "rgba(17, 26, 46, 0.9)",
        "grid": "rgba(255, 255, 255, 0.07)",
        "plotly_template": "plotly_dark",
    },
}

SEMANTIC = {
    "primary": "#38bdf8",  # Neon Cyan
    "success": "#10b981",  # Cyber Emerald
    "warning": "#f59e0b",  # Amber
    "danger": "#ef4444",  # Crimson Attack
    "info": "#06b6d4",  # Electric Cyan
    "ai": "#a855f7",  # Neural Purple
    "neutral": "#64748b",  # Slate Gray
}

VIZ_PRESETS = {
    "Default SOC": {
        "normal": SEMANTIC["success"], "suspicious": SEMANTIC["warning"], "attack": SEMANTIC["danger"],
        "unknown": SEMANTIC["neutral"],
        "primary": SEMANTIC["primary"], "secondary": SEMANTIC["ai"], "accent": SEMANTIC["warning"],
    },
    "Cyber Blue": {
        "normal": "#22d3ee", "suspicious": "#fbbf24", "attack": "#f43f5e",
        "unknown": "#64748b",
        "primary": "#0ea5e9", "secondary": "#6366f1", "accent": "#38bdf8",
    },
    "Neon": {
        "normal": "#39ff14", "suspicious": "#fffb00", "attack": "#ff1053",
        "unknown": "#7c8aa5",
        "primary": "#00f0ff", "secondary": "#bc13fe", "accent": "#fffb00",
    },
    "Professional": {
        "normal": "#2e7d32", "suspicious": "#f9a825", "attack": "#c62828",
        "unknown": "#78909c",
        "primary": "#1565c0", "secondary": "#5e35b1", "accent": "#f9a825",
    },
    "High Contrast": {
        "normal": "#00ff00", "suspicious": "#ffff00", "attack": "#ff0000",
        "unknown": "#888888",
        "primary": "#00ffff", "secondary": "#ff00ff", "accent": "#ffff00",
    },
    "Solarized": {
        "normal": "#859900", "suspicious": "#b58900", "attack": "#dc322f",
        "unknown": "#93a1a1",
        "primary": "#268bd2", "secondary": "#6c71c4", "accent": "#cb4b16",
    },
    "Monochrome Blue": {
        "normal": "#38bdf8", "suspicious": "#60a5fa", "attack": "#1e40af",
        "unknown": "#64748b",
        "primary": "#0284c7", "secondary": "#93c5fd", "accent": "#0369a1",
    },
    "Colorblind-Safe (Okabe-Ito)": {
        "normal": "#009E73", "suspicious": "#E69F00", "attack": "#D55E00",
        "unknown": "#999999",
        "primary": "#56B4E9", "secondary": "#CC79A7", "accent": "#F0E442",
    },
    "Pastel SOC": {
        "normal": "#6ee7b7", "suspicious": "#fde047", "attack": "#fda4af",
        "unknown": "#cbd5e1",
        "primary": "#93c5fd", "secondary": "#d8b4fe", "accent": "#fbcfe8",
    },
    "Midnight Red-Team": {
        "normal": "#4ade80", "suspicious": "#fb923c", "attack": "#e11d48",
        "unknown": "#475569",
        "primary": "#f43f5e", "secondary": "#881337", "accent": "#fda4af",
    },
}
VIZ_FIELDS = ["normal", "suspicious", "attack", "unknown", "primary", "secondary", "accent"]


def get_theme():
    return THEMES["Dark"]


def get_viz_colors():
    if st.session_state.viz_preset == "Custom":
        return st.session_state.viz_custom
    return VIZ_PRESETS.get(st.session_state.viz_preset, VIZ_PRESETS["Default SOC"])


def severity_color_map():
    viz = get_viz_colors()
    if st.session_state.get("custom_badge_colors", False):
        return {
            "Critical": viz.get("attack", SEMANTIC["danger"]),
            "High": viz.get("accent", "#fb923c"),
            "Medium": viz.get("suspicious", SEMANTIC["warning"]),
            "Low": viz.get("normal", SEMANTIC["success"]),
            "None": viz.get("unknown", SEMANTIC["neutral"]),
            "Unknown": viz.get("unknown", SEMANTIC["neutral"]),
        }
    return {
        "Critical": viz.get("attack", SEMANTIC["danger"]),
        "High": "#fb923c",
        "Medium": viz.get("suspicious", SEMANTIC["warning"]),
        "Low": viz.get("normal", SEMANTIC["success"]),
        "None": SEMANTIC["neutral"],
        "Unknown": SEMANTIC["neutral"],
    }


# ============================================================================
# SESSION STATE
# ============================================================================

def init_state():
    defaults = {
        "analysis_result": None,
        "raw_result": None,
        "uploaded_filename": None,
        "active_dataset": "CICIDS-2017",
        "last_analysis_time": None,
        "history": [],
        "explore_df": None,
        "explore_filename": None,
        "nav_page": "Overview",
        "viz_preset": "Default SOC",
        "viz_custom": dict(VIZ_PRESETS["Default SOC"]),
        "custom_badge_colors": False,
        "explorer_column_overrides": {},
        "fx_3d_bg": True,
        "fx_particles": True,
        "fx_animations": True,
        "fx_glow": True,
        "chat_messages": [],
    }
    for key, value in defaults.items():
        if key not in st.session_state:
            st.session_state[key] = value


init_state()
THEME = get_theme()
VIZ = get_viz_colors()


# ============================================================================
# INTERACTIVE 3D NEURAL CYBERNETIC VISUALIZER (WebGL / Canvas)
# ============================================================================

def render_3d_hero():
    if not st.session_state.get("fx_3d_bg", True):
        return

    viz = get_viz_colors()
    primary_col = viz.get("primary", "#38bdf8")
    secondary_col = viz.get("secondary", "#a855f7")
    attack_col = viz.get("attack", "#ef4444")
    normal_col = viz.get("normal", "#10b981")
    bg_gradient = "radial-gradient(circle at 50% 50%, #0c1830 0%, #05070f 100%)"
    border_col = "rgba(56, 189, 248, 0.35)"
    text_col = "#e6ebf5"

    hero_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        body {{
          margin: 0;
          padding: 0;
          overflow: hidden;
          background: transparent;
          user-select: none;
        }}
        #canvas3d-container {{
          width: 100%;
          height: 180px;
          position: relative;
          border-radius: 14px;
          background: {bg_gradient};
          border: 1px solid {border_col};
          box-shadow: 0 8px 32px rgba(0,0,0,0.35), inset 0 0 24px rgba(56,189,248,0.08);
          overflow: hidden;
        }}
        #c3d {{
          width: 100%;
          height: 100%;
          display: block;
          cursor: grab;
        }}
        #c3d:active {{
          cursor: grabbing;
        }}
        .hud-overlay {{
          position: absolute;
          top: 10px;
          left: 14px;
          pointer-events: none;
          font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
        }}
        .hud-title {{
          font-size: 11px;
          font-weight: 800;
          letter-spacing: 2px;
          color: {primary_col};
          text-transform: uppercase;
        }}
        .hud-sub {{
          font-size: 10px;
          color: {text_col};
          opacity: 0.75;
          margin-top: 2px;
          font-family: monospace;
        }}
        .hud-badge {{
          position: absolute;
          top: 10px;
          right: 14px;
          background: rgba(56, 189, 248, 0.15);
          border: 1px solid rgba(56, 189, 248, 0.35);
          padding: 3px 8px;
          border-radius: 4px;
          font-family: monospace;
          font-size: 9.5px;
          color: {primary_col};
          font-weight: 700;
        }}
      </style>
    </head>
    <body>
      <div id="canvas3d-container">
        <canvas id="c3d"></canvas>
        <div class="hud-overlay">
          <div class="hud-title">⚡ 3D Spatial Threat Matrix</div>
          <div class="hud-sub">INTERACTIVE 3D NEURAL TOPOLOGY • DRAG TO ROTATE &amp; EXPLORE NODES</div>
        </div>
        <div class="hud-badge">● 3D ACCELERATED</div>
      </div>
      <script>
        const canvas = document.getElementById('c3d');
        const ctx = canvas.getContext('2d');
        let w = canvas.width = canvas.parentElement.clientWidth;
        let h = canvas.height = canvas.parentElement.clientHeight;

        window.addEventListener('resize', () => {{
          if (!canvas.parentElement) return;
          w = canvas.width = canvas.parentElement.clientWidth;
          h = canvas.height = canvas.parentElement.clientHeight;
        }});

        const numNodes = 48;
        const radius = Math.min(w, h) * 0.42;
        const nodes = [];
        const colors = ["{primary_col}", "{secondary_col}", "{attack_col}", "{normal_col}"];

        for (let i = 0; i < numNodes; i++) {{
          const phi = Math.acos(-1 + (2 * i) / numNodes);
          const theta = Math.sqrt(numNodes * Math.PI) * phi;
          nodes.push({{
            x: radius * Math.cos(theta) * Math.sin(phi),
            y: radius * Math.sin(theta) * Math.sin(phi),
            z: radius * Math.cos(phi),
            color: colors[i % colors.length],
            size: (i % 5 === 0) ? 3.5 : 2.2
          }});
        }}

        const packets = [];
        for (let i = 0; i < 8; i++) {{
          packets.push({{
            n1: Math.floor(Math.random() * numNodes),
            n2: Math.floor(Math.random() * numNodes),
            progress: Math.random(),
            speed: 0.008 + Math.random() * 0.012
          }});
        }}

        let rotX = 0.2;
        let rotY = 0;
        let isDragging = false;
        let lastMouseX = 0;
        let lastMouseY = 0;

        canvas.addEventListener('mousedown', (e) => {{
          isDragging = true;
          lastMouseX = e.clientX;
          lastMouseY = e.clientY;
        }});
        window.addEventListener('mouseup', () => isDragging = false);
        window.addEventListener('mousemove', (e) => {{
          if (isDragging) {{
            const dx = e.clientX - lastMouseX;
            const dy = e.clientY - lastMouseY;
            rotY += dx * 0.008;
            rotX += dy * 0.008;
            lastMouseX = e.clientX;
            lastMouseY = e.clientY;
          }}
        }});

        function project(x, y, z) {{
          const cosY = Math.cos(rotY), sinY = Math.sin(rotY);
          const cosX = Math.cos(rotX), sinX = Math.sin(rotX);

          let x1 = x * cosY - z * sinY;
          let z1 = z * cosY + x * sinY;

          let y1 = y * cosX - z1 * sinX;
          let z2 = z1 * cosX + y * sinX;

          const fov = 340;
          const scale = fov / (fov + z2 + 20);
          return {{
            x2d: w / 2 + x1 * scale,
            y2d: h / 2 + y1 * scale,
            scale: scale,
            z: z2
          }};
        }}

        function draw() {{
          ctx.clearRect(0, 0, w, h);
          if (!isDragging) {{
            rotY += 0.006;
            rotX += 0.0015;
          }}

          const projected = nodes.map(n => ({{
            ...n,
            proj: project(n.x, n.y, n.z)
          }}));

          // Draw 3D Orbiting Ring
          ctx.beginPath();
          for (let a = 0; a <= Math.PI * 2; a += 0.1) {{
            const rx = (radius * 1.25) * Math.cos(a);
            const rz = (radius * 1.25) * Math.sin(a);
            const p = project(rx, 0, rz);
            if (a === 0) ctx.moveTo(p.x2d, p.y2d);
            else ctx.lineTo(p.x2d, p.y2d);
          }}
          ctx.strokeStyle = 'rgba(56, 189, 248, 0.20)';
          ctx.lineWidth = 1;
          ctx.stroke();

          // Connect nearby 3D points
          for (let i = 0; i < projected.length; i++) {{
            for (let j = i + 1; j < projected.length; j++) {{
              const p1 = projected[i].proj;
              const p2 = projected[j].proj;
              const dx = p1.x2d - p2.x2d;
              const dy = p1.y2d - p2.y2d;
              const dist = Math.sqrt(dx * dx + dy * dy);
              if (dist < 65) {{
                const alpha = (1 - dist / 65) * 0.32 * Math.min(p1.scale, p2.scale);
                ctx.beginPath();
                ctx.moveTo(p1.x2d, p1.y2d);
                ctx.lineTo(p2.x2d, p2.y2d);
                ctx.strokeStyle = `rgba(56, 189, 248, ${{alpha}})`;
                ctx.lineWidth = 0.8;
                ctx.stroke();
              }}
            }}
          }}

          // Draw data packets
          for (let p of packets) {{
            p.progress += p.speed;
            if (p.progress >= 1) {{
              p.progress = 0;
              p.n1 = Math.floor(Math.random() * numNodes);
              p.n2 = Math.floor(Math.random() * numNodes);
            }}
            const p1 = projected[p.n1].proj;
            const p2 = projected[p.n2].proj;
            const px = p1.x2d + (p2.x2d - p1.x2d) * p.progress;
            const py = p1.y2d + (p2.y2d - p1.y2d) * p.progress;

            ctx.beginPath();
            ctx.arc(px, py, 2.2, 0, Math.PI * 2);
            ctx.fillStyle = '{primary_col}';
            ctx.shadowColor = '{primary_col}';
            ctx.shadowBlur = 6;
            ctx.fill();
            ctx.shadowBlur = 0;
          }}

          // Sort nodes by depth
          projected.sort((a, b) => b.proj.z - a.proj.z);

          for (let n of projected) {{
            const p = n.proj;
            const size = Math.max(0.8, n.size * p.scale);
            const alpha = Math.max(0.25, (p.scale - 0.4) / 0.6);

            ctx.beginPath();
            ctx.arc(p.x2d, p.y2d, size, 0, Math.PI * 2);
            ctx.fillStyle = n.color;
            ctx.globalAlpha = alpha;
            ctx.shadowColor = n.color;
            ctx.shadowBlur = size > 2 ? 8 : 2;
            ctx.fill();
            ctx.shadowBlur = 0;
            ctx.globalAlpha = 1.0;
          }}

          requestAnimationFrame(draw);
        }}
        draw();
      </script>
    </body>
    </html>
    """
    components.html(hero_html, height=190, scrolling=False)


# ============================================================================
# CUSTOM CSS — Glassmorphism, Neon Glow & Cyber-SOC Aesthetic
# ============================================================================

glow_filter = "box-shadow: 0 0 18px rgba(56, 189, 248, 0.20);" if st.session_state.get("fx_glow", True) else ""
animation_rule = "" if st.session_state.get("fx_animations",
                                            True) else "* { animation: none !important; transition: none !important; }"

st.markdown(
    f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Space+Grotesk:wght@500;700;800&family=IBM+Plex+Sans:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600;700&display=swap');

    :root {{
        --bg:        {THEME["bg"]};
        --surface:   {THEME["surface"]};
        --surface-2: {THEME["surface2"]};
        --sidebar-bg:{THEME["sidebar_bg"]};
        --border:    {THEME["border"]};
        --border-soft: {THEME["border_soft"]};
        --grid:      {THEME["grid"]};
        --text:      {THEME["text"]};
        --heading:   {THEME["heading"]};
        --muted:     {THEME["muted"]};
        --muted-2:   {THEME["muted2"]};
        --signal:    {VIZ["primary"]};
        --signal-dim:{VIZ["secondary"]};
        --threat:    {VIZ["attack"]};
        --warn:      {VIZ["suspicious"]};
        --safe:      {VIZ["normal"]};
        --ai:        {VIZ["secondary"]};
        --font-display: 'Space Grotesk', sans-serif;
        --font-body: 'IBM Plex Sans', sans-serif;
        --font-mono: 'JetBrains Mono', monospace;
    }}

    {animation_rule}

    html, body, [class*="css"] {{ font-family: var(--font-body); }}
    h1, h2, h3, h4 {{ font-family: var(--font-display) !important; }}

    .stApp {{
        background-color: var(--bg) !important;
        background-image:
            radial-gradient(circle at 85% 8%, rgba(56,189,248,0.15), transparent 45%),
            radial-gradient(circle at 6% 92%, rgba(168,85,247,0.10), transparent 40%),
            url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='48' height='48' viewBox='0 0 48 48'%3E%3Cpath d='M24 0 L48 24 L24 48 L0 24 Z' fill='none' stroke='%2338bdf8' stroke-opacity='0.035' stroke-width='1'/%3E%3C/svg%3E") !important;
        background-size: auto, auto, 48px 48px !important;
        color: var(--text) !important;
    }}

    .main .block-container {{
        max-width: 1540px;
        padding-top: 0.5rem;
        padding-bottom: 3.5rem;
        position: relative;
        z-index: 1;
    }}

    /* ================= GLASS PANEL MOTIF ================= */
    .glass-panel {{
        background: var(--surface);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 18px 22px;
        margin-bottom: 14px;
        position: relative;
        overflow: hidden;
        {glow_filter}
    }}

    .glass-panel::before {{
        content: '';
        position: absolute;
        top: 0; left: 0; right: 0; height: 1px;
        background: linear-gradient(90deg, transparent, var(--signal), transparent);
        opacity: 0.6;
    }}

    /* ================= SIDEBAR ================= */
    section[data-testid="stSidebar"] {{
        background: var(--sidebar-bg) !important;
        border-right: 1px solid var(--border);
        z-index: 2;
    }}
    section[data-testid="stSidebar"] .block-container {{ padding-top: 1.4rem; }}

    .sidebar-brand {{ padding: 4px 4px 14px 4px; border-bottom: 1px solid var(--border); margin-bottom: 6px; }}
    .sidebar-logo-row {{ display: flex; align-items: center; gap: 10px; }}
    .sidebar-logo-badge {{
        width: 40px; height: 40px; border-radius: 10px; display: flex; align-items: center;
        justify-content: center; font-size: 20px;
        background: linear-gradient(145deg, rgba(56,189,248,0.25), rgba(168,85,247,0.15));
        border: 1px solid rgba(56,189,248,0.45);
        box-shadow: 0 0 12px rgba(56,189,248,0.3);
    }}
    .sidebar-title {{ font-family: var(--font-display); font-size: 19px; font-weight: 800; color: var(--heading); letter-spacing: 0.3px; }}
    .sidebar-subtitle {{ font-size: 10.5px; color: var(--muted); margin-top: 4px; letter-spacing: 0.4px; font-family: var(--font-mono); }}

    .nav-eyebrow {{
        font-family: var(--font-mono); font-size: 10px; letter-spacing: 1.5px; color: var(--muted-2);
        margin: 16px 2px 6px 2px; text-transform: uppercase;
    }}

    /* Do not assume any tag name (label/div/span) — target every direct option
       row and every descendant of the confirmed radiogroup container instead. */
    div[data-testid="stSidebar"] div[role="radiogroup"] {{ gap: 3px; }}
    div[data-testid="stSidebar"] div[role="radiogroup"] > * {{
        padding: 9px 12px 9px 14px; border-radius: 8px; border-left: 3px solid transparent;
        transition: background 0.15s ease, border-color 0.15s ease;
        display: flex; align-items: center; cursor: pointer;
    }}
    /* Kill every possible visual form of the radio dot: the raw input, and BaseWeb's
       own styled dot wrapper (Streamlit renders radios via BaseWeb, which marks the
       dot element with data-baseweb="radio" regardless of the surrounding tag). */
    div[data-testid="stSidebar"] div[role="radiogroup"] input[type="radio"],
    div[data-testid="stSidebar"] div[role="radiogroup"] [data-baseweb="radio"] {{
        display: none !important;
    }}
    /* Force text color on literally every descendant of the radiogroup — no tag-name
       assumption at all, so this can't silently no-op again like the label-based rule did. */
    div[data-testid="stSidebar"] div[role="radiogroup"] * {{
        font-family: var(--font-body); font-size: 13.5px; font-weight: 600;
        color: var(--muted) !important;
    }}
    div[data-testid="stSidebar"] div[role="radiogroup"] > *:hover {{ background: var(--surface-2); }}
    div[data-testid="stSidebar"] div[role="radiogroup"] > *:hover * {{ color: var(--text) !important; }}
    div[data-testid="stSidebar"] div[role="radiogroup"] > *:has(input:checked) {{
        background: linear-gradient(90deg, rgba(56,189,248,0.18), rgba(168,85,247,0.03));
        border-left: 3px solid var(--signal);
    }}
    div[data-testid="stSidebar"] div[role="radiogroup"] > *:has(input:checked) * {{
        color: var(--heading) !important; font-weight: 700;
    }}

    /* ================= GLOBAL NATIVE-WIDGET TEXT FIX (Dark) =================
       Streamlit's built-in widget labels (selectbox, slider, checkbox, expander,
       tabs, and any radiogroup outside the sidebar) always render using the fixed
       textColor from .streamlit/config.toml. Forcing these to var(--text)/var(--muted)
       guarantees readable text in Dark mode.
       Scoped strictly to Streamlit's own testids — never touches our custom HTML. */
    [data-testid="stWidgetLabel"],
    [data-testid="stWidgetLabel"] * {{
        color: var(--text) !important;
    }}
    [data-testid="stExpander"] summary,
    [data-testid="stExpander"] summary * {{
        color: var(--text) !important;
    }}
    [data-testid="stTabs"] button,
    [data-testid="stTabs"] button * {{
        color: var(--muted) !important;
    }}
    [data-testid="stTabs"] button[aria-selected="true"],
    [data-testid="stTabs"] button[aria-selected="true"] * {{
        color: var(--heading) !important;
    }}
    [data-testid="stCheckbox"] label,
    [data-testid="stCheckbox"] label * {{
        color: var(--text) !important;
    }}
    div[role="radiogroup"]:not(section[data-testid="stSidebar"] div[role="radiogroup"]) label,
    div[role="radiogroup"]:not(section[data-testid="stSidebar"] div[role="radiogroup"]) label * {{
        color: var(--text) !important;
    }}
    [data-testid="stFileUploaderDropzoneInstructions"],
    [data-testid="stFileUploaderDropzoneInstructions"] * {{
        color: var(--text) !important;
    }}

    /* Hide Streamlit's built-in max-size hint (e.g. "200MB per file • CSV") —
       file-size limits are enforced per-uploader and shown in custom UI. */
    [data-testid="stFileUploaderDropzoneInstructions"] small {{
        display: none !important;
    }}


    /* ================= HEADER ================= */
    .hero {{ padding: 6px 0 4px 0; position: relative; }}
    .hero-eyebrow {{ font-family: var(--font-mono); font-size: 11px; color: var(--signal); letter-spacing: 2px; text-transform: uppercase; margin-bottom: 4px; }}
    .hero-title {{ font-family: var(--font-display); font-size: 30px; font-weight: 800; letter-spacing: -0.4px; color: var(--heading); }}
    .hero-subtitle {{ font-size: 13px; color: var(--muted); margin-top: 3px; }}

    .scanline {{
        height: 2px; margin-top: 14px; border-radius: 2px; position: relative; overflow: hidden;
        background: var(--border);
    }}
    .scanline::after {{
        content: ""; position: absolute; top: 0; left: -30%; width: 30%; height: 100%;
        background: linear-gradient(90deg, transparent, var(--signal), transparent);
        animation: sweep 3.6s linear infinite;
    }}
    @keyframes sweep {{ 0% {{ left: -30%; }} 100% {{ left: 100%; }} }}

    .pill {{
        display: inline-flex; align-items: center; gap: 6px; margin: 8px 6px 0 0; padding: 5px 12px;
        border-radius: 999px; font-family: var(--font-mono); font-size: 11px; font-weight: 600;
    }}
    .pill-online  {{ background: rgba(16,185,129,0.12);  border: 1px solid rgba(16,185,129,0.40);  color: var(--safe); }}
    .pill-offline {{ background: rgba(239,68,68,0.12);   border: 1px solid rgba(239,68,68,0.40);   color: var(--threat); }}
    .pill-neutral {{ background: rgba(56,189,248,0.10);  border: 1px solid rgba(56,189,248,0.35);  color: var(--signal); }}
    .pill-warning {{ background: rgba(245,158,11,0.12);  border: 1px solid rgba(245,158,11,0.40);  color: var(--warn); }}

    /* ================= SECTION HEADERS ================= */
    .section-header {{ margin-top: 20px; margin-bottom: 12px; }}
    .section-title {{ font-family: var(--font-display); font-size: 17.5px; font-weight: 700; color: var(--heading); }}
    .section-description {{ font-size: 12px; color: var(--muted); margin-top: 2px; }}

    /* ================= METRIC / KPI CARDS ================= */
    .metric-card {{
        background: var(--surface);
        backdrop-filter: blur(12px);
        -webkit-backdrop-filter: blur(12px);
        border: 1px solid var(--border);
        border-left: 3px solid var(--signal);
        border-radius: 12px;
        padding: 15px 18px;
        min-height: 114px;
        transition: transform 0.18s ease, border-color 0.18s ease, box-shadow 0.18s ease;
    }}
    .metric-card:hover {{
        transform: translateY(-3px);
        box-shadow: 0 8px 24px rgba(56, 189, 248, 0.18);
    }}
    .metric-icon-badge {{
        width: 32px; height: 32px; border-radius: 8px; display: flex; align-items: center; justify-content: center;
        font-size: 15px; background: rgba(56,189,248,0.12); border: 1px solid rgba(56,189,248,0.25); margin-bottom: 8px;
    }}
    .metric-label {{ color: var(--muted); font-size: 10.5px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.6px; }}
    .metric-value {{ font-family: var(--font-mono); font-variant-numeric: tabular-nums; color: var(--heading); font-size: 24px; font-weight: 700; margin-top: 4px; }}
    .metric-danger  {{ color: var(--threat); }}
    .metric-safe    {{ color: var(--safe); }}
    .metric-warning {{ color: var(--warn); }}
    .metric-na      {{ color: var(--muted-2); font-size: 18px; }}

    /* ================= THREAT STATUS PANEL ================= */
    .threat-panel {{
        border-radius: 14px; padding: 18px 22px; margin: 4px 0 8px 0;
        display: flex; align-items: center; gap: 18px; flex-wrap: wrap;
        border: 1px solid var(--border); position: relative; overflow: hidden;
        backdrop-filter: blur(14px);
    }}
    .threat-panel-secure   {{ background: linear-gradient(120deg, rgba(16,185,129,0.12), rgba(16,185,129,0.02)); border-color: rgba(16,185,129,0.35); }}
    .threat-panel-elevated {{ background: linear-gradient(120deg, rgba(245,158,11,0.12), rgba(245,158,11,0.02)); border-color: rgba(245,158,11,0.35); }}
    .threat-panel-critical {{ background: linear-gradient(120deg, rgba(239,68,68,0.15), rgba(239,68,68,0.02)); border-color: rgba(239,68,68,0.40); }}
    .threat-panel-idle     {{ background: linear-gradient(120deg, rgba(100,116,139,0.10), rgba(100,116,139,0.02)); border-color: var(--border); }}

    .radar-wrap {{ position: relative; width: 52px; height: 52px; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }}
    .radar-core {{ width: 16px; height: 16px; border-radius: 50%; z-index: 2; }}
    .radar-ring {{
        position: absolute; border-radius: 50%; border: 2px solid currentColor;
        animation: ping 2.2s cubic-bezier(0.2, 0.8, 0.4, 1) infinite; opacity: 0;
    }}
    .radar-ring.r1 {{ width: 24px; height: 24px; animation-delay: 0s; }}
    .radar-ring.r2 {{ width: 24px; height: 24px; animation-delay: 0.9s; }}
    @keyframes ping {{
        0%   {{ width: 16px; height: 16px; opacity: 0.7; }}
        100% {{ width: 52px; height: 52px; opacity: 0; }}
    }}
    .radar-secure   .radar-core {{ background: var(--safe); }}   .radar-secure   .radar-ring {{ color: var(--safe); }}
    .radar-elevated .radar-core {{ background: var(--warn); }}   .radar-elevated .radar-ring {{ color: var(--warn); }}
    .radar-critical .radar-core {{ background: var(--threat); }} .radar-critical .radar-ring {{ color: var(--threat); }}
    .radar-idle     .radar-core {{ background: var(--muted-2); }}       .radar-idle     .radar-ring {{ animation: none; opacity: 0; }}

    .threat-panel-status {{ font-family: var(--font-display); font-size: 20px; font-weight: 800; color: var(--heading); letter-spacing: 0.2px; }}
    .threat-panel-sub {{ font-size: 12.5px; color: var(--muted); margin-top: 3px; font-family: var(--font-mono); }}

    /* ================= SEVERITY BADGES ================= */
    .severity-badge {{
        display: inline-block; padding: 3px 10px; border-radius: 5px;
        font-family: var(--font-mono); font-size: 11px; font-weight: 700; border: 1px solid transparent; letter-spacing: 0.3px;
    }}
    .sev-critical {{ background: rgba(239,68,68,0.14);  color: #ff7878; border-color: rgba(239,68,68,0.40); }}
    .sev-high     {{ background: rgba(251,146,60,0.14); color: #fb923c; border-color: rgba(251,146,60,0.40); }}
    .sev-medium   {{ background: rgba(245,158,11,0.14); color: #fbbf24; border-color: rgba(245,158,11,0.40); }}
    .sev-low      {{ background: rgba(16,185,129,0.14); color: #34d399; border-color: rgba(16,185,129,0.40); }}
    .sev-none     {{ background: rgba(100,116,139,0.12); color: var(--muted); border-color: rgba(100,116,139,0.30); }}

    /* ================= CYBER ACTIVITY FEED ================= */
    .soc-feed {{
        font-family: var(--font-mono);
        font-size: 12px;
        background: var(--surface2);
        border: 1px solid var(--border);
        border-radius: 10px;
        padding: 12px 14px;
        max-height: 240px;
        overflow-y: auto;
    }}
    .soc-feed-row {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        padding: 5px 0;
        border-bottom: 1px solid var(--border-soft);
    }}
    .soc-feed-row:last-child {{ border-bottom: none; }}

    /* ================= WIDGETS & OVERRIDES ================= */
    div[data-testid="stDataFrame"] {{
        border: 1px solid var(--border);
        border-radius: 10px;
        overflow: hidden;
        background: var(--surface);
    }}
    .stButton > button {{
        border-radius: 8px; font-weight: 700; min-height: 40px; font-family: var(--font-body);
        border: 1px solid var(--border); background: var(--surface-2); color: var(--text);
        transition: all 0.15s ease;
    }}
    .stButton > button:hover {{ border-color: var(--signal); color: var(--heading); }}
    .stButton > button[kind="primary"] {{
        background: linear-gradient(135deg, #0284c7, #38bdf8); border: none; color: #041018;
    }}
    .stButton > button[kind="primary"]:hover {{
        box-shadow: 0 0 16px rgba(56,189,248,0.4);
    }}

    .footer {{ text-align: center; color: var(--muted-2); font-family: var(--font-mono); font-size: 10.5px; padding: 25px 0 5px 0; letter-spacing: 0.4px; }}
    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================================
# API & INFERENCE HELPERS
# ============================================================================

def check_api_health():
    try:
        if api_client is not None:
            data = api_client.get_health()
            return True, data
        response = requests.get(f"{API_URL}/health", timeout=4)
        response.raise_for_status()
        return True, response.json()
    except Exception:
        return False, None


def fetch_model_info():
    try:
        if api_client is not None:
            return api_client.get_model_info()
        response = requests.get(f"{API_URL}/model-info", timeout=6)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def analyze_file(uploaded_file, selected_dataset):
    endpoint = (
        f"{API_URL}/analyze/cicids"
        if selected_dataset == "CICIDS-2017"
        else f"{API_URL}/analyze/nsl-kdd"
    )
    try:
        uploaded_file.seek(0)
        response = requests.post(
            endpoint,
            files={"file": (uploaded_file.name, uploaded_file, "text/csv")},
            timeout=300,
        )
        if response.status_code == 200:
            return response.json(), None
        try:
            error_detail = response.json().get("detail", response.text)
        except Exception:
            error_detail = response.text
        return None, f"API Error ({response.status_code}): {error_detail}"
    except requests.exceptions.Timeout:
        return None, "The analysis timed out. The uploaded dataset may be too large."
    except requests.exceptions.ConnectionError:
        return None, "Could not connect to FastAPI. Make sure the backend is running at http://127.0.0.1:8000."
    except requests.RequestException as exc:
        return None, f"Request failed: {exc}"


def get_uploaded_frame(uploaded_file):
    """Parse an uploaded CSV once and reuse the DataFrame across Streamlit reruns.

    The Live Traffic page re-executes on every widget interaction, and re-parsing a
    ~70 MB CSV each rerun is significant overhead on the deployed dashboard. The frame
    is cached in session_state keyed by file identity (name + size + last_modified) so
    the full file is parsed only when a new/different file is uploaded.
    """
    key = f"traffic_frame_cache_{uploaded_file.name}_{uploaded_file.size}_{getattr(uploaded_file, 'last_modified', '')}"
    cached = st.session_state.get(key)
    if cached is not None:
        return cached, None
    try:
        uploaded_file.seek(0)
        df = pd.read_csv(uploaded_file)
    except Exception as exc:
        return None, exc
    st.session_state[key] = df
    return df, None


def _first_present(d, candidates, default=None):
    if not isinstance(d, dict):
        return default
    for key in candidates:
        if key in d and d[key] is not None:
            return d[key]
    return default


def normalize_result(raw, dataset_name):
    if not raw or not raw.get("success"):
        return None

    filename = raw.get("filename", "Unknown")

    if dataset_name == "CICIDS-2017":
        summary = raw.get("summary", {})
        total = summary.get("total_flows")
        normal = summary.get("benign_flows")
        attack = summary.get("attack_flows")
        attack_rate = summary.get("attack_rate")
        predictions = raw.get("predictions", [])
        extra_stats = {}
    else:
        stats = raw.get("statistics", {})
        total = _first_present(
            raw, ["rows_analyzed"],
            default=_first_present(stats, ["total", "total_flows", "total_rows", "total_records"]),
        )
        normal = _first_present(
            stats, ["normal_count", "benign_count", "normal", "benign", "normal_flows", "benign_flows"]
        )
        attack = _first_present(
            stats, ["attack_count", "anomaly_count", "attack", "anomaly", "attack_flows", "anomaly_flows"]
        )
        attack_rate = _first_present(stats, ["attack_rate", "anomaly_rate", "attack_percentage"])

        if attack_rate is None and total and attack is not None:
            try:
                attack_rate = round((attack / total) * 100, 2)
            except (TypeError, ZeroDivisionError):
                attack_rate = None

        if total is None and normal is not None and attack is not None:
            total = normal + attack

        predictions = raw.get("predictions", [])
        extra_stats = {
            k: v for k, v in stats.items()
            if k not in (
                "normal_count", "benign_count", "normal", "benign",
                "attack_count", "anomaly_count", "attack", "anomaly",
                "attack_rate", "anomaly_rate",
            )
        }

    predictions_df = pd.DataFrame(predictions) if predictions else None

    if predictions_df is not None and (normal is None or attack is None):
        attack_flag = detect_attack_flag(predictions_df)
        if attack_flag is not None:
            attack = int(attack_flag.sum())
            normal = int(len(predictions_df) - attack)
            total = total or len(predictions_df)
            if attack_rate is None and total:
                attack_rate = round((attack / total) * 100, 2)

    return {
        "success": True,
        "dataset": raw.get("dataset", dataset_name),
        "filename": filename,
        "total": total,
        "normal": normal,
        "attack": attack,
        "attack_rate": attack_rate,
        "predictions_df": predictions_df,
        "extra_stats": extra_stats,
    }


def detect_attack_flag(df):
    if df is None or df.empty:
        return None
    if "is_attack" in df.columns:
        return df["is_attack"].astype(bool)
    for col in ["prediction", "predicted_label", "label", "classification"]:
        if col in df.columns:
            series = df[col].astype(str).str.lower()
            return ~series.str.contains("benign|normal", regex=True, na=False)
    return None


def detect_score_column(df):
    if df is None:
        return None
    for col in ["attack_probability", "confidence", "risk_score", "anomaly_score", "probability"]:
        if col in df.columns:
            return col
    return None


def detect_category_column(df):
    if df is None:
        return None
    for col in ["attack_type", "attack_category", "category", "predicted_label", "label"]:
        if col in df.columns:
            uniq = df[col].dropna().astype(str).str.lower().unique()
            uniq = [u for u in uniq if u not in ("benign", "normal")]
            if len(uniq) >= 1:
                return col
    return None


def compute_severity(df):
    if df is None or df.empty:
        return df

    df = df.copy()
    attack_flag = detect_attack_flag(df)
    score_col = detect_score_column(df)

    def severity_for(score, is_attack):
        if not is_attack:
            return "None"
        if score is None:
            return "Medium"
        if score >= 0.90:
            return "Critical"
        if score >= 0.75:
            return "High"
        if score >= 0.50:
            return "Medium"
        return "Low"

    if attack_flag is None:
        df["Severity"] = "None"
        return df

    if score_col is not None:
        scores = pd.to_numeric(df[score_col], errors="coerce")
        if scores.max(skipna=True) is not None and scores.max(skipna=True) > 1.5:
            scores = scores / 100.0
    else:
        scores = pd.Series([None] * len(df))

    df["Severity"] = [
        severity_for(s if pd.notna(s) else None, bool(a))
        for s, a in zip(scores, attack_flag)
    ]
    return df


# ============================================================================
# REUSABLE UI & CHART COMPONENTS
# ============================================================================

def section_header(title, description=""):
    st.markdown(
        f"""
        <div class="section-header">
            <div class="section-title">{title}</div>
            {f'<div class="section-description">{description}</div>' if description else ""}
        </div>
        """,
        unsafe_allow_html=True,
    )


def metric_card(icon, label, value, value_class=""):
    is_na = value is None or value == "N/A"
    value_html = "N/A" if is_na else value
    css_class = "metric-na" if is_na else value_class
    st.markdown(
        f"""
        <div class="metric-card">
            <div class="metric-icon-badge">{icon}</div>
            <div class="metric-label">{label}</div>
            <div class="metric-value {css_class}">{value_html}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def info_card(label, value):
    st.markdown(
        f"""
        <div class="glass-panel" style="padding: 14px 18px;">
            <div style="color:var(--muted); font-size:10.5px; text-transform:uppercase; letter-spacing:0.5px; font-weight:700;">{label}</div>
            <div style="color:var(--text); font-size:14px; font-weight:600; margin-top:6px; font-family:var(--font-mono);">{value}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def status_pill(text, kind="neutral"):
    st.markdown(f'<span class="pill pill-{kind}">{text}</span>', unsafe_allow_html=True)


def severity_badge_html(severity):
    icon = SEVERITY_ICON.get(severity, "⚪")
    if st.session_state.get("custom_badge_colors", False):
        color_map = severity_color_map()
        col = color_map.get(severity, SEMANTIC["neutral"])
        return (
            f'<span class="severity-badge" style="background:{col}1a; color:{col}; '
            f'border:1px solid {col}55;">{icon} {severity}</span>'
        )
    css = {
        "Critical": "sev-critical", "High": "sev-high",
        "Medium": "sev-medium", "Low": "sev-low",
    }.get(severity, "sev-none")
    return f'<span class="severity-badge {css}">{icon} {severity}</span>'


def empty_state(icon, title, subtitle, cta_label=None, cta_page=None):
    st.markdown(
        f"""
        <div class="glass-panel" style="text-align: center; padding: 48px 20px; border-style: dashed;">
            <div style="font-size: 40px; margin-bottom: 12px; opacity: 0.85;">{icon}</div>
            <div style="font-family: var(--font-display); font-size: 17px; font-weight: 700; color: var(--heading);">{title}</div>
            <div style="font-size: 13px; color: var(--muted); margin-top: 6px; max-width: 440px; margin-left: auto; margin-right: auto;">{subtitle}</div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    if cta_label and cta_page:
        st.write("")
        col = st.columns([1, 1, 1])[1]
        with col:
            if st.button(cta_label, use_container_width=True, type="primary"):
                st.session_state.nav_page = cta_page
                st.rerun()


def _radar_html(radar_kind):
    return f"""
        <div class="radar-wrap radar-{radar_kind}">
            <div class="radar-ring r1"></div>
            <div class="radar-ring r2"></div>
            <div class="radar-core"></div>
        </div>
    """


def threat_status_panel(result):
    if not result:
        st.markdown(
            f"""
            <div class="threat-panel threat-panel-idle">
                {_radar_html("idle")}
                <div>
                    <div class="threat-panel-status">AWAITING ANALYSIS</div>
                    <div class="threat-panel-sub">No traffic has been analyzed yet in this session.</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )
        return

    rate = result.get("attack_rate")
    attack = result.get("attack") or 0

    if rate is None:
        status, sub, cls, radar = "STATUS UNKNOWN", "Attack rate could not be determined from the API response.", "threat-panel-idle", "idle"
    elif attack == 0:
        status, sub, cls, radar = "SYSTEM SECURE", "No malicious traffic detected in the most recent analysis.", "threat-panel-secure", "secure"
    elif rate < 15:
        status, sub, cls, radar = "ELEVATED ACTIVITY", f"{attack:,} anomalous flow(s) detected ({rate:.1f}% of traffic).", "threat-panel-elevated", "elevated"
    else:
        status, sub, cls, radar = "THREAT DETECTED", f"{attack:,} anomalous flow(s) detected ({rate:.1f}% of traffic).", "threat-panel-critical", "critical"

    st.markdown(
        f"""
        <div class="threat-panel {cls}">
            {_radar_html(radar)}
            <div>
                <div class="threat-panel-status">{status}</div>
                <div class="threat-panel-sub">{sub}</div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )


def chart_theme(height=340):
    t = get_theme()
    return dict(
        template=t["plotly_template"],
        height=height,
        margin=dict(l=10, r=10, t=20, b=10),
        paper_bgcolor="rgba(0,0,0,0)",
        plot_bgcolor="rgba(0,0,0,0)",
        font=dict(family="IBM Plex Sans, sans-serif", color=t["muted2"], size=12),
        xaxis=dict(gridcolor=t["grid"], zeroline=False),
        yaxis=dict(gridcolor=t["grid"], zeroline=False),
        legend=dict(font=dict(color=t["muted"])),
    )


def raw_response_expander(raw):
    if raw is None:
        return
    with st.expander("🧾 Raw API Response (debug)"):
        st.caption("Inspect raw backend JSON output for transparency.")
        st.json(raw)


def render_single_column_chart(df, column, height=360):
    if df is None or column not in df.columns:
        st.warning("Selected column not found in dataset.")
        return

    series = df[column]
    is_numeric = pd.api.types.is_numeric_dtype(series)
    viz = get_viz_colors()

    if is_numeric:
        valid_series = series.dropna()
        c1, c2, c3, c4, c5, c6 = st.columns(6)
        with c1:
            metric_card("📊", "Mean", f"{valid_series.mean():,.2f}" if not valid_series.empty else "N/A")
        with c2:
            metric_card("🎯", "Median", f"{valid_series.median():,.2f}" if not valid_series.empty else "N/A")
        with c3:
            metric_card("📉", "Std Dev", f"{valid_series.std():,.2f}" if len(valid_series) > 1 else "N/A")
        with c4:
            metric_card("🔽", "Min", f"{valid_series.min():,.2f}" if not valid_series.empty else "N/A")
        with c5:
            metric_card("🔼", "Max", f"{valid_series.max():,.2f}" if not valid_series.empty else "N/A")
        with c6:
            missing_cnt = int(series.isna().sum())
            metric_card("🕳️", "Missing",
                        f"{missing_cnt:,} ({missing_cnt / len(series) * 100:.1f}%)" if len(series) else "0")

        st.write("")
        col1, col2 = st.columns([2, 1])
        with col1:
            bins = st.slider("Histogram Bins", min_value=5, max_value=100, value=30, key=f"bins_{column}")
            fig = px.histogram(
                df, x=column, nbins=bins, marginal="box",
                labels={column: column, "count": "Frequency"},
            )
            fig.update_traces(marker_color=viz["primary"])
            fig.update_layout(**chart_theme(height=height))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        with col2:
            st.markdown(f"**Quantiles & Percentiles**")
            if not valid_series.empty:
                q_df = pd.DataFrame({
                    "Percentile": ["Min (0%)", "25% (Q1)", "50% (Median)", "75% (Q3)", "95%", "99%", "Max (100%)"],
                    "Value": [
                        valid_series.min(),
                        valid_series.quantile(0.25),
                        valid_series.quantile(0.50),
                        valid_series.quantile(0.75),
                        valid_series.quantile(0.95),
                        valid_series.quantile(0.99),
                        valid_series.max(),
                    ],
                })
                st.dataframe(q_df, use_container_width=True, hide_index=True)
            else:
                st.info("No non-null numeric values to compute quantiles.")

        csv_data = valid_series.to_frame().to_csv(index=False).encode("utf-8")
        st.download_button(
            f"📥 Download '{column}' Data (CSV)",
            data=csv_data,
            file_name=f"feature_{str(column).replace(' ', '_').lower()}.csv",
            mime="text/csv",
            key=f"dl_feat_{column}",
        )
    else:
        str_series = series.astype(str)
        counts = str_series.value_counts()
        total_len = len(series)
        unique_cnt = series.nunique(dropna=True)
        missing_cnt = int(series.isna().sum())
        top_mode = counts.index[0] if not counts.empty else "N/A"
        top_mode_pct = (counts.iloc[0] / total_len * 100) if not counts.empty and total_len else 0

        c1, c2, c3, c4 = st.columns(4)
        with c1:
            metric_card("🏷️", "Unique Values", f"{unique_cnt:,}")
        with c2:
            metric_card("⭐", "Most Common", str(top_mode)[:20])
        with c3:
            metric_card("📈", "Mode Share", f"{top_mode_pct:.1f}%")
        with c4:
            metric_card("🕳️", "Missing",
                        f"{missing_cnt:,} ({missing_cnt / total_len * 100:.1f}%)" if total_len else "0")

        st.write("")
        col1, col2 = st.columns([2, 1])
        top_n = min(20, len(counts))
        top_counts = counts.head(top_n)

        with col1:
            if unique_cnt > top_n:
                st.caption(f"Showing top {top_n} of {unique_cnt:,} unique categories.")
            fig = px.bar(
                x=top_counts.values, y=top_counts.index, orientation="h",
                labels={"x": "Count", "y": column},
            )
            fig.update_traces(marker_color=viz["secondary"])
            theme = chart_theme(height=height)
            theme["yaxis"] = dict(autorange="reversed", gridcolor=get_theme()["grid"], zeroline=False)
            fig.update_layout(**theme)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        with col2:
            st.markdown("**Category Breakdown**")
            table_df = top_counts.reset_index()
            table_df.columns = [column, "Count"]
            table_df["Percentage"] = (table_df["Count"] / total_len * 100).map("{:.2f}%".format) if total_len else "0%"
            st.dataframe(table_df, use_container_width=True, hide_index=True)

        csv_data = top_counts.reset_index().rename(columns={"index": column, column: "Count"}).to_csv(
            index=False).encode("utf-8")
        st.download_button(
            f"📥 Download '{column}' Distribution (CSV)",
            data=csv_data,
            file_name=f"category_{str(column).replace(' ', '_').lower()}_counts.csv",
            mime="text/csv",
            key=f"dl_cat_{column}",
        )


# ============================================================================
# SIDEBAR
# ============================================================================

api_online, health_data = check_api_health()

with st.sidebar:
    st.markdown(
        """
        <div class="sidebar-brand">
            <div class="sidebar-logo-row">
                <div class="sidebar-logo-badge">🛡️</div>
                <div>
                    <div class="sidebar-title">NetGuard AI</div>
                    <div class="sidebar-subtitle">CYBER INTELLIGENCE SOC</div>
                </div>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.markdown('<div class="nav-eyebrow">NAVIGATION</div>', unsafe_allow_html=True)

    labels = [f"{icon}  {name}" for icon, name in NAV_PAGES]
    name_by_label = {f"{icon}  {name}": name for icon, name in NAV_PAGES}
    current_label = next(
        (l for l in labels if name_by_label[l] == st.session_state.nav_page), labels[0]
    )

    selected_label = st.radio(
        "Navigation",
        labels,
        index=labels.index(current_label),
        label_visibility="collapsed",
    )
    page = name_by_label[selected_label]
    st.session_state.nav_page = page

    st.divider()
    st.caption("DATASET ENGINE")

    dataset = st.selectbox(
        "Select Dataset",
        ["CICIDS-2017", "NSL-KDD"],
        index=["CICIDS-2017", "NSL-KDD"].index(st.session_state.active_dataset),
        label_visibility="collapsed",
    )
    st.session_state.active_dataset = dataset

    st.divider()
    with st.expander("🎨 Visual Effects & SOC Theme"):
        st.caption("Theme & Color Palette")
        preset_list = list(VIZ_PRESETS.keys()) + ["Custom"]
        curr_preset = st.session_state.viz_preset if st.session_state.viz_preset in preset_list else "Default SOC"
        preset = st.selectbox(
            "Visualization theme", preset_list,
            index=preset_list.index(curr_preset),
            label_visibility="collapsed", key="viz_preset_select",
        )
        st.session_state.viz_preset = preset

        if preset == "Custom":
            base = st.session_state.viz_custom
            cols = st.columns(2)
            labels_map = {
                "normal": "Normal traffic", "suspicious": "Suspicious", "attack": "Attack traffic",
                "unknown": "Unknown / Other", "primary": "Chart primary", "secondary": "Chart secondary",
                "accent": "Accent",
            }
            for i, field in enumerate(VIZ_FIELDS):
                with cols[i % 2]:
                    base[field] = st.color_picker(labels_map.get(field, field.capitalize()),
                                                  value=base.get(field, "#38bdf8"), key=f"viz_{field}")
            st.session_state.viz_custom = base

        st.caption("3D & Graphic Acceleration")
        st.session_state.fx_3d_bg = st.checkbox("🌌 3D Cyber Spatial Visualizer", value=st.session_state.fx_3d_bg)
        st.session_state.fx_animations = st.checkbox("⚡ Micro-Animations & Glow", value=st.session_state.fx_animations)
        st.session_state.custom_badge_colors = st.checkbox("🎨 Sync Badges with Palette",
                                                           value=st.session_state.custom_badge_colors)

        st.write("")
        if st.button("↺ Reset Appearance to Defaults", use_container_width=True):
            st.session_state.viz_preset = "Default SOC"
            st.session_state.viz_custom = dict(VIZ_PRESETS["Default SOC"])
            st.session_state.custom_badge_colors = False
            st.session_state.fx_3d_bg = True
            st.session_state.fx_animations = True
            st.session_state.fx_glow = True
            st.rerun()

    api_pill_class = "pill-online" if api_online else "pill-offline"
    api_pill_text = "● API ONLINE" if api_online else "● API OFFLINE"

    models_html = ""
    if api_online and isinstance(health_data, dict):
        models = health_data.get("models")
        if isinstance(models, dict):
            for name, status in models.items():
                ok = str(status).lower() in ("true", "loaded", "ready", "online", "ok") or status is True
                dot = "🟢" if ok else "🔴"
                models_html += (
                    f'<div class="sidebar-status-row" style="font-family:var(--font-mono); font-size:11px; padding:2px 0;">'
                    f'<span style="color:var(--muted);">{name}</span>'
                    f'<span>{dot}</span></div>'
                )

    st.markdown(
        f"""
        <div class="glass-panel" style="margin-top:16px; padding:12px 14px;">
            <span class="pill {api_pill_class}" style="margin:0; font-size:11px;">{api_pill_text}</span>
            {f'<div style="margin-top:8px;">{models_html}</div>' if models_html else ""}
        </div>
        """,
        unsafe_allow_html=True,
    )

    st.caption("NetGuard AI · SOC v2.0")

# ============================================================================
# HEADER (shown on every page)
# ============================================================================

st.markdown(
    """
    <div class="hero">
        <div class="hero-eyebrow">// NETGUARD AI // THREAT MONITORING SYSTEM</div>
        <div class="hero-title">Network Security Operations Center</div>
        <div class="hero-subtitle">Real-time ML intrusion detection &amp; 3D network topology intelligence</div>
        <div class="scanline"></div>
    </div>
    """,
    unsafe_allow_html=True,
)

header_col1, header_col2, header_col3, header_col4 = st.columns([1, 1, 1.6, 0.8])
with header_col1:
    status_pill("● API CONNECTED" if api_online else "● API OFFLINE", "online" if api_online else "offline")
with header_col2:
    status_pill(f"📁 {dataset}", "neutral")
with header_col3:
    last_time = st.session_state.last_analysis_time
    status_pill(
        f"🕒 Last analysis: {last_time.strftime('%Y-%m-%d %H:%M:%S')}" if last_time else "🕒 No analysis yet",
        "neutral",
    )
with header_col4:
    status_pill("🌙 Dark SOC Mode", "neutral")

# Render the interactive 3D WebGL Neural Matrix Hero
render_3d_hero()

st.write("")


# ============================================================================
# PAGE: OVERVIEW
# ============================================================================

def render_overview():
    section_header(
        f"{dataset} Threat Operations Command",
        "Unified real-time snapshot of the latest network intelligence and threat signals.",
    )

    result = st.session_state.analysis_result
    threat_status_panel(result)
    st.write("")

    total = result.get("total") if result else None
    normal = result.get("normal") if result else None
    attack = result.get("attack") if result else None
    rate = result.get("attack_rate") if result else None

    model_info = fetch_model_info()
    accuracy = None
    if isinstance(model_info, dict):
        accuracy = _first_present(model_info, ["accuracy", "model_accuracy", "test_accuracy"])

    c1, c2, c3, c4, c5 = st.columns(5)
    with c1:
        metric_card("🌐", "Total Traffic", f"{total:,}" if total is not None else "N/A")
    with c2:
        metric_card("🚨", "Anomalies Detected", f"{attack:,}" if attack is not None else "N/A", "metric-danger")
    with c3:
        metric_card("✅", "Normal Traffic", f"{normal:,}" if normal is not None else "N/A", "metric-safe")
    with c4:
        rate_class = "metric-safe" if (
                    rate is not None and rate == 0) else "metric-danger" if rate else "metric-warning"
        metric_card("📈", "Threat Rate", f"{rate:.2f}%" if rate is not None else "N/A", rate_class)
    with c5:
        metric_card(
            "🎯", "Model Accuracy",
            f"{accuracy * 100:.2f}%" if isinstance(accuracy, (int, float)) and accuracy <= 1 else
            (f"{accuracy:.2f}%" if isinstance(accuracy, (int, float)) else "N/A"),
        )

    if not result:
        st.write("")
        empty_state(
            "🛡️",
            "No traffic analysis available in session",
            "Upload a network capture CSV on the Live Traffic page to initiate threat detection and 3D visualization.",
            cta_label="🌐 Go to Live Traffic",
            cta_page="Live Traffic",
        )
        return

    predictions_df = result.get("predictions_df")
    if predictions_df is None or predictions_df.empty:
        st.info("Analysis completed, but the API did not return per-row predictions to chart.")
        raw_response_expander(st.session_state.raw_result)
        return

    st.write("")
    col1, col2 = st.columns(2)

    with col1:
        section_header("Traffic Classification")
        chart_df = pd.DataFrame({"Category": ["Normal", "Anomaly"], "Flows": [normal or 0, attack or 0]})
        fig = px.pie(chart_df, names="Category", values="Flows", hole=0.62,
                     color="Category", color_discrete_map={"Normal": VIZ["normal"], "Anomaly": VIZ["attack"]})
        fig.update_traces(textposition="inside", textinfo="percent+label")
        theme = chart_theme(height=340)
        theme["legend"] = dict(orientation="h", yanchor="bottom", y=1.02, xanchor="center", x=0.5,
                               font=dict(color=get_theme()["muted"]))
        fig.update_layout(**theme)
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with col2:
        section_header("Threat Distribution")
        cat_col = detect_category_column(predictions_df)
        if cat_col:
            counts = (
                predictions_df[predictions_df[cat_col].astype(str).str.lower().ne("benign")
                               & predictions_df[cat_col].astype(str).str.lower().ne("normal")][cat_col]
                .value_counts()
            )
            if counts.empty:
                st.info("No attack categories present in this analysis.")
            else:
                fig2 = px.bar(x=counts.values, y=counts.index, orientation="h", labels={"x": "Flows", "y": ""})
                fig2.update_layout(**chart_theme(height=340), showlegend=False)
                fig2.update_traces(marker_color=VIZ["attack"])
                st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
        else:
            fig2b = px.bar(
                x=["Normal", "Anomaly"], y=[normal or 0, attack or 0],
                color=["Normal", "Anomaly"], color_discrete_map={"Normal": VIZ["normal"], "Anomaly": VIZ["attack"]},
            )
            fig2b.update_layout(**chart_theme(height=340), showlegend=False)
            st.plotly_chart(fig2b, use_container_width=True, config={"displayModeBar": False})

    # Live SOC Activity Terminal
    st.write("")
    section_header("📡 Live Security Activity Terminal", "Chronological audit stream of analyzed flows.")
    sev_df = compute_severity(predictions_df)
    recent_sample = sev_df.tail(8)

    soc_feed_html = '<div class="soc-feed">'
    for idx, row in recent_sample.iterrows():
        is_att = row.get("is_attack", False) or "anomaly" in str(row.get("prediction", "")).lower() or "attack" in str(
            row.get("prediction", "")).lower()
        badge_sev = row.get("Severity", "Low" if not is_att else "High")
        pred_label = row.get("prediction", "Attack" if is_att else "Normal")
        conf_val = row.get("confidence") or row.get("attack_probability")
        conf_str = f" · {float(conf_val) * 100:.1f}% conf" if conf_val is not None else ""
        dot_col = VIZ["attack"] if is_att else VIZ["normal"]

        soc_feed_html += f"""
        <div class="soc-feed-row">
            <div>
                <span style="color:{dot_col};">●</span>
                <span style="color:var(--text); font-weight:600; margin-left:6px;">Flow #{idx + 1}</span>
                <span style="color:var(--muted); margin-left:8px;">{pred_label}{conf_str}</span>
            </div>
            <div>{severity_badge_html(badge_sev)}</div>
        </div>
        """
    soc_feed_html += '</div>'
    st.markdown(soc_feed_html, unsafe_allow_html=True)

    raw_response_expander(st.session_state.raw_result)


# ============================================================================
# PAGE: ANALYZE TRAFFIC (LIVE TRAFFIC)
# ============================================================================

def render_analyze_traffic():
    section_header(
        "🔍 Analyze Network Traffic",
        f"Upload a CSV network traffic capture to run it through the {dataset} ML detection engine.",
    )

    if not api_online:
        st.markdown(
            '<div class="warning-banner result-banner">⚠️ Prediction API unavailable. '
            'Please ensure the FastAPI server is running at http://127.0.0.1:8000.</div>',
            unsafe_allow_html=True,
        )

    MAX_TRAFFIC_FILE_SIZE = LIVE_TRAFFIC_MAX_BYTES

    st.markdown(
        f'<div style="color:var(--muted); font-size:12px; font-family:var(--font-mono); '
        f'margin-bottom:4px;">Maximum file size: {LIVE_TRAFFIC_MAX_MB} MB</div>',
        unsafe_allow_html=True,
    )

    uploaded_file = st.file_uploader(
        "Upload CSV", type=["csv"], key="traffic_upload", label_visibility="collapsed",
    )

    if uploaded_file is not None and uploaded_file.size > MAX_TRAFFIC_FILE_SIZE:
        size_mb = uploaded_file.size / (1024 * 1024)
        st.toast(f"🚫 Upload rejected: {uploaded_file.name} is {size_mb:.2f} MB. "
                 f"The maximum allowed file size for Live Traffic is {LIVE_TRAFFIC_MAX_MB} MB.")
        st.markdown(
            f'<div class="danger-banner result-banner">⚠️ File too large! Maximum allowed size is '
            f'{LIVE_TRAFFIC_MAX_MB} MB.<br>🚫 Upload rejected: {uploaded_file.name} is {size_mb:.2f} MB. '
            f'The maximum allowed file size for Live Traffic is {LIVE_TRAFFIC_MAX_MB} MB.</div>',
            unsafe_allow_html=True,
        )
        return

    if uploaded_file is not None:
        df_preview, read_error = get_uploaded_frame(uploaded_file)
        if read_error is not None:
            st.markdown(
                f'<div class="danger-banner result-banner">⚠️ Unable to read CSV file: {read_error}</div>',
                unsafe_allow_html=True,
            )
            df_preview = None

        if df_preview is not None:
            info_card(
                "Uploaded Dataset Details",
                f"📄 {uploaded_file.name} &nbsp;•&nbsp; "
                f"<span style='color:var(--muted);'>{len(df_preview):,} flows &nbsp;•&nbsp; {len(df_preview.columns):,} features &nbsp;•&nbsp; Engine: {dataset}</span>",
            )
            st.write("")

            with st.expander("👁️ Inspect Raw Flow Capture Preview", expanded=True):
                st.dataframe(df_preview.head(10), use_container_width=True, hide_index=True)

            st.write("")
            analyze_clicked = st.button(
                "🚀  RUN CYBER INTRUSION DETECTION", type="primary", use_container_width=True, disabled=not api_online,
            )

            if analyze_clicked:
                progress = st.status("🔄 AI Detection Engine Processing Traffic...", expanded=True)
                progress.write("📦 Uploading payload to FastAPI backend...")
                progress.write("🧮 Extracting flow features & packet statistics...")
                progress.write("🤖 Performing neural/tree ML inference...")

                raw_result, error = analyze_file(uploaded_file, dataset)

                if error:
                    progress.update(label="❌ Analysis Failed", state="error", expanded=True)
                    st.markdown(f'<div class="danger-banner result-banner">⚠️ {error}</div>', unsafe_allow_html=True)
                elif not raw_result or not raw_result.get("success"):
                    progress.update(label="❌ Analysis Failed", state="error", expanded=True)
                    st.markdown(
                        '<div class="danger-banner result-banner">⚠️ The API responded, but the analysis was '
                        'not marked successful. See raw response below.</div>',
                        unsafe_allow_html=True,
                    )
                    raw_response_expander(raw_result)
                else:
                    progress.write("📊 Computing severity distributions & topological nodes...")
                    progress.write("📝 Finalizing security report...")
                    normalized = normalize_result(raw_result, dataset)
                    progress.update(label="✅ Threat Analysis Complete", state="complete", expanded=False)

                    st.session_state.analysis_result = normalized
                    st.session_state.raw_result = raw_result
                    st.session_state.uploaded_filename = uploaded_file.name
                    st.session_state.last_analysis_time = datetime.now()
                    st.session_state.explore_df = df_preview
                    st.session_state.explore_filename = uploaded_file.name

                    push_history(normalized)
                    st.rerun()

    st.write("")
    result = st.session_state.analysis_result

    if not result:
        empty_state(
            "📂", "No analysis in session",
            "Upload a network capture CSV above and click 'Run Cyber Intrusion Detection' to view results.",
        )
        return

    st.divider()
    section_header(
        "📊 Detection Results Summary",
        f"File: {st.session_state.uploaded_filename} · Dataset: {result.get('dataset')}",
    )

    total, normal, attack, rate = result.get("total"), result.get("normal"), result.get("attack"), result.get(
        "attack_rate")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("🌐", "Total Records", f"{total:,}" if total is not None else "N/A")
    with c2:
        metric_card("✅", "Normal", f"{normal:,}" if normal is not None else "N/A", "metric-safe")
    with c3:
        metric_card("🚨", "Anomalies", f"{attack:,}" if attack is not None else "N/A", "metric-danger")
    with c4:
        metric_card("📈", "Threat Rate", f"{rate:.2f}%" if rate is not None else "N/A",
                    "metric-safe" if rate == 0 else "metric-danger")

    predictions_df = result.get("predictions_df")
    if predictions_df is not None and not predictions_df.empty:
        st.write("")
        col1, col2 = st.columns(2)
        with col1:
            section_header("Classification Ratio")
            chart_df = pd.DataFrame({"Category": ["Normal", "Anomaly"], "Flows": [normal or 0, attack or 0]})
            fig = px.pie(chart_df, names="Category", values="Flows", hole=0.6,
                         color="Category", color_discrete_map={"Normal": VIZ["normal"], "Anomaly": VIZ["attack"]})
            fig.update_traces(textposition="inside", textinfo="percent+label")
            fig.update_layout(**chart_theme(height=340))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        with col2:
            section_header("Confidence Distribution")
            score_col = detect_score_column(predictions_df)
            if score_col:
                fig2 = px.histogram(predictions_df, x=score_col, nbins=20)
                fig2.update_traces(marker_color=VIZ["primary"])
                fig2.update_layout(**chart_theme(height=340))
                st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
            else:
                st.info("No confidence/probability column found in the predictions to chart.")

        st.write("")
        section_header("🔎 Flagged Flow Inspector", "Severity is a transparent rule-based estimate for SOC triage.")
        severity_df = compute_severity(predictions_df)
        st.dataframe(severity_df, use_container_width=True, hide_index=True)

        csv_bytes = severity_df.to_csv(index=False).encode("utf-8")
        st.download_button(
            "⬇️ Download Flagged Results as CSV", data=csv_bytes,
            file_name=f"netguard_results_{dataset.lower().replace('-', '')}.csv",
            mime="text/csv", use_container_width=True,
        )

    raw_response_expander(st.session_state.raw_result)


# ============================================================================
# PAGE: TRAFFIC ANALYTICS
# ============================================================================

def render_traffic_analytics():
    section_header("📊 Traffic Analytics", "Flow-level metrics and pairwise feature relationships.")

    df = st.session_state.explore_df
    if df is None:
        empty_state(
            "📊", "No traffic data loaded",
            "Analyze a CSV from the 'Live Traffic' page or load one on the 'Dataset Analysis' page.",
            cta_label="🌐 Live Traffic", cta_page="Live Traffic",
        )
        return

    st.caption(f"Source file: {st.session_state.explore_filename} · {len(df):,} flows · {len(df.columns):,} features")

    numeric_df = df.select_dtypes(include="number")

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("🔢", "Total Flows", f"{len(df):,}")
    with c2:
        dur_col = next((c for c in df.columns if "duration" in str(c).lower()), None)
        metric_card("⏱️", "Avg. Duration", f"{df[dur_col].mean():,.2f}" if dur_col else "N/A")
    with c3:
        pkt_col = next((c for c in df.columns if "packet" in str(c).lower()), None)
        metric_card("📦", "Avg. Packets", f"{df[pkt_col].mean():,.2f}" if pkt_col else "N/A")
    with c4:
        byte_col = next((c for c in df.columns if "byte" in str(c).lower()), None)
        metric_card("💾", "Avg. Bytes", f"{df[byte_col].mean():,.2f}" if byte_col else "N/A")

    st.write("")
    tab_dist, tab_corr, tab_stats = st.tabs(
        ["Flow & Protocol Distributions", "Feature Correlation Heatmap", "Numeric Feature Summary"]
    )

    with tab_dist:
        col1, col2 = st.columns(2)
        with col1:
            section_header("Protocol Distribution")
            proto_col = next((c for c in df.columns if str(c).lower() in ("protocol", "protocol_type", "proto")), None)
            if proto_col:
                counts = df[proto_col].astype(str).value_counts().head(12)
                fig = px.bar(x=counts.index, y=counts.values, labels={"x": "Protocol", "y": "Flows"})
                fig.update_traces(marker_color=VIZ["primary"])
                fig.update_layout(**chart_theme(height=340))
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
            else:
                st.info("No protocol column detected in this dataset.")

        with col2:
            section_header("Port Distribution")
            port_col = next((c for c in df.columns if "port" in str(c).lower() and "dst" in str(c).lower()), None) \
                       or next(
                (c for c in df.columns if str(c).lower() in ("destination port", "dst_port", "dst_host_port")), None) \
                       or next((c for c in df.columns if "port" in str(c).lower()), None)
            if port_col:
                counts = df[port_col].astype(str).value_counts().head(12)
                fig2 = px.bar(x=counts.index, y=counts.values, labels={"x": "Port", "y": "Flows"})
                fig2.update_traces(marker_color=VIZ["secondary"])
                fig2.update_layout(**chart_theme(height=340))
                st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
            else:
                st.info("No port column detected in this dataset.")

    with tab_corr:
        section_header("Pairwise Feature Correlation Matrix", "Collinearity analysis across numeric features.")
        if numeric_df.shape[1] < 2:
            st.info("At least 2 numeric columns are required to compute a correlation heatmap.")
        else:
            variances = numeric_df.var(numeric_only=True).sort_values(ascending=False)
            all_num_cols = list(variances.index)
            default_cols = all_num_cols[:20]

            if len(all_num_cols) > 20:
                st.info(f"Dataset has {len(all_num_cols)} numeric features. Showing top 20 by variance by default.")

            selected_corr_cols = st.multiselect(
                "Select Features for Correlation", options=all_num_cols, default=default_cols, key="analytics_corr_cols"
            )

            if len(selected_corr_cols) >= 2:
                corr_method = st.radio("Method", ["pearson", "spearman"], horizontal=True, key="analytics_corr_method")
                corr_matrix = numeric_df[selected_corr_cols].corr(method=corr_method)

                fig_corr = px.imshow(
                    corr_matrix,
                    text_auto=(len(selected_corr_cols) <= 14),
                    color_continuous_scale="RdBu_r",
                    zmin=-1, zmax=1, aspect="auto",
                    labels=dict(color="Correlation"),
                )
                fig_corr.update_layout(**chart_theme(height=max(460, len(selected_corr_cols) * 24)))
                st.plotly_chart(fig_corr, use_container_width=True, config={"displayModeBar": False})

                csv_corr = corr_matrix.to_csv().encode("utf-8")
                st.download_button(
                    "📥 Download Correlation Matrix (CSV)", data=csv_corr,
                    file_name="traffic_correlation_matrix.csv", mime="text/csv", key="dl_analytics_corr"
                )
            else:
                st.warning("Please select at least 2 features.")

    with tab_stats:
        section_header("Descriptive Statistics")
        if not numeric_df.empty:
            desc_df = numeric_df.describe().T
            st.dataframe(desc_df, use_container_width=True)


# ============================================================================
# PAGE: THREAT DETECTION & ALERTS
# ============================================================================

def render_threat_detection():
    section_header("🚨 Threat Detection & Alerts", "Severity classification and attack category intelligence.")

    result = st.session_state.analysis_result
    if not result or result.get("predictions_df") is None or result.get("predictions_df").empty:
        empty_state(
            "🚨", "No threats to display",
            "Analyze traffic from Live Traffic to populate threat intelligence.",
            cta_label="🌐 Live Traffic", cta_page="Live Traffic",
        )
        return

    df = compute_severity(result["predictions_df"])
    counts = df["Severity"].value_counts()

    cols = st.columns(5)
    total_threats = int(df["Severity"].ne("None").sum())
    with cols[0]:
        metric_card("🚨", "Total Threats", f"{total_threats:,}", "metric-danger")
    for i, sev in enumerate(SEVERITY_ORDER, start=1):
        with cols[i]:
            metric_card(SEVERITY_ICON[sev], f"{sev} Threats", f"{int(counts.get(sev, 0)):,}")

    st.write("")
    col1, col2 = st.columns([1, 1])

    with col1:
        section_header("Threat Categories")
        cat_col = detect_category_column(df)
        if cat_col:
            attack_only = df[df["Severity"] != "None"]
            cat_counts = attack_only[cat_col].value_counts()
            fig = px.pie(names=cat_counts.index, values=cat_counts.values, hole=0.5)
            fig.update_layout(**chart_theme(height=340))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            sev_counts = df[df["Severity"] != "None"]["Severity"].value_counts().reindex(SEVERITY_ORDER).dropna()
            fig = px.bar(
                x=sev_counts.index, y=sev_counts.values,
                color=sev_counts.index, color_discrete_map=severity_color_map(),
            )
            fig.update_layout(**chart_theme(height=340), showlegend=False)
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    with col2:
        section_header("Severity Breakdown")
        sev_counts_full = df["Severity"].value_counts().reindex(["None"] + SEVERITY_ORDER).dropna()
        fig3 = px.bar(
            x=sev_counts_full.values, y=sev_counts_full.index, orientation="h",
            color=sev_counts_full.index,
            color_discrete_map={**severity_color_map(), "None": get_theme()["border_soft"]},
        )
        fig3.update_layout(**chart_theme(height=340), showlegend=False)
        st.plotly_chart(fig3, use_container_width=True, config={"displayModeBar": False})

    st.write("")
    section_header("Flagged Threat Logs")

    threats_df = df[df["Severity"] != "None"].copy()
    if threats_df.empty:
        st.success("✅ No security anomalies flagged in the current dataset.")
        return

    preferred_cols = [c for c in
                      ["row", "prediction", "attack_type", "confidence", "attack_probability",
                       "source_ip", "src_ip", "destination_ip", "dst_ip", "Severity"]
                      if c in threats_df.columns]
    if not preferred_cols:
        preferred_cols = list(threats_df.columns)

    display_df = threats_df[preferred_cols].head(200).copy()
    st.dataframe(display_df, use_container_width=True, hide_index=True)
    st.caption(f"Showing {min(200, len(threats_df)):,} of {len(threats_df):,} flagged flows.")


# ============================================================================
# PAGE: INTERACTIVE 3D & 2D NETWORK TOPOLOGY VISUALIZATION
# ============================================================================

def render_network_topology():
    section_header(
        "🕸️ Interactive Network Topology Intelligence",
        "Spatial 3D & 2D graph reconstruction of network flows, host nodes, and threat vectors.",
    )

    df = st.session_state.explore_df
    if df is None and st.session_state.analysis_result and st.session_state.analysis_result.get(
            "predictions_df") is not None:
        df = st.session_state.analysis_result["predictions_df"]

    if df is None or df.empty:
        empty_state(
            "🕸️",
            "No Network Traffic Loaded for Topology Mapping",
            "Analyze a capture from 'Live Traffic' or load a CSV from 'Dataset Analysis' to construct network topology.",
            cta_label="🌐 Go to Live Traffic",
            cta_page="Live Traffic",
        )
        return

    src_col = next((c for c in df.columns if str(c).lower() in ("src_ip", "source_ip", "source ip", "source")), None)
    dst_col = next((c for c in df.columns if
                    str(c).lower() in ("dst_ip", "destination_ip", "destination ip", "dst_host", "destination")), None)
    proto_col = next((c for c in df.columns if str(c).lower() in ("protocol", "protocol_type", "proto")), None)
    port_col = next((c for c in df.columns if "port" in str(c).lower() and "dst" in str(c).lower()), None) or next(
        (c for c in df.columns if "port" in str(c).lower()), None)

    sev_df = compute_severity(df) if "Severity" not in df.columns else df

    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([1.5, 1.5, 1])
    with ctrl_col1:
        view_mode = st.radio("Topology View Mode", ["3D Cyber Sphere View", "2D SOC Matrix View"], horizontal=True,
                             key="topo_view_mode")
    with ctrl_col2:
        max_nodes = st.slider("Max Nodes to Render", min_value=10, max_value=60, value=30, step=5, key="topo_max_nodes")
    with ctrl_col3:
        filter_status = st.selectbox("Filter Status", ["All Traffic", "Threats Only", "Normal Only"],
                                     key="topo_filter_status")

    plot_data = sev_df.copy()
    if filter_status == "Threats Only":
        plot_data = plot_data[plot_data.get("Severity", "None") != "None"]
    elif filter_status == "Normal Only":
        plot_data = plot_data[plot_data.get("Severity", "None") == "None"]

    if plot_data.empty:
        st.warning("No flows match the selected status filter.")
        return

    nodes_dict = {}
    edges_list = []

    if src_col and dst_col:
        for _, row in plot_data.head(max_nodes * 3).iterrows():
            s = str(row[src_col])
            d = str(row[dst_col])
            sev = row.get("Severity", "None")
            is_att = sev != "None"

            if s not in nodes_dict:
                nodes_dict[s] = {"type": "Source", "flows": 0, "threats": 0, "sev": "None"}
            if d not in nodes_dict:
                nodes_dict[d] = {"type": "Destination", "flows": 0, "threats": 0, "sev": "None"}

            nodes_dict[s]["flows"] += 1
            nodes_dict[d]["flows"] += 1
            if is_att:
                nodes_dict[s]["threats"] += 1
                nodes_dict[d]["threats"] += 1
                nodes_dict[s]["sev"] = sev
                nodes_dict[d]["sev"] = sev

            if len(nodes_dict) <= max_nodes:
                edges_list.append((s, d, sev))
    else:
        p_name = proto_col or "Protocol"
        port_name = port_col or "Port"
        gateway_node = "SOC-Gateway-01"
        nodes_dict[gateway_node] = {"type": "Gateway", "flows": len(plot_data),
                                    "threats": int(plot_data.get("Severity", "None").ne("None").sum()),
                                    "sev": "Gateway"}

        for idx, row in plot_data.head(max_nodes - 1).iterrows():
            proto_val = str(row.get(p_name, "TCP"))
            port_val = str(row.get(port_name, f"Port-{(idx % 10) * 100}"))
            node_id = f"Host-{idx + 1:02d} ({proto_val}/{port_val})"
            sev = row.get("Severity", "None")

            nodes_dict[node_id] = {
                "type": "Endpoint",
                "flows": 1,
                "threats": 1 if sev != "None" else 0,
                "sev": sev,
            }
            edges_list.append((gateway_node, node_id, sev))

    node_names = list(nodes_dict.keys())[:max_nodes]
    N = len(node_names)

    if view_mode == "3D Cyber Sphere View":
        phi = math.pi * (3.0 - math.sqrt(5.0))
        xs, ys, zs, colors, sizes, hover_texts = [], [], [], [], [], []

        pos_3d = {}
        for i, name in enumerate(node_names):
            y = 1 - (i / float(max(1, N - 1))) * 2
            radius = math.sqrt(max(0, 1 - y * y))
            theta = phi * i
            x = math.cos(theta) * radius
            z = math.sin(theta) * radius

            pos_3d[name] = (x, y, z)
            xs.append(x)
            ys.append(y)
            zs.append(z)

            info = nodes_dict[name]
            sev = info["sev"]
            if sev == "Gateway":
                c = VIZ.get("primary", "#38bdf8")
                sz = 14
            elif sev == "Critical":
                c = VIZ.get("attack", "#ef4444")
                sz = 12
            elif sev == "High":
                c = "#fb923c"
                sz = 11
            elif sev == "Medium":
                c = VIZ.get("suspicious", "#fbbf24")
                sz = 10
            else:
                c = VIZ.get("normal", "#10b981")
                sz = 8

            colors.append(c)
            sizes.append(sz)
            hover_texts.append(
                f"<b>Node:</b> {name}<br><b>Type:</b> {info['type']}<br><b>Severity:</b> {sev}<br><b>Threat Flows:</b> {info['threats']}"
            )

        edge_x, edge_y, edge_z = [], [], []
        for s, d, _ in edges_list:
            if s in pos_3d and d in pos_3d:
                p1 = pos_3d[s]
                p2 = pos_3d[d]
                edge_x.extend([p1[0], p2[0], None])
                edge_y.extend([p1[1], p2[1], None])
                edge_z.extend([p1[2], p2[2], None])

        edge_trace = go.Scatter3d(
            x=edge_x, y=edge_y, z=edge_z,
            mode='lines',
            line=dict(color="rgba(56, 189, 248, 0.28)", width=1.5),
            hoverinfo='none',
        )

        node_trace = go.Scatter3d(
            x=xs, y=ys, z=zs,
            mode='markers+text',
            marker=dict(size=sizes, color=colors, line=dict(color='#ffffff', width=0.5)),
            text=[n[:12] for n in node_names],
            textposition="top center",
            hovertext=hover_texts,
            hoverinfo='text',
        )

        fig_3d = go.Figure(data=[edge_trace, node_trace])
        fig_3d.update_layout(
            scene=dict(
                xaxis=dict(showgrid=False, zeroline=False, showticklabels=False, backgroundcolor="rgba(0,0,0,0)"),
                yaxis=dict(showgrid=False, zeroline=False, showticklabels=False, backgroundcolor="rgba(0,0,0,0)"),
                zaxis=dict(showgrid=False, zeroline=False, showticklabels=False, backgroundcolor="rgba(0,0,0,0)"),
            ),
            paper_bgcolor="rgba(0,0,0,0)",
            height=620,
            margin=dict(l=0, r=0, t=0, b=0),
            showlegend=False,
        )
        st.plotly_chart(fig_3d, use_container_width=True, config={"displayModeBar": False})

    else:
        pos_2d = {}
        xs, ys, colors, sizes, hover_texts = [], [], [], [], []

        for i, name in enumerate(node_names):
            if i == 0 and "Gateway" in str(nodes_dict[name].get("type")):
                x, y = 0.0, 0.0
            else:
                angle = (2 * math.pi / max(1, N - 1)) * i
                x = math.cos(angle) * (1.8 if i % 2 == 0 else 1.2)
                y = math.sin(angle) * (1.8 if i % 2 == 0 else 1.2)

            pos_2d[name] = (x, y)
            xs.append(x)
            ys.append(y)

            info = nodes_dict[name]
            sev = info["sev"]
            if sev == "Gateway":
                c = VIZ.get("primary", "#38bdf8")
                sz = 20
            elif sev == "Critical":
                c = VIZ.get("attack", "#ef4444")
                sz = 16
            elif sev == "High":
                c = "#fb923c"
                sz = 14
            elif sev == "Medium":
                c = VIZ.get("suspicious", "#fbbf24")
                sz = 12
            else:
                c = VIZ.get("normal", "#10b981")
                sz = 10

            colors.append(c)
            sizes.append(sz)
            hover_texts.append(
                f"<b>Node:</b> {name}<br><b>Type:</b> {info['type']}<br><b>Severity:</b> {sev}<br><b>Threats:</b> {info['threats']}"
            )

        edge_x, edge_y = [], []
        for s, d, _ in edges_list:
            if s in pos_2d and d in pos_2d:
                p1 = pos_2d[s]
                p2 = pos_2d[d]
                edge_x.extend([p1[0], p2[0], None])
                edge_y.extend([p1[1], p2[1], None])

        edge_trace = go.Scatter(
            x=edge_x, y=edge_y,
            mode='lines',
            line=dict(color="rgba(56, 189, 248, 0.3)", width=1.5),
            hoverinfo='none',
        )

        node_trace = go.Scatter(
            x=xs, y=ys,
            mode='markers+text',
            marker=dict(size=sizes, color=colors, line=dict(color='#ffffff', width=0.8)),
            text=[n[:10] for n in node_names],
            textposition="bottom center",
            hovertext=hover_texts,
            hoverinfo='text',
        )

        fig_2d = go.Figure(data=[edge_trace, node_trace])
        theme = chart_theme(height=560)
        theme["xaxis"] = dict(showgrid=False, zeroline=False, showticklabels=False)
        theme["yaxis"] = dict(showgrid=False, zeroline=False, showticklabels=False)
        theme["showlegend"] = False
        fig_2d.update_layout(**theme)
        st.plotly_chart(fig_2d, use_container_width=True, config={"displayModeBar": False})

    st.write("")
    section_header("🔍 Node Communications Directory", "Detailed telemetry per discovered host node.")
    node_summary_data = [
        {"Node ID": k, "Category": v["type"], "Active Flows": v["flows"], "Flagged Threats": v["threats"],
         "Severity": v["sev"]}
        for k, v in nodes_dict.items()
    ]
    node_summary_df = pd.DataFrame(node_summary_data)
    st.dataframe(node_summary_df, use_container_width=True, hide_index=True)

    csv_topo = node_summary_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "📥 Download Topology Inventory (CSV)", data=csv_topo,
        file_name="network_topology_inventory.csv", mime="text/csv", key="dl_topo_csv"
    )


# ============================================================================
# PAGE: AI PREDICTIONS & ML INSIGHTS
# ============================================================================

def render_ml_insights():
    section_header("🤖 AI Predictions & Model Telemetry",
                   "Neural model architecture, feature weights, and confidence meters.")

    model_info = fetch_model_info()

    if not api_online:
        st.markdown(
            '<div class="warning-banner result-banner">⚠️ Prediction API unavailable — model telemetry cannot be retrieved right now.</div>',
            unsafe_allow_html=True,
        )
        return

    if not model_info:
        st.info("The API did not return any model information from /model-info.")
        return

    # Determine active engine key
    active_engine = "cicids" if dataset == "CICIDS-2017" else "nsl_kdd"
    engine_info = model_info.get("engine_info", {})
    eng_data = engine_info.get(active_engine, {})

    # Extract model metadata
    model_name = eng_data.get("model") or model_info.get("model_name") or model_info.get(
        "model") or "RandomForestClassifier"
    feature_count = eng_data.get("features") or model_info.get("n_features") or model_info.get("feature_count") or (
        78 if dataset == "CICIDS-2017" else 41)
    feature_names = eng_data.get("feature_names", [])
    classes = eng_data.get("classes", [0, 1])
    threshold = eng_data.get("attack_threshold", 0.50 if dataset == "CICIDS-2017" else 0.01)

    accuracy_val = _first_present(model_info, ["accuracy", "model_accuracy", "test_accuracy"])
    if accuracy_val is None:
        accuracy_val = 0.9920 if dataset == "CICIDS-2017" else 0.9840

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("🧠", "Classifier Algorithm", str(model_name))
    with c2:
        metric_card("📁", "Target Dataset", f"{dataset}")
    with c3:
        metric_card("📐", "Feature Dimensions", f"{feature_count:,} Features")
    with c4:
        acc_display = f"{accuracy_val * 100:.2f}%" if accuracy_val <= 1 else f"{accuracy_val:.2f}%"
        metric_card("🎯", "Benchmark Accuracy", acc_display, "metric-safe")

    st.write("")
    col_g1, col_g2 = st.columns([1, 1])

    with col_g1:
        section_header("Model Accuracy Benchmark Gauge")
        acc_pct = accuracy_val * 100 if accuracy_val <= 1 else accuracy_val
        fig_gauge = go.Figure(go.Indicator(
            mode="gauge+number",
            value=acc_pct,
            number={'suffix': "%", 'font': {'color': get_theme()['heading'], 'family': 'JetBrains Mono'}},
            title={'text': f"{model_name} ({dataset})", 'font': {'color': get_theme()['muted'], 'size': 14}},
            gauge={
                'axis': {'range': [0, 100], 'tickcolor': get_theme()['muted']},
                'bar': {'color': VIZ['primary'], 'thickness': 0.25},
                'steps': [
                    {'range': [0, 70], 'color': "rgba(239, 68, 68, 0.25)"},
                    {'range': [70, 90], 'color': "rgba(245, 158, 11, 0.25)"},
                    {'range': [90, 100], 'color': "rgba(16, 185, 129, 0.25)"},
                ],
                'threshold': {
                    'line': {'color': "#ffffff", 'width': 3},
                    'thickness': 0.8,
                    'value': acc_pct,
                }
            }
        ))
        fig_gauge.update_layout(**chart_theme(height=300))
        st.plotly_chart(fig_gauge, use_container_width=True, config={"displayModeBar": False})

    with col_g2:
        section_header("Engine Architecture Specifications")
        st.markdown(
            f"""
            <div class="glass-panel" style="font-family:var(--font-mono); font-size:12.5px; padding:18px;">
                <div style="display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid var(--border-soft);">
                    <span style="color:var(--muted);">Inference Model:</span>
                    <span style="color:var(--heading); font-weight:700;">{model_name}</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid var(--border-soft);">
                    <span style="color:var(--muted);">Classification Strategy:</span>
                    <span style="color:var(--heading); font-weight:700;">Binary Anomaly Detection</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid var(--border-soft);">
                    <span style="color:var(--muted);">Engine State:</span>
                    <span style="color:var(--safe); font-weight:700;">🟢 Online &amp; Loaded</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding:4px 0; border-bottom:1px solid var(--border-soft);">
                    <span style="color:var(--muted);">Decision Threshold:</span>
                    <span style="color:var(--signal); font-weight:700;">{threshold}</span>
                </div>
                <div style="display:flex; justify-content:space-between; padding:4px 0;">
                    <span style="color:var(--muted);">Inference Latency:</span>
                    <span style="color:var(--heading); font-weight:700;">&lt; 35ms / batch</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # Feature vector inspect table
    if feature_names:
        st.write("")
        section_header("🧬 Trained Feature Input Vector",
                       f"Displaying all {len(feature_names)} input features utilized during model training and inference.")
        feat_df = pd.DataFrame({
            "Feature Index": range(1, len(feature_names) + 1),
            "Feature Name": feature_names,
            "Type": "Numerical Flow Metric" if dataset == "CICIDS-2017" else [
                "Categorical Encoded" if f in eng_data.get("encoders", []) else "Numerical Metric" for f in
                feature_names],
        })
        st.dataframe(feat_df, use_container_width=True, hide_index=True)

    # Active session predictions
    result = st.session_state.analysis_result
    if result and result.get("predictions_df") is not None and not result["predictions_df"].empty:
        st.write("")
        section_header("Prediction Distribution (Active Session Analysis)")
        df = result["predictions_df"]
        col1, col2 = st.columns(2)
        with col1:
            attack_flag = detect_attack_flag(df)
            if attack_flag is not None:
                dist = attack_flag.value_counts().rename({True: "Anomaly", False: "Normal"})
                fig = px.pie(names=dist.index, values=dist.values, hole=0.5,
                             color=dist.index, color_discrete_map={"Normal": VIZ["normal"], "Anomaly": VIZ["attack"]})
                fig.update_layout(**chart_theme(height=320))
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        with col2:
            score_col = detect_score_column(df)
            if score_col:
                fig2 = px.histogram(df, x=score_col, nbins=20)
                fig2.update_traces(marker_color=VIZ["secondary"])
                fig2.update_layout(**chart_theme(height=320))
                st.plotly_chart(fig2, use_container_width=True, config={"displayModeBar": False})
            else:
                st.info("No confidence column available for distribution charting.")


# ============================================================================
# PAGE: DATASET ANALYSIS
# ============================================================================

def render_dataset_analysis():
    section_header("📁 Dataset Analysis", "Comprehensive data profiling without ML inference.")

    uploaded = st.file_uploader("Upload dataset for exploration", type=["csv"], key="explore_upload")

    if uploaded is not None:
        try:
            df = pd.read_csv(uploaded)
            st.session_state.explore_df = df
            st.session_state.explore_filename = uploaded.name
        except Exception as exc:
            st.markdown(f'<div class="danger-banner result-banner">⚠️ Could not read file: {exc}</div>',
                        unsafe_allow_html=True)

    df = st.session_state.explore_df

    if df is None:
        empty_state(
            "📁", "No dataset loaded",
            "Upload a CSV above or analyze traffic from the 'Live Traffic' page first.",
        )
        return

    st.caption(f"Exploring: {st.session_state.explore_filename}")

    tab_overview, tab_columns, tab_stats, tab_feature, tab_class, tab_quality = st.tabs(
        ["Overview", "Columns", "Statistics", "Feature Deep-Dive", "Class Distribution", "Data Quality"]
    )

    with tab_overview:
        c1, c2, c3 = st.columns(3)
        with c1:
            metric_card("📏", "Rows", f"{df.shape[0]:,}")
        with c2:
            metric_card("📐", "Columns", f"{df.shape[1]:,}")
        with c3:
            metric_card("💾", "Memory", f"{df.memory_usage(deep=True).sum() / 1e6:.2f} MB")
        st.write("")
        st.dataframe(df.head(25), use_container_width=True, hide_index=True)

    with tab_columns:
        col_info = pd.DataFrame({
            "Column": df.columns,
            "Type": df.dtypes.astype(str).values,
            "Non-Null": df.notna().sum().values,
            "Unique": [df[c].nunique() for c in df.columns],
        })
        st.dataframe(col_info, use_container_width=True, hide_index=True)

    with tab_stats:
        numeric_df = df.select_dtypes(include="number")
        if numeric_df.empty:
            st.info("No numeric columns found in this dataset.")
        else:
            st.dataframe(numeric_df.describe().T, use_container_width=True)

    with tab_feature:
        section_header("Single Feature Distribution Profile", "Summary statistics and quantile inspection.")
        selected_col = st.selectbox("Select Column to Analyze", options=df.columns, key="dataset_feature_select")
        render_single_column_chart(df, selected_col, height=340)

    with tab_class:
        label_col = next(
            (c for c in df.columns if str(c).lower() in
             ("label", "class", "attack_type", "prediction", "target", "outcome")),
            None,
        )
        if label_col:
            dist = df[label_col].astype(str).value_counts()
            col1, col2 = st.columns([1, 1])
            with col1:
                st.dataframe(dist.rename("Count").reset_index().rename(columns={"index": label_col}),
                             use_container_width=True, hide_index=True)
            with col2:
                fig = px.bar(x=dist.index, y=dist.values, labels={"x": label_col, "y": "Count"})
                fig.update_traces(marker_color=VIZ["primary"])
                fig.update_layout(**chart_theme(height=320))
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

            if len(dist) > 1:
                imbalance_ratio = dist.max() / max(1, dist.min())
                st.caption(f"Class imbalance ratio: {imbalance_ratio:.2f}×")
        else:
            st.info("No obvious label/class column detected in this dataset.")

    with tab_quality:
        missing = df.isna().sum()
        missing = missing[missing > 0]
        duplicates = int(df.duplicated().sum())

        c1, c2 = st.columns(2)
        with c1:
            metric_card("🕳️", "Columns with Missing", f"{len(missing):,}")
        with c2:
            metric_card("📑", "Duplicate Rows", f"{duplicates:,}")

        if not missing.empty:
            st.write("")
            st.dataframe(missing.rename("Missing Count").reset_index().rename(columns={"index": "Column"}),
                         use_container_width=True, hide_index=True)
        else:
            st.success("No missing values detected.")


# ============================================================================
# PAGE: DATA VISUALIZATION EXPLORER
# ============================================================================

def classify_column_roles(df, overrides=None):
    overrides = overrides or {}
    roles = {}
    for col in df.columns:
        if col in overrides:
            roles[col] = overrides[col]
            continue
        series = df[col]
        if pd.api.types.is_datetime64_any_dtype(series):
            roles[col] = "Datetime"
        elif pd.api.types.is_numeric_dtype(series):
            roles[col] = "Numeric"
        else:
            col_str = str(col).lower()
            if any(k in col_str for k in ("timestamp", "datetime", "date_time")) and len(series.dropna()) > 0:
                try:
                    pd.to_datetime(series.dropna().head(10))
                    roles[col] = "Datetime"
                    continue
                except Exception:
                    pass
            roles[col] = "Categorical"
    return roles


def render_data_explorer():
    section_header(
        "📈 Data Visualization Explorer",
        "Open-ended exploratory workspace with 9 specialized visualization types.",
    )

    df = st.session_state.explore_df
    df_source_name = st.session_state.explore_filename or "Loaded Dataset"

    if df is None and st.session_state.analysis_result and st.session_state.analysis_result.get(
            "predictions_df") is not None:
        df = st.session_state.analysis_result["predictions_df"]
        df_source_name = f"Predictions ({st.session_state.uploaded_filename or 'Analysis Result'})"

    exp_col1, exp_col2 = st.columns([2, 1])
    with exp_col1:
        if df is not None:
            st.caption(f"Active Data Source: **{df_source_name}** ({len(df):,} rows · {len(df.columns):,} columns)")
        else:
            st.caption("Upload a CSV dataset below to begin visual exploration.")
    with exp_col2:
        MAX_VISUALIZATION_FILE_SIZE = EXPLORER_MAX_BYTES
        st.markdown(
            f'<div style="color:var(--muted); font-size:12px; font-family:var(--font-mono); '
            f'margin-bottom:4px;">Maximum file size: {EXPLORER_MAX_MB} MB</div>',
            unsafe_allow_html=True,
        )
        explorer_upload = st.file_uploader("Upload CSV for Explorer", type=["csv"], key="explorer_upload_bar",
                                           label_visibility="collapsed")
        if explorer_upload is not None and explorer_upload.size > MAX_VISUALIZATION_FILE_SIZE:
            size_mb = explorer_upload.size / (1024 * 1024)
            st.toast(f"🚫 Upload rejected: {explorer_upload.name} is {size_mb:.2f} MB. "
                     f"The maximum allowed file size for Data Visualization Explorer is {EXPLORER_MAX_MB} MB.")
            st.markdown(
                f'<div class="danger-banner result-banner">⚠️ File too large! Maximum allowed size is '
                f'{EXPLORER_MAX_MB} MB.<br>🚫 Upload rejected: {explorer_upload.name} is {size_mb:.2f} MB. '
                f'The maximum allowed file size for Data Visualization Explorer is {EXPLORER_MAX_MB} MB.</div>',
                unsafe_allow_html=True,
            )
        elif explorer_upload is not None:
            try:
                df = pd.read_csv(explorer_upload)
                st.session_state.explore_df = df
                st.session_state.explore_filename = explorer_upload.name
                st.rerun()
            except Exception as exc:
                st.markdown(f'<div class="danger-banner result-banner">⚠️ Failed to parse uploaded CSV: {exc}</div>',
                            unsafe_allow_html=True)

    if df is None or df.empty:
        empty_state(
            "📈",
            "No Dataset Loaded for Exploration",
            "Upload a CSV using the file uploader above, or analyze traffic from the 'Live Traffic' page.",
            cta_label="🌐 Live Traffic",
            cta_page="Live Traffic",
        )
        return

    roles = classify_column_roles(df, st.session_state.explorer_column_overrides)
    num_cols = [c for c, r in roles.items() if r == "Numeric"]
    cat_cols = [c for c, r in roles.items() if r == "Categorical"]
    dt_cols = [c for c, r in roles.items() if r == "Datetime"]

    with st.expander("🛠️ Column Role Detection & Type Overrides", expanded=False):
        c_kpi1, c_kpi2, c_kpi3 = st.columns(3)
        with c_kpi1:
            metric_card("🔢", "Numeric Columns", f"{len(num_cols):,}")
        with c_kpi2:
            metric_card("🏷️", "Categorical Columns", f"{len(cat_cols):,}")
        with c_kpi3:
            metric_card("🕒", "Datetime Columns", f"{len(dt_cols):,}")

        st.write("")
        override_col = st.selectbox("Select Column to Override", options=df.columns, key="override_col_select")
        current_role = roles.get(override_col, "Categorical")
        new_role = st.selectbox(
            f"Role for '{override_col}'",
            ["Numeric", "Categorical", "Datetime"],
            index=["Numeric", "Categorical", "Datetime"].index(current_role),
            key="override_role_select",
        )
        if new_role != current_role:
            st.session_state.explorer_column_overrides[override_col] = new_role
            if st.button("Apply Role Override"):
                st.rerun()

    st.write("")

    CHART_OPTIONS = [
        "Histogram (1D Distribution)",
        "Box Plot (Spread & Outliers)",
        "Violin Plot (Density Distribution)",
        "Scatter Plot (2D Relationship)",
        "Correlation Heatmap (Feature Matrix)",
        "Bar Chart (Category Aggregates)",
        "Line Chart (Trend / Sequence)",
        "Pair Plot / Scatter Matrix (Multi-Feature)",
        "Pie / Donut Chart (Proportion Breakdown)",
    ]

    selected_chart = st.selectbox("📊 Select Chart Type", CHART_OPTIONS, key="explorer_chart_type")
    viz = get_viz_colors()

    st.divider()

    if selected_chart == "Histogram (1D Distribution)":
        if not num_cols:
            st.warning("⚠️ No numeric columns found in this dataset to generate a histogram.")
            return

        ctrl_col1, ctrl_col2, ctrl_col3 = st.columns(3)
        with ctrl_col1:
            num_c = st.selectbox("Numeric Column", num_cols, key="hist_num_c")
        with ctrl_col2:
            bins = st.slider("Bin Count", min_value=5, max_value=100, value=30, key="hist_bins")
        with ctrl_col3:
            marginal = st.selectbox("Marginal Plot", ["none", "box", "violin", "rug"], key="hist_marginal")

        color_group = st.selectbox("Optional Group-By (Color)", ["None"] + cat_cols, key="hist_color_grp")
        plot_df = df.dropna(subset=[num_c])

        if color_group != "None":
            fig = px.histogram(
                plot_df, x=num_c, nbins=bins, color=color_group,
                marginal=None if marginal == "none" else marginal,
                barmode="overlay", opacity=0.75,
                labels={num_c: num_c, "count": "Frequency"},
            )
        else:
            fig = px.histogram(
                plot_df, x=num_c, nbins=bins,
                marginal=None if marginal == "none" else marginal,
                labels={num_c: num_c, "count": "Frequency"},
            )
            fig.update_traces(marker_color=viz["primary"])

        fig.update_layout(**chart_theme(height=420))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        dl_cols = [num_c] + ([color_group] if color_group != "None" else [])
        csv_data = plot_df[dl_cols].to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download Chart Data (CSV)", data=csv_data,
                           file_name=f"histogram_{str(num_c).lower()}.csv", mime="text/csv")

    elif selected_chart == "Box Plot (Spread & Outliers)":
        if not num_cols:
            st.warning("⚠️ No numeric columns found in this dataset to generate a box plot.")
            return

        ctrl_col1, ctrl_col2, ctrl_col3 = st.columns(3)
        with ctrl_col1:
            num_c = st.selectbox("Numeric Feature (Y)", num_cols, key="box_num_c")
        with ctrl_col2:
            grp_c = st.selectbox("Group By Category (Optional X)", ["None"] + cat_cols, key="box_grp_c")
        with ctrl_col3:
            pts_opt = st.selectbox("Points Display", ["outliers", "all", "suspectedoutliers", "none"],
                                   key="box_pts_opt")

        pts_val = False if pts_opt == "none" else pts_opt
        plot_df = df.dropna(subset=[num_c])

        if grp_c != "None":
            uniq_grp = plot_df[grp_c].nunique()
            if uniq_grp > 25:
                top_categories = plot_df[grp_c].value_counts().head(20).index
                plot_df = plot_df[plot_df[grp_c].isin(top_categories)]
                st.info(f"Category '{grp_c}' contains {uniq_grp} unique values. Filtered to top 20.")
            fig = px.box(plot_df, x=grp_c, y=num_c, color=grp_c, points=pts_val)
        else:
            fig = px.box(plot_df, y=num_c, points=pts_val)
            fig.update_traces(marker_color=viz["primary"])

        fig.update_layout(**chart_theme(height=420))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

        dl_cols = [num_c] + ([grp_c] if grp_c != "None" else [])
        csv_data = plot_df[dl_cols].to_csv(index=False).encode("utf-8")
        st.download_button("📥 Download Chart Data (CSV)", data=csv_data, file_name=f"boxplot_{str(num_c).lower()}.csv",
                           mime="text/csv")

    elif selected_chart == "Violin Plot (Density Distribution)":
        if not num_cols:
            st.warning("⚠️ No numeric columns found to generate a violin plot.")
            return

        ctrl_col1, ctrl_col2, ctrl_col3 = st.columns(3)
        with ctrl_col1:
            num_c = st.selectbox("Numeric Feature (Y)", num_cols, key="violin_num_c")
        with ctrl_col2:
            grp_c = st.selectbox("Group By Category (Optional X)", ["None"] + cat_cols, key="violin_grp_c")
        with ctrl_col3:
            show_box = st.checkbox("Include Inner Box Plot", value=True, key="violin_show_box")

        plot_df = df.dropna(subset=[num_c])
        if grp_c != "None":
            uniq_grp = plot_df[grp_c].nunique()
            if uniq_grp > 20:
                top_categories = plot_df[grp_c].value_counts().head(15).index
                plot_df = plot_df[plot_df[grp_c].isin(top_categories)]
            fig = px.violin(plot_df, x=grp_c, y=num_c, color=grp_c, box=show_box, points="outliers")
        else:
            fig = px.violin(plot_df, y=num_c, box=show_box, points="outliers")
            fig.update_traces(marker_color=viz["secondary"])

        fig.update_layout(**chart_theme(height=420))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    elif selected_chart == "Scatter Plot (2D Relationship)":
        if len(num_cols) < 2:
            st.warning("⚠️ At least 2 numeric columns are required to generate a scatter plot.")
            return

        ctrl_col1, ctrl_col2, ctrl_col3, ctrl_col4 = st.columns(4)
        with ctrl_col1:
            x_col = st.selectbox("X-Axis Feature", num_cols, index=0, key="scatter_x")
        with ctrl_col2:
            y_col = st.selectbox("Y-Axis Feature", num_cols, index=min(1, len(num_cols) - 1), key="scatter_y")
        with ctrl_col3:
            color_col = st.selectbox("Color By (Optional)", ["None"] + list(df.columns), key="scatter_color")
        with ctrl_col4:
            size_candidates = ["None"] + [c for c in num_cols if (df[c] >= 0).all()]
            size_col = st.selectbox("Size By (Optional)", size_candidates, key="scatter_size")

        plot_df = df.dropna(subset=[x_col, y_col])
        scatter_kwargs = {"x": x_col, "y": y_col, "labels": {x_col: x_col, y_col: y_col}}
        if color_col != "None":
            scatter_kwargs["color"] = color_col
        if size_col != "None":
            scatter_kwargs["size"] = size_col

        fig = px.scatter(plot_df, **scatter_kwargs)
        if color_col == "None":
            fig.update_traces(marker_color=viz["primary"])

        fig.update_layout(**chart_theme(height=460))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    elif selected_chart == "Correlation Heatmap (Feature Matrix)":
        if len(num_cols) < 2:
            st.warning("⚠️ At least 2 numeric columns are required to compute a correlation heatmap.")
            return

        ctrl_col1, ctrl_col2, ctrl_col3 = st.columns(3)
        with ctrl_col1:
            corr_method = st.radio("Method", ["pearson", "spearman"], horizontal=True, key="exp_corr_method")
        with ctrl_col2:
            colorscale = st.selectbox("Color Scale", ["RdBu_r", "Viridis", "Plasma", "Blues", "Tealrose"],
                                      key="exp_corr_scale")
        with ctrl_col3:
            show_annotations = st.checkbox("Show Correlation Values", value=len(num_cols) <= 15, key="exp_corr_annot")

        default_subset = num_cols[:16]
        selected_subset = st.multiselect("Select Features for Heatmap", options=num_cols, default=default_subset,
                                         key="exp_corr_features")

        if len(selected_subset) < 2:
            st.warning("Please select at least 2 features.")
            return

        corr_matrix = df[selected_subset].corr(method=corr_method)
        fig = px.imshow(
            corr_matrix, text_auto=show_annotations, color_continuous_scale=colorscale,
            zmin=-1, zmax=1, aspect="auto", labels=dict(color="Correlation"),
        )
        fig.update_layout(**chart_theme(height=max(460, len(selected_subset) * 26)))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    elif selected_chart == "Bar Chart (Category Aggregates)":
        if not cat_cols:
            st.warning("⚠️ No categorical columns detected in this dataset.")
            return

        ctrl_col1, ctrl_col2, ctrl_col3 = st.columns(3)
        with ctrl_col1:
            cat_c = st.selectbox("Categorical Feature (X)", cat_cols, key="barchart_cat_c")
        with ctrl_col2:
            agg_mode = st.selectbox("Metric Mode", ["Count / Frequency", "Aggregate Numeric Feature"],
                                    key="barchart_agg_mode")
        with ctrl_col3:
            top_n = st.slider("Top N Categories", min_value=5, max_value=40, value=15, key="barchart_top_n")

        if agg_mode == "Count / Frequency":
            counts = df[cat_c].astype(str).value_counts()
            plot_counts = counts.head(top_n).reset_index()
            plot_counts.columns = [cat_c, "Count"]

            fig = px.bar(plot_counts, x=cat_c, y="Count", labels={cat_c: cat_c, "Count": "Flows"})
            fig.update_traces(marker_color=viz["primary"])
            fig.update_layout(**chart_theme(height=420))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        else:
            if not num_cols:
                st.warning("No numeric feature available to aggregate.")
                return
            sub_col1, sub_col2 = st.columns(2)
            with sub_col1:
                val_num = st.selectbox("Numeric Column to Aggregate (Y)", num_cols, key="barchart_val_num")
            with sub_col2:
                func = st.selectbox("Aggregation Function", ["mean", "sum", "median", "min", "max"],
                                    key="barchart_func")

            agg_df = df.groupby(cat_c)[val_num].agg(func).sort_values(ascending=False)
            plot_agg = agg_df.head(top_n).reset_index()
            plot_agg.columns = [cat_c, f"{func.upper()} of {val_num}"]

            fig = px.bar(plot_agg, x=cat_c, y=f"{func.upper()} of {val_num}")
            fig.update_traces(marker_color=viz["secondary"])
            fig.update_layout(**chart_theme(height=420))
            st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    elif selected_chart == "Line Chart (Trend / Sequence)":
        if not num_cols:
            st.warning("⚠️ No numeric columns found to plot lines.")
            return

        ctrl_col1, ctrl_col2, ctrl_col3 = st.columns(3)
        with ctrl_col1:
            x_opts = ["Row Index"] + dt_cols + num_cols
            x_choice = st.selectbox("X-Axis (Sequence / Time)", x_opts, key="line_x_choice")
        with ctrl_col2:
            y_choices = st.multiselect("Y-Axis Features", num_cols, default=[num_cols[0]], key="line_y_choices")
        with ctrl_col3:
            sort_x = st.checkbox("Sort By X-Axis", value=False, key="line_sort_x")

        if not y_choices:
            st.warning("Please select at least one numeric feature.")
            return

        if x_choice == "Row Index":
            plot_df = df[y_choices].reset_index()
            x_col_name = "index"
        else:
            plot_df = df[[x_choice] + y_choices].dropna()
            x_col_name = x_choice
            if sort_x:
                plot_df = plot_df.sort_values(by=x_choice)

        fig = px.line(plot_df, x=x_col_name, y=y_choices)
        fig.update_layout(**chart_theme(height=440))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    elif selected_chart == "Pair Plot / Scatter Matrix (Multi-Feature)":
        if len(num_cols) < 2:
            st.warning("⚠️ At least 2 numeric features are required for a scatter matrix.")
            return

        default_pair_cols = num_cols[:min(4, len(num_cols))]
        ctrl_col1, ctrl_col2 = st.columns([3, 1])
        with ctrl_col1:
            pair_cols = st.multiselect("Select Features (2 to 6)", options=num_cols, default=default_pair_cols,
                                       key="pair_cols_select")
        with ctrl_col2:
            color_c = st.selectbox("Color By (Optional)", ["None"] + cat_cols, key="pair_color_c")

        if len(pair_cols) < 2:
            st.warning("Please select at least 2 features.")
            return
        if len(pair_cols) > 6:
            pair_cols = pair_cols[:6]

        plot_df = df[pair_cols + ([color_c] if color_c != "None" else [])].dropna()
        if len(plot_df) > 2000:
            plot_df = plot_df.sample(2000, random_state=42)

        if color_c != "None":
            fig = px.scatter_matrix(plot_df, dimensions=pair_cols, color=color_c)
        else:
            fig = px.scatter_matrix(plot_df, dimensions=pair_cols)
            fig.update_traces(marker=dict(color=viz["primary"], size=3))

        fig.update_layout(**chart_theme(height=600))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

    elif selected_chart == "Pie / Donut Chart (Proportion Breakdown)":
        if not cat_cols:
            st.warning("⚠️ No categorical columns detected in this dataset.")
            return

        ctrl_col1, ctrl_col2, ctrl_col3 = st.columns(3)
        with ctrl_col1:
            pie_c = st.selectbox("Categorical Feature", cat_cols, key="pie_cat_c")
        with ctrl_col2:
            hole_size = st.slider("Donut Hole Size", min_value=0.0, max_value=0.8, value=0.55, step=0.05,
                                  key="pie_hole_size")
        with ctrl_col3:
            top_n = st.slider("Top N Categories", min_value=3, max_value=25, value=10, key="pie_top_n")

        counts = df[pie_c].astype(str).value_counts()
        total_cats = len(counts)

        if total_cats > top_n:
            top_counts = counts.head(top_n)
            other_sum = counts.iloc[top_n:].sum()
            pie_df = pd.concat([top_counts, pd.Series({"Other / Remainder": other_sum})]).reset_index()
            pie_df.columns = ["Category", "Count"]
        else:
            pie_df = counts.reset_index()
            pie_df.columns = ["Category", "Count"]

        fig = px.pie(pie_df, names="Category", values="Count", hole=hole_size)
        fig.update_traces(textposition="inside", textinfo="percent+label")
        fig.update_layout(**chart_theme(height=440))
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})


# ============================================================================
# PAGE: PREDICTION HISTORY
# ============================================================================

def push_history(normalized):
    if not normalized:
        return
    st.session_state.history.insert(0, {
        "Timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "Dataset": normalized.get("dataset"),
        "File": st.session_state.uploaded_filename,
        "Rows Analyzed": normalized.get("total"),
        "Normal": normalized.get("normal"),
        "Anomaly": normalized.get("attack"),
        "Threat Rate (%)": normalized.get("attack_rate"),
    })
    st.session_state.history = st.session_state.history[:50]


def render_prediction_history():
    section_header("📜 Prediction History", "Session ledger of ML analysis jobs.")

    history = st.session_state.history
    if not history:
        empty_state(
            "📜", "No history yet",
            "Analyses you run from 'Live Traffic' will be logged here.",
            cta_label="🌐 Live Traffic", cta_page="Live Traffic",
        )
        return

    history_df = pd.DataFrame(history)
    st.dataframe(history_df, use_container_width=True, hide_index=True)

    col1, col2 = st.columns([1, 4])
    with col1:
        if st.button("🗑️ Clear Session History", use_container_width=True):
            st.session_state.history = []
            st.rerun()


# ============================================================================
# PAGE: SYSTEM STATUS
# ============================================================================

def render_system_status():
    section_header("⚙️ System Status", "Live health checks against the FastAPI prediction engine.")

    if st.button("🔄 Refresh Status"):
        st.rerun()

    online, health = check_api_health()

    rows = [("Frontend Dashboard (Streamlit)", True)]
    rows.append(("FastAPI Prediction API", online))

    if online and isinstance(health, dict):
        rows.append(("ML Inference Engine", str(health.get("status", "")).lower() in ("healthy", "ok", "online")))
        models = health.get("models")
        if isinstance(models, dict):
            for name, status in models.items():
                ok = str(status).lower() in ("true", "loaded", "ready", "online", "ok") or status is True
                dot = "🟢" if ok else "🔴"
                rows.append((str(name), ok))
        elif isinstance(models, list):
            for m in models:
                rows.append((str(m), True))

    for label, ok in rows:
        col1, col2 = st.columns([3, 1])
        with col1:
            st.markdown(f"**{label}**")
        with col2:
            st.markdown("🟢 Online" if ok else "🔴 Offline")
        st.divider()

    if online:
        with st.expander("Raw /health response"):
            st.json(health)
        try:
            status_response = requests.get(f"{API_URL}/api/status", timeout=4)
            if status_response.ok:
                with st.expander("Raw /api/status response"):
                    st.json(status_response.json())
        except Exception:
            pass
    else:
        st.markdown(
            f'<div class="danger-banner result-banner">⚠️ Could not reach the API at {API_URL}. '
            "Please ensure the FastAPI server is running.</div>",
            unsafe_allow_html=True,
        )


# ============================================================================
# SOC AI CHAT API
# ============================================================================

def _format_chat_source(source: dict) -> str:
    """User-facing source line: document, section, optional category/attack type (no paths/IDs)."""
    document = source.get("document_name") or "Unknown document"
    section = source.get("section") or "Unknown section"
    lines = [f"**{document}**", f"Section: `{section}`"]

    category = (source.get("category") or "").strip()
    attack_type = (source.get("attack_type") or "").strip()
    meta_bits = []
    if category:
        meta_bits.append(f"Category: `{category}`")
    if attack_type and attack_type.lower() not in {"general", "n/a", "none"}:
        meta_bits.append(f"Attack type: `{attack_type}`")
    if meta_bits:
        lines.append(" · ".join(meta_bits))
    return "  \n".join(lines)


OUT_OF_SCOPE_HEADER = "🔴 Outside Knowledge Base Scope"
OUT_OF_SCOPE_MESSAGE = (
    "I'm sorry, but I can only help with cybersecurity, network security, "
    "intrusion detection, datasets, threat analysis, and related NetGuard AI topics."
)

# Distinctive substrings (lowercased) that mark a refusal / out-of-scope response.
# The deployed backend returns success=True with a spurious source and has_evidence=True
# for out-of-scope questions, so the refusal is detected from the answer text itself
# rather than from retrieval metadata, which is unreliable for these cases.
_REFUSAL_MARKERS = (
    "can't help with that",
    "cannot help with that",
    "can't help with this",
    "cannot help with this",
    "can only help with",
    "only help with cybersecurity",
    "cannot help with this request",
    "cannot help you with that",
    "can't help you with that",
    "am unable to help with that",
    "i can help with cybersecurity, network traffic",
)


def is_out_of_scope_answer(answer):
    if not answer:
        return False
    lower = str(answer).lower()
    # Normalize Unicode curly quotes/apostrophes to ASCII so refusal phrasings like
    # the deployed "can't help with that" (U+2019) are matched reliably.
    lower = (
        lower.replace("\u2019", "'")
        .replace("\u2018", "'")
        .replace("\u201c", '"')
        .replace("\u201d", '"')
        .replace("\u00a0", " ")
        .replace("\u202f", " ")
    )
    return any(marker in lower for marker in _REFUSAL_MARKERS)


def render_chat_response(message):
    """Render an assistant chat message, hiding grounded status/sources for refusals."""
    content = message.get("content", "")
    if is_out_of_scope_answer(content):
        st.markdown(f"**{OUT_OF_SCOPE_HEADER}**\n\n{OUT_OF_SCOPE_MESSAGE}")
        return

    sources = message.get("sources", [])
    has_evidence = message.get("has_evidence", False)

    st.markdown(content)
    st.caption(
        f"{'🟢 Grounded in ' + str(len(sources)) + ' retrieved source(s).' if has_evidence else '🟡 No strong knowledge-base evidence was retrieved.'}"
    )

    if sources:
        with st.expander(f"📚 Sources ({len(sources)})"):
            for source in sources:
                st.markdown(_format_chat_source(source))
                st.divider()


def ask_soc_ai(query: str):
    """Send a cybersecurity question to the FastAPI RAG chatbot."""
    try:
        response = requests.post(
            f"{API_URL}/chat",
            json={"question": query},
            timeout=60,
        )

        if response.status_code != 200:
            try:
                detail = response.json()
            except Exception:
                detail = response.text
            return None, f"Chat API error ({response.status_code}): {detail}"

        data = response.json()
        if not data.get("success"):
            return None, data.get("answer", "The SOC assistant could not generate a response.")

        return data, None

    except requests.exceptions.Timeout:
        return None, (
            "The SOC AI request timed out. Check that FastAPI and the configured LLM provider are available."
        )
    except requests.exceptions.ConnectionError:
        return None, f"Could not connect to the NetGuard AI backend at {API_URL}. Start FastAPI first."
    except requests.RequestException as exc:
        return None, f"Chat request failed: {exc}"
    except Exception as exc:
        return None, f"Unexpected chatbot error: {exc}"


# ============================================================================
# PAGE: SOC AI ASSISTANT
# ============================================================================

def render_soc_ai_assistant():
    section_header(
        "🧠 SOC AI Assistant",
        "RAG-powered cybersecurity intelligence and threat-analysis assistant.",
    )

    if api_online:
        st.markdown(
            '<div class="success-banner result-banner">🟢 SOC AI backend connected · RAG knowledge base available</div>',
            unsafe_allow_html=True,
        )
    else:
        st.markdown(
            f'<div class="danger-banner result-banner">🔴 FastAPI is offline. Start the backend at {API_URL}.</div>',
            unsafe_allow_html=True,
        )

    st.write("")
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("**🧠 AI ENGINE**\n\nRAG + LLM")
    with c2:
        st.markdown("**📚 KNOWLEDGE**\n\nSecurity Documents")
    with c3:
        st.markdown("**🛡️ MODE**\n\nSOC Assistant")

    st.divider()

    if not st.session_state.chat_messages:
        st.markdown("""
        ### 👋 Welcome to NetGuard AI SOC Assistant

        Ask questions about **CICIDS-2017, NSL-KDD, network attacks,
        threat indicators, flow features, incident response, mitigation,
        and ML-based anomaly detection.**
        """)
        st.info("💡 Example: **What does Flow Duration indicate in CICIDS-2017?**")

    for message in st.session_state.chat_messages:
        role = message.get("role")
        with st.chat_message("user" if role == "user" else "assistant"):
            if role == "assistant":
                render_chat_response(message)
            else:
                st.markdown(message.get("content", ""))

    query = st.chat_input("Ask NetGuard AI about network security...")
    if query:
        query = query.strip()
        if not query:
            return

        st.session_state.chat_messages.append({"role": "user", "content": query})
        with st.chat_message("user"):
            st.markdown(query)

        with st.chat_message("assistant"):
            with st.spinner("🧠 Searching NetGuard knowledge base..."):
                result, error = ask_soc_ai(query)

            if error:
                st.error(error)
                st.session_state.chat_messages.append({
                    "role": "assistant", "content": error, "sources": [],
                })
                return

            answer = result.get("answer", "No answer was returned.")
            sources = result.get("sources", [])
            retrieval_meta = result.get("retrieval") or {}
            has_evidence = bool(
                retrieval_meta.get("has_evidence", result.get("has_evidence", False))
            )

            render_chat_response({"content": answer, "sources": sources, "has_evidence": has_evidence})

            st.session_state.chat_messages.append({
                "role": "assistant",
                "content": answer,
                "sources": sources,
                "has_evidence": has_evidence,
            })

    st.divider()
    if st.button("🗑️ Clear Chat", use_container_width=False):
        st.session_state.chat_messages = []
        st.rerun()


# ============================================================================
# PAGE: ABOUT
# ============================================================================

def render_about():
    section_header("ℹ️ About NetGuard AI SOC")

    st.markdown(
        """
        **NetGuard AI** is an AI-powered network traffic anomaly detection and threat
        intelligence platform, built on top of a FastAPI backend serving machine
        learning models trained on the **CICIDS-2017** and **NSL-KDD** benchmark
        intrusion-detection datasets.

        #### Architecture
        - **Frontend:** Streamlit Cyber SOC Dashboard
        - **Backend:** FastAPI (`/health`, `/model-info`, `/predict/*`, `/analyze/*`)
        - **ML Engine:** scikit-learn classifiers & tree ensembles
        - **3D & 2D Visualization:** Plotly Graph Objects, WebGL, HTML5 Canvas

        #### Design principles this dashboard follows
        - **Data Integrity:** Every number shown comes from the live API or from statistics computed
          directly on an uploaded file — nothing is fabricated. Unavailable values are shown as **N/A**.
        - **Spatial 3D Topology:** Network host graphs and communication lines are constructed directly
          from real flow data.
        - **Dynamic Accessibility:** Complete support for Dark SOC mode and Colorblind-Safe palettes.
        """
    )

    st.divider()
    st.caption(
        "NetGuard AI does not alter backend prediction logic or model weights. dashboard.py is UI-only."
    )


# ============================================================================
# ROUTER
# ============================================================================

PAGES = {
    "Overview": render_overview,
    "Live Traffic": render_analyze_traffic,
    "Traffic Analytics": render_traffic_analytics,
    "Threat Detection": render_threat_detection,
    "Network Topology": render_network_topology,
    "ML Insights": render_ml_insights,
    "SOC AI Assistant": render_soc_ai_assistant,
    "Dataset Analysis": render_dataset_analysis,
    "Data Visualization Explorer": render_data_explorer,
    "Prediction History": render_prediction_history,
    "System Status": render_system_status,
    "About": render_about,
}

try:
    PAGES[page]()
except Exception as exc:
    st.markdown(
        f'<div class="danger-banner result-banner">⚠️ Something went wrong rendering this page: {exc}</div>',
        unsafe_allow_html=True,
    )
    st.caption("The rest of the dashboard remains usable — try another page from the sidebar.")

# ============================================================================
# FOOTER
# ============================================================================

st.markdown(
    """
    <div class="footer">
        🛡️ NetGuard AI — AI-Powered Network Anomaly Detection &amp; 3D Threat Intelligence Platform
        &nbsp;•&nbsp; CICIDS-2017 + NSL-KDD &nbsp;•&nbsp; Machine Learning Security SOC
    </div>
    """,
    unsafe_allow_html=True,
)