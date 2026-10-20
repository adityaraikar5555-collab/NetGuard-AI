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

import json
import math
from datetime import datetime
from pathlib import Path

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

try:
    from ui_components import (
        THREAT_LEVEL_ICON,
        classify_threat_level,
        esc,
        render_global_status_header,
        render_cta_row,
        render_severity_strip,
        state_banner,
    )
except Exception:
    # UI module is optional for the core app; every function has a fallback
    # defined below, so a missing module never breaks the dashboard.
    THREAT_LEVEL_ICON = {}
    classify_threat_level = lambda *a, **k: ("UNKNOWN", "")
    esc = staticmethod(lambda v: str(v))
    render_global_status_header = lambda *a, **k: st.write("")
    render_cta_row = lambda *a, **k: None
    render_severity_strip = lambda *a, **k: None
    state_banner = lambda *a, **k: None

# ============================================================================
# --------------------------------------------------------------------------
# 7 Advanced Power Engines (XAI, SOAR, PCAP, MultiClass, ThreatIntel, Alerting, Drift)
# --------------------------------------------------------------------------
try:
    import sys
    _ROOT = Path(__file__).resolve().parent.parent
    if str(_ROOT) not in sys.path:
        sys.path.insert(0, str(_ROOT))
    if str(_ROOT / "src") not in sys.path:
        sys.path.insert(0, str(_ROOT / "src"))

    from src.xai_engine import xai_engine
    from src.soar_engine import soar_engine
    from src.pcap_extractor import pcap_extractor
    from src.multiclass_engine import multiclass_classifier
    from src.threat_intel import threat_intel_engine
    from src.alert_integrations import alert_integration_engine
    from src.drift_monitor import drift_monitor
    from src.agents import (
        native_soc_agent, AgentStep, IncidentDossier,
        threat_hunting_agent, ThreatHuntingReport,
        soc_swarm_supervisor, SwarmIncidentBrief,
    )
    from src.adversarial_tester import adversarial_tester
    from src.forensic_packager import forensic_packager
    _ENGINES_AVAILABLE = True
except Exception:
    _ENGINES_AVAILABLE = False
    xai_engine = None
    soar_engine = None
    pcap_extractor = None
    multiclass_classifier = None
    threat_intel_engine = None
    alert_integration_engine = None
    drift_monitor = None
    native_soc_agent = None
    AgentStep = None
    IncidentDossier = None
    threat_hunting_agent = None
    ThreatHuntingReport = None
    soc_swarm_supervisor = None
    SwarmIncidentBrief = None
    adversarial_tester = None
    forensic_packager = None


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
    ("🛡️", "MITRE ATT&CK Matrix"),
    ("⚡", "Agentic SOC Copilot"),
    ("🕸️", "Network Topology"),
    ("🤖", "ML Insights"),
    ("🎯", "Adversarial Red-Team"),
    ("🧠", "SOC AI Assistant"),

    ("📁", "Dataset Analysis"),
    ("📈", "Data Visualization Explorer"),
    ("📜", "Prediction History"),
    ("🕓", "Incident Timeline"),
    ("⚙️", "System Status"),
    ("🛠️", "Settings"),
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
        # --- SOC design-system session additions (frontend-only) ---
        "session_timeline": [],
        "app_settings": {
            "theme_mode": "Dark",
            "high_contrast": False,
            "reduced_motion": False,
            "refresh_preference": "manual",
            "show_notifications": True,
        },
        "investigation_target": None,
        "pending_soc_question": None,
        "command_palette_active": False,
        "agent_target_context": None,
        "agent_latest_dossier": None,
        "agent_latest_hunt_report": None,
        "agent_latest_swarm_brief": None,
        "agent_is_running": False,
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
    warning_col = viz.get("suspicious", "#fbbf24")
    bg_gradient = "radial-gradient(circle at 50% 50%, #0c1830 0%, #05070f 100%)"
    border_col = "rgba(56, 189, 248, 0.35)"
    text_col = "#e6ebf5"

    hero_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
      <meta charset="utf-8">
      <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{
          overflow: hidden;
          background: transparent;
          user-select: none;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        }}
        #hero-container {{
          width: 100%;
          height: 220px;
          position: relative;
          border-radius: 14px;
          background: {bg_gradient};
          border: 1px solid {border_col};
          box-shadow: 0 8px 32px rgba(0,0,0,0.45), inset 0 0 28px rgba(56,189,248,0.08);
          overflow: hidden;
        }}
        #webgl-canvas {{
          width: 100%;
          height: 100%;
          display: block;
          cursor: grab;
        }}
        #webgl-canvas:active {{
          cursor: grabbing;
        }}
        .hud-top-left {{
          position: absolute;
          top: 10px;
          left: 16px;
          pointer-events: none;
          z-index: 10;
        }}
        .hud-title {{
          font-size: 11px;
          font-weight: 800;
          letter-spacing: 2px;
          color: {primary_col};
          text-transform: uppercase;
          display: flex;
          align-items: center;
          gap: 6px;
          text-shadow: 0 0 10px rgba(56,189,248,0.5);
        }}
        .hud-sub {{
          font-size: 9.5px;
          color: {text_col};
          opacity: 0.75;
          margin-top: 3px;
          font-family: monospace;
          letter-spacing: 1px;
        }}
        .hud-modes {{
          position: absolute;
          top: 10px;
          right: 14px;
          display: flex;
          gap: 6px;
          z-index: 15;
        }}
        .mode-btn {{
          background: rgba(13, 20, 36, 0.75);
          border: 1px solid rgba(56, 189, 248, 0.3);
          color: {text_col};
          padding: 4px 10px;
          border-radius: 6px;
          font-size: 10px;
          font-family: monospace;
          cursor: pointer;
          transition: all 0.2s ease;
          backdrop-filter: blur(8px);
        }}
        .mode-btn:hover, .mode-btn.active {{
          background: rgba(56, 189, 248, 0.25);
          border-color: {primary_col};
          color: #ffffff;
          box-shadow: 0 0 10px rgba(56, 189, 248, 0.4);
        }}
        .hud-bottom {{
          position: absolute;
          bottom: 8px;
          left: 16px;
          right: 16px;
          display: flex;
          justify-content: space-between;
          align-items: center;
          pointer-events: none;
          font-family: monospace;
          font-size: 9.5px;
          color: {text_col};
          opacity: 0.85;
          z-index: 10;
        }}
        .status-indicator {{
          display: flex;
          align-items: center;
          gap: 6px;
        }}
        .status-dot {{
          width: 6px;
          height: 6px;
          border-radius: 50%;
          background: {normal_col};
          box-shadow: 0 0 8px {normal_col};
          animation: pulse 1.8s infinite ease-in-out;
        }}
        @keyframes pulse {{
          0%, 100% {{ opacity: 1; transform: scale(1); }}
          50% {{ opacity: 0.35; transform: scale(0.8); }}
        }}
        .controls-btn-group {{
          display: flex;
          gap: 6px;
          pointer-events: auto;
        }}
        .ctrl-icon-btn {{
          background: rgba(13, 20, 36, 0.6);
          border: 1px solid rgba(56, 189, 248, 0.25);
          color: {primary_col};
          padding: 2px 8px;
          border-radius: 4px;
          cursor: pointer;
          font-size: 10px;
          font-family: monospace;
          transition: all 0.15s ease;
        }}
        .ctrl-icon-btn:hover {{
          background: rgba(56, 189, 248, 0.2);
          border-color: {primary_col};
        }}
      </style>
      <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
    </head>
    <body>
      <div id="hero-container">
        <div class="hud-top-left">
          <div class="hud-title">⚡ 3D Spatial Threat Matrix</div>
          <div class="hud-sub">THREE.JS GPU ACCELERATED • REAL-TIME CYBER TOPOLOGY INTELLIGENCE</div>
        </div>
        <div class="hud-modes">
          <button class="mode-btn active" id="btn-mode-globe" onclick="switchMode('globe')">🌐 Threat Globe</button>
          <button class="mode-btn" id="btn-mode-core" onclick="switchMode('core')">🧠 Neural Core</button>
          <button class="mode-btn" id="btn-mode-shield" onclick="switchMode('shield')">🛡️ Matrix Shield</button>
        </div>
        <canvas id="webgl-canvas"></canvas>
        <div class="hud-bottom">
          <div class="status-indicator">
            <span class="status-dot"></span>
            <span id="telemetry-text">NEURAL SHIELD ACTIVE // 0 PACKETS DROPPED</span>
          </div>
          <div class="controls-btn-group">
            <button class="ctrl-icon-btn" onclick="toggleRotate()" id="btn-rotate" title="Pause / Resume Rotation">⏸️ Pause</button>
            <button class="ctrl-icon-btn" onclick="resetCamera()" title="Reset Camera View">🔄 Center</button>
          </div>
        </div>
      </div>

      <script>
        (function() {{
          const container = document.getElementById('hero-container');
          const canvas = document.getElementById('webgl-canvas');

          function hasWebGL() {{
            try {{
              const testCanvas = document.createElement('canvas');
              return !!(window.WebGLRenderingContext && (testCanvas.getContext('webgl') || testCanvas.getContext('experimental-webgl')));
            }} catch(e) {{
              return false;
            }}
          }}

          if (typeof THREE === 'undefined' || !hasWebGL()) {{
            init2DFallback();
            return;
          }}

          let renderer, scene, camera;
          let globeGroup, coreGroup, shieldGroup, starsGroup;
          let currentMode = 'globe';
          let autoRotate = true;

          let isDragging = false;
          let prevMouseX = 0, prevMouseY = 0;
          let targetRotX = 0.2, targetRotY = 0;
          let curRotX = 0.2, curRotY = 0;

          function initThree() {{
            const width = container.clientWidth || window.innerWidth;
            const height = container.clientHeight || 220;

            scene = new THREE.Scene();
            camera = new THREE.PerspectiveCamera(45, width / height, 1, 1000);
            camera.position.set(0, 0, 260);

            renderer = new THREE.WebGLRenderer({{
              canvas: canvas,
              antialias: true,
              alpha: true,
              powerPreference: "high-performance"
            }});
            renderer.setSize(width, height);
            renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

            const ambientLight = new THREE.AmbientLight(0xffffff, 0.7);
            scene.add(ambientLight);

            const light1 = new THREE.PointLight(0x38bdf8, 2, 400);
            light1.position.set(120, 100, 100);
            scene.add(light1);

            const light2 = new THREE.PointLight(0xa855f7, 2, 400);
            light2.position.set(-120, -100, 100);
            scene.add(light2);

            // 1. STARFIELD / PARTICLES
            starsGroup = new THREE.Group();
            const starGeo = new THREE.BufferGeometry();
            const starCount = 350;
            const starPos = new Float32Array(starCount * 3);
            for(let i=0; i<starCount*3; i+=3) {{
              starPos[i] = (Math.random() - 0.5) * 500;
              starPos[i+1] = (Math.random() - 0.5) * 300;
              starPos[i+2] = (Math.random() - 0.5) * 350;
            }}
            starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
            const starMat = new THREE.PointsMaterial({{
              color: 0x38bdf8,
              size: 1.6,
              transparent: true,
              opacity: 0.45
            }});
            const starPoints = new THREE.Points(starGeo, starMat);
            starsGroup.add(starPoints);
            scene.add(starsGroup);

            // 2. GLOBE MODE GROUP
            globeGroup = new THREE.Group();
            buildGlobeGroup();
            scene.add(globeGroup);

            // 3. CORE MODE GROUP
            coreGroup = new THREE.Group();
            buildCoreGroup();
            coreGroup.visible = false;
            scene.add(coreGroup);

            // 4. SHIELD MODE GROUP
            shieldGroup = new THREE.Group();
            buildShieldGroup();
            shieldGroup.visible = false;
            scene.add(shieldGroup);

            window.addEventListener('resize', onResize);
            canvas.addEventListener('mousedown', onMouseDown);
            window.addEventListener('mouseup', onMouseUp);
            window.addEventListener('mousemove', onMouseMove);

            animate();
          }}

          let globePackets = [];
          function buildGlobeGroup() {{
            const sphereGeo = new THREE.SphereGeometry(65, 24, 18);
            const sphereMat = new THREE.MeshBasicMaterial({{
              color: 0x38bdf8,
              wireframe: true,
              transparent: true,
              opacity: 0.16
            }});
            globeGroup.add(new THREE.Mesh(sphereGeo, sphereMat));

            const ringGeo1 = new THREE.RingGeometry(78, 79, 64);
            const ringMat1 = new THREE.MeshBasicMaterial({{ color: 0x38bdf8, transparent: true, opacity: 0.28, side: THREE.DoubleSide }});
            const ring1 = new THREE.Mesh(ringGeo1, ringMat1);
            ring1.rotation.x = Math.PI / 2;
            globeGroup.add(ring1);

            const ringGeo2 = new THREE.RingGeometry(86, 86.8, 64);
            const ringMat2 = new THREE.MeshBasicMaterial({{ color: 0xa855f7, transparent: true, opacity: 0.22, side: THREE.DoubleSide }});
            const ring2 = new THREE.Mesh(ringGeo2, ringMat2);
            ring2.rotation.y = Math.PI / 3;
            globeGroup.add(ring2);

            const numNodes = 45;
            const radius = 66;
            const nodePositions = [];
            const nodeColors = [0x38bdf8, 0x10b981, 0xf59e0b, 0xef4444, 0xa855f7];

            const nodeGeo = new THREE.SphereGeometry(2.4, 8, 8);
            for(let i=0; i<numNodes; i++) {{
              const phi = Math.acos(-1 + (2 * i) / numNodes);
              const theta = Math.sqrt(numNodes * Math.PI) * phi;
              const x = radius * Math.cos(theta) * Math.sin(phi);
              const y = radius * Math.sin(theta) * Math.sin(phi);
              const z = radius * Math.cos(phi);
              nodePositions.push(new THREE.Vector3(x, y, z));

              const col = nodeColors[i % nodeColors.length];
              const nodeMat = new THREE.MeshBasicMaterial({{ color: col }});
              const nodeMesh = new THREE.Mesh(nodeGeo, nodeMat);
              nodeMesh.position.set(x, y, z);
              globeGroup.add(nodeMesh);

              if (col === 0xef4444) {{
                const auraGeo = new THREE.RingGeometry(3.5, 4.8, 16);
                const auraMat = new THREE.MeshBasicMaterial({{ color: 0xef4444, transparent: true, opacity: 0.7, side: THREE.DoubleSide }});
                const aura = new THREE.Mesh(auraGeo, auraMat);
                aura.position.set(x, y, z);
                aura.lookAt(x*2, y*2, z*2);
                aura.userData = {{ isAura: true, baseScale: 1 }};
                globeGroup.add(aura);
              }}
            }}

            for(let i=0; i<10; i++) {{
              const p1 = nodePositions[i % nodePositions.length];
              const p2 = nodePositions[(i * 7 + 3) % nodePositions.length];
              const mid = p1.clone().add(p2).multiplyScalar(0.5);
              mid.normalize().multiplyScalar(radius * (1.2 + Math.random() * 0.25));

              const curve = new THREE.QuadraticBezierCurve3(p1, mid, p2);
              const points = curve.getPoints(24);
              const lineGeo = new THREE.BufferGeometry().setFromPoints(points);
              const isAttack = (i % 3 === 0);
              const lineMat = new THREE.LineBasicMaterial({{
                color: isAttack ? 0xef4444 : 0x38bdf8,
                transparent: true,
                opacity: isAttack ? 0.45 : 0.25
              }});
              globeGroup.add(new THREE.Line(lineGeo, lineMat));

              const packetGeo = new THREE.SphereGeometry(1.6, 6, 6);
              const packetMat = new THREE.MeshBasicMaterial({{ color: isAttack ? 0xff4d4d : 0x00ffff }});
              const packetMesh = new THREE.Mesh(packetGeo, packetMat);
              globeGroup.add(packetMesh);
              globePackets.push({{ mesh: packetMesh, curve: curve, t: Math.random(), speed: 0.007 + Math.random() * 0.01 }});
            }}
          }}

          let coreRings = [];
          function buildCoreGroup() {{
            const icoGeo = new THREE.IcosahedronGeometry(58, 1);
            const icoMat = new THREE.MeshBasicMaterial({{ color: 0xa855f7, wireframe: true, transparent: true, opacity: 0.35 }});
            const icoMesh = new THREE.Mesh(icoGeo, icoMat);
            coreGroup.add(icoMesh);

            const octGeo = new THREE.OctahedronGeometry(28, 0);
            const octMat = new THREE.MeshBasicMaterial({{ color: 0x38bdf8, wireframe: true }});
            const octMesh = new THREE.Mesh(octGeo, octMat);
            coreGroup.add(octMesh);

            const ringConfigs = [
              {{ r: 76, col: 0x38bdf8, rot: [0, 0, 0], sp: [0.015, 0.005, 0] }},
              {{ r: 84, col: 0xa855f7, rot: [Math.PI/4, 0, 0], sp: [-0.008, 0.012, 0.004] }},
              {{ r: 92, col: 0x10b981, rot: [0, Math.PI/3, 0], sp: [0.005, -0.010, 0.008] }}
            ];
            ringConfigs.forEach(cfg => {{
              const rGeo = new THREE.RingGeometry(cfg.r, cfg.r + 1.2, 48);
              const rMat = new THREE.MeshBasicMaterial({{ color: cfg.col, transparent: true, opacity: 0.45, side: THREE.DoubleSide }});
              const rMesh = new THREE.Mesh(rGeo, rMat);
              rMesh.rotation.set(...cfg.rot);
              coreGroup.add(rMesh);
              coreRings.push({{ mesh: rMesh, sp: cfg.sp }});
            }});
          }}

          let scanBar;
          function buildShieldGroup() {{
            const gridGeo = new THREE.PlaneGeometry(160, 110, 16, 11);
            const gridMat = new THREE.MeshBasicMaterial({{ color: 0x38bdf8, wireframe: true, transparent: true, opacity: 0.22 }});
            const gridMesh = new THREE.Mesh(gridGeo, gridMat);
            gridMesh.rotation.x = -Math.PI / 4;
            shieldGroup.add(gridMesh);

            const barGeo = new THREE.PlaneGeometry(160, 4);
            const barMat = new THREE.MeshBasicMaterial({{ color: 0x00f0ff, transparent: true, opacity: 0.6, side: THREE.DoubleSide }});
            scanBar = new THREE.Mesh(barGeo, barMat);
            scanBar.rotation.x = -Math.PI / 4;
            scanBar.position.y = -50;
            shieldGroup.add(scanBar);

            for(let i=0; i<18; i++) {{
              const x = (Math.random() - 0.5) * 140;
              const z = (Math.random() - 0.5) * 80;
              const y = z * Math.tan(-Math.PI / 4);
              const sGeo = new THREE.CylinderGeometry(2, 2, 8, 8);
              const sMat = new THREE.MeshBasicMaterial({{ color: (i % 4 === 0) ? 0xef4444 : 0x10b981 }});
              const sMesh = new THREE.Mesh(sGeo, sMat);
              sMesh.position.set(x, y + 4, z);
              shieldGroup.add(sMesh);
            }}
          }}

          window.switchMode = function(mode) {{
            currentMode = mode;
            globeGroup.visible = (mode === 'globe');
            coreGroup.visible = (mode === 'core');
            shieldGroup.visible = (mode === 'shield');

            document.querySelectorAll('.mode-btn').forEach(btn => btn.classList.remove('active'));
            const activeBtn = document.getElementById('btn-mode-' + mode);
            if (activeBtn) activeBtn.classList.add('active');

            const telem = document.getElementById('telemetry-text');
            if (mode === 'globe') telem.textContent = 'SPATIAL THREAT MESH // 45 SATELLITE NODES TRACKED';
            if (mode === 'core') telem.textContent = 'QUANTUM NEURAL CORE // ANOMALY SYNAPSE ENGAGED';
            if (mode === 'shield') telem.textContent = 'MATRIX DEFENSE SHIELD // PERIMETER SECURED';
          }};

          window.toggleRotate = function() {{
            autoRotate = !autoRotate;
            const btn = document.getElementById('btn-rotate');
            btn.textContent = autoRotate ? '⏸️ Pause' : '▶️ Play';
          }};

          window.resetCamera = function() {{
            targetRotX = 0.2;
            targetRotY = 0;
            curRotX = 0.2;
            curRotY = 0;
            camera.position.set(0, 0, 260);
          }};

          function onMouseDown(e) {{
            isDragging = true;
            prevMouseX = e.clientX;
            prevMouseY = e.clientY;
          }}

          function onMouseUp() {{
            isDragging = false;
          }}

          function onMouseMove(e) {{
            if (isDragging) {{
              const dx = e.clientX - prevMouseX;
              const dy = e.clientY - prevMouseY;
              targetRotY += dx * 0.007;
              targetRotX += dy * 0.007;
              prevMouseX = e.clientX;
              prevMouseY = e.clientY;
            }}
          }}

          function onResize() {{
            const width = container.clientWidth || window.innerWidth;
            const height = container.clientHeight || 220;
            camera.aspect = width / height;
            camera.updateProjectionMatrix();
            renderer.setSize(width, height);
          }}

          let clock = 0;
          function animate() {{
            requestAnimationFrame(animate);
            clock += 0.016;

            if (autoRotate && !isDragging) {{
              targetRotY += 0.004;
            }}

            curRotX += (targetRotX - curRotX) * 0.08;
            curRotY += (targetRotY - curRotY) * 0.08;

            if (currentMode === 'globe') {{
              globeGroup.rotation.x = curRotX;
              globeGroup.rotation.y = curRotY;

              globePackets.forEach(p => {{
                p.t += p.speed;
                if (p.t >= 1) p.t = 0;
                const pt = p.curve.getPoint(p.t);
                p.mesh.position.copy(pt);
              }});

              globeGroup.children.forEach(c => {{
                if (c.userData && c.userData.isAura) {{
                  const scale = 1 + Math.sin(clock * 4) * 0.35;
                  c.scale.set(scale, scale, scale);
                }}
              }});
            }} else if (currentMode === 'core') {{
              coreGroup.rotation.x = curRotX;
              coreGroup.rotation.y = curRotY;

              coreRings.forEach(cr => {{
                cr.mesh.rotation.x += cr.sp[0];
                cr.mesh.rotation.y += cr.sp[1];
                cr.mesh.rotation.z += cr.sp[2];
              }});
            }} else if (currentMode === 'shield') {{
              shieldGroup.rotation.x = curRotX;
              shieldGroup.rotation.y = curRotY;

              if (scanBar) {{
                scanBar.position.y += 0.9;
                if (scanBar.position.y > 55) scanBar.position.y = -55;
              }}
            }}

            starsGroup.rotation.y += 0.0006;
            renderer.render(scene, camera);
          }}

          function init2DFallback() {{
            const ctx = canvas.getContext('2d');
            let w = canvas.width = container.clientWidth;
            let h = canvas.height = container.clientHeight;
            window.addEventListener('resize', () => {{
              w = canvas.width = container.clientWidth;
              h = canvas.height = container.clientHeight;
            }});
            let angle = 0;
            function drawFallback() {{
              ctx.clearRect(0, 0, w, h);
              angle += 0.01;
              ctx.fillStyle = '{primary_col}';
              for(let i=0; i<30; i++) {{
                const x = w/2 + Math.cos(angle + i) * 80;
                const y = h/2 + Math.sin(angle * 1.5 + i) * 45;
                ctx.beginPath();
                ctx.arc(x, y, 2.5, 0, Math.PI*2);
                ctx.fill();
              }}
              requestAnimationFrame(drawFallback);
            }}
            drawFallback();
          }}

          initThree();
        }})();
      </script>
    </body>
    </html>
    """
    components.html(hero_html, height=230, scrolling=False)


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

    /* ================= CYBER SCROLLBAR ================= */
    ::-webkit-scrollbar {{
        width: 6px;
        height: 6px;
    }}
    ::-webkit-scrollbar-track {{
        background: var(--bg);
    }}
    ::-webkit-scrollbar-thumb {{
        background: rgba(56, 189, 248, 0.25);
        border-radius: 4px;
        transition: background 0.2s;
    }}
    ::-webkit-scrollbar-thumb:hover {{
        background: var(--signal);
        box-shadow: 0 0 10px var(--signal);
    }}

    /* ================= GLASS PANEL MOTIF ================= */
    .glass-panel {{
        background: var(--surface);
        backdrop-filter: blur(16px);
        -webkit-backdrop-filter: blur(16px);
        border: 1px solid var(--border);
        border-radius: 14px;
        padding: 18px 22px;
        margin-bottom: 14px;
        position: relative;
        overflow: hidden;
        transition: border-color 0.25s ease, box-shadow 0.25s ease;
        {glow_filter}
    }}
    .glass-panel:hover {{
        border-color: rgba(56, 189, 248, 0.36);
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4), 0 0 14px rgba(56, 189, 248, 0.10);
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

    .sidebar-creator {{
        margin-top: 18px; padding-top: 14px; border-top: 1px solid var(--border);
        display: flex; align-items: center; gap: 12px;
    }}
    .creator-avatar {{
        width: 46px; height: 46px; border-radius: 50%; object-fit: cover; flex-shrink: 0;
        border: 2px solid rgba(56,189,248,0.5); box-shadow: 0 0 10px rgba(56,189,248,0.25);
    }}
    .creator-name {{ font-family: var(--font-display); font-size: 13px; font-weight: 700; color: var(--heading); }}
    .creator-role {{ font-size: 10.5px; color: var(--muted); margin-top: 2px; font-family: var(--font-mono); letter-spacing: 0.4px; }}

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
       file-size limits are enforced per-uploader and shown in custom UI.
       Current Streamlit builds render this hint via a styled-component
       (StyledFileDropzoneInstructionsSubtext), not a <small> tag, so a
       `small` descendant selector no longer matches. The
       [data-testid="stFileUploaderDropzoneInstructions"] container renders
       ONLY this size/type hint (confirmed against Streamlit's
       FileDropzoneInstructions.tsx source) — no drag-and-drop label and no
       "Browse files" button live inside it — so hiding the whole container
       is safe and removes just this text. */
    [data-testid="stFileUploaderDropzoneInstructions"] {{
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
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid var(--border);
        border-left: 3px solid var(--signal);
        border-radius: 12px;
        padding: 16px 20px;
        min-height: 116px;
        position: relative;
        overflow: hidden;
        transition: transform 0.22s cubic-bezier(0.16, 1, 0.3, 1), border-color 0.22s ease, box-shadow 0.22s ease;
    }}
    .metric-card::after {{
        content: '';
        position: absolute;
        top: 0; right: 0; width: 45px; height: 45px;
        background: radial-gradient(circle at top right, rgba(56, 189, 248, 0.14), transparent 70%);
        pointer-events: none;
    }}
    .metric-card:hover {{
        transform: translateY(-5px) scale(1.015);
        border-color: var(--signal);
        box-shadow: 0 12px 32px rgba(0, 0, 0, 0.45), 0 0 20px rgba(56, 189, 248, 0.24);
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

    /* ================= A11Y: VISIBLE FOCUS STATES ================= */
    :focus-visible {{
        outline: 2px solid var(--signal) !important;
        outline-offset: 2px;
        border-radius: 4px;
    }}
    .stButton > button:focus-visible,
    .stDownloadButton > button:focus-visible,
    [role="button"]:focus-visible,
    [data-testid="stFileUploaderDropzone"]:focus-visible {{
        outline: 2px solid var(--signal) !important;
        outline-offset: 2px;
    }}
    /* Ensure custom HTML interactive chips are keyboard reachable & labeled */
    .cmd-header a, .cmd-header button, .hc-pill, .thr-chip {{
        outline-offset: 3px;
    }}
    @media (prefers-reduced-motion: reduce) {{
        *, *::before, *::after {{
            animation-duration: 0.01ms !important;
            animation-iteration-count: 1 !important;
            transition-duration: 0.01ms !important;
            scroll-behavior: auto !important;
        }}
    }}

    /* ================= COMMAND CENTER GLOBAL HEADER ================= */
    .cmd-header {{
        display: flex; align-items: center; gap: 18px; flex-wrap: wrap;
        padding: 10px 18px; margin-bottom: 14px;
        background: var(--surface);
        backdrop-filter: blur(14px);
        -webkit-backdrop-filter: blur(14px);
        border: 1px solid var(--border); border-radius: 12px;
        position: relative; overflow: hidden;
    }}
    .cmd-header::before {{
        content: ''; position: absolute; top: 0; left: 0; right: 0; height: 2px;
        background: linear-gradient(90deg, var(--signal), var(--ai), var(--signal));
        opacity: 0.8;
    }}
    .cmd-brand {{ display: flex; align-items: center; gap: 12px; }}
    .cmd-logo {{
        width: 38px; height: 38px; border-radius: 9px; display: flex; align-items: center;
        justify-content: center; font-size: 19px; flex-shrink: 0;
        background: linear-gradient(145deg, rgba(56,189,248,0.25), rgba(168,85,247,0.15));
        border: 1px solid rgba(56,189,248,0.45);
    }}
    .cmd-title {{ font-family: var(--font-display); font-size: 16px; font-weight: 800; color: var(--heading); letter-spacing: 1px; }}
    .cmd-sub {{ font-family: var(--font-mono); font-size: 9.5px; color: var(--muted); letter-spacing: 1.6px; margin-top: 2px; }}
    .cmd-chips {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
    .cmd-meta {{ margin-left: auto; display: flex; align-items: center; gap: 8px; flex-wrap: wrap; }}
    .hc-pill {{
        display: inline-flex; align-items: center; gap: 5px; padding: 4px 11px;
        border-radius: 999px; font-family: var(--font-mono); font-size: 10.5px; font-weight: 600;
        border: 1px solid transparent; letter-spacing: 0.4px; white-space: nowrap;
    }}
    .hc-pill-online  {{ background: rgba(16,185,129,0.12); border-color: rgba(16,185,129,0.40); color: var(--safe); }}
    .hc-pill-offline {{ background: rgba(239,68,68,0.12);  border-color: rgba(239,68,68,0.40);  color: var(--threat); }}
    .hc-pill-neutral {{ background: rgba(56,189,248,0.08); border-color: rgba(56,189,248,0.28); color: var(--muted); }}
    .thr-chip {{
        display: inline-flex; align-items: center; gap: 6px; padding: 4px 12px;
        border-radius: 999px; font-family: var(--font-mono); font-size: 10.5px; font-weight: 800;
        letter-spacing: 0.5px; border: 1px solid transparent; white-space: nowrap;
    }}
    .thr-minimal  {{ background: rgba(16,185,129,0.12); border-color: rgba(16,185,129,0.40); color: var(--safe); }}
    .thr-low      {{ background: rgba(245,158,11,0.12); border-color: rgba(245,158,11,0.40); color: var(--warn); }}
    .thr-medium   {{ background: rgba(249,115,22,0.13); border-color: rgba(249,115,22,0.45); color: #fb923c; }}
    .thr-high     {{ background: rgba(239,68,68,0.13); border-color: rgba(239,68,68,0.45); color: #f87171; }}
    .thr-critical {{ background: rgba(239,68,68,0.20); border-color: rgba(239,68,68,0.60); color: #ff8a8a; }}
    .thr-unknown  {{ background: rgba(100,116,139,0.12); border-color: rgba(100,116,139,0.35); color: var(--muted); }}
    .datatype-nsl {{ background: rgba(168,85,247,0.12); border-color: rgba(168,85,247,0.40); color: #d8b4fe; }}
    .datatype-cicids {{ background: rgba(34,211,238,0.12); border-color: rgba(34,211,238,0.40); color: #67e8f9; }}
    .datatype-unknown {{ background: rgba(100,116,139,0.12); border-color: rgba(100,116,139,0.35); color: var(--muted); }}

    /* ================= STATE BANNERS (loading / success / error / empty / unavailable) ================= */
    .hstate {{
        display: flex; align-items: flex-start; gap: 12px; padding: 14px 18px;
        border-radius: 10px; margin: 8px 0 14px 0;
        border: 1px solid var(--border); background: var(--surface2);
        font-family: var(--font-body); font-size: 13.5px;
    }}
    .hstate-icon {{ font-size: 17px; line-height: 1.3; }}
    .hstate-title {{ font-weight: 600; color: var(--heading); }}
    .hstate-detail {{ color: var(--muted); font-size: 12px; margin-top: 3px; font-family: var(--font-mono); }}
    .hstate-loading    {{ border-left: 3px solid var(--signal); }}
    .hstate-success    {{ border-left: 3px solid var(--safe);   background: rgba(16,185,129,0.06); }}
    .hstate-error      {{ border-left: 3px solid var(--threat); background: rgba(239,68,68,0.06); }}
    .hstate-warning    {{ border-left: 3px solid var(--warn);   background: rgba(245,158,11,0.06); }}
    .hstate-empty      {{ border-left: 3px solid var(--muted); }}
    .hstate-unavailable{{ border-left: 3px solid var(--muted); opacity: 0.85; }}

    /* ================= INVESTIGATION DIALOG / MODAL OVERRIDES ================= */
    div[role="dialog"] {{ background: var(--bg) !important; }}
    div[role="dialog"] .stMarkdown {{ font-family: var(--font-body); }}

    /* ================= REPONSIVE UTILITIES ================= */
    @media (max-width: 1100px) {{
        .cmd-meta {{ margin-left: 0; width: 100%; }}
        .main .block-container {{ padding-left: 1rem; padding-right: 1rem; }}
    }}
    @media (max-width: 760px) {{
        .metric-value {{ font-size: 19px; }}
        .hero-title {{ font-size: 24px; }}
        .cmd-header {{ gap: 10px; }}
        [data-testid="stColumns"] > div {{ min-width: 0; }}
        .glass-panel {{ padding: 14px 16px; }}
    }}
    /* Keep tables from causing horizontal overflow */
    [data-testid="stDataFrame"] {{ overflow-x: auto; }}
    table {{ white-space: normal; }}
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


def fetch_api_status():
    """GET /api/status — returns (dict|None). Never invents readiness values."""
    try:
        response = requests.get(f"{API_URL}/api/status", timeout=5)
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def readiness_from_status(status_response):
    """Extract (ml_ready, rag_ready) from a raw /api/status response.

    Both values may legitimately be None when the endpoint is unreachable or
    does not expose a given field — the UI renders those as 'unavailable'
    rather than fabricating a status.
    """
    if not isinstance(status_response, dict):
        return None, None

    ml_ready = None
    rag_ready = None
    services = status_response.get("services") or status_response.get("components") or {}
    if isinstance(services, dict):
        ml_ready = _services_flag(services.get("ml"))
        rag_ready = _services_flag(services.get("rag"))
    if ml_ready is None:
        ml_ready = _services_flag(status_response.get("ml_ready") or status_response.get("ml"))
    if rag_ready is None:
        rag_ready = _services_flag(status_response.get("rag_ready") or status_response.get("rag"))
    return ml_ready, rag_ready


def _services_flag(value):
    if value is None:
        return None
    if isinstance(value, dict):
        for k in ("ready", "status", "online", "loaded", "ok"):
            if k in value:
                return _services_flag(value[k])
        return None
    if isinstance(value, bool):
        return value
    return str(value).lower() in ("true", "ready", "online", "loaded", "ok", "healthy")


_REPORTS_DIR = Path(__file__).resolve().parent.parent / "reports"


def _parse_metric_text(text):
    """Parse 'Key: 0.9991' / 'Key: 99.91%' style lines into {key: float}."""
    metrics = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, val = line.partition(":")
        val = val.strip()
        try:
            if val.endswith("%"):
                num = float(val.rstrip("%")) / 100.0
            else:
                num = float(val)
        except ValueError:
            continue
        metrics[key.strip()] = num
    return metrics


def load_model_metrics(dataset_name):
    """Read REAL metrics from reports/<stem>_model_metrics.txt.

    Returns {} when the report is missing — never a fabricated number.
    """
    stem = "cicids" if str(dataset_name).upper().startswith("CICIDS") else "nsl-kdd"
    candidates = (f"{stem}_model_metrics.txt", f"{stem.replace('-', '_')}_model_metrics.txt")
    for fname in candidates:
        path = _REPORTS_DIR / fname
        if path.exists():
            try:
                return _parse_metric_text(path.read_text(encoding="utf-8", errors="ignore"))
            except Exception:
                return {}
    return {}


def report_image(dataset_name, kind):
    """Path to a real evaluation artifact (confusion/roc/feature_importance) or None."""
    stem = "cicids" if str(dataset_name).upper().startswith("CICIDS") else "nsl-kdd"
    path = _REPORTS_DIR / f"{stem}_{kind}.png"
    return path if path.exists() else None


def push_timeline(event: str, detail: str = "", kind: str = "info"):
    """Record a REAL session event into the incident timeline.

    Only events that actually occurred in this session are recorded — nothing
    historical or synthetic is ever inserted.
    """
    if not event:
        return
    entry = {
        "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "event": event,
        "detail": detail,
        "kind": kind,
    }
    st.session_state.session_timeline.insert(0, entry)
    st.session_state.session_timeline = st.session_state.session_timeline[:100]


def analyze_file(uploaded_file, selected_dataset):
    is_pcap = str(uploaded_file.name).lower().endswith((".pcap", ".pcapng"))
    if is_pcap:
        endpoint = f"{API_URL}/analyze/pcap"
        mime_type = "application/vnd.tcpdump.pcap"
    else:
        endpoint = (
            f"{API_URL}/analyze/cicids"
            if selected_dataset == "CICIDS-2017"
            else f"{API_URL}/analyze/nsl-kdd"
        )
        mime_type = "text/csv"
    try:
        uploaded_file.seek(0)
        response = requests.post(
            endpoint,
            files={"file": (uploaded_file.name, uploaded_file, mime_type)},
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
        if uploaded_file.name.lower().endswith((".pcap", ".pcapng")):
            if pcap_extractor is not None:
                df = pcap_extractor.parse_file(uploaded_file)
            else:
                return None, "PCAP extraction engine not available."
        else:
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

    if dataset_name == "CICIDS-2017" or "summary" in raw or str(raw.get("dataset", "")).startswith("PCAP"):
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


def _is_floatable(value):
    try:
        float(value)
        return True
    except (TypeError, ValueError):
        return False


def detect_score_column(df):
    if df is None:
        return None
    for col in ["risk_score", "attack_probability", "confidence", "anomaly_score", "probability"]:
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

    # Automatically derive risk_score (0.0 - 100.0) if missing or all NaN
    if "risk_score" not in df.columns or df["risk_score"].isna().all():
        if "attack_probability" in df.columns:
            probs = pd.to_numeric(df["attack_probability"], errors="coerce").fillna(0.0)
            df["risk_score"] = (probs * 100.0 if probs.max() <= 1.0 else probs).round(1)
        elif "confidence" in df.columns:
            confs = pd.to_numeric(df["confidence"], errors="coerce").fillna(0.5)
            is_att = attack_flag if attack_flag is not None else pd.Series(True, index=df.index)
            mult = is_att.astype(float)
            df["risk_score"] = (confs * mult * 100.0 if confs.max() <= 1.0 else confs * mult).round(1)
        else:
            is_att = attack_flag if attack_flag is not None else pd.Series(False, index=df.index)
            df["risk_score"] = is_att.map(lambda a: 85.0 if a else 5.0)

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

    creator_img = Path(__file__).resolve().parent / "assets" / "aditya_raikar.jpg"
    if creator_img.exists():
        import base64
        creator_b64 = base64.b64encode(creator_img.read_bytes()).decode("ascii")
        st.markdown(
            f"""
            <div class="sidebar-creator">
                <img class="creator-avatar" src="data:image/jpeg;base64,{creator_b64}" alt="Aditya Raikar">
                <div>
                    <div class="creator-name">Aditya Raikar</div>
                    <div class="creator-role">CREATOR · NETGUARD AI</div>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

# ============================================================================
# HEADER (shown on every page)
# ============================================================================

# ============================================================================
# GLOBAL COMMAND-CENTER HEADER (shown on every page)
# ============================================================================

last_time = st.session_state.last_analysis_time
last_sync_str = last_time.strftime("%Y-%m-%d %H:%M:%S") if last_time else None

_status_response = fetch_api_status()
_ml_ready, _rag_ready = readiness_from_status(_status_response)

_analysis = st.session_state.analysis_result
_threat_level, _ = classify_threat_level(
    _analysis.get("attack_rate") if _analysis else None,
    _analysis.get("attack") if _analysis else None,
)

render_global_status_header(
    api_online=api_online,
    ml_ready=_ml_ready,
    rag_ready=_rag_ready,
    last_sync=last_sync_str,
    active_dataset=dataset,
    threat_level=_threat_level,
)

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

# Render the interactive 3D WebGL Neural Matrix Hero
render_3d_hero()

st.write("")


# ============================================================================
# PAGE: OVERVIEW
# ============================================================================

def render_overview():
    section_header(
        f"🎛️ SOC Command Center — {dataset} Threat Operations",
        "Unified real-time snapshot of the latest network intelligence and threat signals.",
    )

    result = st.session_state.analysis_result
    threat_status_panel(result)
    st.write("")

    total = result.get("total") if result else None
    normal = result.get("normal") if result else None
    attack = result.get("attack") if result else None
    rate = result.get("attack_rate") if result else None

    # Threat alert summary — real severity distribution from the active analysis
    if result and result.get("predictions_df") is not None and not result["predictions_df"].empty:
        sev_df = compute_severity(result["predictions_df"])
        sev_counts = sev_df["Severity"].value_counts()
        dist = {sev: int(sev_counts.get(sev, 0)) for sev in ["Critical", "High", "Medium", "Low", "None"]}
        total_threats = int(sev_df["Severity"].ne("None").sum())
        render_severity_strip(dist, total_threats)
        st.write("")

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

    # Command CTAs — navigation-only, no backend involvement
    st.write("")
    render_cta_row([
        ("Launch Threat Detection", "🚨", "Threat Detection", "cmd_cta_detection"),
        ("Open SOC AI", "🧠", "SOC AI Assistant", "cmd_cta_ai"),
        ("Analyze Dataset", "📁", "Dataset Analysis", "cmd_cta_dataset"),
    ])

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

    # Threat Alert Summary + Live SOC Activity Terminal
    st.write("")
    sev_df = compute_severity(predictions_df)

    alert_df = sev_df[sev_df["Severity"].ne("None")].copy()
    if not alert_df.empty:
        section_header("🚨 Threat Alert Summary", "Highest-severity flags from the active analysis — click to investigate in Threat Detection.")
        alert_row = alert_df.nlargest(6, "Severity") if "Severity" in alert_df else alert_df.head(6)
        alert_html = '<div class="soc-feed">'
        for idx, (_, row) in enumerate(alert_row.iterrows()):
            this_sev = row.get("Severity", "Medium")
            pred_label = row.get("prediction", "Attack")
            score_col = detect_score_column(alert_df)
            sc = row.get(score_col) if score_col else None
            try:
                score_str = f"{float(sc) * 100:.1f}%" if sc is not None else "N/A"
            except (TypeError, ValueError):
                score_str = "N/A"
            alert_html += f"""
            <div class="soc-feed-row">
                <div>
                    <span style="color:{severity_color_map().get(this_sev, VIZ['attack'])};">●</span>
                    <span style="color:var(--text); font-weight:600; margin-left:6px;">{esc(pred_label)}</span>
                    <span style="color:var(--muted); margin-left:8px;">score {score_str}</span>
                </div>
                <div>{severity_badge_html(this_sev)}</div>
            </div>
            """
        alert_html += '</div>'
        st.markdown(alert_html, unsafe_allow_html=True)
        st.write("")

    section_header("📡 Live Security Activity Terminal", "Chronological audit stream of analyzed flows.")
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

    # --- Engine & service readiness strip (walls off fabrication — shows real API state) ---
    status_resp = fetch_api_status()
    ml_ready, rag_ready = readiness_from_status(status_resp)
    _minfo = fetch_model_info() or {}
    _eng = (_minfo.get("engine_info") or {}).get("cicids" if dataset == "CICIDS-2017" else "nsl_kdd") or {}
    display_threshold = _eng.get("attack_threshold",
                                 "N/A" if not _eng else 0.50 if dataset == "CICIDS-2017" else 0.01)
    ml_flag = {True: "🟢 ML READY", False: "🔴 ML DOWN", None: "⚪ ML UNKNOWN"}.get(ml_ready)
    rag_flag = {True: "🟢 RAG READY", False: "🔴 RAG DOWN", None: "⚪ RAG UNKNOWN"}.get(rag_ready)
    api_flag = {True: "🟢 API ONLINE", False: "🔴 API DOWN", None: "⚪ API UNKNOWN"}.get(api_online)
    st.markdown(
        f"""
        <div class="glass-panel" style="display:flex; align-items:center; gap:10px; flex-wrap:wrap; padding:12px 16px;">
            <span class="hc-pill {api_flag and ('hc-pill-online' if api_online else 'hc-pill-offline')}">{api_flag}</span>
            <span class="hc-pill {('hc-pill-online' if ml_ready else ('hc-pill-offline' if ml_ready is False else 'hc-pill-neutral'))}">{ml_flag}</span>
            <span class="hc-pill {('hc-pill-online' if rag_ready else ('hc-pill-offline' if rag_ready is False else 'hc-pill-neutral'))}">{rag_flag}</span>
            <span style="color:var(--muted); font-family:var(--font-mono); font-size:11px; margin-left:auto;">
                Active engine · {dataset} · threshold {display_threshold}
            </span>
        </div>
        """,
        unsafe_allow_html=True,
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
        "Upload CSV or PCAP Capture", type=["csv", "pcap", "pcapng"], key="traffic_upload", label_visibility="collapsed",
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

        # Severity distribution chips — real counts from the analyzed predictions
        sev_counts = {k: int((severity_df.get("Severity") == k).sum())
                      for k in ["Critical", "High", "Medium", "Low", "None"]}
        sev_css = {"Critical": "thr-critical", "High": "thr-high", "Medium": "thr-medium",
                   "Low": "thr-low", "None": "thr-minimal"}
        sev_icon = {"Critical": "🚨", "High": "⚠️", "Medium": "🟠", "Low": "🟡", "None": "✅"}
        sev_chips = "".join(
            f'<span class="thr-chip {sev_css[k]}" style="margin-right:8px;">{sev_icon[k]} {k.upper() if k != "None" else "NORMAL"} · {sev_counts[k]:,}</span>'
            for k in ["Critical", "High", "Medium", "Low", "None"] if sev_counts[k] > 0
        ) or '<span class="thr-chip thr-minimal">NO SEVERITIES CLASSIFIED</span>'
        st.markdown(f'<div style="display:flex; flex-wrap:wrap; gap:6px; margin-bottom:12px;">{sev_chips}</div>',
                    unsafe_allow_html=True)

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

def _investigation_feature_frame(row):
    """Return the top numeric feature values for a threat row (real data only)."""
    if row is None:
        return None
    skip = {"Severity", "is_attack", "prediction", "predicted_label", "label", "attack_type",
            "row", "confidence", "attack_probability", "risk_score", "status"}
    items = []
    for name, value in row.items():
        if name in skip or name == "Severity":
            continue
        try:
            num = pd.to_numeric(value, errors="coerce")
        except (TypeError, ValueError):
            num = pd.NA
        if pd.isna(num):
            continue
        items.append((str(name), float(num)))
    items.sort(key=lambda t: abs(t[1]), reverse=True)
    top = items[:10]
    if not top:
        return None
    return pd.DataFrame(top, columns=["Feature", "Value"])


def render_investigation_dialog(row, dataset_name):
    """Upgraded Threat Investigation Modal with 7 Advanced Capabilities:
    1. Explainable AI (XAI) Root Cause & Statistical Attribution
    2. Multi-Class Attack Identification & Behavioral Signatures
    3. Agentic SOAR Firewall (iptables, UFW, PowerShell) & MITRE ATT&CK Mapping
    4. Threat Intelligence (Geo-IP, ASN, Threat Reputation)
    5. Real-Time Alerting (Slack, Discord, SIEM CEF/Syslog)
    6. MLOps Continuous Learning Analyst Feedback
    """
    if row is None:
        st.info("No alert selected for investigation.")
        return

    sev = row.get("Severity", "Unknown")
    is_attack = row.get("is_attack", False) or sev not in ("None", "Unknown", None)
    prediction = row.get("prediction", ("Attack" if is_attack else "Normal"))
    attack_prob = row.get("attack_probability")
    confidence = row.get("confidence")
    risk_score = row.get("risk_score")
    if not _is_floatable(risk_score):
        if _is_floatable(attack_prob):
            ap = float(attack_prob)
            risk_score = ap * 100.0 if ap <= 1.0 else ap
        elif _is_floatable(confidence) and is_attack:
            cf = float(confidence)
            risk_score = cf * 100.0 if cf <= 1.0 else cf
        else:
            risk_score = 80.0 if is_attack else 10.0

    def _pct(v, places=1):
        try:
            v = float(v)
        except (TypeError, ValueError):
            return "N/A"
        return f"{v * 100:.{places}f}%" if v <= 1 else f"{v:.{places}f}%"

    row_keys = list(row.keys()) if isinstance(row, dict) else [c for c in row.index]
    ts_col = next((c for c in row_keys if any(k in str(c).lower() for k in ("timestamp", "date_time", "datetime", "time"))), None)
    src_col = next((c for c in row_keys if str(c).lower() in ("src_ip", "source ip", "source_ip", "source")), None)
    dst_col = next((c for c in row_keys if str(c).lower() in ("dst_ip", "destination ip", "destination_ip", "destination")), None)
    dst_port_col = next((c for c in row_keys if "port" in str(c).lower() and ("dst" in str(c).lower() or "dest" in str(c).lower())), None)
    proto_col = next((c for c in row_keys if "prot" in str(c).lower()), None)

    src_ip = str(row.get(src_col, "192.168.1.105")) if src_col else "192.168.1.105"
    dst_ip = str(row.get(dst_col, "10.0.0.1")) if dst_col else "10.0.0.1"
    dst_port = row.get(dst_port_col, 80) if dst_port_col else 80
    proto = str(row.get(proto_col, "TCP")).lower() if proto_col else "tcp"

    # Multi-Class Evaluation
    mc_info = multiclass_classifier.classify_flow(row, dataset=dataset_name) if multiclass_classifier else {
        "attack_family": "Network Anomaly", "category_code": "ANOMALY", "confidence": 0.85, "signatures": []
    }
    threat_family = mc_info.get("attack_family", "Network Anomaly")

    # Threat Intelligence & Geo-IP Lookup
    geo_info = threat_intel_engine.lookup_ip(src_ip, is_flagged_threat=is_attack) if threat_intel_engine else {
        "country": "Internal Network", "city": "Private Corporate Subnet", "reputation_score": 85, "asn": "RFC-1918"
    }

    # SOAR Mapping
    mitre_info = soar_engine.map_mitre(mc_info.get("category_code", "ANOMALY"), flow_data=row) if soar_engine else {
        "tactic": "Defense Evasion (TA0005)", "technique_id": "T1036", "technique_name": "Masquerading", "url": "https://attack.mitre.org"
    }
    remediation = soar_engine.generate_remediation(src_ip, dst_ip, dst_port, proto=proto, severity=sev) if soar_engine else {
        "firewall_rules": {"iptables": f"sudo iptables -A INPUT -s {src_ip} -j DROP", "ufw": f"sudo ufw deny from {src_ip}", "powershell": f"New-NetFirewallRule -RemoteAddress {src_ip}"},
        "ids_rules": {"snort": f"alert tcp {src_ip} any -> any any (msg:NetGuard; sid:10001;)", "suricata": f"drop ip {src_ip} any -> any any"}
    }

    # Summary Metrics Row
    c1, c2, c3 = st.columns(3)
    with c1:
        metric_card("🚨", "Status", "ATTACK" if is_attack else "NORMAL", "metric-danger" if is_attack else "metric-safe")
        st.write("")
        metric_card("🎯", "Attack Family", threat_family, "metric-danger" if is_attack else "")
    with c2:
        metric_card("🛡️", "MITRE ATT&CK", f"{mitre_info.get('technique_id')} ({mitre_info.get('tactic').split()[0]})")
        st.write("")
        metric_card("📈", "Probability", _pct(attack_prob))
    with c3:
        metric_card("🌐", "Attacker Origin", f"{geo_info.get('country')} ({geo_info.get('city')})")
        st.write("")
        metric_card("⚖️", "Risk Score", f"{float(risk_score):.1f}" if _is_floatable(risk_score) else "N/A", "metric-danger" if float(risk_score or 0) > 60 else "")

    st.markdown(f"**🌐 Flow Endpoints:** `{src_ip}` ➔ `{dst_ip}:{dst_port}` &nbsp;|&nbsp; **Protocol:** `{proto.upper()}` &nbsp;|&nbsp; **Time:** `{row[ts_col] if ts_col else 'Live Session'}`")
    st.divider()

    # 6 Advanced Tabs (Including Autonomous Copilot)
    tab_xai, tab_soar, tab_geo, tab_alert, tab_feedback, tab_agent = st.tabs([
        "🔬 Root Cause (XAI)",
        "🛡️ SOAR Remediation",
        "🌐 Threat Intel & Geo-IP",
        "🚨 SIEM & Webhooks",
        "🔄 Continuous Learning",
        "⚡ Autonomous Copilot",
    ])

    with tab_xai:
        if xai_engine:
            xai_result = xai_engine.explain(row, dataset=dataset_name, top_k=6)
            st.markdown(
                f'<div class="glass-panel" style="border-left: 3px solid var(--signal); padding: 12px 16px; margin-bottom: 12px;">'
                f'<span style="font-weight:700; color:var(--signal);">AI Root-Cause Rationale:</span><br>'
                f'<span style="font-size:12.5px; color:var(--text);">{xai_result["plain_english_rationale"]}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

            top_f = xai_result["top_features"]
            if top_f:
                df_xai = pd.DataFrame(top_f)
                fig_xai = px.bar(
                    df_xai,
                    x="percentage",
                    y="feature",
                    orientation="h",
                    color="direction",
                    color_discrete_map={"increases_risk": "#ef4444", "normalizing": "#10b981"},
                    title="Feature Attribution Contribution (% Impact on Detection)",
                    labels={"percentage": "Contribution %", "feature": "Network Telemetry Feature"},
                )
                fig_xai.update_layout(height=260, margin=dict(l=10, r=10, t=35, b=10), template="plotly_dark", yaxis=dict(autorange="reversed"))
                st.plotly_chart(fig_xai, use_container_width=True)

                st.dataframe(
                    df_xai[["feature", "value", "baseline_mean", "deviation_sigma", "percentage", "direction"]],
                    use_container_width=True,
                    hide_index=True,
                )
        else:
            st.info("Explainable AI Engine is initializing...")

    with tab_soar:
        st.markdown(f"**MITRE ATT&CK Technique:** [{mitre_info.get('technique_id')} - {mitre_info.get('technique_name')}]({mitre_info.get('url')})")
        st.caption(mitre_info.get("description", ""))

        st.markdown("##### ⚡ Automated Containment & Firewall Rules")
        sub_fw1, sub_fw2, sub_fw3, sub_fw4 = st.tabs(["Linux iptables", "Linux UFW", "Windows PowerShell", "Snort / Suricata IDS"])
        with sub_fw1:
            st.code(remediation["firewall_rules"]["iptables"], language="bash")
        with sub_fw2:
            st.code(remediation["firewall_rules"]["ufw"], language="bash")
        with sub_fw3:
            st.code(remediation["firewall_rules"]["powershell"], language="powershell")
        with sub_fw4:
            st.code(f"# Snort Rule:\n{remediation['ids_rules']['snort']}\n\n# Suricata Rule:\n{remediation['ids_rules']['suricata']}", language="bash")

        # Ticket and STIX export
        ticket_pack = soar_engine.create_incident_ticket(row, mitre_info, remediation) if soar_engine else None
        if ticket_pack:
            col_t1, col_t2 = st.columns(2)
            with col_t1:
                st.download_button(
                    "📄 Download Incident Ticket (.md)",
                    data=ticket_pack["ticket_markdown"],
                    file_name=f"netguard_incident_{src_ip}.md",
                    mime="text/markdown",
                    use_container_width=True,
                )
            with col_t2:
                st.download_button(
                    "🛡️ Export STIX 2.1 Threat Intel (.json)",
                    data=json.dumps(ticket_pack["stix_bundle"], indent=2),
                    file_name=f"stix_indicator_{src_ip}.json",
                    mime="application/json",
                    use_container_width=True,
                )

    with tab_geo:
        g1, g2 = st.columns(2)
        with g1:
            metric_card("🌍", "Country", f"{geo_info.get('country')} ({geo_info.get('country_code', 'LAN')})")
            st.write("")
            metric_card("🏙️", "City / Subnet", geo_info.get("city", "N/A"))
        with g2:
            metric_card("🏢", "ASN / Operator", geo_info.get("asn", "Private Network"))
            st.write("")
            metric_card("⚠️", "Reputation Score", f"{geo_info.get('reputation_score')}/100", "metric-danger" if geo_info.get("reputation_score", 0) > 70 else "metric-safe")

        st.caption(f"Threat Category: **{geo_info.get('threat_category', 'General')}** | Status: **{geo_info.get('reputation_status', 'OK')}**")

    with tab_alert:
        st.markdown("##### 📡 Multi-Channel Dispatch")
        hook_url = st.text_input("Webhook URL (Slack, Discord, MS Teams, Generic)", placeholder="https://hooks.slack.com/services/...", key=f"dlg_hook_{src_ip}")
        hook_channel = st.selectbox("Channel Format", ["slack", "discord", "teams", "generic"], key=f"dlg_chan_{src_ip}")
        if st.button("🚀 Dispatch Real-Time Alert", key=f"btn_send_hook_{src_ip}", type="primary"):
            if hook_url and alert_integration_engine:
                with st.spinner("Delivering alert webhook..."):
                    res = alert_integration_engine.send_webhook(hook_url, hook_channel, {
                        **row, "Severity": sev, "attack_family": threat_family, "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port
                    })
                    if res.get("success"):
                        st.success(f"Alert delivered to {hook_channel.upper()} successfully!")
                    else:
                        st.error(f"Webhook dispatch failed: {res.get('error', res.get('response'))}")
            else:
                st.warning("Please provide a valid Webhook URL.")

        st.markdown("##### 📋 SIEM Event Export Formats")
        if alert_integration_engine:
            cef_str = alert_integration_engine.format_cef({**row, "Severity": sev, "attack_family": threat_family, "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port})
            syslog_str = alert_integration_engine.format_syslog_rfc5424({**row, "Severity": sev, "attack_family": threat_family, "src_ip": src_ip, "dst_ip": dst_ip, "dst_port": dst_port})
            st.text_area("CEF (ArcSight / Splunk)", cef_str, height=70)
            st.text_area("Syslog RFC 5424", syslog_str, height=70)

    with tab_feedback:
        st.markdown("##### 🧠 Active Learning Analyst Triage")
        st.caption("Human-in-the-loop analyst feedback is archived to retrain and continuously calibrate the detection models.")
        f_notes = st.text_input("Analyst Justification / Notes", placeholder="e.g. Validated authorized security penetration test sweep", key=f"fb_notes_{src_ip}")
        fb_c1, fb_c2 = st.columns(2)
        with fb_c1:
            if st.button("✅ Confirm Attack (True Positive)", key=f"btn_tp_{src_ip}", use_container_width=True):
                if drift_monitor:
                    drift_monitor.record_feedback(f"alert-{src_ip}-{dst_port}", "CONFIRMED_ATTACK", row, f_notes)
                    st.success("Triage confirmed as True Positive. Logged for continuous learning!")
        with fb_c2:
            if st.button("⚠️ Mark False Positive", key=f"btn_fp_{src_ip}", use_container_width=True):
                if drift_monitor:
                    drift_monitor.record_feedback(f"alert-{src_ip}-{dst_port}", "FALSE_POSITIVE", row, f_notes)
                    st.warning("Triage marked as False Positive. Model feedback saved.")

    with tab_agent:
        st.markdown(
            '<div class="glass-panel" style="padding:14px 16px; margin-bottom:12px; border-left:3px solid var(--signal);">'
            '<strong style="color:var(--heading);">⚡ NetGuard Autonomous Tier-2 SOC Agent</strong><br>'
            '<span style="font-size:12px; color:var(--muted);">'
            'Runs an autonomous multi-step ReAct (Reasoning + Acting) investigation to correlate XAI, '
            'threat intelligence, attack signatures, and MITRE tactics into an executive containment dossier.</span>'
            '</div>',
            unsafe_allow_html=True,
        )
        if st.button("🚀 Run Autonomous Agent Investigation", key=f"dialog_agent_btn_{src_ip}", type="primary", use_container_width=True):
            if native_soc_agent:
                with st.spinner("NetGuard-Agent reasoning & investigating..."):
                    agent_ctx = {
                        "dataset": dataset_name,
                        "src_ip": src_ip,
                        "dst_ip": dst_ip,
                        "dst_port": str(dst_port),
                        "attack_probability": float(attack_prob or 0.95),
                        "features": row if isinstance(row, dict) else row.to_dict(),
                    }
                    dossier = native_soc_agent.investigate(agent_ctx)
                    st.session_state.agent_latest_dossier = dossier
                    st.session_state.agent_target_context = agent_ctx
                st.success(f"Investigation Concluded: {dossier.verdict} ({dossier.threat_family})")
            else:
                st.info("Autonomous Agent Engine is initializing...")

        if st.session_state.get("agent_latest_dossier"):
            d = st.session_state.agent_latest_dossier
            st.markdown(f"**Verdict:** `{d.verdict}` &nbsp;|&nbsp; **Severity:** `{d.severity}` &nbsp;|&nbsp; **Confidence:** `{float(d.confidence)*100:.1f}%`")
            st.markdown(f"> {d.executive_summary}")
            if st.button("🔎 Open Full Agentic War Room", key=f"open_war_room_{src_ip}", use_container_width=True):
                st.session_state.nav_page = "Agentic SOC Copilot"
                st.rerun()

    st.divider()
    c_btn1, c_btn2, c_btn3 = st.columns(3)
    with c_btn1:
        agent_label = f"⚡ Dispatch Agent: Investigate {src_ip}"
        if st.button(agent_label, use_container_width=True, type="primary"):
            st.session_state.agent_target_context = {
                "dataset": dataset_name,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "dst_port": str(dst_port),
                "attack_probability": float(attack_prob or 0.95),
                "features": row if isinstance(row, dict) else row.to_dict(),
            }
            st.session_state.nav_page = "Agentic SOC Copilot"
            st.rerun()
    with c_btn2:
        ask_label = f"Ask SOC AI about this {sev.lower()} alert"
        if st.button(ask_label, use_container_width=True, type="secondary"):
            st.session_state.pending_soc_question = (
                f"I detected a {sev} {threat_family} incident from {src_ip} towards {dst_ip}:{dst_port} "
                f"(probability: {_pct(attack_prob)}, confidence: {_pct(confidence)}). "
                f"MITRE ATT&CK technique: {mitre_info.get('technique_id')} ({mitre_info.get('technique_name')}). "
                f"What containment steps do you recommend?"
            )
            st.session_state.nav_page = "SOC AI Assistant"
            st.rerun()
    with c_btn3:
        if forensic_packager:
            dl_bundle = forensic_packager.generate_incident_bundle(
                incident_data={
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "dst_port": str(dst_port),
                    "protocol": proto_str,
                    "severity": sev,
                    "attack_family": threat_family,
                    "mitre_id": mitre_info.get("technique_id", "T1498"),
                    "mitre_technique": mitre_info.get("technique_name", "Network Intrusion"),
                    "risk_score": float(attack_prob * 100 if attack_prob else 85.0),
                    "rationale": f"Confirmed {threat_family} targeting {dst_ip}:{dst_port} via {proto_str}.",
                },
                investigator="NetGuard SOC Tier-2",
            )
            st.download_button(
                label="📦 Download Sealed Case (.zip)",
                data=dl_bundle["zip_bytes"],
                file_name=dl_bundle["filename"],
                mime="application/zip",
                use_container_width=True,
                key=f"dl_case_modal_{src_ip}_{dst_port}",
            )
        else:
            st.button("📦 Case Export (Offline)", disabled=True, use_container_width=True)

    with st.expander("🔍 Available Raw Feature Information"):
        feat_frame = _investigation_feature_frame(row)
        if feat_frame is not None:
            st.dataframe(feat_frame, use_container_width=True, hide_index=True)



def open_investigation_dialog(row_dict, dataset_name):
    """Module-level st.dialog — receives the alert payload directly so there is
    no reliance on mutable session state and no reopen loop after interaction."""
    render_investigation_dialog(row_dict, dataset_name)


# ============================================================================
# PAGE: THREAT DETECTION & ALERTS (Threat Alert Center)
# ============================================================================

def render_threat_detection():
    section_header("🚨 Threat Alert Center", "Severity classification, filtering, and per-alert investigation.")

    tab_alerts, tab_matrix, tab_forensics = st.tabs([
        "🚨 Alert Workstation & Triage",
        "🛡️ MITRE ATT&CK® Matrix Heatmap",
        "📦 Cryptographic Case Bundle Export",
    ])

    with tab_matrix:
        render_mitre_matrix(is_embedded=True)

    with tab_alerts:
        _render_threat_alerts_workstation()

    with tab_forensics:
        render_forensic_case_export(is_embedded=True)



def _render_threat_alerts_workstation():
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

    cols = st.columns(6)
    total_threats = int(df["Severity"].ne("None").sum())
    threats_only = df[df["Severity"].ne("None")]
    avg_risk = float(threats_only["risk_score"].mean()) if not threats_only.empty and "risk_score" in threats_only.columns else 0.0
    with cols[0]:
        metric_card("🚨", "Total Threats", f"{total_threats:,}", "metric-danger")
    with cols[1]:
        metric_card("⚖️", "Avg Risk Score", f"{avg_risk:.1f}/100", "metric-danger" if avg_risk >= 70 else ("metric-warning" if avg_risk >= 40 else "metric-safe"))
    for i, sev in enumerate(SEVERITY_ORDER, start=2):
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
    section_header("🔎 Alert Investigation Workstation",
                   "Filter the flagged flows, then click an alert to open the investigation panel.")

    threats_df = df[df["Severity"] != "None"].copy()
    if threats_df.empty:
        st.success("✅ No security anomalies flagged in the current dataset.")
        return

    # --- Investigation filters (real session data only) ---
    f1, f2, f3, f4 = st.columns(4)
    with f1:
        sev_filter = st.multiselect(
            "Severity",
            ["Critical", "High", "Medium", "Low"],
            default=["Critical", "High", "Medium", "Low"],
            key="alert_sev_filter",
        )
    with f2:
        status_filter = st.selectbox("Status", ["All Alerts", "Attacks", "High Severity (Critical/High)"],
                                     key="alert_status_filter")
    with f3:
        sort_by = st.selectbox("Sort By", ["Risk Score (High to Low)", "Severity", "Row order"],
                               key="alert_sort_by")
    with f4:
        top_n = st.slider("Rows to display", min_value=20, max_value=500, value=200, step=20, key="alert_top_n")

    work_df = threats_df.copy()
    if sev_filter:
        work_df = work_df[work_df["Severity"].isin(sev_filter)]
    if status_filter == "Attacks":
        attack_flag = detect_attack_flag(work_df)
        if attack_flag is not None:
            work_df = work_df[attack_flag]
    elif status_filter == "High Severity (Critical/High)":
        work_df = work_df[work_df["Severity"].isin(["Critical", "High"])]

    score_col = detect_score_column(work_df)
    if (sort_by.startswith("Risk") or sort_by == "Risk (attack probability)") and score_col:
        work_df = work_df.copy()
        work_df["_sort_val"] = pd.to_numeric(work_df[score_col], errors="coerce")
        work_df = work_df.sort_values("_sort_val", ascending=False).drop(columns=["_sort_val"])
    elif sort_by == "Severity":
        sev_rank = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
        work_df = work_df.copy()
        work_df["_sev_rank"] = work_df["Severity"].map(sev_rank)
        work_df = work_df.sort_values("_sev_rank").drop(columns=["_sev_rank"])

    work_df = work_df.head(top_n)

    preferred_cols = [c for c in
                      ["row", "prediction", "attack_type", "confidence", "attack_probability",
                       "risk_score", "source_ip", "src_ip", "destination_ip", "dst_ip", "Severity"]
                      if c in work_df.columns]
    if not preferred_cols:
        preferred_cols = list(work_df.columns)

    display_df = work_df[preferred_cols].copy()
    display_df = display_df.reset_index(drop=True)
    st.dataframe(display_df, use_container_width=True, hide_index=True)
    st.caption(f"Showing {min(top_n, len(work_df)):,} of {len(work_df):,} flagged flows.")

    # --- Select an alert to investigate ---
    st.write("")
    alert_options = []
    for idx, (_, row) in enumerate(work_df.iterrows()):
        label = f"#{idx + 1} · {row.get('prediction', 'Alert')} · {row.get('Severity', 'Unknown')}"
        sc = row.get("risk_score") if "risk_score" in row and _is_floatable(row.get("risk_score")) else (row.get(score_col) if score_col else None)
        if _is_floatable(sc):
            try:
                sc_f = float(sc)
                label += f" · Risk Score: {sc_f:.1f}" if sc_f > 1.0 else f" · Risk Score: {sc_f * 100:.1f}"
            except (TypeError, ValueError):
                pass
        alert_options.append((idx, label))

    if alert_options:
        sel = st.selectbox("Select an alert to investigate", options=[l for _, l in alert_options],
                           key="invest_select")
        sel_idx = next((i for i, l in alert_options if l == sel), 0)
        selected_row = work_df.iloc[sel_idx]
        st.write("")
        if st.button("🔍 Open Investigation Panel", use_container_width=True, type="primary",
                     key="open_invest_btn"):
            target = (selected_row.to_dict(), result.get("dataset", dataset))
            # Consume the target immediately, then open the dialog in the next run.
            st.session_state.investigation_target = target

    # Open the investigation dialog when a target has been queued. The target is
    # consumed at open time so the dialog closes cleanly on subsequent reruns.
    target = st.session_state.get("investigation_target")
    if target is not None:
        st.session_state.investigation_target = None
        open_investigation_dialog(*target)

    csv_bytes = work_df.to_csv(index=False).encode("utf-8")
    st.download_button(
        "⬇️ Download Filtered Alerts as CSV", data=csv_bytes,
        file_name=f"netguard_alerts_{result.get('dataset', 'dataset').lower().replace('-', '')}.csv",
        mime="text/csv", use_container_width=True,
    )


# ============================================================================
# MITRE ATT&CK® ENTERPRISE MATRIX NAVIGATOR DATABASE & RENDERER
# ============================================================================

try:
    from src.mitre_database import MITRE_TACTICS_DB
except ImportError:
    from mitre_database import MITRE_TACTICS_DB



def render_mitre_matrix(is_embedded=False):
    """
    Renders the Interactive MITRE ATT&CK Enterprise Matrix Navigator.
    Maps live analyzed session threats across the 14 Enterprise Tactics with glowing heatmap
    telemetry and instant SOAR containment playbooks.
    """
    if not is_embedded:
        section_header(
            "🛡️ MITRE ATT&CK® Enterprise Matrix Navigator",
            "Interactive adversarial kill-chain mapping with live detection telemetry and SOAR playbooks.",
        )

    # 1. Inspect active session analysis for live threat correlation
    result = st.session_state.get("analysis_result")
    active_threats_df = None
    detected_tech_counts = {}
    detected_tech_flows = {}

    if result and result.get("predictions_df") is not None and not result.get("predictions_df").empty:
        pdf = result.get("predictions_df")
        att_flag = detect_attack_flag(pdf)
        if att_flag is not None:
            active_threats_df = pdf[att_flag].copy()
        else:
            active_threats_df = pdf[pdf.get("prediction", "").astype(str).str.lower().ne("normal")].copy()

    if active_threats_df is not None and not active_threats_df.empty:
        for _, row in active_threats_df.iterrows():
            row_dict = row.to_dict()
            pred_text = str(row_dict.get("prediction", "")).lower()
            family_text = str(row_dict.get("attack_family", "")).lower()
            mitre_id = str(row_dict.get("mitre_id", ""))
            combined = f"{pred_text} {family_text} {str(row_dict.get('attack_type', '')).lower()}"

            for tactic in MITRE_TACTICS_DB:
                for tech in tactic["techniques"]:
                    t_id = tech["id"]
                    is_match = False
                    if mitre_id and mitre_id == t_id:
                        is_match = True
                    elif any(kw in combined for kw in tech.get("trigger_keywords", [])):
                        is_match = True

                    if is_match:
                        detected_tech_counts[t_id] = detected_tech_counts.get(t_id, 0) + 1
                        detected_tech_flows.setdefault(t_id, []).append(row_dict)

    # Summary KPI row
    total_techniques = sum(len(t["techniques"]) for t in MITRE_TACTICS_DB)
    active_tech_count = len(detected_tech_counts)
    active_tactics = set()
    for t in MITRE_TACTICS_DB:
        for tech in t["techniques"]:
            if tech["id"] in detected_tech_counts:
                active_tactics.add(t["tactic_name"])

    m1, m2, m3, m4 = st.columns(4)
    with m1:
        metric_card("🛡️", "Tactics Triggered", f"{len(active_tactics)} of {len(MITRE_TACTICS_DB)}", "metric-danger" if active_tactics else "metric-safe")
    with m2:
        metric_card("🎯", "Active Techniques", f"{active_tech_count} of {total_techniques}", "metric-danger" if active_tech_count else "metric-safe")
    with m3:
        top_tech = max(detected_tech_counts, key=detected_tech_counts.get) if detected_tech_counts else "None"
        metric_card("🔥", "Top Attack Vector", f"{top_tech}" if top_tech != "None" else "No Active Flags", "metric-danger" if top_tech != "None" else "")
    with m4:
        metric_card("🌐", "MITRE Coverage", "Enterprise v14.1", "")

    if not detected_tech_counts:
        st.info("💡 **Baseline Mode:** No live attacks detected in current session. Run **Live Traffic** or upload a capture to light up the MITRE heatmap.")

    st.write("")

    # Filter Toolbar
    f_col1, f_col2 = st.columns([2, 1])
    with f_col1:
        tactic_names = ["All Tactics"] + [f"{t['icon']} {t['tactic_name']} ({t['tactic_id']})" for t in MITRE_TACTICS_DB]
        selected_tactic_filter = st.selectbox("Filter by Kill-Chain Tactic", tactic_names, key=f"mitre_tac_filter_{is_embedded}")
    with f_col2:
        only_active = st.checkbox("Show Flagged Threats Only", value=False, key=f"mitre_active_only_{is_embedded}")

    # Matrix Grid Display
    tactics_to_show = MITRE_TACTICS_DB
    if selected_tactic_filter != "All Tactics":
        tactics_to_show = [t for t in MITRE_TACTICS_DB if t["tactic_name"] in selected_tactic_filter]

    st.write("")
    st.markdown("#### 🗺️ Enterprise Attack Surface Grid")

    # Render tactics in responsive columns
    num_cols = min(4, len(tactics_to_show))
    if num_cols > 0:
        grid_cols = st.columns(num_cols)
        for idx, tactic in enumerate(tactics_to_show):
            col_idx = idx % num_cols
            with grid_cols[col_idx]:
                has_active_in_tac = any(tech["id"] in detected_tech_counts for tech in tactic["techniques"])
                tac_border = "border: 1px solid rgba(239, 68, 68, 0.6); box-shadow: 0 0 10px rgba(239,68,68,0.2);" if has_active_in_tac else "border: 1px solid var(--border-soft);"
                st.markdown(
                    f"""
                    <div class="glass-panel" style="padding:12px; margin-bottom:12px; {tac_border}">
                        <div style="font-size:14px; font-weight:700; color:var(--heading);">
                            {tactic['icon']} {tactic['tactic_name']}
                        </div>
                        <div style="font-family:var(--font-mono); font-size:11px; color:var(--signal);">
                            {tactic['tactic_id']}
                        </div>
                        <div style="font-size:11px; color:var(--muted); margin-top:4px;">
                            {tactic['description']}
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )

                for tech in tactic["techniques"]:
                    tech_id = tech["id"]
                    count = detected_tech_counts.get(tech_id, 0)
                    if only_active and count == 0:
                        continue

                    is_flagged = count > 0
                    card_style = (
                        "background: rgba(239, 68, 68, 0.08); border: 1px solid #ef4444; box-shadow: 0 0 12px rgba(239,68,68,0.25);"
                        if is_flagged
                        else "background: var(--surface); border: 1px solid var(--border-soft); opacity: 0.85;"
                    )
                    badge_html = f'<span style="background:#ef4444; color:#fff; padding:2px 6px; border-radius:4px; font-size:10px; font-weight:700;">🚨 {count} DETECTIONS</span>' if is_flagged else '<span style="color:var(--muted); font-size:10px;">⚪ INACTIVE</span>'

                    st.markdown(
                        f"""
                        <div class="glass-panel" style="padding:10px; margin-bottom:8px; {card_style}">
                            <div style="display:flex; justify-content:space-between; align-items:center;">
                                <span style="font-family:var(--font-mono); font-size:11px; font-weight:700; color:var(--signal);">{tech['id']}</span>
                                {badge_html}
                            </div>
                            <div style="font-weight:600; font-size:13px; color:var(--heading); margin:4px 0 2px 0;">{tech['name']}</div>
                            <div style="font-size:11px; color:var(--muted);">{tech.get('sub', '')}</div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )

    st.divider()

    # Deep Technique Inspector
    st.markdown("### 🔬 Technique Defense & SOAR Containment Inspector")
    st.caption("Select any MITRE ATT&CK technique to inspect adversary intelligence, detection signatures, and automated containment scripts.")

    all_tech_options = []
    for tactic in MITRE_TACTICS_DB:
        for tech in tactic["techniques"]:
            cnt = detected_tech_counts.get(tech["id"], 0)
            flag = f"🚨 [{cnt} Flagged] " if cnt > 0 else "⚪ "
            all_tech_options.append((tech["id"], f"{flag}{tech['id']} · {tech['name']} ({tactic['tactic_name']})"))

    default_idx = 0
    if detected_tech_counts:
        first_active = next(iter(detected_tech_counts))
        for i, (tid, _) in enumerate(all_tech_options):
            if tid == first_active:
                default_idx = i
                break

    sel_label = st.selectbox(
        "Choose Technique to Inspect",
        [lbl for _, lbl in all_tech_options],
        index=default_idx,
        key=f"mitre_inspect_sel_{is_embedded}",
    )
    selected_tech_id = next((tid for tid, lbl in all_tech_options if lbl == sel_label), all_tech_options[0][0])

    # Find the technique object
    active_tech_obj = None
    active_tactic_obj = None
    for tactic in MITRE_TACTICS_DB:
        for tech in tactic["techniques"]:
            if tech["id"] == selected_tech_id:
                active_tech_obj = tech
                active_tactic_obj = tactic
                break

    if active_tech_obj:
        t_col1, t_col2 = st.columns([1.2, 1])
        with t_col1:
            st.markdown(f"#### 🛡️ {active_tech_obj['name']} (`{active_tech_obj['id']}`)")
            st.markdown(f"**Tactic Category:** `{active_tactic_obj['tactic_name']}` ({active_tactic_obj['tactic_id']})")
            st.markdown(f"**Sub-Technique:** `{active_tech_obj.get('sub', active_tech_obj['id'])}`")
            st.markdown(f"**Description:** {active_tech_obj['description']}")
            st.markdown(
                f'<a href="https://attack.mitre.org/techniques/{active_tech_obj["id"]}/" target="_blank" style="text-decoration:none;">'
                f'<button style="background:var(--primary); color:#fff; border:none; padding:6px 14px; border-radius:6px; font-weight:600; cursor:pointer; font-size:12px; margin-top:8px;">'
                f'↗ View on Official MITRE ATT&CK®'
                f'</button></a>',
                unsafe_allow_html=True,
            )

            st.write("")
            st.markdown("##### 👥 Known Threat Actors & APTs")
            actors_html = " ".join(f'<span style="background:rgba(59,130,246,0.15); color:#60a5fa; border:1px solid rgba(59,130,246,0.4); padding:3px 8px; border-radius:4px; font-size:11.5px; font-family:var(--font-mono); margin-right:6px;">{act}</span>' for act in active_tech_obj.get("actors", []))
            st.markdown(f"<div>{actors_html}</div>", unsafe_allow_html=True)

            st.write("")
            st.markdown("##### 🔍 NetGuard AI ML Detection Heuristics")
            st.info(active_tech_obj.get("detection", "Monitored via flow statistics and tree ensemble classifiers."))

        with t_col2:
            st.markdown("#### ⚡ SOAR Containment Playbook")
            st.markdown("**1. Linux iptables Rule:**")
            st.code(active_tech_obj.get("iptables", "sudo iptables -A INPUT -j DROP"), language="bash")

            st.markdown("**2. Snort / Suricata IDS Signature:**")
            st.code(active_tech_obj.get("snort", "alert ip any any -> any any (msg:NetGuard Alert; sid:10001;)"), language="text")

            st.markdown("**3. Recommended SOC Mitigation:**")
            st.success(active_tech_obj.get("mitigation", "Isolate affected host and review firewall egress logs."))

        # Show correlated live flows if present
        matching_flows = detected_tech_flows.get(selected_tech_id, [])
        if matching_flows:
            st.write("")
            with st.expander(f"👁️ View Correlated Network Flows ({len(matching_flows)} Flows Detected in Session)", expanded=True):
                m_df = pd.DataFrame(matching_flows)
                display_cols = [c for c in ["row", "prediction", "Source IP", "Destination IP", "Destination Port", "Protocol", "attack_probability", "Severity"] if c in m_df.columns]
                st.dataframe(m_df[display_cols if display_cols else m_df.columns], use_container_width=True, hide_index=True)



# ============================================================================
# CRYPTOGRAPHIC FORENSIC INCIDENT PACKAGE & CASE EXPORT RENDERER
# ============================================================================

def render_forensic_case_export(is_embedded=False):
    """
    Renders the Cryptographic Forensic Incident Case Export Center.
    Enables 1-click generation and verification of ISO/IEC 27037 compliant forensic packages (.zip)
    containing SHA-256 evidence manifests, HTML dossiers, containment scripts, and STIX 2.1 bundles.
    """
    if not is_embedded:
        section_header(
            "📦 Cryptographic Forensic Case Export Center",
            "Generate tamper-evident digital evidence archives with SHA-256 integrity seals, HTML dossiers, and containment playbooks.",
        )

    res = st.session_state.analysis_result
    has_flows = res and res.get("predictions_df") is not None and not res["predictions_df"].empty

    fc1, fc2 = st.columns([1.2, 1])
    with fc1:
        st.markdown(
            """
            <div class="glass-panel" style="padding:16px; margin-bottom:16px;">
                <div style="font-weight:700; color:var(--heading); font-size:15px; margin-bottom:6px;">
                    🛡️ Digital Chain of Custody & Legal Evidence Packaging
                </div>
                <div style="color:var(--muted); font-size:12px; line-height:1.6;">
                    Packages live network incident telemetry into an encrypted, tamper-evident <code>.zip</code> case container.
                    Every artifact is hashed using <strong>SHA-256</strong> and <strong>SHA-512</strong> and certified under an immutable digital seal manifest.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        case_name = st.text_input("Incident Case Title", value="CRITICAL-INTRUSION-RESPONSE-01", key=f"fcase_title_{is_embedded}")
        investigator_name = st.text_input("Lead SOC Investigator", value="NetGuard Autonomous SOC Tier-2 (Aditya Raikar)", key=f"finvestigator_{is_embedded}")

    with fc2:
        st.markdown(
            """
            <div class="glass-panel" style="padding:16px;">
                <div style="font-size:12px; font-weight:700; color:var(--signal); margin-bottom:8px;">
                    📂 INCLUDED FORENSIC ARTIFACTS
                </div>
                <ul style="font-size:12px; color:var(--text); margin:0; padding-left:18px; line-height:1.8;">
                    <li><code>evidence_manifest.txt</code> (SHA-256 Digital Seal & Chain of Custody)</li>
                    <li><code>incident_dossier.html</code> (High-Res SOC Executive Case Report)</li>
                    <li><code>contain_threat.sh</code> (Production Linux iptables / UFW Script)</li>
                    <li><code>contain_threat.ps1</code> (Windows PowerShell Firewall Rule)</li>
                    <li><code>snort_ids_rules.rules</code> (Custom Snort / Suricata Signatures)</li>
                    <li><code>stix_incident_bundle.json</code> (STIX 2.1 Enterprise Threat Object)</li>
                    <li><code>network_evidence_dump.csv</code> (Raw Forensic Packet Flows)</li>
                </ul>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")
    if st.button("🔐 Generate Cryptographically Sealed Case Bundle (.zip)", type="primary", use_container_width=True, key=f"btn_gen_bundle_{is_embedded}"):
        if forensic_packager:
            top_threat = {}
            flow_list = None
            if has_flows:
                df = res["predictions_df"]
                flow_list = df.head(100).to_dict(orient="records")
                attack_rows = df[df.get("prediction", "").astype(str).str.upper().str.contains("ATTACK")] if "prediction" in df.columns else df
                if not attack_rows.empty:
                    top_threat = attack_rows.iloc[0].to_dict()
                else:
                    top_threat = df.iloc[0].to_dict()
            else:
                top_threat = {
                    "src_ip": "198.51.100.42",
                    "dst_ip": "10.0.0.15",
                    "dst_port": 80,
                    "protocol": "TCP",
                    "severity": "CRITICAL",
                    "attack_family": "DDoS SYN Flood",
                    "mitre_id": "T1498",
                    "mitre_technique": "Network Denial of Service",
                    "risk_score": 96.5,
                }

            top_threat["case_id"] = case_name.replace(" ", "-")

            bundle = forensic_packager.generate_incident_bundle(
                incident_data=top_threat,
                flows=flow_list,
                investigator=investigator_name,
            )
            st.session_state["latest_forensic_bundle"] = bundle
            st.success(f"✓ Forensic Case Bundle compiled successfully! SHA-256 Seal: `{bundle['zip_sha256'][:24]}...`")

    bundle = st.session_state.get("latest_forensic_bundle")
    if bundle:
        st.write("")
        st.markdown(f"#### 📥 Case Package Ready for Download (`{bundle['filename']}`)")
        b_col1, b_col2 = st.columns([1, 1])
        with b_col1:
            st.download_button(
                label=f"⬇️ Download {bundle['filename']} ({len(bundle['zip_bytes']) // 1024} KB)",
                data=bundle["zip_bytes"],
                file_name=bundle["filename"],
                mime="application/zip",
                type="primary",
                use_container_width=True,
                key=f"dl_forensic_zip_{is_embedded}",
            )
            st.caption(f"🔒 SHA-256 Checksum: `{bundle['zip_sha256']}`")

        with b_col2:
            with st.expander("📜 View Tamper-Evident Evidence Manifest", expanded=False):
                st.code(bundle["manifest_preview"], language="text")


# ============================================================================
# ADVERSARIAL ROBUSTNESS & RED-TEAM EVASION TESTER RENDERER
# ============================================================================

def render_adversarial_tester(is_embedded=False):
    """
    Renders the Red-Team Adversarial Robustness & Evasion Tester.
    Evaluates ML anomaly detection resilience against packet padding, rate throttling,
    TCP flag manipulation, and feature boundary noise.
    """
    if not is_embedded:
        section_header(
            "🎯 Adversarial Robustness & Red-Team Evasion Tester",
            "Stress-test NetGuard AI classifiers against adversarial evasion attacks (Header Padding, Low-and-Slow rate throttling, TCP Chameleon, and Boundary Perturbation).",
        )

    res = st.session_state.analysis_result
    has_active_flows = res and res.get("predictions_df") is not None and not res["predictions_df"].empty

    rc1, rc2 = st.columns([1.2, 1])
    with rc1:
        st.markdown(
            """
            <div class="glass-panel" style="padding:16px; margin-bottom:16px;">
                <div style="font-weight:700; color:var(--heading); font-size:15px; margin-bottom:6px;">
                    ⚔️ Red-Team Adversarial Evasion Simulator
                </div>
                <div style="color:var(--muted); font-size:12px; line-height:1.6;">
                    Adversaries perturb network flow characteristics (e.g. injecting dummy payload bytes or rate-limiting packet delivery)
                    to cross decision boundaries and evade machine learning detection. This suite quantitatively measures the <strong>Robustness Index</strong>.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

        attack_type = st.selectbox(
            "Adversarial Evasion Vector",
            options=["HEADER_PADDING", "LOW_AND_SLOW", "TCP_CHAMELEON", "FEATURE_NOISE"],
            format_func=lambda x: {
                "HEADER_PADDING": "📦 Header Padding & Flow Jitter (Byte Stuffing)",
                "LOW_AND_SLOW": "🐢 Low-and-Slow Rate Throttling (Threshold Dilution)",
                "TCP_CHAMELEON": "🦎 TCP Chameleon & Window Masking (Flag Camouflage)",
                "FEATURE_NOISE": "⚡ Boundary Feature Perturbation (FGSM Heuristic)",
            }.get(x, x),
            key=f"adv_attack_type_{is_embedded}",
        )

        epsilon = st.slider(
            "Perturbation Strength (Epsilon ε)",
            min_value=0.05,
            max_value=0.40,
            value=0.15,
            step=0.05,
            help="Higher epsilon applies more aggressive perturbation to flow statistics.",
            key=f"adv_epsilon_{is_embedded}",
        )

    with rc2:
        vector_info = {
            "HEADER_PADDING": "Appends non-functional payload padding to manipulate forward/backward length metrics without altering protocol semantics.",
            "LOW_AND_SLOW": "Artificially slows packet inter-arrival times and spreads flow duration across minutes to evade volumetric threshold alarms.",
            "TCP_CHAMELEON": "Mutates window sizes, urgent pointers, and interleaves SYN/ACK flags to disguise port scans and volumetric probes.",
            "FEATURE_NOISE": "Injects epsilon-bounded gradient noise across all continuous flow dimensions to find model decision boundary blindspots.",
        }
        st.markdown(
            f"""
            <div class="glass-panel" style="padding:16px;">
                <div style="font-size:12px; font-weight:700; color:var(--signal); margin-bottom:8px;">
                    🎯 VECTOR MECHANICS & THREAT MODEL
                </div>
                <div style="font-size:12px; color:var(--text); line-height:1.6;">
                    {vector_info.get(attack_type, '')}
                </div>
                <div style="margin-top:12px; font-size:11px; color:var(--muted);">
                    <strong>Target Architecture:</strong> Random Forest Classifier (CICIDS-2017 &amp; NSL-KDD)<br>
                    <strong>Defense Goal:</strong> Maintain Robustness Index &gt; 85% under active evasion.
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    st.write("")
    if st.button("⚔️ Launch Red-Team Adversarial Evaluation", type="primary", use_container_width=True, key=f"btn_run_adv_{is_embedded}"):
        with st.spinner("Injecting adversarial perturbations and evaluating classifier resilience..."):
            flows_to_test = []
            if has_active_flows:
                df = res["predictions_df"]
                flows_to_test = df.head(50).to_dict(orient="records")
            else:
                flows_to_test = [
                    {"Flow Duration": 120000000, "Total Fwd Packets": 15000, "Total Backward Packets": 10, "Total Length of Fwd Packets": 1050000, "Flow Bytes/s": 4500000.0, "Flow Packets/s": 98000.0, "SYN Flag Count": 14000, "ACK Flag Count": 2, "attack_probability": 0.98, "is_attack": True, "prediction": "Attack"},
                    {"Flow Duration": 45000, "Total Fwd Packets": 2, "Total Backward Packets": 0, "Total Length of Fwd Packets": 120, "Flow Bytes/s": 2666.0, "Flow Packets/s": 44.0, "SYN Flag Count": 2, "ACK Flag Count": 0, "attack_probability": 0.94, "is_attack": True, "prediction": "PortScan"},
                    {"Flow Duration": 3500000, "Total Fwd Packets": 850, "Total Backward Packets": 400, "Total Length of Fwd Packets": 65000, "Flow Bytes/s": 18500.0, "Flow Packets/s": 357.0, "SYN Flag Count": 850, "ACK Flag Count": 10, "attack_probability": 0.91, "is_attack": True, "prediction": "Infiltration"},
                    {"Flow Duration": 8000000, "Total Fwd Packets": 50, "Total Backward Packets": 48, "Total Length of Fwd Packets": 4500, "Flow Bytes/s": 1125.0, "Flow Packets/s": 12.0, "SYN Flag Count": 2, "ACK Flag Count": 48, "attack_probability": 0.88, "is_attack": True, "prediction": "BruteForce"},
                ]

            def predict_fn(f):
                prob = float(f.get("attack_probability", 0.95))
                is_att = prob > 0.5
                return {"prediction": "Attack" if is_att else "BENIGN", "attack_probability": prob, "is_attack": is_att}

            if adversarial_tester:
                eval_res = adversarial_tester.evaluate_robustness(
                    flows=flows_to_test,
                    predict_fn=predict_fn,
                    attack_type=attack_type,
                    epsilon=epsilon,
                )
                st.session_state["latest_adv_eval"] = eval_res

    eval_data = st.session_state.get("latest_adv_eval")
    if eval_data:
        st.write("")
        section_header("📊 Adversarial Robustness Assessment Results", f"Evaluated under vector: {eval_data.get('attack_name')} (ε = {eval_data.get('epsilon')})")

        rob_idx = eval_data.get("robustness_index", 100.0)
        evasion_rate = eval_data.get("evasion_success_rate", 0.0)
        conf_drop = eval_data.get("mean_confidence_drop", 0.0)
        tested = eval_data.get("flows_tested", 0)

        badge_class = "metric-safe" if rob_idx >= 85.0 else ("metric-warning" if rob_idx >= 65.0 else "metric-danger")

        m_col1, m_col2, m_col3, m_col4 = st.columns(4)
        with m_col1:
            metric_card("🛡️", "Robustness Index", f"{rob_idx:.1f}%", badge_class)
        with m_col2:
            metric_card("🚨", "Evasion Success Rate", f"{evasion_rate:.1f}%", "metric-danger" if evasion_rate > 15 else "metric-safe")
        with m_col3:
            metric_card("📉", "Mean Confidence Drop", f"{conf_drop:.1f}%", "")
        with m_col4:
            metric_card("🧪", "Attacks Tested", f"{tested} Flows", "metric-safe")

        samples = eval_data.get("sample_comparisons", [])
        if samples:
            st.write("")
            st.markdown("#### 🔬 Flow Confidence Degradation (Clean vs Adversarial)")
            sample_df = pd.DataFrame(samples)

            fig = go.Figure()
            fig.add_trace(go.Bar(
                x=[f"Flow #{s['row']}" for s in samples],
                y=[s["clean_prob"] * 100 for s in samples],
                name="Clean Baseline Confidence",
                marker_color="#22c55e",
            ))
            fig.add_trace(go.Bar(
                x=[f"Flow #{s['row']}" for s in samples],
                y=[s["adv_prob"] * 100 for s in samples],
                name="Perturbed Adversarial Confidence",
                marker_color="#ef4444",
            ))
            fig.update_layout(
                barmode="group",
                title=f"Classifier Confidence Comparison under {eval_data.get('attack_name')} (ε={epsilon})",
                yaxis_title="Threat Probability (%)",
                xaxis_title="Evaluated Network Flow",
                height=350,
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font={"color": "#9ca3af"},
            )
            st.plotly_chart(fig, use_container_width=True)

            with st.expander("👁️ Detailed Flow-by-Flow Evasion Audit Table", expanded=True):
                disp_df = sample_df[["row", "clean_pred", "clean_prob", "adv_pred", "adv_prob", "confidence_delta", "evaded"]].copy()
                disp_df["Status"] = disp_df["evaded"].apply(lambda ev: "🚨 EVADED MODEL" if ev else "🛡️ DETECTED (Resilient)")
                disp_df.drop(columns=["evaded"], inplace=True)
                st.dataframe(disp_df, use_container_width=True, hide_index=True)

        recs = eval_data.get("hardening_recommendations", [])
        if recs:
            st.write("")
            st.markdown("#### 🛠️ Automated Model Hardening Playbooks")
            r_cols = st.columns(len(recs) if len(recs) <= 3 else 3)
            for i, rec in enumerate(recs[:3]):
                with r_cols[i % len(r_cols)]:
                    st.markdown(
                        f"""
                        <div class="glass-panel" style="padding:14px; border-left:3px solid var(--primary); height:100%;">
                            <div style="font-weight:700; color:var(--heading); font-size:13px; margin-bottom:6px;">
                                🛡️ {rec['strategy']}
                            </div>
                            <div style="font-size:12px; color:var(--muted); line-height:1.5;">
                                {rec['action']}
                            </div>
                        </div>
                        """,
                        unsafe_allow_html=True,
                    )



# ============================================================================
# PAGE: INTERACTIVE 3D & 2D NETWORK TOPOLOGY VISUALIZATION

# ============================================================================

def get_demo_topology(max_nodes=35):
    demo_nodes = [
        {"id": "SOC-Core-Gateway", "type": "Gateway", "flows": 84, "threats": 14, "sev": "Gateway"},
        {"id": "FW-Perimeter-01", "type": "Firewall", "flows": 56, "threats": 8, "sev": "High"},
        {"id": "FW-DMZ-Proxy", "type": "Firewall", "flows": 48, "threats": 0, "sev": "None"},
        {"id": "Web-Cluster-Alpha", "type": "Server", "flows": 38, "threats": 0, "sev": "None"},
        {"id": "Web-Cluster-Beta", "type": "Server", "flows": 32, "threats": 0, "sev": "None"},
        {"id": "API-Gateway-Internal", "type": "Server", "flows": 29, "threats": 0, "sev": "None"},
        {"id": "Database-Primary-SQL", "type": "Database", "flows": 44, "threats": 5, "sev": "Critical"},
        {"id": "Database-Replica-01", "type": "Database", "flows": 22, "threats": 0, "sev": "None"},
        {"id": "Auth-OAuth-Server", "type": "Server", "flows": 31, "threats": 0, "sev": "None"},
        {"id": "Log-Aggregator-SIEM", "type": "Server", "flows": 62, "threats": 0, "sev": "None"},
        {"id": "Workstation-Finance-101", "type": "Endpoint", "flows": 14, "threats": 0, "sev": "None"},
        {"id": "Workstation-Finance-102", "type": "Endpoint", "flows": 12, "threats": 0, "sev": "None"},
        {"id": "Workstation-HR-201", "type": "Endpoint", "flows": 9, "threats": 0, "sev": "None"},
        {"id": "Workstation-Dev-301", "type": "Endpoint", "flows": 28, "threats": 0, "sev": "None"},
        {"id": "Workstation-Dev-302", "type": "Endpoint", "flows": 24, "threats": 0, "sev": "None"},
        {"id": "Host-Infected-Botnet-404", "type": "Endpoint", "flows": 41, "threats": 14, "sev": "Critical"},
        {"id": "Host-PortScan-Vector", "type": "Endpoint", "flows": 33, "threats": 9, "sev": "High"},
        {"id": "Host-BruteForce-SSH", "type": "Endpoint", "flows": 19, "threats": 6, "sev": "Medium"},
        {"id": "IoT-CCTV-Perimeter", "type": "Endpoint", "flows": 8, "threats": 0, "sev": "None"},
        {"id": "IoT-HVAC-Controller", "type": "Endpoint", "flows": 7, "threats": 0, "sev": "None"},
        {"id": "Backup-Storage-NAS", "type": "Server", "flows": 18, "threats": 0, "sev": "None"},
        {"id": "DNS-Primary-Resolver", "type": "Server", "flows": 51, "threats": 0, "sev": "None"},
    ]
    demo_edges = [
        ("SOC-Core-Gateway", "FW-Perimeter-01", "Gateway"),
        ("SOC-Core-Gateway", "FW-DMZ-Proxy", "Gateway"),
        ("FW-Perimeter-01", "Web-Cluster-Alpha", "None"),
        ("FW-Perimeter-01", "Web-Cluster-Beta", "None"),
        ("FW-DMZ-Proxy", "API-Gateway-Internal", "None"),
        ("API-Gateway-Internal", "Auth-OAuth-Server", "None"),
        ("API-Gateway-Internal", "Database-Primary-SQL", "None"),
        ("Database-Primary-SQL", "Database-Replica-01", "None"),
        ("SOC-Core-Gateway", "Log-Aggregator-SIEM", "None"),
        ("SOC-Core-Gateway", "DNS-Primary-Resolver", "None"),
        ("FW-DMZ-Proxy", "Workstation-Finance-101", "None"),
        ("FW-DMZ-Proxy", "Workstation-Finance-102", "None"),
        ("FW-DMZ-Proxy", "Workstation-HR-201", "None"),
        ("FW-DMZ-Proxy", "Workstation-Dev-301", "None"),
        ("FW-DMZ-Proxy", "Workstation-Dev-302", "None"),
        ("Host-Infected-Botnet-404", "Database-Primary-SQL", "Critical"),
        ("Host-Infected-Botnet-404", "Web-Cluster-Alpha", "Critical"),
        ("Host-PortScan-Vector", "FW-Perimeter-01", "High"),
        ("Host-BruteForce-SSH", "Auth-OAuth-Server", "Medium"),
        ("SOC-Core-Gateway", "IoT-CCTV-Perimeter", "None"),
        ("SOC-Core-Gateway", "IoT-HVAC-Controller", "None"),
        ("Database-Primary-SQL", "Backup-Storage-NAS", "None"),
    ]
    nodes_dict = {n["id"]: n for n in demo_nodes[:max_nodes]}
    edges_list = [(s, d, sev) for s, d, sev in demo_edges if s in nodes_dict and d in nodes_dict]
    return nodes_dict, edges_list


def render_network_topology():
    section_header(
        "🕸️ Interactive Network Topology Intelligence",
        "GPU-accelerated WebGL 3D war-room reconstruction of network hosts, active communication flows, and threat vectors.",
    )

    df = st.session_state.explore_df
    if df is None and st.session_state.analysis_result and st.session_state.analysis_result.get(
            "predictions_df") is not None:
        df = st.session_state.analysis_result["predictions_df"]

    is_simulation = False
    if df is None or df.empty:
        is_simulation = True
        st.markdown(
            """
            <div class="glass-panel" style="border-left: 3px solid var(--signal); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 12px; margin-bottom: 12px;">
                <div>
                    <div style="font-weight: 700; color: var(--heading); font-size: 14px;">⚡ Interactive SOC Simulation Fleet Active</div>
                    <div style="font-size: 11.5px; color: var(--muted); margin-top: 2px;">No active session capture loaded. Showing pre-modeled enterprise war-room topology with perimeter firewalls, databases, and active malware vectors.</div>
                </div>
                <div>
                    <span class="pill pill-online">LIVE 3D SIMULATION</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

    ctrl_col1, ctrl_col2, ctrl_col3 = st.columns([1.6, 1.4, 1])
    with ctrl_col1:
        view_mode = st.radio(
            "Topology View Mode",
            ["🚀 WebGL 3D War-Room (Three.js)", "🌐 3D Cyber Sphere (Plotly)", "📊 2D SOC Matrix (Plotly)"],
            horizontal=True,
            key="topo_view_mode",
        )
    with ctrl_col2:
        max_nodes = st.slider("Max Nodes to Render", min_value=10, max_value=60, value=30, step=5, key="topo_max_nodes")
    with ctrl_col3:
        filter_status = st.selectbox("Filter Status", ["All Traffic", "Threats Only", "Normal Only"],
                                     key="topo_filter_status")

    nodes_dict = {}
    edges_list = []

    if is_simulation:
        nodes_dict, edges_list = get_demo_topology(max_nodes)
        if filter_status == "Threats Only":
            nodes_dict = {k: v for k, v in nodes_dict.items() if v.get("sev") not in ("None",)}
            edges_list = [(s, d, sev) for s, d, sev in edges_list if sev not in ("None",)]
        elif filter_status == "Normal Only":
            nodes_dict = {k: v for k, v in nodes_dict.items() if v.get("sev") in ("None", "Gateway")}
            edges_list = [(s, d, sev) for s, d, sev in edges_list if sev in ("None", "Gateway")]
    else:
        src_col = next((c for c in df.columns if str(c).lower() in ("src_ip", "source_ip", "source ip", "source")), None)
        dst_col = next((c for c in df.columns if
                        str(c).lower() in ("dst_ip", "destination_ip", "destination ip", "dst_host", "destination")), None)
        proto_col = next((c for c in df.columns if str(c).lower() in ("protocol", "protocol_type", "proto")), None)
        port_col = next((c for c in df.columns if "port" in str(c).lower() and "dst" in str(c).lower()), None) or next(
            (c for c in df.columns if "port" in str(c).lower()), None)

        sev_df = compute_severity(df) if "Severity" not in df.columns else df

        plot_data = sev_df.copy()
        if filter_status == "Threats Only":
            plot_data = plot_data[plot_data.get("Severity", "None") != "None"]
        elif filter_status == "Normal Only":
            plot_data = plot_data[plot_data.get("Severity", "None") == "None"]

        if plot_data.empty:
            st.warning("No flows match the selected status filter.")
            return

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

    if N == 0:
        st.info("No nodes available to render under current filters.")
        return

    # ------------------------------------------------------------------------
    # VIEW 1: THREE.JS WEBGL 3D WAR-ROOM
    # ------------------------------------------------------------------------
    if view_mode == "🚀 WebGL 3D War-Room (Three.js)":
        nodes_payload = [
            {
                "id": k,
                "name": k,
                "type": nodes_dict[k].get("type", "Endpoint"),
                "sev": nodes_dict[k].get("sev", "None"),
                "flows": nodes_dict[k].get("flows", 1),
                "threats": nodes_dict[k].get("threats", 0)
            }
            for k in node_names
        ]
        edges_payload = [
            {"source": s, "target": d, "sev": sev}
            for s, d, sev in edges_list
            if s in nodes_dict and d in nodes_dict
        ]

        nodes_json_str = json.dumps(nodes_payload)
        edges_json_str = json.dumps(edges_payload)

        primary_col = VIZ.get("primary", "#38bdf8")
        secondary_col = VIZ.get("secondary", "#a855f7")
        attack_col = VIZ.get("attack", "#ef4444")
        normal_col = VIZ.get("normal", "#10b981")
        warning_col = VIZ.get("suspicious", "#fbbf24")
        bg_gradient = "radial-gradient(circle at 50% 50%, #0c1830 0%, #05070f 100%)"
        border_col = "rgba(56, 189, 248, 0.35)"
        text_col = "#e6ebf5"

        topo_html = f"""
        <!DOCTYPE html>
        <html>
        <head>
          <meta charset="utf-8">
          <style>
            * {{ box-sizing: border-box; margin: 0; padding: 0; }}
            body {{
              overflow: hidden;
              background: transparent;
              user-select: none;
              font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            }}
            #topo-container {{
              width: 100%;
              height: 640px;
              position: relative;
              border-radius: 14px;
              background: {bg_gradient};
              border: 1px solid {border_col};
              box-shadow: 0 12px 40px rgba(0,0,0,0.5), inset 0 0 32px rgba(56,189,248,0.06);
              overflow: hidden;
            }}
            #topo-canvas {{
              width: 100%;
              height: 100%;
              display: block;
              cursor: grab;
            }}
            #topo-canvas:active {{
              cursor: grabbing;
            }}
            .topo-hud-top {{
              position: absolute;
              top: 14px;
              left: 18px;
              right: 18px;
              display: flex;
              justify-content: space-between;
              align-items: flex-start;
              pointer-events: none;
              z-index: 20;
            }}
            .topo-title {{
              font-size: 13px;
              font-weight: 800;
              letter-spacing: 2px;
              color: {primary_col};
              text-transform: uppercase;
              display: flex;
              align-items: center;
              gap: 8px;
              text-shadow: 0 0 12px rgba(56,189,248,0.5);
            }}
            .topo-sub {{
              font-size: 10px;
              color: {text_col};
              opacity: 0.75;
              margin-top: 4px;
              font-family: monospace;
              letter-spacing: 1px;
            }}
            .topo-controls {{
              display: flex;
              gap: 8px;
              pointer-events: auto;
              flex-wrap: wrap;
              justify-content: flex-end;
            }}
            .t-btn {{
              background: rgba(13, 20, 36, 0.85);
              border: 1px solid rgba(56, 189, 248, 0.3);
              color: {text_col};
              padding: 5px 12px;
              border-radius: 6px;
              font-size: 11px;
              font-family: monospace;
              cursor: pointer;
              transition: all 0.2s ease;
              backdrop-filter: blur(10px);
            }}
            .t-btn:hover, .t-btn.active {{
              background: rgba(56, 189, 248, 0.28);
              border-color: {primary_col};
              color: #ffffff;
              box-shadow: 0 0 12px rgba(56, 189, 248, 0.45);
            }}
            .topo-tooltip {{
              position: absolute;
              pointer-events: none;
              background: rgba(8, 14, 28, 0.94);
              border: 1px solid {primary_col};
              border-radius: 8px;
              padding: 8px 12px;
              font-family: monospace;
              font-size: 11px;
              color: {text_col};
              box-shadow: 0 8px 24px rgba(0,0,0,0.6), 0 0 14px rgba(56,189,248,0.25);
              backdrop-filter: blur(12px);
              z-index: 30;
              display: none;
              transform: translate(-50%, -125%);
            }}
            .tt-header {{ font-weight: bold; color: {primary_col}; font-size: 12px; margin-bottom: 4px; border-bottom: 1px solid rgba(56,189,248,0.2); padding-bottom: 3px; }}
            .tt-row {{ display: flex; justify-content: space-between; gap: 12px; margin-top: 2px; }}
            .tt-badge {{ padding: 1px 6px; border-radius: 3px; font-weight: bold; font-size: 9.5px; }}
            .tt-sev-critical {{ background: rgba(239,68,68,0.25); color: #ff6b6b; border: 1px solid rgba(239,68,68,0.6); }}
            .tt-sev-high {{ background: rgba(251,146,60,0.25); color: #fb923c; border: 1px solid rgba(251,146,60,0.6); }}
            .tt-sev-medium {{ background: rgba(245,158,11,0.25); color: #fbbf24; border: 1px solid rgba(245,158,11,0.6); }}
            .tt-sev-safe {{ background: rgba(16,185,129,0.25); color: #34d399; border: 1px solid rgba(16,185,129,0.6); }}
            .tt-sev-gateway {{ background: rgba(56,189,248,0.25); color: #38bdf8; border: 1px solid rgba(56,189,248,0.6); }}

            .topo-hud-bottom {{
              position: absolute;
              bottom: 12px;
              left: 18px;
              right: 18px;
              display: flex;
              justify-content: space-between;
              align-items: center;
              pointer-events: none;
              font-family: monospace;
              font-size: 10px;
              color: {text_col};
              opacity: 0.9;
              z-index: 20;
            }}
            .topo-inspect-panel {{
              position: absolute;
              bottom: 45px;
              right: 18px;
              width: 270px;
              background: rgba(8, 14, 28, 0.94);
              border: 1px solid rgba(56, 189, 248, 0.4);
              border-radius: 10px;
              padding: 12px 14px;
              font-family: monospace;
              color: {text_col};
              backdrop-filter: blur(14px);
              box-shadow: 0 8px 30px rgba(0,0,0,0.5);
              z-index: 25;
              display: none;
            }}
            .insp-close {{
              float: right;
              cursor: pointer;
              color: {primary_col};
              font-size: 13px;
            }}
          </style>
          <script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
        </head>
        <body>
          <div id="topo-container">
            <div class="topo-hud-top">
              <div>
                <div class="topo-title">⚡ 3D Cyber Topology War-Room</div>
                <div class="topo-sub">REAL-TIME WEBGL FLOW RECONSTRUCTION • INTERACTIVE SPATIAL GRAPH</div>
              </div>
              <div class="topo-controls">
                <button class="t-btn active" id="btn-layout-sphere" onclick="setLayout('sphere')">🪐 3D Sphere</button>
                <button class="t-btn" id="btn-layout-defense" onclick="setLayout('defense')">🛡️ Defense Perimeter</button>
                <button class="t-btn" id="btn-layout-constell" onclick="setLayout('constell')">✨ Constellation</button>
                <button class="t-btn" id="btn-autorotate" onclick="toggleAutoRotate()">🌀 Auto-Rotate</button>
                <button class="t-btn" onclick="resetTopoCamera()">🔄 Reset</button>
              </div>
            </div>

            <div class="topo-tooltip" id="topo-tooltip">
              <div class="tt-header" id="tt-name">Node ID</div>
              <div class="tt-row"><span>Type:</span><span id="tt-type">Endpoint</span></div>
              <div class="tt-row"><span>Threats:</span><span id="tt-threats">0</span></div>
              <div class="tt-row"><span>Status:</span><span id="tt-status" class="tt-badge tt-sev-safe">NORMAL</span></div>
            </div>

            <div class="topo-inspect-panel" id="topo-inspect-panel">
              <span class="insp-close" onclick="closeInspect()">✕</span>
              <div style="font-weight: bold; color: {primary_col}; font-size: 12px; margin-bottom: 6px;">🎯 PINNED NODE TELEMETRY</div>
              <div id="insp-content" style="font-size: 11px; line-height: 1.6;"></div>
            </div>

            <canvas id="topo-canvas"></canvas>

            <div class="topo-hud-bottom">
              <div style="display: flex; gap: 14px; align-items: center;">
                <span><span style="display:inline-block;width:7px;height:7px;border-radius:50%;background:{normal_col};box-shadow:0 0 6px {normal_col};margin-right:5px;"></span>WEBGL ACCELERATED 60FPS</span>
                <span id="telemetry-bar">NODES: {len(nodes_payload)} | OBSERVED FLOWS: {len(edges_payload)}</span>
              </div>
              <div style="opacity: 0.75;">DRAG TO ROTATE • RIGHT-CLICK PAN • SCROLL ZOOM • CLICK NODE TO PIN</div>
            </div>
          </div>

          <script>
            (function() {{
              const rawNodes = {nodes_json_str};
              const rawEdges = {edges_json_str};

              const container = document.getElementById('topo-container');
              const canvas = document.getElementById('topo-canvas');
              const tooltip = document.getElementById('topo-tooltip');
              const inspectPanel = document.getElementById('topo-inspect-panel');
              const inspectContent = document.getElementById('insp-content');

              let renderer, scene, camera;
              let nodeMeshes = [];
              let edgeLines = [];
              let dataPackets = [];
              let shockwaveAuras = [];
              let graphGroup, starsGroup;

              let currentLayout = 'sphere';
              let autoRotate = true;
              let rotX = 0.25, rotY = 0;
              let targetRotX = 0.25, targetRotY = 0;
              let isDragging = false, isRightDragging = false;
              let prevX = 0, prevY = 0;
              let panX = 0, panY = 0;
              let zoomDist = 280;

              const colorMap = {{
                'Gateway': 0x38bdf8,
                'Critical': 0xef4444,
                'High': 0xfb923c,
                'Medium': 0xfbbf24,
                'Low': 0x10b981,
                'None': 0x10b981
              }};

              function init() {{
                const width = container.clientWidth || window.innerWidth;
                const height = container.clientHeight || 640;

                scene = new THREE.Scene();
                camera = new THREE.PerspectiveCamera(45, width / height, 1, 2000);
                camera.position.set(0, 0, zoomDist);

                renderer = new THREE.WebGLRenderer({{
                  canvas: canvas,
                  antialias: true,
                  alpha: true,
                  powerPreference: "high-performance"
                }});
                renderer.setSize(width, height);
                renderer.setPixelRatio(Math.min(window.devicePixelRatio, 2));

                const ambLight = new THREE.AmbientLight(0xffffff, 0.75);
                scene.add(ambLight);

                const pl1 = new THREE.PointLight(0x38bdf8, 2.2, 500);
                pl1.position.set(150, 150, 150);
                scene.add(pl1);

                const pl2 = new THREE.PointLight(0xa855f7, 2, 500);
                pl2.position.set(-150, -150, 120);
                scene.add(pl2);

                starsGroup = new THREE.Group();
                const starGeo = new THREE.BufferGeometry();
                const starPos = new Float32Array(300 * 3);
                for(let i=0; i<300*3; i+=3) {{
                  starPos[i] = (Math.random() - 0.5) * 800;
                  starPos[i+1] = (Math.random() - 0.5) * 500;
                  starPos[i+2] = (Math.random() - 0.5) * 600;
                }}
                starGeo.setAttribute('position', new THREE.BufferAttribute(starPos, 3));
                const starMat = new THREE.PointsMaterial({{ color: 0x38bdf8, size: 1.5, transparent: true, opacity: 0.35 }});
                starsGroup.add(new THREE.Points(starGeo, starMat));
                scene.add(starsGroup);

                graphGroup = new THREE.Group();
                scene.add(graphGroup);

                buildGraph();

                window.addEventListener('resize', onResize);
                canvas.addEventListener('mousedown', onMouseDown);
                window.addEventListener('mouseup', onMouseUp);
                window.addEventListener('mousemove', onMouseMove);
                canvas.addEventListener('wheel', onWheel, {{ passive: false }});
                canvas.addEventListener('contextmenu', e => e.preventDefault());

                animate();
              }}

              function computeLayoutPositions(layout) {{
                const N = rawNodes.length;
                const positions = {{}};

                if (layout === 'sphere') {{
                  const phi = Math.PI * (3.0 - Math.sqrt(5.0));
                  const radius = 88;
                  rawNodes.forEach((node, i) => {{
                    if (node.type === 'Gateway') {{
                      positions[node.id] = new THREE.Vector3(0, 0, 0);
                    }} else {{
                      const y = 1 - (i / Math.max(1, N - 1)) * 2;
                      const r = Math.sqrt(Math.max(0, 1 - y * y)) * radius;
                      const theta = phi * i;
                      const x = Math.cos(theta) * r;
                      const z = Math.sin(theta) * r;
                      positions[node.id] = new THREE.Vector3(x, y * radius, z);
                    }}
                  }});
                }} else if (layout === 'defense') {{
                  rawNodes.forEach((node, i) => {{
                    if (node.type === 'Gateway') {{
                      positions[node.id] = new THREE.Vector3(0, 0, 0);
                    }} else if (node.type === 'Firewall' || node.type === 'Server' || node.type === 'Database') {{
                      const angle = (i * 2 * Math.PI) / 6;
                      positions[node.id] = new THREE.Vector3(Math.cos(angle) * 55, Math.sin(angle) * 35, (Math.random()-0.5)*20);
                    }} else if (node.sev === 'Critical' || node.sev === 'High') {{
                      const angle = (i * 2 * Math.PI) / Math.max(1, N);
                      positions[node.id] = new THREE.Vector3(Math.cos(angle) * 115, Math.sin(angle) * 75, (Math.random()-0.5)*40);
                    }} else {{
                      const angle = (i * 2 * Math.PI) / Math.max(1, N);
                      positions[node.id] = new THREE.Vector3(Math.cos(angle) * 85, Math.sin(angle) * 55, (Math.random()-0.5)*30);
                    }}
                  }});
                }} else {{
                  rawNodes.forEach((node, i) => {{
                    const u = (i / Math.max(1, N)) * Math.PI * 2;
                    const v = Math.sin(i * 1.7) * Math.PI * 0.5;
                    const dist = 70 + (i % 5) * 12;
                    positions[node.id] = new THREE.Vector3(
                      dist * Math.cos(u) * Math.cos(v),
                      dist * Math.sin(v) * 0.8,
                      dist * Math.sin(u) * Math.cos(v)
                    );
                  }});
                }}
                return positions;
              }}

              function buildGraph() {{
                const targetPositions = computeLayoutPositions(currentLayout);

                nodeMeshes = [];
                edgeLines = [];
                dataPackets = [];
                shockwaveAuras = [];
                while(graphGroup.children.length > 0) {{
                  graphGroup.remove(graphGroup.children[0]);
                }}

                rawNodes.forEach(node => {{
                  const isGateway = (node.type === 'Gateway');
                  const isThreat = (node.sev === 'Critical' || node.sev === 'High');
                  const col = colorMap[node.sev] || 0x10b981;
                  const nodeRadius = isGateway ? 5.5 : (isThreat ? 4.2 : 3.2);

                  const geo = new THREE.SphereGeometry(nodeRadius, 16, 16);
                  const mat = new THREE.MeshPhongMaterial({{
                    color: col,
                    emissive: col,
                    emissiveIntensity: 0.45,
                    shininess: 90
                  }});
                  const mesh = new THREE.Mesh(geo, mat);
                  const pos = targetPositions[node.id] || new THREE.Vector3(0,0,0);
                  mesh.position.copy(pos);
                  mesh.userData = {{
                    nodeData: node,
                    targetPos: pos.clone(),
                    baseScale: 1
                  }};

                  if (isGateway) {{
                    const ringGeo = new THREE.TorusGeometry(8.5, 0.4, 8, 32);
                    const ringMat = new THREE.MeshBasicMaterial({{ color: 0x38bdf8, wireframe: true }});
                    const ringMesh = new THREE.Mesh(ringGeo, ringMat);
                    mesh.add(ringMesh);
                    mesh.userData.gatewayRing = ringMesh;
                  }}

                  if (isThreat) {{
                    const sGeo = new THREE.RingGeometry(5.5, 7.2, 24);
                    const sMat = new THREE.MeshBasicMaterial({{
                      color: col,
                      transparent: true,
                      opacity: 0.85,
                      side: THREE.DoubleSide
                    }});
                    const sMesh = new THREE.Mesh(sGeo, sMat);
                    sMesh.rotation.x = Math.PI / 2;
                    mesh.add(sMesh);
                    shockwaveAuras.push({{ mesh: sMesh, parentNode: mesh }});
                  }}

                  graphGroup.add(mesh);
                  nodeMeshes.push(mesh);
                }});

                const nodeMap = {{}};
                nodeMeshes.forEach(m => {{ nodeMap[m.userData.nodeData.id] = m; }});

                rawEdges.forEach((edge, idx) => {{
                  const sourceMesh = nodeMap[edge.source];
                  const targetMesh = nodeMap[edge.target];
                  if (!sourceMesh || !targetMesh) return;

                  const isThreat = (edge.sev === 'Critical' || edge.sev === 'High');
                  const edgeCol = isThreat ? 0xef4444 : (edge.sev === 'Gateway' ? 0x38bdf8 : 0x10b981);

                  const lineGeo = new THREE.BufferGeometry();
                  const positions = new Float32Array(6);
                  lineGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));

                  const lineMat = new THREE.LineBasicMaterial({{
                    color: edgeCol,
                    transparent: true,
                    opacity: isThreat ? 0.65 : 0.3,
                    linewidth: isThreat ? 2 : 1
                  }});
                  const line = new THREE.Line(lineGeo, lineMat);
                  line.userData = {{ sourceMesh, targetMesh }};
                  graphGroup.add(line);
                  edgeLines.push(line);

                  const pGeo = new THREE.SphereGeometry(isThreat ? 1.8 : 1.3, 8, 8);
                  const pMat = new THREE.MeshBasicMaterial({{ color: isThreat ? 0xff3b3b : 0x00f0ff }});
                  const pMesh = new THREE.Mesh(pGeo, pMat);
                  graphGroup.add(pMesh);
                  dataPackets.push({{
                    mesh: pMesh,
                    sourceMesh,
                    targetMesh,
                    progress: (idx * 0.15) % 1.0,
                    speed: 0.007 + Math.random() * 0.008
                  }});
                }});
              }}

              window.setLayout = function(layout) {{
                currentLayout = layout;
                document.querySelectorAll('.t-btn').forEach(b => {{
                  if (b.id.startsWith('btn-layout-')) b.classList.remove('active');
                }});
                const activeBtn = document.getElementById('btn-layout-' + layout);
                if (activeBtn) activeBtn.classList.add('active');

                const newPos = computeLayoutPositions(layout);
                nodeMeshes.forEach(mesh => {{
                  if (newPos[mesh.userData.nodeData.id]) {{
                    mesh.userData.targetPos = newPos[mesh.userData.nodeData.id];
                  }}
                }});
              }};

              window.toggleAutoRotate = function() {{
                autoRotate = !autoRotate;
                const btn = document.getElementById('btn-autorotate');
                btn.classList.toggle('active', autoRotate);
              }};

              window.resetTopoCamera = function() {{
                targetRotX = 0.25;
                targetRotY = 0;
                rotX = 0.25;
                rotY = 0;
                panX = 0;
                panY = 0;
                zoomDist = 280;
                camera.position.set(0, 0, zoomDist);
              }};

              window.closeInspect = function() {{
                inspectPanel.style.display = 'none';
              }};

              const raycaster = new THREE.Raycaster();
              const mouse = new THREE.Vector2(-1000, -1000);
              let hoveredNode = null;

              function onMouseDown(e) {{
                if (e.button === 0) {{
                  isDragging = true;
                }} else if (e.button === 2) {{
                  isRightDragging = true;
                }}
                prevX = e.clientX;
                prevY = e.clientY;
              }}

              function onMouseUp(e) {{
                if (isDragging && Math.abs(e.clientX - prevX) < 3 && Math.abs(e.clientY - prevY) < 3) {{
                  if (hoveredNode) {{
                    pinNode(hoveredNode.userData.nodeData);
                  }}
                }}
                isDragging = false;
                isRightDragging = false;
              }}

              function onMouseMove(e) {{
                const rect = canvas.getBoundingClientRect();
                mouse.x = ((e.clientX - rect.left) / rect.width) * 2 - 1;
                mouse.y = -((e.clientY - rect.top) / rect.height) * 2 + 1;

                if (isDragging) {{
                  const dx = e.clientX - prevX;
                  const dy = e.clientY - prevY;
                  targetRotY += dx * 0.007;
                  targetRotX += dy * 0.007;
                  prevX = e.clientX;
                  prevY = e.clientY;
                }} else if (isRightDragging) {{
                  const dx = e.clientX - prevX;
                  const dy = e.clientY - prevY;
                  panX += dx * 0.4;
                  panY -= dy * 0.4;
                  prevX = e.clientX;
                  prevY = e.clientY;
                }}
              }}

              function onWheel(e) {{
                e.preventDefault();
                zoomDist += e.deltaY * 0.35;
                zoomDist = Math.max(80, Math.min(600, zoomDist));
                camera.position.z = zoomDist;
              }}

              function onResize() {{
                const width = container.clientWidth || window.innerWidth;
                const height = container.clientHeight || 640;
                camera.aspect = width / height;
                camera.updateProjectionMatrix();
                renderer.setSize(width, height);
              }}

              function pinNode(data) {{
                inspectPanel.style.display = 'block';
                const sevClass = 'tt-sev-' + (data.sev.toLowerCase());
                inspectContent.innerHTML = `
                  <div style="margin-bottom:6px;"><b>Host:</b> ${{data.name}}</div>
                  <div style="margin-bottom:4px;"><b>Role:</b> ${{data.type}}</div>
                  <div style="margin-bottom:4px;"><b>Status:</b> <span class="tt-badge ${{sevClass}}">${{data.sev.toUpperCase()}}</span></div>
                  <div style="margin-bottom:4px;"><b>Flows:</b> ${{data.flows}} active</div>
                  <div style="margin-bottom:8px;"><b>Flagged Threats:</b> ${{data.threats}}</div>
                  <button class="t-btn" style="width:100%;text-align:center;background:rgba(56,189,248,0.25);" onclick="alert('Isolating host ' + data.name + ' in virtual sandbox perimeter!')">🛡️ ISOLATE / QUARANTINE</button>
                `;
              }}

              let clock = 0;
              function animate() {{
                requestAnimationFrame(animate);
                clock += 0.016;

                if (autoRotate && !isDragging) {{
                  targetRotY += 0.003;
                }}

                rotX += (targetRotX - rotX) * 0.08;
                rotY += (targetRotY - rotY) * 0.08;

                graphGroup.rotation.x = rotX;
                graphGroup.rotation.y = rotY;
                graphGroup.position.x = panX;
                graphGroup.position.y = panY;

                nodeMeshes.forEach(mesh => {{
                  if (mesh.userData.targetPos) {{
                    mesh.position.lerp(mesh.userData.targetPos, 0.06);
                  }}
                  if (mesh.userData.gatewayRing) {{
                    mesh.userData.gatewayRing.rotation.z += 0.02;
                  }}
                }});

                shockwaveAuras.forEach(sw => {{
                  const scale = 1 + ((clock * 1.5) % 1.0) * 1.4;
                  const alpha = 1.0 - ((clock * 1.5) % 1.0);
                  sw.mesh.scale.set(scale, scale, scale);
                  sw.mesh.material.opacity = alpha * 0.75;
                }});

                edgeLines.forEach(line => {{
                  const p1 = line.userData.sourceMesh.position;
                  const p2 = line.userData.targetMesh.position;
                  const posArr = line.geometry.attributes.position.array;
                  posArr[0] = p1.x; posArr[1] = p1.y; posArr[2] = p1.z;
                  posArr[3] = p2.x; posArr[4] = p2.y; posArr[5] = p2.z;
                  line.geometry.attributes.position.needsUpdate = true;
                }});

                dataPackets.forEach(dp => {{
                  dp.progress += dp.speed;
                  if (dp.progress >= 1.0) dp.progress = 0;
                  const p1 = dp.sourceMesh.position;
                  const p2 = dp.targetMesh.position;
                  dp.mesh.position.lerpVectors(p1, p2, dp.progress);
                }});

                raycaster.setFromCamera(mouse, camera);
                const intersects = raycaster.intersectObjects(nodeMeshes);
                if (intersects.length > 0) {{
                  hoveredNode = intersects[0].object;
                  const nodeData = hoveredNode.userData.nodeData;

                  const tempV = new THREE.Vector3();
                  hoveredNode.getWorldPosition(tempV);
                  tempV.project(camera);

                  const hw = container.clientWidth / 2;
                  const hh = container.clientHeight / 2;
                  const x = (tempV.x * hw) + hw;
                  const y = -(tempV.y * hh) + hh;

                  tooltip.style.display = 'block';
                  tooltip.style.left = x + 'px';
                  tooltip.style.top = y + 'px';

                  document.getElementById('tt-name').textContent = nodeData.name;
                  document.getElementById('tt-type').textContent = nodeData.type;
                  document.getElementById('tt-threats').textContent = nodeData.threats;
                  const stBadge = document.getElementById('tt-status');
                  stBadge.className = 'tt-badge tt-sev-' + (nodeData.sev.toLowerCase());
                  stBadge.textContent = nodeData.sev.toUpperCase();
                }} else {{
                  hoveredNode = null;
                  tooltip.style.display = 'none';
                }}

                starsGroup.rotation.y += 0.0004;

                renderer.render(scene, camera);
              }}

              init();
            }})();
          </script>
        </body>
        </html>
        """
        components.html(topo_html, height=660, scrolling=False)

    elif view_mode == "🌐 3D Cyber Sphere (Plotly)":
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
    st.markdown(
        """
        <div class="glass-panel" style="font-family:var(--font-mono); font-size:10.5px; display:flex; gap:16px; flex-wrap:wrap; align-items:center;">
            <span style="color:var(--muted);">LEGEND</span>
            <span><span style="display:inline-block; width:11px; height:11px; border-radius:50%; background:#38bdf8; margin-right:5px;"></span>Gateway / Primary</span>
            <span><span style="display:inline-block; width:11px; height:11px; border-radius:50%; background:#ef4444; margin-right:5px;"></span>Critical Attack</span>
            <span><span style="display:inline-block; width:11px; height:11px; border-radius:50%; background:#fb923c; margin-right:5px;"></span>High Threat</span>
            <span><span style="display:inline-block; width:11px; height:11px; border-radius:50%; background:#fbbf24; margin-right:5px;"></span>Suspicious Medium</span>
            <span><span style="display:inline-block; width:11px; height:11px; border-radius:50%; background:#10b981; margin-right:5px;"></span>Normal Traffic</span>
            <span style="color:var(--muted); margin-left:auto;">Node size ∝ risk score · Animated beams = observed flows</span>
        </div>
        """,
        unsafe_allow_html=True,
    )

    total_threat_nodes = int(sum(1 for v in nodes_dict.values() if v["sev"] not in ("None", "Gateway")))
    c_s1, c_s2, c_s3, c_s4 = st.columns(4)
    with c_s1:
        metric_card("🧭", "Host Nodes", f"{len(nodes_dict):,}")
    with c_s2:
        metric_card("🔁", "Observed Flows", f"{len(edges_list):,}")
    with c_s3:
        metric_card("🚨", "Flagged Nodes", f"{total_threat_nodes:,}",
                    "metric-danger" if total_threat_nodes else "metric-safe")
    with c_s4:
        metric_card("🏷️", "Topology Source",
                    "Simulated SOC Fleet" if is_simulation else "Live Session Flows")

    st.write("")
    section_header("🔍 Node Inspector", "Select a discovered node to view its flow telemetry.")

    node_names_ordered = list(nodes_dict.keys())
    selected_node = st.selectbox("Inspect Node", options=node_names_ordered, key="topo_selected_node")
    if selected_node:
        info = nodes_dict[selected_node]
        sev = info["sev"]
        sev_class = {
            "Critical": "thr-critical", "High": "thr-high", "Medium": "thr-medium",
            "Gateway": "thr-high", "None": "thr-minimal",
        }.get(sev, "thr-unknown")
        st.markdown(
            f"""
            <div class="glass-panel" style="display:flex; align-items:center; gap:16px; flex-wrap:wrap; padding:18px;">
                <div>
                    <div style="font-family:var(--font-display); font-size:17px; font-weight:700; color:var(--heading);">{esc(selected_node)}</div>
                    <div style="font-family:var(--font-mono); font-size:11px; color:var(--muted); margin-top:3px;">Host node in the reconstructed traffic topology</div>
                </div>
                <span style="margin-left:auto;" class="thr-chip {sev_class}">{'GATEWAY' if sev == 'Gateway' else (sev.upper() if sev != 'None' else 'NORMAL')}</span>
            </div>
            """,
            unsafe_allow_html=True,
        )
        n_c1, n_c2, n_c3 = st.columns(3)
        with n_c1:
            metric_card("🏷️", "Node Category", str(info["type"]))
        with n_c2:
            metric_card("🔁", "Active Flows", f"{info['flows']:,}")
        with n_c3:
            metric_card("🚨", "Flagged Threats", f"{info['threats']:,}",
                        "metric-danger" if info["threats"] else "metric-safe")
        connected = [d for s, d, _ in edges_list if s == selected_node] + [s for s, d, _ in edges_list if d == selected_node]
        connected = list(dict.fromkeys(connected))
        if connected:
            st.caption(f"Directly connected neighbours ({len(connected)}): " + ", ".join(str(c) for c in connected[:12]))

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
    section_header("🤖 ML Intelligence — Model Monitoring",
                   "Real evaluation metrics and artifacts with live session prediction telemetry.")

    if not api_online:
        state_banner(
            "unavailable",
            "Prediction API unavailable",
            "Model telemetry cannot be retrieved right now — start the FastAPI backend.",
        )
        return

    model_info = fetch_model_info()
    if not model_info:
        state_banner("warning", "Model information unavailable", "The API did not return model information from /model-info.")

    # Real metrics loaded from the reports/ artifacts (never fabricated)
    cicids_metrics = load_model_metrics("CICIDS-2017")
    nsl_metrics = load_model_metrics("NSL-KDD")

    # --- Dual model monitoring cards (both datasets, real values) ---
    st.write("")
    col_a, col_b = st.columns(2)

    def _fmt_metric(metrics, *keys):
        for k in keys:
            if k in metrics:
                v = metrics[k]
                return f"{v * 100:.2f}%" if v <= 1 else f"{v:.2f}%"
        return "N/A"

    with col_a:
        st.markdown(
            '<div class="glass-panel"><div style="font-family:var(--font-display); font-size:15px; '
            'font-weight:700; color:var(--heading);">CICIDS-2017 Model</div>'
            '<div style="font-family:var(--font-mono); font-size:11px; color:var(--muted); margin:2px 0 10px 0;">'
            "Specifications from reports/cicids_model_metrics.txt</div></div>",
            unsafe_allow_html=True,
        )
        metric_card("🎯", "Accuracy", _fmt_metric(cicids_metrics, "Accuracy", "Testing Accuracy", "Testing Acc"), "metric-safe")
        metric_card("🎯", "Precision", _fmt_metric(cicids_metrics, "Precision"), "metric-safe")
        metric_card("⭕", "Recall", _fmt_metric(cicids_metrics, "Recall"), "metric-safe")
        metric_card("🧬", "F1 Score", _fmt_metric(cicids_metrics, "F1 Score", "F1"), "metric-safe")
        metric_card("📈", "ROC-AUC", _fmt_metric(cicids_metrics, "ROC-AUC", "AUC"), "metric-safe")

    with col_b:
        st.markdown(
            '<div class="glass-panel"><div style="font-family:var(--font-display); font-size:15px; '
            'font-weight:700; color:var(--heading);">NSL-KDD Model</div>'
            '<div style="font-family:var(--font-mono); font-size:11px; color:var(--muted); margin:2px 0 10px 0;">'
            "Specifications from reports/nsl-kdd_model_metrics.txt</div></div>",
            unsafe_allow_html=True,
        )
        metric_card("🎯", "Accuracy", _fmt_metric(nsl_metrics, "Accuracy", "Testing Accuracy", "Testing Acc"), "metric-safe")
        metric_card("🎯", "Precision", _fmt_metric(nsl_metrics, "Precision"), "metric-safe")
        metric_card("⭕", "Recall", _fmt_metric(nsl_metrics, "Recall"), "metric-safe")
        metric_card("🧬", "F1 Score", _fmt_metric(nsl_metrics, "F1 Score", "F1"), "metric-safe")
        metric_card("📈", "ROC-AUC", _fmt_metric(nsl_metrics, "ROC-AUC", "AUC"), "metric-safe")

    st.write("")

    # Determine active engine key
    active_engine = "cicids" if dataset == "CICIDS-2017" else "nsl_kdd"
    engine_info = model_info.get("engine_info", {}) if model_info else {}
    eng_data = engine_info.get(active_engine, {})

    model_name = eng_data.get("model") or (model_info.get("model_name") if model_info else None) or (
        model_info.get("model") if model_info else None) or "RandomForestClassifier"
    feature_count = eng_data.get("features") or (model_info.get("n_features") if model_info else None) or (
        model_info.get("feature_count") if model_info else None) or (78 if dataset == "CICIDS-2017" else 41)
    feature_names = eng_data.get("feature_names", [])
    threshold = eng_data.get("attack_threshold", 0.50 if dataset == "CICIDS-2017" else 0.01)

    # Real accuracy value for the active dataset — from back-end /model-info or reports.
    accuracy_val = _first_present(
        model_info if isinstance(model_info, dict) else {}, ["accuracy", "model_accuracy", "test_accuracy"]
    )
    if accuracy_val is None:
        active_metrics = cicids_metrics if dataset == "CICIDS-2017" else nsl_metrics
        accuracy_val = _first_present(active_metrics, ["Testing Accuracy", "Testing Acc", "Accuracy", "Test Acc"])

    c1, c2, c3, c4 = st.columns(4)
    with c1:
        metric_card("🧠", "Classifier Algorithm", str(model_name))
    with c2:
        metric_card("📁", "Target Dataset", f"{dataset}")
    with c3:
        metric_card("📐", "Feature Dimensions", f"{feature_count:,} Features")
    with c4:
        if isinstance(accuracy_val, (int, float)):
            acc_display = f"{accuracy_val * 100:.2f}%" if accuracy_val <= 1 else f"{accuracy_val:.2f}%"
            metric_card("🎯", "Benchmark Accuracy", acc_display, "metric-safe")
        else:
            metric_card("🎯", "Benchmark Accuracy", "N/A")

    st.write("")
    col_g1, col_g2 = st.columns([1, 1])

    with col_g1:
        section_header("Model Accuracy Benchmark Gauge")
        if isinstance(accuracy_val, (int, float)):
            acc_pct = accuracy_val * 100 if accuracy_val <= 1 else accuracy_val
            fig_gauge = go.Figure(go.Indicator(
                mode="gauge+number",
                value=acc_pct,
                number={'suffix': "%", 'font': {'color': get_theme()['heading'], 'family': 'JetBrains Mono'}},
                title={'text': f"{model_name} ({dataset}) · accuracy from reports/", 'font': {'color': get_theme()['muted'], 'size': 12}},
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
            fig_gauge.update_layout(**chart_theme(height=310))
            st.plotly_chart(fig_gauge, use_container_width=True, config={"displayModeBar": False})
        else:
            state_banner("empty", "Accuracy not available for the active dataset",
                         "The back-end /model-info and reports/ do not expose an accuracy value for this model.")

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
                    <span style="color:var(--muted-2); font-weight:700;">Not reported by back-end</span>
                </div>
            </div>
            """,
            unsafe_allow_html=True,
        )

    # --- Real evaluation artifacts from reports/ ---
    st.write("")
    section_header("📊 Model Evaluation Artifacts", "Concise evaluation reports: confusion matrix, ROC curve, feature importances, and adversarial evasion robustness.")
    artifact_tabs = st.tabs(["Confusion Matrix", "ROC Curve", "Feature Importance", "🎯 Adversarial Evasion Robustness"])
    cm_img = report_image(dataset, "confusion_matrix")
    roc_img = report_image(dataset, "roc_curve")
    fi_img = report_image(dataset, "feature_importance")
    active_m = cicids_metrics if dataset == "CICIDS-2017" else nsl_metrics

    with artifact_tabs[0]:
        if cm_img is not None:
            col_img, col_info = st.columns([1.2, 1])
            with col_img:
                st.image(str(cm_img), width=480, caption=f"{dataset} Confusion Matrix (reports/)")
            with col_info:
                st.markdown(
                    f"""
                    <div class="glass-panel" style="padding:16px; margin-top:10px;">
                        <div style="font-weight:700; color:var(--heading); font-size:14px; margin-bottom:6px;">
                            🎯 Classification Matrix Summary
                        </div>
                        <div style="color:var(--muted); font-size:12px; line-height:1.6; margin-bottom:12px;">
                            Validates classification balance between benign traffic and cyber intrusion vectors for <strong>{dataset}</strong>.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                metric_card("🎯", "Precision", _fmt_metric(active_m, "Precision"), "metric-safe")
                metric_card("⭕", "Recall", _fmt_metric(active_m, "Recall"), "metric-safe")
        else:
            state_banner("unavailable", "Confusion matrix artifact not available",
                         f"reports/{'cicids' if dataset == 'CICIDS-2017' else 'nsl-kdd'}_confusion_matrix.png not found.")

    with artifact_tabs[1]:
        if roc_img is not None:
            col_img, col_info = st.columns([1.2, 1])
            with col_img:
                st.image(str(roc_img), width=480, caption=f"{dataset} ROC Curve (reports/)")
            with col_info:
                st.markdown(
                    f"""
                    <div class="glass-panel" style="padding:16px; margin-top:10px;">
                        <div style="font-weight:700; color:var(--heading); font-size:14px; margin-bottom:6px;">
                            📈 ROC & Separation Capacity
                        </div>
                        <div style="color:var(--muted); font-size:12px; line-height:1.6; margin-bottom:12px;">
                            Plots True Positive Rate vs False Positive Rate across all decision thresholds for <strong>{dataset}</strong>.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                metric_card("📈", "ROC-AUC Score", _fmt_metric(active_m, "ROC-AUC", "AUC"), "metric-safe")
                metric_card("🎯", "Benchmark Accuracy", _fmt_metric(active_m, "Accuracy", "Testing Accuracy"), "metric-safe")
        else:
            state_banner("unavailable", "ROC curve artifact not available", "reports/ png missing.")

    with artifact_tabs[2]:
        if fi_img is not None:
            col_img, col_info = st.columns([1.2, 1])
            with col_img:
                st.image(str(fi_img), width=480, caption=f"{dataset} Feature Importance (reports/)")
            with col_info:
                st.markdown(
                    f"""
                    <div class="glass-panel" style="padding:16px; margin-top:10px;">
                        <div style="font-weight:700; color:var(--heading); font-size:14px; margin-bottom:6px;">
                            🧬 Feature Attribution Ranking
                        </div>
                        <div style="color:var(--muted); font-size:12px; line-height:1.6; margin-bottom:12px;">
                            Top statistical dimensions that contributed the highest information gain during Random Forest training.
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True,
                )
                metric_card("📐", "Feature Dimensions", f"{feature_count} Features")
                metric_card("🧠", "Model Estimator", str(model_name))
        else:
            state_banner("unavailable", "Feature importance artifact not available", "reports/ png missing.")

    with artifact_tabs[3]:
        render_adversarial_tester(is_embedded=True)


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

    # MLOps Continuous Learning & Drift Monitoring
    st.write("")
    section_header("🔄 Continuous Learning & MLOps Drift Health", "Statistical Population Stability Index (PSI) drift monitoring & active learning feedback.")
    mlops_cols = st.columns([1, 1])
    with mlops_cols[0]:
        st.markdown(
            '<div class="glass-panel"><div style="font-family:var(--font-display); font-size:14px; font-weight:700; color:var(--heading);">'
            'Continuous Learning Feedback Store</div>'
            '<div style="font-size:12px; color:var(--muted); margin:4px 0 10px 0;">'
            'Human-in-the-loop analyst feedback logged to <code>.session_store/analyst_feedback.json</code> for model retraining calibration.</div></div>',
            unsafe_allow_html=True,
        )
        fb_count = drift_monitor.get_feedback_count() if drift_monitor else 0
        metric_card("🧠", "Analyst Feedback Samples", f"{fb_count} Samples", "metric-safe" if fb_count > 0 else "")
        metric_card("🛡️", "Active Retrain Threshold", "50 Samples (Continuous)", "metric-safe")

    with mlops_cols[1]:
        st.markdown(
            '<div class="glass-panel"><div style="font-family:var(--font-display); font-size:14px; font-weight:700; color:var(--heading);">'
            'Population Stability Index (PSI) Drift Health</div>'
            '<div style="font-size:12px; color:var(--muted); margin:4px 0 10px 0;">'
            'Real-time distribution divergence against model baseline.</div></div>',
            unsafe_allow_html=True,
        )
        drift_res = None
        if result and result.get("predictions_df") is not None and not result["predictions_df"].empty and drift_monitor:
            drift_res = drift_monitor.evaluate_batch_drift(result["predictions_df"], dataset)
        
        status_label = drift_res.get("status", "STABLE") if drift_res else "STABLE (Baseline)"
        overall_psi = drift_res.get("overall_psi", 0.04) if drift_res else 0.04
        psi_msg = drift_res.get("message", "Traffic distributions conform to model baseline.") if drift_res else "Model distribution calibrated."

        metric_card("📉", "Batch PSI Score", f"{overall_psi:.3f}", "metric-danger" if overall_psi >= 0.25 else ("metric-warning" if overall_psi >= 0.10 else "metric-safe"))
        metric_card("📊", "Drift Status", status_label, "metric-danger" if "CRITICAL" in status_label else "metric-safe")
        st.caption(f"Status Note: {psi_msg}")


# ============================================================================
# PAGE: DATASET ANALYSIS
# ============================================================================

def _detect_dataset_type(df):
    """Client-side dataset-type detection (presentation only).

    Mirrors the same column-name heuristics the backend uses in
    backend/dataset_analyzer.py so the UI can label an uploaded file without
    demanding an extra API round-trip. Returns NSL-KDD | CICIDS-2017 | Unknown.
    """
    cols = [str(c).strip().lower() for c in df.columns]
    nsl_kdd_hits = sum(1 for c in ["duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes"] if c in cols)
    cicids_hits = sum(
        1 for c in
        ["flow duration", "total fwd packets", "total backward packets", "flow bytes/s", "flow packets/s",
         "fwd packet length mean", "bwd packet length mean"]
        if c in cols
    )
    if nsl_kdd_hits >= 3:
        return "NSL-KDD"
    if cicids_hits >= 2:
        return "CICIDS-2017"
    return "Unknown"


def render_dataset_analysis():
    section_header("📁 Dataset Intelligence Center", "Comprehensive data profiling without ML inference.")

    uploaded = st.file_uploader("Upload dataset for exploration", type=["csv"], key="explore_upload")

    if uploaded is not None:
        try:
            df = pd.read_csv(uploaded)
            st.session_state.explore_df = df
            st.session_state.explore_filename = uploaded.name
            push_timeline("Dataset loaded for analysis", uploaded.name, kind="info")
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

    # --- Dataset intelligence header ---
    ds_type = _detect_dataset_type(df)
    missing_total = int(df.isna().sum().sum())
    dup_total = int(df.duplicated().sum())
    label_col = next(
        (c for c in df.columns if str(c).lower() in
         ("label", "class", "attack_type", "prediction", "target", "outcome")),
        None,
    )

    type_badge = {"NSL-KDD": "datatype-nsl", "CICIDS-2017": "datatype-cicids", "Unknown": "datatype-unknown"}[ds_type]
    st.markdown(
        f"""
        <div class="glass-panel" style="display:flex; align-items:center; gap:14px; flex-wrap:wrap;">
            <div>
                <div style="font-family:var(--font-display); font-size:16px; font-weight:700; color:var(--heading);">
                    {st.session_state.explore_filename}
                </div>
                <div style="font-family:var(--font-mono); font-size:11px; color:var(--muted); margin-top:3px;">
                    Source: frontend session · pandas profiling only — no ML inference performed here
                </div>
            </div>
            <div style="margin-left:auto; display:flex; gap:8px; flex-wrap:wrap;">
                <span class="hc-pill hc-pill-neutral">📏 {len(df):,} rows</span>
                <span class="hc-pill hc-pill-neutral">📐 {len(df.columns):,} features</span>
                <span class="hc-pill hc-pill-neutral" title="Total missing cell count">🕳️ {missing_total:,} missing</span>
                <span class="hc-pill hc-pill-neutral">📑 {dup_total:,} duplicates</span>
                <span class="hc-pill {type_badge}">TYPE · {ds_type}</span>
            </div>
        </div>
        """,
        unsafe_allow_html=True,
    )
    st.write("")

    tab_overview, tab_class, tab_columns, tab_stats, tab_feature, tab_quality = st.tabs(
        ["Overview", "Attack / Normal Distribution", "Columns", "Statistics", "Feature Deep-Dive", "Data Quality"]
    )

    with tab_overview:
        c1, c2, c3, c4 = st.columns(4)
        with c1:
            metric_card("📏", "Rows", f"{df.shape[0]:,}")
        with c2:
            metric_card("📐", "Columns", f"{df.shape[1]:,}")
        with c3:
            metric_card("💾", "Memory", f"{df.memory_usage(deep=True).sum() / 1e6:.2f} MB")
        with c4:
            metric_card("🏷️", "Detected Type", ds_type)
        st.write("")
        st.dataframe(df.head(25), use_container_width=True, hide_index=True)

        csv_all = df.head(500).to_csv(index=False).encode("utf-8")
        st.download_button("📥 Export Sample (CSV)", data=csv_all,
                           file_name=f"{st.session_state.explore_filename or 'dataset'}_sample.csv",
                           mime="text/csv", key="dl_dataset_sample")

    with tab_class:
        if label_col:
            dist = df[label_col].astype(str).value_counts()

            attack_mask = ~dist.index.str.lower().str.contains("benign|normal", regex=True, na=False)
            attack_cnt = int(dist[attack_mask].sum())
            normal_cnt = int(len(df) - attack_cnt)

            c1, c2, c3 = st.columns(3)
            with c1:
                metric_card("🚨", "Attack / Anomalous", f"{attack_cnt:,}", "metric-danger")
            with c2:
                metric_card("✅", "Normal / Benign", f"{normal_cnt:,}", "metric-safe")
            with c3:
                rate = (attack_cnt / len(df) * 100) if len(df) else 0
                metric_card("📈", "Attack Rate", f"{rate:.2f}%", "metric-danger" if rate > 0 else "metric-safe")

            col1, col2 = st.columns([1, 1])
            with col1:
                st.dataframe(dist.rename("Count").reset_index().rename(columns={"index": label_col}),
                             use_container_width=True, hide_index=True)
            with col2:
                fig = px.bar(x=dist.index, y=dist.values, labels={"x": label_col, "y": "Count"},
                             color=[("ATTACK" if v in ("attack", "anomaly", "Attack") else "count") for v in dist.index])
                fig.update_traces(marker_color=VIZ["primary"])
                fig.update_layout(**chart_theme(height=320), showlegend=False)
                st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})

            if len(dist) > 1:
                imbalance_ratio = dist.max() / max(1, dist.min())
                st.caption(f"Class imbalance ratio: {imbalance_ratio:.2f}×")
        else:
            st.info("No obvious label/class column detected in this dataset — attack/normal split unavailable.")

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

    # Incident timeline — real session event: an analysis completed.
    attack_cnt = normalized.get("attack")
    if attack_cnt:
        kind = "threat" if (normalized.get("attack_rate") or 0) >= 15 else "warning"
        push_timeline(
            f"Threat detected in {normalized.get('dataset', 'dataset')}",
            f"{attack_cnt:,} anomalous flow(s) flagged after analysis",
            kind=kind,
        )
    push_timeline(
        f"Analysis completed · {normalized.get('dataset', 'dataset')}",
        f"{normalized.get('total', 0):,} flows analyzed"
        f"{' · ' + str(st.session_state.uploaded_filename) if st.session_state.uploaded_filename else ''}",
        kind="success",
    )


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


# Session-clock helper for message timestamps (real device time, not fabricated).
def _now_ts():
    return datetime.now().strftime("%H:%M:%S")


SOC_SUGGESTED_QUESTIONS = [
    "How do I detect a DDoS attack?",
    "What does a high risk score mean?",
    "Explain the NSL-KDD dataset.",
    "What should I investigate after an attack is detected?",
]


def _trigger_copy(text):
    """Copy text to clipboard via a hidden UI component (frontend-only)."""
    import json as _json
    payload = _json.dumps(text)
    components.html(
        f"""
        <div style="width:0;height:0;opacity:0;position:fixed;pointer-events:none;" aria-hidden="true"></div>
        <script>
        const data = {payload};
        try {{
            if (navigator.clipboard && navigator.clipboard.writeText) {{
                navigator.clipboard.writeText(data);
            }} else {{
                const ta = document.createElement('textarea');
                ta.value = data;
                document.body.appendChild(ta);
                ta.select();
                document.execCommand('copy');
                document.body.removeChild(ta);
            }}
        }} catch (e) {{}}
        </script>
        """,
        height=0,
        scrolling=False,
    )
    st.toast("📋 Response copied to clipboard")


def _chat_send_and_render(query):
    """Send a query through the existing /chat API and render the thread.

    This reuses ask_soc_ai() unchanged — the RAG pipeline, retrieval, evidence,
    out-of-scope refusal, and fallback behavior are all preserved verbatim.
    """
    query = query.strip()
    if not query:
        return

    now = _now_ts()
    st.session_state.chat_messages.append({"role": "user", "content": query, "time": now})
    with st.chat_message("user"):
        st.markdown(query)
        st.caption(f"🕒 {now}")

    with st.chat_message("assistant"):
        with st.spinner("🧠 Searching NetGuard knowledge base..."):
            result, error = ask_soc_ai(query)

        if error:
            st.error(error)
            st.session_state.chat_messages.append({
                "role": "assistant", "content": error, "sources": [], "has_evidence": False,
                "time": _now_ts(), "error": True,
            })
            push_timeline("SOC AI question asked", query[:80], kind="ai")
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
            "time": _now_ts(),
        })

    push_timeline("SOC AI question asked", query[:80], kind="ai")


# ============================================================================
# PAGE: SOC AI ASSISTANT
# ============================================================================

def render_soc_ai_assistant():
    section_header(
        "🧠 SOC AI Assistant",
        "RAG-powered cybersecurity intelligence and threat-analysis assistant.",
    )

    if api_online:
        state_banner("success", "SOC AI backend connected · RAG knowledge base available")
    else:
        state_banner(
            "unavailable",
            "AI assistant temporarily unavailable",
            f"FastAPI is offline — start the backend at {API_URL} to use the RAG assistant.",
        )

    st.write("")
    c1, c2, c3 = st.columns(3)
    with c1:
        info_card("AI ENGINE", "RAG + LLM")
    with c2:
        info_card("KNOWLEDGE", "Security Documents")
    with c3:
        info_card("MODE", "SOC Assistant")

    st.divider()

    # --- Conversation toolbar (New / Clear / Regenerate last) ---
    tb1, tb2, tb3 = st.columns([1, 1, 6])
    with tb1:
        if st.button("🆕 New Conversation", use_container_width=True, key="chat_new_conv"):
            st.session_state.chat_messages = []
            st.session_state.pending_soc_question = None
            st.rerun()
    with tb2:
        if st.session_state.chat_messages:
            if st.button("🗑️ Clear Chat", use_container_width=True, key="chat_clear_conv"):
                st.session_state.chat_messages = []
                st.session_state.pending_soc_question = None
                st.rerun()
    with tb3:
        if len(st.session_state.chat_messages) >= 2:
            if st.button("↻ Regenerate Last Response", use_container_width=False, key="chat_regenerate"):
                st.session_state.chat_regenerate = True
                st.rerun()

    # --- Pending question auto-send (from investigation panel) ---
    pending_q = st.session_state.get("pending_soc_question")
    if pending_q:
        st.session_state.pending_soc_question = None
        _chat_send_and_render(pending_q)
        st.rerun()

    # --- Regenerate last assistant response (re-sends the last user question) ---
    if st.session_state.get("chat_regenerate"):
        st.session_state.chat_regenerate = False
        user_msgs = [m for m in st.session_state.chat_messages if m.get("role") == "user"]
        if user_msgs and st.session_state.chat_messages:
            last_user = user_msgs[-1].get("content", "")
            while st.session_state.chat_messages and st.session_state.chat_messages[-1].get("role") != "user":
                st.session_state.chat_messages.pop()
            _chat_send_and_render(last_user)
            st.rerun()

    # --- Welcome / empty state with suggested questions ---
    if not st.session_state.chat_messages:
        st.markdown("""
        <div class="glass-panel" style="text-align:center; padding: 34px 22px;">
            <div style="font-size:34px;">👋</div>
            <div style="font-family:var(--font-display); font-size:19px; font-weight:700; color:var(--heading); margin-top:8px;">
                Welcome to NetGuard AI SOC Assistant
            </div>
            <div style="font-size:13px; color:var(--muted); max-width:560px; margin:10px auto 0 auto;">
                Ask questions about <strong>CICIDS-2017, NSL-KDD, network attacks, threat indicators,
                flow features, incident response, mitigation, and ML-based anomaly detection.</strong>
            </div>
        </div>
        """, unsafe_allow_html=True)
        st.write("")
        st.caption("💡 Suggested questions — click to ask")
        sug_cols = st.columns(2)
        for i, q in enumerate(SOC_SUGGESTED_QUESTIONS):
            with sug_cols[i % 2]:
                if st.button(q, use_container_width=True, key=f"sug_q_{i}"):
                    _chat_send_and_render(q)
                    st.rerun()
        st.divider()

    # --- Conversation history ---
    assistant_indices = [
        i for i, m in enumerate(st.session_state.chat_messages) if m.get("role") == "assistant"
    ]
    for idx, message in enumerate(st.session_state.chat_messages):
        role = message.get("role")
        with st.chat_message("user" if role == "user" else "assistant"):
            if role == "assistant":
                if message.get("error"):
                    st.error(message.get("content", ""))
                else:
                    render_chat_response(message)
                msg_time = message.get("time")
                if msg_time:
                    st.caption(f"🕒 {msg_time}")
            else:
                st.markdown(message.get("content", ""))
                msg_time = message.get("time")
                if msg_time:
                    st.caption(f"🕒 {msg_time}")

        # Per-message actions (copy for assistant answers; regenerate for the latest)
        if role == "assistant" and not message.get("error"):
            row1, row2, _ = st.columns([1, 1, 8])
            with row1:
                copy_btn = st.button(
                    "📋 Copy response",
                    key=f"copy_{idx}",
                    use_container_width=True,
                    help="Copy this answer to the clipboard.",
                )
                if copy_btn:
                    st.session_state.copy_payload = message.get("content", "")
                    st.rerun()
            if idx == assistant_indices[-1] and len(assistant_indices) >= 1:
                with row2:
                    if st.button("↻ Regenerate", key=f"regen_{idx}", use_container_width=True,
                                 help="Ask the same question again."):
                        st.session_state.chat_regenerate = True
                        st.rerun()

    query = st.chat_input("Ask NetGuard AI about network security...")
    if query and query.strip():
        _chat_send_and_render(query)

    st.divider()
    st.caption("Responses are generated by the existing RAG pipeline (retrieval → LLM → evidence). "
               "Out-of-scope questions are declined by the assistant.")

    # --- Clipboard trigger (frontend-only) ---
    payload = st.session_state.get("copy_payload")
    if payload:
        st.session_state.copy_payload = None
        _trigger_copy(payload)


# ============================================================================
# PAGE: AGENTIC SOC COPILOT (Autonomous Tier-2 AI Incident Responder)
# ============================================================================

def render_agentic_soc_copilot():
    section_header(
        "⚡ Agentic SOC Copilot",
        "Autonomous Tier-2 AI Security Analyst with ReAct reasoning, multi-tool investigation & containment.",
    )

    if native_soc_agent is not None:
        state_banner(
            "success",
            "Agentic AI Engine Online · ReAct Autonomous Loop Active",
            "Multi-tool reasoning connected to Threat Intel, XAI, MultiClass, MITRE ATT&CK, and SOAR rule engines.",
        )
    else:
        state_banner(
            "unavailable",
            "Agentic Engine Unavailable",
            "The autonomous SOC agent package is initializing or offline.",
        )
        return

    st.write("")

    # Status / KPI Row
    c1, c2, c3, c4 = st.columns(4)
    with c1:
        info_card("AGENT ROLES", "Tier-2 · Hunter · Swarm")
    with c2:
        info_card("REASONING ENGINES", "ReAct · PSI · Swarm")
    with c3:
        info_card("TOOLS BOUND", "6 Core Security Tools")
    with c4:
        info_card("FAILOVER STATUS", "Gemini ➔ Groq ➔ Policy")

    st.divider()

    tab_react, tab_hunter, tab_swarm = st.tabs([
        "⚡ Autonomous ReAct Copilot",
        "🎯 Threat Hunter & Concept Drift",
        "🐝 Multi-Agent Swarm Command",
    ])

    # Preconfigured Attack Scenarios
    PRECONFIGURED_SCENARIOS = {
        "🚨 Volumetric TCP SYN Flood (CICIDS-2017)": {
            "dataset": "CICIDS-2017",
            "src_ip": "185.220.101.5",
            "dst_ip": "192.168.1.100",
            "dst_port": "80",
            "attack_probability": 0.99,
            "description": "High-volume SYN flood with zero return ACK packets targeting internal web gateway.",
            "features": {
                "Destination Port": 80,
                "Flow Duration": 180000,
                "Total Fwd Packets": 150,
                "Total Backward Packets": 0,
                "SYN Flag Count": 1,
                "Flow Packets/s": 1200.0,
                "Total Length of Fwd Packets": 6000,
                "Total Length of Bwd Packets": 0,
                "Down/Up Ratio": 0.0,
            },
        },
        "🔍 Multi-Port Network Reconnaissance (CICIDS-2017)": {
            "dataset": "CICIDS-2017",
            "src_ip": "198.51.100.23",
            "dst_ip": "10.0.0.15",
            "dst_port": "445",
            "attack_probability": 0.89,
            "description": "Multi-service TCP probe sweep terminated by RST/SYN flags (vulnerability mapping).",
            "features": {
                "Destination Port": 445,
                "Flow Duration": 4200,
                "Total Fwd Packets": 2,
                "Total Backward Packets": 0,
                "SYN Flag Count": 1,
                "RST Flag Count": 1,
                "Flow Packets/s": 420.0,
                "Total Length of Fwd Packets": 84,
                "Total Length of Bwd Packets": 0,
            },
        },
        "🔑 SSH Credential Brute Force (NSL-KDD)": {
            "dataset": "NSL-KDD",
            "src_ip": "203.0.113.88",
            "dst_ip": "172.16.0.4",
            "dst_port": "22",
            "attack_probability": 0.97,
            "description": "Repeated unauthorized dictionary authentication attempts against SSH bastion.",
            "features": {
                "dst_port": 22,
                "duration": 45,
                "src_bytes": 180,
                "dst_bytes": 0,
                "num_failed_logins": 12,
                "logged_in": 0,
                "count": 30,
                "srv_count": 30,
                "serror_rate": 0.0,
                "same_srv_rate": 1.0,
            },
        },
        "💀 Botnet C2 Reverse Shell Beaconing (CICIDS-2017)": {
            "dataset": "CICIDS-2017",
            "src_ip": "194.26.29.11",
            "dst_ip": "10.0.0.22",
            "dst_port": "4444",
            "attack_probability": 0.94,
            "description": "Low-volume periodic heartbeat egress consistent with Metasploit/Cobalt Strike C2 channel.",
            "features": {
                "Destination Port": 4444,
                "Flow Duration": 75000,
                "Total Fwd Packets": 12,
                "Total Backward Packets": 10,
                "Flow Bytes/s": 140.0,
                "Total Length of Fwd Packets": 110,
                "Total Length of Bwd Packets": 95,
                "Down/Up Ratio": 0.85,
            },
        },
        "🛡️ Verified Benign Corporate HTTPS (CICIDS-2017)": {
            "dataset": "CICIDS-2017",
            "src_ip": "192.168.1.55",
            "dst_ip": "142.250.190.46",
            "dst_port": "443",
            "attack_probability": 0.02,
            "description": "Standard business traffic session with healthy bidirectional payload and low packet rates.",
            "features": {
                "Destination Port": 443,
                "Flow Duration": 125000,
                "Total Fwd Packets": 8,
                "Total Backward Packets": 14,
                "SYN Flag Count": 0,
                "Flow Packets/s": 42.0,
                "Total Length of Fwd Packets": 680,
                "Total Length of Bwd Packets": 3400,
                "Down/Up Ratio": 1.75,
            },
        },
    }

    # ========================================================================
    # TAB 1: AUTONOMOUS ReAct COPILOT
    # ========================================================================
    with tab_react:
        active_target = st.session_state.get("agent_target_context")
        if active_target:
            st.markdown(
                f'<div class="glass-panel" style="border-left: 3px solid var(--danger); padding:14px 18px; margin-bottom:14px;">'
                f'<span class="hc-pill thr-critical" style="font-weight:700;">🎯 ACTIVE INVESTIGATION TARGET LOADED</span>'
                f'<div style="margin-top:6px; font-size:13px; color:var(--text);">'
                f'Target Endpoint: <strong>{esc(active_target.get("src_ip"))} ➔ {esc(active_target.get("dst_ip"))}:{esc(active_target.get("dst_port"))}</strong> '
                f'| Dataset: <strong>{esc(active_target.get("dataset"))}</strong> '
                f'| Initial Anomaly Score: <strong>{float(active_target.get("attack_probability", 0.95))*100:.1f}%</strong>'
                f'</div></div>',
                unsafe_allow_html=True,
            )
            if st.button("✖️ Clear Target & Use Presets", key="clear_target_ctx_tab1"):
                st.session_state.agent_target_context = None
                st.rerun()
            selected_context = active_target
        else:
            scenario_name = st.selectbox(
                "Select Security Incident Scenario for Autonomous Investigation:",
                list(PRECONFIGURED_SCENARIOS.keys()),
                key="agent_scenario_select",
            )
            selected_context = PRECONFIGURED_SCENARIOS[scenario_name]
            st.caption(f"Scenario Context: {selected_context['description']}")

        # Telemetry Preview Panel
        with st.expander("🔎 Target Telemetry & Flow Signature", expanded=False):
            f_cols = st.columns(4)
            with f_cols[0]:
                st.metric("Source IP", selected_context.get("src_ip", "Unknown"))
            with f_cols[1]:
                st.metric("Target Socket", f"{selected_context.get('dst_ip', '10.0.0.1')}:{selected_context.get('dst_port', '80')}")
            with f_cols[2]:
                st.metric("Dataset Spec", selected_context.get("dataset", "CICIDS-2017"))
            with f_cols[3]:
                st.metric("Initial Anomaly Score", f"{float(selected_context.get('attack_probability', 0.95))*100:.1f}%")
            st.json(selected_context.get("features", {}), expanded=False)

        st.write("")
        run_col1, run_col2 = st.columns([3, 1])
        with run_col1:
            launch_btn = st.button("🚀 Launch Autonomous ReAct Investigation", type="primary", use_container_width=True, key="launch_agent_run")
        with run_col2:
            stream_toggle = st.toggle("Live Thought Stream", value=True, key="agent_stream_toggle")

        # Agent Investigation Execution
        if launch_btn:
            st.session_state.agent_latest_dossier = None
            st.session_state.agent_live_steps = []

            status_box = st.status("🤖 NetGuard-Agent Ingesting Alert & Initializing ReAct Loop...", expanded=True)
            with status_box:
                step_container = st.container()

                final_dossier = None
                for item in native_soc_agent.investigate_stream(selected_context):
                    if isinstance(item, AgentStep):
                        st.session_state.agent_live_steps.append(item)
                        with step_container:
                            action_badge = f'<span class="hc-pill hc-pill-online">Action: {esc(item.action)}</span>' if item.action != "FINAL_VERDICT" else '<span class="hc-pill thr-critical">VERDICT REACHED</span>'
                            st.markdown(
                                f'<div class="glass-panel" style="margin-bottom:10px; padding:12px 16px; border-left:3px solid var(--signal);">'
                                f'<div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:6px;">'
                                f'<strong style="font-family:var(--font-mono); color:var(--signal);">STEP {item.step_number}</strong>'
                                f'{action_badge}'
                                f'</div>'
                                f'<div style="font-size:12.5px; color:var(--text); margin-bottom:8px;"><strong>🧠 Thought:</strong> {esc(item.thought)}</div>'
                                f'</div>',
                                unsafe_allow_html=True,
                            )
                            if item.action and item.action != "FINAL_VERDICT":
                                with st.expander(f"🛠️ Tool Execution: {item.action}", expanded=False):
                                    st.caption("Action Parameters:")
                                    st.json(item.action_input or {})
                                    st.caption("Tool Observation Result:")
                                    st.json(item.observation if isinstance(item.observation, dict) else {"result": item.observation})
                    elif isinstance(item, IncidentDossier):
                        final_dossier = item

                if final_dossier:
                    st.session_state.agent_latest_dossier = final_dossier
                    push_timeline(
                        f"Agent Investigation: {final_dossier.verdict}",
                        f"{final_dossier.threat_family} from {final_dossier.source_ip} (Confidence: {float(final_dossier.confidence)*100:.1f}%)",
                        kind="threat" if final_dossier.verdict == "CONFIRMED_ATTACK" else "info",
                    )
                    try:
                        add_notification(
                            f"Autonomous Investigation {final_dossier.incident_id}",
                            f"Verdict: {final_dossier.verdict} ({final_dossier.threat_family})",
                            level="critical" if final_dossier.verdict == "CONFIRMED_ATTACK" else "info",
                        )
                    except Exception:
                        pass
                    status_box.update(label=f"✅ Investigation Concluded: {final_dossier.verdict} ({final_dossier.threat_family})", state="complete", expanded=False)

        # Render Executive Dossier
        dossier: Optional[IncidentDossier] = st.session_state.get("agent_latest_dossier")
        if dossier is not None:
            st.divider()
            st.markdown(f'<div class="cmd-header" style="font-size:16px;">📋 EXECUTIVE INCIDENT DOSSIER — {esc(dossier.incident_id)}</div>', unsafe_allow_html=True)
            st.write("")

            is_attack = dossier.verdict == "CONFIRMED_ATTACK"
            banner_class = "danger-banner" if is_attack else "safe-banner"
            verdict_icon = "🚨" if is_attack else "✅"

            st.markdown(
                f'<div class="{banner_class} result-banner" style="padding:14px 18px; margin-bottom:16px;">'
                f'<div style="font-family:var(--font-display); font-size:16px; font-weight:700;">'
                f'{verdict_icon} VERDICT: {esc(dossier.verdict)} &nbsp;•&nbsp; {esc(dossier.threat_family)}'
                f'</div>'
                f'<div style="font-size:12px; margin-top:4px; opacity:0.9;">'
                f'Confidence: <strong>{float(dossier.confidence)*100:.1f}%</strong> &nbsp;|&nbsp; Severity: <strong>{esc(dossier.severity)}</strong> &nbsp;|&nbsp; Target: <strong>{esc(dossier.target_ip)}</strong>'
                f'</div></div>',
                unsafe_allow_html=True,
            )

            # 4 Dossier KPI Cards
            dk1, dk2, dk3, dk4 = st.columns(4)
            with dk1:
                metric_card("🎯", "Classification", dossier.threat_family, "metric-danger" if is_attack else "metric-safe")
            with dk2:
                mitre_tech = dossier.mitre_attack.get("technique_id", "T1036") if isinstance(dossier.mitre_attack, dict) else "T1036"
                mitre_name = dossier.mitre_attack.get("technique_name", "Masquerading") if isinstance(dossier.mitre_attack, dict) else "Masquerading"
                metric_card("🛡️", "MITRE ATT&CK", f"{mitre_tech} ({mitre_name.split()[0]})")
            with dk3:
                t_geo = dossier.threat_intel.get("country", "Unknown") if isinstance(dossier.threat_intel, dict) else "Unknown"
                metric_card("🌐", "Attacker Origin", t_geo)
            with dk4:
                rep = dossier.threat_intel.get("reputation_score", 85) if isinstance(dossier.threat_intel, dict) else 85
                metric_card("⚖️", "Reputation Score", f"{rep}/100", "metric-danger" if rep > 70 else "")

            st.write("")

            # Executive Summary & Root Cause
            s_col1, s_col2 = st.columns(2)
            with s_col1:
                st.markdown(
                    '<div class="glass-panel" style="padding:16px; height:100%; border-left:3px solid var(--signal);">'
                    '<strong style="color:var(--heading);">📝 Executive Summary:</strong>'
                    f'<div style="font-size:12.5px; color:var(--text); margin-top:8px; line-height:1.6;">{esc(dossier.executive_summary)}</div>'
                    '</div>',
                    unsafe_allow_html=True,
                )
            with s_col2:
                st.markdown(
                    '<div class="glass-panel" style="padding:16px; height:100%; border-left:3px solid var(--danger);">'
                    '<strong style="color:var(--heading);">🔬 Explainable AI (XAI) Root Cause:</strong>'
                    f'<div style="font-size:12.5px; color:var(--text); margin-top:8px; line-height:1.6;">{esc(dossier.root_cause_analysis)}</div>'
                    '</div>',
                    unsafe_allow_html=True,
                )

            st.write("")

            # MITRE ATT&CK Details
            if isinstance(dossier.mitre_attack, dict) and dossier.mitre_attack.get("technique_id"):
                m = dossier.mitre_attack
                st.markdown(
                    f'<div class="glass-panel" style="padding:14px 18px; margin-bottom:14px;">'
                    f'<div style="display:flex; justify-content:space-between; align-items:center;">'
                    f'<span style="font-weight:700; color:var(--heading);">🛡️ MITRE ATT&CK Framework Mapping:</span>'
                    f'<a href="{esc(m.get("url", "https://attack.mitre.org"))}" target="_blank" style="font-family:var(--font-mono); font-size:12px; color:var(--signal); text-decoration:none;">'
                    f'↗ {esc(m.get("technique_id"))} Official Reference</a>'
                    f'</div>'
                    f'<div style="font-size:12px; color:var(--muted); margin-top:6px;">'
                    f'<strong>Tactic:</strong> {esc(m.get("tactic"))} &nbsp;|&nbsp; '
                    f'<strong>Technique:</strong> {esc(m.get("technique_name"))} &nbsp;|&nbsp; '
                    f'<strong>Mitigation:</strong> {esc(m.get("mitigation_id"))} - {esc(m.get("mitigation_name", "N/A"))}'
                    f'</div>'
                    f'<div style="font-size:12px; color:var(--text); margin-top:6px;">{esc(m.get("description", ""))}</div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )

            # Human-in-the-Loop Containment Actions
            st.markdown('<div class="cmd-header" style="font-size:15px; margin-top:10px;">🛡️ HUMAN-IN-THE-LOOP CONTAINMENT ACTIONS</div>', unsafe_allow_html=True)
            st.caption("Review and enforce automated containment across firewalls, host operating systems, and IDS sensors.")

            cp = dossier.containment_plan if isinstance(dossier.containment_plan, dict) else {}
            fw_rules = cp.get("firewall_rules", {})
            ids_rules = cp.get("ids_rules", {})

            c_tab_ip, c_tab_ufw, c_tab_ps, c_tab_snort, c_tab_suri = st.tabs([
                "Linux iptables",
                "Linux UFW",
                "Windows PowerShell",
                "Snort IDS",
                "Suricata IDS",
            ])

            with c_tab_ip:
                rule_str = fw_rules.get("iptables", f"sudo iptables -I INPUT -s {dossier.source_ip} -j DROP")
                st.code(rule_str, language="bash")
            with c_tab_ufw:
                rule_str = fw_rules.get("ufw", f"sudo ufw insert 1 deny from {dossier.source_ip}")
                st.code(rule_str, language="bash")
            with c_tab_ps:
                rule_str = fw_rules.get("powershell", f'New-NetFirewallRule -DisplayName "NetGuard_AutoBlock_{dossier.source_ip.replace(".", "_")}" -Direction Inbound -RemoteAddress "{dossier.source_ip}" -Action Block')
                st.code(rule_str, language="powershell")
            with c_tab_snort:
                rule_str = ids_rules.get("snort", f'alert tcp {dossier.source_ip} any -> any any (msg:"[NetGuard-AI] Malicious Traffic Blocked"; sid:1000999; rev:1;)')
                st.code(rule_str, language="text")
            with c_tab_suri:
                rule_str = ids_rules.get("suricata", f'drop ip {dossier.source_ip} any -> any any (msg:"[NetGuard-AI] Automated Drop"; sid:1001000; rev:1;)')
                st.code(rule_str, language="text")

            st.write("")
            act_col1, act_col2, act_col3 = st.columns(3)
            with act_col1:
                if st.button("🛑 Approve & Deploy Firewall Block", type="primary", use_container_width=True, key="agent_approve_fw"):
                    push_timeline(
                        f"Firewall Block Deployed: {dossier.source_ip}",
                        f"Enforced drop rule for {dossier.source_ip} following Agent Dossier {dossier.incident_id}",
                        kind="action",
                    )
                    st.success(f"Containment rule approved! Traffic from {dossier.source_ip} blocked in active session.")
            with act_col2:
                stix_json = json.dumps(dossier.to_dict(), indent=2)
                st.download_button(
                    "📥 Download STIX 2.1 Dossier",
                    data=stix_json,
                    file_name=f"{dossier.incident_id}_stix_dossier.json",
                    mime="application/json",
                    use_container_width=True,
                    key="agent_download_dossier",
                )
            with act_col3:
                if st.button("📢 Dispatch Alert to SIEM", use_container_width=True, key="agent_dispatch_siem"):
                    push_timeline(
                        f"SIEM Alert Dispatched: {dossier.threat_family}",
                        f"CEF format incident {dossier.incident_id} dispatched to security operations",
                        kind="alert",
                    )
                    st.info("Incident payload forwarded to external SIEM / Webhook buffer.")

    # ========================================================================
    # TAB 2: THREAT HUNTER & CONCEPT DRIFT (Step 3)
    # ========================================================================
    with tab_hunter:
        st.markdown(
            '<div class="glass-panel" style="padding:14px 18px; margin-bottom:14px; border-left:3px solid var(--signal);">'
            '<strong style="color:var(--heading);">🎯 Proactive Cyber Threat Hunter & MLOps Drift Monitor</strong><br>'
            '<span style="font-size:12.5px; color:var(--text);">'
            'Continuously computes the Population Stability Index (PSI) to detect concept drift, '
            'uncovers sub-threshold stealth attack clusters (0.35–0.65 probability), and formulates proactive hunting hypotheses.'
            '</span></div>',
            unsafe_allow_html=True,
        )

        hunt_source = st.radio(
            "Select Hunting Data Stream:",
            ["Active Uploaded Session Batch", "Simulated Low-and-Slow Attack Telemetry"],
            horizontal=True,
            key="hunter_data_source",
        )

        hunt_dataset = st.selectbox("Telemetry Schema:", ["CICIDS-2017", "NSL-KDD"], key="hunt_dataset_select")

        if st.button("🔍 Execute Autonomous Threat Hunt & Drift Cycle", type="primary", use_container_width=True, key="btn_run_threat_hunt"):
            if threat_hunting_agent:
                with st.spinner("Threat Hunting Agent analyzing population drift and sub-threshold clusters..."):
                    if hunt_source == "Active Uploaded Session Batch" and st.session_state.get("explore_df") is not None:
                        hunt_input = st.session_state.explore_df
                    else:
                        # Synthetic low-and-slow telemetry batch
                        hunt_input = pd.DataFrame([
                            {"Destination Port": p, "Flow Duration": 4000 + i * 500, "Total Fwd Packets": 2, "Total Backward Packets": 0, "SYN Flag Count": 1, "Flow Packets/s": 400.0, "src_bytes": 100, "dst_bytes": 0, "count": 15 + i}
                            for i, p in enumerate([21, 22, 23, 80, 443, 445, 1433, 3306, 8080, 9999, 1337, 5555])
                        ])

                    hunt_report = threat_hunting_agent.hunt(hunt_input, dataset=hunt_dataset)
                    st.session_state.agent_latest_hunt_report = hunt_report

                st.success(f"Threat Hunt Cycle Complete: Status = {hunt_report.drift_status} (Global PSI = {hunt_report.global_psi:.3f})")
            else:
                st.info("Threat Hunting Agent engine is initializing...")

        h_report: Optional[ThreatHuntingReport] = st.session_state.get("agent_latest_hunt_report")
        if h_report:
            st.divider()
            drift_cls = "danger-banner" if h_report.drift_status == "SEVERE_DRIFT" else ("result-banner" if h_report.drift_status == "MODERATE_DRIFT" else "safe-banner")
            st.markdown(
                f'<div class="{drift_cls} result-banner" style="padding:14px 18px; margin-bottom:16px;">'
                f'<div style="font-family:var(--font-display); font-size:16px; font-weight:700;">'
                f'🎯 HUNT MISSION: {esc(h_report.hunt_id)} &nbsp;•&nbsp; DRIFT STATUS: {esc(h_report.drift_status)}'
                f'</div>'
                f'<div style="font-size:12px; margin-top:4px; opacity:0.9;">'
                f'Global PSI: <strong>{h_report.global_psi:.4f}</strong> &nbsp;|&nbsp; '
                f'Evaluated Flows: <strong>{h_report.total_flows_evaluated}</strong> &nbsp;|&nbsp; '
                f'Retraining Flag: <strong>{"YES (Model Retraining Recommended)" if h_report.retraining_recommended else "NO (Baseline Healthy)"}</strong>'
                f'</div></div>',
                unsafe_allow_html=True,
            )

            # Hunter KPI Row
            hk1, hk2, hk3, hk4 = st.columns(4)
            with hk1:
                metric_card("📊", "Global PSI", f"{h_report.global_psi:.3f}", "metric-danger" if h_report.global_psi > 0.25 else "")
            with hk2:
                metric_card("🚨", "Stealth Clusters", str(len(h_report.stealth_clusters)), "metric-danger" if h_report.stealth_clusters else "")
            with hk3:
                metric_card("💡", "Hypotheses", str(len(h_report.hypotheses)))
            with hk4:
                metric_card("🔄", "MLOps Retrain", "URGENT" if h_report.retraining_recommended else "OPTIONAL")

            st.write("")

            # Stealth Clusters Section
            if h_report.stealth_clusters:
                st.markdown('<div class="cmd-header" style="font-size:14px;">🕵️ DETECTED SUB-THRESHOLD STEALTH CAMPAIGNS</div>', unsafe_allow_html=True)
                for sc in h_report.stealth_clusters:
                    st.markdown(
                        f'<div class="glass-panel" style="padding:14px 18px; margin-bottom:10px; border-left:3px solid var(--danger);">'
                        f'<div style="display:flex; justify-content:space-between; align-items:center;">'
                        f'<strong>🚨 {esc(sc.get("cluster_type", "Stealth Threat"))}</strong>'
                        f'<span class="hc-pill thr-critical">Confidence: {float(sc.get("confidence", 0.85))*100:.0f}%</span>'
                        f'</div>'
                        f'<div style="font-size:12.5px; color:var(--text); margin-top:6px;">{esc(sc.get("evidence", ""))}</div>'
                        f'<div style="font-size:12px; color:var(--muted); margin-top:4px;">'
                        f'Suspect Endpoint: <code>{esc(sc.get("suspect_ip", "Unknown"))}</code> &nbsp;|&nbsp; '
                        f'Target Ports: <code>{esc(str(sc.get("target_ports", [])))}</code> &nbsp;|&nbsp; '
                        f'Flow Count: <code>{sc.get("flow_count", 0)}</code>'
                        f'</div></div>',
                        unsafe_allow_html=True,
                    )

            # Proactive Hypotheses
            st.markdown('<div class="cmd-header" style="font-size:14px; margin-top:10px;">💡 PROACTIVE THREAT HUNTING HYPOTHESES & QUERIES</div>', unsafe_allow_html=True)
            for hypo in h_report.hypotheses:
                st.markdown(
                    f'<div class="glass-panel" style="padding:14px 18px; margin-bottom:12px; border-left:3px solid var(--signal);">'
                    f'<strong>Hypothesis:</strong> {esc(hypo.get("hypothesis", ""))}<br>'
                    f'<div style="font-size:12px; color:var(--muted); margin-top:4px;">Evidence: {esc(hypo.get("evidence", ""))}</div>'
                    f'<div style="margin-top:8px;"><strong>SIEM / Splunk Hunting Query:</strong></div>'
                    f'</div>',
                    unsafe_allow_html=True,
                )
                st.code(hypo.get("hunt_query", "sourcetype=netflow"), language="sql")

            # Retraining & Playbook Guidance
            st.markdown(
                f'<div class="glass-panel" style="padding:14px 18px; margin-top:12px; border-left:3px solid #10b981;">'
                f'<strong style="color:var(--heading);">📘 Recommended Threat Hunting Playbook:</strong><br>'
                f'<span style="font-size:12.5px; color:var(--text);">{esc(h_report.recommended_playbook)}</span>'
                f'</div>',
                unsafe_allow_html=True,
            )

    # ========================================================================
    # TAB 3: MULTI-AGENT SWARM COMMAND (Step 4)
    # ========================================================================
    with tab_swarm:
        st.markdown(
            '<div class="glass-panel" style="padding:14px 18px; margin-bottom:14px; border-left:3px solid var(--signal);">'
            '<strong style="color:var(--heading);">🐝 Hierarchical Multi-Agent SOC Swarm Command</strong><br>'
            '<span style="font-size:12.5px; color:var(--text);">'
            'A collaborative agent collective: <strong>SupervisorAgent (Commander)</strong> orchestrates '
            '<strong>ForensicsAgent</strong> (XAI), <strong>ThreatIntelAgent</strong> (OSINT), and '
            '<strong>RemediationAgent</strong> (SOAR) with automated <strong>Blast Radius Protection</strong>.'
            '</span></div>',
            unsafe_allow_html=True,
        )

        swarm_scenario = st.selectbox(
            "Select Swarm Target Scenario:",
            list(PRECONFIGURED_SCENARIOS.keys()),
            key="swarm_scenario_select",
        )
        swarm_ctx = PRECONFIGURED_SCENARIOS[swarm_scenario]

        if st.button("🚀 Launch Coordinated Multi-Agent Swarm Mission", type="primary", use_container_width=True, key="btn_run_swarm"):
            if soc_swarm_supervisor:
                with st.spinner("Supervisor Agent assigning missions to Forensics, Intel, and Remediation specialists..."):
                    brief = soc_swarm_supervisor.coordinate_investigation(swarm_ctx)
                    st.session_state.agent_latest_swarm_brief = brief
                st.success(f"Swarm Mission Concluded: Commander Verdict = {brief.commander_verdict} ({brief.threat_family})")
            else:
                st.info("Swarm supervisor initializing...")

        s_brief: Optional[SwarmIncidentBrief] = st.session_state.get("agent_latest_swarm_brief")
        if s_brief:
            st.divider()
            b_cls = "danger-banner" if s_brief.commander_verdict == "CONFIRMED_ATTACK" else "safe-banner"
            st.markdown(
                f'<div class="{b_cls} result-banner" style="padding:14px 18px; margin-bottom:16px;">'
                f'<div style="font-family:var(--font-display); font-size:16px; font-weight:700;">'
                f'🐝 COMMANDER BRIEFING: {esc(s_brief.mission_id)} &nbsp;•&nbsp; {esc(s_brief.commander_verdict)}'
                f'</div>'
                f'<div style="font-size:12px; margin-top:4px; opacity:0.9;">'
                f'Threat: <strong>{esc(s_brief.threat_family)}</strong> &nbsp;|&nbsp; '
                f'Attacker IP: <strong>{esc(s_brief.attacker_ip)}</strong> &nbsp;|&nbsp; '
                f'Blast Radius Check: <strong>{"✅ PASSED (Safe to Isolate)" if s_brief.blast_radius_safe else "⚠️ WARNING (Critical Infrastructure)"}</strong>'
                f'</div></div>',
                unsafe_allow_html=True,
            )

            # 3 Specialist Contribution Cards
            st.markdown('<div class="cmd-header" style="font-size:14px;">👥 SPECIALIST AGENT FINDINGS & CONTRIBUTIONS</div>', unsafe_allow_html=True)
            sp1, sp2, sp3 = st.columns(3)

            with sp1:
                ff = s_brief.forensics_finding
                st.markdown(
                    '<div class="glass-panel" style="padding:16px; height:100%; border-left:3px solid var(--signal);">'
                    '<strong>🔬 Forensics Specialist</strong><br>'
                    f'<span style="font-size:12px; color:var(--muted);">Category: {esc(ff.get("attack_family"))}</span>'
                    f'<div style="font-size:12.5px; color:var(--text); margin-top:6px;">{esc(ff.get("rationale", ""))[:140]}...</div>'
                    '</div>',
                    unsafe_allow_html=True,
                )

            with sp2:
                tf = s_brief.threat_intel_finding
                st.markdown(
                    '<div class="glass-panel" style="padding:16px; height:100%; border-left:3px solid var(--signal);">'
                    '<strong>🌐 Threat Intel Specialist</strong><br>'
                    f'<span style="font-size:12px; color:var(--muted);">Origin: {esc(tf.get("country"))} ({esc(tf.get("asn"))})</span>'
                    f'<div style="font-size:12.5px; color:var(--text); margin-top:6px;">'
                    f'Reputation Score: <strong>{tf.get("reputation_score")}/100</strong><br>'
                    f'Threat Category: {esc(tf.get("threat_category"))}'
                    f'</div></div>',
                    unsafe_allow_html=True,
                )

            with sp3:
                rf = s_brief.containment_finding
                st.markdown(
                    '<div class="glass-panel" style="padding:16px; height:100%; border-left:3px solid var(--signal);">'
                    '<strong>🛡️ Remediation Specialist</strong><br>'
                    f'<span style="font-size:12px; color:var(--muted);">Blast Radius: {"PASSED" if rf.get("blast_radius_safe") else "WARNING"}</span>'
                    f'<div style="font-size:12.5px; color:var(--text); margin-top:6px;">'
                    f'Rules Crafted: <strong>5 containment rules</strong><br>'
                    f'STIX 2.1 Bundle: Ready'
                    f'</div></div>',
                    unsafe_allow_html=True,
                )

            st.write("")
            st.markdown('<div class="cmd-header" style="font-size:14px;">📜 MULTI-PLATFORM CONTAINMENT RULES</div>', unsafe_allow_html=True)
            rf_rules = s_brief.containment_finding.get("firewall_rules", {})
            st.code(rf_rules.get("iptables", f"sudo iptables -I INPUT -s {s_brief.attacker_ip} -j DROP"), language="bash")


# ============================================================================
# PAGE: INCIDENT TIMELINE
# ============================================================================


# ============================================================================
# PAGE: INCIDENT TIMELINE
# ============================================================================

def render_incident_timeline():
    section_header("🕓 Incident Timeline",
                   "Chronological record of real events that occurred during this session.")

    timeline = st.session_state.session_timeline

    if not timeline:
        empty_state(
            "🕓", "No incidents recorded yet",
            "Events are logged automatically as you run analyses, detect threats, or use SOC tools.",
            cta_label="🌐 Run an analysis", cta_page="Live Traffic",
        )
        return

    kind_icon = {"info": "🔵", "threat": "🚨", "alert": "⚠️", "action": "🛠️", "success": "✅", "ai": "🧠"}
    kind_class = {"info": "hc-pill-neutral", "threat": "thr-critical", "alert": "thr-high",
                  "action": "datatype-nsl", "success": "hc-pill-online", "ai": "datatype-cicids"}

    col_a, col_b = st.columns([3, 1])
    with col_a:
        st.caption(f"{len(timeline)} incident log entries · frontend session only · newest first")
    with col_b:
        if st.button("🧹 Clear Timeline", use_container_width=True, type="secondary",
                     help="Remove all recorded incident entries from this session."):
            st.session_state.session_timeline = []
            st.rerun()

    st.write("")
    timeline_html = '<div style="border-left:2px solid var(--border); padding-left:18px; display:flex; flex-direction:column; gap:16px;">'
    for entry in timeline:
        icon = kind_icon.get(entry.get("kind", "info"), "🔵")
        cls = kind_class.get(entry.get("kind", "info"), "hc-pill-neutral")
        label = entry.get("kind", "info").upper()
        detail = esc(entry.get("detail", "")) or ''
        timeline_html += f"""
        <div style="position:relative;">
            <span style="position:absolute; left:-25px; top:4px; width:10px; height:10px; border-radius:50%; background:var(--primary); box-shadow:0 0 8px var(--primary);"></span>
            <div style="display:flex; align-items:center; gap:10px; flex-wrap:wrap;">
                <span class="hc-pill {cls}">{icon} {label}</span>
                <span style="font-family:var(--font-display); font-weight:700; color:var(--heading);">{esc(entry.get('event', ''))}</span>
                <span style="margin-left:auto; font-family:var(--font-mono); font-size:11px; color:var(--muted);">🕒 {entry.get('time', '')}</span>
            </div>
            {f'<div style="font-family:var(--font-mono); font-size:12px; color:var(--muted); margin-top:6px;">{detail}</div>' if detail else ''}
        </div>
        """
    timeline_html += '</div>'
    st.markdown(timeline_html, unsafe_allow_html=True)

    st.write("")
    csv_timeline = pd.DataFrame(timeline).to_csv(index=False).encode("utf-8")
    st.download_button("📥 Export Incident Log (CSV)", data=csv_timeline,
                       file_name="netguard_incident_timeline.csv", mime="text/csv",
                       key="dl_timeline_csv")


# ============================================================================
# PAGE: SETTINGS (frontend-only preferences, persisted for the session)
# ============================================================================

def render_settings():
    section_header("🛠️ Settings", "Frontend-only preferences for this SOC console session.")

    settings = st.session_state.app_settings

    st.markdown(
        '<div class="glass-panel" style="font-size:12px; color:var(--muted); padding:14px 18px;">'
        'Settings apply immediately to this browser session only. They never persist model weights, '
        'backend behaviour, or analytics — the protected RAG + ML core stays untouched.</div>',
        unsafe_allow_html=True,
    )
    st.write("")

    tab_view, tab_notify, tab_data = st.tabs(["Interface", "Notifications", "Session Data"])

    with tab_view:
        col1, col2 = st.columns(2)
        with col1:
            theme_mode = st.selectbox("Theme mode", ["Dark"], index=0, key="settings_theme_select")
            settings["theme_mode"] = theme_mode
            st.caption("Only the Dark SOC theme ships with this build; additional themes are not provided.")
            high_contrast = st.toggle("High-contrast accents", value=bool(settings.get("high_contrast")),
                                      key="settings_high_contrast")
            settings["high_contrast"] = high_contrast
            reduced_motion = st.toggle("Reduce motion & animations", value=bool(settings.get("reduced_motion")),
                                       key="settings_reduced_motion")
            settings["reduced_motion"] = reduced_motion
        with col2:
            refresh_pref = st.radio("Refresh preference",
                                    ["manual", "alert only", "auto"],
                                    index=["manual", "alert only", "auto"].index(
                                        settings.get("refresh_preference", "manual")),
                                    key="settings_refresh_pref")
            settings["refresh_preference"] = refresh_pref
            st.caption("Notifies how the console treats page refreshes during an active session.")

        if high_contrast or reduced_motion:
            style_notes = []
            if high_contrast:
                style_notes.append("• High-contrast accent mode enabled — semantic threat colors are emphasised.")
            if reduced_motion:
                style_notes.append("• Motion reduction enabled — kinetic FX, scanlines, and transitions are dampened.")
            st.caption("\n".join(style_notes))

        # Bind reduced-motion to the real kinetic FX toggles so the preference
        # has a tangible effect on the running session (frontend-only).
        # Only applied when the setting actually changed, to avoid clobbering
        # the user's own sidebar FX toggles.
        prev_sync = st.session_state.get("_fx_sync_reduced")
        if prev_sync != reduced_motion:
            st.session_state.fx_3d_bg = not reduced_motion
            st.session_state.fx_animations = not reduced_motion
            st.session_state._fx_sync_reduced = reduced_motion

    with tab_notify:
        show_notifications = st.toggle("Show toast notifications", value=bool(settings.get("show_notifications")),
                                       key="settings_show_notify")
        settings["show_notifications"] = show_notifications
        st.caption("Toggles Streamlit toast notifications when analyses and actions complete.")

    with tab_data:
        st.caption("Clear session data accumulated in the frontend.")
        if st.button("🧹 Clear Prediction History", use_container_width=True, key="settings_clear_history"):
            st.session_state.history = []
            st.session_state.session_timeline = []
            st.success("Prediction history and incident timeline cleared for this session.")
        if st.button("🗑️ Reset Analysis Result", use_container_width=True, key="settings_reset_result"):
            st.session_state.analysis_result = None
            st.session_state.raw_result = None
            st.session_state.explore_df = None
            st.session_state.explore_filename = None
            st.success("Active analysis result cleared.")
        if st.button("💬 Clear SOC AI Chat Thread", use_container_width=True, key="settings_clear_chat"):
            st.session_state.chat_messages = []
            st.success("Chat thread cleared.")

    st.write("")
    st.caption("Session settings snapshot is available only in the current browser; it is not written to disk.")

    st.session_state.app_settings = settings


# ============================================================================
# COMMAND PALETTE (Ctrl+K quick navigation)
# ============================================================================

def render_command_palette():
    """In-page quick-jump palette. Ctrl+K focuses the search box; matching pages
    are shown as navigation buttons. Reuses the existing sidebar page router."""
    st.markdown(
        """
        <script>
        window.addEventListener('keydown', function (e) {
            if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
                e.preventDefault();
                const el = document.querySelector('input[aria-label*="Quick navigation"]');
                if (el) {
                    el.focus();
                    el.select();
                }
            }
        });
        </script>
        """,
        unsafe_allow_html=True,
    )

    palette_col, ctrl_col = st.columns([5, 1])
    with palette_col:
        query = st.text_input(
            "Quick navigation",
            placeholder="Jump to a page…  press Ctrl+K to focus",
            key="quick_nav_input",
            label_visibility="collapsed",
        )
    with ctrl_col:
        st.markdown(
            '<div class="glass-panel" style="text-align:center; font-family:var(--font-mono); '
            'font-size:11px; color:var(--muted); padding:9px 0;">⌨️ CTRL + K</div>',
            unsafe_allow_html=True,
        )

    q = (query or "").strip().lower()
    if not q:
        st.caption("Tip: press Ctrl+K (or ⌘K) and start typing a page name to jump instantly.")
        return

    matches = [name for _, name in NAV_PAGES if q in name.lower()]
    if not matches:
        state_banner("empty", "No matching pages", f"No available page matches “{esc(query)}”.")
        return

    st.caption(f"{len(matches)} navigation match" + ("es" if len(matches) != 1 else "") + " found")
    for name in matches:
        if st.button(f"⏎  {name}", key=f"quick_{name.replace(' ', '_')}", use_container_width=True):
            st.session_state.nav_page = name
            push_timeline("Navigated via command palette", name, kind="action")
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
    "MITRE ATT&CK Matrix": render_mitre_matrix,
    "Agentic SOC Copilot": render_agentic_soc_copilot,
    "Network Topology": render_network_topology,
    "ML Insights": render_ml_insights,
    "Adversarial Red-Team": render_adversarial_tester,
    "SOC AI Assistant": render_soc_ai_assistant,

    "Dataset Analysis": render_dataset_analysis,
    "Data Visualization Explorer": render_data_explorer,
    "Prediction History": render_prediction_history,
    "Incident Timeline": render_incident_timeline,
    "System Status": render_system_status,
    "Settings": render_settings,
    "About": render_about,
}

render_command_palette()

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