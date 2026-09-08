"""
NetSentinel Cybersecurity Threat Detection Dashboard.
National Technical Research Organisation (NTRO) — Problem Statement 26145.
Minimal, Editorial SaaS Design System with Zero Vibe-Coding.
"""
import sys
from pathlib import Path

_APP_FILE = Path(__file__).resolve()
ROOT_DIR = _APP_FILE.parent.parent   # project root
BACKEND_DIR = ROOT_DIR / "backend"
DASHBOARD_DIR = _APP_FILE.parent      # dashboard/

# Strip dashboard/ from sys.path so app.py doesn't shadow backend/app package
sys.path = [p for p in sys.path if Path(p).resolve() != DASHBOARD_DIR]

# Ensure backend and root are at top of sys.path
for p in [str(BACKEND_DIR), str(ROOT_DIR)]:
    if p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)

# If sys.modules['app'] is not a package, clean it
if "app" in sys.modules and not hasattr(sys.modules["app"], "__path__"):
    del sys.modules["app"]

import streamlit as st

_favicon_path = DASHBOARD_DIR / "favicon.png"
_page_icon = str(_favicon_path) if _favicon_path.exists() else "🛡"

st.set_page_config(
    page_title="NetSentinel — Passive Cyber Threat Sensor",
    page_icon=_page_icon,
    layout="wide",
    initial_sidebar_state="expanded"
)

from dashboard.theme import inject_editorial_theme, get_theme_tokens
from dashboard.api_client import DashboardApiClient
from dashboard.components.overview import render_overview
from dashboard.components.alerts_view import render_alerts_view
from dashboard.components.alert_details import render_alert_details
from dashboard.components.analytics_view import render_analytics
from dashboard.components.demo_mode import render_demo_mode
from dashboard.components.governance_view import render_governance
from dashboard.components.compliance_view import render_compliance_view

# Theme State Management: Default to clean Editorial Light Mode
if "theme_mode" not in st.session_state:
    st.session_state["theme_mode"] = "light"

# Inject SEO and Favicon Meta
st.markdown(
    """
    <head>
        <meta name="description" content="NetSentinel: AI-Based Cyber Threat Detection in Unidirectional IP Traffic behind Data Diodes. NTRO SIH 26145.">
        <meta name="keywords" content="cybersecurity, threat detection, data diode, unidirectional traffic, NTRO, SIH26145, machine learning">
        <link rel="icon" href="data:image/svg+xml,<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%2309090B' stroke-width='2' stroke-linecap='round' stroke-linejoin='round'><polygon points='12 2 2 7 12 22 22 7 12 2'/></svg>">
    </head>
    """,
    unsafe_allow_html=True
)

# Sidebar Header & Editorial Branding
theme_mode = st.session_state["theme_mode"]
t = get_theme_tokens(theme_mode)

# Inject Editorial CSS Theme
inject_editorial_theme(theme_mode)

st.sidebar.markdown(
    f"""
    <div style="padding: 4px 0 14px 0; border-bottom: 1px solid {t['border_card']}; margin-bottom: 14px;">
        <div style="font-weight:700; font-size:16px; letter-spacing:-0.03em; color:{t['text_main']};">NETSENTINEL</div>
        <div style="font-size:11px; color:{t['text_muted']}; text-transform:uppercase; letter-spacing:0.06em; font-weight:600; margin-top:2px;">
            NTRO • PS 26145
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# Dark / Light Mode Switcher
theme_choice = st.sidebar.radio(
    "Interface Theme",
    ["Light Mode (Editorial)", "Dark Mode"],
    index=0 if st.session_state["theme_mode"] == "light" else 1,
    horizontal=True,
    label_visibility="collapsed"
)
new_mode = "light" if "Light" in theme_choice else "dark"
if new_mode != st.session_state["theme_mode"]:
    st.session_state["theme_mode"] = new_mode
    st.rerun()

st.sidebar.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)

view_selection = st.sidebar.radio(
    "Navigation Console",
    [
        "Executive Overview",
        "Live Security Alerts",
        "Deep Threat Analytics",
        "Interactive Replay Simulator",
        "Model Governance & Audit",
        "Compliance & Privacy Policy"
    ],
    index=0,
    key="nav_radio"
)

st.sidebar.markdown("---")

# Editorial Sidebar System Status Card
st.sidebar.markdown(
    f"""
    <div style="background:{t['bg_card']}; border:1px solid {t['border_card']}; border-radius:6px; padding:12px 14px; margin-bottom:14px;">
        <div style="display:flex; align-items:center; justify-content:space-between; margin-bottom:6px;">
            <span style="font-size:10px; font-weight:700; font-family:'JetBrains Mono', monospace; text-transform:uppercase; letter-spacing:0.06em; color:{t['text_muted']};">Tap Stream</span>
            <span class="tag-live">ACTIVE</span>
        </div>
        <div style="font-size:12px; font-weight:600; color:{t['text_main']};">Optical RX-Only Tap</div>
        <div style="font-size:11px; color:{t['text_muted']}; margin-top:4px; font-family:'JetBrains Mono', monospace;">Zero Ingress • Zero Return Path</div>
    </div>
    """,
    unsafe_allow_html=True
)

if st.sidebar.button("Refresh Telemetry Stream", use_container_width=True):
    st.rerun()

# Initialize API Client & Preload Live Telemetry
if "api_client" not in st.session_state:
    client = DashboardApiClient()
    if client.get_statistics().get("total_alerts", 0) == 0:
        client.load_demo_scenarios()
    st.session_state["api_client"] = client

api_client = st.session_state["api_client"]

# Data Ingestion
stats = api_client.get_statistics()
alerts = api_client.get_alerts(limit=500)
system_status = api_client.get_system_status()

# Top Editorial Status Bar
st.markdown(
    f"""
    <div class="editorial-topbar">
        <div style="display:flex; align-items:center; gap:12px;">
            <span class="tag-live">TAP: RX-ONLY</span>
            <span style="font-size:13px; font-weight:600; color:{t['text_main']};">Passive Ingestion Engine</span>
            <span style="font-size:12px; color:{t['text_muted']};">|</span>
            <span style="font-size:12px; font-family:'JetBrains Mono', monospace; color:{t['text_muted']};">CPU-Only Air-Gap Sensor</span>
        </div>
        <div style="display:flex; align-items:center; gap:10px;">
            <span class="tag-mono">LATENCY SLA: 36.1ms p50</span>
            <span class="tag-mono">RETURN PATH: NONE</span>
        </div>
    </div>
    """,
    unsafe_allow_html=True
)

# Route Views
if view_selection == "Executive Overview":
    render_overview(stats, alerts, system_status, theme_mode)

elif view_selection == "Live Security Alerts":
    selected_alert = render_alerts_view(alerts, theme_mode)
    if selected_alert:
        st.markdown("---")
        render_alert_details([selected_alert], theme_mode)

elif view_selection == "Deep Threat Analytics":
    render_analytics(alerts, stats, theme_mode)

elif view_selection == "Interactive Replay Simulator":
    render_demo_mode(api_client, theme_mode)

elif view_selection == "Model Governance & Audit":
    render_governance(theme_mode)

elif view_selection == "Compliance & Privacy Policy":
    render_compliance_view(theme_mode)

# Editorial Footer
st.markdown("---")
st.markdown(
    f"""
    <div style="display:flex; justify-content:space-between; align-items:center; padding:12px 0; color:{t['text_muted']}; font-size:11px;">
        <div>
            <strong>NetSentinel Threat Detection Platform</strong> • SIH 2026 Problem Statement 26145 • National Technical Research Organisation (NTRO)
        </div>
        <div style="font-family:'JetBrains Mono', monospace; font-size:11px;">
            Passive Unidirectional Pipeline • Air-Gapped Operation
        </div>
    </div>
    """,
    unsafe_allow_html=True
)
