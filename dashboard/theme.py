"""
Editorial SaaS Design System and Theme Engine for NetSentinel Dashboard.
Provides minimal, premium light/dark mode tokens, sharp 1px borders,
black/charcoal typography, zero vibe-coding (no purple gradients, no pill buttons),
and synchronized Plotly chart configurations.
"""
from typing import Dict, Any
import streamlit as st

# Color Tokens: Minimal, Editorial SaaS Palette
LIGHT_THEME = {
    "bg_canvas": "#FAFAFA",
    "bg_card": "#FFFFFF",
    "bg_card_hover": "#F4F4F5",
    "border_card": "#E4E4E7",
    "border_card_hover": "#D4D4D8",
    "text_main": "#09090B",
    "text_muted": "#52525B",
    "text_subtle": "#71717A",
    "accent_emerald": "#059669",
    "accent_rose": "#DC2626",
    "accent_amber": "#D97706",
    "accent_blue": "#2563EB",
    "accent_neutral": "#27272A",
    "badge_bg": "#F4F4F5",
    "badge_border": "#E4E4E7",
    "btn_primary_bg": "#18181B",
    "btn_primary_text": "#FFFFFF",
    "plotly_template": "plotly_white",
    "chart_bg": "rgba(0,0,0,0)",
    "grid_color": "#F4F4F5",
    "sidebar_bg": "#F4F4F5",
}

DARK_THEME = {
    "bg_canvas": "#09090B",
    "bg_card": "#121215",
    "bg_card_hover": "#18181B",
    "border_card": "#27272A",
    "border_card_hover": "#3F3F46",
    "text_main": "#FAFAFA",
    "text_muted": "#A1A1AA",
    "text_subtle": "#71717A",
    "accent_emerald": "#10B981",
    "accent_rose": "#EF4444",
    "accent_amber": "#F59E0B",
    "accent_blue": "#3B82F6",
    "accent_neutral": "#E4E4E7",
    "badge_bg": "#18181B",
    "badge_border": "#27272A",
    "btn_primary_bg": "#FAFAFA",
    "btn_primary_text": "#09090B",
    "plotly_template": "plotly_dark",
    "chart_bg": "rgba(0,0,0,0)",
    "grid_color": "#1C1C21",
    "sidebar_bg": "#0D0D10",
}


def get_theme_tokens(theme_mode: str = "light") -> Dict[str, Any]:
    """Returns the design tokens for the active theme mode."""
    return DARK_THEME if str(theme_mode).lower() == "dark" else LIGHT_THEME


def inject_stackgrid_theme(theme_mode: str = "light"):
    """
    Injects comprehensive CSS rules into Streamlit to render the Editorial SaaS UI.
    Named inject_stackgrid_theme for backwards compatibility with existing imports.
    """
    inject_editorial_theme(theme_mode)


def inject_editorial_theme(theme_mode: str = "light"):
    """Injects minimal, high-contrast editorial SaaS CSS tokens and overrides."""
    t = get_theme_tokens(theme_mode)
    is_dark = str(theme_mode).lower() == "dark"

    css = f"""
    <style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500;600&display=swap');

    :root {{
        --ed-canvas: {t["bg_canvas"]};
        --ed-card: {t["bg_card"]};
        --ed-card-hover: {t["bg_card_hover"]};
        --ed-border: {t["border_card"]};
        --ed-border-hover: {t["border_card_hover"]};
        --ed-text: {t["text_main"]};
        --ed-text-muted: {t["text_muted"]};
        --ed-text-subtle: {t["text_subtle"]};
        --ed-emerald: {t["accent_emerald"]};
        --ed-rose: {t["accent_rose"]};
        --ed-amber: {t["accent_amber"]};
        --ed-blue: {t["accent_blue"]};
        --ed-neutral: {t["accent_neutral"]};
        --ed-badge-bg: {t["badge_bg"]};
        --ed-btn-primary-bg: {t["btn_primary_bg"]};
        --ed-btn-primary-text: {t["btn_primary_text"]};
    }}

    /* Global Body & Layout Reset */
    html, body, .stApp {{
        background-color: var(--ed-canvas) !important;
        color: var(--ed-text) !important;
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif !important;
        letter-spacing: -0.015em;
        -webkit-font-smoothing: antialiased;
        -moz-osx-font-smoothing: grayscale;
    }}

    /* Clean Header */
    header[data-testid="stHeader"] {{
        background-color: transparent !important;
    }}

    /* Sidebar Styling */
    section[data-testid="stSidebar"] {{
        background-color: {t["sidebar_bg"]} !important;
        border-right: 1px solid var(--ed-border) !important;
    }}
    section[data-testid="stSidebar"] hr {{
        border-color: var(--ed-border) !important;
        margin: 16px 0 !important;
    }}
    section[data-testid="stSidebar"] .stRadio label {{
        font-size: 13px !important;
        font-weight: 500 !important;
        color: var(--ed-text) !important;
    }}

    /* Typography Hierarchy */
    h1 {{
        font-size: 24px !important;
        font-weight: 700 !important;
        letter-spacing: -0.03em !important;
        color: var(--ed-text) !important;
        margin-bottom: 8px !important;
    }}
    h2 {{
        font-size: 19px !important;
        font-weight: 700 !important;
        letter-spacing: -0.025em !important;
        color: var(--ed-text) !important;
        margin-top: 16px !important;
        margin-bottom: 8px !important;
    }}
    h3 {{
        font-size: 15px !important;
        font-weight: 600 !important;
        letter-spacing: -0.02em !important;
        color: var(--ed-text) !important;
        margin-top: 14px !important;
        margin-bottom: 6px !important;
    }}
    h4, h5, h6 {{
        font-size: 12px !important;
        font-weight: 600 !important;
        letter-spacing: 0.05em !important;
        text-transform: uppercase !important;
        color: var(--ed-text-muted) !important;
        margin-top: 12px !important;
        margin-bottom: 6px !important;
    }}

    p, span, label {{
        color: var(--ed-text) !important;
        font-size: 14px;
        line-height: 1.5;
    }}

    /* Streamlit Metric Overrides: Sharp, Minimal, High-Contrast */
    div[data-testid="stMetric"] {{
        background-color: var(--ed-card) !important;
        border: 1px solid var(--ed-border) !important;
        border-radius: 6px !important;
        padding: 14px 18px !important;
        box-shadow: {'0 1px 3px rgba(0,0,0,0.3)' if is_dark else '0 1px 2px rgba(0,0,0,0.04)'} !important;
        transition: border-color 0.15s ease !important;
    }}
    div[data-testid="stMetric"]:hover {{
        border-color: var(--ed-border-hover) !important;
    }}
    div[data-testid="stMetricLabel"] {{
        color: var(--ed-text-muted) !important;
        font-size: 11px !important;
        text-transform: uppercase !important;
        letter-spacing: 0.07em !important;
        font-weight: 600 !important;
    }}
    div[data-testid="stMetricValue"] {{
        color: var(--ed-text) !important;
        font-family: 'Inter', sans-serif !important;
        font-size: 24px !important;
        font-weight: 700 !important;
        letter-spacing: -0.02em !important;
    }}
    div[data-testid="stMetricDelta"] {{
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 11px !important;
        font-weight: 500 !important;
    }}

    /* Buttons: Flat, Rectangular, No Gradients, No Pills */
    .stButton > button {{
        background-color: var(--ed-card) !important;
        color: var(--ed-text) !important;
        border: 1px solid var(--ed-border) !important;
        border-radius: 6px !important;
        font-weight: 600 !important;
        font-size: 13px !important;
        padding: 7px 14px !important;
        transition: all 0.12s ease-in-out !important;
        box-shadow: {'0 1px 2px rgba(0,0,0,0.2)' if is_dark else '0 1px 2px rgba(0,0,0,0.03)'} !important;
    }}
    .stButton > button:hover {{
        background-color: var(--ed-card-hover) !important;
        border-color: var(--ed-border-hover) !important;
        color: var(--ed-text) !important;
    }}
    .stButton > button[kind="primary"], .stButton > button[data-testid="baseButton-primary"] {{
        background-color: var(--ed-btn-primary-bg) !important;
        color: var(--ed-btn-primary-text) !important;
        border: 1px solid var(--ed-btn-primary-bg) !important;
        box-shadow: {'0 1px 3px rgba(0,0,0,0.4)' if is_dark else '0 1px 2px rgba(0,0,0,0.1)'} !important;
    }}
    .stButton > button[kind="primary"]:hover, .stButton > button[data-testid="baseButton-primary"]:hover {{
        opacity: 0.9 !important;
        color: var(--ed-btn-primary-text) !important;
    }}

    /* Input & Select Box styling */
    div[data-baseweb="select"] > div, div[data-baseweb="input"] > div {{
        background-color: var(--ed-card) !important;
        border: 1px solid var(--ed-border) !important;
        border-radius: 6px !important;
        color: var(--ed-text) !important;
        font-size: 13px !important;
    }}
    div[data-baseweb="select"] > div:hover, div[data-baseweb="input"] > div:hover {{
        border-color: var(--ed-border-hover) !important;
    }}
    
    /* Code & JSON display */
    code, pre, .stCode {{
        font-family: 'JetBrains Mono', monospace !important;
        font-size: 12px !important;
        border-radius: 6px !important;
        border: 1px solid var(--ed-border) !important;
        background-color: var(--ed-card) !important;
        color: var(--ed-text) !important;
    }}
    
    /* Table / Dataframe styling */
    div[data-testid="stDataFrame"] {{
        border: 1px solid var(--ed-border) !important;
        border-radius: 6px !important;
        overflow: hidden !important;
        background-color: var(--ed-card) !important;
    }}

    /* Editorial Custom Card Containers */
    .editorial-card {{
        background-color: var(--ed-card);
        border: 1px solid var(--ed-border);
        border-radius: 6px;
        padding: 16px 20px;
        box-shadow: {'0 1px 3px rgba(0,0,0,0.2)' if is_dark else '0 1px 2px rgba(0,0,0,0.04)'};
        margin-bottom: 14px;
        transition: border-color 0.15s ease;
    }}
    .editorial-card:hover {{
        border-color: var(--ed-border-hover);
    }}

    .editorial-card-header {{
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 10px;
    }}

    /* Editorial Monospace Badges (Strictly Rectangular, NO Pills) */
    .tag-mono {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: 0.05em;
        padding: 3px 8px;
        border-radius: 4px;
        background: var(--ed-badge-bg);
        border: 1px solid var(--ed-border);
        color: var(--ed-text-muted);
    }}

    .tag-live {{
        display: inline-flex;
        align-items: center;
        gap: 6px;
        font-size: 11px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
        letter-spacing: 0.05em;
        padding: 3px 8px;
        border-radius: 4px;
        background: {'rgba(16,185,129,0.1)' if is_dark else '#ECFDF5'};
        border: 1px solid {'#065F46' if is_dark else '#A7F3D0'};
        color: var(--ed-emerald);
    }}

    /* Alert Severity Badges: High Contrast, Editorial Rectangular */
    .badge-critical {{
        background: {'rgba(239, 68, 68, 0.15)' if is_dark else '#FEF2F2'};
        color: var(--ed-rose);
        border: 1px solid {'rgba(239, 68, 68, 0.3)' if is_dark else '#FECACA'};
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }}
    .badge-high {{
        background: {'rgba(245, 158, 11, 0.15)' if is_dark else '#FFFBEB'};
        color: var(--ed-amber);
        border: 1px solid {'rgba(245, 158, 11, 0.3)' if is_dark else '#FDE68A'};
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }}
    .badge-medium {{
        background: {'rgba(59, 130, 246, 0.15)' if is_dark else '#EFF6FF'};
        color: var(--ed-blue);
        border: 1px solid {'rgba(59, 130, 246, 0.3)' if is_dark else '#BFDBFE'};
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }}
    .badge-low {{
        background: {'rgba(16, 185, 129, 0.15)' if is_dark else '#ECFDF5'};
        color: var(--ed-emerald);
        border: 1px solid {'rgba(16, 185, 129, 0.3)' if is_dark else '#A7F3D0'};
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }}
    .badge-info {{
        background: var(--ed-badge-bg);
        color: var(--ed-text-muted);
        border: 1px solid var(--ed-border);
        padding: 2px 7px;
        border-radius: 4px;
        font-size: 11px;
        font-weight: 600;
        font-family: 'JetBrains Mono', monospace;
    }}

    /* Top Navigation Status Header */
    .editorial-topbar {{
        display: flex;
        justify-content: space-between;
        align-items: center;
        background: var(--ed-card);
        border: 1px solid var(--ed-border);
        border-radius: 6px;
        padding: 12px 18px;
        margin-bottom: 20px;
        box-shadow: {'0 1px 3px rgba(0,0,0,0.2)' if is_dark else '0 1px 2px rgba(0,0,0,0.04)'};
    }}

    /* Clean Callout Block */
    .editorial-callout {{
        background-color: var(--ed-card);
        border-left: 3px solid var(--ed-neutral);
        border-top: 1px solid var(--ed-border);
        border-right: 1px solid var(--ed-border);
        border-bottom: 1px solid var(--ed-border);
        border-radius: 4px;
        padding: 14px 18px;
        margin-bottom: 14px;
    }}
    </style>
    """
    st.markdown(css, unsafe_allow_html=True)


def get_plotly_layout(theme_mode: str = "light", height: int = 320) -> Dict[str, Any]:
    """Generates standard Plotly chart layout properties aligned to Editorial SaaS."""
    t = get_theme_tokens(theme_mode)
    return dict(
        template=t["plotly_template"],
        height=height,
        paper_bgcolor=t["chart_bg"],
        plot_bgcolor=t["chart_bg"],
        font=dict(family="Inter, sans-serif", color=t["text_main"], size=12),
        margin=dict(l=24, r=24, t=40, b=24),
        xaxis=dict(
            gridcolor=t["grid_color"],
            zerolinecolor=t["grid_color"],
            tickfont=dict(family="Inter, sans-serif", color=t["text_muted"], size=10),
            showline=True,
            linecolor=t["border_card"],
        ),
        yaxis=dict(
            gridcolor=t["grid_color"],
            zerolinecolor=t["grid_color"],
            tickfont=dict(family="Inter, sans-serif", color=t["text_muted"], size=10),
            showline=True,
            linecolor=t["border_card"],
        ),
    )
