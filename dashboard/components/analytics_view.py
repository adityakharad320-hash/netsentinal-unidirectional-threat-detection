"""
Traffic Analysis & Threat Analytics Charts Component for NetSentinel.
Editorial SaaS styled visualizations for severity, attribution, and anomaly distributions.
"""
import streamlit as st
import pandas as pd
import plotly.express as px
from typing import List, Dict, Any
from dashboard.theme import get_plotly_layout, get_theme_tokens


def render_analytics(alerts: List[Dict[str, Any]], stats: Dict[str, Any], theme_mode: str = "light"):
    t = get_theme_tokens(theme_mode)
    is_dark = str(theme_mode).lower() == "dark"

    st.markdown("## Security Telemetry & Anomaly Analytics")
    st.markdown(
        f"<div style='font-size:13px; color:{t['text_muted']}; margin-top:-4px; margin-bottom:18px;'>"
        "Statistical telemetry distributions, risk severity breakdowns, and Isolation Forest score separation."
        "</div>",
        unsafe_allow_html=True
    )

    if not alerts:
        st.markdown(
            f"""
            <div class="editorial-callout">
                <div style="font-size:13px; font-weight:600; color:{t['text_main']};">NO TELEMETRY AVAILABLE</div>
                <div style="font-size:12px; color:{t['text_muted']}; margin-top:4px;">
                    No security alerts have been generated yet. Use the Interactive Replay Simulator to stream synthetic PCAP traces.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        return

    df = pd.DataFrame(alerts)

    c1, c2 = st.columns(2)

    with c1:
        # Severity Breakdown Chart
        sev_counts = df["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Alert Count"]
        fig_sev = px.pie(
            sev_counts,
            names="Severity",
            values="Alert Count",
            color="Severity",
            color_discrete_map={
                "CRITICAL": "#DC2626",
                "HIGH": "#D97706",
                "MEDIUM": "#2563EB",
                "LOW": "#059669",
                "INFO": "#71717A"
            },
            title="Alerts by Risk Severity",
            hole=0.60
        )
        fig_sev.update_layout(**get_plotly_layout(theme_mode, height=300))
        st.plotly_chart(fig_sev, use_container_width=True)

    with c2:
        # Detection Methods Breakdown
        meth_counts = df["detection_method"].value_counts().reset_index()
        meth_counts.columns = ["Detection Engine", "Count"]
        fig_meth = px.bar(
            meth_counts,
            x="Detection Engine",
            y="Count",
            color="Detection Engine",
            color_discrete_sequence=["#18181B" if not is_dark else "#FAFAFA", "#52525B", "#71717A", "#A1A1AA"],
            title="Detection Attribution by Engine Type"
        )
        layout_meth = get_plotly_layout(theme_mode, height=300)
        layout_meth["showlegend"] = False
        fig_meth.update_layout(**layout_meth)
        st.plotly_chart(fig_meth, use_container_width=True)

    # Anomaly Score Distribution Histogram
    st.markdown("### Isolation Forest Anomaly Score Distribution")
    if "anomaly_score" in df.columns:
        fig_hist = px.histogram(
            df,
            x="anomaly_score",
            color="threat_class",
            nbins=30,
            title="Isolation Forest Decision Function Separation (Lower = More Anomalous)"
        )
        layout_hist = get_plotly_layout(theme_mode, height=300)
        layout_hist["xaxis_title"] = "Raw Decision Function Score"
        layout_hist["yaxis_title"] = "Event Count"
        fig_hist.update_layout(**layout_hist)
        st.plotly_chart(fig_hist, use_container_width=True)
