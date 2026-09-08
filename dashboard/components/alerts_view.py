"""
Live Alerts Table Component for NetSentinel.
Search, severity filtering, high-density telemetry table, and deep-dive selector.
"""
import streamlit as st
import pandas as pd
from typing import List, Dict, Any, Optional
from dashboard.theme import get_theme_tokens


def render_alerts_view(alerts: List[Dict[str, Any]], theme_mode: str = "light") -> Optional[Dict[str, Any]]:
    t = get_theme_tokens(theme_mode)

    st.markdown("## Live Security Alerts & Threat Stream")
    st.markdown(
        f"<div style='font-size:13px; color:{t['text_muted']}; margin-top:-4px; margin-bottom:18px;'>"
        "Real-time event stream from passive optical tap. Filter by threat category, severity, or network coordinates."
        "</div>",
        unsafe_allow_html=True
    )

    if not alerts:
        st.markdown(
            f"""
            <div class="editorial-callout">
                <div style="font-size:13px; font-weight:600; color:{t['text_main']};">NO SECURITY ALERTS RECORDED</div>
                <div style="font-size:12px; color:{t['text_muted']}; margin-top:4px;">
                    The passive tap buffer is currently clear. Use the Interactive Replay Simulator to stream synthetic PCAP traffic.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )
        return None

    # Filter Controls
    f1, f2, f3 = st.columns([2, 2, 3])
    
    threat_classes = ["ALL"] + sorted(list(set(a.get("threat_class", "") for a in alerts if a.get("threat_class"))))
    selected_threat = f1.selectbox("Threat Category", threat_classes)

    severities = ["ALL", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]
    selected_sev = f2.selectbox("Severity Level", severities)

    search_query = f3.text_input("Search Coordinates", placeholder="Filter by IP, Port, or Alert ID")

    # Apply Filters
    filtered = alerts
    if selected_threat != "ALL":
        filtered = [a for a in filtered if a.get("threat_class") == selected_threat]
    if selected_sev != "ALL":
        filtered = [a for a in filtered if a.get("severity") == selected_sev]
    if search_query:
        q = search_query.strip().lower()
        filtered = [
            a for a in filtered
            if q in a.get("flow_id", "").lower() or q in a.get("alert_id", "").lower()
        ]

    st.markdown(
        f"""
        <div style="display:flex; justify-content:space-between; align-items:center; margin: 10px 0;">
            <div style="font-size:12px; color:{t['text_muted']};">
                Showing <strong>{len(filtered)}</strong> of <strong>{len(alerts)}</strong> total detections
            </div>
            <span class="tag-live">STREAM ACTIVE</span>
        </div>
        """,
        unsafe_allow_html=True
    )

    if not filtered:
        st.markdown(
            f"""
            <div class="editorial-card" style="text-align:center; padding:24px; color:{t['text_muted']}; font-size:13px;">
                No alerts match the selected filter criteria.
            </div>
            """,
            unsafe_allow_html=True
        )
        return None

    # Format table records
    table_rows = []
    for a in filtered:
        table_rows.append({
            "Alert ID": a.get("alert_id"),
            "Timestamp (UTC)": a.get("timestamp_iso", "")[:19].replace("T", " "),
            "Threat Category": a.get("threat_class"),
            "Severity": a.get("severity") or "LOW",
            "Confidence": f"{float(a.get('confidence_score') or 0.0) * 100:.1f}%",
            "Flow 5-Tuple": a.get("flow_id") or "—",
            "Instances": a.get("occurrence_count", 1),
            "Detection Engine": a.get("detection_method") or "—"
        })

    df = pd.DataFrame(table_rows)
    st.dataframe(df, use_container_width=True, height=360)

    # Return top alert for deep inspection selector
    alert_choices = [
        f"{a['alert_id']} | {a['threat_class']} ({a['severity']}) — {a['flow_id']}"
        for a in filtered[:50]
    ]
    st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
    selected_choice = st.selectbox("Select Alert for Deep-Dive Explainability Analysis", alert_choices)
    selected_id = selected_choice.split(" | ")[0]
    return next((a for a in filtered if a["alert_id"] == selected_id), filtered[0])
