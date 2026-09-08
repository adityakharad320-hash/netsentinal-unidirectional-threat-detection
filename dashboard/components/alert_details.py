"""
Alert Deep-Dive & Explainability Explorer Component for NetSentinel.
Displays exact observed feature snapshots, ML probabilities, IF anomaly scores,
and factual human-readable evidence in an editorial SaaS layout.
"""
import streamlit as st
from typing import List, Dict, Any
from dashboard.theme import get_theme_tokens


def render_alert_details(alerts: List[Dict[str, Any]], theme_mode: str = "light"):
    if not alerts:
        st.info("No security alert selected for inspection.")
        return

    alert = alerts[0]
    t = get_theme_tokens(theme_mode)

    st.markdown("### Threat Investigation & Explainability Deep-Dive")
    st.markdown(
        f"<div style='font-size:12px; color:{t['text_muted']}; margin-top:-4px; margin-bottom:16px;'>"
        f"Alert Reference: <code style='font-family:JetBrains Mono, monospace;'>{alert.get('alert_id')}</code>"
        "</div>",
        unsafe_allow_html=True
    )

    # Top Badges Row
    b1, b2, b3, b4 = st.columns(4)
    b1.metric("Threat Category", alert.get("threat_class"))
    b2.metric("Confidence Score", f"{alert.get('confidence_score', 0.0) * 100:.1f}%")
    b3.metric("Severity Level", alert.get("severity"))
    b4.metric("Detection Engine", alert.get("detection_method"))

    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)

    # SOC Operator Summary
    st.markdown(
        f"""
        <div class="editorial-callout">
            <div style="font-size:11px; text-transform:uppercase; letter-spacing:0.06em; color:{t['text_muted']}; font-weight:700; margin-bottom:4px;">
                Primary Detection Rationale
            </div>
            <div style="font-size:13px; color:{t['text_main']}; font-weight:500; line-height:1.5;">
                {alert.get('primary_reason')}
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )

    # Factual Supporting Evidence
    evidence_list = alert.get("supporting_evidence", [])
    if evidence_list:
        st.markdown("#### Factual Observed Evidence")
        for ev in evidence_list:
            st.markdown(
                f"""
                <div style="display:flex; align-items:flex-start; gap:8px; margin-bottom:6px;">
                    <span style="color:{t['text_muted']}; font-family:'JetBrains Mono', monospace; font-size:12px;">[+]</span>
                    <span style="font-size:13px; color:{t['text_main']}; font-weight:500;">{ev}</span>
                </div>
                """,
                unsafe_allow_html=True
            )
    else:
        st.caption("No specific abnormal evidence rules triggered.")

    st.markdown("---")

    # Dual-Engine AI Classification & Observed Features
    col_ml, col_feat = st.columns([1, 1])

    with col_ml:
        st.markdown("#### Dual-Engine AI Classification")
        
        # Random Forest Probabilities
        rf_probs = alert.get("rf_class_probabilities", {})
        if rf_probs:
            st.markdown(
                f"<div style='font-size:12px; font-weight:600; color:{t['text_muted']}; margin-bottom:8px;'>"
                "RANDOM FOREST CLASS PROBABILITIES"
                "</div>",
                unsafe_allow_html=True
            )
            for cls, prob in sorted(rf_probs.items(), key=lambda x: -x[1]):
                st.progress(float(prob), text=f"{cls}: {prob * 100:.1f}%")
        
        # Isolation Forest Anomaly Score
        if_score = alert.get("anomaly_score", 0.0)
        is_anom = alert.get("if_is_anomalous", False)
        anom_badge_class = "badge-critical" if is_anom else "badge-low"
        
        st.markdown(
            f"""
            <div class="editorial-card" style="margin-top:16px;">
                <div style="display:flex; justify-content:space-between; align-items:center;">
                    <span style="font-size:12px; font-weight:600; color:{t['text_muted']};">ISOLATION FOREST ENGINE</span>
                    <span class="{anom_badge_class}">{'ANOMALOUS' if is_anom else 'NORMAL'}</span>
                </div>
                <div style="font-size:12px; color:{t['text_muted']}; margin-top:8px; font-family:'JetBrains Mono', monospace;">
                    Decision Function: {if_score:.6f}
                </div>
                <div style="font-size:11px; color:{t['text_subtle']}; margin-top:4px;">
                    Unsupervised anomaly score based on average tree path length.
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        # Triggered Deterministic Detectors
        trig_dets = alert.get("triggered_detectors", [])
        st.markdown(
            f"<div style='margin-top:14px; margin-bottom:6px; font-size:12px; font-weight:600; color:{t['text_muted']};'>"
            f"TRIGGERED BEHAVIORAL DETECTORS ({len(trig_dets)})"
            "</div>",
            unsafe_allow_html=True
        )
        if trig_dets:
            for td in trig_dets:
                st.markdown(
                    f"""
                    <div style="display:flex; align-items:center; gap:8px; margin-bottom:4px;">
                        <span class="tag-mono" style="color:{t['accent_rose']};">{td}</span>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
        else:
            st.caption("Zero deterministic rule violations.")

    with col_feat:
        st.markdown("#### Observed Telemetry Feature Snapshot")
        snapshot = alert.get("feature_snapshot", {})
        if snapshot:
            st.json(snapshot)
        else:
            st.caption("No specific feature snapshot attached.")

        st.markdown("#### Network Coordinates & Provenance")
        st.markdown(
            f"""
            <div class="editorial-card" style="font-family:'JetBrains Mono', monospace; font-size:12px; line-height:1.8;">
                <div><span style="color:{t['text_muted']};">Flow 5-Tuple:</span> {alert.get('flow_id')}</div>
                <div><span style="color:{t['text_muted']};">Timestamp:</span> {alert.get('timestamp_iso')}</div>
                <div><span style="color:{t['text_muted']};">Occurrences:</span> {alert.get('occurrence_count', 1)} correlated instances</div>
                <div><span style="color:{t['text_muted']};">Model / Schema:</span> Schema {alert.get('schema_version')} | Model {alert.get('model_version')}</div>
            </div>
            """,
            unsafe_allow_html=True
        )
