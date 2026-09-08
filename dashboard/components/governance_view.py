"""
Model Governance & Verified Training Metrics Component for NetSentinel.
Presents verifiable dataset audit numbers, confusion matrices, and model limitations in an editorial SaaS layout.
"""
import streamlit as st
import pandas as pd
from dashboard.theme import get_theme_tokens


def render_governance(theme_mode: str = "light"):
    t = get_theme_tokens(theme_mode)

    st.markdown("## Model Governance & Verifiable AI Metrics")
    st.markdown(
        f"<div style='font-size:13px; color:{t['text_muted']}; margin-top:-4px; margin-bottom:18px;'>"
        "Empirical training audits, cross-validation metrics, confusion matrices, and documented boundaries for NTRO PS-26145."
        "</div>",
        unsafe_allow_html=True
    )

    # 1. Dataset Audit
    st.markdown("### Pre-Training Dataset Health Audit")
    audit_data = [
        {"Threat Category": "DDOS", "Flows": 500, "Share": "80.9%", "Pipeline Architecture": "Supervised ONNX RF", "Missing / NaN": "0 NaNs"},
        {"Threat Category": "PORT_SCAN", "Flows": 100, "Share": "16.2%", "Pipeline Architecture": "Supervised ONNX RF", "Missing / NaN": "0 NaNs"},
        {"Threat Category": "BENIGN", "Flows": 13, "Share": "2.1%", "Pipeline Architecture": "Supervised RF + IF Baseline", "Missing / NaN": "0 NaNs"},
        {"Threat Category": "DGA_DNS_TUNNELLING", "Flows": 4, "Share": "0.6%", "Pipeline Architecture": "Rule-Based Heuristic (<10 samples)", "Missing / NaN": "0 NaNs"},
        {"Threat Category": "C2_BEACONING", "Flows": 1, "Share": "0.2%", "Pipeline Architecture": "Rule-Based Heuristic (<10 samples)", "Missing / NaN": "0 NaNs"},
        {"Threat Category": "ENCRYPTED_MALWARE", "Flows": 0, "Share": "0.0%", "Pipeline Architecture": "UNSUPPORTED (No labeled data)", "Missing / NaN": "-"},
        {"Threat Category": "DATA_EXFILTRATION", "Flows": 0, "Share": "0.0%", "Pipeline Architecture": "UNSUPPORTED (No labeled data)", "Missing / NaN": "-"}
    ]
    st.dataframe(pd.DataFrame(audit_data), use_container_width=True)

    st.markdown("---")

    # 2. Random Forest Supervised Classifier (v2.0)
    st.markdown("### Supervised Model: ONNX Random Forest Classifier")
    st.markdown(
        f"<div style='font-size:12px; color:{t['text_muted']}; margin-top:-4px; margin-bottom:12px;'>"
        "5-Fold Stratified Cross-Validation on verified SIH 26145 feature vectors."
        "</div>",
        unsafe_allow_html=True
    )

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("5-Fold CV Accuracy", "99.79% ± 0.42%")
    c2.metric("5-Fold Macro F1", "99.75% ± 0.49%")
    c3.metric("Held-Out Test Precision", "100.0%")
    c4.metric("Held-Out Test Recall", "100.0%")

    st.markdown("#### Test Confusion Matrix (`['BENIGN', 'DDOS', 'PORT_SCAN']`)")
    cm_data = {
        "Actual Class": ["BENIGN", "DDOS", "PORT_SCAN"],
        "Pred: BENIGN": [4, 0, 0],
        "Pred: DDOS": [0, 107, 0],
        "Pred: PORT_SCAN": [0, 0, 21],
        "Per-Class FPR": ["0.0000", "0.0000", "0.0000"]
    }
    st.dataframe(pd.DataFrame(cm_data), use_container_width=True)

    st.markdown("---")

    # 3. Isolation Forest Anomaly Detector
    st.markdown("### Unsupervised Model: Isolation Forest Anomaly Detector")
    st.markdown(
        f"""
        <div class="editorial-card">
            <div style="font-size:13px; font-weight:600; color:{t['text_main']}; margin-bottom:6px;">
                Isolation Forest Configuration & Mathematical Thresholds
            </div>
            <div style="font-size:12px; color:{t['text_muted']}; line-height:1.6; font-family:'JetBrains Mono', monospace;">
                • Baseline Training Sample: 9 clean benign flow feature vectors (contamination parameter = 0.01)<br/>
                • Calibrated Threshold: 0.073393 (50th percentile of benign validation decision scores)<br/>
                • Architectural Role: Serves strictly as a safety net for novel/unseen anomalies when Random Forest confidence is ambiguous (&lt; 0.85).<br/>
                • Documented Limitation: Isolation Forest scores reflect average tree path length depths and are uncalibrated non-probabilistic distances.
            </div>
        </div>
        """,
        unsafe_allow_html=True
    )
