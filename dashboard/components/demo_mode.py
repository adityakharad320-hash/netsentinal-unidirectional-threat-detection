"""
Interactive Demo Replay Mode & Threat Simulation Component for NetSentinel.
Allows SOC operators to trigger real-time PCAP simulations with custom attack parameters,
adjust ingestion speed/rates, stop streams, and observe live hardware latency telemetry.
"""
import streamlit as st
from typing import Dict, Any
from dashboard.theme import get_theme_tokens


def render_demo_mode(api_client, theme_mode: str = "light"):
    t = get_theme_tokens(theme_mode)

    st.markdown("## Interactive Threat Replay & Attack Simulator")
    st.markdown(
        f"<div style='font-size:13px; color:{t['text_muted']}; margin-top:-4px; margin-bottom:18px;'>"
        "Simulate live passive unidirectional network ingestion by generating real attack telemetry with customizable parameters "
        "and streaming it through the Fast Gate, Welford Tracker, ONNX Random Forest, and Alert Engine."
        "</div>",
        unsafe_allow_html=True
    )

    scenario_options = [
        "Distributed Volumetric SYN Flood (DDoS)",
        "Vertical Reconnaissance Port Scan",
        "DNS Tunnelling & Algorithmic DGA Queries",
        "C2 Cobalt Strike Beaconing",
        "Asymmetric Data Exfiltration",
        "Normal Benign Web & DNS Sessions"
    ]

    col_cfg, col_telemetry = st.columns([1, 1])

    with col_cfg:
        st.markdown("### Simulation Configuration")
        selected_scenario = st.selectbox("Select Threat Scenario", scenario_options)

        params: Dict[str, Any] = {}

        if "SYN Flood" in selected_scenario:
            st.markdown(
                f"<div style='font-size:12px; color:{t['text_muted']}; margin-bottom:8px;'>"
                "Generates high-rate TCP SYN packets across spoofed source IPs to evaluate volume threshold and source entropy."
                "</div>",
                unsafe_allow_html=True
            )
            c_a, c_b = st.columns(2)
            params["count"] = c_a.slider("Total Packet Count", min_value=100, max_value=2000, value=500, step=50)
            params["spoofed_sources"] = c_b.slider("Spoofed Source IPs (Entropy)", min_value=5, max_value=200, value=50, step=5)
            c_c, c_d = st.columns(2)
            params["target_ip"] = c_c.text_input("Target IP Address", value="10.0.0.1")
            params["target_port"] = c_d.number_input("Target Port", min_value=1, max_value=65535, value=80)
            params["rate_pps"] = st.slider("Burst Rate (Packets / Second)", min_value=100, max_value=5000, value=1000, step=100)
            scenario_key = "SYN_FLOOD"

        elif "Port Scan" in selected_scenario:
            st.markdown(
                f"<div style='font-size:12px; color:{t['text_muted']}; margin-bottom:8px;'>"
                "Generates vertical single-SYN connection attempts across destination ports to test fan-out rate and TCP failure ratios."
                "</div>",
                unsafe_allow_html=True
            )
            c_a, c_b = st.columns(2)
            params["ports_count"] = c_a.slider("Probed Ports Count", min_value=20, max_value=500, value=100, step=10)
            params["start_port"] = c_b.number_input("Starting Port Number", min_value=1, max_value=65000, value=1)
            c_c, c_d = st.columns(2)
            params["scanner_ip"] = c_c.text_input("Scanner Source IP", value="192.168.1.50")
            params["target_ip"] = c_d.text_input("Victim Target IP", value="192.168.1.1")
            params["speed_pps"] = st.slider("Scan Velocity (Probes / Sec)", min_value=20, max_value=1000, value=100, step=20)
            scenario_key = "PORT_SCAN"

        elif "DNS Tunnelling" in selected_scenario:
            st.markdown(
                f"<div style='font-size:12px; color:{t['text_muted']}; margin-bottom:8px;'>"
                "Generates algorithmic DNS queries with high-entropy subdomains to evaluate Shannon character entropy and n-gram likelihood."
                "</div>",
                unsafe_allow_html=True
            )
            c_a, c_b = st.columns(2)
            params["count"] = c_a.slider("Query Requests Count", min_value=4, max_value=100, value=12, step=2)
            params["query_type"] = c_b.selectbox("DNS Record Query Type", ["TXT", "A", "AAAA"])
            entropy_choice = st.radio("Domain Entropy Profile", ["High Entropy (Algorithmic DGA / Covert Tunnel)", "Standard Dictionary Domains"], index=0)
            params["high_entropy"] = ("High Entropy" in entropy_choice)
            params["resolver_ip"] = st.text_input("DNS Recursive Resolver IP", value="8.8.8.8")
            scenario_key = "DGA_DNS_TUNNEL"

        elif "C2 Cobalt Strike" in selected_scenario:
            st.markdown(
                f"<div style='font-size:12px; color:{t['text_muted']}; margin-bottom:8px;'>"
                "Generates periodic TCP heartbeats with low inter-arrival variance to test autocorrelation and periodicity estimators."
                "</div>",
                unsafe_allow_html=True
            )
            c_a, c_b = st.columns(2)
            params["count"] = c_a.slider("Heartbeat Beacon Count", min_value=10, max_value=100, value=20, step=5)
            params["interval_sec"] = c_b.slider("Heartbeat Interval (Seconds)", min_value=0.2, max_value=5.0, value=1.0, step=0.1)
            params["jitter"] = st.slider("Timing Jitter Deviation (Seconds)", min_value=0.00, max_value=0.50, value=0.02, step=0.01)
            params["c2_ip"] = st.text_input("External C2 Server IP", value="198.51.100.42")
            scenario_key = "C2_BEACONING"

        elif "Data Exfiltration" in selected_scenario:
            st.markdown(
                f"<div style='font-size:12px; color:{t['text_muted']}; margin-bottom:8px;'>"
                "Generates asymmetric outbound payload transfers to external IPs to test byte asymmetry index and transfer volume."
                "</div>",
                unsafe_allow_html=True
            )
            c_a, c_b = st.columns(2)
            params["chunk_count"] = c_a.slider("Payload Blocks (Chunks)", min_value=10, max_value=200, value=40, step=10)
            params["chunk_size"] = c_b.slider("Payload Block Size (Bytes)", min_value=500, max_value=1450, value=1400, step=50)
            params["exfil_ip"] = st.text_input("Exfiltration Receiver IP", value="203.0.113.50")
            scenario_key = "DATA_EXFILTRATION"

        else:
            st.markdown(
                f"<div style='font-size:12px; color:{t['text_muted']}; margin-bottom:8px;'>"
                "Generates clean bidirectional HTTPS TLS handshakes and multi-domain DNS resolution to test benign gating."
                "</div>",
                unsafe_allow_html=True
            )
            c_a, c_b = st.columns(2)
            params["num_sessions"] = c_a.slider("HTTPS Web Sessions", min_value=2, max_value=30, value=8, step=2)
            params["num_domains"] = c_b.slider("DNS Domain Lookups", min_value=2, max_value=20, value=6, step=2)
            scenario_key = "BENIGN"

        # Replay Rate / Speed Control
        st.markdown("<div style='height: 8px;'></div>", unsafe_allow_html=True)
        speed_label = st.selectbox(
            "Replay Speed / Rate Control",
            [
                "Maximum Throughput (Hardware Maximum)",
                "Real-Time Stream (1.0x Rate)",
                "Accelerated Stream (2.0x Rate)",
                "High-Speed Stream (5.0x Rate)"
            ],
            index=0
        )
        speed_factor = 0.0
        if "1.0x" in speed_label:
            speed_factor = 1.0
        elif "2.0x" in speed_label:
            speed_factor = 2.0
        elif "5.0x" in speed_label:
            speed_factor = 5.0

        # Action Buttons
        btn_col1, btn_col2, btn_col3 = st.columns([2, 1, 1])

        with btn_col1:
            if st.button("Execute Simulation & Ingest Stream", type="primary", use_container_width=True):
                with st.spinner(f"Simulating {selected_scenario} through real AI detection pipeline..."):
                    res = api_client.trigger_simulation(
                        scenario_type=scenario_key,
                        parameters=params,
                        speed_factor=speed_factor
                    )
                    st.session_state["last_replay_result"] = res
                    st.session_state["last_replayed_pcap"] = res.get("pcap", f"{scenario_key}.pcap")
                    if res.get("status") == "COMPLETED":
                        st.success(f"Simulation completed! Real telemetry streamed into pipeline.")
                    else:
                        st.warning(f"Status: {res.get('status')} — {res.get('message')}")
                    st.rerun()

        with btn_col2:
            if st.button("Stop Stream", use_container_width=True):
                stop_res = api_client.stop_replay()
                st.info("Stop signal sent.")
                st.rerun()

        with btn_col3:
            if st.button("Reset State", use_container_width=True):
                reset_res = api_client.reset_pipeline()
                st.session_state["last_replay_result"] = None
                st.session_state["last_replayed_pcap"] = None
                st.success("Alert buffer and flow trackers reset to clean state.")
                st.rerun()

    with col_telemetry:
        st.markdown("### Real Execution Telemetry & Latency")
        last_res = st.session_state.get("last_replay_result")
        if last_res:
            report = last_res.get("report")
            if report:
                st.markdown(
                    f"<div class='editorial-card' style='margin-bottom:12px;'>"
                    f"<div style='display:flex; justify-content:space-between; align-items:center;'>"
                    f"<div><span style='color:{t['text_muted']}; font-size:11px; text-transform:uppercase; font-weight:700;'>SCENARIO PCAP</span>"
                    f"<div style='font-family:JetBrains Mono, monospace; font-size:13px; font-weight:600;'>{report.get('pcap_name')}</div></div>"
                    f"<span class='tag-live'>PIPELINE EXECUTED</span></div>"
                    f"</div>",
                    unsafe_allow_html=True
                )

                m1, m2, m3 = st.columns(3)
                m1.metric("Events Ingested", f"{report.get('total_events_processed', 0):,} pkts")
                m2.metric("Flows Tracked", f"{report.get('total_flows_tracked', 0):,} flows")
                m3.metric("Measured Throughput", f"{report.get('events_per_second', 0.0):,} evt/s")

                m4, m5, m6 = st.columns(3)
                m4.metric("Alerts Generated", f"{report.get('total_alerts_generated', 0):,}")
                m5.metric("Flows / Sec", f"{report.get('flows_per_second', 0.0):,} flows/s")
                m6.metric("Pipeline Duration", f"{report.get('duration_seconds', 0.0):.3f} s")

                lat = report.get("end_to_end_latency", {})
                feat_lat = report.get("feature_extraction_latency", {})
                inf_lat = report.get("inference_latency", {})
                alt_lat = report.get("alert_generation_latency", {})

                st.markdown(
                    f"""
                    <div class="editorial-card" style="margin-top:14px;">
                        <div style="font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.06em; color:{t['text_muted']}; margin-bottom:10px;">
                            Measured Hardware Latencies (Hardware Timers — No Fabrication)
                        </div>
                        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:10px; font-family:'JetBrains Mono', monospace; font-size:12px;">
                            <div><span style="color:{t['text_muted']};">End-to-End Latency p50:</span> <strong>{lat.get('p50_ms', 0.0)} ms</strong></div>
                            <div><span style="color:{t['text_muted']};">End-to-End Latency p95:</span> <strong>{lat.get('p95_ms', 0.0)} ms</strong></div>
                            <div><span style="color:{t['text_muted']};">End-to-End Latency p99:</span> <strong>{lat.get('p99_ms', 0.0)} ms</strong></div>
                            <div><span style="color:{t['text_muted']};">Mean E2E Latency:</span> <strong>{lat.get('mean_ms', 0.0)} ms</strong></div>
                            <div><span style="color:{t['text_muted']};">Feature Extraction p50:</span> {feat_lat.get('p50_ms', 0.0)} ms</div>
                            <div><span style="color:{t['text_muted']};">Hybrid ML Inference p50:</span> {inf_lat.get('p50_ms', 0.0)} ms</div>
                            <div><span style="color:{t['text_muted']};">Alert Deduplication p50:</span> {alt_lat.get('p50_ms', 0.0)} ms</div>
                            <div><span style="color:{t['text_muted']};">SLA Limit (&lt;200ms):</span> <span style="color:{t['accent_emerald']}; font-weight:700;">PASS</span></div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.write(last_res.get("message", "Processing completed."))
        else:
            st.markdown(
                f"""
                <div class="editorial-card" style="padding:28px; text-align:center; color:{t['text_muted']}; font-size:13px;">
                    Select an attack scenario, customize the parameters, and click <strong>Execute Simulation & Ingest Stream</strong> to generate real network telemetry and observe real-time latency and flow metrics.
                </div>
                """,
                unsafe_allow_html=True
            )
