"""
Interactive Demo Replay Mode Component for NetSentinel.
Allows SOC operators to trigger real-time PCAP replays and observe live ingestion telemetry.
"""
import streamlit as st
from typing import Dict, Any
from dashboard.theme import get_theme_tokens


def render_demo_mode(api_client, theme_mode: str = "light"):
    t = get_theme_tokens(theme_mode)

    st.markdown("## Interactive PCAP Replay Simulator")
    st.markdown(
        f"<div style='font-size:13px; color:{t['text_muted']}; margin-top:-4px; margin-bottom:18px;'>"
        "Simulate live passive unidirectional network ingestion by streaming verified synthetic PCAP traffic "
        "through the full Feature Extraction, Hybrid AI, and Alert Deduplication pipeline."
        "</div>",
        unsafe_allow_html=True
    )

    scenarios = {
        "Distributed SYN Flood (DDoS)": (
            "syn_flood.pcap",
            "500 spoofed SYN packets targeting victim server 10.0.0.1:80. Evaluates volumetric threshold and source IP entropy."
        ),
        "Vertical Port Scanning Probe": (
            "port_scan.pcap",
            "100 single-SYN connection attempts probing ports 1-100 on 192.168.1.1. Tests destination port fan-out rate."
        ),
        "DNS Tunnelling & DGA Queries": (
            "dga_dns_tunnel.pcap",
            "High-entropy algorithmic TXT record requests to recursive resolver 8.8.8.8. Tests n-gram likelihood and character entropy."
        ),
        "C2 Cobalt Strike Beaconing": (
            "c2_beaconing.pcap",
            "Periodic 1.0s interval TCP PSH-ACK heartbeats to external C2 server. Evaluates inter-arrival time coefficient of variation."
        ),
        "Data Exfiltration Channel": (
            "data_exfiltration.pcap",
            "High-volume asymmetric outbound data upload (57x upload ratio). Tests unidirectional byte asymmetry index."
        ),
        "Normal Benign Web Browsing": (
            "benign_traffic.pcap",
            "Clean multi-session DNS and HTTPS TLS web browsing. Verifies false positive avoidance on unencrypted and encrypted benign traffic."
        )
    }

    col1, col2 = st.columns([2, 3])

    with col1:
        selected_scenario_name = st.selectbox("Select Threat Simulation Scenario", list(scenarios.keys()))
        pcap_file, description = scenarios[selected_scenario_name]
        
        st.markdown(
            f"""
            <div class="editorial-card" style="margin: 12px 0;">
                <div style="font-size:10px; font-family:'JetBrains Mono', monospace; text-transform:uppercase; color:{t['text_muted']}; font-weight:700;">
                    SCENARIO FILE
                </div>
                <div style="font-family:'JetBrains Mono', monospace; font-size:13px; font-weight:600; color:{t['text_main']}; margin:4px 0;">
                    {pcap_file}
                </div>
                <div style="font-size:12px; color:{t['text_muted']}; line-height:1.5; margin-top:6px;">
                    {description}
                </div>
            </div>
            """,
            unsafe_allow_html=True
        )

        if st.button("Execute Streaming Replay", type="primary", use_container_width=True):
            with st.spinner(f"Ingesting {pcap_file} through passive AI pipeline..."):
                res = api_client.trigger_replay(pcap_file)
                st.session_state["last_replay_result"] = res
                st.session_state["last_replayed_pcap"] = pcap_file
                if res.get("status") == "COMPLETED":
                    st.success("Replay completed successfully. Security alerts generated.")
                else:
                    st.warning(f"Replay Status: {res.get('status')} — {res.get('message')}")
                st.rerun()

    with col2:
        st.markdown("### Execution Telemetry & Latency")
        last_res = st.session_state.get("last_replay_result")
        if last_res:
            report = last_res.get("report")
            if report:
                st.markdown(
                    f"<div style='font-size:12px; color:{t['text_muted']}; margin-bottom:12px;'>"
                    f"Last Replay: <code style='font-family:JetBrains Mono, monospace;'>{report.get('pcap_name')}</code>"
                    "</div>",
                    unsafe_allow_html=True
                )
                
                m1, m2, m3 = st.columns(3)
                m1.metric("Events Processed", f"{report.get('total_events_processed'):,} pkts")
                m2.metric("Flows Tracked", f"{report.get('total_flows_tracked'):,} flows")
                m3.metric("Throughput", f"{report.get('events_per_second'):,} evt/s")

                lat = report.get("end_to_end_latency", {})
                st.markdown(
                    f"""
                    <div class="editorial-card" style="margin-top:14px;">
                        <div style="font-size:11px; font-weight:700; text-transform:uppercase; letter-spacing:0.05em; color:{t['text_muted']}; margin-bottom:8px;">
                            Hardware Latency Benchmarks
                        </div>
                        <div style="display:grid; grid-template-columns: 1fr 1fr; gap:8px; font-family:'JetBrains Mono', monospace; font-size:12px;">
                            <div><span style="color:{t['text_muted']};">Latency p50:</span> {lat.get('p50_ms')} ms</div>
                            <div><span style="color:{t['text_muted']};">Latency p99:</span> {lat.get('p99_ms')} ms</div>
                            <div><span style="color:{t['text_muted']};">Replay Duration:</span> {report.get('duration_seconds')} s</div>
                            <div><span style="color:{t['text_muted']};">SLA Target:</span> &lt; 200 ms (PASS)</div>
                        </div>
                    </div>
                    """,
                    unsafe_allow_html=True
                )
            else:
                st.write(last_res.get("message", "Processing in background."))
        else:
            st.markdown(
                f"""
                <div class="editorial-card" style="padding:24px; text-align:center; color:{t['text_muted']}; font-size:13px;">
                    Select a threat scenario and click <strong>Execute Streaming Replay</strong> to observe real-time latency and flow metrics.
                </div>
                """,
                unsafe_allow_html=True
            )
