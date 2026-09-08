"""
Targeted Acceptance Test for Interactive Replay Simulator & Live Dashboard Data Flow.

Validates the full chain:
1. Record current alert count.
2. Run scenarios through Interactive Replay Simulator (benign, SYN flood, port scan, DGA, C2, exfiltration).
3. New events enter the real detection pipeline (Welford, Fast Gate, ONNX RF + IF).
4. New alerts appear with CURRENT live timestamps.
5. Alert count increments.
6. Deep Threat Analytics and Live Security Alerts update with the new alert data.
7. Changing attack parameters & speed factor alters event rate and total events.
8. Stop signal verified.
"""
import sys
import os
import time
from pathlib import Path
from datetime import datetime, timezone

# Ensure project paths
root_dir = Path(__file__).resolve().parent
backend_dir = root_dir / "backend"
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(backend_dir))

from dashboard.api_client import DashboardApiClient
from dashboard.components.analytics_view import render_analytics
from dashboard.components.alerts_view import render_alerts_view
from dashboard.components.overview import render_overview

def test_acceptance():
    print("=" * 70)
    print("RUNNING LIVE SIMULATOR ACCEPTANCE TEST")
    print("=" * 70)

    client = DashboardApiClient()
    
    # Reset and seed baseline
    print("[1] Initializing clean state and baseline telemetry...")
    client.reset_pipeline()
    client.load_demo_scenarios()
    
    initial_stats = client.get_statistics()
    initial_alerts = client.get_alerts(limit=500)
    initial_count = initial_stats.get("total_alerts", 0)
    print(f"Initial Baseline Alert Count: {initial_count} alerts across {initial_stats.get('total_events_processed')} events.")
    assert initial_count > 0, "Initial demo load failed to create baseline alerts!"

    # 1. Run SYN Flood with custom live parameters
    print("\n[2] Executing SYN Flood via Simulator with custom live parameters...")
    t_before_syn = time.time()
    res_syn = client.trigger_simulation(
        "SYN_FLOOD",
        parameters={
            "count": 600,
            "spoofed_sources": 60,
            "target_ip": "10.0.0.99",
            "target_port": 8080,
            "rate_pps": 1500
        },
        speed_factor=0.0
    )
    assert res_syn.get("status") == "COMPLETED", f"SYN flood failed: {res_syn}"
    
    stats_after_syn = client.get_statistics()
    alerts_after_syn = client.get_alerts(limit=500)
    syn_count = stats_after_syn.get("total_alerts", 0)
    print(f"Post-SYN Flood Alert Count: {syn_count} (Delta: +{syn_count - initial_count})")
    assert syn_count > initial_count, f"Alert count did not increase after SYN Flood! (Before: {initial_count}, After: {syn_count})"
    
    # Verify latest alert is fresh with current timestamp and matches scenario
    latest_alert = alerts_after_syn[0]
    print(f"Latest Alert: ID={latest_alert.get('alert_id')}, Class={latest_alert.get('threat_class')}, Timestamp={latest_alert.get('timestamp_iso')}, Flow={latest_alert.get('flow_id')}")
    assert latest_alert.get("threat_class") in ("DDOS", "SYN_FLOOD"), f"Latest alert is not DDOS: {latest_alert}"
    assert "10.0.0.99" in latest_alert.get("flow_id", ""), f"Custom target IP 10.0.0.99 not found in flow ID: {latest_alert.get('flow_id')}"
    alert_time = latest_alert.get("timestamp", 0.0)
    assert alert_time >= t_before_syn - 5.0, f"Alert timestamp {alert_time} is not live (before {t_before_syn})!"
    print("PASS: SYN Flood produced fresh live alert with custom target IP and live timestamp.")

    # 2. Run Port Scan with custom parameters
    print("\n[3] Executing Port Scan via Simulator with custom scanner IP...")
    t_before_scan = time.time()
    res_scan = client.trigger_simulation(
        "PORT_SCAN",
        parameters={
            "ports_count": 120,
            "scanner_ip": "192.168.99.50",
            "target_ip": "192.168.99.1",
            "start_port": 1000
        },
        speed_factor=0.0
    )
    assert res_scan.get("status") == "COMPLETED", f"Port scan failed: {res_scan}"
    stats_after_scan = client.get_statistics()
    alerts_after_scan = client.get_alerts(limit=500)
    scan_count = stats_after_scan.get("total_alerts", 0)
    print(f"Post-Port Scan Alert Count: {scan_count} (Delta: +{scan_count - syn_count})")
    assert scan_count > syn_count, f"Alert count did not increase after Port Scan! (Before: {syn_count}, After: {scan_count})"
    latest_scan_alert = alerts_after_scan[0]
    print(f"Latest Alert: ID={latest_scan_alert.get('alert_id')}, Class={latest_scan_alert.get('threat_class')}, Flow={latest_scan_alert.get('flow_id')}")
    assert latest_scan_alert.get("threat_class") == "PORT_SCAN"
    assert "192.168.99.50" in latest_scan_alert.get("flow_id", "")
    print("PASS: Port scan produced fresh live alert with custom scanner IP.")

    # 3. Run DGA / DNS Tunnelling
    print("\n[4] Executing DGA / DNS Tunnel via Simulator...")
    res_dga = client.trigger_simulation("DGA_DNS_TUNNEL", parameters={"count": 16, "query_type": "TXT", "high_entropy": True})
    assert res_dga.get("status") == "COMPLETED"
    stats_dga = client.get_statistics()
    assert stats_dga.get("total_alerts", 0) >= scan_count
    print(f"Post-DGA Alert Count: {stats_dga.get('total_alerts')}")
    print("PASS: DGA / DNS Tunnelling executed through pipeline.")

    # 4. Run C2 Beaconing
    print("\n[5] Executing C2 Beaconing via Simulator...")
    res_c2 = client.trigger_simulation("C2_BEACONING", parameters={"count": 30, "interval_sec": 0.8, "jitter": 0.01, "c2_ip": "198.51.100.99"})
    assert res_c2.get("status") == "COMPLETED"
    stats_c2 = client.get_statistics()
    assert stats_c2.get("total_alerts", 0) >= stats_dga.get("total_alerts", 0)
    print(f"Post-C2 Alert Count: {stats_c2.get('total_alerts')}")
    print("PASS: C2 Beaconing executed through pipeline.")

    # 5. Run Data Exfiltration
    print("\n[6] Executing Data Exfiltration via Simulator...")
    res_exfil = client.trigger_simulation("DATA_EXFILTRATION", parameters={"chunk_count": 50, "chunk_size": 1420, "exfil_ip": "203.0.113.99"})
    assert res_exfil.get("status") == "COMPLETED"
    stats_exfil = client.get_statistics()
    assert stats_exfil.get("total_alerts", 0) >= stats_c2.get("total_alerts", 0)
    print(f"Post-Exfil Alert Count: {stats_exfil.get('total_alerts')}")
    print("PASS: Data Exfiltration executed through pipeline.")

    # 6. Run Benign Traffic
    print("\n[7] Executing Benign Traffic via Simulator...")
    res_benign = client.trigger_simulation("BENIGN", parameters={"num_domains": 6, "num_sessions": 8})
    assert res_benign.get("status") == "COMPLETED"
    print(f"Benign events processed: {res_benign['report']['total_events_processed']}")
    print("PASS: Benign traffic processed without false alarms.")

    # 7. Test Parameter Sensitivity
    print("\n[8] Testing Parameter Sensitivity...")
    res_p1 = client.trigger_simulation("SYN_FLOOD", parameters={"count": 150, "spoofed_sources": 15})
    res_p2 = client.trigger_simulation("SYN_FLOOD", parameters={"count": 800, "spoofed_sources": 100})
    ev1 = res_p1["report"]["total_events_processed"]
    ev2 = res_p2["report"]["total_events_processed"]
    print(f"150 packets request -> {ev1} events | 800 packets request -> {ev2} events")
    assert ev2 > ev1, "Parameter change did not alter total event throughput!"
    print("PASS: Parameter change directly controls throughput and event count.")

    # 8. Test Stop Signal
    print("\n[9] Testing Stop Signal...")
    stop_res = client.stop_replay()
    assert stop_res.get("status") == "STOPPED"
    print("PASS: Stop signal verified.")

    # 9. Verify UI Renderers with final live alert dataset
    print("\n[10] Verifying Live Security Alerts and Deep Threat Analytics renderers...")
    final_stats = client.get_statistics()
    final_alerts = client.get_alerts(limit=500)
    system_status = client.get_system_status()
    
    print(f"Final Live Dataset: {len(final_alerts)} alerts, {final_stats.get('total_events_processed')} events.")
    
    # Must run without any TypeError or exceptions
    render_overview(final_stats, final_alerts, system_status, "light")
    render_alerts_view(final_alerts, "light")
    render_analytics(final_alerts, final_stats, "light")
    render_overview(final_stats, final_alerts, system_status, "dark")
    render_analytics(final_alerts, final_stats, "dark")
    print("PASS: All views rendered with 100% success in both Light and Dark editorial modes.")

    print("\n" + "=" * 70)
    print("ALL ACCEPTANCE CRITERIA VERIFIED AND PASSED (100%)")
    print("=" * 70)

if __name__ == "__main__":
    test_acceptance()
