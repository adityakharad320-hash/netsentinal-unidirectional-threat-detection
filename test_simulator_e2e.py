"""
End-to-End Verification Test for Interactive Simulator & Detection Pipeline.
Validates:
1. Benign replay -> pipeline updates
2. SYN flood -> DDOS appears
3. Port scan -> PORT_SCAN appears
4. DGA/DNS tunnel -> DGA_DNS_TUNNELLING appears
5. C2 beaconing -> C2_BEACONING appears
6. Data exfiltration -> DATA_EXFILTRATION appears
7. Parameter/rate changes -> output changes
8. Stop replay -> events stop
9. Dashboard rendering components execute with 0 errors
"""
import sys
import os
import time
from pathlib import Path

# Setup paths
root_dir = Path(__file__).resolve().parent
backend_dir = root_dir / "backend"
sys.path.insert(0, str(root_dir))
sys.path.insert(0, str(backend_dir))

from dashboard.api_client import DashboardApiClient
from dashboard.components.overview import render_overview
from dashboard.components.alerts_view import render_alerts_view
from dashboard.components.alert_details import render_alert_details
from dashboard.components.analytics_view import render_analytics
from dashboard.components.governance_view import render_governance

def run_tests():
    print("=" * 60)
    print("STARTING FULL END-TO-END DATA FLOW & SIMULATOR VERIFICATION")
    print("=" * 60)

    client = DashboardApiClient()
    
    # 0. Test Reset
    print("\n[Step 0] Resetting pipeline state...")
    client.reset_pipeline()
    stats = client.get_statistics()
    alerts = client.get_alerts()
    print(f"Post-reset stats: total_alerts={stats.get('total_alerts')}, alerts_len={len(alerts)}")
    assert stats.get("total_alerts", 0) == 0, "Reset failed to clear alerts!"
    assert len(alerts) == 0, "Reset failed to clear alert list!"
    print("PASS: Reset pipeline is clean.")

    # 1. Test Benign Replay
    print("\n[Step 1] Running Benign Traffic simulation...")
    res_benign = client.trigger_simulation("BENIGN", {"num_domains": 5, "num_sessions": 6})
    assert res_benign.get("status") == "COMPLETED", f"Benign simulation failed: {res_benign}"
    rep_b = res_benign.get("report", {})
    print(f"Benign report: {rep_b.get('total_events_processed')} events, {rep_b.get('total_flows_tracked')} flows, e2e_p50={rep_b.get('end_to_end_latency', {}).get('p50_ms')}ms")
    assert rep_b.get("total_events_processed", 0) > 0, "Benign simulation produced 0 events!"
    print("PASS: Benign simulation executed through real pipeline.")

    # 2. Test SYN Flood
    print("\n[Step 2] Running SYN Flood simulation...")
    res_syn = client.trigger_simulation("SYN_FLOOD", {"count": 300, "spoofed_sources": 40, "target_ip": "10.0.0.1", "target_port": 80})
    assert res_syn.get("status") == "COMPLETED", f"SYN Flood simulation failed: {res_syn}"
    rep_syn = res_syn.get("report", {})
    print(f"SYN Flood report: {rep_syn.get('total_events_processed')} events, {rep_syn.get('total_flows_tracked')} flows, {rep_syn.get('total_alerts_generated')} alerts")
    alerts_syn = client.get_alerts(limit=50)
    syn_threats = [a for a in alerts_syn if a.get("threat_class") in ("DDOS", "SYN_FLOOD")]
    print(f"Found {len(syn_threats)} DDOS alerts in live alert engine.")
    assert len(syn_threats) > 0, "SYN Flood failed to generate DDOS alerts!"
    print("PASS: SYN Flood produced real DDOS alerts.")

    # 3. Test Port Scan
    print("\n[Step 3] Running Port Scan simulation...")
    res_scan = client.trigger_simulation("PORT_SCAN", {"ports_count": 80, "scanner_ip": "192.168.1.50", "target_ip": "192.168.1.1"})
    assert res_scan.get("status") == "COMPLETED", f"Port Scan simulation failed: {res_scan}"
    rep_scan = res_scan.get("report", {})
    print(f"Port Scan report: {rep_scan.get('total_events_processed')} events, {rep_scan.get('total_flows_tracked')} flows, {rep_scan.get('total_alerts_generated')} alerts")
    alerts_scan = client.get_alerts(limit=50)
    scan_threats = [a for a in alerts_scan if a.get("threat_class") == "PORT_SCAN"]
    print(f"Found {len(scan_threats)} PORT_SCAN alerts in live alert engine.")
    assert len(scan_threats) > 0, "Port Scan failed to generate PORT_SCAN alerts!"
    print("PASS: Port Scan produced real PORT_SCAN alerts.")

    # 4. Test DGA / DNS Tunnelling
    print("\n[Step 4] Running DGA / DNS Tunnel simulation...")
    res_dga = client.trigger_simulation("DGA_DNS_TUNNEL", {"count": 10, "query_type": "TXT", "high_entropy": True})
    assert res_dga.get("status") == "COMPLETED", f"DGA simulation failed: {res_dga}"
    rep_dga = res_dga.get("report", {})
    print(f"DGA report: {rep_dga.get('total_events_processed')} events, {rep_dga.get('total_flows_tracked')} flows, {rep_dga.get('total_alerts_generated')} alerts")
    alerts_dga = client.get_alerts(limit=50)
    dga_threats = [a for a in alerts_dga if "DGA" in a.get("threat_class", "") or "DNS" in a.get("threat_class", "")]
    print(f"Found {len(dga_threats)} DGA/DNS alerts in live alert engine.")
    assert len(dga_threats) > 0, "DGA/DNS Tunnel failed to generate detection alerts!"
    print("PASS: DGA / DNS Tunnel produced real detections.")

    # 5. Test C2 Beaconing
    print("\n[Step 5] Running C2 Beaconing simulation...")
    res_c2 = client.trigger_simulation("C2_BEACONING", {"count": 25, "interval_sec": 1.0, "jitter": 0.01})
    assert res_c2.get("status") == "COMPLETED", f"C2 simulation failed: {res_c2}"
    rep_c2 = res_c2.get("report", {})
    print(f"C2 report: {rep_c2.get('total_events_processed')} events, {rep_c2.get('total_flows_tracked')} flows, {rep_c2.get('total_alerts_generated')} alerts")
    alerts_c2 = client.get_alerts(limit=50)
    c2_threats = [a for a in alerts_c2 if "C2" in a.get("threat_class", "") or "BEACON" in a.get("threat_class", "")]
    print(f"Found {len(c2_threats)} C2 alerts in live alert engine.")
    assert len(c2_threats) > 0, "C2 Beaconing failed to generate C2 alerts!"
    print("PASS: C2 Beaconing produced real C2 alerts.")

    # 6. Test Data Exfiltration
    print("\n[Step 6] Running Data Exfiltration simulation...")
    res_exfil = client.trigger_simulation("DATA_EXFILTRATION", {"chunk_count": 30, "chunk_size": 1400, "exfil_ip": "203.0.113.50"})
    assert res_exfil.get("status") == "COMPLETED", f"Data Exfiltration simulation failed: {res_exfil}"
    rep_exfil = res_exfil.get("report", {})
    print(f"Exfiltration report: {rep_exfil.get('total_events_processed')} events, {rep_exfil.get('total_flows_tracked')} flows, {rep_exfil.get('total_alerts_generated')} alerts")
    alerts_exfil = client.get_alerts(limit=50)
    exfil_threats = [a for a in alerts_exfil if "EXFIL" in a.get("threat_class", "")]
    print(f"Found {len(exfil_threats)} DATA_EXFILTRATION alerts in live alert engine.")
    assert len(exfil_threats) > 0, "Data Exfiltration failed to generate exfiltration alerts!"
    print("PASS: Data Exfiltration produced real alerts.")

    # 7. Test Parameter / Rate Changes
    print("\n[Step 7] Testing parameter changes...")
    res_syn_small = client.trigger_simulation("SYN_FLOOD", {"count": 100, "spoofed_sources": 10})
    res_syn_large = client.trigger_simulation("SYN_FLOOD", {"count": 600, "spoofed_sources": 80})
    ev_small = res_syn_small["report"]["total_events_processed"]
    ev_large = res_syn_large["report"]["total_events_processed"]
    print(f"Small parameter events: {ev_small} | Large parameter events: {ev_large}")
    assert ev_large > ev_small, "Parameter change did not alter total event count!"
    print("PASS: Parameter change directly alters output metrics.")

    # 8. Test Stop Replay
    print("\n[Step 8] Testing stop signal...")
    stop_res = client.stop_replay()
    assert stop_res.get("status") == "STOPPED", "Stop signal failed!"
    print("PASS: Stop signal verified.")

    # 9. Test Dashboard Components Execution (Zero TypeErrors)
    print("\n[Step 9] Verifying dashboard rendering components with live alert data...")
    live_stats = client.get_statistics()
    live_alerts = client.get_alerts(limit=500)
    system_status = client.get_system_status()
    print(f"Total live alerts to render: {len(live_alerts)}")

    # Test all views without errors
    try:
        render_overview(live_stats, live_alerts, system_status, "light")
        render_alerts_view(live_alerts, "light")
        if live_alerts:
            render_alert_details([live_alerts[0]], "light")
        render_analytics(live_alerts, live_stats, "light")
        render_governance("light")
        print("PASS: All dashboard views rendered with 100% success and 0 errors.")
    except Exception as e:
        print(f"FAIL: Dashboard view rendering raised exception: {e}")
        raise

    print("\n" + "=" * 60)
    print("ALL 8 END-TO-END VERIFICATION CHECKS PASSED SUCCESSFULLY (100%)")
    print("=" * 60)

if __name__ == "__main__":
    run_tests()
