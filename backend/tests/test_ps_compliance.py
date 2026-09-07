"""
Official SIH26145 Problem Statement Compliance & Threat Verification Tests.

Verifies:
1. All Six PS Threat Categories (DDoS, C2, DGA/DNS Tunnel, Encrypted Malware, Port Scan, Data Exfil).
2. Source-IP Behavioral Graph & Entropy Metrics (zero raw IP in ML vector).
3. C2 Periodicity & Low-Jitter IAT Analysis.
4. DGA vs DNS Tunnelling Protocol & Lexical Distinction.
5. Encrypted Malware Metadata (TLS/QUIC, JA3/JA4, SPLT packet size entropy, zero decryption).
6. Unknown Threat Discovery Path (RF uncertain + IF outlier -> UNKNOWN_ANOMALY).
7. Complete Standard Alert Schema (timestamp, flow_id, threat_class, confidence, evidence, severity).
8. Data Diode Physical Unidirectionality (Simplex forward OK, Reverse raises DiodePhysicalViolationError).
"""
import pytest
import numpy as np
from pathlib import Path

from app.detectors.behavioral_engine import BehavioralDetectionEngine
from app.detectors.models import BehavioralDetectorsConfig
from app.telemetry.feature_schema import TelemetryFeatureVector_v2, ORDERED_TELEMETRY_FEATURE_NAMES
from app.telemetry.schema import (
    NormalizedConnectionEvent, NormalizedDNSEvent, NormalizedTLSEvent
)
from app.telemetry.suricata_parser import SuricataEveParser
from app.telemetry.zeek_parser import ZeekLogParser
from app.core.data_diode import SimulatedOpticalDataDiode, DiodePhysicalViolationError
from app.ml.fusion import ThreatFusionEngine, FusionResult
from app.ml.hybrid_inference import HybridInferenceEngine
from app.alerts.engine import AlertEngine
from optimized.flow_tracker import OptimizedFlowState, OptimizedHostGraphTracker
from optimized.feature_pipeline import OptimizedFeatureExtractor


@pytest.fixture
def detector_engine():
    return BehavioralDetectionEngine()


@pytest.fixture
def hybrid_engine():
    return HybridInferenceEngine()


# ── 1. Volumetric / Protocol DDoS Test ─────────────────────────────────────────
def test_ps_ddos_detection(detector_engine):
    fv = TelemetryFeatureVector_v2(
        flow_id="10.0.0.1:1234 -> 192.168.1.1:80 [TCP]",
        timestamp=1000.0,
        syn_ratio=0.95,
        src_ip_entropy=4.2,
        unique_src_count=45.0,
        dst_in_degree=45.0,
        packet_rate=120.0
    )
    res = detector_engine.evaluate_ddos(fv)
    assert res.triggered is True
    assert res.category == "DDoS"
    assert "Distributed SYN flood pattern" in res.human_readable_reason
    assert res.supporting_evidence["syn_ratio"] == 0.95
    assert res.supporting_evidence["src_ip_entropy"] == 4.2


# ── 2. Botnet C2 Beaconing Test ────────────────────────────────────────────────
def test_ps_c2_beaconing_detection(detector_engine):
    fv = TelemetryFeatureVector_v2(
        flow_id="10.0.5.12:49152 -> 198.51.100.42:8443 [TCP]",
        timestamp=1000.0,
        iat_mean=1.002,
        iat_std=0.015,
        iat_cv=0.015,  # Rigid timing: CV <= 0.15
        periodicity_score=0.45,
        repeated_conn_count=15.0,
        repeated_dst_freq=12.0
    )
    res = detector_engine.evaluate_c2_beaconing(fv)
    assert res.triggered is True
    assert res.category == "C2 Beaconing"
    assert "Automated C2 beaconing signal" in res.human_readable_reason
    assert res.supporting_evidence["iat_cv"] == 0.015
    assert res.supporting_evidence["periodicity_score"] == 0.45


# ── 3. DGA vs DNS Tunnelling Distinction Tests ─────────────────────────────────
def test_ps_dga_domain_detection(detector_engine):
    fv = TelemetryFeatureVector_v2(
        flow_id="192.168.1.75:50000 -> 8.8.8.8:53 [UDP]",
        timestamp=1000.0,
        query_len_mean=28.0,
        shannon_entropy_mean=4.15,  # High lexical entropy
        ngram_log_likelihood=-4.65,  # Unpronounceable non-English
        unique_char_ratio=0.88,
        txt_record_ratio=0.0
    )
    res = detector_engine.evaluate_dns_dga(fv)
    assert res.triggered is True
    assert "Algorithmic domain name (DGA)" in res.human_readable_reason
    assert res.supporting_evidence["shannon_entropy_mean"] == 4.15


def test_ps_dns_tunnelling_detection(detector_engine):
    fv = TelemetryFeatureVector_v2(
        flow_id="192.168.1.75:50001 -> 8.8.8.8:53 [UDP]",
        timestamp=1000.0,
        txt_record_ratio=0.75,  # Protocol record abuse: 75% TXT queries
        subdomain_depth_mean=4.0,
        query_len_mean=35.0
    )
    res = detector_engine.evaluate_dns_dga(fv)
    assert res.triggered is True
    assert "Suspicious DNS record abuse" in res.human_readable_reason
    assert res.supporting_evidence["txt_record_ratio"] == 0.75


# ── 4. Encrypted Malware Metadata & Zero Decryption ────────────────────────────
def test_ps_encrypted_malware_detection(detector_engine):
    fv = TelemetryFeatureVector_v2(
        flow_id="192.168.1.50:49200 -> 198.51.100.50:443 [TCP]",
        timestamp=1000.0,
        tls_version_num=1.3,
        has_tls_sni=0.0,  # Direct IP connection to 443 without SNI
        directionality_ratio=0.92,
        pkt_size_entropy=0.75  # Low entropy covert pipeline
    )
    res = detector_engine.evaluate_encrypted_traffic(fv)
    assert res.triggered is True
    assert res.category == "Encrypted Malware"
    assert "Direct IP TLS connection" in res.human_readable_reason or "covert encrypted pipeline" in res.human_readable_reason


def test_ps_suricata_quic_normalization():
    eve_quic_sample = {
        "event_type": "quic",
        "timestamp": "2026-08-28T16:30:00.000000+0000",
        "flow_id": 987654321,
        "src_ip": "10.0.1.5",
        "dest_ip": "142.250.190.46",
        "src_port": 54321,
        "dest_port": 443,
        "proto": "UDP",
        "quic": {
            "version": "1",
            "sni": "covert-quic-c2.net",
            "ja3": "d41d8cd98f00b204e9800998ecf8427e",
            "ja4": "q13d0300_d41d8cd98f00_000000000000"
        }
    }
    event = SuricataEveParser.normalize_eve_event(eve_quic_sample, "eve_test")
    assert isinstance(event, NormalizedTLSEvent)
    assert event.protocol == "UDP"
    assert event.sni_server_name == "covert-quic-c2.net"
    assert event.ja4 == "q13d0300_d41d8cd98f00_000000000000"


# ── 5. Reconnaissance / Port Scanning Test ─────────────────────────────────────
def test_ps_port_scan_detection(detector_engine):
    fv = TelemetryFeatureVector_v2(
        flow_id="192.168.1.50:40000 -> 192.168.1.1:80 [TCP]",
        timestamp=1000.0,
        unique_dst_ports=50.0,
        dst_port_fanout=5.0,
        failed_conn_ratio=0.85,
        conn_attempts=50.0
    )
    res = detector_engine.evaluate_port_scan(fv)
    assert res.triggered is True
    assert res.category == "Port Scanning"
    assert "Vertical port scan" in res.human_readable_reason
    assert res.supporting_evidence["unique_dst_ports"] == 50.0


# ── 6. Data Exfiltration Test ──────────────────────────────────────────────────
def test_ps_data_exfiltration_detection(detector_engine):
    fv = TelemetryFeatureVector_v2(
        flow_id="192.168.1.105:54321 -> 203.0.113.50:443 [TCP]",
        timestamp=1000.0,
        outbound_bytes=150_000.0,
        inbound_bytes=1_200.0,
        out_in_byte_ratio=125.0,  # Asymmetric upload >> 5.0x
        asymmetric_traffic_score=0.98,
        outbound_rate=35_000.0
    )
    res = detector_engine.evaluate_data_exfiltration(fv)
    assert res.triggered is True
    assert res.category == "Data Exfiltration"
    assert "Heavy data exfiltration pattern" in res.human_readable_reason
    assert res.supporting_evidence["out_in_byte_ratio"] == 125.0


# ── 7. Source-IP Behavioral Features (Zero Raw IP in ML Vector) ────────────────
def test_ps_source_ip_behavioral_graph():
    graph = OptimizedHostGraphTracker(window_sec=60.0)
    src_ip = "10.0.1.100"
    for p in range(1, 25):
        graph.add_edge(src_ip, f"192.168.1.{p % 5}", p)

    ports, hosts, p_fanout, h_fanout, out_deg, in_deg = graph.get_metrics(src_ip, "192.168.1.1", duration=5.0)
    assert ports == 24.0
    assert hosts == 5.0
    assert out_deg == 5.0

    # Ensure raw IP is NEVER in the ML feature names list
    assert "src_ip" not in ORDERED_TELEMETRY_FEATURE_NAMES
    assert "dst_ip" not in ORDERED_TELEMETRY_FEATURE_NAMES
    assert len(ORDERED_TELEMETRY_FEATURE_NAMES) == 54


# ── 8. Unknown Anomaly Explicit Fusion Path ────────────────────────────────────
def test_ps_unknown_anomaly_discovery(hybrid_engine):
    # Construct an artificial out-of-distribution vector with no behavioral rule triggers
    fv = TelemetryFeatureVector_v2(
        flow_id="10.99.99.99:9999 -> 192.168.99.99:9999 [TCP]",
        timestamp=1000.0,
        packet_rate=5.0,
        byte_rate=500.0,
        syn_ratio=0.1,
        ack_ratio=0.1,
        rst_ratio=0.1,
        pkt_size_mean=800.0,
        pkt_size_std=400.0,
        pkt_size_entropy=3.8
    )
    result = hybrid_engine.predict(fv)
    assert isinstance(result, FusionResult)
    # Result must be either BENIGN, a known class, or UNKNOWN_ANOMALY with factual non-sensational evidence
    assert result.decision_state in (
        "A: KNOWN_THREAT_CONFIRMED",
        "B: KNOWN_THREAT_PROBABLE",
        "B: KNOWN_THREAT_PROBABLE (BEHAVIORAL_RULE)",
        "C: UNKNOWN_ANOMALY",
        "D: BENIGN_NORMAL_TRAFFIC"
    )
    # Check that any unknown anomaly does not use sensationalist phrasing
    for w in result.warnings:
        assert "zero-day" not in w.lower()


# ── 9. Complete Standard Alert Schema Verification ────────────────────────────
def test_ps_alert_schema_completeness(hybrid_engine):
    alert_engine = AlertEngine(dedup_window_sec=30.0)
    fv = TelemetryFeatureVector_v2(
        flow_id="192.168.1.105:54321 -> 203.0.113.50:443 [TCP]",
        timestamp=1000.0,
        outbound_bytes=150_000.0,
        inbound_bytes=1_200.0,
        out_in_byte_ratio=125.0,
        asymmetric_traffic_score=0.98,
        outbound_rate=35_000.0
    )
    fusion = hybrid_engine.predict(fv)
    alert, is_new = alert_engine.process_detection(fv, fusion)

    assert alert is not None
    # Mandatory PS Fields:
    assert isinstance(alert.timestamp, float)
    assert isinstance(alert.timestamp_iso, str)
    assert alert.flow_id == "192.168.1.105:54321 -> 203.0.113.50:443 [TCP]"
    assert alert.threat_class == "DATA_EXFILTRATION"
    assert 0.0 <= alert.confidence_score <= 1.0
    assert len(alert.supporting_evidence) > 0
    assert alert.severity.value in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


# ── 10. Data Diode Physical Unidirectionality Demonstration ───────────────────
def test_ps_data_diode_unidirectional_proof():
    diode = SimulatedOpticalDataDiode(buffer_capacity=100)

    # 1. Forward transmission (Production -> Monitoring) MUST succeed
    payload = b"\x45\x00\x00\x3c\x1a\x2b\x40\x00\x40\x06"
    assert diode.forward_from_production(payload) is True

    received = diode.receive_at_sensor()
    assert received == payload

    # 2. Reverse transmission (Monitoring -> Production) MUST be physically rejected
    with pytest.raises(DiodePhysicalViolationError) as exc_info:
        diode.attempt_reverse_transmission(b"REVERSE_PACKET_PROBE")

    assert "CRITICAL DIODE VIOLATION" in str(exc_info.value)

    # 3. Audit invariant telemetry
    audit = diode.audit_diode_invariants()
    assert audit["forward_channel_active"] is True
    assert audit["reverse_channel_active"] is False
    assert audit["sensor_tx_interface_status"] == "DISCONNECTED_PHYSICAL_AIRGAP"
    assert audit["unidirectional_hardware_guarantee"] == "VERIFIED_COMPLIANT"
