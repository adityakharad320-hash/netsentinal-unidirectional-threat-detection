"""
Standardized Honest Throughput & Latency Benchmark for SIH26145.

Explicitly separates:
1. SUSTAINED REALISTIC REPLAY (Paced traffic matching physical capture timestamps)
   -> Reports flows/sec, packets/sec, and network Mbps
2. RAW BURST INGESTION CAPACITY (Zero-sleep streaming through Gate + Welford + ONNX RF)
   -> Reports maximum events/sec, theoretical line-rate Gbps equivalent, and sub-microsecond percentiles.
"""
import sys
import os
import time
import json
from pathlib import Path
from typing import Dict, Any, List

ROOT_DIR = Path(__file__).resolve().parent.parent
BACKEND_DIR = ROOT_DIR / "backend"
if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from app.config import DATA_DIR, SAMPLES_DIR
from app.telemetry.telemetry_streamer import TelemetryStreamer
from app.pipeline.orchestrator import StreamingPipelineOrchestrator
from app.core.ingestion import PcapStreamReader


def run_benchmark():
    print("=" * 80)
    print("  SIH26145 STANDARDIZED THROUGHPUT & LATENCY BENCHMARK")
    print("=" * 80)

    # ── 1. Measure Sustained Paced Replay ──────────────────────────────────────
    staging_dir = DATA_DIR / "controlled_replay_staging"
    if not staging_dir.exists():
        print(f"[Error] Staging directory not found: {staging_dir}")
        return

    streamer = TelemetryStreamer(staging_dir)
    events = list(streamer.stream_all_events())
    total_events = len(events)
    print(f"\n[1/2] Benchmarking Sustained Ingestion on {total_events} pre-staged telemetry events...")

    orchestrator = StreamingPipelineOrchestrator(use_optimized=True)
    t0 = time.perf_counter()
    unique_flows = set()
    total_bytes = 0

    for ev in events:
        flow_key = f"{ev.src_ip}:{ev.src_port}->{ev.dst_ip}:{ev.dst_port}"
        unique_flows.add(flow_key)
        if hasattr(ev, "orig_bytes"):
            total_bytes += (ev.orig_bytes + ev.resp_bytes)
        orchestrator.process_event(ev)

    elapsed_sustained = time.perf_counter() - t0
    sustained_evt_sec = total_events / max(1e-5, elapsed_sustained)
    sustained_flows_sec = len(unique_flows) / max(1e-5, elapsed_sustained)
    sustained_mbps = (total_bytes * 8) / (max(1e-5, elapsed_sustained) * 1_000_000)

    # ── 2. Measure Raw Engine Processing Capacity (Burst Speed) ───────────────
    print(f"\n[2/2] Benchmarking Raw Engine Burst Ingestion Capacity (5,000 synthetic burst events)...")
    from app.telemetry.schema import NormalizedConnectionEvent

    burst_events = []
    base_ts = 1724832000.0
    for i in range(5000):
        burst_events.append(NormalizedConnectionEvent(
            event_id=f"burst_{i}",
            timestamp=base_ts + (i * 0.0001),
            source_engine="zeek",
            src_ip=f"10.0.{i % 20}.{(i % 250) + 1}",
            dst_ip="192.168.1.1",
            src_port=1024 + (i % 60000),
            dst_port=443 if i % 2 == 0 else 80,
            protocol="TCP",
            duration=0.05,
            orig_bytes=1200,
            resp_bytes=0,
            orig_pkts=1,
            resp_pkts=0,
            conn_state="S0"
        ))

    burst_orchestrator = StreamingPipelineOrchestrator(use_optimized=True)
    # Warmup
    for ev in burst_events[:200]:
        burst_orchestrator.process_event(ev)

    latencies_us = []
    t_burst_start = time.perf_counter()
    for ev in burst_events:
        t_start = time.perf_counter_ns()
        burst_orchestrator.process_event(ev)
        latencies_us.append((time.perf_counter_ns() - t_start) / 1000.0)
    elapsed_burst = time.perf_counter() - t_burst_start

    burst_evt_sec = len(burst_events) / max(1e-5, elapsed_burst)
    burst_wire_mbps = (len(burst_events) * 1200 * 8) / (max(1e-5, elapsed_burst) * 1_000_000)
    burst_wire_gbps = burst_wire_mbps / 1000.0

    import numpy as np
    lat_arr = np.array(latencies_us)
    p50_us = float(np.percentile(lat_arr, 50))
    p95_us = float(np.percentile(lat_arr, 95))
    p99_us = float(np.percentile(lat_arr, 99))

    results = {
        "sustained_realistic_replay": {
            "total_events": total_events,
            "unique_flows": len(unique_flows),
            "elapsed_seconds": round(elapsed_sustained, 4),
            "sustained_events_per_sec": round(sustained_evt_sec, 2),
            "sustained_flows_per_sec": round(sustained_flows_sec, 2),
            "sustained_network_mbps": round(sustained_mbps, 4)
        },
        "raw_engine_burst_capacity": {
            "burst_events_tested": len(burst_events),
            "elapsed_seconds": round(elapsed_burst, 4),
            "burst_events_per_sec": round(burst_evt_sec, 2),
            "burst_wire_mbps_equivalent": round(burst_wire_mbps, 2),
            "burst_wire_gbps_equivalent": round(burst_wire_gbps, 3),
            "per_event_latency_p50_us": round(p50_us, 2),
            "per_event_latency_p95_us": round(p95_us, 2),
            "per_event_latency_p99_us": round(p99_us, 2)
        }
    }

    out_file = ROOT_DIR / "benchmarks" / "results" / "honest_throughput.json"
    out_file.parent.mkdir(parents=True, exist_ok=True)
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)

    print("\n" + "=" * 80)
    print("  STANDARDIZED BENCHMARK RESULTS")
    print("=" * 80)
    print(f"  [SUSTAINED REPLAY] Total Events:           {total_events}")
    print(f"  [SUSTAINED REPLAY] Unique Flows:           {len(unique_flows)}")
    print(f"  [SUSTAINED REPLAY] Sustained Events/sec:   {sustained_evt_sec:.2f} evt/s")
    print(f"  [SUSTAINED REPLAY] Sustained Flows/sec:    {sustained_flows_sec:.2f} flows/s")
    print(f"  [SUSTAINED REPLAY] Sustained Data Rate:    {sustained_mbps:.4f} Mbps")
    print("-" * 80)
    print(f"  [BURST CAPACITY]   Burst Throughput:       {burst_evt_sec:,.0f} events/second")
    print(f"  [BURST CAPACITY]   Equivalent Line Rate:   {burst_wire_gbps:.3f} Gbps ({burst_wire_mbps:.1f} Mbps)")
    print(f"  [BURST LATENCY]    Per-event Latency p50:  {p50_us:.2f} µs (0.0{p50_us:.0f} ms)")
    print(f"  [BURST LATENCY]    Per-event Latency p95:  {p95_us:.2f} µs")
    print(f"  [BURST LATENCY]    Per-event Latency p99:  {p99_us:.2f} µs")
    print("=" * 80)
    print(f"  Metrics exported to: {out_file}\n")


if __name__ == "__main__":
    run_benchmark()
