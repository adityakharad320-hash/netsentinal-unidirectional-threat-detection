"""
FastAPI Server for SIH 2026 AI Cybersecurity Threat Detection Engine.

Endpoints:
  GET   /                   — Health check & system overview
  GET   /alerts             — Paginated alert queries with filtering
  GET   /alerts/{id}        — Single alert lookup
  GET   /statistics         — Aggregated threat statistics
  POST  /pipeline/replay    — Streaming PCAP replay through AI pipeline (sync/async)
  POST  /pipeline/simulate  — Dynamic simulation with customizable parameters
  POST  /pipeline/reset     — Clear state and reset telemetry buffers
  POST  /pipeline/stop      — Signal active replay to stop
  GET   /pipeline/metrics   — Real-time streaming pipeline performance & latency metrics
  WS    /ws/alerts          — Real-time alert streaming WebSocket
"""
import asyncio
import json
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from contextlib import asynccontextmanager

from fastapi import FastAPI, WebSocket, WebSocketDisconnect, Query, HTTPException, Path as FPath, BackgroundTasks
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field

from app.alerts.models import SecurityAlert_v2, AlertSeverity, AlertStatistics
from app.alerts.engine import AlertEngine
from app.ml.hybrid_inference import HybridInferenceEngine
from app.pipeline.orchestrator import StreamingPipelineOrchestrator, PipelinePerformanceReport
from app.config import SAMPLES_DIR, DATA_DIR

logger = logging.getLogger("api")

# Global Singleton Alert Engine & WebSocket Manager
global_alert_engine = AlertEngine(dedup_window_sec=30.0)

class ConnectionManager:
    """Manages active WebSocket client connections for real-time alert broadcasts."""
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self._lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        async with self._lock:
            self.active_connections.append(websocket)
        logger.info(f"WebSocket client connected. Total clients: {len(self.active_connections)}")

    async def disconnect(self, websocket: WebSocket):
        async with self._lock:
            if websocket in self.active_connections:
                self.active_connections.remove(websocket)
        logger.info(f"WebSocket client disconnected. Total clients: {len(self.active_connections)}")

    async def broadcast_alert(self, alert: SecurityAlert_v2):
        if not self.active_connections:
            return
        payload = alert.model_dump_json()
        async with self._lock:
            stale = []
            for ws in self.active_connections:
                try:
                    await ws.send_text(payload)
                except Exception:
                    stale.append(ws)
            for s in stale:
                if s in self.active_connections:
                    self.active_connections.remove(s)

ws_manager = ConnectionManager()

# Global Streaming Pipeline Orchestrator with WebSocket broadcast callback
global_orchestrator = StreamingPipelineOrchestrator(
    alert_engine=global_alert_engine,
    broadcast_callback=ws_manager.broadcast_alert
)

# Latest performance report store & active replay stop event
latest_pipeline_reports: Dict[str, Any] = {}
active_replay_stop_event = asyncio.Event()

class ReplayRequest(BaseModel):
    pcap_filename: str = Field(default="syn_flood.pcap", description="PCAP file to replay from samples directory")
    speed_factor: float = Field(default=0.0, description="Replay speed factor (0.0 = unthrottled hardware speed)")
    sync_mode: bool = Field(default=True, description="Whether to execute synchronously and return the full report")

class SimulationRequest(BaseModel):
    scenario_type: str = Field(..., description="Scenario type: BENIGN, SYN_FLOOD, PORT_SCAN, DGA_DNS_TUNNEL, C2_BEACONING, DATA_EXFILTRATION")
    parameters: Dict[str, Any] = Field(default_factory=dict, description="Custom scenario parameters (counts, IPs, ports, jitter, etc.)")
    speed_factor: float = Field(default=0.0, description="Replay speed factor (0.0 = unthrottled hardware speed)")
    sync_mode: bool = Field(default=True, description="Whether to execute synchronously and return the full report")

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting SIH 2026 Threat Detection FastAPI Backend ...")
    yield
    logger.info("Shutting down FastAPI Backend.")

app = FastAPI(
    title="SIH 2026 AI Cyber Threat Detection Engine API",
    description="Passive Unidirectional Network Security Telemetry & AI Threat Detection Platform",
    version="2.0.0",
    lifespan=lifespan
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/", tags=["System"])
async def root():
    return {
        "system": "SIH 2026 AI Cyber Threat Detection Engine",
        "organization": "National Technical Research Organisation (NTRO)",
        "version": "2.0.0",
        "status": "ONLINE",
        "mode": "PASSIVE_UNIDIRECTIONAL_INSPECTION",
        "endpoints": {
            "alerts": "/alerts",
            "statistics": "/statistics",
            "pipeline_replay": "/pipeline/replay",
            "pipeline_simulate": "/pipeline/simulate",
            "pipeline_reset": "/pipeline/reset",
            "pipeline_stop": "/pipeline/stop",
            "pipeline_metrics": "/pipeline/metrics",
            "websocket_stream": "/ws/alerts",
            "docs": "/docs"
        }
    }

@app.get("/alerts", response_model=List[SecurityAlert_v2], tags=["Alerts"])
async def get_alerts(
    limit: int = Query(default=500, ge=1, le=1000, description="Max alerts to return"),
    offset: int = Query(default=0, ge=0, description="Offset for pagination"),
    threat_class: Optional[str] = Query(default=None, description="Filter by threat class e.g. DDOS, PORT_SCAN"),
    severity: Optional[AlertSeverity] = Query(default=None, description="Filter by severity level"),
    exclude_benign: bool = Query(default=False, description="Exclude normal benign sessions from results")
):
    """Retrieve security alerts with optional class, severity, and pagination filters."""
    alerts = global_alert_engine.get_alerts(
        limit=limit,
        offset=offset,
        threat_class=threat_class,
        severity=severity,
        exclude_benign=exclude_benign
    )
    return alerts

@app.get("/alerts/{alert_id}", response_model=SecurityAlert_v2, tags=["Alerts"])
async def get_alert_by_id(
    alert_id: str = FPath(..., description="Unique alert ID e.g. ALT-20260828-ABCD1234")
):
    """Retrieve full details and supporting evidence for a specific alert."""
    alert = global_alert_engine.get_alert_by_id(alert_id)
    if not alert:
        raise HTTPException(status_code=404, detail=f"Alert with ID '{alert_id}' not found.")
    return alert

@app.get("/statistics", response_model=AlertStatistics, tags=["Statistics"])
async def get_statistics():
    """Retrieve aggregated threat statistics, severity breakdowns, and deduplication metrics."""
    return global_alert_engine.get_statistics()

@app.post("/pipeline/replay", tags=["Pipeline"])
async def trigger_pcap_replay(req: ReplayRequest, background_tasks: BackgroundTasks):
    """Triggers streaming replay of a PCAP file through the AI pipeline."""
    pcap_path = SAMPLES_DIR / req.pcap_filename
    if not pcap_path.exists():
        # Check in dynamic simulations
        dyn_path = SAMPLES_DIR / "dynamic_simulations" / req.pcap_filename
        if dyn_path.exists():
            pcap_path = dyn_path
        else:
            raise HTTPException(status_code=404, detail=f"PCAP sample '{req.pcap_filename}' not found.")

    active_replay_stop_event.clear()

    if req.sync_mode:
        report = await global_orchestrator.run_pipeline_on_pcap(
            pcap_path=pcap_path,
            staging_dir=DATA_DIR / "api_pipeline_staging",
            speed_factor=req.speed_factor if req.speed_factor > 0 else None,
            stop_event=active_replay_stop_event
        )
        latest_pipeline_reports[req.pcap_filename] = report.model_dump()
        return {
            "status": "COMPLETED",
            "pcap": req.pcap_filename,
            "report": report.model_dump(),
            "message": f"PCAP '{req.pcap_filename}' streaming replay completed."
        }
    else:
        async def _run_replay():
            report = await global_orchestrator.run_pipeline_on_pcap(
                pcap_path=pcap_path,
                staging_dir=DATA_DIR / "api_pipeline_staging",
                speed_factor=req.speed_factor if req.speed_factor > 0 else None,
                stop_event=active_replay_stop_event
            )
            latest_pipeline_reports[req.pcap_filename] = report.model_dump()

        background_tasks.add_task(_run_replay)
        return {
            "status": "PROCESSING_STARTED",
            "pcap": req.pcap_filename,
            "message": f"PCAP '{req.pcap_filename}' streaming replay launched in background. Alerts will stream to /ws/alerts."
        }

@app.post("/pipeline/simulate", tags=["Pipeline"])
async def trigger_simulation(req: SimulationRequest, background_tasks: BackgroundTasks):
    """Generates synthetic traffic with custom parameters and streams it through the full detection pipeline."""
    from app.utils.traffic_scenarios import ControlledTrafficGenerator
    
    active_replay_stop_event.clear()
    sim_dir = SAMPLES_DIR / "dynamic_simulations"
    sim_dir.mkdir(parents=True, exist_ok=True)
    
    scen = req.scenario_type.upper().replace(" ", "_")
    p = req.parameters
    now_t = float(p.get("base_t")) if p.get("base_t") is not None else time.time()
    
    if "SYN_FLOOD" in scen or "DDOS" in scen:
        pcap_path = ControlledTrafficGenerator.generate_syn_flood(
            sim_dir / "sim_syn_flood.pcap",
            count=int(p.get("count", 500)),
            spoofed_sources=int(p.get("spoofed_sources", 50)),
            target_ip=str(p.get("target_ip", "10.0.0.1")),
            target_port=int(p.get("target_port", 80)),
            rate_pps=int(p.get("rate_pps", 1000)),
            base_t=now_t
        )
    elif "PORT_SCAN" in scen or "SCAN" in scen:
        pcap_path = ControlledTrafficGenerator.generate_port_scan(
            sim_dir / "sim_port_scan.pcap",
            ports_count=int(p.get("ports_count", 100)),
            scanner_ip=str(p.get("scanner_ip", "192.168.1.50")),
            target_ip=str(p.get("target_ip", "192.168.1.1")),
            start_port=int(p.get("start_port", 1)),
            speed_pps=int(p.get("speed_pps", 100)),
            base_t=now_t
        )
    elif "DGA" in scen or "DNS" in scen:
        pcap_path = ControlledTrafficGenerator.generate_dga_dns_tunnel(
            sim_dir / "sim_dga_dns_tunnel.pcap",
            count=int(p.get("count", 8)),
            query_type=str(p.get("query_type", "TXT")),
            resolver_ip=str(p.get("resolver_ip", "8.8.8.8")),
            src_ip=str(p.get("src_ip", "192.168.1.75")),
            high_entropy=bool(p.get("high_entropy", True)),
            base_t=now_t
        )
    elif "C2" in scen or "BEACON" in scen:
        pcap_path = ControlledTrafficGenerator.generate_c2_beaconing(
            sim_dir / "sim_c2_beaconing.pcap",
            count=int(p.get("count", 20)),
            interval_sec=float(p.get("interval_sec", 1.0)),
            jitter=float(p.get("jitter", 0.02)),
            c2_ip=str(p.get("c2_ip", "198.51.100.42")),
            infected_host=str(p.get("infected_host", "10.0.5.12")),
            base_t=now_t
        )
    elif "EXFIL" in scen or "DATA" in scen:
        pcap_path = ControlledTrafficGenerator.generate_data_exfiltration(
            sim_dir / "sim_data_exfiltration.pcap",
            chunk_count=int(p.get("chunk_count", 40)),
            chunk_size=int(p.get("chunk_size", 1400)),
            exfil_ip=str(p.get("exfil_ip", "203.0.113.50")),
            src_ip=str(p.get("src_ip", "192.168.1.105")),
            base_t=now_t
        )
    elif "BENIGN" in scen:
        pcap_path = ControlledTrafficGenerator.generate_benign(
            sim_dir / "sim_benign.pcap",
            num_domains=int(p.get("num_domains", 4)),
            num_sessions=int(p.get("num_sessions", 5)),
            base_t=now_t
        )
    else:
        raise HTTPException(status_code=400, detail=f"Unknown scenario_type '{req.scenario_type}'.")

    if req.sync_mode:
        report = await global_orchestrator.run_pipeline_on_pcap(
            pcap_path=pcap_path,
            staging_dir=DATA_DIR / "api_pipeline_staging",
            speed_factor=req.speed_factor if req.speed_factor > 0 else None,
            stop_event=active_replay_stop_event
        )
        latest_pipeline_reports[pcap_path.name] = report.model_dump()
        return {
            "status": "COMPLETED",
            "scenario": req.scenario_type,
            "pcap": pcap_path.name,
            "report": report.model_dump(),
            "message": f"Simulation of '{req.scenario_type}' completed."
        }
    else:
        async def _run_sim():
            report = await global_orchestrator.run_pipeline_on_pcap(
                pcap_path=pcap_path,
                staging_dir=DATA_DIR / "api_pipeline_staging",
                speed_factor=req.speed_factor if req.speed_factor > 0 else None,
                stop_event=active_replay_stop_event
            )
            latest_pipeline_reports[pcap_path.name] = report.model_dump()

        background_tasks.add_task(_run_sim)
        return {
            "status": "PROCESSING_STARTED",
            "scenario": req.scenario_type,
            "pcap": pcap_path.name,
            "message": f"Simulation of '{req.scenario_type}' launched in background."
        }

@app.post("/pipeline/reset", tags=["Pipeline"])
async def reset_pipeline():
    """Resets the alert engine, flow trackers, and performance metrics to a clean slate."""
    global_alert_engine._alerts.clear()
    global_alert_engine._dedup_cache.clear()
    global_alert_engine._statistics = AlertStatistics()
    global_orchestrator.reset()
    latest_pipeline_reports.clear()
    return {
        "status": "RESET_SUCCESS",
        "total_alerts": 0,
        "total_flows": 0
    }

@app.post("/pipeline/stop", tags=["Pipeline"])
async def stop_pipeline():
    """Signals any active streaming replay or simulation to stop immediately."""
    active_replay_stop_event.set()
    return {
        "status": "STOPPED",
        "message": "Stop signal sent to active streaming replay."
    }

@app.get("/pipeline/metrics", tags=["Pipeline"])
async def get_pipeline_metrics():
    """Retrieve real-time streaming pipeline throughput and latency statistics."""
    stream_metrics = global_orchestrator.event_stream.get_stream_metrics()
    return {
        "event_stream": stream_metrics,
        "latest_reports": latest_pipeline_reports
    }

@app.websocket("/ws/alerts")
async def websocket_alerts_endpoint(websocket: WebSocket):
    """WebSocket endpoint for real-time live alert streaming to SOC dashboards."""
    await ws_manager.connect(websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        await ws_manager.disconnect(websocket)
    except Exception as e:
        logger.debug(f"WebSocket exception: {e}")
        await ws_manager.disconnect(websocket)
