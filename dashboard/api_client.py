"""
Resilient Backend Client for Streamlit Dashboard.
Communicates with FastAPI backend server or executes directly in-process
using the StreamingPipelineOrchestrator when FastAPI server is offline.
"""
import os
import sys
import asyncio
import logging
import time
from pathlib import Path
from typing import List, Dict, Any, Optional

# Path setup
_HERE = Path(__file__).resolve()
_ROOT = _HERE.parent.parent          # project root
_BACKEND = _ROOT / "backend"
_DASHBOARD = _HERE.parent            # dashboard/

sys.path = [p for p in sys.path if Path(p).resolve() != _DASHBOARD]

for p in [str(_BACKEND), str(_ROOT)]:
    if p in sys.path:
        sys.path.remove(p)
    sys.path.insert(0, p)

if "app" in sys.modules and not hasattr(sys.modules["app"], "__path__"):
    del sys.modules["app"]

logger = logging.getLogger("dashboard_client")

# Lazy singletons
_engine = None
_hybrid = None
_orchestrator = None

def _get_engine():
    global _engine
    if _engine is None:
        if "app" in sys.modules and not hasattr(sys.modules["app"], "__path__"):
            del sys.modules["app"]
        try:
            from app.main import global_alert_engine
            _engine = global_alert_engine
        except Exception:
            from app.alerts.engine import AlertEngine
            _engine = AlertEngine(dedup_window_sec=30.0)
    return _engine

def _get_hybrid():
    global _hybrid
    if _hybrid is None:
        if "app" in sys.modules and not hasattr(sys.modules["app"], "__path__"):
            del sys.modules["app"]
        from app.ml.hybrid_inference import HybridInferenceEngine
        _hybrid = HybridInferenceEngine()
    return _hybrid

def _get_orchestrator():
    global _orchestrator
    if _orchestrator is None:
        if "app" in sys.modules and not hasattr(sys.modules["app"], "__path__"):
            del sys.modules["app"]
        try:
            from app.main import global_orchestrator
            _orchestrator = global_orchestrator
        except Exception:
            from app.pipeline.orchestrator import StreamingPipelineOrchestrator
            _orchestrator = StreamingPipelineOrchestrator(
                alert_engine=_get_engine(),
                hybrid_engine=_get_hybrid()
            )
    return _orchestrator


class DashboardApiClient:
    def __init__(self, base_url: Optional[str] = None):
        self.base_url = base_url or os.getenv("BACKEND_API_URL", "http://localhost:8000")

    @property
    def engine(self):
        return _get_engine()

    @property
    def hybrid(self):
        return _get_hybrid()

    @property
    def orchestrator(self):
        return _get_orchestrator()

    def get_system_status(self) -> Dict[str, Any]:
        try:
            import httpx
            resp = httpx.get(f"{self.base_url}/", timeout=1.0)
            if resp.status_code == 200:
                data = resp.json()
                data["backend_mode"] = "FASTAPI_REST"
                return data
        except Exception:
            pass
        return {
            "system": "NetSentinel AI Cyber Threat Detection Engine",
            "organization": "NetSentinel",
            "version": "2.0.0",
            "status": "ONLINE",
            "backend_mode": "DIRECT_IN_PROCESS",
            "mode": "PASSIVE_UNIDIRECTIONAL_INSPECTION"
        }

    def get_alerts(self, limit: int = 500) -> List[Dict[str, Any]]:
        try:
            import httpx
            resp = httpx.get(f"{self.base_url}/alerts?limit={limit}", timeout=1.5)
            if resp.status_code == 200:
                data = resp.json()
                if isinstance(data, list):
                    return data
                elif isinstance(data, dict):
                    return data.get("alerts", [])
        except Exception:
            pass
        alerts = self.engine.get_alerts(limit=limit)
        return [a.model_dump() for a in alerts]

    def get_alert_by_id(self, alert_id: str) -> Optional[Dict[str, Any]]:
        try:
            import httpx
            resp = httpx.get(f"{self.base_url}/alerts/{alert_id}", timeout=1.5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        alert = self.engine.get_alert_by_id(alert_id)
        return alert.model_dump() if alert else None

    def get_statistics(self) -> Dict[str, Any]:
        try:
            import httpx
            resp = httpx.get(f"{self.base_url}/statistics", timeout=1.5)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return self.engine.get_statistics().model_dump()

    def explain_alert(self, alert_data: Dict[str, Any]) -> Dict[str, Any]:
        """
        Requests an advisory explanation for a security alert from the Claude AI explainer.
        Tries FastAPI endpoint first, then falls back to in-process ClaudeAlertExplainer.
        """
        payload = {
            "alert_id": alert_data.get("alert_id"),
            "threat_class": alert_data.get("threat_class", "UNKNOWN"),
            "confidence_score": float(alert_data.get("confidence_score", 0.0)),
            "severity": str(alert_data.get("severity", "INFO")),
            "supporting_evidence": alert_data.get("supporting_evidence", []),
            "primary_reason": alert_data.get("primary_reason")
        }
        # 1. Try FastAPI endpoint
        try:
            import httpx
            resp = httpx.post(
                f"{self.base_url}/api/ai/explain-alert",
                json=payload,
                timeout=20.0
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        # 2. In-process fallback
        try:
            from app.ai.models import ExplainAlertRequest
            from app.ai.explainer import ClaudeAlertExplainer
            explainer = ClaudeAlertExplainer()
            req = ExplainAlertRequest(**payload)
            res = explainer.explain_alert(req)
            return res.model_dump()
        except Exception as e:
            return {
                "alert_id": payload.get("alert_id"),
                "threat_class": payload.get("threat_class"),
                "severity": payload.get("severity"),
                "confidence_score": payload.get("confidence_score"),
                "explanation": f"Failed to initialize in-process AI explainer: {str(e)}",
                "status": "error",
                "model_used": None,
                "ai_generated": True,
                "advisory_notice": "AI-generated advisory interpretation. This advisory does not modify detection results, severity, or trigger automated network actions."
            }

    def trigger_simulation(
        self,
        scenario_type: str,
        parameters: Optional[Dict[str, Any]] = None,
        speed_factor: float = 0.0
    ) -> Dict[str, Any]:
        """
        Executes a real simulation with custom attack parameters through the full pipeline.
        """
        params = parameters or {}
        # 1. Try FastAPI REST endpoint
        try:
            import httpx
            resp = httpx.post(
                f"{self.base_url}/pipeline/simulate",
                json={
                    "scenario_type": scenario_type,
                    "parameters": params,
                    "speed_factor": speed_factor,
                    "sync_mode": True
                },
                timeout=30.0
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        # 2. Fallback: Execute full StreamingPipelineOrchestrator in-process
        try:
            from app.config import SAMPLES_DIR, DATA_DIR
            from app.utils.traffic_scenarios import ControlledTrafficGenerator

            sim_dir = SAMPLES_DIR / "dynamic_simulations"
            sim_dir.mkdir(parents=True, exist_ok=True)
            scen = scenario_type.upper().replace(" ", "_")
            now_t = float(params.get("base_t")) if params.get("base_t") is not None else time.time()

            if "SYN_FLOOD" in scen or "DDOS" in scen:
                pcap_path = ControlledTrafficGenerator.generate_syn_flood(
                    sim_dir / "sim_syn_flood.pcap",
                    count=int(params.get("count", 500)),
                    spoofed_sources=int(params.get("spoofed_sources", 50)),
                    target_ip=str(params.get("target_ip", "10.0.0.1")),
                    target_port=int(params.get("target_port", 80)),
                    rate_pps=int(params.get("rate_pps", 1000)),
                    base_t=now_t
                )
            elif "PORT_SCAN" in scen or "SCAN" in scen:
                pcap_path = ControlledTrafficGenerator.generate_port_scan(
                    sim_dir / "sim_port_scan.pcap",
                    ports_count=int(params.get("ports_count", 100)),
                    scanner_ip=str(params.get("scanner_ip", "192.168.1.50")),
                    target_ip=str(params.get("target_ip", "192.168.1.1")),
                    start_port=int(params.get("start_port", 1)),
                    speed_pps=int(params.get("speed_pps", 100)),
                    base_t=now_t
                )
            elif "DGA" in scen or "DNS" in scen:
                pcap_path = ControlledTrafficGenerator.generate_dga_dns_tunnel(
                    sim_dir / "sim_dga_dns_tunnel.pcap",
                    count=int(params.get("count", 8)),
                    query_type=str(params.get("query_type", "TXT")),
                    resolver_ip=str(params.get("resolver_ip", "8.8.8.8")),
                    src_ip=str(params.get("src_ip", "192.168.1.75")),
                    high_entropy=bool(params.get("high_entropy", True)),
                    base_t=now_t
                )
            elif "C2" in scen or "BEACON" in scen:
                pcap_path = ControlledTrafficGenerator.generate_c2_beaconing(
                    sim_dir / "sim_c2_beaconing.pcap",
                    count=int(params.get("count", 20)),
                    interval_sec=float(params.get("interval_sec", 1.0)),
                    jitter=float(params.get("jitter", 0.02)),
                    c2_ip=str(params.get("c2_ip", "198.51.100.42")),
                    infected_host=str(params.get("infected_host", "10.0.5.12")),
                    base_t=now_t
                )
            elif "EXFIL" in scen or "DATA" in scen:
                pcap_path = ControlledTrafficGenerator.generate_data_exfiltration(
                    sim_dir / "sim_data_exfiltration.pcap",
                    chunk_count=int(params.get("chunk_count", 40)),
                    chunk_size=int(params.get("chunk_size", 1400)),
                    exfil_ip=str(params.get("exfil_ip", "203.0.113.50")),
                    src_ip=str(params.get("src_ip", "192.168.1.105")),
                    base_t=now_t
                )
            elif "BENIGN" in scen:
                pcap_path = ControlledTrafficGenerator.generate_benign(
                    sim_dir / "sim_benign.pcap",
                    num_domains=int(params.get("num_domains", 4)),
                    num_sessions=int(params.get("num_sessions", 5)),
                    base_t=now_t
                )
            else:
                return {"status": "ERROR", "message": f"Unknown scenario {scenario_type}"}

            report = self._run_orchestrator(
                pcap_path=pcap_path,
                staging_dir=DATA_DIR / "api_pipeline_staging",
                speed_factor=speed_factor
            )
            return {
                "status": "COMPLETED",
                "scenario": scenario_type,
                "pcap": pcap_path.name,
                "report": report.model_dump(),
                "message": f"Simulation for {scenario_type} completed successfully."
            }
        except Exception as e:
            logger.error(f"trigger_simulation in-process error: {e}", exc_info=True)
            return {"status": "ERROR", "message": str(e)}

    def _run_orchestrator(self, pcap_path: Path, staging_dir: Path, speed_factor: float = 0.0) -> Any:
        """Safe orchestrator invocation — passes speed_factor via **kwargs to avoid any TypeError."""
        kw = {"speed_factor": speed_factor if speed_factor > 0 else None}
        try:
            return asyncio.run(
                self.orchestrator.run_pipeline_on_pcap(pcap_path, staging_dir, **kw)
            )
        except TypeError:
            # Ultimate fallback: old signature with no extra args at all
            try:
                return asyncio.run(
                    self.orchestrator.run_pipeline_on_pcap(pcap_path, staging_dir)
                )
            except Exception as e:
                logger.error(f"_run_orchestrator fallback also failed: {e}", exc_info=True)
                raise

    def trigger_replay(self, pcap_filename: str, speed_factor: float = 0.0) -> Dict[str, Any]:
        """
        Replays an existing PCAP file from samples through the streaming pipeline.
        """
        try:
            import httpx
            resp = httpx.post(
                f"{self.base_url}/pipeline/replay",
                json={
                    "pcap_filename": pcap_filename,
                    "speed_factor": speed_factor,
                    "sync_mode": True
                },
                timeout=30.0
            )
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        try:
            from app.config import SAMPLES_DIR, DATA_DIR
            pcap_path = SAMPLES_DIR / pcap_filename
            if not pcap_path.exists():
                pcap_path = SAMPLES_DIR / "dynamic_simulations" / pcap_filename
            if not pcap_path.exists():
                return {"status": "UNAVAILABLE", "message": f"PCAP sample not found: {pcap_filename}"}

            report = self._run_orchestrator(
                pcap_path=pcap_path,
                staging_dir=DATA_DIR / "api_pipeline_staging",
                speed_factor=speed_factor
            )
            return {
                "status": "COMPLETED",
                "pcap": pcap_filename,
                "report": report.model_dump(),
                "message": f"Replay for {pcap_filename} completed."
            }
        except Exception as e:
            logger.error(f"trigger_replay in-process error: {e}", exc_info=True)
            return {"status": "ERROR", "message": str(e)}

    def reset_pipeline(self) -> Dict[str, Any]:
        """
        Resets alert history, deduplication cache, and performance trackers.
        """
        try:
            import httpx
            resp = httpx.post(f"{self.base_url}/pipeline/reset", timeout=2.0)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass

        self.engine.reset()
        self.orchestrator.reset()
        return {"status": "RESET_SUCCESS", "total_alerts": 0}

    def stop_replay(self) -> Dict[str, Any]:
        """
        Signals active streaming replay to stop.
        """
        try:
            import httpx
            resp = httpx.post(f"{self.base_url}/pipeline/stop", timeout=2.0)
            if resp.status_code == 200:
                return resp.json()
        except Exception:
            pass
        return {"status": "STOPPED", "message": "Replay stopped."}

    def load_demo_scenarios(self):
        """Initial baseline load of controlled scenarios."""
        try:
            base_t = time.time() - 300.0
            for i, scen in enumerate(["BENIGN", "SYN_FLOOD", "PORT_SCAN", "DGA_DNS_TUNNEL", "C2_BEACONING", "DATA_EXFILTRATION"]):
                self.trigger_simulation(scen, parameters={"base_t": base_t + (i * 35.0)}, speed_factor=0.0)
        except Exception as e:
            logger.error(f"load_demo_scenarios error: {e}", exc_info=True)
