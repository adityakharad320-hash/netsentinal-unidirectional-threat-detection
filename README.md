# NetSentinal — Passive Cyber Threat Detection for Unidirectional Networks

[![Product](https://img.shields.io/badge/Product-NetSentinal-09090B.svg)](https://netsentinal.dev)
[![Architecture](https://img.shields.io/badge/Architecture-Data%20Diode%20Air--Gap-blue.svg)](https://netsentinal.dev)
[![Tests](https://img.shields.io/badge/Tests-100%2F100%20Passing-brightgreen.svg)](backend/tests/)
[![Inference Engine](https://img.shields.io/badge/Inference-ONNX%20Runtime%20SIMD-orange.svg)](backend/app/ml/)
[![Python](https://img.shields.io/badge/Python-3.11%20%7C%203.12%20%7C%203.13-blue.svg)](requirements.txt)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

NetSentinal is a real-time, passive network security monitoring platform designed for environments where traffic flows in only one direction — such as networks protected by hardware data diodes. It detects and classifies cyber threats from raw IP traffic without requiring a return path, decrypting payloads, or taking any active network action.

---

## Problem Being Solved

Conventional intrusion detection systems depend on bidirectional traffic visibility: they inspect TCP handshakes, retransmission behavior, or apply active probing to clarify suspicious activity. These assumptions fail when the monitoring sensor is physically or logically isolated from the network — as is the case in data diode architectures used in critical infrastructure, government networks, and classified environments.

In a unidirectional setup:
- There is no reverse-path visibility (no SYN-ACK, no FIN, no RST from the target).
- The sensor cannot query external threat intelligence or DNS.
- No inline blocking or active response is possible.
- Flow state must be inferred entirely from forward-direction packet headers and timing.

NetSentinal is built around this constraint. It treats missing reverse packets as normal, infers flow completion from temporal TTLs, and makes all classifications from one-directional telemetry metadata alone.

---

## Key Capabilities

- **Passive-only ingest** — reads from file descriptors and pcap streams with no socket write operations.
- **Sub-millisecond behavioral screening gate** — evaluates low-cost observables (SYN/ACK ratios, packet rates, port fan-out) in under 1 µs to pass steady-state traffic without invoking ML.
- **Welford O(1) statistical flow tracker** — maintains running mean, variance, standard deviation, and inter-arrival jitter per flow using a single-pass algorithm, replacing O(n) deque conversions.
- **54-dimensional feature extraction** — constructs a fixed-length, contiguous feature vector per flow for ML inference.
- **ONNX-accelerated Random Forest** — 100-tree classifier exported to ONNX Runtime SIMD; 195× faster than the equivalent scikit-learn model at inference time.
- **Selective Isolation Forest escalation** — invoked only when RF confidence falls below 0.75, avoiding unnecessary computation on high-certainty classifications.
- **Threat fusion and deduplication** — resolves classifier outputs into prioritized alerts with a 30-second deduplication window.
- **FastAPI streaming REST + WebSocket API** — serves live alerts and pipeline metrics.
- **Streamlit SOC dashboard** — provides a live security view, alert detail panel, deep threat analytics, and replay simulation controls.
- **Claude-powered advisory explanations** — an optional AI feature that sends minimal alert metadata to Anthropic's Claude API and returns a structured, four-section advisory for human analysts. Not the detection engine; never modifies classification results.

---

## Architecture

```
                    Physical / Virtual Tap (Optical Diode / Rx-Only)
                                         │
                                         ▼
                               Zeek + Suricata Engines
                                         │
                                         ▼
                             Normalized Telemetry Stream
                        (TSV conn/dns/ssl + Suricata EVE JSON)
                                         │
                                         ▼
                         ┌───────────────────────────────────────┐
                         │      Fast Behavioral Gate (<1 µs)     │
                         │   (L4/L7 Header Screening & Heuristics)│
                         └───────────────────┬───────────────────┘
                                             │
                       ┌─────────────────────┴─────────────────────┐
                       │ PASS_NORMAL                               │ SUSPICIOUS / UNKNOWN
                       ▼                                           ▼
             ┌───────────────────┐                       ┌───────────────────┐
             │  Welford O(1)     │                       │  54-D Vectorized  │
             │  Flow State       │                       │  Feature Extractor│
             │  (Moments & Jitter│                       │  (Contiguous Pool)│
             └───────────────────┘                       └─────────┬─────────┘
                                                                   │
                                                                   ▼
                                                         ┌───────────────────┐
                                                         │ Inlined Fast      │
                                                         │ Z-Score Scaler    │
                                                         └─────────┬─────────┘
                                                                   │
                                                                   ▼
                                                         ┌───────────────────┐
                                                         │ ONNX Runtime RF   │
                                                         │ (100 Trees SIMD)  │
                                                         └─────────┬─────────┘
                                                                   │
                                                         ┌─────────┴─────────┐
                                    rf_conf >= 0.75      │                   │ rf_conf < 0.75
                                    (High Certainty)     ▼                   ▼ (Ambiguous Anomaly)
                                                ┌────────────────┐   ┌────────────────┐
                                                │ Bypass Iso-    │   │ Selective Iso- │
                                                │ Forest (0 ms)  │   │ Forest Engine  │
                                                └────────┬───────┘   └────────┬───────┘
                                                         │                    │
                                                         └─────────┬──────────┘
                                                                   │
                                                                   ▼
                                                         ┌───────────────────┐
                                                         │ Prioritized Threat│
                                                         │ Fusion Resolver   │
                                                         └─────────┬─────────┘
                                                                   │
                                                                   ▼
                                                         ┌───────────────────┐
                                                         │ Alert Deduplication│
                                                         │ (30-second window) │
                                                         └─────────┬─────────┘
                                                                   │
                                               ┌─────────────────────────────────┐
                                               ▼                                 ▼
                                      FastAPI REST + WebSocket           Streamlit SOC Dashboard
                                      (localhost:8000)                   (localhost:8501)
```

---

## How Detection Works

### 1. Ingestion
Raw packets are read from PCAP files or live taps via `dpkt`. Zeek and Suricata can supply pre-normalized connection logs and EVE JSON, which are parsed into flow records.

### 2. Behavioral Gate (<1 µs)
Each flow is evaluated against lightweight L4/L7 heuristics before any ML is invoked. Flows that clearly match normal traffic patterns are marked `PASS_NORMAL` and bypass the feature pipeline entirely.

### 3. 54-Dimensional Feature Extraction
Suspicious flows proceed to a fixed-width feature vector covering:
- Packet and byte volume statistics (mean, variance, standard deviation via Welford's algorithm)
- Inter-arrival timing (mean, jitter, coefficient of variation)
- TCP flag distributions (SYN, ACK, FIN, RST, PSH ratios)
- IP header diversity (source entropy, TTL variance)
- Port behavior (fan-out, destination concentration, unique port count)
- DNS-specific features (query entropy, bigram log-likelihood, record type ratios)
- Application-layer signals (payload size histograms, upload/download asymmetry)

### 4. ONNX Random Forest Inference
The 54-D vector is fed into a 100-tree Random Forest compiled to ONNX format and run via ONNX Runtime with SIMD instructions. Inference time at p50 is **0.0815 ms** (vs. 15.898 ms with scikit-learn — a **195× improvement**).

### 5. Selective Isolation Forest Escalation
When RF confidence is below 0.75, the flow is escalated to an Isolation Forest for unsupervised novelty scoring. High-confidence flows skip this step entirely, keeping average pipeline latency low.

### 6. Threat Fusion and Alert Deduplication
Classifier outputs from RF and Isolation Forest are merged by a prioritized fusion resolver. Resulting alerts are deduplicated over a 30-second window before being stored and broadcast.

---

## Claude-Powered Alert Analysis

NetSentinal includes an optional **"Explain with Claude"** feature in the SOC dashboard. When an analyst clicks the button on any alert detail panel, the system calls Anthropic's Claude Messages API and displays a structured explanation.

### What is sent to Claude
Only minimal, factual alert metadata is transmitted — no raw packet payloads, no PCAPs, no credentials, and no internal network topology:

| Field | Description |
|:---|:---|
| `alert_id` | Alert reference identifier |
| `threat_class` | Classification label (e.g. `DDOS`, `PORT_SCAN`) |
| `confidence_score` | Normalized score [0.0–1.0] |
| `severity` | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INFO` |
| `supporting_evidence` | Factual telemetry strings (e.g. "SYN ratio: 0.97") |
| `primary_reason` | One-sentence detection rationale |

### What Claude returns
A structured Markdown response with four sections:
1. **Alert Overview** — what the threat class means in a unidirectional perimeter context
2. **Evidence Analysis** — how the observed telemetry indicators support the classification
3. **False-Positive Assessment** — benign administrative or application behaviors that could trigger similar patterns
4. **Human Analyst Recommended Actions** — 3–4 concrete manual triage steps

### Important: role and limitations
- Claude explanations are **advisory only**. They do not modify detection results, confidence scores, severity ratings, or trigger any network action.
- All responses are clearly labelled as AI-generated in the dashboard.
- The Claude integration has been implemented and unit-tested with mocked API responses (8/8 tests passing). A live Anthropic API call requires a valid `ANTHROPIC_API_KEY` to be configured.
- Default model: `claude-3-5-haiku-20241022`. Configurable via `ANTHROPIC_MODEL` environment variable.

### Configuration
```bash
cp .env.example .env
# Then edit .env:
ANTHROPIC_API_KEY=sk-ant-api03-...
ANTHROPIC_MODEL=claude-3-5-haiku-20241022   # optional; this is the default
```

If `ANTHROPIC_API_KEY` is not set, the system runs fully offline. Alert explanation cards display clear setup instructions rather than an error.

---

## Threat Categories

| Threat Class | Detection Approach | Training Data |
|:---|:---|:---|
| **DDoS / SYN Flood** | Supervised RF (ONNX) + behavioral gate | 500 labeled flows |
| **Port Scanning** | Supervised RF (ONNX) + behavioral gate | 100 labeled flows |
| **DNS / DGA Tunnelling** | Rule-based heuristics (query entropy > 3.4 bits, bigram log-likelihood, TXT record ratio > 50%) | Insufficient labeled data for supervised ML |
| **C2 Beaconing** | Rule-based heuristics (inter-arrival CV ≤ 0.15, FFT spectral periodicity) | Insufficient labeled data for supervised ML |
| **Data Exfiltration** | Rule-based heuristics (upload/download asymmetry > 5×, throughput > 25 KB/s) | No labeled training data |
| **Encrypted Malware** | Rule-based heuristics (direct-IP TLS, missing SNI, low entropy) | No labeled training data — marked UNSUPPORTED |
| **Unknown Novel Anomalies** | Unsupervised Isolation Forest novelty detection | N/A (unsupervised) |

> [!NOTE]
> The RF classifier was trained on 618 labeled flows (DDOS=500, PORT_SCAN=100, BENIGN=13, DGA=4, C2=1). DGA/DNS Tunnelling, C2 Beaconing, Data Exfiltration, and Encrypted Malware detections rely on hand-crafted behavioral heuristics due to insufficient labeled examples in the current training set. Extending the labeled dataset would allow supervised ML for these classes.

---

## Performance Benchmarks

Measured on CPU-only hardware across 6 replay scenarios (1,618 events, 613 active flows):

| Metric | Baseline (scikit-learn) | Optimized (ONNX Runtime) | Improvement |
|:---|:---|:---|:---|
| Pipeline replay duration | 71.02 s | **35.47 s** | 2.0× faster |
| Throughput (replay) | 22.8 evt/s | **45.6 evt/s** | 2.0× higher |
| Throughput (synthetic burst) | 5,800 evt/s | **131,442 evt/s** | 22.6× higher |
| End-to-end latency p50 | 42.66 ms | **21.58 ms** | 1.98× faster |
| End-to-end latency p95 | 50.16 ms | **23.32 ms** | 2.15× faster |
| End-to-end latency p99 | 63.88 ms | **27.51 ms** | 2.32× lower tail |
| RF inference p50 | 15.898 ms | **0.0815 ms** | **195× faster** |
| Memory per 5,000 active flows | 35.10 MB | **15.14 MB** | 56.9% savings |
| Cold start to first prediction | 0.2222 s | **0.0427 s** | 5.2× faster |
| Model size on disk (RF) | 309.7 KB | **105.1 KB** | 2.95× smaller |
| Feature schema dimensions | 54/54 | **54/54** | 100% parity |

---

## Technology Stack

| Component | Technology |
|:---|:---|
| Runtime language | Python 3.11 / 3.12 / 3.13 |
| HTTP API | FastAPI ≥ 0.110.0 + Uvicorn |
| WebSocket streaming | `websockets` ≥ 12.0 |
| HTTP client | `httpx` ≥ 0.27.0 |
| ML inference engine | ONNX Runtime ≥ 1.17.0 (SIMD) |
| Model training | scikit-learn ≥ 1.4.0, XGBoost ≥ 2.0.0 |
| Feature computation | NumPy ≥ 1.26.0 |
| Data validation | Pydantic ≥ 2.6.0 |
| Packet parsing | dpkt ≥ 1.9.8, Scapy ≥ 2.5.0 |
| Telemetry parsing | Zeek TSV / Suricata EVE JSON |
| SOC dashboard | Streamlit ≥ 1.32.0 + Plotly ≥ 5.19.0 |
| AI advisory | Anthropic Python SDK ≥ 0.18.0 (optional) |
| ONNX export | skl2onnx ≥ 1.16.0 |
| Test framework | pytest ≥ 8.0.0, pytest-asyncio |
| Container orchestration | Docker Compose |

---

## Unidirectional Compliance

NetSentinal is designed from the ground up for receive-only environments:

- **Read-only ingest** — all stream processing uses `open(..., 'rb')` iterators and generator pipelines; no write sockets.
- **Zero return path** — no calls to `send()`, `sendto()`, or any packet-transmission primitive.
- **Zero active probing** — no ping sweeps, TCP handshakes, ICMP messages, or DNS queries are generated toward the monitored network.
- **Zero external lookups** — no cloud threat-intelligence APIs, WHOIS queries, or external DNS resolution. Fully air-gapped.
- **Zero inline blocking** — strictly out-of-band; no iptables/nftables manipulation.
- **Zero payload decryption** — operates exclusively on L3/L4 metadata, TLS SNI, cipher suites, and JA3/JA4 fingerprints.
- **Missing reverse packets are normal** — missing SYN-ACK, reverse ACK, or FIN is treated as standard diode behavior, not an anomaly.
- **Flow eviction without FIN/RST** — flow state tables use temporal sliding-window TTLs for termination inference.

---

## Quickstart

### 1. Clone and install (headless sensor only)
```bash
git clone https://github.com/adityakharad320-hash/sih-unidirectional-threat-detection.git
cd sih-unidirectional-threat-detection
pip install -r requirements-sensor.txt
```

### 2. Full installation (dashboard + API + AI explainer + tests)
```bash
pip install -r requirements.txt
```

### 3. Configure environment (optional — only for Claude integration)
```bash
cp .env.example .env
# Edit .env and add your ANTHROPIC_API_KEY
```

### 4. Run the test suite (100 tests)
```bash
python -m pytest backend/tests -v
```

### 5. Run controlled detection scenarios
```bash
cd backend
python run_controlled_scenarios.py
```

### 6. Run the performance benchmark
```bash
cd backend
python run_pipeline_benchmark.py
```

### 7. Start the FastAPI backend
```bash
cd backend
python -m uvicorn app.main:app --host 0.0.0.0 --port 8000 --reload
```

### 8. Start the Streamlit SOC dashboard
```bash
streamlit run dashboard/app.py --server.port 8501
```

Open [http://localhost:8501](http://localhost:8501) to access the monitoring interface. The API is available at [http://localhost:8000/docs](http://localhost:8000/docs).

### Docker (optional)
```bash
docker-compose up --build
```

---

## API Endpoints

| Method | Path | Description |
|:---|:---|:---|
| `GET` | `/` | System health and endpoint catalog |
| `GET` | `/alerts` | Paginated alert queries with class/severity filters |
| `GET` | `/alerts/{alert_id}` | Single alert lookup by ID |
| `GET` | `/statistics` | Aggregated threat statistics |
| `POST` | `/pipeline/replay` | Streaming PCAP replay through the detection pipeline |
| `POST` | `/pipeline/simulate` | Synthetic traffic simulation with configurable parameters |
| `POST` | `/pipeline/reset` | Clear alert state and telemetry buffers |
| `POST` | `/pipeline/stop` | Signal an active replay or simulation to stop |
| `GET` | `/pipeline/metrics` | Real-time pipeline throughput and latency statistics |
| `POST` | `/api/ai/explain-alert` | Generate a Claude advisory explanation for an alert |
| `WS` | `/ws/alerts` | Real-time alert streaming WebSocket |

---

## Project Structure

```
sih-unidirectional-threat-detection/
├── .env.example             # Template for API credentials & model config
├── docker-compose.yml       # Container orchestration for backend + dashboard
├── requirements.txt         # Full platform dependencies (including anthropic SDK)
├── requirements-sensor.txt  # Minimal headless sensor dependencies (<85 MB)
├── backend/
│   ├── app/
│   │   ├── ai/              # Claude Messages API integration (explainer + schemas)
│   │   ├── alerts/          # SecurityAlert_v2 engine & deduplication
│   │   ├── detectors/       # Behavioral detection engines (DDoS, port scan, DGA, C2, exfil)
│   │   ├── ingestion/       # PCAP & raw packet stream readers
│   │   ├── ml/              # Hybrid RF (ONNX) + Isolation Forest inference
│   │   ├── pipeline/        # Streaming orchestrator (gate + Welford flow tracker)
│   │   ├── telemetry/       # Zeek / Suricata log parsers & 54-D feature schema
│   │   └── main.py          # FastAPI application & WebSocket router
│   ├── models/
│   │   └── weights/         # random_forest_v2.0.onnx + scaler parameters
│   ├── tests/               # 100 automated pytest test cases
│   ├── run_controlled_scenarios.py
│   ├── run_pipeline_benchmark.py
│   └── run_sih_benchmark.py
├── dashboard/
│   ├── app.py               # Streamlit application layout and routing
│   ├── api_client.py        # Resilient HTTP client with in-process fallback
│   └── components/          # Overview, Alerts, Alert Details, Analytics, Governance
├── optimized/               # Modular reference implementations of pipeline components
│   ├── gate.py              # Fast behavioral screening gate (<1 µs)
│   ├── flow_tracker.py      # Welford O(1) statistical flow engine
│   ├── feature_pipeline.py  # Zero-copy contiguous 54-D feature buffer
│   ├── inference_engine.py  # Vectorized inlined Z-scaler
│   ├── fusion.py            # Threat fusion & IF escalation
│   └── onnx_converter.py    # scikit-learn to ONNX conversion pipeline
├── benchmarks/              # Microsecond profiling harnesses & raw results
├── reports/                 # Forensic & performance engineering reports
└── docs/                    # Technical architecture & compliance specifications
```

---

## Dependency Tiers

| Tier | Requirements File | Target | Footprint |
|:---|:---|:---|:---|
| **Core passive sensor** | `requirements-sensor.txt` | Headless data diode appliance | <85 MB (6 packages: `numpy`, `pydantic`, `onnxruntime`, `scikit-learn`, `joblib`, `dpkt`) |
| **Full SOC + management** | `requirements.txt` | Central SOC, dashboard, FastAPI, Claude integration | Standard deployment |

---

## License & Contact

MIT License.

NetSentinal — [netsentinal.dev](https://netsentinal.dev) · [getintouch@netsentinal.dev](mailto:getintouch@netsentinal.dev)
