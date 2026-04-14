
---

# Agentic Network Security Monitor

> An autonomous, multi-agent threat detection and response system implementing the ReAct (Reasoning and Acting) paradigm for real-time Security Operations Center (SOC) workflows.

---

## The Problem We Solved

Enterprise security teams are drowning. The average SOC analyst receives over **10,000 alerts per day**, of which the majority are false positives. Traditional Intrusion Detection Systems (IDS) are passive rule-engines — they match known signatures and emit alerts, but they do not reason, they do not remember, and they do not act. When a novel attack pattern emerges, they are blind to it. When the same attacker returns repeatedly, they treat each incident as if it never happened before.

The result: **alert fatigue, missed threats, and slow response times** — the exact conditions that enable breaches.

This project addresses that gap by building a system that thinks, remembers, and acts — autonomously.

---

## What We Built

A production-grade **five-agent autonomous security pipeline** that:

- **Observes** raw network traffic logs in real time
- **Detects** both known attack signatures and novel behavioral anomalies
- **Reasons** over accumulated attacker history to escalate repeat offenders
- **Acts** with policy-constrained autonomous responses — block, rate-limit, alert, or monitor
- **Learns** from each incident by writing to persistent memory, improving future decisions

All of this without a human in the loop per incident.

---

## System Architecture

```
Raw Network Logs
      │
      ▼
┌─────────────────┐     OBSERVE
│ MonitoringAgent │ ◄── Ingests feature vectors, triggers pipeline
└────────┬────────┘
         │
         ▼
┌─────────────────┐     THINK (Detect)
│ DetectionAgent  │ ◄── Rule-based signatures + Isolation Forest anomaly detection
└────────┬────────┘
         │
         ▼
┌─────────────────┐     THINK (Memory)
│ IncidentMemory  │ ◄── SQLite store, RepScore engine, IP history lookup
└────────┬────────┘
         │
         ▼
┌─────────────────┐     THINK (Triage)
│  TriageAgent    │ ◄── Priority severity chain + memory escalation
└────────┬────────┘
         │
         ▼
┌─────────────────┐     ACT
│ ResponseAgent   │ ◄── Policy-constrained autonomous response selection
└────────┬────────┘
         │
         ▼
   Incident Stored → SOC Dashboard
```

The pipeline implements the **ReAct (Reasoning and Acting)** agentic paradigm — every incident goes through a full Think-Act-Observe cycle before a response is committed.

---

## Why This Architecture

| Design Decision | Rationale |
|---|---|
| Multi-agent decomposition | Separation of concerns — each agent has a single responsibility, making the system modular, testable, and extensible |
| Hybrid detection (rules + ML) | Rules give zero-FP precision on known threats; Isolation Forest catches novel behavioral anomalies invisible to signatures |
| Deterministic reasoning engine | Lambda-based severity chain over LLM prompting — microsecond latency, fully reproducible, auditable decisions |
| Persistent SQLite memory | Structured IP history lookup — key-value pattern, no need for embedding-based vector search |
| Policy engine with hard constraints | RFC-1918 CIDR guard and confidence floors prevent the probabilistic model from autonomously blocking internal infrastructure |
| ReAct workflow | Explicit OBSERVE → THINK → ACT cycle makes agent reasoning transparent, debuggable, and aligned with SOC operational requirements |

---

## Tech Stack

| Layer | Technology | Purpose |
|---|---|---|
| Agent Framework | Python custom BaseAgent hierarchy | Multi-agent orchestration |
| Anomaly Detection | Isolation Forest scikit-learn | Unsupervised behavioral anomaly detection |
| Feature Engineering | pandas numpy | Time-windowed IP behavioral feature extraction |
| Persistent Memory | SQLite | Incident storage reputation scoring |
| Policy Engine | JSON-configured rule loader | Hard constraint enforcement |
| Dashboard | Streamlit + Plotly | Real-time SOC visualization |
| Data Pipeline | CSV ingestion to feature extraction to detection to triage to response | End-to-end log processing |

---

## Detection Engine

### Rule-Based Layer

Five signature detectors with configurable thresholds loaded from config/detection_rules.json:

- **Port Scan** — 20 or more unique ports per 60-second window
- **Brute Force** — 5 or more failed logins per 300-second window
- **DDoS** — 100 or more connections or 10MB or more per 60-second window
- **Suspicious Ports** — access to known malicious port numbers

### Anomaly Layer

Isolation Forest trained on 10,000-record normal traffic baseline. Six-dimensional behavioral feature space: unique_ports, connection_count, total_bytes, failed_logins, connection_rate, port_diversity.

Confidence conversion via sigmoid transformation: confidence = 1 divided by (1 + e to the power of score)

### Fusion Logic

Detections merged on (source_ip, timestamp) composite key. threat_types = set union of both layers. confidence = max of both layers.

---

## Severity Triage

Priority-ordered reasoning chain evaluated top-down:

- **CRITICAL** — ddos or brute_force in threat_types AND confidence >= 0.9
- **HIGH** — 2 or more distinct threat types OR confidence >= 0.75
- **MEDIUM** — confidence >= 0.6
- **LOW** — fallback

**Memory escalation:** IPs with prior incident history are escalated one tier. low becomes medium, medium becomes high. This enables the system to treat persistent attackers more aggressively over time.

**Reputation Score:** RepScore = max(0, 100 minus (N times 10) minus (mean_confidence times 20)). Lower scores indicate higher risk.

---

## Results

Evaluated on 18,217 raw network log records yielding 9,684 feature vectors after time-window aggregation.

### Component Performance

| Component | Detected | Critical | FPR% | ms/incident |
|---|---|---|---|---|
| Rule-based only | 96 | 9 | 0.0% | 2.28 |
| Isolation Forest only | 1,257 | 0 | 100.0% | 0.97 |
| Full hybrid system | 1,257 | 9 | 92.4% | 0.98 |

### Ablation Study

| Condition | Detected | Critical | FPR% |
|---|---|---|---|
| A — Full system rule + IF + memory | 1,257 | 9 | 92.4% |
| B — No Isolation Forest | 96 | 9 | 0.0% |
| C — No memory escalation | 1,257 | 9 | 92.4% |
| D — No rules anomaly only | 1,257 | 0 | 100.0% |

### Contamination Tuning

| Contamination | Total | Critical | FPR% |
|---|---|---|---|
| 0.05 optimal | 748 | 9 | 87.2% |
| 0.10 default | 1,257 | 9 | 92.4% |
| 0.15 | 1,722 | 9 | 94.4% |

**Key finding:** Removing Isolation Forest reduces detection coverage by 92.4%. Removing rule-based labels eliminates all critical and high classifications. Neither layer alone is sufficient — the fusion is what makes the system work.

---

## Real-World Impact

| Problem | How This System Addresses It |
|---|---|
| Alert fatigue | Severity-differentiated triage routes only critical and high incidents to immediate SOC attention |
| Novel threat blindness | Isolation Forest detects behavioral anomalies outside known signature space |
| Stateless detection | Persistent memory escalates repeat offenders — the system gets smarter as attackers persist |
| False blocks on internal infrastructure | PolicyEngine CIDR guard hard-routes all RFC-1918 IPs to monitor regardless of anomaly score |
| Slow manual response | Sub-millisecond autonomous response selection — 0.98ms mean per incident |
| Non-transparent decisions | Full OBSERVE THINK ACT audit trail logged per cycle |

---

## Project Structure

```
agentic-network-security/
├── src/
│   ├── agents.py               # BaseAgent, MonitoringAgent, DetectionAgent,
│   │                           # TriageAgent, ResponseAgent, AgentOrchestrator
│   ├── detection_engine.py     # ThreatDetector: rule-based + Isolation Forest + fusion
│   ├── incident_memory.py      # IncidentMemory: SQLite store + RepScore engine
│   ├── policy_engine.py        # PolicyEngine: policy.json loader + action validation
│   ├── security_monitor.py     # AgenticSecurityMonitor: main pipeline runner
│   ├── data_ingestion.py       # LogIngester: CSV log loader
│   ├── feature_engineering.py  # FeatureExtractor: time-window aggregation
│   └── main.py                 # Streamlit dashboard entry point
├── dashboard/
│   └── streamlit_app.py        # SOC dashboard: KPI cards, log-scale charts, incident table
├── tests/
│   ├── ablation_study.py       # Four-condition ablation across detection components
│   ├── contamination_search.py # Grid search over IF contamination parameter
│   └── evaluation.py           # End-to-end evaluation pipeline
├── config/
│   ├── detection_rules.json    # Rule thresholds: port_scan, brute_force, ddos
│   └── policies.json           # Response policies, CIDR guards, confidence floors
├── data/
│   ├── raw_logs/               # network_logs.csv, normal_traffic.csv
│   ├── ablation_results.json   # Ablation study output
│   └── contamination_results.json
└── requirements.txt
```

---

## How to Run

### Prerequisites

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### Run the Pipeline

```bash
cd src
python security_monitor.py
```

### Run the SOC Dashboard

```bash
streamlit run dashboard/streamlit_app.py
```

### Run Ablation Study

```bash
python tests/ablation_study.py
```

### Run Contamination Grid Search

```bash
python tests/contamination_search.py
```

---

## Academic Context

This project was developed for CIS 600: Applied Agentic AI Systems at Syracuse University. It demonstrates the application of multi-agent agentic workflows to a real-world cybersecurity problem, grounded in the ReAct paradigm and evaluated through rigorous ablation and hyperparameter studies.

---

Built with Python · scikit-learn · SQLite · Streamlit · Plotly

---
