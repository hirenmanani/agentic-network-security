🛡️ Agentic Network Security Monitor

Autonomous Threat Orchestration with ML-Driven Anomaly Detection
---
📖 Overview

Developed as part of the Applied Agentic-AI Systems (CIS 600) curriculum at Syracuse University, this project implements a state-of-the-art multi-agent framework for real-time network security. Unlike traditional SIEMs that rely on static signatures, this monitor utilizes an Isolation Forest model to detect zero-day anomalies and a Stateful Agentic Pipeline to execute autonomous responses.

--- 

🏗️ Architecture & Engineering Reasoning
1. Multi-Agent Orchestration (The "Reasoning" Layer)

We utilize a decentralized agent architecture to decompose the security lifecycle. This allows for modular scaling and independent logic updates:

Monitoring Agent: Handles high-throughput log ingestion and triggers the pipeline.

Detection Agent: A hybrid engine combining rule-based heuristics with an Isolation Forest ML model (set at contamination=0.1) to identify behavioral outliers.

Triage Agent: Contextualizes threats by querying a persistent SQLite memory layer to differentiate between first-time anomalies and repeat offenders.

Response Agent: An autonomous decision-maker that enforces a policy.json framework, applying actions like rate_limit, block, or monitor based on risk and IP reputation.

2. Stateful Memory & Reputation Scoring

A critical component for any Lead Data Engineer is data persistence. We implemented a SQLite-backed memory manager that:

Maintains a historical record of all incidents.

Calculates a dynamic Reputation Score (0−100) for every IP based on frequency and confidence of detected threats.

Ensures transactional integrity using a shared-connection pattern to prevent database locking during high-volume bursts.

--- 

📊 Performance & Data Insights

The system was validated against a labeled test set of 10,217 records, achieving a 1.0 Recall (100% Detection Rate) for all malicious payloads.

Key Findings from dataset_visualization.jpg:

Feature Variance: Malicious traffic in our simulation consistently exhibits lower byte counts (mean ≈2,000) compared to benign traffic (mean ≈25,000), identifying the "low-and-slow" probing characteristics of the simulated attacks.

Temporal Spikes: The agents successfully handled a massive traffic surge on Feb 17 at 03:00, triaging over 1,200 incidents without system degradation.

---

🛠️ Technical Stack

ML Core: Scikit-learn (Isolation Forest).

Data Engineering: Pandas, NumPy, JSON-based Policy Engines.

Persistence: SQLite3 with custom row factory for efficient querying.

Visualization: Matplotlib, Seaborn.

---

🔮 Roadmap

Precision Tuning: Iterating on the contamination hyperparameter to reduce false-positive rates below 20%.

Streamlit Dashboard: Building a real-time UI to visualize the incidents.db and agent reasoning chains.

Ablation Study: Quantifying the delta between "Agent-Lead" vs. "Heuristic-Only" detection performance.

---

🎓 Academic Context

Hiren Manani

Master of Science in Computer Science, Syracuse University (Expected May 2026)

Focus: Data Engineering, Software Development, and Applied AI
