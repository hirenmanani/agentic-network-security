Agentic Network Security Monitor

An autonomous, multi-agent security orchestration system that leverages Machine Learning and persistent memory to detect, triage, and respond to network threats in real-time.
🎯 Project Vision

Traditional security systems often rely on static rules that fail against "zero-day" anomalies. This project implements a LangGraph-inspired multi-agent architecture that combines the precision of rule-based detection with the adaptability of an Isolation Forest ML model.
🛠️ The Tech Stack

    Language: Python 3.13

    Machine Learning: Scikit-learn (IsolationForest)

    Orchestration: Multi-agent pipeline (Monitoring, Detection, Triage, Response)

    Data Processing: Pandas, NumPy

    Memory/Persistence: SQLite3

    Visualization: Matplotlib, Seaborn

🚀 Milestones Achieved

We have successfully built a complete end-to-end security lifecycle:

    100% Recall Performance: The system successfully identified all malicious attacks within a test set of 10,217 records.

    Hybrid Detection Engine: Integrated both signature-based rules and an anomaly detector trained on a behavioral baseline of normal_traffic.csv.

    Persistent IP Reputation: Built an IncidentMemory layer that tracks IP history, calculating dynamic Reputation Scores to intelligently identify repeat offenders.

    Autonomous Policy Enforcement: Implemented a policy engine that protects critical internal ranges (e.g., 192.168.1.x) by defaulting to monitor actions for protected IPs.

🧠 Reasoning & Architecture
Why Multi-Agent?

Security is a multi-step reasoning process. By using specialized agents, we isolate concerns:

    Detection Agent: Focuses on statistical anomalies.

    Triage Agent: Contextualizes the threat by checking historical database records for repeat behavior.

    Response Agent: Executes actions (block, rate_limit, alert) based on a predefined policy.json.

Why Isolation Forest?

We used a contamination=0.1 setting to proactively flag the top 10% of unusual traffic. Our analysis shows that malicious traffic in this simulation typically has a lower byte count (probing) compared to the larger payloads of benign traffic.
📈 Data Insights

Based on our dataset_visualization.png:

    Protocol Distribution: 87% TCP traffic.

    Traffic Profile: Malicious connections are high-frequency but low-byte, characteristic of scanning and brute-force attempts.

🔮 Future Roadmap

    Precision Tuning: Refine the anomaly threshold to reduce the current False Positive Rate.

    Ablation Study: Quantify the improvement of agentic AI over traditional rule-only systems.

    Real-time Dashboard: Integrate a Streamlit interface to visualize incidents.db in real-time.

👨‍💻 Author

Hiren Manani

    MS in Computer Science, Syracuse University (Expected May 2026)
