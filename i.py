import os

structure = [
    "data/raw_logs/", "data/processed/", "data/incidents.db",
    "src/data_ingestion.py", "src/feature_engineering.py", "src/detection_engine.py",
    "src/agents.py", "src/policy_engine.py", "src/incident_memory.py",
    "src/response_simulator.py", "src/main.py",
    "config/policies.json", "config/detection_rules.json",
    "dashboard/streamlit_app.py", "tests/evaluation.py", "requirements.txt"
]

for path in structure:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not path.endswith('/'):
        with open(path, 'w') as f:
            pass
