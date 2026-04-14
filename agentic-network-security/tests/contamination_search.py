import sys, os, json
import numpy as np
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'src'))

from data_ingestion import LogIngester
from feature_engineering import FeatureExtractor
from detection_engine import ThreatDetector
from policy_engine import PolicyEngine
from incident_memory import IncidentMemory
from agents import AgentOrchestrator

ROOT   = Path(__file__).resolve().parent.parent
CONFIG = str(ROOT / 'config' / 'detection_rules.json')
POLICY = str(ROOT / 'config' / 'policies.json')
NORMAL = str(ROOT / 'data' / 'raw_logs' / 'normal_traffic.csv')
TEST   = str(ROOT / 'data' / 'raw_logs' / 'network_logs.csv')
FCOLS  = ['unique_ports','connection_count','total_bytes',
          'failed_logins','connection_rate','port_diversity']


def run_c(c):
    db = str(ROOT / 'data' / 'cont_temp.db')
    if os.path.exists(db):
        os.remove(db)
    ingester  = LogIngester()
    extractor = FeatureExtractor(time_window=60)
    detector  = ThreatDetector(config_path=CONFIG)
    policy    = PolicyEngine(config_path=POLICY)
    memory    = IncidentMemory(db_path=db)
    df_n = ingester.load_csv_logs(NORMAL)
    X    = extractor.extract_features(df_n)[FCOLS].fillna(0).astype(np.float64)
    detector.scaler = StandardScaler()
    Xs   = detector.scaler.fit_transform(X)
    detector.anomaly_detector = IsolationForest(
        contamination=c, random_state=42, n_estimators=100)
    detector.anomaly_detector.fit(Xs)
    detector.trained = True
    orc      = AgentOrchestrator(detector, policy, memory)
    df_t     = ingester.load_csv_logs(TEST)
    features = extractor.extract_features(df_t)
    incidents = orc.process_logs(features)
    total    = len(incidents)
    critical = sum(1 for i in incidents if i['severity'] == 'critical')
    fp       = sum(1 for i in incidents
                   if i['severity'] == 'medium'
                   and set(i.get('threat_types', [])) == {'anomaly'})
    fpr      = round(fp / total * 100, 1) if total else 0
    memory.close()
    return {'contamination': c, 'total': total,
            'critical': critical, 'fp_proxy': fp, 'fpr_pct': fpr}


if __name__ == "__main__":
    values = [0.05, 0.08, 0.10, 0.12, 0.15]
    print("\nCONTAMINATION GRID SEARCH")
    print(f"{'Contam':>8} {'Total':>7} {'Critical':>9} "
          f"{'FP proxy':>9} {'FPR%':>6}")
    print('-'*48)
    results = []
    for c in values:
        r = run_c(c)
        results.append(r)
        print(f"{r['contamination']:>8.2f} "
              f"{r['total']:>7} "
              f"{r['critical']:>9} "
              f"{r['fp_proxy']:>9} "
              f"{r['fpr_pct']:>5}%")
    out = ROOT / 'data' / 'contamination_results.json'
    with open(out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out}")
    print("Pick: lowest FPR% where critical stays same as c=0.10")
