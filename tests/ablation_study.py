import sys, os, json, time
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


def fresh(config_path, db_name):
    db = str(ROOT / 'data' / db_name)
    if os.path.exists(db):
        os.remove(db)
    return (LogIngester(),
            FeatureExtractor(time_window=60),
            ThreatDetector(config_path=config_path),
            PolicyEngine(config_path=POLICY),
            IncidentMemory(db_path=db))


def train_if(detector, ingester, extractor, c=0.1):
    df = ingester.load_csv_logs(NORMAL)
    X  = extractor.extract_features(df)[FCOLS].fillna(0).astype(np.float64)
    detector.scaler = StandardScaler()
    Xs = detector.scaler.fit_transform(X)
    detector.anomaly_detector = IsolationForest(
        contamination=c, random_state=42, n_estimators=100)
    detector.anomaly_detector.fit(Xs)
    detector.trained = True


def summarise(name, incidents, elapsed):
    n    = len(incidents)
    sev  = {s: sum(1 for i in incidents if i['severity'] == s)
            for s in ['critical','high','medium','low']}
    acts = {a: sum(1 for i in incidents if i['response']['action'] == a)
            for a in ['block','rate_limit','alert','monitor']}
    fp   = sum(1 for i in incidents
               if i['severity'] == 'medium'
               and set(i.get('threat_types', [])) == {'anomaly'})
    ms   = round((elapsed / n * 1000) if n else 0, 2)
    return {'condition': name, 'detected': n, **sev, **acts,
            'fp_proxy': fp,
            'fpr_pct': round(fp / n * 100, 1) if n else 0,
            'latency_ms': ms, 'total_s': round(elapsed, 2)}


def run(name, use_anomaly, use_memory, config_path, db_name):
    print(f"\n{'='*55}\nCONDITION: {name}\n{'='*55}")
    ingester, extractor, detector, policy, memory = fresh(config_path, db_name)
    if use_anomaly:
        train_if(detector, ingester, extractor)
        print("  Anomaly detector : ENABLED")
    else:
        print("  Anomaly detector : DISABLED")
    if not use_memory:
        memory.get_ip_history = lambda ip: []
        print("  Memory escalation: DISABLED")
    orc      = AgentOrchestrator(detector, policy, memory)
    df       = LogIngester().load_csv_logs(TEST)
    features = FeatureExtractor(time_window=60).extract_features(df)
    t0       = time.time()
    incidents = orc.process_logs(features)
    elapsed  = time.time() - t0
    result   = summarise(name, incidents, elapsed)
    for k, v in result.items():
        if k != 'condition':
            print(f"  {k:<22}: {v}")
    memory.close()
    return result


def make_zeroed():
    z = {"port_scan":       {"enabled": False, "threshold": 9999, "time_window": 60},
         "brute_force":     {"enabled": False, "threshold": 9999, "time_window": 300},
         "ddos":            {"enabled": False, "connection_threshold": 9999999,
                             "bytes_threshold": 9999999999, "time_window": 60},
         "suspicious_port": {"enabled": False, "ports": []}}
    p = ROOT / 'config' / 'detection_rules_zeroed.json'
    with open(p, 'w') as f:
        json.dump(z, f, indent=2)
    return str(p)


if __name__ == "__main__":
    results = []
    results.append(run("A - Full system (rule+IF+memory)",
                       True,  True,  CONFIG, "ablation_A.db"))
    results.append(run("B - Rule-only (no Isolation Forest)",
                       False, True,  CONFIG, "ablation_B.db"))
    results.append(run("C - No memory escalation",
                       True,  False, CONFIG, "ablation_C.db"))
    results.append(run("D - Anomaly-only (no rules)",
                       True,  True,  make_zeroed(), "ablation_D.db"))

    print(f"\n\n{'='*80}")
    print("ABLATION STUDY — FINAL COMPARISON TABLE")
    print(f"{'='*80}")
    print(f"{'Condition':<38} {'Det':>5} {'Crit':>5} {'High':>5} "
          f"{'Med':>5} {'Blk':>5} {'FPR%':>6} {'ms/i':>8}")
    print('-'*80)
    for r in results:
        print(f"{r['condition']:<38} "
              f"{r['detected']:>5} "
              f"{r['critical']:>5} "
              f"{r['high']:>5} "
              f"{r['medium']:>5} "
              f"{r['block']:>5} "
              f"{r['fpr_pct']:>5}% "
              f"{r['latency_ms']:>7}ms")
    print('='*80)

    out = ROOT / 'data' / 'ablation_results.json'
    with open(out, 'w') as f:
        json.dump(results, f, indent=2)
    print(f"\nSaved to {out}")
