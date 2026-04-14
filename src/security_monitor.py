import sys
import logging
from pathlib import Path
import os

from data_ingestion import LogIngester
from feature_engineering import FeatureExtractor
from detection_engine import ThreatDetector
from policy_engine import PolicyEngine
from incident_memory import IncidentMemory
from response_simulator import ResponseSimulator
from agents import AgentOrchestrator

os.makedirs('data', exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('data/security_monitor.log'),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger(__name__)


class AgenticSecurityMonitor:

    def __init__(self):
        current_file = Path(__file__).resolve()
        root = current_file.parent
        while root != root.parent:
            if (root / 'config').exists():
                self.project_root = root
                break
            root = root.parent
        else:
            self.project_root = Path.cwd()

        config_path = self.project_root / 'config' / 'detection_rules.json'
        policy_path = self.project_root / 'config' / 'policies.json'
        db_path     = self.project_root / 'data' / 'incidents.db'

        logger.info(f"Project root: {self.project_root}")

        self.ingester          = LogIngester()
        self.feature_extractor = FeatureExtractor(time_window=60)
        self.detector          = ThreatDetector(config_path=str(config_path))
        self.policy_engine     = PolicyEngine(config_path=str(policy_path))
        self.memory_manager    = IncidentMemory(db_path=str(db_path))
        self.response_simulator = ResponseSimulator()
        self.orchestrator      = AgentOrchestrator(
            self.detector, self.policy_engine, self.memory_manager)

        logger.info("System initialized.")

    def train_anomaly_detector(self, normal_traffic_path: str):
        import time
        logger.info(f"Training anomaly detector on {normal_traffic_path}")
        abs_path = self.project_root / normal_traffic_path
        df = self.ingester.load_csv_logs(str(abs_path))
        if df.empty:
            logger.error("No data loaded for training.")
            return
        features = self.feature_extractor.extract_features(df)
        self.detector.train_anomaly_detector(features)
        logger.info("Anomaly detector training complete.")

    def process_logs(self, log_path: str):
        import time
        abs_log_path = self.project_root / log_path
        logger.info(f"Processing: {abs_log_path}")

        df = self.ingester.load_csv_logs(str(abs_log_path))
        if df.empty:
            logger.warning("No logs found.")
            return []

        features  = self.feature_extractor.extract_features(df)

        t0        = time.time()
        incidents = self.orchestrator.process_logs(features)
        elapsed   = time.time() - t0

        n = len(incidents) if incidents else 1
        print(f"\n{'='*50}")
        print(f"PIPELINE LATENCY REPORT")
        print(f"  Incidents processed : {len(incidents)}")
        print(f"  Total time          : {elapsed:.2f}s")
        print(f"  Mean per incident   : {elapsed/n*1000:.2f}ms")
        print(f"{'='*50}\n")

        for incident in incidents:
            self.response_simulator.execute_response(incident)

        if incidents:
            report = self.response_simulator.generate_report(incidents)
            print("\n" + report)

        return incidents

    def get_statistics(self):
        stats = self.memory_manager.get_statistics()
        print(f"\nTotal Incidents: {stats.get('total_incidents', 0)}")
        print(f"Unique IPs:      {stats.get('unique_ips', 0)}")

    def shutdown(self):
        self.memory_manager.close()
        logger.info("Shutdown complete.")


if __name__ == "__main__":
    monitor = AgenticSecurityMonitor()
    monitor.train_anomaly_detector('data/raw_logs/normal_traffic.csv')
    monitor.process_logs('data/raw_logs/network_logs.csv')
    monitor.get_statistics()
    monitor.shutdown()
