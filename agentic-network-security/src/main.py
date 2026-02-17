import sys
import logging
from pathlib import Path
import os

# Internal module imports
from data_ingestion import LogIngester
from feature_engineering import FeatureExtractor
from detection_engine import ThreatDetector
from policy_engine import PolicyEngine
from incident_memory import IncidentMemory
from response_simulator import ResponseSimulator
from agents import AgentOrchestrator

# Ensure data directory exists for logs
os.makedirs('data', exist_ok=True)

# Configure logging
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
    """Main application class for the Agentic Network Security Monitor"""

    def __init__(self):
        # Anchor the project root by searching for the 'config' directory
        current_file = Path(__file__).resolve()
        root = current_file.parent

        while root != root.parent:
            if (root / 'config').exists():
                self.project_root = root
                break
            root = root.parent
        else:
            self.project_root = Path.cwd()

        # Define absolute paths for configuration and data
        config_path = self.project_root / 'config' / 'detection_rules.json'
        policy_path = self.project_root / 'config' / 'policies.json'
        db_path = self.project_root / 'data' / 'incidents.db'

        logger.info(f"Actual System Root Found: {self.project_root}")

        if not config_path.exists():
            logger.error(f"CRITICAL: File does not exist at {config_path}")
            sys.exit(1)

        # Initialize core components
        self.ingester = LogIngester()
        self.feature_extractor = FeatureExtractor(time_window=60)
        self.detector = ThreatDetector(config_path=str(config_path))
        self.policy_engine = PolicyEngine(config_path=str(policy_path))
        self.memory_manager = IncidentMemory(db_path=str(db_path))
        self.response_simulator = ResponseSimulator()

        # Initialize the LangGraph-powered orchestrator
        self.orchestrator = AgentOrchestrator(
            self.detector,
            self.policy_engine,
            self.memory_manager
        )
        logger.info("System successfully initialized.")

    def train_anomaly_detector(self, normal_traffic_path: str):
        """
        Loads normal traffic logs and trains the Isolation Forest or 
        anomaly detection model within the ThreatDetector.
        """
        logger.info(f"Training anomaly detector on {normal_traffic_path}")

        # 1. Ingest normal data
        abs_path = self.project_root / normal_traffic_path
        df = self.ingester.load_csv_logs(str(abs_path))

        if df.empty:
            logger.error("No data loaded for training. Check your CSV path.")
            return

        # 2. Extract features (Numerical representation for the ML model)
        features = self.feature_extractor.extract_features(df)

        # 3. Fit the model
        self.detector.train_anomaly_detector(features)

        logger.info("Anomaly detector training complete.")

    def process_logs(self, log_path: str):
        """Processes logs through the detection and agentic response pipeline"""
        abs_log_path = self.project_root / log_path
        logger.info(f"Processing: {abs_log_path}")

        # Ingestion
        df = self.ingester.load_csv_logs(str(abs_log_path))
        if df.empty:
            logger.warning("No logs found to process.")
            return []

        # Feature Engineering
        features = self.feature_extractor.extract_features(df)

        # Agentic Pipeline (Triage -> Analysis -> Response)
        incidents = self.orchestrator.process_logs(features)

        # Execute simulated responses (e.g., blocking IPs)
        for incident in incidents:
            self.response_simulator.execute_response(incident)

        if incidents:
            report = self.response_simulator.generate_report(incidents)
            print("\n" + report)

        return incidents

    def get_statistics(self):
        """Retrieves and prints historical incident data from Memory Manager"""
        stats = self.memory_manager.get_statistics()
        print(f"\nTotal Incidents Detected: {stats.get('total_incidents', 0)}")

    def shutdown(self):
        """Gracefully closes database connections"""
        self.memory_manager.close()
        logger.info("System shutdown complete.")


def main():
    monitor = AgenticSecurityMonitor()

    # UNCOMMENT THIS so the agents can find the 426 threats instead of just 96
    monitor.train_anomaly_detector('data/raw_logs/normal_traffic.csv')

    monitor.process_logs('data/raw_logs/network_logs.csv')
    monitor.get_statistics()
    monitor.shutdown()


if __name__ == "__main__":
    main()
