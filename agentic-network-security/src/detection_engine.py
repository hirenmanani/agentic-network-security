# src/detection_engine.py
import pandas as pd
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from typing import List, Dict, Tuple
import json
import logging

logger = logging.getLogger(__name__)


class ThreatDetector:
    """Multi-layer threat detection engine"""

    def __init__(self, config_path: str = 'config/detection_rules.json'):
        import os
        print(f"DEBUG: Looking for config at: {os.path.abspath(config_path)}")

        if not os.path.exists(config_path) or os.path.getsize(config_path) == 0:
            raise ValueError(
                f"Config file is missing or empty at {config_path}")

        with open(config_path, 'r') as f:
            self.rules = json.load(f)

        self.anomaly_detector = None
        self.scaler = StandardScaler()
        self.trained = False

    def detect_rule_based(self, features: pd.DataFrame) -> List[Dict]:
        """Rule-based threat detection"""
        threats = []

        for idx, row in features.iterrows():
            detected_threats = []
            confidence_scores = []

            # Port Scanning Detection
            if self.rules['port_scan']['enabled']:
                if row['unique_ports'] >= self.rules['port_scan']['threshold']:
                    detected_threats.append('port_scan')
                    confidence = min(
                        row['unique_ports'] / (self.rules['port_scan']['threshold'] * 2), 1.0)
                    confidence_scores.append(confidence)

            # Brute Force Detection
            if self.rules['brute_force']['enabled']:
                if row['failed_logins'] >= self.rules['brute_force']['threshold']:
                    detected_threats.append('brute_force')
                    confidence = min(
                        row['failed_logins'] / (self.rules['brute_force']['threshold'] * 2), 1.0)
                    confidence_scores.append(confidence)

            # DDoS Detection
            if self.rules['ddos']['enabled']:
                if (row['connection_count'] >= self.rules['ddos']['connection_threshold'] or
                        row['total_bytes'] >= self.rules['ddos']['bytes_threshold']):
                    detected_threats.append('ddos')
                    conn_conf = min(
                        row['connection_count'] / (self.rules['ddos']['connection_threshold'] * 2), 1.0)
                    bytes_conf = min(
                        row['total_bytes'] / (self.rules['ddos']['bytes_threshold'] * 2), 1.0)
                    confidence_scores.append(max(conn_conf, bytes_conf))

            # If threats detected, create threat record
            if detected_threats:
                avg_confidence = np.mean(confidence_scores)

                threat = {
                    'source_ip': row['source_ip'],
                    'timestamp': row['time_bin'],
                    'threat_types': detected_threats,
                    'confidence': float(avg_confidence),
                    'features': {
                        'unique_ports': int(row['unique_ports']),
                        'connection_count': int(row['connection_count']),
                        'total_bytes': int(row['total_bytes']),
                        'failed_logins': int(row['failed_logins']),
                        'connection_rate': float(row['connection_rate'])
                    },
                    'detection_method': 'rule_based'
                }

                threats.append(threat)

        logger.info(f"Rule-based detection found {len(threats)} threats")
        return threats

    def train_anomaly_detector(self, features: pd.DataFrame):
        """Train anomaly detection model on normal traffic"""
        feature_cols = ['unique_ports', 'connection_count', 'total_bytes',
                        'failed_logins', 'connection_rate', 'port_diversity']

        # Ensure numeric types for NumPy 2.x compatibility
        X = features[feature_cols].fillna(0).astype(np.float64)
        X_scaled = self.scaler.fit_transform(X)

        self.anomaly_detector = IsolationForest(
            contamination=0.1,
            random_state=42,
            n_estimators=100
        )

        self.anomaly_detector.fit(X_scaled)
        self.trained = True
        logger.info(f"Trained anomaly detector on {len(X)} samples")

    def detect_anomalies(self, features: pd.DataFrame) -> List[Dict]:
        """Anomaly-based threat detection"""
        if not self.trained:
            logger.warning(
                "Anomaly detector not trained. Skipping anomaly detection.")
            return []

        feature_cols = ['unique_ports', 'connection_count', 'total_bytes',
                        'failed_logins', 'connection_rate', 'port_diversity']

        X = features[feature_cols].fillna(0)
        X_scaled = self.scaler.transform(X)

        predictions = self.anomaly_detector.predict(X_scaled)
        anomaly_scores = self.anomaly_detector.score_samples(X_scaled)

        threats = []

        for idx, (pred, score) in enumerate(zip(predictions, anomaly_scores)):
            if pred == -1:  # Anomaly detected
                row = features.iloc[idx]

                # Convert anomaly score to confidence (0-1 range)
                confidence = 1 / (1 + np.exp(score))  # Sigmoid transformation

                threat = {
                    'source_ip': row['source_ip'],
                    'timestamp': row['time_bin'],
                    'threat_types': ['anomaly'],
                    'confidence': float(confidence),
                    'anomaly_score': float(score),
                    'features': {
                        'unique_ports': int(row['unique_ports']),
                        'connection_count': int(row['connection_count']),
                        'total_bytes': int(row['total_bytes']),
                        'failed_logins': int(row['failed_logins']),
                        'connection_rate': float(row['connection_rate'])
                    },
                    'detection_method': 'anomaly_based'
                }

                threats.append(threat)

        logger.info(f"Anomaly detection found {len(threats)} threats")
        return threats

    def combine_detections(self, rule_threats: List[Dict],
                           anomaly_threats: List[Dict]) -> List[Dict]:
        """Combine and deduplicate detections from both methods"""
        # Create a dictionary keyed by (ip, timestamp)
        combined = {}

        for threat in rule_threats + anomaly_threats:
            key = (threat['source_ip'], threat['timestamp'])

            if key not in combined:
                combined[key] = threat
            else:
                # Merge threat types and take max confidence
                existing = combined[key]
                existing['threat_types'] = list(set(
                    existing['threat_types'] + threat['threat_types']
                ))
                existing['confidence'] = max(
                    existing['confidence'], threat['confidence'])

                if 'anomaly_score' in threat:
                    existing['anomaly_score'] = threat['anomaly_score']

        return list(combined.values())
