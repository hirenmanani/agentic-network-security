# src/feature_engineering.py
import pandas as pd
import numpy as np
from typing import Dict
import logging

logger = logging.getLogger(__name__)


class FeatureExtractor:
    """Extract behavioral features from network logs"""

    def __init__(self, time_window: int = 60):
        self.time_window = time_window  # seconds

    def extract_features(self, df: pd.DataFrame) -> pd.DataFrame:
        """Extract all features from log data"""
        if df.empty:
            return pd.DataFrame()

        # Ensure timestamp is datetime
        df['timestamp'] = pd.to_datetime(df['timestamp'])

        # Create time windows
        df['time_bin'] = df['timestamp'].dt.floor(f'{self.time_window}s')

        # Group by source IP and time window
        features = df.groupby(['source_ip', 'time_bin']).agg({
            'dest_ip': 'nunique',
            'port': ['nunique', 'count'],
            'bytes': 'sum',
            'protocol': lambda x: x.mode()[0] if len(x) > 0 else 'unknown',
            'failed_login': 'sum',
            'timestamp': ['min', 'max']
        }).reset_index()

        # Flatten column names
        features.columns = [
            'source_ip', 'time_bin',
            'unique_dest_ips', 'unique_ports', 'connection_count',
            'total_bytes', 'primary_protocol', 'failed_logins',
            'window_start', 'window_end'
        ]

        # Calculate connection rate
        features['connection_rate'] = features['connection_count'] / \
            self.time_window

        # Calculate average bytes per connection
        features['avg_bytes_per_conn'] = features['total_bytes'] / \
            features['connection_count']

        # Add port diversity metric
        features['port_diversity'] = features['unique_ports'] / \
            features['connection_count']

        logger.info(
            f"Extracted features for {len(features)} IP-window combinations")

        return features

    def extract_ip_history_features(self, df: pd.DataFrame, ip: str) -> Dict:
        """Extract historical features for a specific IP"""
        ip_data = df[df['source_ip'] == ip]

        if ip_data.empty:
            return {}

        features = {
            'first_seen': ip_data['timestamp'].min(),
            'last_seen': ip_data['timestamp'].max(),
            'total_connections': len(ip_data),
            'unique_destinations': ip_data['dest_ip'].nunique(),
            'total_bytes': ip_data['bytes'].sum(),
            'protocols_used': ip_data['protocol'].unique().tolist(),
            'ports_accessed': ip_data['port'].unique().tolist(),
            'total_failed_logins': ip_data['failed_login'].sum()
        }

        return features
