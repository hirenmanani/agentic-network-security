# src/data_ingestion.py
import pandas as pd
import json
import glob
from datetime import datetime
from typing import List, Dict
import logging

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class LogIngester:
    """Handles ingestion and normalization of network logs"""

    def __init__(self):
        self.required_fields = [
            'timestamp', 'source_ip', 'dest_ip',
            'port', 'protocol', 'bytes'
        ]

    def load_csv_logs(self, filepath: str) -> pd.DataFrame:
        """Load logs from CSV file"""
        try:
            df = pd.read_csv(filepath)
            logger.info(f"Loaded {len(df)} records from {filepath}")
            return self._normalize_schema(df)
        except Exception as e:
            logger.error(f"Error loading CSV: {e}")
            return pd.DataFrame()

    def load_json_logs(self, filepath: str) -> pd.DataFrame:
        """Load logs from JSON file"""
        try:
            with open(filepath, 'r') as f:
                data = json.load(f)
            df = pd.DataFrame(data)
            logger.info(f"Loaded {len(df)} records from {filepath}")
            return self._normalize_schema(df)
        except Exception as e:
            logger.error(f"Error loading JSON: {e}")
            return pd.DataFrame()

    def _normalize_schema(self, df: pd.DataFrame) -> pd.DataFrame:
        """Normalize different log formats to standard schema"""
        # Convert timestamp to datetime
        if 'timestamp' in df.columns:
            df['timestamp'] = pd.to_datetime(df['timestamp'])

        # Handle different field naming conventions
        field_mappings = {
            'src_ip': 'source_ip',
            'srcip': 'source_ip',
            'dst_ip': 'dest_ip',
            'dstip': 'dest_ip',
            'dest_port': 'port',
            'dport': 'port',
            'proto': 'protocol'
        }

        df = df.rename(columns=field_mappings)

        # Add missing fields with defaults
        if 'event_type' not in df.columns:
            df['event_type'] = 'connection'

        if 'failed_login' not in df.columns:
            df['failed_login'] = 0

        if 'bytes' not in df.columns:
            df['bytes'] = 0

        return df

    def load_multiple_logs(self, directory: str, pattern: str = "*.csv") -> pd.DataFrame:
        """Load and combine multiple log files"""
        files = glob.glob(f"{directory}/{pattern}")
        dfs = []

        for file in files:
            if file.endswith('.csv'):
                df = self.load_csv_logs(file)
            elif file.endswith('.json'):
                df = self.load_json_logs(file)
            else:
                continue

            if not df.empty:
                dfs.append(df)

        if dfs:
            combined = pd.concat(dfs, ignore_index=True)
            logger.info(
                f"Combined {len(combined)} total records from {len(files)} files")
            return combined

        return pd.DataFrame()
