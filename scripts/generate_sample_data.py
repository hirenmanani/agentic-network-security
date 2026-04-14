# scripts/generate_sample_dataset.py
import pandas as pd
import numpy as np
from datetime import datetime, timedelta
import random
import os


def generate_normal_traffic(n_records=10000):
    """Generate normal network traffic"""
    np.random.seed(42)

    # Internal IP ranges
    internal_ips = [f"192.168.1.{i}" for i in range(2, 50)]
    external_ips = [f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                    for _ in range(100)]

    # Common legitimate ports
    normal_ports = [80, 443, 22, 53, 25, 110, 143, 993, 995, 3306, 5432, 6379]

    protocols = ['TCP', 'UDP', 'ICMP']

    data = []
    start_time = datetime.now() - timedelta(hours=24)

    for i in range(n_records):
        timestamp = start_time + timedelta(seconds=random.randint(0, 86400))
        source_ip = random.choice(internal_ips)
        dest_ip = random.choice(external_ips)
        port = random.choice(normal_ports)
        protocol = random.choice(protocols)
        bytes_sent = random.randint(100, 50000)

        data.append({
            'timestamp': timestamp.isoformat(),
            'source_ip': source_ip,
            'dest_ip': dest_ip,
            'port': port,
            'protocol': protocol,
            'bytes': bytes_sent,
            'failed_login': 0,
            'event_type': 'connection'
        })

    df = pd.DataFrame(data)
    df = df.sort_values('timestamp')
    return df


def generate_attack_traffic(n_attacks=100):
    """Generate malicious traffic patterns"""
    np.random.seed(123)

    attack_ips = [f"{random.randint(50, 200)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(0, 255)}"
                  for _ in range(20)]
    target_ips = [f"192.168.1.{i}" for i in range(2, 10)]

    data = []
    start_time = datetime.now() - timedelta(hours=12)

    for i in range(n_attacks):
        attack_type = random.choice(['port_scan', 'brute_force', 'ddos'])
        attacker_ip = random.choice(attack_ips)
        target_ip = random.choice(target_ips)
        attack_time = start_time + timedelta(seconds=random.randint(0, 43200))

        if attack_type == 'port_scan':
            # Port scanning - many different ports in short time
            for _ in range(random.randint(25, 50)):
                data.append({
                    'timestamp': (attack_time + timedelta(seconds=random.randint(0, 60))).isoformat(),
                    'source_ip': attacker_ip,
                    'dest_ip': target_ip,
                    'port': random.randint(1, 65535),
                    'protocol': 'TCP',
                    'bytes': random.randint(50, 500),
                    'failed_login': 0,
                    'event_type': 'connection'
                })

        elif attack_type == 'brute_force':
            # Brute force - many failed logins
            for _ in range(random.randint(10, 20)):
                data.append({
                    'timestamp': (attack_time + timedelta(seconds=random.randint(0, 300))).isoformat(),
                    'source_ip': attacker_ip,
                    'dest_ip': target_ip,
                    'port': 22,  # SSH
                    'protocol': 'TCP',
                    'bytes': random.randint(100, 1000),
                    'failed_login': 1,
                    'event_type': 'auth_attempt'
                })

        else:  # ddos
            # DDoS - high connection rate
            for _ in range(random.randint(150, 300)):
                data.append({
                    'timestamp': (attack_time + timedelta(seconds=random.randint(0, 60))).isoformat(),
                    'source_ip': attacker_ip,
                    'dest_ip': target_ip,
                    'port': 80,
                    'protocol': 'TCP',
                    'bytes': random.randint(50, 5000),
                    'failed_login': 0,
                    'event_type': 'connection'
                })

    df = pd.DataFrame(data)
    df = df.sort_values('timestamp')
    return df


def main():
    """Generate and save sample datasets"""
    os.makedirs('data/raw_logs', exist_ok=True)

    # Generate normal traffic
    print("Generating normal traffic...")
    normal_df = generate_normal_traffic(10000)
    normal_df.to_csv('data/raw_logs/normal_traffic.csv', index=False)
    print(f"Saved {len(normal_df)} normal traffic records")

    # Generate attack traffic
    print("Generating attack traffic...")
    attack_df = generate_attack_traffic(100)
    attack_df.to_csv('data/raw_logs/attack_traffic.csv', index=False)
    print(f"Saved {len(attack_df)} attack records")

    # Combine for mixed dataset
    print("Creating mixed dataset...")
    mixed_df = pd.concat([normal_df, attack_df], ignore_index=True)
    mixed_df = mixed_df.sort_values('timestamp').reset_index(drop=True)
    mixed_df.to_csv('data/raw_logs/network_logs.csv', index=False)
    print(f"Saved {len(mixed_df)} total records to network_logs.csv")

    print("\nDataset generation complete!")
    print("Files created:")
    print("  - data/raw_logs/normal_traffic.csv (for training)")
    print("  - data/raw_logs/attack_traffic.csv (attacks only)")
    print("  - data/raw_logs/network_logs.csv (mixed, for testing)")


if __name__ == "__main__":
    main()
