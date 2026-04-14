import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import os


def verify_and_visualize_dataset():
    """Verify dataset quality and create visualizations with defensive column checks"""

    # 1. Path Setup: Relative to project root
    # Adjusting for your nested 'agentic-network-security' folder structure
    current_dir = Path(__file__).resolve().parent
    project_root = current_dir.parent
    data_dir = project_root / 'data' / 'raw_logs'
    file_path = data_dir / 'test_data_labeled.csv'

    print("="*80)
    print("DATASET VERIFICATION AND VISUALIZATION")
    print("="*80 + "\n")

    if not file_path.exists():
        print(f"Error: {file_path} not found. Run tests/evaluation.py first.")
        return

    # 2. Load Dataset
    df = pd.read_csv(file_path)
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')

    print(f"Dataset loaded: {len(df)} records\n")

    # 3. Basic Statistics
    print("1. BASIC STATISTICS")
    print("-" * 40)
    print(f"Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    print(f"Unique source IPs: {df['source_ip'].nunique()}")

    # Check for labels (0 for benign, 1 for malicious)
    if 'label' in df.columns:
        malicious_count = (df['label'] == 1).sum()
        print(f"Total Malicious Events Identified: {malicious_count}")

    # 4. Create Visualizations
    print("\n2. GENERATING ANALYTICS...")
    sns.set_theme(style="whitegrid")
    fig, axes = plt.subplots(2, 2, figsize=(15, 10))
    fig.suptitle('Agentic Security Dataset Profile',
                 fontsize=16, fontweight='bold')

    # Plot A: Traffic over time (Hourly)
    df_hourly = df.set_index('timestamp').resample('H').size()
    axes[0, 0].plot(df_hourly.index, df_hourly.values,
                    marker='o', color='blue')
    axes[0, 0].set_title('Log Frequency Over Time')
    axes[0, 0].tick_params(axis='x', rotation=45)

    # Plot B: Bytes Distribution
    if 'bytes' in df.columns:
        sns.boxplot(data=df, x='label', y='bytes',
                    ax=axes[0, 1], palette='viridis')
        axes[0, 1].set_title('Byte Volume: Benign vs. Malicious')

    # Plot C: Protocol Distribution
    if 'protocol' in df.columns:
        protocol_counts = df['protocol'].value_counts()
        axes[1, 0].pie(protocol_counts.values,
                       labels=protocol_counts.index, autopct='%1.1f%%')
        axes[1, 0].set_title('Protocol Distribution')

    # Plot D: Top Attacking IPs
    if 'label' in df.columns:
        malicious_ips = df[df['label'] ==
                           1]['source_ip'].value_counts().head(10)
        axes[1, 1].barh(malicious_ips.index, malicious_ips.values, color='red')
        axes[1, 1].set_title('Top 10 Malicious Source IPs')

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])

    # Save the output visualization
    output_path = data_dir / 'dataset_visualization.png'
    plt.savefig(output_path, dpi=300)
    print(f"✓ Saved visualization to: {output_path}")


if __name__ == "__main__":
    verify_and_visualize_dataset()
