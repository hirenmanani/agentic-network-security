import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from pathlib import Path
import sys


def verify_and_visualize_dataset():
    """Verify dataset quality and create visualizations with defensive column checks"""

    # Use the nested path identified in your previous terminal logs
    data_dir = Path('data/raw_logs')
    file_path = data_dir / 'test_data_labeled.csv'

    print("="*80)
    print("DATASET VERIFICATION AND VISUALIZATION")
    print("="*80 + "\n")

    if not file_path.exists():
        print(f"Error: {file_path} not found. Run tests/evaluation.py first.")
        return

    # Load complete dataset
    df = pd.read_csv(file_path)
    df['timestamp'] = pd.to_datetime(df['timestamp'])

    print(f"Dataset loaded: {len(df)} records\n")

    # 1. Basic statistics
    print("1. BASIC STATISTICS")
    print("-" * 40)
    print(f"Time range: {df['timestamp'].min()} to {df['timestamp'].max()}")
    print(f"Unique source IPs: {df['source_ip'].nunique()}")
    print(f"Unique destination IPs: {df['dest_ip'].nunique()}")
    if 'protocol' in df.columns:
        print(f"Protocols: {df['protocol'].unique()}")
    print()

    # 2. Attack distribution
    print("2. ATTACK TYPE DISTRIBUTION")
    print("-" * 40)
    if 'event_type' in df.columns:
        print(df['event_type'].value_counts())
    elif 'attack_type' in df.columns:
        print(df['attack_type'].value_counts())
    print()

    # 3. Label distribution
    print("3. LABEL DISTRIBUTION")
    print("-" * 40)
    if 'label' in df.columns:
        benign_count = (df['label'] == 0).sum()
        malicious_count = (df['label'] == 1).sum()
        print(f"Benign (0): {benign_count} ({benign_count/len(df)*100:.2f}%)")
        print(
            f"Malicious (1): {malicious_count} ({malicious_count/len(df)*100:.2f}%)")
    print()

    # 4. Feature statistics
    print("4. FEATURE STATISTICS")
    print("-" * 40)
    # Only describe columns that actually exist in your CSV
    potential_features = ['bytes', 'packets', 'duration', 'port']
    available_features = [
        col for col in potential_features if col in df.columns]

    if available_features:
        print(df[available_features].describe())
    else:
        print("No numerical feature columns found for description.")
    print()

    # 5. Data Quality Check
    print("5. DATA QUALITY CHECK")
    print("-" * 40)
    missing = df.isnull().sum()
    print("Missing values:")
    print(missing[missing > 0] if missing.sum() > 0 else "No missing values ✓")
    print()

    # 6. Create Visualizations
    print("6. CREATING VISUALIZATIONS...")
    print("-" * 40)

    # Set style for better looking plots
    sns.set_theme(style="whitegrid")
    fig, axes = plt.subplots(2, 3, figsize=(18, 10))
    fig.suptitle('Network Security Dataset Analysis',
                 fontsize=16, fontweight='bold')

    # Plot 1: Attack type distribution (using event_type or attack_type)
    type_col = 'attack_type' if 'attack_type' in df.columns else 'event_type'
    if type_col in df.columns:
        counts = df[type_col].value_counts()
        axes[0, 0].bar(range(len(counts)), counts.values, color='skyblue')
        axes[0, 0].set_xticks(range(len(counts)))
        axes[0, 0].set_xticklabels(counts.index, rotation=45, ha='right')
        axes[0, 0].set_title(
            f'{type_col.replace("_", " ").title()} Distribution')

    # Plot 2: Protocol distribution
    if 'protocol' in df.columns:
        protocol_counts = df['protocol'].value_counts()
        axes[0, 1].pie(protocol_counts.values,
                       labels=protocol_counts.index, autopct='%1.1f%%')
        axes[0, 1].set_title('Protocol Distribution')

    # Plot 3: Bytes distribution
    if 'bytes' in df.columns:
        axes[0, 2].hist(df[df['bytes'] > 0]['bytes'], bins=50,
                        log=True, color='green', alpha=0.7)
        axes[0, 2].set_title('Bytes Distribution (log scale)')
        axes[0, 2].set_xlabel('Bytes')

    # Plot 4: Timeline
    df_hourly = df.set_index('timestamp').resample('H').size()
    axes[1, 0].plot(df_hourly.index, df_hourly.values,
                    marker='o', linestyle='-')
    axes[1, 0].set_title('Traffic Over Time (Hourly)')
    axes[1, 0].tick_params(axis='x', rotation=45)

    # Plot 5: Port distribution
    if 'port' in df.columns:
        top_ports = df['port'].value_counts().head(15)
        axes[1, 1].barh(range(len(top_ports)),
                        top_ports.values, color='salmon')
        axes[1, 1].set_yticks(range(len(top_ports)))
        axes[1, 1].set_yticklabels(top_ports.index)
        axes[1, 1].set_title('Top 15 Ports')

    # Plot 6: Average Bytes by Label
    if 'label' in df.columns and 'bytes' in df.columns:
        avg_bytes = df.groupby('label')['bytes'].mean()
        axes[1, 2].bar(['Benign', 'Malicious'],
                       avg_bytes.values, color=['green', 'red'])
        axes[1, 2].set_title('Avg Bytes: Benign vs Malicious')

    plt.tight_layout(rect=[0, 0.03, 1, 0.95])
    plot_path = data_dir / 'dataset_visualization.png'
    plt.savefig(plot_path, dpi=300)
    print(f"✓ Saved visualization: {plot_path}")

    # 7. Sample records
    print("\n7. SAMPLE RECORDS")
    print("-" * 40)
    sample_cols = [c for c in ['timestamp', 'source_ip',
                               'dest_ip', 'port', 'bytes', 'label'] if c in df.columns]
    print(df[sample_cols].head(5).to_string(index=False))

    print("\n" + "="*80)
    print("VERIFICATION COMPLETE ✓")
    print("="*80)


if __name__ == "__main__":
    verify_and_visualize_dataset()
