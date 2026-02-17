# tests/evaluation.py
from main import AgenticSecurityMonitor
import json
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix
import numpy as np
import pandas as pd
import sys
sys.path.append('../src')


def create_labeled_test_data():
    """Create test data with ground truth labels"""
    # Load the attack traffic (we know these are malicious)
    attacks = pd.read_csv('../data/raw_logs/attack_traffic.csv')
    attacks['label'] = 1  # Malicious

    # Load normal traffic
    normal = pd.read_csv('../data/raw_logs/normal_traffic.csv')
    normal = normal.sample(n=min(2000, len(normal)))  # Sample subset
    normal['label'] = 0  # Benign

    # Combine
    test_data = pd.concat([attacks, normal], ignore_index=True)
    test_data = test_data.sample(frac=1).reset_index(drop=True)  # Shuffle

    return test_data


def evaluate_detection_performance():
    """Evaluate detection accuracy"""
    print("=" * 80)
    print("EVALUATION: Detection Performance")
    print("=" * 80)

    # Create test data
    test_data = create_labeled_test_data()
    test_data.to_csv('../data/raw_logs/test_data_labeled.csv', index=False)

    # Initialize system
    monitor = AgenticSecurityMonitor()

    # Train on normal traffic
    print("\nTraining anomaly detector...")
    monitor.train_anomaly_detector('../data/raw_logs/normal_traffic.csv')

    # Process test data
    print("\nProcessing test data...")

    # Save without labels for processing
    test_input = test_data.drop('label', axis=1)
    test_input.to_csv('../data/raw_logs/test_input.csv', index=False)

    incidents = monitor.process_logs('../data/raw_logs/test_input.csv')

    # Create predictions DataFrame
    detected_ips = set()
    for incident in incidents:
        detected_ips.add(incident['source_ip'])

    # Map detections back to original data
    test_data['predicted'] = test_data['source_ip'].apply(
        lambda ip: 1 if ip in detected_ips else 0
    )

    # Calculate metrics per unique IP
    ip_labels = test_data.groupby('source_ip')['label'].max()
    ip_predictions = test_data.groupby('source_ip')['predicted'].max()

    # Align indices
    common_ips = ip_labels.index.intersection(ip_predictions.index)
    y_true = ip_labels.loc[common_ips].values
    y_pred = ip_predictions.loc[common_ips].values

    # Calculate metrics
    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    # Confusion matrix
    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print("\nResults:")
    print(f"Precision: {precision:.3f}")
    print(f"Recall: {recall:.3f}")
    print(f"F1-Score: {f1:.3f}")
    print(f"False Positive Rate: {fpr:.3f}")
    print(f"\nConfusion Matrix:")
    print(f"  True Positives: {tp}")
    print(f"  False Positives: {fp}")
    print(f"  True Negatives: {tn}")
    print(f"  False Negatives: {fn}")

    # Save results
    results = {
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'false_positive_rate': float(fpr),
        'confusion_matrix': {
            'tp': int(tp),
            'fp': int(fp),
            'tn': int(tn),
            'fn': int(fn)
        }
    }

    with open('../data/evaluation_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to data/evaluation_results.json")

    monitor.shutdown()


def ablation_study():
    """Compare system with and without key components"""
    print("\n" + "=" * 80)
    print("ABLATION STUDY")
    print("=" * 80)

    # TODO: Implement comparison between:
    # 1. Full system (rules + anomaly + memory + agents)
    # 2. Rules only
    # 3. Rules + anomaly (no memory)
    # 4. Rules + memory (no anomaly)

    print("\nAblation study would compare:")
    print("  - Full system")
    print("  - Rules only")
    print("  - No memory")
    print("  - No anomaly detection")
    print("\n(Implementation left as exercise)")


if __name__ == "__main__":
    evaluate_detection_performance()
    # ablation_study()
