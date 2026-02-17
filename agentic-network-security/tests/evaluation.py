import sys
import os
import json
from pathlib import Path
import numpy as np
import pandas as pd
from sklearn.metrics import precision_score, recall_score, f1_score, confusion_matrix

# --- PATH FIX START ---
# Get the absolute path of the project root (one level up from /tests)
PROJECT_ROOT = Path(__file__).resolve().parent.parent
# Add the 'src' directory to the Python path
sys.path.append(str(PROJECT_ROOT / "src"))
# --- PATH FIX END ---

# Now we can import from main.py and other src files
try:
    from main import AgenticSecurityMonitor
except ImportError as e:
    print(
        f"Error: Could not find 'main.py' in {PROJECT_ROOT}/src. Details: {e}")
    sys.exit(1)


def create_labeled_test_data():
    """Create test data with ground truth labels"""
    try:
        # Load the attack traffic
        attacks = pd.read_csv('data/raw_logs/attack_traffic.csv')
        attacks['label'] = 1  # Malicious

        # Load normal traffic
        normal = pd.read_csv('data/raw_logs/normal_traffic.csv')
        normal_subset = normal.sample(n=min(2000, len(normal)))
        normal_subset['label'] = 0  # Benign

        # Combine and shuffle
        test_data = pd.concat([attacks, normal_subset], ignore_index=True)
        test_data = test_data.sample(frac=1).reset_index(drop=True)
        return test_data
    except FileNotFoundError:
        print("Error: Base CSV files not found in data/raw_logs/. Run generate_sample_data.py first.")
        sys.exit(1)


def evaluate_detection_performance():
    """Evaluate detection accuracy"""
    print("=" * 80)
    print("EVALUATION: Detection Performance")
    print("=" * 80)

    # 1. Create test data
    test_data = create_labeled_test_data()
    test_data.to_csv('data/raw_logs/test_data_labeled.csv', index=False)

    # 2. Initialize system
    monitor = AgenticSecurityMonitor()

    # 3. Training
    print("\nTraining anomaly detector...")
    monitor.train_anomaly_detector('data/raw_logs/normal_traffic.csv')

    # 4. Processing
    print("\nProcessing test data through agents...")
    test_input = test_data.drop('label', axis=1)
    test_input_path = 'data/raw_logs/test_input.csv'
    test_input.to_csv(test_input_path, index=False)

    incidents = monitor.process_logs(test_input_path)

    # 5. Calculate Metrics
    detected_ips = {incident['source_ip'] for incident in incidents}
    test_data['predicted'] = test_data['source_ip'].apply(
        lambda ip: 1 if ip in detected_ips else 0
    )

    ip_labels = test_data.groupby('source_ip')['label'].max()
    ip_predictions = test_data.groupby('source_ip')['predicted'].max()

    common_ips = ip_labels.index.intersection(ip_predictions.index)
    y_true = ip_labels.loc[common_ips].values
    y_pred = ip_predictions.loc[common_ips].values

    precision = precision_score(y_true, y_pred, zero_division=0)
    recall = recall_score(y_true, y_pred, zero_division=0)
    f1 = f1_score(y_true, y_pred, zero_division=0)

    tn, fp, fn, tp = confusion_matrix(y_true, y_pred).ravel()
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    print("\nResults:")
    print(f"Precision: {precision:.3f}")
    print(f"Recall: {recall:.3f}")
    print(f"F1-Score: {f1:.3f}")
    print(f"False Positive Rate: {fpr:.3f}")
    print(f"\nConfusion Matrix:")
    print(f"  True Positives (Detected): {tp}")
    print(f"  False Positives (Mistakes): {fp}")
    print(f"  True Negatives (Correct Normal): {tn}")
    print(f"  False Negatives (Missed Attacks): {fn}")

    # 6. Save Results
    results = {
        'precision': float(precision),
        'recall': float(recall),
        'f1_score': float(f1),
        'false_positive_rate': float(fpr),
        'confusion_matrix': {'tp': int(tp), 'fp': int(fp), 'tn': int(tn), 'fn': int(fn)}
    }

    with open('data/evaluation_results.json', 'w') as f:
        json.dump(results, f, indent=2)

    print(f"\nResults saved to data/evaluation_results.json")
    monitor.shutdown()


if __name__ == "__main__":
    evaluate_detection_performance()
