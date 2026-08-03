"""Train the small Random Forest used by the IDS demo.

The default data is synthetic so the project can be run without downloading a
large dataset.  A CSV containing the same feature columns and a `label` column
can be passed with --data when real flow data is available.
"""

import argparse
from pathlib import Path

import numpy as np
import pandas as pd
from joblib import dump
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import MinMaxScaler


BASE_DIR = Path(__file__).resolve().parent
MODEL_PATH = BASE_DIR / "random_forest_model.joblib"

# These are simple versions of the behavioral features described in the paper.
FEATURE_NAMES = [
    "flow_duration",
    "packet_count",
    "byte_count",
    "iat_mean",
    "average_packet_size",
    "syn_count",
    "ack_count",
    "syn_ack_ratio",
]


def generate_demo_data(number_of_rows=5000):
    """Create simple normal and malicious flow examples."""

    rng = np.random.default_rng(42)
    rows = []
    labels = []

    for _ in range(number_of_rows):
        malicious = bool(rng.integers(0, 2))

        if malicious:
            # High packet rate, small packets, many SYNs and few ACKs.
            packet_count = int(rng.integers(60, 180))
            average_size = float(rng.uniform(40, 120))
            syn_count = int(rng.uniform(packet_count * 0.7, packet_count))
            ack_count = int(rng.integers(0, 5))
            flow_duration = float(rng.uniform(0.2, 15))
            iat_mean = float(rng.uniform(0.001, 0.05))
        else:
            # Ordinary application traffic has fewer packets and many ACKs.
            packet_count = int(rng.integers(5, 40))
            average_size = float(rng.uniform(250, 1400))
            syn_count = int(rng.integers(1, 4))
            ack_count = max(1, int(packet_count * rng.uniform(0.5, 0.95)))
            flow_duration = float(rng.uniform(1, 60))
            iat_mean = float(rng.uniform(0.05, 2))

        rows.append(
            {
                "flow_duration": flow_duration,
                "packet_count": packet_count,
                "byte_count": packet_count * average_size,
                "iat_mean": iat_mean,
                "average_packet_size": average_size,
                "syn_count": syn_count,
                "ack_count": ack_count,
                "syn_ack_ratio": syn_count / ack_count if ack_count else syn_count,
            }
        )
        labels.append(int(malicious))

    return pd.DataFrame(rows, columns=FEATURE_NAMES), pd.Series(labels, name="label")


def load_csv(path):
    """Load a CSV with the eight feature columns and a label column."""

    frame = pd.read_csv(path)
    missing = [name for name in FEATURE_NAMES + ["label"] if name not in frame.columns]
    if missing:
        raise ValueError("CSV is missing columns: " + ", ".join(missing))

    features = frame[FEATURE_NAMES].apply(pd.to_numeric, errors="coerce").fillna(0)
    labels = frame["label"].apply(
        lambda value: 0 if str(value).strip().lower() in {"0", "normal", "benign"} else 1
    )
    return features, labels


def train(data, labels, output_path):
    x_train, x_test, y_train, y_test = train_test_split(
        data,
        labels,
        test_size=0.30,  # 70/30 split used in the paper
        random_state=42,
        stratify=labels,
    )

    # Scaling and classification are kept together so inference uses the same
    # preprocessing as training.
    model = Pipeline(
        [
            ("scaler", MinMaxScaler()),
            (
                "classifier",
                RandomForestClassifier(
                    n_estimators=100,
                    max_depth=15,
                    random_state=42,
                    n_jobs=-1,
                ),
            ),
        ]
    )
    model.fit(x_train, y_train)
    predictions = model.predict(x_test)

    print(classification_report(y_test, predictions, target_names=["Normal", "Malicious"]))
    dump(
        {
            "model": model,
            "feature_names": FEATURE_NAMES,
            "threshold": 0.75,
            "model_version": "simple-rf-v1",
        },
        output_path,
    )
    print(f"Model saved to {output_path}")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", help="Optional CSV with the eight features and label")
    parser.add_argument("--rows", type=int, default=5000)
    parser.add_argument("--output", default=str(MODEL_PATH))
    args = parser.parse_args()

    if args.data:
        data, labels = load_csv(args.data)
        source = args.data
    else:
        data, labels = generate_demo_data(args.rows)
        source = "synthetic demo data"

    print(f"Training with {len(data)} rows from {source}")
    train(data, labels, Path(args.output))


if __name__ == "__main__":
    main()
