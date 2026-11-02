"""
SRAM PUF Machine Learning Model Trainer
Trains a Random Forest Regressor to predict Bit Error Rate (BER %)
from hardware telemetry (Temperature, Supply Voltage, Boot Count).
Also fits an Anomaly Detector for Physical Tamper / Fault Injection detection.
Saves model to: 'backend/ml/puf_predictor.pkl'
"""

import os
import sys
import csv
from pathlib import Path
import joblib
import numpy as np
from sklearn.ensemble import RandomForestRegressor, IsolationForest
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error, mean_absolute_error, r2_score

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.ml.dataset_generator import DATASET_PATH, generate_dataset

MODEL_PATH = Path(__file__).resolve().parent / "puf_predictor.pkl"


def load_data(csv_path: Path):
    """Loads feature matrix X and target y from CSV."""
    if not csv_path.exists():
        generate_dataset()

    X = []
    y_ber = []
    statuses = []

    with open(csv_path, mode="r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            temp = float(row["temperature_c"])
            volt = float(row["voltage_v"])
            boots = float(row["boot_count"])
            ber = float(row["bit_error_rate_pct"])
            
            X.append([temp, volt, boots])
            y_ber.append(ber)
            statuses.append(row["status"])

    return np.array(X), np.array(y_ber), statuses


def train_and_export_model():
    """Trains the Random Forest Regressor & Anomaly Detector, evaluates and exports."""
    print("[PUF ML Trainer] Loading environmental dataset...")
    X, y, statuses = load_data(DATASET_PATH)

    # Train-test split (80% train, 20% test)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    # 1. Regressor for Bit Error Rate prediction
    print("[PUF ML Trainer] Fitting Random Forest Regressor (100 estimators)...")
    regressor = RandomForestRegressor(
        n_estimators=100,
        max_depth=10,
        min_samples_split=4,
        random_state=42
    )
    regressor.fit(X_train, y_train)

    # Evaluate
    y_pred = regressor.predict(X_test)
    mae = mean_absolute_error(y_test, y_pred)
    mse = mean_squared_error(y_test, y_pred)
    r2 = r2_score(y_test, y_pred)

    print("\n========================================================")
    print("  SRAM PUF ML MODEL EVALUATION RESULTS")
    print("========================================================")
    print(f"  Training Samples   : {len(X_train)}")
    print(f"  Testing Samples    : {len(X_test)}")
    print(f"  Mean Absolute Error: {mae:.3f}% BER")
    print(f"  Root Mean Sq Error : {np.sqrt(mse):.3f}% BER")
    print(f"  R² Goodness of Fit : {r2:.4f} (Optimal: 1.000)")
    print("========================================================\n")

    # 2. Train Anomaly Detector for extreme fault injection / freeze spray
    # Filter normal operating data for anomaly baseline
    normal_indices = [i for i, s in enumerate(statuses) if s == "HEALTHY"]
    X_normal = X[normal_indices] if len(normal_indices) > 50 else X

    anomaly_detector = IsolationForest(
        n_estimators=100,
        contamination=0.05,
        random_state=42
    )
    anomaly_detector.fit(X_normal)

    # Package payload
    model_bundle = {
        "regressor": regressor,
        "anomaly_detector": anomaly_detector,
        "feature_names": ["temperature_c", "voltage_v", "boot_count"],
        "metrics": {
            "mae": round(mae, 3),
            "r2": round(r2, 4)
        }
    }

    MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model_bundle, MODEL_PATH)
    print(f"[PUF ML Trainer] Model successfully saved to: {MODEL_PATH}")
    return model_bundle


if __name__ == "__main__":
    train_and_export_model()
