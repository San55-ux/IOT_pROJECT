"""
PUF Health & Environmental Drift Prediction Service
Provides real-time machine learning inference for SRAM PUF health,
temperature drift forecasting, and hardware physical tamper detection.
"""

import os
import sys
from pathlib import Path
from typing import Dict, Any, Optional, List
from datetime import datetime, timezone
import joblib
import numpy as np

from backend.database.db import Database
from backend.services.alert_service import AlertService

MODEL_PATH = Path(__file__).resolve().parent.parent / "ml" / "puf_predictor.pkl"


class PufHealthService:
    """Manages ML inference and telemetry tracking for PUF hardware reliability."""

    _model_bundle = None

    @classmethod
    def _get_model(cls):
        """Lazy-loads the serialized ML model bundle."""
        if cls._model_bundle is None:
            if not MODEL_PATH.exists():
                from backend.ml.train_puf_model import train_and_export_model
                cls._model_bundle = train_and_export_model()
            else:
                cls._model_bundle = joblib.load(MODEL_PATH)
        return cls._model_bundle

    @classmethod
    def evaluate_telemetry(
        cls,
        device_id: str,
        temperature_c: float,
        voltage_v: float = 3.30,
        boot_count: int = 1
    ) -> Dict[str, Any]:
        """
        Runs ML inference on hardware telemetry:
        - Predicts Bit Error Rate (BER %)
        - Computes Silicon Health Score (0-100%)
        - Detects Physical Tamper / Fault Injection (Freeze attack or voltage drop)
        - Logs telemetry to SQLite database
        """
        model = cls._get_model()
        regressor = model["regressor"]
        anomaly_detector = model["anomaly_detector"]

        # 1. Feature vector: [temperature_c, voltage_v, boot_count]
        features = np.array([[temperature_c, voltage_v, boot_count]])

        # 2. Predicted Bit Error Rate (Regression)
        predicted_ber = float(regressor.predict(features)[0])
        predicted_ber = max(0.0, round(predicted_ber, 2))

        # 3. Anomaly / Physical Tamper Detection
        # Check rule-based bounds first (deterministic physical bounds)
        is_tamper = False
        tamper_reason = None

        if temperature_c < -10.0:
            is_tamper = True
            tamper_reason = f"Extreme Low Temperature ({temperature_c:.1f}°C) - Freeze Attack Suspected"
        elif temperature_c > 85.0:
            is_tamper = True
            tamper_reason = f"Extreme High Temperature ({temperature_c:.1f}°C) - Thermal Fault Injection"
        elif voltage_v < 2.80:
            is_tamper = True
            tamper_reason = f"Voltage Rail Droop ({voltage_v:.2f}V) - Undervolting / Glitch Attack"
        else:
            # Unsupervised Isolation Forest score
            anomaly_flag = anomaly_detector.predict(features)[0]
            if anomaly_flag == -1:
                is_tamper = True
                tamper_reason = "Out-of-Distribution Hardware Telemetry Anomaly"

        # 4. Silicon Health Score (0% - 100%)
        health_score = max(0.0, min(100.0, 100.0 - (predicted_ber * 5.0)))
        health_score = round(health_score, 1)

        # 5. Status categorization
        if is_tamper:
            status = "PHYSICAL_TAMPER"
            # Trigger high-priority security alert
            AlertService.record_alert(
                alert_type="PHYSICAL_TAMPER_DETECTED",
                description=f"CRITICAL: {tamper_reason} on device '{device_id}'",
                severity="CRITICAL",
                device_id=device_id
            )
        elif health_score >= 85.0:
            status = "OPTIMAL"
        elif health_score >= 60.0:
            status = "DEGRADATION_WARNING"
            AlertService.record_alert(
                alert_type="PUF_DEGRADATION_WARNING",
                description=(
                    f"Warning: Device '{device_id}' PUF health degraded to {health_score}% "
                    f"(Predicted BER: {predicted_ber}%). Recommend helper data re-enrollment."
                ),
                severity="WARNING",
                device_id=device_id
            )
        else:
            status = "CRITICAL_DEGRADATION"
            AlertService.record_alert(
                alert_type="PUF_CRITICAL_DEGRADATION",
                description=(
                    f"CRITICAL: Device '{device_id}' PUF health dropped to {health_score}%! "
                    f"Risk of cryptographic key loss is imminent."
                ),
                severity="HIGH",
                device_id=device_id
            )

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")

        # 6. Record to SQLite database
        try:
            query = """
                INSERT INTO puf_telemetry (
                    device_id, temperature, voltage, boot_count,
                    predicted_ber, health_score, status, timestamp
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """
            Database.execute(query, (
                device_id, temperature_c, voltage_v, boot_count,
                predicted_ber, health_score, status, now
            ))
        except Exception as e:
            # Table might not exist yet if schema hasn't migrated; non-fatal
            pass

        return {
            "device_id": device_id,
            "temperature_c": temperature_c,
            "voltage_v": voltage_v,
            "boot_count": boot_count,
            "predicted_ber_pct": predicted_ber,
            "health_score": health_score,
            "status": status,
            "is_tamper": is_tamper,
            "tamper_reason": tamper_reason,
            "timestamp": now
        }

    @classmethod
    def get_recent_telemetry(cls, device_id: Optional[str] = None, limit: int = 20) -> List[Dict[str, Any]]:
        """Fetches recent telemetry history for dashboard charts."""
        try:
            if device_id:
                query = """
                    SELECT id, device_id, temperature, voltage, boot_count,
                           predicted_ber, health_score, status, timestamp
                    FROM puf_telemetry
                    WHERE device_id = ?
                    ORDER BY id DESC LIMIT ?
                """
                return Database.fetch_all(query, (device_id, limit))
            else:
                query = """
                    SELECT id, device_id, temperature, voltage, boot_count,
                           predicted_ber, health_score, status, timestamp
                    FROM puf_telemetry
                    ORDER BY id DESC LIMIT ?
                """
                return Database.fetch_all(query, (limit,))
        except Exception:
            return []
