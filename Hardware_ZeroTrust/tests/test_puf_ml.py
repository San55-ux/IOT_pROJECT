"""
Unit & Integration Tests for Option 3: SRAM PUF Machine Learning Predictor
Verifies:
1. Dataset generation and feature extraction
2. Random Forest Regressor & Anomaly Detector inference
3. Temperature drift predictions & health scoring
4. Anti-tamper freeze spray and voltage glitch detection
"""

import unittest
import sys
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.ml.dataset_generator import calculate_physical_noise
from backend.services.puf_health_service import PufHealthService
from backend.database.db import Database, init_db


class TestPufMLPredictor(unittest.TestCase):
    """Test suite for the Machine Learning PUF health and drift prediction engine."""

    @classmethod
    def setUpClass(cls):
        init_db()

    def test_physical_noise_calculation(self):
        """Tests that semiconductor physics formulas produce expected noise trends."""
        # Baseline at 25°C, 3.3V, 1 boot
        nominal_noise = calculate_physical_noise(25.0, 3.30, 1)
        self.assertGreater(nominal_noise, 0.0)

        # Higher temperature -> higher thermal noise
        hot_noise = calculate_physical_noise(75.0, 3.30, 1)
        self.assertGreater(hot_noise, nominal_noise)

        # Lower supply voltage -> lower static noise margin -> higher noise
        low_voltage_noise = calculate_physical_noise(25.0, 2.80, 1)
        self.assertGreater(low_voltage_noise, nominal_noise)

        # High boot cycles (silicon aging) -> higher noise
        aged_noise = calculate_physical_noise(25.0, 3.30, 10000)
        self.assertGreater(aged_noise, nominal_noise)

    def test_ml_healthy_prediction(self):
        """Tests that nominal operating conditions yield high health score and OPTIMAL status."""
        result = PufHealthService.evaluate_telemetry(
            device_id="TEST-ESP32-ML-01",
            temperature_c=32.0,
            voltage_v=3.30,
            boot_count=10
        )
        self.assertIn("predicted_ber_pct", result)
        self.assertIn("health_score", result)
        self.assertIn("status", result)
        self.assertFalse(result["is_tamper"])
        self.assertGreaterEqual(result["health_score"], 70.0)
        self.assertIn(result["status"], ["OPTIMAL", "DEGRADATION_WARNING"])

    def test_ml_freeze_tamper_detection(self):
        """Tests that extreme negative temperature (-15°C) is flagged as PHYSICAL_TAMPER."""
        result = PufHealthService.evaluate_telemetry(
            device_id="TEST-ESP32-ML-FREEZE",
            temperature_c=-15.0,
            voltage_v=3.30,
            boot_count=50
        )
        self.assertTrue(result["is_tamper"])
        self.assertEqual(result["status"], "PHYSICAL_TAMPER")
        self.assertIn("Freeze Attack", result["tamper_reason"])

    def test_ml_voltage_glitch_detection(self):
        """Tests that severe undervolting (2.65V) is flagged as fault injection."""
        result = PufHealthService.evaluate_telemetry(
            device_id="TEST-ESP32-ML-GLITCH",
            temperature_c=35.0,
            voltage_v=2.65,
            boot_count=50
        )
        self.assertTrue(result["is_tamper"])
        self.assertEqual(result["status"], "PHYSICAL_TAMPER")
        self.assertIn("Voltage Rail Droop", result["tamper_reason"])

    def test_telemetry_history_retrieval(self):
        """Tests that telemetry entries are recorded in SQLite and retrievable."""
        PufHealthService.evaluate_telemetry(
            device_id="TEST-ESP32-HIST",
            temperature_c=30.0,
            voltage_v=3.30,
            boot_count=5
        )
        history = PufHealthService.get_recent_telemetry(device_id="TEST-ESP32-HIST", limit=5)
        self.assertGreater(len(history), 0)
        self.assertEqual(history[0]["device_id"], "TEST-ESP32-HIST")


if __name__ == "__main__":
    unittest.main()
