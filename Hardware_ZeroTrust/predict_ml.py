"""
Interactive ML Model Output & Telemetry Inspector
Demonstrates the Random Forest & Isolation Forest ML predictions for SRAM PUF health.
Run with:
    python predict_ml.py
"""

import sys
import json
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from backend.database.db import init_db
from backend.services.puf_health_service import PufHealthService


def run_demo():
    init_db()
    print("=" * 65)
    print("      SRAM PUF MACHINE LEARNING PREDICTION ENGINE")
    print("=" * 65)

    test_cases = [
        {
            "scenario": "1. Nominal / Healthy Operating Condition",
            "device_id": "ESP32_ROOM_TEMP",
            "temperature_c": 28.5,
            "voltage_v": 3.30,
            "boot_count": 12,
        },
        {
            "scenario": "2. High Ambient Heat (Thermal Stress)",
            "device_id": "ESP32_HOT_ENV",
            "temperature_c": 68.0,
            "voltage_v": 3.30,
            "boot_count": 1500,
        },
        {
            "scenario": "3. Adversary Freeze-Spray Attack (-18°C Tampering)",
            "device_id": "ESP32_TAMPER_COLD",
            "temperature_c": -18.0,
            "voltage_v": 3.30,
            "boot_count": 5,
        },
        {
            "scenario": "4. Supply Voltage Glitch / Undervolting (2.60V Attack)",
            "device_id": "ESP32_VOLT_GLITCH",
            "temperature_c": 30.0,
            "voltage_v": 2.60,
            "boot_count": 20,
        },
    ]

    for case in test_cases:
        print(f"\n>>> Running Scenario: {case['scenario']}")
        print(f"    Inputs  : Temp = {case['temperature_c']}°C, Voltage = {case['voltage_v']}V, Boots = {case['boot_count']}")
        
        result = PufHealthService.evaluate_telemetry(
            device_id=case["device_id"],
            temperature_c=case["temperature_c"],
            voltage_v=case["voltage_v"],
            boot_count=case["boot_count"],
        )

        print("    ------------------ ML INFERENCE OUTPUT ------------------")
        print(f"    Predicted Bit Error Rate (BER) : {result['predicted_ber_pct']}%")
        print(f"    Silicon Health Score           : {result['health_score']}% / 100%")
        print(f"    Operating Status               : {result['status']}")
        print(f"    Tamper Detected?               : {'YES [ALERT!]' if result['is_tamper'] else 'NO [NORMAL]'}")
        if result['is_tamper']:
            print(f"    Tamper Reason                  : {result['tamper_reason']}")

    print("\n" + "=" * 65)
    print("  [SUCCESS] All ML predictions completed successfully!")
    print("=" * 65 + "\n")


if __name__ == "__main__":
    run_demo()
