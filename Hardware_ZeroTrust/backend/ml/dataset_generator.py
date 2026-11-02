"""
SRAM PUF Environmental Dataset Generator
Simulates physical 6T SRAM cell responses across varying:
- Ambient / Die Temperature (-20°C to +85°C)
- Power Rail Supply Voltage (2.6V to 3.6V)
- Aging / Boot Cycles (1 to 20,000 cycles)

Calculates the resulting Fractional Hamming Distance (FHD) and Bit Error Rate (BER %).
Outputs: 'backend/ml/puf_environmental_dataset.csv'
"""

import os
import sys
import math
import random
import csv
from pathlib import Path

# Add project root to path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from backend.crypto.puf_helper import SRAMCellModel, PUFEnrollment, PUFMetricsEvaluator, PUF_BIT_LENGTH

DATASET_PATH = Path(__file__).resolve().parent / "puf_environmental_dataset.csv"


def calculate_physical_noise(temp_c: float, voltage_v: float, boot_count: int) -> float:
    """
    Computes effective noise factor based on semiconductor physics:
    1. Thermal noise: Proportional to sqrt(Kelvin)
    2. Voltage drift: Sub-nominal voltage (<3.3V) degrades Static Noise Margin (SNM)
    3. Silicon Aging (NBTI): Shifts threshold voltage as a power law of boot count
    """
    temp_kelvin = temp_c + 273.15
    # Baseline nominal: 25°C = 298.15K, 3.3V
    thermal_ratio = math.sqrt(temp_kelvin / 298.15)
    
    # Voltage sensitivity: lower voltage -> higher noise sensitivity
    voltage_factor = 1.0 + max(0.0, (3.3 - voltage_v) * 1.5) if voltage_v < 3.3 else 1.0 - (voltage_v - 3.3) * 0.2
    
    # Aging factor (NBTI drift): power-law exponent ~0.25
    aging_factor = 1.0 + (0.05 * math.log10(max(1, boot_count)))

    base_noise = 0.025
    effective_noise = base_noise * thermal_ratio * voltage_factor * aging_factor
    return max(0.005, effective_noise)


def generate_dataset(num_samples: int = 1200, seed: int = 42) -> Path:
    """Generates synthetic environmental telemetry samples and records true BER."""
    random.seed(seed)
    print(f"[Dataset Generator] Generating {num_samples} physical SRAM PUF samples...")

    # Create master reference device
    reference_model = SRAMCellModel(num_bits=PUF_BIT_LENGTH, seed=12345)
    # Generate golden reference at nominal conditions (25°C, 3.3V)
    golden_reads = [reference_model.power_on_read(noise_factor=0.015) for _ in range(7)]
    helper_data, ref_bits = PUFEnrollment.enroll(golden_reads)

    rows = []
    for i in range(num_samples):
        # Sample realistic environmental conditions:
        # Temperature: -15°C to +85°C (normal distribution centered around 35°C with wide tails)
        temp_c = round(random.gauss(35.0, 18.0), 1)
        temp_c = max(-15.0, min(85.0, temp_c))

        # Voltage: 2.8V to 3.6V (centered around 3.3V)
        voltage_v = round(random.uniform(2.80, 3.50), 2)

        # Cumulative boot cycles (aging)
        boot_count = int(random.choice([
            random.randint(1, 50),
            random.randint(50, 500),
            random.randint(500, 5000),
            random.randint(5000, 25000)
        ]))

        # Physical noise under these conditions
        noise = calculate_physical_noise(temp_c, voltage_v, boot_count)

        # Read PUF response under physical noise
        current_read = reference_model.power_on_read(noise_factor=noise)
        
        # Reconstruct stabilized bits using helper data mask
        reconstructed = PUFEnrollment.reconstruct(current_read, helper_data)
        golden_reconstructed = PUFEnrollment.reconstruct(ref_bits, helper_data)

        # True Bit Error Rate (%)
        hd = PUFMetricsEvaluator.hamming_distance(reconstructed, golden_reconstructed)
        ber = (hd / len(reconstructed)) * 100.0

        # Health score (100% minus 5x BER, clamped to [0, 100])
        health_score = max(0.0, min(100.0, 100.0 - (ber * 5.0)))

        # Status label
        if temp_c < -10.0:
            status = "FREEZE_TAMPER"
        elif voltage_v < 2.85:
            status = "VOLTAGE_GLITCH"
        elif ber > 10.0:
            status = "DEGRADATION_CRITICAL"
        elif ber > 5.0:
            status = "DEGRADATION_WARNING"
        else:
            status = "HEALTHY"

        rows.append({
            "temperature_c": temp_c,
            "voltage_v": voltage_v,
            "boot_count": boot_count,
            "noise_factor": round(noise, 4),
            "bit_error_rate_pct": round(ber, 2),
            "health_score": round(health_score, 1),
            "status": status
        })

    # Write to CSV
    DATASET_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(DATASET_PATH, mode="w", newline="", encoding="utf-8") as f:
        fieldnames = ["temperature_c", "voltage_v", "boot_count", "noise_factor", "bit_error_rate_pct", "health_score", "status"]
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    print(f"[Dataset Generator] Successfully saved {len(rows)} samples to: {DATASET_PATH}")
    return DATASET_PATH


if __name__ == "__main__":
    generate_dataset()
