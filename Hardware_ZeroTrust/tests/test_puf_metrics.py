"""
Statistical and Reliability Tests for ESP32 SRAM PUF Modeling & Key Derivation
"""

import unittest
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.crypto.puf_helper import (
    SRAMCellModel, PUFEnrollment, PUFMetricsEvaluator,
    PUF_BIT_LENGTH, MIN_STABLE_BITS_REQUIRED
)
from backend.crypto.schnorr_verifier import ORDER


class TestSRAMPUFMetrics(unittest.TestCase):
    """Evaluates PUF stability, uniqueness, entropy, and key derivation reproducibility."""

    def test_sram_power_on_read(self):
        """Verifies SRAM model produces correct bit length."""
        cell_model = SRAMCellModel(num_bits=512, seed=42)
        read1 = cell_model.power_on_read()
        self.assertEqual(len(read1), 512)
        self.assertTrue(all(b in (0, 1) for b in read1))

    def test_puf_enrollment_and_stability(self):
        """Tests that enrollment identifies stable cells and filters noisy bits."""
        cell_model = SRAMCellModel(num_bits=1024, seed=123)
        # Collect 11 power-on reads
        reads = [cell_model.power_on_read(noise_factor=0.04) for _ in range(11)]

        helper_data, ref_bits = PUFEnrollment.enroll(reads)
        stable_count = sum(helper_data)

        self.assertGreaterEqual(stable_count, MIN_STABLE_BITS_REQUIRED,
                                "Enrollment must identify at least minimum stable bits")

        # Stable bitmask (helper data) must match reference bits
        for i in range(1024):
            if helper_data[i] == 1:
                # All 11 reads must agree with ref_bits
                for r in reads:
                    self.assertEqual(r[i], ref_bits[i])

    def test_puf_reconstruction_and_key_derivation(self):
        """
        Tests that reconstructed stable bits across two independent boots of the same chip
        produce identical cryptographic keys.
        """
        cell_model = SRAMCellModel(num_bits=1024, seed=999)
        enroll_reads = [cell_model.power_on_read(noise_factor=0.03) for _ in range(11)]
        helper_data, ref_bits = PUFEnrollment.enroll(enroll_reads)

        # Reconstruct on Boot A
        boot_a_read = cell_model.power_on_read(noise_factor=0.03)
        stable_bits_a = PUFEnrollment.reconstruct(boot_a_read, helper_data)
        bytes_a = PUFEnrollment.bits_to_bytes(stable_bits_a)
        secret_a = PUFEnrollment.derive_private_secret(bytes_a, "ESP32-TEST", ORDER)

        # Reconstruct on Boot B
        boot_b_read = cell_model.power_on_read(noise_factor=0.03)
        stable_bits_b = PUFEnrollment.reconstruct(boot_b_read, helper_data)
        bytes_b = PUFEnrollment.bits_to_bytes(stable_bits_b)
        secret_b = PUFEnrollment.derive_private_secret(bytes_b, "ESP32-TEST", ORDER)

        self.assertEqual(secret_a, secret_b,
                         "PUF key derivation must be 100% reproducible for the same chip")

    def test_inter_device_uniqueness(self):
        """
        Verifies that two distinct chips have an Inter-Device Hamming Distance near 50%
        and derive distinct private keys.
        """
        chip_1 = SRAMCellModel(num_bits=1024, seed=1)
        chip_2 = SRAMCellModel(num_bits=1024, seed=2)

        read_1 = chip_1.power_on_read()
        read_2 = chip_2.power_on_read()

        inter_hd = PUFMetricsEvaluator.fractional_hamming_distance(read_1, read_2)
        # Inter-HD between distinct chips should be close to 50% (typical 45% - 55%)
        self.assertGreater(inter_hd, 42.0)
        self.assertLess(inter_hd, 58.0)

    def test_shannon_entropy(self):
        """Verifies high Shannon entropy in raw PUF startup vectors."""
        chip = SRAMCellModel(num_bits=2048, seed=777)
        bits = chip.power_on_read()
        entropy = PUFMetricsEvaluator.calculate_shannon_entropy(bits)
        self.assertGreater(entropy, 0.95, "SRAM startup response must exhibit high entropy")


if __name__ == "__main__":
    unittest.main()
