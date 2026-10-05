"""
Integration Test Suite for Zero-Trust Gateway API Endpoints
Tests registration, challenge-response cycle, replay rejection, and relay control.
"""

import unittest
import sys
from pathlib import Path
from fastapi.testclient import TestClient

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.main import app
from backend.database.db import init_db
from backend.crypto.schnorr_verifier import (
    SchnorrProtocol, ORDER, encode_point
)


class TestGatewayAPI(unittest.TestCase):
    """Integration test suite using FastAPI TestClient."""

    @classmethod
    def setUpClass(cls):
        init_db()
        cls.client = TestClient(app)

    def test_health_check(self):
        """Verifies health check endpoint."""
        res = self.client.get("/health")
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "HEALTHY")

    def test_end_to_end_authentication_cycle(self):
        """
        Tests the complete 4-step sequence:
        1. Device registers public key
        2. Prover requests challenge with commitment R
        3. Prover calculates response s and submits for verification
        4. Gateway verifies proof, marks TRUSTED, and unlocks relay
        """
        device_id = "ESP32-INTEG-01"
        mac = "30:AE:A4:07:0B:44"

        # Generate private key x & public key Y
        secret_x = 0x3f5c71a92e104b689dfa1234567890abcdef1234567890abcdef1234567890ab
        pub_pt = SchnorrProtocol.derive_public_key(secret_x)
        pub_hex = encode_point(pub_pt, compressed=True)

        # 1. Register device
        reg_payload = {
            "device_id": device_id,
            "mac_address": mac,
            "chip_model": "ESP32",
            "chip_revision": 1,
            "public_key": pub_hex,
            "helper_data": "deadbeef"
        }
        reg_res = self.client.post("/api/device/register", json=reg_payload)
        self.assertEqual(reg_res.status_code, 200)
        self.assertEqual(reg_res.json()["trust_status"], "UNTRUSTED")

        # 2. Request Challenge with commitment R = k * G
        k, R = SchnorrProtocol.generate_commitment()
        R_hex = encode_point(R, compressed=True)

        chal_payload = {
            "device_id": device_id,
            "commitment": R_hex
        }
        chal_res = self.client.post("/api/auth/challenge", json=chal_payload)
        self.assertEqual(chal_res.status_code, 200)
        chal_data = chal_res.json()
        session_id = chal_data["session_id"]
        challenge_hex = chal_data["challenge"]
        challenge_int = int(challenge_hex, 16)

        # 3. Prover computes response s = (k + c * x) mod q
        s = SchnorrProtocol.compute_response(k, challenge_int, secret_x)
        s_hex = hex(s)[2:].zfill(64)

        # 4. Submit Proof
        verify_payload = {
            "session_id": session_id,
            "device_id": device_id,
            "response": s_hex
        }
        verify_res = self.client.post("/api/auth/verify", json=verify_payload)
        self.assertEqual(verify_res.status_code, 200)
        v_data = verify_res.json()

        self.assertTrue(v_data["authenticated"])
        self.assertEqual(v_data["trust_status"], "TRUSTED")
        self.assertEqual(v_data["relay_status"], "UNLOCKED")

    def test_replay_attack_rejection(self):
        """
        Verifies that re-submitting an already consumed proof payload
        results in an immediate REPLAY_ATTACK alert and rejection.
        """
        device_id = "ESP32-REPLAY-TARGET"
        secret_x = 0x9876543210fedcba9876543210fedcba9876543210fedcba9876543210fedcba
        pub_pt = SchnorrProtocol.derive_public_key(secret_x)
        pub_hex = encode_point(pub_pt, compressed=True)

        # Register
        self.client.post("/api/device/register", json={
            "device_id": device_id,
            "mac_address": "AA:BB:CC:11:22:33",
            "public_key": pub_hex
        })

        # Legitimate first run
        k, R = SchnorrProtocol.generate_commitment()
        chal_res = self.client.post("/api/auth/challenge", json={
            "device_id": device_id,
            "commitment": encode_point(R, compressed=True)
        })
        chal_data = chal_res.json()
        c = int(chal_data["challenge"], 16)
        s = SchnorrProtocol.compute_response(k, c, secret_x)
        s_hex = hex(s)[2:].zfill(64)

        payload = {
            "session_id": chal_data["session_id"],
            "device_id": device_id,
            "response": s_hex
        }

        # First verification succeeds
        v1 = self.client.post("/api/auth/verify", json=payload)
        self.assertTrue(v1.json()["authenticated"])

        # ADVERSARY REPLAYS EXACT SAME PAYLOAD
        v2 = self.client.post("/api/auth/verify", json=payload)
        self.assertEqual(v2.status_code, 200)
        v2_data = v2.json()

        self.assertFalse(v2_data["authenticated"], "Replayed authentication must be rejected")
        self.assertEqual(v2_data["relay_status"], "LOCKED", "Relay must remain locked on replay")
        self.assertIn("Replay attack detected", v2_data["message"])

    def test_unknown_device_rejected(self):
        """Verifies unknown devices are denied at challenge request."""
        k, R = SchnorrProtocol.generate_commitment()
        chal_res = self.client.post("/api/auth/challenge", json={
            "device_id": "ESP32-UNKNOWN-ROGUE",
            "commitment": encode_point(R, compressed=True)
        })
        self.assertEqual(chal_res.status_code, 400)
        self.assertIn("not enrolled", chal_res.json()["detail"])

    def test_relay_manual_override(self):
        """Verifies admin manual override endpoint."""
        res = self.client.post("/api/relay/override", json={
            "status": "UNLOCKED",
            "duration_seconds": 10,
            "reason": "ADMIN_TEST"
        })
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()["status"], "UNLOCKED")


if __name__ == "__main__":
    unittest.main()
