"""
Unit Tests for Schnorr Identification & secp256k1 Cryptographic Engine
"""

import unittest
import sys
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.crypto.schnorr_verifier import (
    SchnorrProtocol, G, ORDER, P, scalar_mult, point_add,
    encode_point, decode_point, is_on_curve, POINT_INFINITY
)


class TestSchnorrCrypto(unittest.TestCase):
    """Test suite verifying mathematical soundness of the Schnorr ZKP implementation."""

    def test_generator_on_curve(self):
        """Verifies generator G lies on secp256k1 curve y^2 = x^3 + 7."""
        self.assertTrue(is_on_curve(G))

    def test_point_at_infinity(self):
        """Verifies point at infinity behaves as additive identity."""
        self.assertEqual(point_add(G, POINT_INFINITY), G)
        self.assertEqual(point_add(POINT_INFINITY, G), G)

    def test_point_serialization(self):
        """Verifies compressed and uncompressed point encoding & decoding."""
        # Compressed
        comp_hex = encode_point(G, compressed=True)
        self.assertEqual(len(comp_hex), 66)  # 33 bytes in hex
        decoded_pt = decode_point(comp_hex)
        self.assertEqual(decoded_pt, G)

        # Uncompressed
        uncomp_hex = encode_point(G, compressed=False)
        self.assertEqual(len(uncomp_hex), 130)  # 65 bytes in hex
        decoded_uncomp = decode_point(uncomp_hex)
        self.assertEqual(decoded_uncomp, G)

    def test_schnorr_identification_soundness(self):
        """
        Tests the 3-pass interactive Schnorr identification:
        s * G == R + c * Y
        """
        # 1. Prover has private secret x derived from PUF
        private_secret = 0x4f8a3d12bc90e541a778129e9cb001f302a9de12e892c5bb48e11a3028cd9121
        public_key = SchnorrProtocol.derive_public_key(private_secret)
        self.assertTrue(is_on_curve(public_key))

        # 2. Prover generates commitment R = k * G
        k, R = SchnorrProtocol.generate_commitment()
        self.assertTrue(is_on_curve(R))

        # 3. Verifier generates fresh challenge c
        c = SchnorrProtocol.generate_challenge()

        # 4. Prover computes response s = (k + c * x) mod q
        s = SchnorrProtocol.compute_response(k, c, private_secret)

        # 5. Verifier verifies: s * G == R + c * Y
        is_valid = SchnorrProtocol.verify_proof(public_key, R, c, s)
        self.assertTrue(is_valid, "Valid Schnorr proof must verify successfully")

    def test_schnorr_invalid_response_fails(self):
        """Verifies that an altered response scalar s fails verification."""
        private_secret = 0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef
        public_key = SchnorrProtocol.derive_public_key(private_secret)
        k, R = SchnorrProtocol.generate_commitment()
        c = SchnorrProtocol.generate_challenge()

        # Genuine response
        s = SchnorrProtocol.compute_response(k, c, private_secret)

        # Adversary bit-flip in response
        corrupted_s = (s ^ 0x01) % ORDER
        is_valid = SchnorrProtocol.verify_proof(public_key, R, c, corrupted_s)
        self.assertFalse(is_valid, "Corrupted response scalar must be rejected")

    def test_schnorr_wrong_public_key_fails(self):
        """Verifies proof fails if submitted against a different public key."""
        secret_legit = 0x1111111111111111111111111111111111111111111111111111111111111111
        secret_impostor = 0x2222222222222222222222222222222222222222222222222222222222222222

        pub_legit = SchnorrProtocol.derive_public_key(secret_legit)
        pub_impostor = SchnorrProtocol.derive_public_key(secret_impostor)

        # Prover produces proof using secret_legit
        k, R = SchnorrProtocol.generate_commitment()
        c = SchnorrProtocol.generate_challenge()
        s = SchnorrProtocol.compute_response(k, c, secret_legit)

        # Verifier checks against wrong public key
        is_valid = SchnorrProtocol.verify_proof(pub_impostor, R, c, s)
        self.assertFalse(is_valid, "Proof with mismatching public key must fail")

    def test_fiat_shamir_non_interactive_mode(self):
        """Verifies non-interactive Fiat-Shamir transformation mode."""
        device_id = "ESP32-TEST-01"
        secret = 0xabcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890
        pub = SchnorrProtocol.derive_public_key(secret)

        k, R = SchnorrProtocol.generate_commitment()
        c = SchnorrProtocol.compute_fiat_shamir_challenge(device_id, pub, R, "NONCE-123")
        s = SchnorrProtocol.compute_response(k, c, secret)

        is_valid = SchnorrProtocol.verify_proof(pub, R, c, s)
        self.assertTrue(is_valid, "Fiat-Shamir proof must verify successfully")


if __name__ == "__main__":
    unittest.main()
