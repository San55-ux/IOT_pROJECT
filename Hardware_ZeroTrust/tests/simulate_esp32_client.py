"""
Virtual ESP32 Microcontroller Client Simulator
Simulates the physical ESP32 startup cycle, SRAM PUF extraction,
helper data reconstruction, key derivation, and interactive Schnorr authentication.
"""

import sys
import time
import argparse
import requests
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.crypto.schnorr_verifier import (
    SchnorrProtocol, encode_point, decode_point, ORDER
)
from backend.crypto.puf_helper import (
    SRAMCellModel, PUFEnrollment, PUF_BIT_LENGTH
)


class VirtualESP32:
    """Emulates the complete hardware and firmware lifecycle of an ESP32 node."""

    def __init__(self, device_id: str = "ESP32-001", gateway_url: str = "http://127.0.0.1:8000", seed: int = 42):
        self.device_id = device_id
        self.gateway_url = gateway_url.rstrip("/")
        self.mac_address = "24:6F:28:B2:1A:E0"
        self.chip_model = "ESP32-D0WDQ6"
        self.chip_revision = 1

        print("\n========================================================")
        print("  VIRTUAL ESP32 HARDWARE INITIALIZATION")
        print("========================================================")
        print(f"  Device ID   : {self.device_id}")
        print(f"  eFuse MAC   : {self.mac_address}")
        print(f"  Chip Model  : {self.chip_model} (Rev {self.chip_revision})")
        print(f"  Gateway URL : {self.gateway_url}")
        print("========================================================\n")

        # 1. Initialize physical SRAM cell array model
        print("[ESP32] Simulating uninitialized SRAM startup state...")
        self.sram_model = SRAMCellModel(num_bits=PUF_BIT_LENGTH, seed=seed)

        # 2. Perform PUF Enrollment (11 simulated cold power-on readings)
        print("[ESP32] Performing multi-sample majority voting enrollment...")
        samples = [self.sram_model.power_on_read(noise_factor=0.035) for _ in range(11)]
        self.helper_data, self.ref_bits = PUFEnrollment.enroll(samples)
        self.stable_count = sum(self.helper_data)
        print(f"[ESP32] Identified {self.stable_count} / {PUF_BIT_LENGTH} stable SRAM cells.")

        # Pack helper data to hex string
        helper_bytes = PUFEnrollment.bits_to_bytes(self.helper_data)
        self.helper_data_hex = helper_bytes.hex()

        # 3. Derive Cryptographic Secret on boot
        current_boot_read = self.sram_model.power_on_read(noise_factor=0.035)
        stabilized_bits = PUFEnrollment.reconstruct(current_boot_read, self.helper_data)
        stabilized_bytes = PUFEnrollment.bits_to_bytes(stabilized_bits)

        self.private_secret = PUFEnrollment.derive_private_secret(
            stabilized_bytes, self.device_id, ORDER
        )
        print(f"[ESP32] Derived 256-bit Private Secret x from stabilized PUF via HKDF-SHA256.")

        # 4. Generate Schnorr Public Key Y = x * G
        self.public_key_point = SchnorrProtocol.derive_public_key(self.private_secret)
        self.public_key_hex = encode_point(self.public_key_point, compressed=True)
        print(f"[ESP32] Computed Schnorr Public Key Y: {self.public_key_hex}")

    def register(self) -> bool:
        """Enrolls device with the Zero-Trust Gateway directory."""
        print(f"\n[ESP32 -> Gateway] Registering device '{self.device_id}'...")
        payload = {
            "device_id": self.device_id,
            "mac_address": self.mac_address,
            "chip_model": self.chip_model,
            "chip_revision": self.chip_revision,
            "public_key": self.public_key_hex,
            "helper_data": self.helper_data_hex
        }
        try:
            res = requests.post(f"{self.gateway_url}/api/device/register", json=payload, timeout=5)
            if res.status_code == 200:
                print(f"[Gateway -> ESP32] Registration successful: {res.json()['message']}")
                return True
            else:
                print(f"[Gateway -> ESP32] Registration failed: {res.status_code} - {res.text}")
                return False
        except Exception as e:
            print(f"[Error] Failed to connect to Gateway at {self.gateway_url}: {e}")
            return False

    def authenticate(self) -> bool:
        """Executes full 3-pass interactive Schnorr authentication against Gateway."""
        print("\n--------------------------------------------------------")
        print(">>> INITIATING 3-PASS SCHNORR ZERO-KNOWLEDGE PROOF <<<")
        print("--------------------------------------------------------")
        start_time = time.time()

        # Step 1: Commitment R = k * G
        k, R = SchnorrProtocol.generate_commitment()
        R_hex = encode_point(R, compressed=True)
        print(f"[Step 1] Generated Ephemeral Nonce k and Commitment R:")
        print(f"         R = {R_hex}")

        # Send commitment to request challenge
        chal_payload = {
            "device_id": self.device_id,
            "commitment": R_hex
        }
        try:
            chal_res = requests.post(f"{self.gateway_url}/api/auth/challenge", json=chal_payload, timeout=5)
            if chal_res.status_code != 200:
                print(f"[Error] Challenge request rejected: {chal_res.text}")
                return False
            chal_data = chal_res.json()
        except Exception as e:
            print(f"[Error] Network failure during challenge phase: {e}")
            return False

        session_id = chal_data["session_id"]
        challenge_hex = chal_data["challenge"]
        challenge_int = int(challenge_hex, 16)
        print(f"[Step 2] Received Fresh Ephemeral Challenge c from Gateway:")
        print(f"         c = {challenge_hex}")
        print(f"         Session ID: {session_id}")

        # Step 3: Compute Schnorr response s = (k + c * x) mod q
        s = SchnorrProtocol.compute_response(k, challenge_int, self.private_secret)
        s_hex = hex(s)[2:].zfill(64)
        print(f"[Step 3] Computed Schnorr Response Scalar s:")
        print(f"         s = (k + c * x) mod q = {s_hex}")

        # Submit response to Gateway for verification
        verify_payload = {
            "session_id": session_id,
            "device_id": self.device_id,
            "response": s_hex
        }
        try:
            verify_res = requests.post(f"{self.gateway_url}/api/auth/verify", json=verify_payload, timeout=5)
            v_data = verify_res.json()
        except Exception as e:
            print(f"[Error] Network failure during verification phase: {e}")
            return False

        elapsed_ms = (time.time() - start_time) * 1000.0

        if v_data.get("authenticated"):
            print("\n[RESULT] **************************************************")
            print(f"[RESULT] >>> AUTHENTICATION GRANTED! DEVICE TRUSTED <<<")
            print(f"[RESULT] Physical Relay Status : {v_data.get('relay_status')}")
            print(f"[RESULT] End-to-End Latency    : {elapsed_ms:.1f} ms (Gateway: {v_data.get('latency_ms')} ms)")
            print("[RESULT] **************************************************\n")
            return True
        else:
            print("\n[RESULT] XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            print(f"[RESULT] >>> AUTHENTICATION DENIED! DEVICE UNTRUSTED <<<")
            print(f"[RESULT] Reason: {v_data.get('message')}")
            print("[RESULT] XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n")
            return False


def main():
    parser = argparse.ArgumentParser(description="Simulate ESP32 PUF & Schnorr Client")
    parser.add_argument("--device-id", default="ESP32-001", help="Device Identifier")
    parser.add_argument("--gateway", default="http://127.0.0.1:8000", help="Gateway base URL")
    parser.add_argument("--register", action="store_true", help="Register device before authenticating")
    parser.add_argument("--loop", type=int, default=1, help="Number of authentication cycles to run")
    parser.add_argument("--interval", type=int, default=5, help="Interval between loops in seconds")
    args = parser.parse_args()

    client = VirtualESP32(device_id=args.device_id, gateway_url=args.gateway)

    if args.register:
        client.register()

    for i in range(args.loop):
        print(f"\n--- Authentication Cycle {i+1} of {args.loop} ---")
        client.authenticate()
        if i < args.loop - 1:
            time.sleep(args.interval)


if __name__ == "__main__":
    main()
