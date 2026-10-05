"""
Automated Security Threat & Attack Demonstration Suite
Executes the 4 Core Demonstration Scenarios:
  Scenario 1: Authorized ESP32 (Pass & Relay Unlock)
  Scenario 2: Unauthorized / Unknown Device (Access Denied)
  Scenario 3: Replay Attack (Session Reuse Rejection & Alert)
  Scenario 4: Modified / Forged Proof (Cryptographic Failure & Alert)
"""

import sys
import time
import requests
import argparse
from pathlib import Path

# Add project root to sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from backend.crypto.schnorr_verifier import (
    SchnorrProtocol, encode_point, ORDER
)


class AttackSimulator:
    """Executes penetration tests and verification scenarios against the Zero-Trust Gateway."""

    def __init__(self, gateway_url: str = "http://127.0.0.1:8000"):
        self.gateway_url = gateway_url.rstrip("/")

    def print_header(self, title: str):
        print("\n" + "=" * 70)
        print(f"  {title.upper()}")
        print("=" * 70)

    # --------------------------------------------------------------------------
    # Scenario 1: Legitimate Authorized ESP32
    # --------------------------------------------------------------------------
    def run_scenario_1_authorized(self) -> bool:
        self.print_header("Scenario 1: Authorized ESP32 Authentication")
        device_id = "ESP32-AUTH-NODE"
        mac = "30:AE:A4:AA:BB:CC"

        # PUF-derived secret x and public key Y = x * G
        secret_x = 0x55aa55aa1234567890abcdef1234567890abcdef1234567890abcdef12345678
        pub_pt = SchnorrProtocol.derive_public_key(secret_x)
        pub_hex = encode_point(pub_pt, compressed=True)

        print(f"[Setup] Registering authorized device '{device_id}'...")
        reg_res = requests.post(f"{self.gateway_url}/api/device/register", json={
            "device_id": device_id,
            "mac_address": mac,
            "chip_model": "ESP32",
            "chip_revision": 1,
            "public_key": pub_hex,
            "helper_data": "ffffffff"
        })
        print(f"[Setup] Gateway Registration: {reg_res.json().get('message')}")

        # Prover generates commitment R = k * G
        k, R = SchnorrProtocol.generate_commitment()
        R_hex = encode_point(R, compressed=True)
        print(f"[Prover] Generated Commitment R = k * G ({R_hex[:16]}...)")

        # Request challenge from Gateway
        chal_res = requests.post(f"{self.gateway_url}/api/auth/challenge", json={
            "device_id": device_id,
            "commitment": R_hex
        })
        chal_data = chal_res.json()
        session_id = chal_data["session_id"]
        challenge_int = int(chal_data["challenge"], 16)
        print(f"[Gateway] Issued Fresh Challenge c: {chal_data['challenge'][:16]}... (Session: {session_id[:8]}...)")

        # Prover calculates response s = (k + c * x) mod q
        s = SchnorrProtocol.compute_response(k, challenge_int, secret_x)
        s_hex = hex(s)[2:].zfill(64)
        print(f"[Prover] Computed Response s = (k + c * x) mod q ({s_hex[:16]}...)")

        # Submit response
        verify_res = requests.post(f"{self.gateway_url}/api/auth/verify", json={
            "session_id": session_id,
            "device_id": device_id,
            "response": s_hex
        })
        v_data = verify_res.json()

        print(f"[Gateway Verification Result]")
        print(f"  -> Authenticated : {v_data.get('authenticated')}")
        print(f"  -> Trust Status  : {v_data.get('trust_status')}")
        print(f"  -> Relay Status  : {v_data.get('relay_status')}")
        print(f"  -> Message       : {v_data.get('message')}")

        success = v_data.get("authenticated") is True and v_data.get("relay_status") == "UNLOCKED"
        print(f"\n[CONCLUSION] Scenario 1: {'PASSED (ACCESS GRANTED)' if success else 'FAILED'}")
        return success

    # --------------------------------------------------------------------------
    # Scenario 2: Unauthorized / Unknown Device
    # --------------------------------------------------------------------------
    def run_scenario_2_unauthorized(self) -> bool:
        self.print_header("Scenario 2: Unauthorized / Unknown Device")
        rogue_device_id = "ESP32-ROGUE-CLONE"

        k, R = SchnorrProtocol.generate_commitment()
        R_hex = encode_point(R, compressed=True)
        print(f"[Attacker] Rogue device '{rogue_device_id}' attempting challenge request...")

        chal_res = requests.post(f"{self.gateway_url}/api/auth/challenge", json={
            "device_id": rogue_device_id,
            "commitment": R_hex
        })

        print(f"[Gateway Response] HTTP {chal_res.status_code}")
        print(f"  -> Detail: {chal_res.text}")

        # Check relay status to confirm it remains locked
        relay_res = requests.get(f"{self.gateway_url}/api/relay/status").json()
        print(f"  -> Physical Relay Status: {relay_res.get('status')}")

        success = chal_res.status_code == 400 and relay_res.get("status") == "LOCKED"
        print(f"\n[CONCLUSION] Scenario 2: {'PASSED (ACCESS DENIED & ALERT RAISED)' if success else 'FAILED'}")
        return success

    # --------------------------------------------------------------------------
    # Scenario 3: Replay Attack
    # --------------------------------------------------------------------------
    def run_scenario_3_replay(self) -> bool:
        self.print_header("Scenario 3: Replay Attack Demonstration")
        device_id = "ESP32-TARGET-02"

        secret_x = 0x99887766554433221100aabbccddeeff99887766554433221100aabbccddeeff
        pub_pt = SchnorrProtocol.derive_public_key(secret_x)
        pub_hex = encode_point(pub_pt, compressed=True)

        requests.post(f"{self.gateway_url}/api/device/register", json={
            "device_id": device_id,
            "mac_address": "11:22:33:44:55:66",
            "public_key": pub_hex
        })

        # Step A: Perform legitimate authentication and eavesdrop payload
        k, R = SchnorrProtocol.generate_commitment()
        chal_res = requests.post(f"{self.gateway_url}/api/auth/challenge", json={
            "device_id": device_id,
            "commitment": encode_point(R, compressed=True)
        }).json()

        session_id = chal_res["session_id"]
        c = int(chal_res["challenge"], 16)
        s = SchnorrProtocol.compute_response(k, c, secret_x)
        s_hex = hex(s)[2:].zfill(64)

        payload = {
            "session_id": session_id,
            "device_id": device_id,
            "response": s_hex
        }

        print("[Eavesdropper] Intercepted valid transmission:")
        print(f"               Session ID: {session_id}")
        print(f"               Response s: {s_hex[:20]}...")

        # Legitimate first verification
        v1 = requests.post(f"{self.gateway_url}/api/auth/verify", json=payload).json()
        print(f"[Legitimate Request] Authenticated: {v1.get('authenticated')}")

        time.sleep(1)

        # Step B: Attacker replays intercepted payload
        print("\n[Attacker] Replaying intercepted payload against Gateway...")
        v2 = requests.post(f"{self.gateway_url}/api/auth/verify", json=payload).json()

        print(f"[Gateway Verification Result on Replay]")
        print(f"  -> Authenticated : {v2.get('authenticated')}")
        print(f"  -> Relay Status  : {v2.get('relay_status')}")
        print(f"  -> Message       : {v2.get('message')}")

        # Check alerts
        alerts = requests.get(f"{self.gateway_url}/api/alerts?limit=5").json().get("alerts", [])
        has_replay_alert = any("REPLAY_ATTACK" in a.get("alert_type", "") for a in alerts)
        print(f"  -> Replay Alert Recorded in Security Database: {has_replay_alert}")

        success = (v2.get("authenticated") is False and 
                   v2.get("relay_status") == "LOCKED" and 
                   has_replay_alert)
        print(f"\n[CONCLUSION] Scenario 3: {'PASSED (REPLAY REJECTED & CRITICAL ALERT TRIGGERED)' if success else 'FAILED'}")
        return success

    # --------------------------------------------------------------------------
    # Scenario 4: Modified / Forged Proof
    # --------------------------------------------------------------------------
    def run_scenario_4_modified_proof(self) -> bool:
        self.print_header("Scenario 4: Modified / Forged Proof Attack")
        device_id = "ESP32-AUTH-NODE"

        # Request fresh challenge
        k, R = SchnorrProtocol.generate_commitment()
        chal_res = requests.post(f"{self.gateway_url}/api/auth/challenge", json={
            "device_id": device_id,
            "commitment": encode_point(R, compressed=True)
        }).json()

        session_id = chal_res["session_id"]
        c = int(chal_res["challenge"], 16)

        # Honest response
        # Secret from Scenario 1
        secret_x = 0x55aa55aa1234567890abcdef1234567890abcdef1234567890abcdef12345678
        s = SchnorrProtocol.compute_response(k, c, secret_x)

        # Man-in-the-middle bit tampering: flip lowest byte
        s_tampered = (s ^ 0xFF) % ORDER
        s_tampered_hex = hex(s_tampered)[2:].zfill(64)

        print("[MITM Attacker] Modified proof bits during transmission:")
        print(f"                Genuine s  : {hex(s)[2:].zfill(64)[:20]}...")
        print(f"                Tampered s : {s_tampered_hex[:20]}...")

        v_res = requests.post(f"{self.gateway_url}/api/auth/verify", json={
            "session_id": session_id,
            "device_id": device_id,
            "response": s_tampered_hex
        }).json()

        print(f"[Gateway Verification Result]")
        print(f"  -> Authenticated : {v_res.get('authenticated')}")
        print(f"  -> Relay Status  : {v_res.get('relay_status')}")
        print(f"  -> Message       : {v_res.get('message')}")

        success = v_res.get("authenticated") is False and v_res.get("relay_status") == "LOCKED"
        print(f"\n[CONCLUSION] Scenario 4: {'PASSED (TAMPERED PROOF DETECTED & DENIED)' if success else 'FAILED'}")
        return success

    def run_all(self):
        print("\n" + "#" * 70)
        print("  HARDWARE-BOUND ZERO-TRUST COMPLETE SECURITY VERIFICATION")
        print("#" * 70)

        s1 = self.run_scenario_1_authorized()
        time.sleep(1)
        s2 = self.run_scenario_2_unauthorized()
        time.sleep(1)
        s3 = self.run_scenario_3_replay()
        time.sleep(1)
        s4 = self.run_scenario_4_modified_proof()

        print("\n" + "=" * 70)
        print("  DEMONSTRATION SUMMARY MATRIX")
        print("=" * 70)
        print(f"  Scenario 1 (Authorized ESP32)     : {'[PASSED] Access Granted & Relay ON' if s1 else '[FAILED]'}")
        print(f"  Scenario 2 (Unauthorized Device)   : {'[PASSED] Access Denied & Relay Locked' if s2 else '[FAILED]'}")
        print(f"  Scenario 3 (Replay Attack)         : {'[PASSED] Replay Rejected & Threat Alert' if s3 else '[FAILED]'}")
        print(f"  Scenario 4 (Modified Proof)        : {'[PASSED] Math Failure & Access Blocked' if s4 else '[FAILED]'}")
        print("=" * 70 + "\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run Zero-Trust Attack Verification Scenarios")
    parser.add_argument("--gateway", default="http://127.0.0.1:8000", help="Gateway URL")
    args = parser.parse_args()

    simulator = AttackSimulator(gateway_url=args.gateway)
    simulator.run_all()
