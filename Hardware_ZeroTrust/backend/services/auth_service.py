"""
Zero-Trust Authentication Service
Implements challenge generation, session tracking, replay attack detection,
Schnorr proof verification, and relay access state transitions.
"""

import time
import uuid
from datetime import datetime, timedelta, timezone
from typing import Dict, Any, Optional, Tuple

from backend.config import CHALLENGE_TTL_SECONDS, RELAY_UNLOCK_DURATION_SECONDS
from backend.database.db import Database
from backend.crypto.schnorr_verifier import (
    SchnorrProtocol, decode_point, encode_point, Point
)
from backend.services.alert_service import AlertService


class AuthService:
    """Core Zero-Trust authentication and access control controller."""

    @staticmethod
    def register_device(
        device_id: str,
        mac_address: str,
        chip_model: str,
        chip_revision: int,
        public_key_hex: str,
        helper_data: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Enrolls/registers an ESP32 hardware device with its Schnorr public key.
        Enforces Zero-Trust default: newly registered devices start as 'UNTRUSTED'
        until a successful Schnorr proof is verified.
        """
        # Validate public key format on elliptic curve
        try:
            pt = decode_point(public_key_hex)
        except Exception as e:
            raise ValueError(f"Invalid public key encoding: {str(e)}")

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        existing = Database.fetch_one("SELECT id FROM devices WHERE device_id = ?", (device_id,))

        if existing:
            query = """
                UPDATE devices
                SET mac_address = ?, chip_model = ?, chip_revision = ?,
                    public_key = ?, helper_data = ?, trust_status = 'UNTRUSTED',
                    last_seen = ?
                WHERE device_id = ?
            """
            Database.execute(query, (
                mac_address, chip_model, chip_revision,
                public_key_hex, helper_data, now, device_id
            ))
            message = "Device registration updated. Current status: UNTRUSTED (pending proof)."
        else:
            query = """
                INSERT INTO devices (
                    device_id, mac_address, chip_model, chip_revision,
                    public_key, helper_data, trust_status, registration_time, last_seen
                ) VALUES (?, ?, ?, ?, ?, ?, 'UNTRUSTED', ?, ?)
            """
            Database.execute(query, (
                device_id, mac_address, chip_model, chip_revision,
                public_key_hex, helper_data, now, now
            ))
            message = "Device enrolled successfully. Current status: UNTRUSTED (Zero-Trust baseline)."

        return {
            "success": True,
            "message": message,
            "device_id": device_id,
            "trust_status": "UNTRUSTED"
        }

    @staticmethod
    def create_challenge(device_id: str, commitment_hex: str) -> Dict[str, Any]:
        """
        Initiates 3-pass Schnorr Identification:
        1. Validates device identity in directory
        2. Validates commitment point R
        3. Generates fresh random challenge c with strict TTL
        """
        device = Database.fetch_one("SELECT device_id FROM devices WHERE device_id = ?", (device_id,))
        if not device:
            AlertService.record_alert(
                alert_type="UNKNOWN_DEVICE_ACCESS",
                description=f"Unregistered device '{device_id}' attempted authentication initiation.",
                severity="HIGH",
                device_id=device_id
            )
            raise ValueError(f"Device '{device_id}' is not enrolled in Zero-Trust Gateway.")

        # Validate commitment point R is valid curve point
        try:
            R = decode_point(commitment_hex)
        except Exception as e:
            raise ValueError(f"Invalid Schnorr commitment point R: {str(e)}")

        session_id = str(uuid.uuid4())
        challenge_int = SchnorrProtocol.generate_challenge()
        challenge_hex = hex(challenge_int)[2:].zfill(64)

        now = datetime.now(timezone.utc)
        expires_at = now + timedelta(seconds=CHALLENGE_TTL_SECONDS)

        query = """
            INSERT INTO auth_sessions (
                session_id, device_id, commitment, challenge, created_at, expires_at, used
            ) VALUES (?, ?, ?, ?, ?, ?, 0)
        """
        Database.execute(query, (
            session_id, device_id, commitment_hex, challenge_hex,
            now.strftime("%Y-%m-%d %H:%M:%S"),
            expires_at.strftime("%Y-%m-%d %H:%M:%S")
        ))

        return {
            "session_id": session_id,
            "device_id": device_id,
            "challenge": challenge_hex,
            "expires_in_seconds": CHALLENGE_TTL_SECONDS
        }

    @staticmethod
    def verify_proof(
        session_id: str,
        device_id: str,
        response_hex: str,
        client_ip: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Verifies the Schnorr response s:
        - Detects replay attacks (consumed or expired session)
        - Verifies s * G == R + c * Y
        - Manages Zero-Trust state and physical relay lock/unlock
        """
        start_time = time.time()
        now_dt = datetime.now(timezone.utc)
        now_str = now_dt.strftime("%Y-%m-%d %H:%M:%S")

        # 1. Lookup session
        session = Database.fetch_one(
            "SELECT * FROM auth_sessions WHERE session_id = ?", (session_id,)
        )

        if not session:
            latency = (time.time() - start_time) * 1000.0
            AlertService.record_alert(
                alert_type="INVALID_SESSION_ATTEMPT",
                description=f"Verification attempted with non-existent session ID: {session_id}",
                severity="HIGH",
                device_id=device_id
            )
            AuthService._log_attempt(device_id, "FAILED", latency, "Invalid session ID", client_ip)
            return {
                "authenticated": False,
                "trust_status": "UNTRUSTED",
                "message": "Authentication failed: Session not found.",
                "relay_status": AuthService.get_relay_status()["status"],
                "latency_ms": round(latency, 2)
            }

        # 2. Replay attack check: Has session already been used?
        if session["used"] == 1:
            latency = (time.time() - start_time) * 1000.0
            # REPLAY ATTACK DETECTED
            AlertService.record_alert(
                alert_type="REPLAY_ATTACK_DETECTED",
                description=(
                    f"CRITICAL: Replay attack detected for device '{device_id}'! "
                    f"Session '{session_id}' has already been consumed."
                ),
                severity="CRITICAL",
                device_id=device_id
            )
            # Demote device to untrusted
            Database.execute(
                "UPDATE devices SET trust_status = 'UNTRUSTED', auth_fail_count = auth_fail_count + 1 WHERE device_id = ?",
                (device_id,)
            )
            AuthService._log_attempt(device_id, "REPLAY_ATTACK", latency, "Session reuse detected", client_ip)
            return {
                "authenticated": False,
                "trust_status": "UNTRUSTED",
                "message": "SECURITY ALERT: Replay attack detected! Session already consumed.",
                "relay_status": "LOCKED",
                "latency_ms": round(latency, 2)
            }

        # 3. Check expiration
        expires_at = datetime.strptime(session["expires_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
        if now_dt > expires_at:
            # Mark session as used to prevent further attempts
            Database.execute("UPDATE auth_sessions SET used = 1 WHERE session_id = ?", (session_id,))
            latency = (time.time() - start_time) * 1000.0
            AlertService.record_alert(
                alert_type="CHALLENGE_TIMEOUT",
                description=f"Challenge response submitted after TTL expiration ({CHALLENGE_TTL_SECONDS}s).",
                severity="WARNING",
                device_id=device_id
            )
            AuthService._log_attempt(device_id, "FAILED", latency, "Challenge expired", client_ip)
            return {
                "authenticated": False,
                "trust_status": "UNTRUSTED",
                "message": "Authentication failed: Challenge expired.",
                "relay_status": AuthService.get_relay_status()["status"],
                "latency_ms": round(latency, 2)
            }

        # Mark session as consumed immediately to eliminate race conditions
        Database.execute("UPDATE auth_sessions SET used = 1 WHERE session_id = ?", (session_id,))

        # 4. Fetch device public key
        device = Database.fetch_one("SELECT * FROM devices WHERE device_id = ?", (device_id,))
        if not device:
            latency = (time.time() - start_time) * 1000.0
            AlertService.record_alert(
                alert_type="UNKNOWN_DEVICE_ACCESS",
                description=f"Device '{device_id}' not found during verification stage.",
                severity="HIGH",
                device_id=device_id
            )
            AuthService._log_attempt(device_id, "UNKNOWN_DEVICE", latency, "Device not registered", client_ip)
            return {
                "authenticated": False,
                "trust_status": "UNTRUSTED",
                "message": "Authentication failed: Device not found.",
                "relay_status": "LOCKED",
                "latency_ms": round(latency, 2)
            }

        # 5. Cryptographic Verification
        try:
            pub_key = decode_point(device["public_key"])
            commitment = decode_point(session["commitment"])
            challenge = int(session["challenge"], 16)
            response = int(response_hex, 16)

            is_valid = SchnorrProtocol.verify_proof(pub_key, commitment, challenge, response)
        except Exception as e:
            is_valid = False

        latency = (time.time() - start_time) * 1000.0

        if is_valid:
            # Zero-Trust verification successful
            Database.execute("""
                UPDATE devices
                SET trust_status = 'TRUSTED', auth_success_count = auth_success_count + 1, last_seen = ?
                WHERE device_id = ?
            """, (now_str, device_id))

            # Trigger Relay Unlock
            auto_lock = (now_dt + timedelta(seconds=RELAY_UNLOCK_DURATION_SECONDS)).strftime("%Y-%m-%d %H:%M:%S")
            Database.execute("""
                UPDATE relay_state
                SET status = 'UNLOCKED', last_changed = ?, triggered_by = ?, auto_lock_at = ?
                WHERE id = 1
            """, (now_str, device_id, auto_lock))

            AuthService._log_attempt(device_id, "SUCCESS", latency, None, client_ip)

            return {
                "authenticated": True,
                "trust_status": "TRUSTED",
                "message": "Schnorr Zero-Knowledge Proof verified successfully. Hardware PUF identity confirmed.",
                "relay_status": "UNLOCKED",
                "latency_ms": round(latency, 2)
            }
        else:
            # Verification failed: invalid secret / tampered proof
            Database.execute("""
                UPDATE devices
                SET trust_status = 'UNTRUSTED', auth_fail_count = auth_fail_count + 1, last_seen = ?
                WHERE device_id = ?
            """, (now_str, device_id))

            # Ensure relay is locked
            Database.execute("""
                UPDATE relay_state
                SET status = 'LOCKED', last_changed = ?, triggered_by = 'AUTH_FAILURE_LOCK'
                WHERE id = 1
            """, (now_str,))

            AlertService.record_alert(
                alert_type="INVALID_SCHNORR_PROOF",
                description=(
                    f"Schnorr proof verification equation s*G == R + c*Y failed for device '{device_id}'. "
                    f"Possible cloned device, corrupted PUF response, or tampered payload."
                ),
                severity="CRITICAL",
                device_id=device_id
            )

            AuthService._log_attempt(device_id, "FAILED", latency, "Invalid Schnorr proof", client_ip)

            return {
                "authenticated": False,
                "trust_status": "UNTRUSTED",
                "message": "Authentication rejected: Invalid cryptographic proof.",
                "relay_status": "LOCKED",
                "latency_ms": round(latency, 2)
            }

    @staticmethod
    def _log_attempt(
        device_id: str,
        result: str,
        latency_ms: float,
        failure_reason: Optional[str] = None,
        client_ip: Optional[str] = None
    ):
        """Records an authentication event in the database."""
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        query = """
            INSERT INTO authentication_logs (device_id, timestamp, result, latency_ms, failure_reason, client_ip)
            VALUES (?, ?, ?, ?, ?, ?)
        """
        Database.execute(query, (device_id, now, result, latency_ms, failure_reason, client_ip))

    @staticmethod
    def get_relay_status() -> Dict[str, Any]:
        """
        Returns current physical relay state, enforcing automatic relock timer.
        """
        row = Database.fetch_one("SELECT * FROM relay_state WHERE id = 1")
        if not row:
            return {"status": "LOCKED", "last_changed": None, "triggered_by": "DEFAULT"}

        # Auto-relock check
        if row["status"] == "UNLOCKED" and row["auto_lock_at"]:
            now = datetime.now(timezone.utc)
            auto_lock_time = datetime.strptime(row["auto_lock_at"], "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc)
            if now >= auto_lock_time:
                now_str = now.strftime("%Y-%m-%d %H:%M:%S")
                Database.execute("""
                    UPDATE relay_state
                    SET status = 'LOCKED', last_changed = ?, triggered_by = 'AUTO_RELOCK_TIMER', auto_lock_at = NULL
                    WHERE id = 1
                """, (now_str,))
                return {"status": "LOCKED", "last_changed": now_str, "triggered_by": "AUTO_RELOCK_TIMER"}

        return dict(row)

    @staticmethod
    def set_relay_override(status: str, duration_seconds: int = 5, reason: str = "MANUAL_OVERRIDE") -> Dict[str, Any]:
        """Manual administrative override of the relay state."""
        now = datetime.now(timezone.utc)
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")
        auto_lock = None

        if status == "UNLOCKED":
            auto_lock = (now + timedelta(seconds=duration_seconds)).strftime("%Y-%m-%d %H:%M:%S")

        Database.execute("""
            UPDATE relay_state
            SET status = ?, last_changed = ?, triggered_by = ?, auto_lock_at = ?
            WHERE id = 1
        """, (status, now_str, reason, auto_lock))

        return {
            "status": status,
            "last_changed": now_str,
            "triggered_by": reason,
            "auto_lock_at": auto_lock
        }
