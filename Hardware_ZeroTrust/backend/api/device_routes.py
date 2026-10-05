"""
Device Management, Logs, Security Alerts, and Relay API Endpoints
"""

from typing import List, Optional
from fastapi import APIRouter, HTTPException, Query
from backend.models.schemas import (
    DeviceRegisterRequest, DeviceRegisterResponse,
    RelayOverrideRequest
)
from backend.services.auth_service import AuthService
from backend.services.alert_service import AlertService
from backend.crypto.puf_helper import PUFMetricsEvaluator
from backend.database.db import Database
from backend.api.ws_routes import ws_manager

router = APIRouter()


@router.post("/device/register", response_model=DeviceRegisterResponse)
async def register_device(req: DeviceRegisterRequest):
    """
    Enrolls a new ESP32 device into the Zero-Trust Gateway directory.
    Stores device ID, eFuse MAC, and Schnorr Public Key Y.
    Sets trust status to UNTRUSTED by default.
    """
    try:
        res = AuthService.register_device(
            device_id=req.device_id,
            mac_address=req.mac_address,
            chip_model=req.chip_model or "ESP32",
            chip_revision=req.chip_revision or 1,
            public_key_hex=req.public_key,
            helper_data=req.helper_data
        )

        await ws_manager.broadcast({
            "event": "DEVICE_REGISTERED",
            "device_id": req.device_id,
            "mac_address": req.mac_address,
            "trust_status": "UNTRUSTED"
        })
        return res
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Registration error: {str(e)}")


@router.get("/devices")
async def list_devices():
    """Lists all registered IoT devices with trust and authentication counts."""
    query = """
        SELECT id, device_id, mac_address, chip_model, chip_revision,
               public_key, trust_status, registration_time, last_seen,
               auth_success_count, auth_fail_count
        FROM devices
        ORDER BY id ASC
    """
    devices = Database.fetch_all(query)
    return {"devices": devices, "total": len(devices)}


@router.get("/device/{device_id}/status")
async def get_device_status(device_id: str):
    """Retrieves full status and authentication profile for a specific device."""
    query = "SELECT * FROM devices WHERE device_id = ?"
    device = Database.fetch_one(query, (device_id,))
    if not device:
        raise HTTPException(status_code=404, detail=f"Device '{device_id}' not found.")
    return device


@router.get("/logs")
async def get_logs(limit: int = Query(50, ge=1, le=500)):
    """Retrieves historical authentication logs for Zero-Trust audit trail."""
    query = """
        SELECT id, device_id, timestamp, result, latency_ms, failure_reason, client_ip
        FROM authentication_logs
        ORDER BY id DESC
        LIMIT ?
    """
    logs = Database.fetch_all(query, (limit,))
    return {"logs": logs, "count": len(logs)}


@router.get("/alerts")
async def get_alerts(limit: int = Query(50, ge=1, le=500)):
    """Retrieves recent security alerts (e.g. replay attacks, forged proofs)."""
    alerts = AlertService.get_recent_alerts(limit=limit)
    return {"alerts": alerts, "count": len(alerts)}


@router.post("/alerts/{alert_id}/resolve")
async def resolve_alert(alert_id: int):
    """Marks a security alert as resolved."""
    AlertService.resolve_alert(alert_id)
    await ws_manager.broadcast({
        "event": "ALERT_RESOLVED",
        "alert_id": alert_id
    })
    return {"success": True, "alert_id": alert_id, "resolved": 1}


@router.get("/relay/status")
async def get_relay():
    """Returns current physical relay state (LOCKED / UNLOCKED)."""
    return AuthService.get_relay_status()


@router.post("/relay/override")
async def override_relay(req: RelayOverrideRequest):
    """Administrative manual override of the physical relay."""
    result = AuthService.set_relay_override(
        status=req.status,
        duration_seconds=req.duration_seconds or 5,
        reason=req.reason or "MANUAL_OVERRIDE"
    )
    await ws_manager.broadcast({
        "event": "RELAY_STATUS_CHANGED",
        "relay_status": result["status"],
        "triggered_by": result["triggered_by"]
    })
    return result


@router.get("/puf/metrics")
async def get_puf_metrics():
    """
    Computes and returns academic statistical PUF metrics:
    Intra-device HD, Inter-device HD, Bit Error Rate (BER),
    PUF reliability, Uniqueness, and Shannon Entropy.
    """
    metrics = PUFMetricsEvaluator.evaluate_system_benchmarks()
    return metrics
