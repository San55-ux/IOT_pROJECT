"""
Authentication API Endpoints
Implements challenge generation, proof verification, and replay rejection.
"""

from fastapi import APIRouter, HTTPException, Request
from backend.models.schemas import (
    AuthChallengeRequest, AuthChallengeResponse,
    AuthVerifyRequest, AuthVerifyResponse
)
from backend.services.auth_service import AuthService
from backend.services.alert_service import AlertService
from backend.api.ws_routes import ws_manager

router = APIRouter()


@router.post("/auth/challenge", response_model=AuthChallengeResponse)
async def generate_challenge(req: AuthChallengeRequest):
    """
    Step 1: ESP32 Prover submits commitment point R = k * G.
    Gateway Verifier returns single-use ephemeral challenge c.
    """
    try:
        challenge_data = AuthService.create_challenge(
            device_id=req.device_id,
            commitment_hex=req.commitment
        )
        # Notify dashboard of challenge initiation
        await ws_manager.broadcast({
            "event": "AUTH_CHALLENGE_ISSUED",
            "device_id": req.device_id,
            "session_id": challenge_data["session_id"],
            "expires_in": challenge_data["expires_in_seconds"]
        })
        return challenge_data
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Internal challenge generation error: {str(e)}")


@router.post("/auth/verify", response_model=AuthVerifyResponse)
async def verify_proof(req: AuthVerifyRequest, request: Request):
    """
    Step 2: ESP32 Prover submits response scalar s = (k + c * x) mod q.
    Gateway Verifier checks s * G == R + c * Y, updates trust status,
    and commands physical relay access.
    """
    client_ip = request.client.host if request.client else "unknown"
    result = AuthService.verify_proof(
        session_id=req.session_id,
        device_id=req.device_id,
        response_hex=req.response,
        client_ip=client_ip
    )

    # Broadcast event to real-time dashboard
    await ws_manager.broadcast({
        "event": "AUTH_VERIFICATION_COMPLETE",
        "device_id": req.device_id,
        "authenticated": result["authenticated"],
        "trust_status": result["trust_status"],
        "relay_status": result["relay_status"],
        "latency_ms": result["latency_ms"],
        "message": result["message"]
    })

    # If verification caused an alert, broadcast alerts update
    if not result["authenticated"]:
        recent_alerts = AlertService.get_recent_alerts(limit=5)
        await ws_manager.broadcast({
            "event": "SECURITY_ALERT",
            "alerts": recent_alerts
        })

    return result
