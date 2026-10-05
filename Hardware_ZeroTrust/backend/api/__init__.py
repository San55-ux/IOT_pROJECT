"""API router package initialization."""
from backend.api.auth_routes import router as auth_router
from backend.api.device_routes import router as device_router
from backend.api.ws_routes import router as ws_router, ws_manager
