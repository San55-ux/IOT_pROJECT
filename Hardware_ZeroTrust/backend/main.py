"""
Hardware-Bound Zero-Trust Gateway Main Server Application
FastAPI server orchestrating SRAM PUF verification, Schnorr ZKP,
security telemetry, WebSocket broadcasting, and physical relay control.
"""

import os
import asyncio
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse

from backend.config import HOST, PORT, DEBUG, DASHBOARD_DIR
from backend.database.db import init_db
from backend.api.auth_routes import router as auth_router
from backend.api.device_routes import router as device_router
from backend.api.ws_routes import router as ws_router, ws_manager
from backend.services.auth_service import AuthService


async def relay_monitor_loop():
    """Background task to enforce relay auto-relock timer."""
    while True:
        try:
            status = AuthService.get_relay_status()
            if status.get("triggered_by") == "AUTO_RELOCK_TIMER":
                await ws_manager.broadcast({
                    "event": "RELAY_STATUS_CHANGED",
                    "relay_status": "LOCKED",
                    "triggered_by": "AUTO_RELOCK_TIMER"
                })
        except Exception:
            pass
        await asyncio.sleep(1.0)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application startup and shutdown hooks."""
    # Initialize database tables
    init_db()
    # Start background relay auto-lock monitor
    monitor_task = asyncio.create_task(relay_monitor_loop())
    yield
    monitor_task.cancel()


app = FastAPI(
    title="Hardware-Bound Zero-Trust Authentication Gateway",
    description="ESP32 SRAM PUF and Schnorr Zero-Knowledge Proof Authentication System",
    version="1.0.0",
    lifespan=lifespan
)

# Enable CORS for dashboard and external IoT requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.middleware("http")
async def add_no_cache_headers(request: Request, call_next):
    """Prevents aggressive browser caching of dashboard static assets during development."""
    response = await call_next(request)
    if (request.url.path.startswith("/static") or 
        request.url.path == "/" or 
        request.url.path.endswith(".css") or 
        request.url.path.endswith(".js")):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Pragma"] = "no-cache"
        response.headers["Expires"] = "0"
    return response

# Mount API routers (both /api prefix and root level for ESP32 conceptual routes)
app.include_router(auth_router, prefix="/api", tags=["Authentication"])
app.include_router(auth_router, tags=["Authentication Root"])
app.include_router(device_router, prefix="/api", tags=["Device Management"])
app.include_router(device_router, tags=["Device Management Root"])
app.include_router(ws_router, tags=["WebSockets"])

# Serve dashboard static assets (both /static and root for relative asset paths)
if DASHBOARD_DIR.exists():
    app.mount("/static", StaticFiles(directory=str(DASHBOARD_DIR)), name="static")
    app.mount("/", StaticFiles(directory=str(DASHBOARD_DIR), html=True), name="dashboard_root")
else:
    @app.get("/")
    async def root():
        return {"message": "Zero-Trust Gateway Online. Dashboard directory not found."}


@app.get("/health")
async def health():
    """Gateway health check."""
    return {"status": "HEALTHY", "system": "Zero-Trust ESP32 PUF Gateway"}


if __name__ == "__main__":
    import uvicorn
    print(f"Starting Zero-Trust Gateway on http://{HOST}:{PORT}")
    uvicorn.run("backend.main:app", host=HOST, port=PORT, reload=DEBUG)
