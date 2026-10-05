"""
System Configuration Settings for Zero-Trust Gateway
"""

import os
from pathlib import Path

# Paths
BASE_DIR = Path(__file__).resolve().parent.parent
DB_DIR = BASE_DIR / "database"
DB_DIR.mkdir(parents=True, exist_ok=True)
DATABASE_PATH = DB_DIR / "zerotrust.db"

DASHBOARD_DIR = BASE_DIR / "dashboard"

# Network & Server Settings
HOST = os.getenv("GATEWAY_HOST", "0.0.0.0")
PORT = int(os.getenv("GATEWAY_PORT", "8000"))
DEBUG = os.getenv("GATEWAY_DEBUG", "True").lower() == "true"

# Security & Protocol Timers
CHALLENGE_TTL_SECONDS = 30  # Challenge expires after 30 seconds
RELAY_UNLOCK_DURATION_SECONDS = 5  # Relay stays unlocked for 5s upon successful auth
MAX_FAILED_ATTEMPTS = 5  # Threshold before temporary device lockout

# Zero-Trust Policy Defaults
DEFAULT_TRUST_STATUS = "UNTRUSTED"
REQUIRE_FRESH_CHALLENGE = True
