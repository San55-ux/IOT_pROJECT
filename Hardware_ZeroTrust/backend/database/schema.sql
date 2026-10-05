-- Zero-Trust Hardware-Bound Authentication System Database Schema

CREATE TABLE IF NOT EXISTS devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT UNIQUE NOT NULL,
    mac_address TEXT NOT NULL,
    chip_model TEXT DEFAULT 'ESP32',
    chip_revision INTEGER DEFAULT 1,
    public_key TEXT NOT NULL,
    helper_data TEXT,
    trust_status TEXT DEFAULT 'UNTRUSTED',
    registration_time TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    auth_success_count INTEGER DEFAULT 0,
    auth_fail_count INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS auth_sessions (
    session_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL,
    commitment TEXT NOT NULL,
    challenge TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    used INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS authentication_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    result TEXT NOT NULL,
    latency_ms REAL DEFAULT 0.0,
    failure_reason TEXT,
    client_ip TEXT
);

CREATE TABLE IF NOT EXISTS security_alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    device_id TEXT,
    alert_type TEXT NOT NULL,
    description TEXT NOT NULL,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    severity TEXT NOT NULL,
    resolved INTEGER DEFAULT 0
);

CREATE TABLE IF NOT EXISTS relay_state (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    status TEXT NOT NULL DEFAULT 'LOCKED',
    last_changed TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    triggered_by TEXT DEFAULT 'SYSTEM_INIT',
    auto_lock_at TIMESTAMP
);

-- Seed initial relay row
INSERT OR IGNORE INTO relay_state (id, status, triggered_by) VALUES (1, 'LOCKED', 'SYSTEM_INIT');

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_devices_device_id ON devices(device_id);
CREATE INDEX IF NOT EXISTS idx_auth_sessions_device ON auth_sessions(device_id);
CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON authentication_logs(timestamp);
CREATE INDEX IF NOT EXISTS idx_alerts_timestamp ON security_alerts(timestamp);
