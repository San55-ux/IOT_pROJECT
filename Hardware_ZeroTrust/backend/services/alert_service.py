"""
Security Alert Service
Records security events and notifies real-time listeners.
"""

from typing import Optional, Dict, Any, List
from datetime import datetime, timezone
from backend.database.db import Database


class AlertService:
    """Manages recording, querying, and dispatching security alerts."""

    @staticmethod
    def record_alert(
        alert_type: str,
        description: str,
        severity: str = "HIGH",
        device_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Inserts a new security alert into the database and returns the record.
        Severity levels: INFO, WARNING, HIGH, CRITICAL
        """
        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        query = """
            INSERT INTO security_alerts (device_id, alert_type, description, timestamp, severity, resolved)
            VALUES (?, ?, ?, ?, ?, 0)
        """
        alert_id = Database.execute(query, (device_id, alert_type, description, now, severity))

        alert_data = {
            "id": alert_id,
            "device_id": device_id,
            "alert_type": alert_type,
            "description": description,
            "timestamp": now,
            "severity": severity,
            "resolved": 0
        }
        return alert_data

    @staticmethod
    def get_recent_alerts(limit: int = 50) -> List[Dict[str, Any]]:
        """Fetches the most recent security alerts."""
        query = """
            SELECT id, device_id, alert_type, description, timestamp, severity, resolved
            FROM security_alerts
            ORDER BY id DESC
            LIMIT ?
        """
        return Database.fetch_all(query, (limit,))

    @staticmethod
    def resolve_alert(alert_id: int):
        """Marks an alert as resolved."""
        query = "UPDATE security_alerts SET resolved = 1 WHERE id = ?"
        Database.execute(query, (alert_id,))
