"""
Database access and management layer using SQLite with row factory and connection lifecycle.
"""

import sqlite3
import threading
from typing import List, Dict, Any, Optional
from datetime import datetime
from backend.config import DATABASE_PATH

_lock = threading.Lock()


def get_db_connection() -> sqlite3.Connection:
    """Creates a thread-safe connection to the SQLite database with dictionary rows."""
    conn = sqlite3.connect(str(DATABASE_PATH), timeout=10.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Initializes database schema from schema.sql."""
    with _lock:
        conn = get_db_connection()
        try:
            schema_path = DATABASE_PATH.parent.parent / "backend" / "database" / "schema.sql"
            with open(schema_path, "r", encoding="utf-8") as f:
                schema_sql = f.read()
            conn.executescript(schema_sql)
            conn.commit()
        finally:
            conn.close()


class Database:
    """Helper methods for database operations."""

    @staticmethod
    def execute(query: str, params: tuple = ()) -> int:
        """Executes INSERT/UPDATE/DELETE and returns lastrowid or rowcount."""
        with _lock:
            conn = get_db_connection()
            try:
                cur = conn.cursor()
                cur.execute(query, params)
                conn.commit()
                return cur.lastrowid
            finally:
                conn.close()

    @staticmethod
    def fetch_one(query: str, params: tuple = ()) -> Optional[Dict[str, Any]]:
        """Fetches a single row as a dictionary."""
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(query, params)
            row = cur.fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    @staticmethod
    def fetch_all(query: str, params: tuple = ()) -> List[Dict[str, Any]]:
        """Fetches all rows as a list of dictionaries."""
        conn = get_db_connection()
        try:
            cur = conn.cursor()
            cur.execute(query, params)
            rows = cur.fetchall()
            return [dict(r) for r in rows]
        finally:
            conn.close()
