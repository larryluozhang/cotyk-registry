import json
import os
import sqlite3
import threading
import time


SCHEMA = """
CREATE TABLE IF NOT EXISTS bridges (
    bridge_id        TEXT PRIMARY KEY,
    realm_id         TEXT NOT NULL,
    host_name        TEXT NOT NULL,
    endpoint         TEXT NOT NULL,
    public_key       TEXT NOT NULL,
    capabilities     TEXT NOT NULL,
    reported_status  TEXT NOT NULL DEFAULT 'offline',
    last_seen        INTEGER NOT NULL,
    registration_seq INTEGER NOT NULL,
    registered_at    INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_bridges_realm ON bridges(realm_id);
"""


class Database:
    def __init__(self, path):
        self._path = path
        self._lock = threading.Lock()
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def register(self, record):
        """Insert or update a bridge. Returns the new registration_seq."""
        now = int(time.time())
        with self._lock:
            cur = self._conn.execute(
                "SELECT registration_seq FROM bridges WHERE bridge_id = ?",
                (record["bridge_id"],),
            )
            row = cur.fetchone()
            seq = (row["registration_seq"] + 1) if row else 1
            self._conn.execute(
                """
                INSERT INTO bridges (bridge_id, realm_id, host_name, endpoint,
                                     public_key, capabilities, reported_status,
                                     last_seen, registration_seq, registered_at)
                VALUES (?, ?, ?, ?, ?, ?, 'online', ?, ?, ?)
                ON CONFLICT(bridge_id) DO UPDATE SET
                    realm_id = excluded.realm_id,
                    host_name = excluded.host_name,
                    endpoint = excluded.endpoint,
                    public_key = excluded.public_key,
                    capabilities = excluded.capabilities,
                    reported_status = 'online',
                    last_seen = excluded.last_seen,
                    registration_seq = excluded.registration_seq
                """,
                (
                    record["bridge_id"], record["realm_id"], record["host_name"],
                    record["endpoint"], record["public_key"],
                    json.dumps(record["capabilities"], sort_keys=True, separators=(",", ":")),
                    now, seq, now,
                ),
            )
            self._conn.commit()
            return seq

    def heartbeat(self, bridge_id, status):
        """Update last_seen (and reported status). Returns True if bridge exists."""
        now = int(time.time())
        with self._lock:
            cur = self._conn.execute(
                "UPDATE bridges SET last_seen = ?, reported_status = ? WHERE bridge_id = ?",
                (now, status, bridge_id),
            )
            self._conn.commit()
            return cur.rowcount > 0

    def get(self, bridge_id):
        with self._lock:
            row = self._conn.execute(
                "SELECT * FROM bridges WHERE bridge_id = ?", (bridge_id,)
            ).fetchone()
            return dict(row) if row else None

    def list_by_realm(self, realm_id):
        with self._lock:
            rows = self._conn.execute(
                "SELECT * FROM bridges WHERE realm_id = ? ORDER BY bridge_id",
                (realm_id,),
            ).fetchall()
            return [dict(r) for r in rows]

    def delete(self, bridge_id):
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM bridges WHERE bridge_id = ?", (bridge_id,)
            )
            self._conn.commit()
            return cur.rowcount > 0
