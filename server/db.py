from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterable

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE,
    password_hash BLOB NOT NULL,
    otp_secret TEXT NOT NULL,
    signing_public_key TEXT NOT NULL,
    exchange_public_key TEXT NOT NULL,
    key_fingerprint TEXT NOT NULL,
    last_seen_at TEXT,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS sessions (
    token TEXT PRIMARY KEY,
    user_id INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS rate_limits (
    key TEXT NOT NULL,
    bucket TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    count INTEGER NOT NULL,
    PRIMARY KEY (key, bucket)
);

CREATE TABLE IF NOT EXISTS friend_requests (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    requester_id INTEGER NOT NULL,
    target_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending','accepted','rejected','cancelled')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    UNIQUE (requester_id, target_id),
    FOREIGN KEY (requester_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (target_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS contacts (
    user_id INTEGER NOT NULL,
    contact_id INTEGER NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('friends','blocked')),
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (user_id, contact_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (contact_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    message_id TEXT NOT NULL UNIQUE,
    session_id TEXT NOT NULL,
    sender_id INTEGER NOT NULL,
    recipient_id INTEGER NOT NULL,
    sender_username TEXT NOT NULL,
    recipient_username TEXT NOT NULL,
    sender_key_fingerprint TEXT NOT NULL,
    recipient_key_fingerprint TEXT NOT NULL,
    counter INTEGER NOT NULL,
    nonce TEXT NOT NULL,
    ad_json TEXT NOT NULL,
    ciphertext TEXT NOT NULL,
    signature TEXT NOT NULL,
    expires_at TEXT,
    sent_at TEXT NOT NULL,
    delivered_at TEXT,
    status TEXT NOT NULL CHECK (status IN ('queued','delivered','expired','deleted')),
    FOREIGN KEY (sender_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (recipient_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_messages_recipient_status ON messages(recipient_id, status, id);
CREATE INDEX IF NOT EXISTS idx_messages_sender_status ON messages(sender_id, status, id);
CREATE INDEX IF NOT EXISTS idx_friend_requests_target_status ON friend_requests(target_id, status);

CREATE TABLE IF NOT EXISTS status_updates (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id INTEGER NOT NULL,
    message_id TEXT NOT NULL,
    peer_username TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (owner_id) REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_status_updates_owner_id ON status_updates(owner_id, id);
"""


class Database:
    def __init__(self, path: str | Path):
        self.path = str(path)
        self._lock = threading.Lock()

    def connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def init_db(self) -> None:
        conn = self.connect()
        try:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def fetchone(self, sql: str, params: Iterable[Any] = ()) -> sqlite3.Row | None:
        conn = self.connect()
        try:
            cur = conn.execute(sql, tuple(params))
            return cur.fetchone()
        finally:
            conn.close()

    def fetchall(self, sql: str, params: Iterable[Any] = ()) -> list[sqlite3.Row]:
        conn = self.connect()
        try:
            cur = conn.execute(sql, tuple(params))
            return cur.fetchall()
        finally:
            conn.close()

    def execute(self, sql: str, params: Iterable[Any] = ()) -> int:
        conn = self.connect()
        try:
            cur = conn.execute(sql, tuple(params))
            conn.commit()
            return int(cur.lastrowid or 0)
        finally:
            conn.close()

    def executemany(self, sql: str, rows: Iterable[Iterable[Any]]) -> None:
        conn = self.connect()
        try:
            conn.executemany(sql, rows)
            conn.commit()
        finally:
            conn.close()

    @contextmanager
    def transaction(self):
        conn = self.connect()
        try:
            yield conn
        finally:
            conn.close()
