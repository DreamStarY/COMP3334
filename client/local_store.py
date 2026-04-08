from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from common.utils import iso_now

SCHEMA_SQL = """
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS contacts (
    username TEXT PRIMARY KEY,
    signing_public_key TEXT NOT NULL,
    exchange_public_key TEXT NOT NULL,
    trusted_key_fingerprint TEXT,
    current_key_fingerprint TEXT NOT NULL,
    verified INTEGER NOT NULL DEFAULT 0,
    key_changed INTEGER NOT NULL DEFAULT 0,
    blocked INTEGER NOT NULL DEFAULT 0,
    last_activity TEXT,
    unread_count INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS conversation_state (
    peer TEXT PRIMARY KEY,
    next_out_counter INTEGER NOT NULL DEFAULT 1,
    last_in_counter INTEGER NOT NULL DEFAULT 0,
    session_id TEXT
);

CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id TEXT NOT NULL UNIQUE,
    peer TEXT NOT NULL,
    direction TEXT NOT NULL,
    kind TEXT NOT NULL,
    body TEXT NOT NULL,
    sent_at TEXT NOT NULL,
    expires_at TEXT,
    status TEXT NOT NULL,
    counter INTEGER NOT NULL,
    session_id TEXT NOT NULL,
    read_flag INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_messages_peer_sent_at ON messages(peer, sent_at DESC);

CREATE TABLE IF NOT EXISTS seen_messages (
    msg_id TEXT PRIMARY KEY,
    peer TEXT NOT NULL,
    counter INTEGER NOT NULL,
    seen_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
    key TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
"""


class LocalStore:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        return conn

    def _init_db(self) -> None:
        conn = self._connect()
        try:
            conn.executescript(SCHEMA_SQL)
            conn.commit()
        finally:
            conn.close()

    def get_setting(self, key: str, default: str = "") -> str:
        conn = self._connect()
        try:
            row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default
        finally:
            conn.close()

    def set_setting(self, key: str, value: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                (key, value),
            )
            conn.commit()
        finally:
            conn.close()

    def upsert_contact(
        self,
        username: str,
        signing_public_key: str,
        exchange_public_key: str,
        key_fingerprint: str,
        blocked: bool = False,
    ) -> None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT trusted_key_fingerprint, current_key_fingerprint, verified FROM contacts WHERE username = ?",
                (username,),
            ).fetchone()
            if row is None:
                conn.execute(
                    """
                    INSERT INTO contacts(
                        username, signing_public_key, exchange_public_key,
                        trusted_key_fingerprint, current_key_fingerprint,
                        verified, key_changed, blocked, last_activity, unread_count
                    ) VALUES (?, ?, ?, ?, ?, 0, 0, ?, NULL, 0)
                    """,
                    (username, signing_public_key, exchange_public_key, key_fingerprint, key_fingerprint, int(blocked)),
                )
            else:
                trusted_fp = row["trusted_key_fingerprint"]
                verified = int(row["verified"])
                key_changed = 1 if trusted_fp and trusted_fp != key_fingerprint else 0
                if blocked:
                    key_changed = 0 if not trusted_fp else key_changed
                conn.execute(
                    """
                    UPDATE contacts
                    SET signing_public_key = ?, exchange_public_key = ?, current_key_fingerprint = ?,
                        key_changed = ?, blocked = ?
                    WHERE username = ?
                    """,
                    (signing_public_key, exchange_public_key, key_fingerprint, key_changed, int(blocked), username),
                )
                if not trusted_fp:
                    conn.execute(
                        "UPDATE contacts SET trusted_key_fingerprint = ?, verified = ? WHERE username = ?",
                        (key_fingerprint, verified, username),
                    )
            conn.execute(
                "INSERT INTO conversation_state(peer) VALUES (?) ON CONFLICT(peer) DO NOTHING",
                (username,),
            )
            conn.commit()
        finally:
            conn.close()

    def mark_contact_verified(self, username: str, verified: bool = True) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE contacts SET verified = ?, trusted_key_fingerprint = current_key_fingerprint, key_changed = 0 WHERE username = ?",
                (int(verified), username),
            )
            conn.commit()
        finally:
            conn.close()

    def trust_new_key(self, username: str) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "UPDATE contacts SET trusted_key_fingerprint = current_key_fingerprint, key_changed = 0, verified = 0 WHERE username = ?",
                (username,),
            )
            conn.commit()
        finally:
            conn.close()

    def remove_contact(self, username: str) -> None:
        conn = self._connect()
        try:
            conn.execute("DELETE FROM contacts WHERE username = ?", (username,))
            conn.execute("DELETE FROM conversation_state WHERE peer = ?", (username,))
            conn.commit()
        finally:
            conn.close()

    def list_contacts(self) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute("SELECT * FROM contacts ORDER BY COALESCE(last_activity, ''), username").fetchall()
            return [dict(row) for row in rows[::-1]]
        finally:
            conn.close()

    def get_contact(self, username: str) -> dict[str, Any] | None:
        conn = self._connect()
        try:
            row = conn.execute("SELECT * FROM contacts WHERE username = ?", (username,)).fetchone()
            return dict(row) if row else None
        finally:
            conn.close()

    def get_or_create_counter(self, peer: str) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT next_out_counter FROM conversation_state WHERE peer = ?",
                (peer,),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO conversation_state(peer, next_out_counter, last_in_counter) VALUES (?, 1, 0)",
                    (peer,),
                )
                conn.commit()
                return 1
            return int(row["next_out_counter"])
        finally:
            conn.close()

    def consume_next_counter(self, peer: str, session_id: str) -> int:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT next_out_counter FROM conversation_state WHERE peer = ?",
                (peer,),
            ).fetchone()
            next_counter = int(row["next_out_counter"]) if row else 1
            conn.execute(
                "INSERT INTO conversation_state(peer, next_out_counter, last_in_counter, session_id) VALUES (?, ?, 0, ?) ON CONFLICT(peer) DO UPDATE SET next_out_counter = ?, session_id = ?",
                (peer, next_counter + 1, session_id, next_counter + 1, session_id),
            )
            conn.commit()
            return next_counter
        finally:
            conn.close()

    def update_last_in_counter(self, peer: str, counter: int, session_id: str) -> None:
        conn = self._connect()
        try:
            row = conn.execute(
                "SELECT last_in_counter FROM conversation_state WHERE peer = ?",
                (peer,),
            ).fetchone()
            current = int(row["last_in_counter"]) if row else 0
            new_value = max(current, counter)
            conn.execute(
                "INSERT INTO conversation_state(peer, next_out_counter, last_in_counter, session_id) VALUES (?, 1, ?, ?) ON CONFLICT(peer) DO UPDATE SET last_in_counter = ?, session_id = ?",
                (peer, new_value, session_id, new_value, session_id),
            )
            conn.commit()
        finally:
            conn.close()

    def has_seen_message(self, msg_id: str) -> bool:
        conn = self._connect()
        try:
            row = conn.execute("SELECT 1 FROM seen_messages WHERE msg_id = ?", (msg_id,)).fetchone()
            return row is not None
        finally:
            conn.close()

    def record_seen_message(self, msg_id: str, peer: str, counter: int) -> None:
        conn = self._connect()
        try:
            conn.execute(
                "INSERT OR IGNORE INTO seen_messages(msg_id, peer, counter, seen_at) VALUES (?, ?, ?, ?)",
                (msg_id, peer, counter, iso_now()),
            )
            conn.commit()
        finally:
            conn.close()

    def add_message(
        self,
        msg_id: str,
        peer: str,
        direction: str,
        kind: str,
        body: str,
        sent_at: str,
        expires_at: str | None,
        status: str,
        counter: int,
        session_id: str,
        read_flag: bool,
    ) -> None:
        conn = self._connect()
        try:
            conn.execute(
                """
                INSERT OR REPLACE INTO messages(
                    msg_id, peer, direction, kind, body, sent_at,
                    expires_at, status, counter, session_id, read_flag
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    msg_id,
                    peer,
                    direction,
                    kind,
                    body,
                    sent_at,
                    expires_at,
                    status,
                    counter,
                    session_id,
                    int(read_flag),
                ),
            )
            conn.execute(
                "UPDATE contacts SET last_activity = ? WHERE username = ?",
                (sent_at, peer),
            )
            if direction == "incoming" and not read_flag:
                conn.execute(
                    "UPDATE contacts SET unread_count = unread_count + 1 WHERE username = ?",
                    (peer,),
                )
            conn.commit()
        finally:
            conn.close()

    def update_message_status(self, msg_id: str, status: str) -> None:
        conn = self._connect()
        try:
            conn.execute("UPDATE messages SET status = ? WHERE msg_id = ?", (status, msg_id))
            conn.commit()
        finally:
            conn.close()

    def list_messages(self, peer: str, limit: int = 50, offset: int = 0) -> list[dict[str, Any]]:
        conn = self._connect()
        try:
            rows = conn.execute(
                "SELECT * FROM messages WHERE peer = ? ORDER BY sent_at DESC LIMIT ? OFFSET ?",
                (peer, limit, offset),
            ).fetchall()
            ordered = [dict(row) for row in rows]
            ordered.reverse()
            return ordered
        finally:
            conn.close()

    def mark_chat_read(self, peer: str) -> None:
        conn = self._connect()
        try:
            conn.execute("UPDATE messages SET read_flag = 1 WHERE peer = ? AND direction = 'incoming'", (peer,))
            conn.execute("UPDATE contacts SET unread_count = 0 WHERE username = ?", (peer,))
            conn.commit()
        finally:
            conn.close()

    def cleanup_expired_messages(self) -> int:
        conn = self._connect()
        try:
            now_iso = iso_now()
            rows = conn.execute(
                "SELECT msg_id, peer FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?",
                (now_iso,),
            ).fetchall()
            expired_count = len(rows)
            if expired_count:
                peers = {row["peer"] for row in rows}
                conn.execute("DELETE FROM messages WHERE expires_at IS NOT NULL AND expires_at <= ?", (now_iso,))
                for peer in peers:
                    unread = conn.execute(
                        "SELECT COUNT(*) AS c FROM messages WHERE peer = ? AND direction = 'incoming' AND read_flag = 0",
                        (peer,),
                    ).fetchone()["c"]
                    conn.execute("UPDATE contacts SET unread_count = ? WHERE username = ?", (int(unread), peer))
                conn.commit()
            return expired_count
        finally:
            conn.close()
