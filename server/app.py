from __future__ import annotations

import functools
import json
from datetime import timedelta
from pathlib import Path
from typing import Any, Callable, Iterable

import bcrypt
import pyotp
from flask import Flask, g, jsonify, request

from common.utils import (
    iso_now,
    make_token,
    now_utc,
    parse_iso,
    validate_password,
    validate_username,
)
from server.config import Config
from server.db import Database


def create_app(config: Config | None = None) -> Flask:
    config = config or Config()
    app = Flask(__name__)
    app.config["SECURECHAT_CONFIG"] = config
    db = Database(config.database_path)
    db.init_db()

    def json_error(message: str, status_code: int = 400, **extra: Any):
        payload = {"ok": False, "error": message}
        payload.update(extra)
        return jsonify(payload), status_code

    def get_db() -> Database:
        return db

    def row_to_dict(row) -> dict[str, Any]:
        return dict(row) if row is not None else {}

    def get_user_by_username(username: str):
        return db.fetchone("SELECT * FROM users WHERE username = ?", (username,))

    def get_user_by_id(user_id: int):
        return db.fetchone("SELECT * FROM users WHERE id = ?", (user_id,))

    def get_contact_status(user_id: int, contact_id: int) -> str | None:
        row = db.fetchone(
            "SELECT status FROM contacts WHERE user_id = ? AND contact_id = ?",
            (user_id, contact_id),
        )
        return row["status"] if row else None

    def is_blocked_any_direction(user_a: int, user_b: int) -> bool:
        rows = db.fetchall(
            "SELECT 1 FROM contacts WHERE ((user_id = ? AND contact_id = ?) OR (user_id = ? AND contact_id = ?)) AND status = 'blocked' LIMIT 1",
            (user_a, user_b, user_b, user_a),
        )
        return bool(rows)

    def are_friends(user_a: int, user_b: int) -> bool:
        first = get_contact_status(user_a, user_b)
        second = get_contact_status(user_b, user_a)
        return first == "friends" and second == "friends"

    def allow_rate_limit(key: str, bucket: str, limit: int, window_seconds: int) -> bool:
        now_bucket = int(now_utc().timestamp()) // window_seconds
        with db.transaction() as conn:
            row = conn.execute(
                "SELECT count, window_start FROM rate_limits WHERE key = ? AND bucket = ?",
                (key, bucket),
            ).fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO rate_limits(key, bucket, window_start, count) VALUES (?, ?, ?, 1)",
                    (key, bucket, now_bucket),
                )
                conn.commit()
                return True
            if int(row["window_start"]) != now_bucket:
                conn.execute(
                    "UPDATE rate_limits SET window_start = ?, count = 1 WHERE key = ? AND bucket = ?",
                    (now_bucket, key, bucket),
                )
                conn.commit()
                return True
            if int(row["count"]) >= limit:
                return False
            conn.execute(
                "UPDATE rate_limits SET count = count + 1 WHERE key = ? AND bucket = ?",
                (key, bucket),
            )
            conn.commit()
            return True

    def cleanup_messages() -> None:
        now_iso = iso_now()
        with db.transaction() as conn:
            conn.execute(
                "UPDATE messages SET status = 'expired' WHERE status = 'queued' AND expires_at IS NOT NULL AND expires_at <= ?",
                (now_iso,),
            )
            conn.execute(
                "DELETE FROM messages WHERE status IN ('expired', 'deleted') AND sent_at <= datetime('now', '-1 day')"
            )
            conn.execute(
                "DELETE FROM messages WHERE status = 'delivered' AND delivered_at IS NOT NULL AND delivered_at <= datetime('now', '-1 day')"
            )
            conn.commit()

    def extract_token() -> str | None:
        auth_header = request.headers.get("Authorization", "")
        prefix = "Bearer "
        if auth_header.startswith(prefix):
            return auth_header[len(prefix) :].strip()
        return None

    def auth_required(view: Callable[..., Any]):
        @functools.wraps(view)
        def wrapped(*args: Any, **kwargs: Any):
            token = extract_token()
            if not token:
                return json_error("缺少访问令牌", 401)
            row = db.fetchone(
                "SELECT s.token, s.user_id, s.expires_at, u.* FROM sessions s JOIN users u ON s.user_id = u.id WHERE s.token = ?",
                (token,),
            )
            if row is None:
                return json_error("令牌无效", 401)
            expires_at = parse_iso(row["expires_at"])
            if expires_at is None or expires_at <= now_utc():
                db.execute("DELETE FROM sessions WHERE token = ?", (token,))
                return json_error("令牌已过期", 401)
            g.token = token
            g.user = row
            db.execute("UPDATE users SET last_seen_at = ? WHERE id = ?", (iso_now(), row["id"]))
            cleanup_messages()
            return view(*args, **kwargs)

        return wrapped

    @app.after_request
    def set_headers(response):
        response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/api/health")
    def health():
        cleanup_messages()
        return jsonify({"ok": True, "server_time": iso_now()})

    @app.post("/api/auth/register")
    def register():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        signing_public_key = str(data.get("signing_public_key", "")).strip()
        exchange_public_key = str(data.get("exchange_public_key", "")).strip()
        key_fingerprint = str(data.get("key_fingerprint", "")).strip()
        client_key_fingerprint = str(data.get("client_key_fingerprint", "")).strip() or key_fingerprint

        if not allow_rate_limit(request.remote_addr or "register", "register", 10, 60):
            return json_error("注册过于频繁，请稍后再试", 429)
        if not validate_username(username):
            return json_error("用户名需为 3-32 位，只能包含字母、数字、下划线、点、连字符")
        password_ok, password_msg = validate_password(password)
        if not password_ok:
            return json_error(password_msg)
        if not signing_public_key or not exchange_public_key or not key_fingerprint:
            return json_error("缺少设备公钥材料")
        if key_fingerprint != client_key_fingerprint:
            return json_error("设备指纹不一致")
        if get_user_by_username(username):
            return json_error("用户名已存在", 409)

        otp_secret = pyotp.random_base32()
        password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=12))
        now_iso = iso_now()
        db.execute(
            """
            INSERT INTO users(
                username, password_hash, otp_secret,
                signing_public_key, exchange_public_key, key_fingerprint,
                last_seen_at, created_at, updated_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                username,
                password_hash,
                otp_secret,
                signing_public_key,
                exchange_public_key,
                key_fingerprint,
                now_iso,
                now_iso,
                now_iso,
            ),
        )
        provisioning_uri = pyotp.TOTP(otp_secret).provisioning_uri(name=username, issuer_name="SecureChat")
        return jsonify(
            {
                "ok": True,
                "message": "注册成功，请将 OTP secret 导入认证器后再登录",
                "otp_secret": otp_secret,
                "otp_provisioning_uri": provisioning_uri,
                "key_fingerprint": key_fingerprint,
            }
        )

    @app.post("/api/auth/login")
    def login():
        data = request.get_json(silent=True) or {}
        username = str(data.get("username", "")).strip()
        password = str(data.get("password", ""))
        otp = str(data.get("otp", "")).strip()

        if not allow_rate_limit(username or request.remote_addr or "login", "login", 10, 300):
            return json_error("登录尝试过多，请 5 分钟后再试", 429)

        user = get_user_by_username(username)
        if user is None:
            return json_error("用户名或密码错误", 401)
        if not bcrypt.checkpw(password.encode("utf-8"), bytes(user["password_hash"])):
            return json_error("用户名或密码错误", 401)
        if not pyotp.TOTP(user["otp_secret"]).verify(otp, valid_window=1):
            return json_error("OTP 无效", 401)

        token = make_token(24)
        created_at = now_utc()
        expires_at = created_at + timedelta(hours=config.token_ttl_hours)
        db.execute(
            "INSERT INTO sessions(token, user_id, created_at, expires_at) VALUES (?, ?, ?, ?)",
            (token, user["id"], created_at.isoformat(), expires_at.isoformat()),
        )
        db.execute("UPDATE users SET last_seen_at = ? WHERE id = ?", (iso_now(), user["id"]))
        return jsonify(
            {
                "ok": True,
                "token": token,
                "expires_at": expires_at.isoformat(),
                "user": {
                    "username": user["username"],
                    "key_fingerprint": user["key_fingerprint"],
                    "signing_public_key": user["signing_public_key"],
                    "exchange_public_key": user["exchange_public_key"],
                },
            }
        )

    @app.post("/api/auth/logout")
    @auth_required
    def logout():
        db.execute("DELETE FROM sessions WHERE token = ?", (g.token,))
        return jsonify({"ok": True})

    @app.get("/api/auth/me")
    @auth_required
    def me():
        return jsonify(
            {
                "ok": True,
                "user": {
                    "id": g.user["id"],
                    "username": g.user["username"],
                    "key_fingerprint": g.user["key_fingerprint"],
                    "signing_public_key": g.user["signing_public_key"],
                    "exchange_public_key": g.user["exchange_public_key"],
                    "last_seen_at": g.user["last_seen_at"],
                },
            }
        )

    @app.post("/api/account/rotate-keys")
    @auth_required
    def rotate_keys():
        data = request.get_json(silent=True) or {}
        signing_public_key = str(data.get("signing_public_key", "")).strip()
        exchange_public_key = str(data.get("exchange_public_key", "")).strip()
        key_fingerprint = str(data.get("key_fingerprint", "")).strip()
        if not signing_public_key or not exchange_public_key or not key_fingerprint:
            return json_error("缺少完整公钥材料")
        db.execute(
            "UPDATE users SET signing_public_key = ?, exchange_public_key = ?, key_fingerprint = ?, updated_at = ? WHERE id = ?",
            (signing_public_key, exchange_public_key, key_fingerprint, iso_now(), g.user["id"]),
        )
        return jsonify({"ok": True, "message": "设备公钥已更新", "key_fingerprint": key_fingerprint})

    @app.get("/api/users/search")
    @auth_required
    def search_users():
        query = str(request.args.get("q", "")).strip()
        if len(query) < 1:
            return jsonify({"ok": True, "users": []})
        rows = db.fetchall(
            "SELECT username FROM users WHERE username LIKE ? AND id != ? ORDER BY username LIMIT 20",
            (f"%{query}%", g.user["id"]),
        )
        return jsonify({"ok": True, "users": [row["username"] for row in rows]})

    @app.get("/api/contacts/list")
    @auth_required
    def list_contacts():
        rows = db.fetchall(
            """
            SELECT c.status, u.username, u.signing_public_key, u.exchange_public_key, u.key_fingerprint, u.last_seen_at
            FROM contacts c
            JOIN users u ON u.id = c.contact_id
            WHERE c.user_id = ?
            ORDER BY u.username
            """,
            (g.user["id"],),
        )
        contacts = [
            {
                "username": row["username"],
                "status": row["status"],
                "signing_public_key": row["signing_public_key"],
                "exchange_public_key": row["exchange_public_key"],
                "key_fingerprint": row["key_fingerprint"],
                "last_seen_at": row["last_seen_at"],
            }
            for row in rows
        ]
        return jsonify({"ok": True, "contacts": contacts})

    @app.get("/api/contacts/key-bundle/<username>")
    @auth_required
    def contact_key_bundle(username: str):
        user = get_user_by_username(username)
        if user is None:
            return json_error("用户不存在", 404)
        if not are_friends(g.user["id"], user["id"]):
            return json_error("仅允许获取好友公钥", 403)
        return jsonify(
            {
                "ok": True,
                "bundle": {
                    "username": user["username"],
                    "signing_public_key": user["signing_public_key"],
                    "exchange_public_key": user["exchange_public_key"],
                    "key_fingerprint": user["key_fingerprint"],
                },
            }
        )

    @app.post("/api/contacts/request")
    @auth_required
    def send_friend_request():
        data = request.get_json(silent=True) or {}
        target_username = str(data.get("target_username", "")).strip()
        target = get_user_by_username(target_username)
        if target is None:
            return json_error("目标用户不存在", 404)
        if target["id"] == g.user["id"]:
            return json_error("不能给自己发送好友请求")
        if is_blocked_any_direction(g.user["id"], target["id"]):
            return json_error("该用户当前不可接收请求", 403)
        if are_friends(g.user["id"], target["id"]):
            return json_error("你们已经是好友", 409)
        if not allow_rate_limit(str(g.user["id"]), "friend_request", 20, 3600):
            return json_error("好友请求过于频繁，请稍后再试", 429)

        now_iso = iso_now()
        existing = db.fetchone(
            "SELECT * FROM friend_requests WHERE requester_id = ? AND target_id = ?",
            (g.user["id"], target["id"]),
        )
        if existing:
            if existing["status"] == "pending":
                return json_error("好友请求已发送", 409)
            db.execute(
                "UPDATE friend_requests SET status = 'pending', updated_at = ? WHERE id = ?",
                (now_iso, existing["id"]),
            )
            return jsonify({"ok": True, "request_id": existing["id"]})

        request_id = db.execute(
            "INSERT INTO friend_requests(requester_id, target_id, status, created_at, updated_at) VALUES (?, ?, 'pending', ?, ?)",
            (g.user["id"], target["id"], now_iso, now_iso),
        )
        return jsonify({"ok": True, "request_id": request_id})

    @app.get("/api/contacts/requests")
    @auth_required
    def list_friend_requests():
        incoming = db.fetchall(
            """
            SELECT fr.id, u.username, fr.status, fr.created_at, fr.updated_at
            FROM friend_requests fr
            JOIN users u ON u.id = fr.requester_id
            WHERE fr.target_id = ? AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
            """,
            (g.user["id"],),
        )
        outgoing = db.fetchall(
            """
            SELECT fr.id, u.username, fr.status, fr.created_at, fr.updated_at
            FROM friend_requests fr
            JOIN users u ON u.id = fr.target_id
            WHERE fr.requester_id = ? AND fr.status = 'pending'
            ORDER BY fr.created_at DESC
            """,
            (g.user["id"],),
        )
        return jsonify(
            {
                "ok": True,
                "incoming": [row_to_dict(row) for row in incoming],
                "outgoing": [row_to_dict(row) for row in outgoing],
            }
        )

    def create_friendship(user_a: int, user_b: int, now_iso: str) -> None:
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO contacts(user_id, contact_id, status, created_at, updated_at) VALUES (?, ?, 'friends', ?, ?) ON CONFLICT(user_id, contact_id) DO UPDATE SET status = 'friends', updated_at = excluded.updated_at",
                (user_a, user_b, now_iso, now_iso),
            )
            conn.execute(
                "INSERT INTO contacts(user_id, contact_id, status, created_at, updated_at) VALUES (?, ?, 'friends', ?, ?) ON CONFLICT(user_id, contact_id) DO UPDATE SET status = 'friends', updated_at = excluded.updated_at",
                (user_b, user_a, now_iso, now_iso),
            )
            conn.commit()

    def set_contact_state(owner_id: int, other_id: int, status: str, now_iso: str) -> None:
        with db.transaction() as conn:
            conn.execute(
                "INSERT INTO contacts(user_id, contact_id, status, created_at, updated_at) VALUES (?, ?, ?, ?, ?) ON CONFLICT(user_id, contact_id) DO UPDATE SET status = excluded.status, updated_at = excluded.updated_at",
                (owner_id, other_id, status, now_iso, now_iso),
            )
            conn.commit()

    @app.post("/api/contacts/request/<int:request_id>/accept")
    @auth_required
    def accept_request(request_id: int):
        row = db.fetchone(
            "SELECT * FROM friend_requests WHERE id = ? AND target_id = ?",
            (request_id, g.user["id"]),
        )
        if row is None or row["status"] != "pending":
            return json_error("请求不存在或已处理", 404)
        if is_blocked_any_direction(int(row["requester_id"]), g.user["id"]):
            return json_error("该请求当前不可接受", 403)
        now_iso = iso_now()
        db.execute("UPDATE friend_requests SET status = 'accepted', updated_at = ? WHERE id = ?", (now_iso, request_id))
        create_friendship(int(row["requester_id"]), g.user["id"], now_iso)
        return jsonify({"ok": True})

    @app.post("/api/contacts/request/<int:request_id>/reject")
    @auth_required
    def reject_request(request_id: int):
        row = db.fetchone(
            "SELECT * FROM friend_requests WHERE id = ? AND target_id = ?",
            (request_id, g.user["id"]),
        )
        if row is None or row["status"] != "pending":
            return json_error("请求不存在或已处理", 404)
        db.execute("UPDATE friend_requests SET status = 'rejected', updated_at = ? WHERE id = ?", (iso_now(), request_id))
        return jsonify({"ok": True})

    @app.post("/api/contacts/request/<int:request_id>/cancel")
    @auth_required
    def cancel_request(request_id: int):
        row = db.fetchone(
            "SELECT * FROM friend_requests WHERE id = ? AND requester_id = ?",
            (request_id, g.user["id"]),
        )
        if row is None or row["status"] != "pending":
            return json_error("请求不存在或已处理", 404)
        db.execute("UPDATE friend_requests SET status = 'cancelled', updated_at = ? WHERE id = ?", (iso_now(), request_id))
        return jsonify({"ok": True})

    @app.post("/api/contacts/block")
    @auth_required
    def block_contact():
        data = request.get_json(silent=True) or {}
        target_username = str(data.get("target_username", "")).strip()
        target = get_user_by_username(target_username)
        if target is None:
            return json_error("目标用户不存在", 404)
        now_iso = iso_now()
        set_contact_state(g.user["id"], target["id"], "blocked", now_iso)
        db.execute(
            "UPDATE friend_requests SET status = 'cancelled', updated_at = ? WHERE (requester_id = ? AND target_id = ?) OR (requester_id = ? AND target_id = ?)",
            (now_iso, g.user["id"], target["id"], target["id"], g.user["id"]),
        )
        return jsonify({"ok": True})

    @app.post("/api/contacts/unblock")
    @auth_required
    def unblock_contact():
        data = request.get_json(silent=True) or {}
        target_username = str(data.get("target_username", "")).strip()
        target = get_user_by_username(target_username)
        if target is None:
            return json_error("目标用户不存在", 404)
        db.execute(
            "DELETE FROM contacts WHERE user_id = ? AND contact_id = ? AND status = 'blocked'",
            (g.user["id"], target["id"]),
        )
        return jsonify({"ok": True})

    @app.post("/api/contacts/remove")
    @auth_required
    def remove_contact():
        data = request.get_json(silent=True) or {}
        target_username = str(data.get("target_username", "")).strip()
        target = get_user_by_username(target_username)
        if target is None:
            return json_error("目标用户不存在", 404)
        db.execute(
            "DELETE FROM contacts WHERE ((user_id = ? AND contact_id = ?) OR (user_id = ? AND contact_id = ?)) AND status = 'friends'",
            (g.user["id"], target["id"], target["id"], g.user["id"]),
        )
        return jsonify({"ok": True})

    @app.post("/api/messages/send")
    @auth_required
    def send_message():
        data = request.get_json(silent=True) or {}
        envelope = data.get("envelope") or {}
        recipient_username = str(envelope.get("recipient", "")).strip()
        if not recipient_username:
            return json_error("缺少接收方")
        recipient = get_user_by_username(recipient_username)
        if recipient is None:
            return json_error("接收方不存在", 404)
        if recipient["id"] == g.user["id"]:
            return json_error("当前版本不支持给自己发消息")
        if not are_friends(g.user["id"], recipient["id"]):
            return json_error("默认仅允许好友互发消息", 403)
        if is_blocked_any_direction(g.user["id"], recipient["id"]):
            return json_error("该用户当前不可接收消息", 403)

        required_fields = [
            "message_id",
            "session_id",
            "sender",
            "recipient",
            "sender_key_fingerprint",
            "recipient_key_fingerprint",
            "counter",
            "nonce",
            "ad_json",
            "ciphertext",
            "signature",
            "sent_at",
        ]
        for field in required_fields:
            if field not in envelope or envelope[field] in (None, ""):
                return json_error(f"消息缺少字段: {field}")

        if envelope["sender"] != g.user["username"]:
            return json_error("发送者身份不匹配", 403)
        if envelope["sender_key_fingerprint"] != g.user["key_fingerprint"]:
            return json_error("发送端本地密钥不是当前服务器记录的密钥，可能已轮换", 409, code="sender_key_changed")
        if envelope["recipient_key_fingerprint"] != recipient["key_fingerprint"]:
            return json_error("接收方密钥已变化，请刷新联系人公钥后重试", 409, code="recipient_key_changed")

        encoded_size = sum(len(str(envelope.get(field, ""))) for field in required_fields)
        if encoded_size > config.max_message_bytes:
            return json_error("消息过大")

        pending_count = db.fetchone(
            "SELECT COUNT(*) AS c FROM messages WHERE recipient_id = ? AND status = 'queued'",
            (recipient["id"],),
        )["c"]
        if int(pending_count) >= config.max_pending_messages:
            return json_error("接收方离线队列已满，请稍后再试", 429)

        try:
            json.loads(envelope["ad_json"])
        except Exception:
            return json_error("ad_json 不是合法 JSON")

        expires_at = envelope.get("expires_at")
        now_iso = iso_now()
        try:
            message_id = str(envelope["message_id"])
            db.execute(
                """
                INSERT INTO messages(
                    message_id, session_id, sender_id, recipient_id, sender_username, recipient_username,
                    sender_key_fingerprint, recipient_key_fingerprint, counter, nonce, ad_json,
                    ciphertext, signature, expires_at, sent_at, status
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'queued')
                """,
                (
                    message_id,
                    str(envelope["session_id"]),
                    g.user["id"],
                    recipient["id"],
                    g.user["username"],
                    recipient_username,
                    str(envelope["sender_key_fingerprint"]),
                    str(envelope["recipient_key_fingerprint"]),
                    int(envelope["counter"]),
                    str(envelope["nonce"]),
                    str(envelope["ad_json"]),
                    str(envelope["ciphertext"]),
                    str(envelope["signature"]),
                    str(expires_at) if expires_at else None,
                    str(envelope["sent_at"]),
                ),
            )
        except Exception as exc:
            if "UNIQUE constraint failed: messages.message_id" in str(exc):
                return json_error("消息 ID 重复", 409)
            raise

        return jsonify({"ok": True, "message_id": message_id, "server_received_at": now_iso, "status": "sent"})

    @app.get("/api/messages/sync")
    @auth_required
    def sync_messages():
        limit = min(max(int(request.args.get("limit", 50)), 1), 200)
        rows = db.fetchall(
            """
            SELECT m.*, u.signing_public_key AS sender_signing_public_key, u.exchange_public_key AS sender_exchange_public_key
            FROM messages m
            JOIN users u ON u.id = m.sender_id
            WHERE m.recipient_id = ? AND m.status = 'queued'
              AND (m.expires_at IS NULL OR m.expires_at > ?)
            ORDER BY m.id ASC
            LIMIT ?
            """,
            (g.user["id"], iso_now(), limit),
        )
        status_rows = db.fetchall(
            "SELECT id, message_id, peer_username, status, created_at FROM status_updates WHERE owner_id = ? ORDER BY id ASC LIMIT 200",
            (g.user["id"],),
        )
        if status_rows:
            ids = [row["id"] for row in status_rows]
            placeholders = ",".join("?" for _ in ids)
            db.execute(f"DELETE FROM status_updates WHERE id IN ({placeholders})", ids)
        messages = []
        for row in rows:
            messages.append(
                {
                    "message_id": row["message_id"],
                    "session_id": row["session_id"],
                    "sender": row["sender_username"],
                    "recipient": row["recipient_username"],
                    "sender_key_fingerprint": row["sender_key_fingerprint"],
                    "recipient_key_fingerprint": row["recipient_key_fingerprint"],
                    "counter": row["counter"],
                    "nonce": row["nonce"],
                    "ad_json": row["ad_json"],
                    "ciphertext": row["ciphertext"],
                    "signature": row["signature"],
                    "sent_at": row["sent_at"],
                    "expires_at": row["expires_at"],
                    "sender_signing_public_key": row["sender_signing_public_key"],
                    "sender_exchange_public_key": row["sender_exchange_public_key"],
                }
            )
        return jsonify(
            {
                "ok": True,
                "messages": messages,
                "status_updates": [row_to_dict(row) for row in status_rows],
                "server_time": iso_now(),
            }
        )

    @app.post("/api/messages/ack-delivered")
    @auth_required
    def ack_delivered():
        data = request.get_json(silent=True) or {}
        message_ids = data.get("message_ids") or []
        if not isinstance(message_ids, list):
            return json_error("message_ids 必须是列表")
        message_ids = [str(item) for item in message_ids[:200] if str(item).strip()]
        if not message_ids:
            return jsonify({"ok": True, "acked": []})

        now_iso = iso_now()
        acked: list[str] = []
        with db.transaction() as conn:
            for message_id in message_ids:
                row = conn.execute(
                    "SELECT * FROM messages WHERE message_id = ? AND recipient_id = ?",
                    (message_id, g.user["id"]),
                ).fetchone()
                if row is None or row["status"] != "queued":
                    continue
                conn.execute(
                    "UPDATE messages SET status = 'delivered', delivered_at = ? WHERE message_id = ?",
                    (now_iso, message_id),
                )
                conn.execute(
                    "INSERT INTO status_updates(owner_id, message_id, peer_username, status, created_at) VALUES (?, ?, ?, 'delivered', ?)",
                    (row["sender_id"], row["message_id"], row["recipient_username"], now_iso),
                )
                acked.append(message_id)
            conn.commit()
        return jsonify({"ok": True, "acked": acked})

    return app


def main() -> None:
    config = Config()
    Path(config.database_path).parent.mkdir(parents=True, exist_ok=True)
    app = create_app(config)
    ssl_context = None
    if Path(config.tls_cert_path).exists() and Path(config.tls_key_path).exists():
        ssl_context = (config.tls_cert_path, config.tls_key_path)
    app.run(host=config.host, port=config.port, debug=False, ssl_context=ssl_context)


if __name__ == "__main__":
    main()
