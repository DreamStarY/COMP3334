from __future__ import annotations

import base64
import json
import uuid
from pathlib import Path
from typing import Any

from client.api import ServerAPI
from client.device_store import DeviceStore
from client.local_store import LocalStore
from common.crypto import (
    build_signable_payload,
    decrypt_payload,
    derive_root_key,
    derive_session_id,
    encrypt_payload,
    fingerprint_from_public_keys,
    sign_envelope,
    verify_signature,
)
from common.utils import iso_now, ttl_to_expiry, validate_password, validate_username

DEFAULT_TLS_CERT = Path(__file__).resolve().parent.parent / "certs" / "localhost-cert.pem"
DEFAULT_STATE_ROOT = Path.home() / ".securechat_webui"


class SecureChatService:
    def __init__(
        self,
        server_url: str,
        tls_verify: bool | str | Path = DEFAULT_TLS_CERT,
        state_root: Path = DEFAULT_STATE_ROOT,
    ):
        self.server_url = server_url.rstrip("/")
        self.tls_verify = str(tls_verify) if isinstance(tls_verify, Path) else tls_verify
        self.state_root = state_root
        self.api = ServerAPI(self.server_url, verify=self.tls_verify)
        self.username: str | None = None
        self.identity: dict[str, Any] | None = None
        self.device_store: DeviceStore | None = None
        self.local_store: LocalStore | None = None
        self.pending_requests: dict[str, list[dict[str, Any]]] = {"incoming": [], "outgoing": []}
        self.last_sync_summary: str = ""

    async def start(self) -> None:
        await self.api.start()

    async def close(self) -> None:
        await self.api.close()

    def _user_dir(self, username: str) -> Path:
        return self.state_root / username

    def _require_login(self) -> None:
        if not self.username or not self.identity or not self.local_store:
            raise RuntimeError("当前未登录")

    async def register(self, username: str, password: str) -> dict[str, Any]:
        device_store = DeviceStore(self.state_root, username)
        if not validate_username(username):
            raise RuntimeError("用户名需为 3-32 位，只能包含字母、数字、下划线、点、连字符")
        password_ok, password_msg = validate_password(password)
        if not password_ok:
            raise RuntimeError(password_msg)
        if device_store.has_keys():
            identity = device_store.load_identity(password)
            pending_bundle = None
        else:
            pending_bundle = device_store.generate_identity()
            identity = {
                "signing_public_key": pending_bundle.signing_public_key_b64,
                "exchange_public_key": pending_bundle.exchange_public_key_b64,
                "key_fingerprint": pending_bundle.key_fingerprint,
            }
        payload = {
            "username": username,
            "password": password,
            "signing_public_key": identity["signing_public_key"],
            "exchange_public_key": identity["exchange_public_key"],
            "key_fingerprint": identity["key_fingerprint"],
            "client_key_fingerprint": identity["key_fingerprint"],
        }
        result = await self.api.register(payload)
        if pending_bundle is not None:
            device_store.persist_identity(password, pending_bundle)
        return result

    async def login(self, username: str, password: str, otp: str) -> dict[str, Any]:
        self.device_store = DeviceStore(self.state_root, username)
        identity = self.device_store.load_identity(password)
        result = await self.api.login(username, password, otp)
        server_user = result["user"]
        if server_user["key_fingerprint"] != identity["key_fingerprint"]:
            raise RuntimeError(
                "服务器记录的设备密钥与本地密钥不一致。当前项目不支持多设备同步，请恢复原设备状态或重新注册演示账号。"
            )
        self.username = username
        self.identity = identity
        self.local_store = LocalStore(self._user_dir(username) / "client_state.db")
        self.api.set_token(result["token"])
        self.local_store.set_setting("server_url", self.server_url)
        await self.refresh_contacts()
        await self.refresh_requests()
        return result

    async def logout(self) -> None:
        try:
            await self.api.logout()
        except Exception:
            pass
        self.api.set_token(None)
        self.username = None
        self.identity = None
        self.device_store = None
        self.local_store = None
        self.pending_requests = {"incoming": [], "outgoing": []}

    async def rotate_keys(self, password: str) -> dict[str, Any]:
        self._require_login()
        assert self.device_store is not None
        new_identity = self.device_store.rotate_identity(password)
        result = await self.api.rotate_keys(
            {
                "signing_public_key": new_identity["signing_public_key"],
                "exchange_public_key": new_identity["exchange_public_key"],
                "key_fingerprint": new_identity["key_fingerprint"],
            }
        )
        self.identity = new_identity
        return result

    async def refresh_requests(self) -> dict[str, list[dict[str, Any]]]:
        self._require_login()
        result = await self.api.list_friend_requests()
        self.pending_requests = {
            "incoming": result.get("incoming", []),
            "outgoing": result.get("outgoing", []),
        }
        return self.pending_requests

    async def search_users(self, query: str) -> list[str]:
        self._require_login()
        result = await self.api.search_users(query)
        return result.get("users", [])

    async def send_friend_request(self, target_username: str) -> dict[str, Any]:
        self._require_login()
        result = await self.api.send_friend_request(target_username)
        await self.refresh_requests()
        return result

    async def accept_request(self, request_id: int) -> None:
        self._require_login()
        await self.api.accept_request(request_id)
        await self.refresh_requests()
        await self.refresh_contacts()

    async def reject_request(self, request_id: int) -> None:
        self._require_login()
        await self.api.reject_request(request_id)
        await self.refresh_requests()

    async def cancel_request(self, request_id: int) -> None:
        self._require_login()
        await self.api.cancel_request(request_id)
        await self.refresh_requests()

    async def block_contact(self, username: str) -> None:
        self._require_login()
        await self.api.block_contact(username)
        await self.refresh_contacts()

    async def unblock_contact(self, username: str) -> None:
        self._require_login()
        await self.api.unblock_contact(username)
        await self.refresh_contacts()

    async def remove_contact(self, username: str) -> None:
        self._require_login()
        await self.api.remove_contact(username)
        assert self.local_store is not None
        self.local_store.remove_contact(username)
        await self.refresh_contacts()

    async def refresh_contacts(self) -> list[dict[str, Any]]:
        self._require_login()
        assert self.local_store is not None
        result = await self.api.list_contacts()
        current_names = set()
        for item in result.get("contacts", []):
            current_names.add(item["username"])
            self.local_store.upsert_contact(
                username=item["username"],
                signing_public_key=item["signing_public_key"],
                exchange_public_key=item["exchange_public_key"],
                key_fingerprint=item["key_fingerprint"],
                blocked=item["status"] == "blocked",
            )
        local_contacts = self.local_store.list_contacts()
        for contact in local_contacts:
            if contact["username"] not in current_names:
                self.local_store.remove_contact(contact["username"])
        return self.local_store.list_contacts()

    def list_local_contacts(self) -> list[dict[str, Any]]:
        self._require_login()
        assert self.local_store is not None
        self.local_store.cleanup_expired_messages()
        return self.local_store.list_contacts()

    def list_messages(self, peer: str, limit: int = 100, offset: int = 0) -> list[dict[str, Any]]:
        self._require_login()
        assert self.local_store is not None
        self.local_store.cleanup_expired_messages()
        self.local_store.mark_chat_read(peer)
        return self.local_store.list_messages(peer, limit=limit, offset=offset)

    def verify_contact(self, username: str) -> None:
        self._require_login()
        assert self.local_store is not None
        self.local_store.mark_contact_verified(username, True)

    def trust_new_key(self, username: str) -> None:
        self._require_login()
        assert self.local_store is not None
        self.local_store.trust_new_key(username)

    def get_contact(self, username: str) -> dict[str, Any] | None:
        self._require_login()
        assert self.local_store is not None
        return self.local_store.get_contact(username)

    def local_fingerprint(self) -> str:
        self._require_login()
        assert self.identity is not None
        return self.identity["key_fingerprint"]

    async def send_text_message(self, peer: str, text: str, ttl_seconds: int | None = None) -> dict[str, Any]:
        self._require_login()
        assert self.local_store is not None and self.identity is not None and self.username is not None
        contact = self.local_store.get_contact(peer)
        if not contact:
            raise RuntimeError("联系人不存在，请先刷新联系人列表")
        if contact["blocked"]:
            raise RuntimeError("该联系人当前在本地被标记为 blocked")
        if contact["key_changed"]:
            raise RuntimeError("联系人密钥已变化，请先在本地确认新的指纹")

        bundle_result = await self.api.get_key_bundle(peer)
        bundle = bundle_result["bundle"]
        self.local_store.upsert_contact(
            username=bundle["username"],
            signing_public_key=bundle["signing_public_key"],
            exchange_public_key=bundle["exchange_public_key"],
            key_fingerprint=bundle["key_fingerprint"],
            blocked=False,
        )
        contact = self.local_store.get_contact(peer)
        assert contact is not None
        if contact["key_changed"]:
            raise RuntimeError("联系人公钥刚刚发生变化，已阻止发送，请先确认新指纹")

        session_id = derive_session_id(
            self.username,
            peer,
            self.identity["key_fingerprint"],
            contact["current_key_fingerprint"],
        )
        counter = self.local_store.consume_next_counter(peer, session_id)
        message_id = str(uuid.uuid4())
        expires_at = ttl_to_expiry(ttl_seconds)
        sent_at = iso_now()
        root_key = derive_root_key(
            self.identity["exchange_private_key"],
            contact["exchange_public_key"],
            self.username,
            peer,
            self.identity["key_fingerprint"],
            contact["current_key_fingerprint"],
        )
        associated_data = {
            "kind": "text",
            "sender": self.username,
            "recipient": peer,
            "session_id": session_id,
            "counter": counter,
            "message_id": message_id,
            "sent_at": sent_at,
            "ttl_seconds": ttl_seconds,
            "expires_at": expires_at,
        }
        plaintext = {"kind": "text", "text": text}
        enc = encrypt_payload(root_key, session_id, counter, message_id, plaintext, associated_data)
        envelope = {
            "message_id": message_id,
            "session_id": session_id,
            "sender": self.username,
            "recipient": peer,
            "sender_key_fingerprint": self.identity["key_fingerprint"],
            "recipient_key_fingerprint": contact["current_key_fingerprint"],
            "counter": counter,
            "nonce": enc["nonce"],
            "ad_json": enc["ad_json"],
            "ciphertext": enc["ciphertext"],
            "signature": "",
            "sent_at": sent_at,
            "expires_at": expires_at,
        }
        envelope["signature"] = sign_envelope(
            self.identity["signing_private_key"], build_signable_payload(envelope)
        )
        try:
            result = await self.api.send_message(envelope)
        except APIError as exc:
            if exc.payload.get("code") == "recipient_key_changed":
                await self.refresh_contacts()
            raise
        self.local_store.add_message(
            msg_id=message_id,
            peer=peer,
            direction="outgoing",
            kind="text",
            body=text,
            sent_at=sent_at,
            expires_at=expires_at,
            status=result.get("status", "sent"),
            counter=counter,
            session_id=session_id,
            read_flag=True,
        )
        return result

    async def sync_once(self) -> dict[str, Any]:
        self._require_login()
        assert self.local_store is not None and self.identity is not None and self.username is not None
        self.local_store.cleanup_expired_messages()
        await self.refresh_contacts()
        sync_result = await self.api.sync_messages(limit=100)
        ack_ids: list[str] = []
        new_messages = 0
        warnings: list[str] = []

        for status_update in sync_result.get("status_updates", []):
            self.local_store.update_message_status(status_update["message_id"], status_update["status"])

        for envelope in sync_result.get("messages", []):
            msg_id = envelope["message_id"]
            peer = envelope["sender"]
            sender_sign_b64 = envelope["sender_signing_public_key"]
            sender_exchange_b64 = envelope["sender_exchange_public_key"]
            envelope_fingerprint = fingerprint_from_public_keys(
                base64.b64decode(sender_sign_b64),
                base64.b64decode(sender_exchange_b64),
            )
            if envelope_fingerprint != envelope["sender_key_fingerprint"]:
                warnings.append(f"检测到 {peer} 的公钥材料与指纹不一致，已跳过一条消息")
                continue
            self.local_store.upsert_contact(
                username=peer,
                signing_public_key=sender_sign_b64,
                exchange_public_key=sender_exchange_b64,
                key_fingerprint=envelope_fingerprint,
                blocked=False,
            )
            contact = self.local_store.get_contact(peer)
            if contact is None:
                continue
            if contact["key_changed"]:
                warnings.append(f"{peer} 的身份密钥已变化，已阻止自动解密，需先确认新指纹")
                continue
            if self.local_store.has_seen_message(msg_id):
                ack_ids.append(msg_id)
                continue
            if not verify_signature(sender_sign_b64, build_signable_payload(envelope), envelope["signature"]):
                warnings.append(f"来自 {peer} 的一条消息签名校验失败，已丢弃")
                continue
            root_key = derive_root_key(
                self.identity["exchange_private_key"],
                sender_exchange_b64,
                self.username,
                peer,
                self.identity["key_fingerprint"],
                contact["current_key_fingerprint"],
            )
            try:
                plaintext = decrypt_payload(root_key, envelope)
            except Exception as exc:
                warnings.append(f"来自 {peer} 的一条消息无法解密：{exc}")
                continue
            kind = plaintext.get("kind", "text")
            body = plaintext.get("text", json.dumps(plaintext, ensure_ascii=False))
            self.local_store.record_seen_message(msg_id, peer, int(envelope["counter"]))
            self.local_store.update_last_in_counter(peer, int(envelope["counter"]), envelope["session_id"])
            self.local_store.add_message(
                msg_id=msg_id,
                peer=peer,
                direction="incoming",
                kind=kind,
                body=body,
                sent_at=envelope["sent_at"],
                expires_at=envelope.get("expires_at"),
                status="received",
                counter=int(envelope["counter"]),
                session_id=envelope["session_id"],
                read_flag=False,
            )
            ack_ids.append(msg_id)
            new_messages += 1

        if ack_ids:
            await self.api.ack_delivered(ack_ids)

        await self.refresh_requests()
        self.local_store.cleanup_expired_messages()
        self.last_sync_summary = f"新消息 {new_messages} 条，状态更新 {len(sync_result.get('status_updates', []))} 条"
        return {
            "new_messages": new_messages,
            "status_updates": sync_result.get("status_updates", []),
            "warnings": warnings,
            "summary": self.last_sync_summary,
        }
