from __future__ import annotations

import json
import tempfile
import unittest
import uuid
from pathlib import Path

from common.crypto import (
    build_signable_payload,
    decrypt_payload,
    derive_root_key,
    derive_session_id,
    encrypt_payload,
    generate_identity_bundle,
    sign_envelope,
    verify_signature,
)
from common.utils import iso_now
from server.app import create_app
from server.config import Config


class SecureChatFlowTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        db_path = str(Path(self.temp_dir.name) / "test.db")
        self.app = create_app(Config(database_path=db_path, tls_cert_path="", tls_key_path=""))
        self.client = self.app.test_client()
        self.alice = generate_identity_bundle()
        self.bob = generate_identity_bundle()

    def tearDown(self) -> None:
        self.temp_dir.cleanup()

    def post(self, path: str, json_data: dict, token: str | None = None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.post(path, json=json_data, headers=headers)

    def get(self, path: str, token: str | None = None):
        headers = {"Authorization": f"Bearer {token}"} if token else {}
        return self.client.get(path, headers=headers)

    def register_and_login(self, username: str, password: str, bundle) -> tuple[str, dict]:
        register = self.post(
            "/api/auth/register",
            {
                "username": username,
                "password": password,
                "signing_public_key": bundle.signing_public_key_b64,
                "exchange_public_key": bundle.exchange_public_key_b64,
                "key_fingerprint": bundle.key_fingerprint,
                "client_key_fingerprint": bundle.key_fingerprint,
            },
        )
        self.assertEqual(register.status_code, 200, register.get_json())
        secret = register.get_json()["otp_secret"]
        import pyotp

        otp = pyotp.TOTP(secret).now()
        login = self.post(
            "/api/auth/login",
            {"username": username, "password": password, "otp": otp},
        )
        self.assertEqual(login.status_code, 200, login.get_json())
        return login.get_json()["token"], register.get_json()

    def test_end_to_end_message_flow(self) -> None:
        alice_token, _ = self.register_and_login("alice", "AlicePass123", self.alice)
        bob_token, _ = self.register_and_login("bob", "BobPass12345", self.bob)

        send_req = self.post("/api/contacts/request", {"target_username": "bob"}, token=alice_token)
        self.assertEqual(send_req.status_code, 200, send_req.get_json())

        reqs = self.get("/api/contacts/requests", token=bob_token)
        incoming = reqs.get_json()["incoming"]
        self.assertEqual(len(incoming), 1)
        accept = self.post(f"/api/contacts/request/{incoming[0]['id']}/accept", {}, token=bob_token)
        self.assertEqual(accept.status_code, 200, accept.get_json())

        session_id = derive_session_id(
            "alice", "bob", self.alice.key_fingerprint, self.bob.key_fingerprint
        )
        message_id = str(uuid.uuid4())
        sent_at = iso_now()
        root_key = derive_root_key(
            self.alice.exchange_private_key_b64,
            self.bob.exchange_public_key_b64,
            "alice",
            "bob",
            self.alice.key_fingerprint,
            self.bob.key_fingerprint,
        )
        ad = {
            "kind": "text",
            "sender": "alice",
            "recipient": "bob",
            "session_id": session_id,
            "counter": 1,
            "message_id": message_id,
            "sent_at": sent_at,
            "ttl_seconds": None,
            "expires_at": None,
        }
        plaintext = {"kind": "text", "text": "hello bob"}
        enc = encrypt_payload(root_key, session_id, 1, message_id, plaintext, ad)
        envelope = {
            "message_id": message_id,
            "session_id": session_id,
            "sender": "alice",
            "recipient": "bob",
            "sender_key_fingerprint": self.alice.key_fingerprint,
            "recipient_key_fingerprint": self.bob.key_fingerprint,
            "counter": 1,
            "nonce": enc["nonce"],
            "ad_json": enc["ad_json"],
            "ciphertext": enc["ciphertext"],
            "signature": "",
            "sent_at": sent_at,
            "expires_at": None,
        }
        envelope["signature"] = sign_envelope(self.alice.signing_private_key_b64, build_signable_payload(envelope))

        send = self.post("/api/messages/send", {"envelope": envelope}, token=alice_token)
        self.assertEqual(send.status_code, 200, send.get_json())
        self.assertEqual(send.get_json()["status"], "sent")

        sync = self.get("/api/messages/sync", token=bob_token)
        self.assertEqual(sync.status_code, 200, sync.get_json())
        messages = sync.get_json()["messages"]
        self.assertEqual(len(messages), 1)
        incoming_env = messages[0]
        self.assertTrue(
            verify_signature(
                self.alice.signing_public_key_b64,
                build_signable_payload(incoming_env),
                incoming_env["signature"],
            )
        )
        bob_root_key = derive_root_key(
            self.bob.exchange_private_key_b64,
            self.alice.exchange_public_key_b64,
            "bob",
            "alice",
            self.bob.key_fingerprint,
            self.alice.key_fingerprint,
        )
        opened = decrypt_payload(bob_root_key, incoming_env)
        self.assertEqual(opened["text"], "hello bob")

        ack = self.post("/api/messages/ack-delivered", {"message_ids": [message_id]}, token=bob_token)
        self.assertEqual(ack.status_code, 200, ack.get_json())
        self.assertEqual(ack.get_json()["acked"], [message_id])

        sync_sender = self.get("/api/messages/sync", token=alice_token)
        self.assertEqual(sync_sender.status_code, 200, sync_sender.get_json())
        statuses = sync_sender.get_json()["status_updates"]
        self.assertEqual(len(statuses), 1)
        self.assertEqual(statuses[0]["status"], "delivered")
        self.assertEqual(statuses[0]["message_id"], message_id)

    def test_tamper_detection(self) -> None:
        root_key = derive_root_key(
            self.alice.exchange_private_key_b64,
            self.bob.exchange_public_key_b64,
            "alice",
            "bob",
            self.alice.key_fingerprint,
            self.bob.key_fingerprint,
        )
        session_id = derive_session_id(
            "alice", "bob", self.alice.key_fingerprint, self.bob.key_fingerprint
        )
        message_id = str(uuid.uuid4())
        ad = {
            "kind": "text",
            "sender": "alice",
            "recipient": "bob",
            "session_id": session_id,
            "counter": 5,
            "message_id": message_id,
            "sent_at": iso_now(),
            "ttl_seconds": None,
            "expires_at": None,
        }
        enc = encrypt_payload(root_key, session_id, 5, message_id, {"kind": "text", "text": "tamper me"}, ad)
        envelope = {
            "message_id": message_id,
            "session_id": session_id,
            "sender": "alice",
            "recipient": "bob",
            "sender_key_fingerprint": self.alice.key_fingerprint,
            "recipient_key_fingerprint": self.bob.key_fingerprint,
            "counter": 5,
            "nonce": enc["nonce"],
            "ad_json": enc["ad_json"],
            "ciphertext": enc["ciphertext"],
            "signature": "",
            "sent_at": ad["sent_at"],
            "expires_at": None,
        }
        envelope["signature"] = sign_envelope(self.alice.signing_private_key_b64, build_signable_payload(envelope))

        modified = dict(envelope)
        modified["ad_json"] = json.dumps({**json.loads(envelope["ad_json"]), "recipient": "mallory"})
        self.assertFalse(
            verify_signature(
                self.alice.signing_public_key_b64,
                build_signable_payload(modified),
                envelope["signature"],
            )
        )
        with self.assertRaises(Exception):
            decrypt_payload(root_key, modified)


if __name__ == "__main__":
    unittest.main(verbosity=2)
