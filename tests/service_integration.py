from __future__ import annotations

import asyncio
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

import pyotp
from werkzeug.serving import make_server

from client.service import SecureChatService
from server.app import create_app
from server.config import Config


class ServerThread(threading.Thread):
    def __init__(self, app, host: str, port: int):
        super().__init__(daemon=True)
        self.server = make_server(host, port, app, ssl_context="adhoc")
        self.ctx = app.app_context()
        self.ctx.push()

    def run(self) -> None:
        self.server.serve_forever()

    def shutdown(self) -> None:
        self.server.shutdown()
        self.ctx.pop()


class ServiceIntegrationTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        self.state_root = Path(self.temp_dir.name) / "state"
        self.db_path = str(Path(self.temp_dir.name) / "server.db")
        app = create_app(Config(database_path=self.db_path, tls_cert_path="", tls_key_path=""))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.server_thread = ServerThread(app, "127.0.0.1", self.port)
        self.server_thread.start()
        time.sleep(0.3)
        self.server_url = f"https://127.0.0.1:{self.port}"

    def tearDown(self) -> None:
        self.server_thread.shutdown()
        self.temp_dir.cleanup()

    def test_service_roundtrip_and_key_change(self) -> None:
        asyncio.run(self._test_service_roundtrip_and_key_change())

    async def _test_service_roundtrip_and_key_change(self) -> None:
        alice = SecureChatService(self.server_url, tls_verify=False, state_root=self.state_root)
        bob = SecureChatService(self.server_url, tls_verify=False, state_root=self.state_root)
        await alice.start()
        await bob.start()
        try:
            reg_alice = await alice.register("alice", "AlicePass123")
            reg_bob = await bob.register("bob", "BobPass12345")
            await alice.login("alice", "AlicePass123", pyotp.TOTP(reg_alice["otp_secret"]).now())
            await bob.login("bob", "BobPass12345", pyotp.TOTP(reg_bob["otp_secret"]).now())

            await alice.send_friend_request("bob")
            reqs = await bob.refresh_requests()
            self.assertEqual(len(reqs["incoming"]), 1)
            await bob.accept_request(reqs["incoming"][0]["id"])
            await alice.refresh_contacts()
            await bob.refresh_contacts()

            result = await alice.send_text_message("bob", "hello from service", ttl_seconds=60)
            self.assertEqual(result["status"], "sent")

            bob_sync = await bob.sync_once()
            self.assertEqual(bob_sync["new_messages"], 1)
            msgs = bob.list_messages("alice")
            self.assertEqual(msgs[-1]["body"], "hello from service")

            alice_sync = await alice.sync_once()
            out = alice.list_messages("bob")
            self.assertEqual(out[-1]["status"], "delivered")

            await bob.rotate_keys("BobPass12345")
            await alice.refresh_contacts()
            contact = alice.get_contact("bob")
            assert contact is not None
            self.assertTrue(contact["key_changed"])
        finally:
            await alice.close()
            await bob.close()


if __name__ == "__main__":
    unittest.main(verbosity=2)
