from __future__ import annotations

import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path

import pyotp
from werkzeug.serving import make_server

from client.app import create_web_app
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


class WebUISmokeTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp_dir = tempfile.TemporaryDirectory()
        root = Path(self.temp_dir.name)
        self.state_root = root / "client_state"
        self.db_path = str(root / "server.db")
        server_app = create_app(Config(database_path=self.db_path, tls_cert_path="", tls_key_path=""))
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            self.port = sock.getsockname()[1]
        self.server_thread = ServerThread(server_app, "127.0.0.1", self.port)
        self.server_thread.start()
        time.sleep(0.3)
        self.server_url = f"https://127.0.0.1:{self.port}"
        self.web_app = create_web_app(self.server_url, False, self.state_root, secret_key="test-secret")
        self.client = self.web_app.test_client()

    def tearDown(self) -> None:
        self.web_app.config["BRIDGE"].shutdown()
        self.server_thread.shutdown()
        self.temp_dir.cleanup()

    def test_login_and_dashboard_render(self) -> None:
        bridge = self.web_app.config["BRIDGE"]
        reg = bridge.call(bridge.service.register("alice", "AlicePass123"))

        index_resp = self.client.get("/")
        self.assertIn("本地 Web UI 客户端", index_resp.get_data(as_text=True))

        login_resp = self.client.post(
            "/login",
            data={
                "username": "alice",
                "password": "AlicePass123",
                "otp": pyotp.TOTP(reg["otp_secret"]).now(),
            },
            follow_redirects=True,
        )
        body = login_resp.get_data(as_text=True)
        self.assertIn("SecureChat Web UI", body)
        self.assertIn("本机指纹", body)
        self.assertIn("alice", body)

        logout_resp = self.client.post("/logout", follow_redirects=True)
        self.assertIn("登录", logout_resp.get_data(as_text=True))


if __name__ == "__main__":
    unittest.main(verbosity=2)
