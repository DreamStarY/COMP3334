from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path


@dataclass(slots=True)
class Config:
    host: str = os.environ.get("SECURECHAT_HOST", "127.0.0.1")
    port: int = int(os.environ.get("SECURECHAT_PORT", "5443"))
    database_path: str = os.environ.get(
        "SECURECHAT_DB", str(Path(__file__).resolve().parent.parent / "server.db")
    )
    tls_cert_path: str = os.environ.get(
        "SECURECHAT_TLS_CERT", str(Path(__file__).resolve().parent.parent / "certs" / "localhost-cert.pem")
    )
    tls_key_path: str = os.environ.get(
        "SECURECHAT_TLS_KEY", str(Path(__file__).resolve().parent.parent / "certs" / "localhost-key.pem")
    )
    token_ttl_hours: int = int(os.environ.get("SECURECHAT_TOKEN_TTL_HOURS", "12"))
    max_pending_messages: int = int(os.environ.get("SECURECHAT_MAX_PENDING_MESSAGES", "500"))
    max_message_bytes: int = int(os.environ.get("SECURECHAT_MAX_MESSAGE_BYTES", str(32 * 1024)))
