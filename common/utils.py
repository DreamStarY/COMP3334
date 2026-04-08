from __future__ import annotations

import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict

USERNAME_RE = re.compile(r"^[a-zA-Z0-9_.-]{3,32}$")


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return now_utc().isoformat()


def parse_iso(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value)


def is_expired(iso_timestamp: str | None) -> bool:
    dt = parse_iso(iso_timestamp)
    if dt is None:
        return False
    return dt <= now_utc()


def make_token(length: int = 32) -> str:
    return secrets.token_urlsafe(length)


def validate_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username or ""))


def validate_password(password: str) -> tuple[bool, str]:
    if len(password) < 10:
        return False, "密码至少需要 10 个字符"
    if password.lower() == password or password.upper() == password:
        return False, "密码应同时包含大小写字母"
    if not any(ch.isdigit() for ch in password):
        return False, "密码至少包含一个数字"
    return True, "ok"


def ttl_to_expiry(ttl_seconds: int | None) -> str | None:
    if not ttl_seconds:
        return None
    return (now_utc() + timedelta(seconds=int(ttl_seconds))).isoformat()


def ensure_parent(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)


def read_json(path: Path, default: Dict[str, Any] | None = None) -> Dict[str, Any]:
    if not path.exists():
        return default or {}
    return json.loads(path.read_text(encoding="utf-8"))


def write_json(path: Path, data: Dict[str, Any]) -> None:
    ensure_parent(path)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except PermissionError:
        pass
