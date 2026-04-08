from __future__ import annotations

import shutil
from pathlib import Path
from typing import Any

from cryptography.exceptions import InvalidTag

from common.crypto import IdentityBundle, decrypt_private_bundle, encrypt_private_bundle, generate_identity_bundle
from common.utils import read_json, write_json


class DeviceStore:
    def __init__(self, base_dir: Path, username: str):
        self.base_dir = base_dir / username
        self.keystore_path = self.base_dir / "keystore.json"
        self.meta_path = self.base_dir / "device_meta.json"

    def has_keys(self) -> bool:
        return self.keystore_path.exists()

    def _bundle_to_identity(self, bundle: IdentityBundle) -> dict[str, Any]:
        return {
            "signing_private_key": bundle.signing_private_key_b64,
            "signing_public_key": bundle.signing_public_key_b64,
            "exchange_private_key": bundle.exchange_private_key_b64,
            "exchange_public_key": bundle.exchange_public_key_b64,
            "key_fingerprint": bundle.key_fingerprint,
        }

    def generate_identity(self) -> IdentityBundle:
        return generate_identity_bundle()

    def persist_identity(self, password: str, bundle: IdentityBundle) -> dict[str, Any]:
        encrypted = encrypt_private_bundle(password, bundle)
        write_json(self.keystore_path, encrypted)
        write_json(
            self.meta_path,
            {
                "username": self.base_dir.name,
                "key_fingerprint": bundle.key_fingerprint,
                "signing_public_key": bundle.signing_public_key_b64,
                "exchange_public_key": bundle.exchange_public_key_b64,
            },
        )
        return self._bundle_to_identity(bundle)

    def load_identity(self, password: str) -> dict[str, Any]:
        encrypted = read_json(self.keystore_path)
        try:
            return decrypt_private_bundle(password, encrypted)
        except InvalidTag as exc:
            raise RuntimeError(
                f"本地已存在用户 {self.base_dir.name} 的身份密钥，但当前密码无法解锁。"
                f"如果这是之前注册过的本机账号，请使用当时的密码；"
                f"如果要重新注册，请先删除本地目录 {self.base_dir}"
            ) from exc

    def rotate_identity(self, password: str) -> dict[str, Any]:
        bundle = generate_identity_bundle()
        return self.persist_identity(password, bundle)

    def read_meta(self) -> dict[str, Any]:
        return read_json(self.meta_path, default={})

    def clear_identity(self) -> None:
        if self.base_dir.exists():
            shutil.rmtree(self.base_dir, ignore_errors=True)
