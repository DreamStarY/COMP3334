from __future__ import annotations

import base64
import hashlib
import json
import os
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

RAW_ENCODING = serialization.Encoding.Raw
RAW_PUBLIC = serialization.PublicFormat.Raw
RAW_PRIVATE = serialization.PrivateFormat.Raw
NO_ENCRYPTION = serialization.NoEncryption()


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def iso_now() -> str:
    return utc_now().isoformat()


def canonical_json(data: Dict[str, Any]) -> str:
    return json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"))


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def format_fingerprint(hex_digest: str) -> str:
    clean = hex_digest.lower()
    return " ".join(clean[i : i + 4] for i in range(0, min(len(clean), 48), 4))


@dataclass(slots=True)
class IdentityBundle:
    signing_private_key_b64: str
    signing_public_key_b64: str
    exchange_private_key_b64: str
    exchange_public_key_b64: str
    key_fingerprint: str

    def public_bundle(self) -> Dict[str, str]:
        return {
            "signing_public_key": self.signing_public_key_b64,
            "exchange_public_key": self.exchange_public_key_b64,
            "key_fingerprint": self.key_fingerprint,
        }


def generate_identity_bundle() -> IdentityBundle:
    signing_private = ed25519.Ed25519PrivateKey.generate()
    exchange_private = x25519.X25519PrivateKey.generate()

    signing_private_raw = signing_private.private_bytes(RAW_ENCODING, RAW_PRIVATE, NO_ENCRYPTION)
    signing_public_raw = signing_private.public_key().public_bytes(RAW_ENCODING, RAW_PUBLIC)
    exchange_private_raw = exchange_private.private_bytes(RAW_ENCODING, RAW_PRIVATE, NO_ENCRYPTION)
    exchange_public_raw = exchange_private.public_key().public_bytes(RAW_ENCODING, RAW_PUBLIC)

    fingerprint = fingerprint_from_public_keys(signing_public_raw, exchange_public_raw)
    return IdentityBundle(
        signing_private_key_b64=b64e(signing_private_raw),
        signing_public_key_b64=b64e(signing_public_raw),
        exchange_private_key_b64=b64e(exchange_private_raw),
        exchange_public_key_b64=b64e(exchange_public_raw),
        key_fingerprint=fingerprint,
    )


def fingerprint_from_public_keys(signing_public_raw: bytes, exchange_public_raw: bytes) -> str:
    return sha256_hex(signing_public_raw + exchange_public_raw)


def load_signing_private_key(key_b64: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(b64d(key_b64))


def load_signing_public_key(key_b64: str) -> ed25519.Ed25519PublicKey:
    return ed25519.Ed25519PublicKey.from_public_bytes(b64d(key_b64))


def load_exchange_private_key(key_b64: str) -> x25519.X25519PrivateKey:
    return x25519.X25519PrivateKey.from_private_bytes(b64d(key_b64))


def load_exchange_public_key(key_b64: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(b64d(key_b64))


def derive_root_key(
    local_exchange_private_b64: str,
    remote_exchange_public_b64: str,
    user_a: str,
    user_b: str,
    local_key_fingerprint: str,
    remote_key_fingerprint: str,
) -> bytes:
    shared_secret = load_exchange_private_key(local_exchange_private_b64).exchange(
        load_exchange_public_key(remote_exchange_public_b64)
    )
    ordered_users = "|".join(sorted([user_a, user_b])).encode("utf-8")
    ordered_fps = "|".join(sorted([local_key_fingerprint, remote_key_fingerprint])).encode("ascii")
    salt = hashlib.sha256(ordered_users + b"|" + ordered_fps).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=b"securechat-root-v1",
    ).derive(shared_secret)


def derive_session_id(
    user_a: str,
    user_b: str,
    local_key_fingerprint: str,
    remote_key_fingerprint: str,
) -> str:
    ordered_users = "|".join(sorted([user_a, user_b]))
    ordered_fps = "|".join(sorted([local_key_fingerprint, remote_key_fingerprint]))
    return sha256_hex(f"session|{ordered_users}|{ordered_fps}".encode("utf-8"))


def derive_message_key(root_key: bytes, session_id: str, counter: int, message_id: str) -> bytes:
    salt = hashlib.sha256(message_id.encode("utf-8")).digest()
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        info=f"securechat-msg-v1|{session_id}|{counter}".encode("utf-8"),
    ).derive(root_key)


def sign_envelope(signing_private_key_b64: str, signable_payload: str) -> str:
    signature = load_signing_private_key(signing_private_key_b64).sign(signable_payload.encode("utf-8"))
    return b64e(signature)


def verify_signature(signing_public_key_b64: str, signable_payload: str, signature_b64: str) -> bool:
    try:
        load_signing_public_key(signing_public_key_b64).verify(
            b64d(signature_b64), signable_payload.encode("utf-8")
        )
        return True
    except InvalidSignature:
        return False


def encrypt_payload(root_key: bytes, session_id: str, counter: int, message_id: str, plaintext: Dict[str, Any], associated_data: Dict[str, Any]) -> Dict[str, str]:
    message_key = derive_message_key(root_key, session_id, counter, message_id)
    nonce = os.urandom(12)
    aesgcm = AESGCM(message_key)
    ad_json = canonical_json(associated_data)
    ciphertext = aesgcm.encrypt(nonce, canonical_json(plaintext).encode("utf-8"), ad_json.encode("utf-8"))
    return {
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
        "ad_json": ad_json,
    }


def decrypt_payload(root_key: bytes, envelope: Dict[str, Any]) -> Dict[str, Any]:
    counter = int(envelope["counter"])
    message_id = str(envelope["message_id"])
    session_id = str(envelope["session_id"])
    message_key = derive_message_key(root_key, session_id, counter, message_id)
    aesgcm = AESGCM(message_key)
    try:
        plaintext = aesgcm.decrypt(
            b64d(envelope["nonce"]),
            b64d(envelope["ciphertext"]),
            envelope["ad_json"].encode("utf-8"),
        )
    except InvalidTag as exc:
        raise ValueError("密文认证失败，消息可能被篡改或密钥不匹配") from exc
    return json.loads(plaintext.decode("utf-8"))


def build_signable_payload(envelope: Dict[str, Any]) -> str:
    signable = {
        "message_id": envelope["message_id"],
        "session_id": envelope["session_id"],
        "counter": envelope["counter"],
        "nonce": envelope["nonce"],
        "ciphertext": envelope["ciphertext"],
        "ad_json": envelope["ad_json"],
        "sender": envelope["sender"],
        "recipient": envelope["recipient"],
        "sender_key_fingerprint": envelope["sender_key_fingerprint"],
        "recipient_key_fingerprint": envelope["recipient_key_fingerprint"],
    }
    return canonical_json(signable)


def encrypt_private_bundle(password: str, identity: IdentityBundle) -> Dict[str, Any]:
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_storage_key(password, salt)
    aesgcm = AESGCM(key)
    secret_payload = canonical_json(
        {
            "signing_private_key": identity.signing_private_key_b64,
            "signing_public_key": identity.signing_public_key_b64,
            "exchange_private_key": identity.exchange_private_key_b64,
            "exchange_public_key": identity.exchange_public_key_b64,
            "key_fingerprint": identity.key_fingerprint,
            "version": 1,
            "created_at": iso_now(),
        }
    ).encode("utf-8")
    ciphertext = aesgcm.encrypt(nonce, secret_payload, b"securechat-keystore-v1")
    return {
        "version": 1,
        "kdf": "scrypt",
        "salt": b64e(salt),
        "nonce": b64e(nonce),
        "ciphertext": b64e(ciphertext),
    }


def decrypt_private_bundle(password: str, encrypted_blob: Dict[str, Any]) -> Dict[str, Any]:
    salt = b64d(encrypted_blob["salt"])
    nonce = b64d(encrypted_blob["nonce"])
    ciphertext = b64d(encrypted_blob["ciphertext"])
    key = _derive_storage_key(password, salt)
    plaintext = AESGCM(key).decrypt(nonce, ciphertext, b"securechat-keystore-v1")
    return json.loads(plaintext.decode("utf-8"))


def _derive_storage_key(password: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
    return kdf.derive(password.encode("utf-8"))
