"""Credential encryption, password hashing and legacy User.db decryption.

New records use AES-256-GCM with a random nonce. The master key lives only in
``data/master.key`` on the server, never in the (possibly cloud) database.

``legacy_decrypt_password`` reproduces the encryption used by the original
MFC program: AES-128-ECB with a 16-byte GBK key and PKCS#7-style padding,
stored as uppercase hex. It is only used by the migration tool.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import os

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Aes.h in the original project: #define AES_KEY "远程连接管理软件" (GBK, 16 bytes)
LEGACY_AES_KEY = "远程连接管理软件".encode("gbk")
if len(LEGACY_AES_KEY) != 16:  # pragma: no cover - guards against source edits
    raise RuntimeError("legacy AES key must be exactly 16 bytes")

PBKDF2_ROUNDS = 200_000
_PREFIX = "v1:"


def encrypt_secret(plain: str | None, key: bytes) -> str:
    """Return a self-contained ciphertext string, or '' for empty input."""
    if not plain:
        return ""
    nonce = os.urandom(12)
    ciphertext = AESGCM(key).encrypt(nonce, plain.encode("utf-8"), None)
    return _PREFIX + base64.urlsafe_b64encode(nonce + ciphertext).decode("ascii")


def decrypt_secret(token: str | None, key: bytes) -> str:
    """Decrypt a value produced by encrypt_secret. Raises on tampering."""
    if not token:
        return ""
    if not token.startswith(_PREFIX):
        raise ValueError("unsupported credential format")
    blob = base64.urlsafe_b64decode(token[len(_PREFIX):].encode("ascii"))
    if len(blob) < 13:
        raise ValueError("truncated credential")
    plain = AESGCM(key).decrypt(blob[:12], blob[12:], None)
    return plain.decode("utf-8")


def legacy_decrypt_password(hex_text: str | None) -> str:
    """Decrypt a HostTab.Password value from the original SQLite User.db.

    The C implementation pads with ``n = 16 - len % 16`` bytes of value ``n``,
    encrypts with AES-128-ECB and stores the bytes as hex.
    """
    if not hex_text:
        return ""
    raw = bytes.fromhex(hex_text.strip())
    if not raw or len(raw) % 16:
        raise ValueError("legacy password is not a whole number of AES blocks")
    decryptor = Cipher(algorithms.AES(LEGACY_AES_KEY), modes.ECB()).decryptor()
    padded = decryptor.update(raw) + decryptor.finalize()
    pad = padded[-1]
    if pad < 1 or pad > 16 or pad >= len(padded):
        raise ValueError("invalid legacy padding")
    if any(byte != pad for byte in padded[-pad:]):
        raise ValueError("invalid legacy padding bytes")
    body = padded[:-pad]
    try:
        return body.decode("utf-8")
    except UnicodeDecodeError:
        return body.decode("gbk", errors="replace")


def hash_password(password: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ROUNDS)
    return "pbkdf2_sha256${}${}${}".format(
        PBKDF2_ROUNDS,
        base64.urlsafe_b64encode(salt).decode("ascii"),
        base64.urlsafe_b64encode(digest).decode("ascii"),
    )


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, rounds_text, salt_text, digest_text = stored.split("$", 3)
        if scheme != "pbkdf2_sha256":
            return False
        rounds = int(rounds_text)
        salt = base64.urlsafe_b64decode(salt_text.encode("ascii"))
        expected = base64.urlsafe_b64decode(digest_text.encode("ascii"))
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, rounds)
    return hmac.compare_digest(actual, expected)
