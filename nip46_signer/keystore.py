"""Password-protected storage of the Nostr secret key, using NIP-49 (`ncryptsec`).

File format (JSON, permissions 0600):
    {"version": 1, "pubkey": "<hex>", "ncryptsec": "ncryptsec1..."}

The public key is stored in clear so `info` works without the password.
"""

import hashlib
import json
import os
import unicodedata
from pathlib import Path

from nacl.bindings import (
    crypto_aead_xchacha20poly1305_ietf_decrypt,
    crypto_aead_xchacha20poly1305_ietf_encrypt,
)

from . import bech32
from .crypto import pubkey_hex

DEFAULT_PATH = Path(os.environ.get("NIP46_KEYFILE", Path.home() / ".nip46-signer" / "key.json"))
DEFAULT_LOG_N = 16  # 64 MiB of scrypt memory, ~0.1–0.5 s; NIP-49 suggests 16 as a sane minimum
KEY_SECURITY_UNKNOWN = 0x02


def _scrypt(password: str, salt: bytes, log_n: int) -> bytes:
    pw = unicodedata.normalize("NFKC", password).encode()
    n = 1 << log_n
    return hashlib.scrypt(pw, salt=salt, n=n, r=8, p=1, dklen=32, maxmem=128 * 8 * n * 2)


def encrypt_secret(secret: bytes, password: str, log_n: int = DEFAULT_LOG_N) -> str:
    salt, nonce = os.urandom(16), os.urandom(24)
    ad = bytes([KEY_SECURITY_UNKNOWN])
    ct = crypto_aead_xchacha20poly1305_ietf_encrypt(secret, ad, nonce, _scrypt(password, salt, log_n))
    return bech32.encode("ncryptsec", bytes([0x02, log_n]) + salt + nonce + ad + ct)


def decrypt_secret(ncryptsec: str, password: str) -> bytes:
    hrp, data = bech32.decode(ncryptsec)
    if hrp != "ncryptsec" or len(data) != 91 or data[0] != 0x02:
        raise ValueError("invalid ncryptsec")
    log_n, salt, nonce, ad, ct = data[1], data[2:18], data[18:42], data[42:43], data[43:]
    try:
        return crypto_aead_xchacha20poly1305_ietf_decrypt(ct, ad, nonce, _scrypt(password, salt, log_n))
    except Exception:
        raise ValueError("wrong password") from None


def save(secret: bytes, password: str, path: Path = DEFAULT_PATH) -> Path:
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    payload = {"version": 1, "pubkey": pubkey_hex(secret), "ncryptsec": encrypt_secret(secret, password)}
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as f:
        json.dump(payload, f, indent=2)
    return path


def load_meta(path: Path = DEFAULT_PATH) -> dict:
    with open(path) as f:
        return json.load(f)


def unlock(password: str, path: Path = DEFAULT_PATH) -> bytes:
    meta = load_meta(path)
    secret = decrypt_secret(meta["ncryptsec"], password)
    if pubkey_hex(secret) != meta["pubkey"]:
        raise ValueError("key file is inconsistent")
    return secret
