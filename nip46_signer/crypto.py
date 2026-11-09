"""Nostr cryptography: keys (NIP-01/NIP-19), event signing (BIP-340), NIP-04 and NIP-44 v2.

secp256k1 comes from `coincurve` (libsecp256k1 bindings) and symmetric primitives from
`cryptography`. Nothing here is hand-rolled except the NIP-specific glue.
"""

import base64
import hashlib
import hmac
import json
import math
import os

from coincurve import PrivateKey, PublicKey, PublicKeyXOnly
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.kdf.hkdf import HKDFExpand

from . import bech32


# --------------------------------------------------------------------------- keys

def generate_secret() -> bytes:
    return PrivateKey().secret


def pubkey_hex(secret: bytes) -> str:
    """x-only public key (32 bytes, hex) as used everywhere in Nostr."""
    return PublicKeyXOnly.from_secret(secret).format().hex()


def parse_secret(text: str) -> bytes:
    """Accepts an `nsec1...` or a 64-char hex private key."""
    text = text.strip()
    if text.startswith("nsec1"):
        hrp, data = bech32.decode(text)
        if hrp != "nsec" or len(data) != 32:
            raise ValueError("invalid nsec")
        secret = data
    else:
        secret = bytes.fromhex(text)
        if len(secret) != 32:
            raise ValueError("private key must be 32 bytes")
    PrivateKey(secret)  # validates range (0 < k < n)
    return secret


def npub(pubkey: str) -> str:
    return bech32.encode("npub", bytes.fromhex(pubkey))


def nsec(secret: bytes) -> str:
    return bech32.encode("nsec", secret)


# ------------------------------------------------------------------------- events

def event_id(ev: dict) -> str:
    """NIP-01 id: sha256 of the compact JSON serialization.

    `ensure_ascii=False` + compact separators reproduces JavaScript's JSON.stringify, which is
    what Stacker News uses server-side to recompute the id.
    """
    data = [0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]]
    raw = json.dumps(data, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(raw.encode()).hexdigest()


def sign_event(secret: bytes, template: dict) -> dict:
    ev = {
        "pubkey": pubkey_hex(secret),
        "created_at": int(template["created_at"]),
        "kind": int(template["kind"]),
        "tags": template.get("tags", []),
        "content": template.get("content", ""),
    }
    ev["id"] = event_id(ev)
    ev["sig"] = PrivateKey(secret).sign_schnorr(bytes.fromhex(ev["id"]), os.urandom(32)).hex()
    return ev


def verify_event(ev: dict) -> bool:
    try:
        if event_id(ev) != ev["id"]:
            return False
        return PublicKeyXOnly(bytes.fromhex(ev["pubkey"])).verify(
            bytes.fromhex(ev["sig"]), bytes.fromhex(ev["id"])
        )
    except Exception:
        return False


# ------------------------------------------------------------------------- ECDH

def _shared_x(secret: bytes, pubkey: str) -> bytes:
    """Raw x coordinate of secret * P (no hashing), as required by NIP-04 and NIP-44."""
    point = PublicKey(b"\x02" + bytes.fromhex(pubkey)).multiply(secret)
    return point.format(compressed=True)[1:]


# ------------------------------------------------------------------------- NIP-04
# Deprecated but still the default of NDK 2.12 (the version Stacker News ships), so required.

def nip04_encrypt(secret: bytes, pubkey: str, plaintext: str) -> str:
    key, iv = _shared_x(secret, pubkey), os.urandom(16)
    padder = padding.PKCS7(128).padder()
    data = padder.update(plaintext.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    ct = enc.update(data) + enc.finalize()
    return f"{base64.b64encode(ct).decode()}?iv={base64.b64encode(iv).decode()}"


def nip04_decrypt(secret: bytes, pubkey: str, payload: str) -> str:
    ct_b64, iv_b64 = payload.split("?iv=")
    key = _shared_x(secret, pubkey)
    dec = Cipher(algorithms.AES(key), modes.CBC(base64.b64decode(iv_b64))).decryptor()
    data = dec.update(base64.b64decode(ct_b64)) + dec.finalize()
    unpadder = padding.PKCS7(128).unpadder()
    return (unpadder.update(data) + unpadder.finalize()).decode()


# ------------------------------------------------------------------------- NIP-44 v2

def nip44_conversation_key(secret: bytes, pubkey: str) -> bytes:
    # HKDF-extract == HMAC(salt, ikm)
    return hmac.new(b"nip44-v2", _shared_x(secret, pubkey), hashlib.sha256).digest()


def _nip44_message_keys(conv_key: bytes, nonce: bytes):
    keys = HKDFExpand(algorithm=hashes.SHA256(), length=76, info=nonce).derive(conv_key)
    return keys[0:32], keys[32:44], keys[44:76]


def _calc_padded_len(n: int) -> int:
    if n <= 32:
        return 32
    next_power = 1 << (math.floor(math.log2(n - 1)) + 1)
    chunk = 32 if next_power <= 256 else next_power // 8
    return chunk * (math.floor((n - 1) / chunk) + 1)


def _chacha20(key: bytes, nonce12: bytes, data: bytes) -> bytes:
    # `cryptography` expects a 16-byte nonce: 4-byte little-endian counter (0) + 12-byte nonce.
    c = Cipher(algorithms.ChaCha20(key, b"\x00" * 4 + nonce12), mode=None).encryptor()
    return c.update(data) + c.finalize()


def nip44_encrypt_with_key(conv_key: bytes, plaintext: str, nonce: bytes | None = None) -> str:
    raw = plaintext.encode()
    if not 1 <= len(raw) <= 65535:
        raise ValueError("invalid plaintext length")
    nonce = nonce or os.urandom(32)
    ck, cn, hk = _nip44_message_keys(conv_key, nonce)
    padded = len(raw).to_bytes(2, "big") + raw + b"\x00" * (_calc_padded_len(len(raw)) - len(raw))
    ct = _chacha20(ck, cn, padded)
    mac = hmac.new(hk, nonce + ct, hashlib.sha256).digest()
    return base64.b64encode(b"\x02" + nonce + ct + mac).decode()


def nip44_decrypt_with_key(conv_key: bytes, payload: str) -> str:
    if not payload or payload[0] == "#":
        raise ValueError("unknown encryption version")
    data = base64.b64decode(payload, validate=True)
    if data[0] != 2 or not 99 <= len(data) <= 65603:
        raise ValueError("invalid payload")
    nonce, ct, mac = data[1:33], data[33:-32], data[-32:]
    ck, cn, hk = _nip44_message_keys(conv_key, nonce)
    if not hmac.compare_digest(mac, hmac.new(hk, nonce + ct, hashlib.sha256).digest()):
        raise ValueError("invalid MAC")
    padded = _chacha20(ck, cn, ct)
    n = int.from_bytes(padded[:2], "big")
    if n == 0 or len(padded) != 2 + _calc_padded_len(n):
        raise ValueError("invalid padding")
    return padded[2:2 + n].decode()


def nip44_encrypt(secret: bytes, pubkey: str, plaintext: str) -> str:
    return nip44_encrypt_with_key(nip44_conversation_key(secret, pubkey), plaintext)


def nip44_decrypt(secret: bytes, pubkey: str, payload: str) -> str:
    return nip44_decrypt_with_key(nip44_conversation_key(secret, pubkey), payload)


def detect_scheme(payload: str) -> str:
    """NIP-04 payloads always carry '?iv='; NIP-44 payloads are plain base64."""
    return "nip04" if "?iv=" in payload else "nip44"
