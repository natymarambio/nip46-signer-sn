"""Crypto tests against official vectors (NIP-44, NIP-49, NIP-19) plus round-trips."""

import json
from pathlib import Path

import pytest

from nip46_signer import crypto, keystore

VECTORS = json.loads((Path(__file__).parent / "vectors" / "nip44.vectors.json").read_text())["v2"]


@pytest.mark.parametrize("v", VECTORS["valid"]["get_conversation_key"])
def test_nip44_conversation_key(v):
    assert crypto.nip44_conversation_key(bytes.fromhex(v["sec1"]), v["pub2"]).hex() == v["conversation_key"]


@pytest.mark.parametrize("v", VECTORS["valid"]["calc_padded_len"])
def test_nip44_padding(v):
    assert crypto._calc_padded_len(v[0]) == v[1]


@pytest.mark.parametrize("v", VECTORS["valid"]["encrypt_decrypt"])
def test_nip44_encrypt_decrypt(v):
    sec1, sec2 = bytes.fromhex(v["sec1"]), bytes.fromhex(v["sec2"])
    key = crypto.nip44_conversation_key(sec1, crypto.pubkey_hex(sec2))
    assert key.hex() == v["conversation_key"]
    assert crypto.nip44_encrypt_with_key(key, v["plaintext"], bytes.fromhex(v["nonce"])) == v["payload"]
    # the peer derives the same key from the other side
    assert crypto.nip44_decrypt(sec2, crypto.pubkey_hex(sec1), v["payload"]) == v["plaintext"]


@pytest.mark.parametrize("v", VECTORS["invalid"]["decrypt"])
def test_nip44_invalid_payloads_rejected(v):
    with pytest.raises(Exception):
        crypto.nip44_decrypt_with_key(bytes.fromhex(v["conversation_key"]), v["payload"])


def test_nip04_roundtrip():
    a, b = crypto.generate_secret(), crypto.generate_secret()
    ct = crypto.nip04_encrypt(a, crypto.pubkey_hex(b), "hola ñandú 🚀")
    assert crypto.detect_scheme(ct) == "nip04"
    assert crypto.nip04_decrypt(b, crypto.pubkey_hex(a), ct) == "hola ñandú 🚀"


def test_nip49_official_vector():
    # https://github.com/nostr-protocol/nips/blob/master/49.md#test-data
    ncryptsec = (
        "ncryptsec1qgg9947rlpvqu76pj5ecreduf9jxhselq2nae2kghhvd5g7dgjtcxfqtd67p9m0w57lspw8gsq6yphnm8623nsl8x"
        "n9j4jdzz84zm3frztj3z7s35vpzmqf6ksu8r89qk5z2zxfmu5gv8th8wclt0h4p"
    )
    secret = keystore.decrypt_secret(ncryptsec, "nostr")
    assert secret.hex() == "3501454135014541350145413501453fefb02227e449e57cf4d3a3ce05378683"


def test_keystore_roundtrip_and_wrong_password(tmp_path):
    secret = crypto.generate_secret()
    path = keystore.save(secret, "correct horse", tmp_path / "key.json")
    assert (path.stat().st_mode & 0o777) == 0o600
    assert keystore.unlock("correct horse", path) == secret
    with pytest.raises(ValueError):
        keystore.unlock("wrong", path)


def test_nsec_npub_roundtrip():
    # NIP-19 example
    sk = crypto.parse_secret("nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5")
    assert sk.hex() == "67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa"
    assert crypto.nsec(sk) == "nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5"
    assert crypto.npub("7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e") == (
        "npub10elfcs4fr0l0r8af98jlmgdh9c8tcxjvz9qkw038js35mp4dma8qzvjptg"
    )


def test_event_sign_verify_matches_js_serialization():
    sk = crypto.generate_secret()
    ev = crypto.sign_event(sk, {"kind": 1, "created_at": 1, "tags": [["t", "ñ"]], "content": "é \"q\" \n"})
    assert crypto.verify_event(ev)
    ev["content"] = "tampered"
    assert not crypto.verify_event(ev)
