"""Minimal BIP-173 bech32 encoding, enough for NIP-19 (npub/nsec) and NIP-49 (ncryptsec).

NIP-49 payloads are longer than the 90-char limit of BIP-173, so the limit is not enforced.
"""

CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"


def _polymod(values):
    gen = [0x3B6A57B2, 0x26508E6D, 0x1EA119FA, 0x3D4233DD, 0x2A1462B3]
    chk = 1
    for v in values:
        top = chk >> 25
        chk = (chk & 0x1FFFFFF) << 5 ^ v
        for i in range(5):
            chk ^= gen[i] if ((top >> i) & 1) else 0
    return chk


def _hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]


def _convertbits(data, frombits, tobits, pad=True):
    acc, bits, ret = 0, 0, []
    maxv = (1 << tobits) - 1
    for value in data:
        acc = (acc << frombits) | value
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        raise ValueError("invalid padding")
    return ret


def encode(hrp: str, data: bytes) -> str:
    values = _convertbits(data, 8, 5)
    polymod = _polymod(_hrp_expand(hrp) + values + [0] * 6) ^ 1
    checksum = [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]
    return hrp + "1" + "".join(CHARSET[d] for d in values + checksum)


def decode(bech: str) -> tuple[str, bytes]:
    bech = bech.strip().lower()
    pos = bech.rfind("1")
    if pos < 1 or pos + 7 > len(bech):
        raise ValueError("invalid bech32 string")
    hrp = bech[:pos]
    try:
        values = [CHARSET.index(c) for c in bech[pos + 1:]]
    except ValueError:
        raise ValueError("invalid bech32 character") from None
    if _polymod(_hrp_expand(hrp) + values) != 1:
        raise ValueError("invalid bech32 checksum")
    return hrp, bytes(_convertbits(values[:-6], 5, 8, pad=False))
