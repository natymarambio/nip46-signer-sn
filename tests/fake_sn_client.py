"""Test helpers: an in-process Nostr relay and a NIP-46 client that mimics Stacker News.

The client reproduces what NDK 2.12.2 (the version Stacker News ships) does on login:
  connect([user_pubkey or "", secret]) -> expects "ack"
  get_public_key()
  sign_event(kind 27235, tags [["challenge", k1], ["u", url], ["method", "GET"]])
and then the verification Stacker News runs server-side (pages/api/auth/[...nextauth].js).
"""

import asyncio
import hashlib
import json
import secrets
import time
import uuid

from websockets.asyncio.client import connect
from websockets.asyncio.server import serve
from websockets.exceptions import ConnectionClosed

from nip46_signer import crypto


class LocalRelay:
    """Just enough of NIP-01: REQ with kinds/#p/since filters, EVENT fan-out, OK."""

    def __init__(self):
        self.subs = {}  # (ws, sub_id) -> filters

    @staticmethod
    def _match(f, ev):
        if "kinds" in f and ev["kind"] not in f["kinds"]:
            return False
        if "#p" in f and not any(t[0] == "p" and t[1] in f["#p"] for t in ev["tags"]):
            return False
        if "since" in f and ev["created_at"] < f["since"]:
            return False
        return True

    async def _handler(self, ws):
        try:
            async for raw in ws:
                msg = json.loads(raw)
                if msg[0] == "REQ":
                    self.subs[(ws, msg[1])] = msg[2:]
                    await ws.send(json.dumps(["EOSE", msg[1]]))
                elif msg[0] == "EVENT":
                    ev = msg[1]
                    await ws.send(json.dumps(["OK", ev["id"], crypto.verify_event(ev), ""]))
                    for (sock, sid), filters in list(self.subs.items()):
                        if any(self._match(f, ev) for f in filters):
                            try:
                                await sock.send(json.dumps(["EVENT", sid, ev]))
                            except Exception:
                                pass
        except ConnectionClosed:
            pass
        finally:
            for key in [k for k in self.subs if k[0] is ws]:
                del self.subs[key]

    async def __aenter__(self):
        self.server = await serve(self._handler, "127.0.0.1", 0)
        self.url = f"ws://127.0.0.1:{self.server.sockets[0].getsockname()[1]}"
        return self

    async def __aexit__(self, *exc):
        self.server.close()
        await self.server.wait_closed()


class FakeStackerNewsClient:
    def __init__(self, relay_url: str, scheme: str = "nip04"):
        self.relay_url = relay_url
        self.scheme = scheme  # NDK 2.12 default is nip04
        self.sk = crypto.generate_secret()
        self.pk = crypto.pubkey_hex(self.sk)
        self.pending: dict[str, asyncio.Future] = {}

    async def __aenter__(self):
        self.ws = await connect(self.relay_url)
        sub = uuid.uuid4().hex[:8]
        await self.ws.send(json.dumps(["REQ", sub, {"kinds": [24133], "#p": [self.pk]}]))
        self.reader = asyncio.create_task(self._read())
        return self

    async def __aexit__(self, *exc):
        self.reader.cancel()
        await self.ws.close()

    async def _read(self):
        async for raw in self.ws:
            msg = json.loads(raw)
            if msg[0] != "EVENT":
                continue
            ev = msg[2]
            dec = crypto.nip04_decrypt if "?iv=" in ev["content"] else crypto.nip44_decrypt
            res = json.loads(dec(self.sk, ev["pubkey"], ev["content"]))
            res["_from"] = ev["pubkey"]
            fut = self.pending.pop(res["id"], None)
            if fut and not fut.done():
                fut.set_result(res)
            elif "_any" in self.pending:
                self.pending.pop("_any").set_result(res)

    async def request(self, signer_pubkey: str, method: str, params: list, timeout=5) -> dict:
        req_id = secrets.token_hex(4)
        fut = asyncio.get_running_loop().create_future()
        self.pending[req_id] = fut
        enc = crypto.nip04_encrypt if self.scheme == "nip04" else crypto.nip44_encrypt
        ev = crypto.sign_event(self.sk, {
            "kind": 24133, "created_at": int(time.time()), "tags": [["p", signer_pubkey]],
            "content": enc(self.sk, signer_pubkey, json.dumps({"id": req_id, "method": method, "params": params})),
        })
        await self.ws.send(json.dumps(["EVENT", ev]))
        return await asyncio.wait_for(fut, timeout)

    async def wait_any(self, timeout=5) -> dict:
        fut = asyncio.get_running_loop().create_future()
        self.pending["_any"] = fut
        return await asyncio.wait_for(fut, timeout)

    async def login(self, bunker_uri: str) -> dict:
        """Full Stacker News login flow; returns the signed auth event after SN-style checks."""
        from urllib.parse import parse_qs, urlparse
        u = urlparse(bunker_uri.replace("bunker://", "http://"))  # same patch SN applies
        signer_pk, secret = u.hostname, parse_qs(u.query)["secret"][0]

        res = await self.request(signer_pk, "connect", ["", secret])
        assert res.get("result") == "ack", res
        user_pk = (await self.request(signer_pk, "get_public_key", []))["result"]

        k1 = secrets.token_hex(32)
        template = {
            "kind": 27235, "created_at": int(time.time()), "content": "Stacker News Authentication",
            "tags": [["challenge", k1], ["u", "https://stacker.news"], ["method", "GET"]],
        }
        res = await self.request(signer_pk, "sign_event", [json.dumps(template)])
        assert "error" not in res, res
        ev = json.loads(res["result"])

        # --- what Stacker News checks server-side (nostrEventAuth) ---
        expected_id = hashlib.sha256(json.dumps(
            [0, ev["pubkey"], ev["created_at"], ev["kind"], ev["tags"], ev["content"]],
            separators=(",", ":"), ensure_ascii=False).encode()).hexdigest()
        assert ev["id"] == expected_id, "invalid event id"
        assert crypto.verify_event(ev), "invalid signature"
        assert ev["tags"][0] == ["challenge", k1], "challenge must be the first tag"
        assert ev["pubkey"] == user_pk
        return ev
