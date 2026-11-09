"""NIP-46 remote signer ("bunker").

Design notes (see README for the full rationale):
- remote-signer key == user key. The spec allows it and it is the most compatible option
  with older clients; NDK 2.12 (used by Stacker News) works either way.
- Requests may arrive NIP-04 or NIP-44 encrypted; each response uses the same scheme as its
  request. NDK 2.12 defaults to NIP-04, the spec mandates NIP-44.
- Every sensitive method (connect, sign_event, encrypt/decrypt) goes through `approve`, a
  callback the UI provides. The CLI asks the user on the terminal.
- Sessions live in memory: they end when the process stops.
"""

import asyncio
import json
import logging
import secrets
import time
from dataclasses import dataclass, field
from typing import Awaitable, Callable
from urllib.parse import parse_qs, quote, urlparse

from . import crypto
from .relays import RelayPool

log = logging.getLogger(__name__)

KIND_NIP46 = 24133
DEFAULT_RELAYS = ["wss://relay.nsec.app", "wss://nos.lol"]

# approve(kind_of_request, client_pubkey, human_readable_details) -> bool
Approver = Callable[[str, str, str], Awaitable[bool]]


async def deny_all(*_):
    return False


async def allow_all(*_):
    return True


@dataclass
class Session:
    client_pubkey: str
    metadata: dict = field(default_factory=dict)
    connected_at: int = field(default_factory=lambda: int(time.time()))


class Nip46Signer:
    def __init__(self, secret: bytes, relays: list[str] | None = None, approve: Approver = deny_all,
                 on_status: Callable[[str], None] = print):
        self.secret = secret
        self.pubkey = crypto.pubkey_hex(secret)
        self.relays = relays or DEFAULT_RELAYS
        self.approve = approve
        self.status = on_status
        self.sessions: dict[str, Session] = {}
        self.connect_secret = secrets.token_hex(16)
        self.pool = RelayPool(self.relays, self._on_event)
        self._lock = asyncio.Lock()  # one request at a time keeps terminal prompts readable

    # ------------------------------------------------------------------ public API

    def bunker_uri(self) -> str:
        relays = "&".join(f"relay={quote(r, safe='')}" for r in self.relays)
        return f"bunker://{self.pubkey}?{relays}&secret={self.connect_secret}"

    async def start(self):
        self.pool.subscribe({"kinds": [KIND_NIP46], "#p": [self.pubkey], "since": int(time.time()) - 5})
        await self.pool.start()

    async def stop(self):
        await self.pool.stop()

    async def accept_nostrconnect(self, uri: str):
        """Client-initiated flow: the user pastes a `nostrconnect://` URI shown by an app."""
        u = urlparse(uri)
        if u.scheme != "nostrconnect":
            raise ValueError("expected a nostrconnect:// URI")
        client_pubkey = u.netloc or u.path.lstrip("/")
        q = parse_qs(u.query)
        if len(client_pubkey) != 64 or not q.get("relay") or not q.get("secret"):
            raise ValueError("nostrconnect URI must contain a client pubkey, relay and secret")
        meta = {k: q[k][0] for k in ("name", "url", "image", "perms") if k in q}
        details = f"app: {meta.get('name', '?')} {meta.get('url', '')}\npermisos: {meta.get('perms', '-')}"
        if not await self.approve("connect", client_pubkey, details):
            raise PermissionError("connection rejected by user")
        await self.pool.add_relays(q["relay"])
        await asyncio.sleep(1.5)  # let the new sockets open before publishing
        self.sessions[client_pubkey] = Session(client_pubkey, meta)
        # The connect *response* carries the client's secret so it can detect spoofing.
        await self._respond(client_pubkey, secrets.token_hex(8), q["secret"][0], None, "nip44")
        self.status(f"Conectado con {meta.get('name', client_pubkey[:12])} (nostrconnect)")

    # ------------------------------------------------------------------ internals

    async def _on_event(self, ev: dict):
        if ev.get("kind") != KIND_NIP46 or not crypto.verify_event(ev):
            return
        client = ev["pubkey"]
        scheme = crypto.detect_scheme(ev["content"])
        try:
            if scheme == "nip04":
                req = json.loads(crypto.nip04_decrypt(self.secret, client, ev["content"]))
            else:
                req = json.loads(crypto.nip44_decrypt(self.secret, client, ev["content"]))
        except Exception as e:
            log.debug("could not decrypt event %s: %s", ev.get("id"), e)
            return
        if "method" not in req:  # a response addressed to us; we are not a client
            return
        async with self._lock:
            try:
                result = await self._dispatch(client, req.get("method"), req.get("params") or [])
                await self._respond(client, req.get("id"), result, None, scheme)
            except Exception as e:
                await self._respond(client, req.get("id"), None, str(e) or e.__class__.__name__, scheme)

    async def _respond(self, client: str, req_id, result, error, scheme: str):
        payload = {"id": req_id, "result": result}
        if error:
            payload["error"] = error
        text = json.dumps(payload, ensure_ascii=False)
        enc = crypto.nip04_encrypt if scheme == "nip04" else crypto.nip44_encrypt
        ev = crypto.sign_event(self.secret, {
            "kind": KIND_NIP46,
            "created_at": int(time.time()),
            "tags": [["p", client]],
            "content": enc(self.secret, client, text),
        })
        await self.pool.publish(ev)

    async def _dispatch(self, client: str, method: str, params: list):
        if method == "connect":
            return await self._connect(client, params)
        if method == "ping":
            return "pong"
        if client not in self.sessions:
            raise PermissionError("not connected: send `connect` first")
        if method == "get_public_key":
            return self.pubkey
        if method == "sign_event":
            return await self._sign_event(client, params)
        if method in ("nip04_encrypt", "nip04_decrypt", "nip44_encrypt", "nip44_decrypt"):
            return await self._cipher(client, method, params)
        if method == "switch_relays":
            return None  # we keep the relays the bunker URI advertised
        if method == "logout":
            self.sessions.pop(client, None)
            self.status(f"Sesión cerrada por el cliente {client[:12]}…")
            return "ack"
        raise ValueError(f"unsupported method: {method}")

    async def _connect(self, client: str, params: list):
        if client in self.sessions:
            return "ack"
        secret = params[1] if len(params) > 1 else ""
        if not secret or not secrets.compare_digest(secret, self.connect_secret):
            raise PermissionError("invalid or already used secret")
        meta = {}
        if len(params) > 3 and params[3]:
            try:
                meta = json.loads(params[3])
            except ValueError:
                pass
        perms = params[2] if len(params) > 2 and params[2] else "-"
        details = f"app: {meta.get('name', 'desconocida')} {meta.get('url', '')}\npermisos pedidos: {perms}"
        if not await self.approve("connect", client, details):
            raise PermissionError("connection rejected by user")
        self.sessions[client] = Session(client, meta)
        # The secret is single-use (NIP-46). Issue a fresh one for the next client.
        self.connect_secret = secrets.token_hex(16)
        self.status(f"Cliente {client[:12]}… conectado. Nuevo token para otro login:\n  {self.bunker_uri()}")
        return "ack"  # NDK requires exactly "ack" for bunker:// connections

    async def _sign_event(self, client: str, params: list):
        template = json.loads(params[0])
        if "pubkey" in template and template["pubkey"] not in ("", self.pubkey):
            raise ValueError("event pubkey does not match the user key")
        template.setdefault("created_at", int(time.time()))
        details = (f"kind: {template.get('kind')}\ncontent: {str(template.get('content'))[:200]}\n"
                   f"tags: {json.dumps(template.get('tags', []), ensure_ascii=False)[:300]}")
        if not await self.approve("sign_event", client, details):
            raise PermissionError("signature rejected by user")
        signed = crypto.sign_event(self.secret, template)
        self.status(f"Evento kind {signed['kind']} firmado (id {signed['id'][:12]}…)")
        return json.dumps(signed, ensure_ascii=False)

    async def _cipher(self, client: str, method: str, params: list):
        peer, text = params[0], params[1]
        if not await self.approve(method, client, f"contraparte: {peer[:16]}…"):
            raise PermissionError("rejected by user")
        fn = {
            "nip04_encrypt": crypto.nip04_encrypt, "nip04_decrypt": crypto.nip04_decrypt,
            "nip44_encrypt": crypto.nip44_encrypt, "nip44_decrypt": crypto.nip44_decrypt,
        }[method]
        return fn(self.secret, peer, text)
