"""End-to-end tests over a real (local) websocket relay."""

import asyncio
import json
import time

import pytest

from nip46_signer import crypto
from nip46_signer.signer import Nip46Signer, allow_all, deny_all
from tests.fake_sn_client import FakeStackerNewsClient, LocalRelay


def run(coro):
    return asyncio.run(asyncio.wait_for(coro, 20))


async def _with_signer(approve, body):
    async with LocalRelay() as relay:
        sk = crypto.generate_secret()
        signer = Nip46Signer(sk, [relay.url], approve, on_status=lambda m: None)
        await signer.start()
        try:
            await body(relay, signer, sk)
        finally:
            await signer.stop()


@pytest.mark.parametrize("scheme", ["nip04", "nip44"])
def test_stacker_news_login_flow(scheme):
    async def body(relay, signer, sk):
        async with FakeStackerNewsClient(relay.url, scheme) as client:
            ev = await client.login(signer.bunker_uri())
            assert ev["pubkey"] == crypto.pubkey_hex(sk)
            assert ev["kind"] == 27235
    run(_with_signer(allow_all, body))


def test_secret_is_single_use_and_rotated():
    async def body(relay, signer, sk):
        old_uri = signer.bunker_uri()
        async with FakeStackerNewsClient(relay.url) as c1:
            await c1.login(old_uri)
        assert signer.bunker_uri() != old_uri
        async with FakeStackerNewsClient(relay.url) as c2:
            with pytest.raises(AssertionError):
                await c2.login(old_uri)  # reused secret is refused
        async with FakeStackerNewsClient(relay.url) as c3:
            await c3.login(signer.bunker_uri())  # fresh token works
    run(_with_signer(allow_all, body))


def test_requests_without_connect_are_refused():
    async def body(relay, signer, sk):
        async with FakeStackerNewsClient(relay.url) as client:
            res = await client.request(signer.pubkey, "sign_event",
                                       [json.dumps({"kind": 1, "content": "x", "tags": [], "created_at": 1})])
            assert "not connected" in res["error"]
            assert (await client.request(signer.pubkey, "ping", []))["result"] == "pong"
    run(_with_signer(allow_all, body))


def test_user_can_reject():
    async def body(relay, signer, sk):
        async with FakeStackerNewsClient(relay.url) as client:
            secret = signer.bunker_uri().split("secret=")[1]
            res = await client.request(signer.pubkey, "connect", ["", secret])
            assert "rejected" in res["error"]
    run(_with_signer(deny_all, body))


def test_sign_only_rejected_when_connect_allowed():
    async def approve(kind, client, details):
        return kind == "connect"

    async def body(relay, signer, sk):
        async with FakeStackerNewsClient(relay.url) as client:
            with pytest.raises(AssertionError, match="rejected"):
                await client.login(signer.bunker_uri())
    run(_with_signer(approve, body))


def test_nip44_encrypt_decrypt_methods():
    async def body(relay, signer, sk):
        async with FakeStackerNewsClient(relay.url, "nip44") as client:
            secret = signer.bunker_uri().split("secret=")[1]
            await client.request(signer.pubkey, "connect", ["", secret])
            peer = crypto.generate_secret()
            ct = (await client.request(signer.pubkey, "nip44_encrypt", [crypto.pubkey_hex(peer), "hola"]))["result"]
            assert crypto.nip44_decrypt(peer, signer.pubkey, ct) == "hola"
            res = await client.request(signer.pubkey, "unknown_method", [])
            assert "unsupported" in res["error"]
    run(_with_signer(allow_all, body))


def test_nostrconnect_flow():
    async def body(relay, signer, sk):
        async with FakeStackerNewsClient(relay.url, "nip44") as client:
            uri = f"nostrconnect://{client.pk}?relay={relay.url}&secret=s3cr3t&name=Demo"
            waiter = asyncio.create_task(client.wait_any())
            await signer.accept_nostrconnect(uri)
            res = await waiter
            assert res["result"] == "s3cr3t" and res["_from"] == signer.pubkey
            # session is established: signing works without a separate connect
            r = await client.request(signer.pubkey, "sign_event",
                                     [json.dumps({"kind": 1, "content": "hi", "tags": [],
                                                  "created_at": int(time.time())})])
            assert crypto.verify_event(json.loads(r["result"]))
    run(_with_signer(allow_all, body))
