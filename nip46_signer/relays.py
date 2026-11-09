"""Tiny Nostr relay pool: one websocket per relay, auto-reconnect, one subscription, publish to all."""

import asyncio
import json
import logging
import uuid

from websockets.asyncio.client import connect

log = logging.getLogger(__name__)


class RelayPool:
    def __init__(self, urls: list[str], on_event):
        """`on_event(event_dict)` is awaited for each new (deduplicated) event received."""
        self.urls = list(dict.fromkeys(urls))
        self.on_event = on_event
        self._filters: list[dict] = []
        self._sub_id = uuid.uuid4().hex[:12]
        self._sockets: dict[str, object] = {}
        self._seen: set[str] = set()
        self._tasks: list[asyncio.Task] = []
        self._ready = asyncio.Event()

    def subscribe(self, *filters: dict):
        self._filters = list(filters)

    async def start(self, ready_timeout: float = 10):
        self._tasks = [asyncio.create_task(self._run(url)) for url in self.urls]
        try:
            await asyncio.wait_for(self._ready.wait(), ready_timeout)
        except asyncio.TimeoutError:
            raise ConnectionError(f"could not connect to any relay: {self.urls}") from None

    async def stop(self):
        for t in self._tasks:
            t.cancel()
        await asyncio.gather(*self._tasks, return_exceptions=True)

    async def add_relays(self, urls: list[str]):
        for url in urls:
            if url not in self.urls:
                self.urls.append(url)
                self._tasks.append(asyncio.create_task(self._run(url)))

    async def publish(self, event: dict) -> int:
        """Sends the event to every connected relay; returns how many relays it was sent to."""
        msg = json.dumps(["EVENT", event])
        sent = 0
        for url, ws in list(self._sockets.items()):
            try:
                await ws.send(msg)
                sent += 1
            except Exception as e:  # relay dropped; the reconnect loop will handle it
                log.debug("publish to %s failed: %s", url, e)
        return sent

    async def _run(self, url: str):
        backoff = 1
        while True:
            try:
                async with connect(url, open_timeout=10, ping_interval=30) as ws:
                    self._sockets[url] = ws
                    await ws.send(json.dumps(["REQ", self._sub_id, *self._filters]))
                    log.info("connected to %s", url)
                    self._ready.set()
                    backoff = 1
                    async for raw in ws:
                        await self._handle(url, raw)
            except asyncio.CancelledError:
                raise
            except Exception as e:
                log.warning("relay %s: %s (retrying in %ss)", url, e, backoff)
            finally:
                self._sockets.pop(url, None)
            await asyncio.sleep(backoff)
            backoff = min(backoff * 2, 30)

    async def _handle(self, url: str, raw):
        try:
            msg = json.loads(raw)
        except ValueError:
            return
        if msg[0] == "EVENT" and len(msg) >= 3 and msg[1] == self._sub_id:
            ev = msg[2]
            if ev.get("id") in self._seen:
                return
            self._seen.add(ev.get("id"))
            try:
                await self.on_event(ev)
            except Exception:
                log.exception("error handling event from %s", url)
        elif msg[0] == "OK" and len(msg) >= 3 and not msg[2]:
            log.warning("relay %s rejected event: %s", url, msg[3] if len(msg) > 3 else "")
        elif msg[0] == "NOTICE":
            log.info("notice from %s: %s", url, msg[1])
