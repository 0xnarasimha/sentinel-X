# sentinelx/netwatch.py
from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable

from sentinelx.models import NetBackend, NetState

logger = logging.getLogger(__name__)


class NetWatcher:
    """Polls default route and interface state every `interval_s` (default 2.0s, §3 & §6.5)."""

    def __init__(
        self,
        backend: NetBackend,
        on_update: Callable[[NetState | None], Awaitable[None]],
        iface_override: str | None = None,
        interval_s: float = 2.0,
    ) -> None:
        self.backend = backend
        self.on_update = on_update
        self.iface_override = (
            iface_override if iface_override and iface_override != "auto" else None
        )
        self.interval_s = interval_s
        self._stop_event = asyncio.Event()

    def poll_once_sync(self) -> NetState | None:
        route = self.backend.default_route()
        if route is None:
            return None
        iface, gw_ip = route
        if self.iface_override and iface != self.iface_override:
            iface = self.iface_override
        try:
            return self.backend.net_state(iface, gw_ip)
        except Exception as exc:
            logger.debug("net_state failed for %s: %s", iface, exc)
            return None

    async def poll_once(self) -> NetState | None:
        net = await asyncio.to_thread(self.poll_once_sync)
        await self.on_update(net)
        return net

    async def run(self) -> None:
        while not self._stop_event.is_set():
            try:
                await self.poll_once()
            except Exception as exc:
                logger.warning("NetWatcher poll error: %s", exc)
            try:
                await asyncio.wait_for(self._stop_event.wait(), timeout=self.interval_s)
            except asyncio.TimeoutError:
                pass

    def stop(self) -> None:
        self._stop_event.set()
