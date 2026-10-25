# sentinelx/sniffer.py
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from sentinelx.models import ArpEvent
from sentinelx.trust import normalize_mac

logger = logging.getLogger(__name__)


def parse_arp(pkt: Any, iface: str, ts: float | None = None) -> ArpEvent | None:
    """Pure packet-to-ArpEvent parser (§9 WP1).

    Lowercases MACs and rejects non-ARP, malformed, or truncated packets.
    """
    if pkt is None:
        return None
    try:
        from scapy.config import conf  # type: ignore[import-untyped]

        conf.ipv6_enabled = False
        from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
    except Exception:
        return None

    try:
        if not pkt.haslayer(Ether) or not pkt.haslayer(ARP):
            return None
        eth = pkt[Ether]
        arp = pkt[ARP]

        # Validate IPv4 (ptype 0x0800) and Ethernet (hwtype 1) ARP fields exist
        op = int(arp.op)
        if op not in (1, 2):
            return None

        eth_src = normalize_mac(str(eth.src))
        arp_sha = normalize_mac(str(arp.hwsrc))
        arp_spa = str(arp.psrc).strip()
        arp_tha = normalize_mac(str(arp.hwdst))
        arp_tpa = str(arp.pdst).strip()

        if len(eth_src) != 17 or len(arp_sha) != 17 or len(arp_tha) != 17:
            return None
        if not arp_spa or not arp_tpa:
            return None

        pkt_ts = ts if ts is not None else float(getattr(pkt, "time", time.time()))
        return ArpEvent(
            ts=pkt_ts,
            iface=iface,
            op=op,
            eth_src=eth_src,
            arp_sha=arp_sha,
            arp_spa=arp_spa,
            arp_tha=arp_tha,
            arp_tpa=arp_tpa,
        )
    except Exception:
        return None


class Sniffer:
    """Wraps Scapy `AsyncSniffer(iface, filter="arp", store=False)` and pushes `ArpEvent`s
    into a bounded `asyncio.Queue` via `loop.call_soon_threadsafe`.

    On queue overflow, drops the event and increments `dropped_events` (§3, §6.4, §9 WP1).
    """

    def __init__(
        self,
        iface: str,
        queue: asyncio.Queue[ArpEvent],
        loop: asyncio.AbstractEventLoop,
    ) -> None:
        self.iface = iface
        self.queue = queue
        self.loop = loop
        self.dropped_events: int = 0
        self._sniffer: Any = None
        self._running: bool = False

    def _enqueue_safe(self, ev: ArpEvent) -> None:
        try:
            self.queue.put_nowait(ev)
        except asyncio.QueueFull:
            self.dropped_events += 1

    def feed_packet(self, pkt: Any) -> None:
        """Thread-safe packet callback invoked by Scapy sniffer thread (or tests)."""
        ev = parse_arp(pkt, self.iface)
        if ev is None:
            return
        try:
            self.loop.call_soon_threadsafe(self._enqueue_safe, ev)
        except RuntimeError:
            # Event loop already closed
            pass

    def start(self) -> None:
        if self._running:
            return
        from scapy.config import conf  # type: ignore[import-untyped]

        conf.ipv6_enabled = False
        from scapy.sendrecv import AsyncSniffer  # type: ignore[import-untyped]

        self._sniffer = AsyncSniffer(
            iface=self.iface,
            filter="arp",
            prn=self.feed_packet,
            store=False,
        )
        self._sniffer.start()
        self._running = True

    def stop(self) -> None:
        if not self._running:
            return
        self._running = False
        if self._sniffer is not None:
            try:
                self._sniffer.stop()
            except Exception as exc:
                logger.debug("Sniffer stop warning: %s", exc)
            self._sniffer = None
