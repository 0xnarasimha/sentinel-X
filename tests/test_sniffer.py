# tests/test_sniffer.py
from __future__ import annotations

import asyncio

from scapy.layers.inet import ICMP, IP  # type: ignore[import-untyped]
from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]
from scapy.packet import Raw  # type: ignore[import-untyped]

from sentinelx.models import ArpEvent
from sentinelx.sniffer import Sniffer, parse_arp


def test_parse_arp_who_has_request() -> None:
    pkt = Ether(src="02:77:00:00:00:10", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=1,
        hwsrc="02:77:00:00:00:10",
        psrc="10.77.0.10",
        hwdst="00:00:00:00:00:00",
        pdst="10.77.0.1",
    )
    ev = parse_arp(pkt, iface="v-victim", ts=123.45)
    assert ev == ArpEvent(
        ts=123.45,
        iface="v-victim",
        op=1,
        eth_src="02:77:00:00:00:10",
        arp_sha="02:77:00:00:00:10",
        arp_spa="10.77.0.10",
        arp_tha="00:00:00:00:00:00",
        arp_tpa="10.77.0.1",
    )


def test_parse_arp_is_at_reply() -> None:
    pkt = Ether(src="02:77:00:00:00:66", dst="02:77:00:00:00:10") / ARP(
        op=2,
        hwsrc="02:77:00:00:00:66",
        psrc="10.77.0.1",
        hwdst="02:77:00:00:00:10",
        pdst="10.77.0.10",
    )
    ev = parse_arp(pkt, iface="v-victim", ts=200.0)
    assert ev is not None
    assert ev.op == 2
    assert ev.arp_spa == "10.77.0.1"
    assert ev.arp_sha == "02:77:00:00:00:66"


def test_parse_arp_normalizes_mixed_case_macs() -> None:
    pkt = Ether(src="AA:BB:CC:DD:EE:FF", dst="FF:FF:FF:FF:FF:FF") / ARP(
        op=2,
        hwsrc="AA:BB:CC:DD:EE:FF",
        psrc="10.77.0.1",
        hwdst="02:77:00:00:00:10",
        pdst="10.77.0.10",
    )
    ev = parse_arp(pkt, iface="v-victim", ts=1.0)
    assert ev is not None
    assert ev.eth_src == "aa:bb:cc:dd:ee:ff"
    assert ev.arp_sha == "aa:bb:cc:dd:ee:ff"


def test_parse_arp_preserves_eth_src_mismatch() -> None:
    pkt = Ether(src="aa:bb:cc:00:00:01", dst="02:77:00:00:00:10") / ARP(
        op=2,
        hwsrc="dd:ee:ff:00:00:02",
        psrc="10.77.0.1",
        hwdst="02:77:00:00:00:10",
        pdst="10.77.0.10",
    )
    ev = parse_arp(pkt, iface="v-victim", ts=1.0)
    assert ev is not None
    assert ev.eth_src == "aa:bb:cc:00:00:01"
    assert ev.arp_sha == "dd:ee:ff:00:00:02"


def test_parse_arp_rejects_non_arp_packets() -> None:
    icmp_pkt = (
        Ether(src="02:77:00:00:00:10", dst="02:77:00:00:00:01")
        / IP(src="10.77.0.10", dst="10.77.0.1")
        / ICMP()
    )
    assert parse_arp(icmp_pkt, iface="v-victim") is None
    assert parse_arp(Raw(b"\x00\x01\x02"), iface="v-victim") is None
    assert parse_arp(None, iface="v-victim") is None


def test_parse_arp_rejects_invalid_arp_op() -> None:
    pkt = Ether(src="02:77:00:00:00:10", dst="ff:ff:ff:ff:ff:ff") / ARP(
        op=9,  # RARP / invalid op for IPv4 ARP
        hwsrc="02:77:00:00:00:10",
        psrc="10.77.0.10",
        hwdst="00:00:00:00:00:00",
        pdst="10.77.0.1",
    )
    assert parse_arp(pkt, iface="v-victim") is None


def test_parse_arp_rejects_arp_without_ether() -> None:
    pkt = ARP(op=1, psrc="10.77.0.10", pdst="10.77.0.1")
    assert parse_arp(pkt, iface="v-victim") is None


def test_sniffer_bounded_queue_drops_and_counts_overflow() -> None:
    async def _run() -> None:
        loop = asyncio.get_running_loop()
        q: asyncio.Queue[ArpEvent] = asyncio.Queue(maxsize=3)
        sniffer = Sniffer(iface="v-victim", queue=q, loop=loop)

        pkt = Ether(src="02:77:00:00:00:66", dst="02:77:00:00:00:10") / ARP(
            op=2,
            hwsrc="02:77:00:00:00:66",
            psrc="10.77.0.1",
            hwdst="02:77:00:00:00:10",
            pdst="10.77.0.10",
        )
        for _ in range(5):
            sniffer.feed_packet(pkt)

        # Let loop.call_soon_threadsafe callbacks run
        await asyncio.sleep(0.02)
        assert q.qsize() == 3
        assert sniffer.dropped_events == 2

    asyncio.run(_run())
