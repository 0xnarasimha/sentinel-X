# sentinelx/healer.py
from __future__ import annotations

from typing import Any

from sentinelx.models import MAC, Heal, IPv4, NetBackend
from sentinelx.trust import normalize_mac


def build_corrective_arp(our_mac: MAC, our_ip: IPv4, gw_mac: MAC, gw_ip: IPv4) -> Any:
    """Build unicast corrective ARP reply to the router per §6.4:
    `Ether(src=our_mac, dst=gw_mac) / ARP(op=2, hwsrc=our_mac, psrc=our_ip, hwdst=gw_mac, pdst=gw_ip)`
    """
    from scapy.config import conf  # type: ignore[import-untyped]

    conf.ipv6_enabled = False
    from scapy.layers.l2 import ARP, Ether  # type: ignore[import-untyped]

    smac = normalize_mac(our_mac)
    dmac = normalize_mac(gw_mac)
    return Ether(src=smac, dst=dmac) / ARP(
        op=2,
        hwsrc=smac,
        psrc=our_ip,
        hwdst=dmac,
        pdst=gw_ip,
    )


def verify_pinned_entry(backend: NetBackend, iface: str, gw_ip: IPv4, expected_mac: MAC) -> bool:
    """Read back kernel neighbour entry and confirm it is PERMANENT with expected_mac."""
    entry = backend.neigh_get(iface, gw_ip)
    if entry is None:
        return False
    return (
        normalize_mac(entry.mac) == normalize_mac(expected_mac)
        and "PERMANENT" in entry.state.upper()
    )


def execute_heal(
    backend: NetBackend,
    heal: Heal,
    first_pkt_ts: float | None,
    now: float,
) -> dict[str, Any]:
    """Execute a Heal action against NetBackend, verify by read-back, and return log payload (§6.4)."""
    gw_mac = normalize_mac(heal.gw_mac)
    backend.neigh_pin(heal.net.iface, heal.net.gw_ip, gw_mac)
    verified = verify_pinned_entry(backend, heal.net.iface, heal.net.gw_ip, gw_mac)

    if heal.send_corrective:
        backend.send_arp_reply(
            iface=heal.net.iface,
            src_mac=normalize_mac(heal.net.our_mac),
            src_ip=heal.net.our_ip,
            dst_mac=gw_mac,
            dst_ip=heal.net.gw_ip,
        )

    latency_ms = 0.0
    if first_pkt_ts is not None:
        latency_ms = round(max(0.0, (now - first_pkt_ts) * 1000.0), 3)

    return {
        "iface": heal.net.iface,
        "gw_ip": heal.net.gw_ip,
        "pinned_mac": gw_mac,
        "verified": verified,
        "corrective_sent": bool(heal.send_corrective),
        "latency_ms_from_first_pkt": latency_ms,
        "reason": heal.reason,
    }
