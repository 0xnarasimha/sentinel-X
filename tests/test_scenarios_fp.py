# tests/test_scenarios_fp.py
from __future__ import annotations

import pytest

from sentinelx.engine import Engine
from sentinelx.models import ArpEvent, EngineConfig, NetState
from sentinelx.trust import MemoryTrustStore

GW_IP = "10.77.0.1"
GW_MAC = "02:77:00:00:00:01"
OUR_IP = "10.77.0.10"
OUR_MAC = "02:77:00:00:00:10"


@pytest.mark.parametrize(
    ("op", "sha", "spa", "tpa"),
    [
        (1, GW_MAC, GW_IP, OUR_IP),
        (2, GW_MAC, GW_IP, OUR_IP),
        (2, GW_MAC, GW_IP, GW_IP),
        (1, "02:77:00:00:00:50", "10.77.0.50", GW_IP),
        (2, "02:77:00:00:00:50", "10.77.0.50", OUR_IP),
        (1, "02:77:00:00:00:50", "0.0.0.0", GW_IP),
        (1, OUR_MAC, OUR_IP, GW_IP),
    ],
)
def test_smoke_false_positive_scenarios_never_alert(
    op: int, sha: str, spa: str, tpa: str
) -> None:
    store = MemoryTrustStore()
    eng = Engine(store, EngineConfig())
    net = NetState("v-victim", "wired", OUR_IP, OUR_MAC, GW_IP)
    eng.on_net(net, now=1.0)
    eng.on_tofu_result({GW_MAC: 5}, now=2.0)

    ev = ArpEvent(
        ts=10.0,
        iface="v-victim",
        op=op,
        eth_src=sha,
        arp_sha=sha,
        arp_spa=spa,
        arp_tha=OUR_MAC,
        arp_tpa=tpa,
    )
    assert eng.on_arp(ev, now=10.0) == []
