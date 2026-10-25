# tests/test_scenarios_attack.py
from __future__ import annotations

import pytest

from sentinelx.engine import Engine
from sentinelx.models import ArpEvent, EngineConfig, Heal, LogRecord, NetState
from sentinelx.trust import MemoryTrustStore

GW_IP = "10.77.0.1"
GW_MAC = "02:77:00:00:00:01"
OUR_IP = "10.77.0.10"
OUR_MAC = "02:77:00:00:00:10"


@pytest.mark.parametrize(
    ("op", "eth_src", "sha", "tha", "tpa"),
    [
        (2, "02:77:00:00:00:66", "02:77:00:00:00:66", OUR_MAC, OUR_IP),
        (1, "02:77:00:00:00:66", "02:77:00:00:00:66", "00:00:00:00:00:00", OUR_IP),
        (2, "02:77:00:00:00:66", "02:77:00:00:00:66", "ff:ff:ff:ff:ff:ff", GW_IP),
        (2, GW_MAC, "02:77:00:00:00:66", OUR_MAC, OUR_IP),
        (2, "00:00:5e:00:01:01", "00:00:5e:00:01:01", OUR_MAC, OUR_IP),
    ],
)
def test_smoke_attack_scenarios_always_alert(
    op: int, eth_src: str, sha: str, tha: str, tpa: str
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
        eth_src=eth_src,
        arp_sha=sha,
        arp_spa=GW_IP,
        arp_tha=tha,
        arp_tpa=tpa,
    )
    actions = eng.on_arp(ev, now=10.0)
    assert any(isinstance(a, LogRecord) and a.type == "detect" for a in actions)
    assert any(isinstance(a, Heal) for a in actions)
